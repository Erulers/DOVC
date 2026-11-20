"""Transactions, blocks, validation, genesis and mining for Dove (DOVC).

Prototype scope: in-memory chain with fork handling and a UTXO set per block.
No networking and no disk storage yet.  See README.md for what is and is not
implemented, and for the places where this code deliberately follows the spec's
"[Default - review]" choices.
"""

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import bip340
from . import params as P
from . import schedule

ZERO32 = bytes(32)
ZERO64 = bytes(64)


class BlockError(Exception):
    """Raised when a block (or a transaction inside it) breaks a consensus rule."""


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

@dataclass
class TxIn:
    prev_txid: bytes
    index: int
    pubkey: bytes = ZERO32
    signature: bytes = ZERO64


@dataclass
class TxOut:
    value: int                       # base units
    lock_type: int                   # P.LOCK_P2PKH or P.LOCK_P2PKH_HEIGHT
    payload: bytes                   # SHA-256 of the 32-byte x-only public key
    unlock_height: int = 0           # only used by LOCK_P2PKH_HEIGHT


@dataclass
class Tx:
    inputs: List[TxIn]
    outputs: List[TxOut]
    version: int = 1
    coinbase_data: bytes = b""       # free text; only allowed in the coinbase

    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].prev_txid == ZERO32

    def serialize(self, include_signatures: bool = True) -> bytes:
        out = struct.pack("<I", self.version) + varint(len(self.inputs))
        for i in self.inputs:
            out += i.prev_txid + struct.pack("<I", i.index) + i.pubkey
            if include_signatures:
                out += i.signature
        out += varint(len(self.outputs))
        for o in self.outputs:
            out += struct.pack("<QB", o.value, o.lock_type) + o.payload
            if o.lock_type == P.LOCK_P2PKH_HEIGHT:
                out += struct.pack("<I", o.unlock_height)
        out += varint(len(self.coinbase_data)) + self.coinbase_data
        return out

    def txid(self) -> bytes:
        """Double SHA-256 of the serialization without signatures."""
        return sha256d(self.serialize(include_signatures=False))

    def sighash(self) -> bytes:
        """The 32-byte message every input signs (it commits to the whole transaction)."""
        return sha256(b"DOVC-SIG-v1" + self.txid())


def pubkey_payload(pubkey: bytes) -> bytes:
    return sha256(pubkey)


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------

@dataclass
class Header:
    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    nonce: int

    def serialize(self) -> bytes:
        return struct.pack("<I32s32sIQ", self.version, self.prev_hash,
                           self.merkle_root, self.timestamp, self.nonce)


@dataclass
class Block:
    header: Header
    txs: List[Tx] = field(default_factory=list)

    def block_id(self) -> bytes:
        return sha256d(self.header.serialize())

    def serialize(self) -> bytes:
        out = self.header.serialize() + varint(len(self.txs))
        for tx in self.txs:
            out += tx.serialize()
        return out

    def size(self) -> int:
        return len(self.serialize())


def merkle_root(txids: List[bytes]) -> bytes:
    layer = list(txids)
    if not layer:
        return ZERO32
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def pow_hash(header_bytes: bytes, memory_kib: int = P.POW_MEMORY_KIB) -> bytes:
    kdf = Argon2id(salt=P.POW_SALT, length=32, iterations=P.POW_TIME_COST,
                   lanes=P.POW_LANES, memory_cost=memory_kib)
    return kdf.derive(header_bytes)


def meets_target(header: Header, height: int, memory_kib: int = P.POW_MEMORY_KIB) -> bool:
    value = int.from_bytes(pow_hash(header.serialize(), memory_kib), "big")
    return value <= schedule.target_for_height(height)


# ---------------------------------------------------------------------------
# UTXO set and transaction checking
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Utxo:
    value: int
    lock_type: int
    payload: bytes
    unlock_height: int
    created_height: int
    is_coinbase: bool


Outpoint = Tuple[bytes, int]


class UtxoOverlay:
    """A scratch view on top of a UTXO dict: reads fall through, writes stay local."""

    def __init__(self, base: dict):
        self.base = base
        self.added: dict = {}
        self.removed: set = set()

    def get(self, key, default=None):
        if key in self.added:
            return self.added[key]
        if key in self.removed:
            return default
        return self.base.get(key, default)

    def __contains__(self, key) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key):
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key, value) -> None:
        self.added[key] = value
        self.removed.discard(key)

    def __delitem__(self, key) -> None:
        if key in self.added:
            del self.added[key]
        else:
            self.removed.add(key)


def check_and_apply_tx(utxos: dict, tx: Tx, height: int, verify_sigs: bool = True) -> int:
    """Validate a non-coinbase transaction against `utxos` and apply it in place.

    `height` is the height of the block that would include the transaction.
    Returns the fee in base units.  Raises BlockError on any violation.
    """
    if tx.version != 1:
        raise BlockError("unknown transaction version")
    if tx.coinbase_data:
        raise BlockError("only the coinbase may carry coinbase data")
    if not tx.inputs or not tx.outputs:
        raise BlockError("transaction needs at least one input and one output")
    if tx.is_coinbase():
        raise BlockError("unexpected coinbase transaction")

    seen = set()
    total_in = 0
    msg = tx.sighash()
    for txin in tx.inputs:
        outpoint = (txin.prev_txid, txin.index)
        if outpoint in seen:
            raise BlockError("duplicate input inside one transaction")
        seen.add(outpoint)
        utxo = utxos.get(outpoint)
        if utxo is None:
            raise BlockError("input is missing or already spent")
        if utxo.is_coinbase and height - utxo.created_height < P.COINBASE_MATURITY:
            raise BlockError("coinbase output is not mature yet")
        if utxo.lock_type == P.LOCK_P2PKH_HEIGHT and height < utxo.unlock_height:
            raise BlockError("output is still timelocked")
        if pubkey_payload(txin.pubkey) != utxo.payload:
            raise BlockError("public key does not match the output")
        if verify_sigs and not bip340.schnorr_verify(msg, txin.pubkey, txin.signature):
            raise BlockError("bad signature")
        total_in += utxo.value

    total_out = 0
    for out in tx.outputs:
        if out.lock_type not in (P.LOCK_P2PKH, P.LOCK_P2PKH_HEIGHT):
            raise BlockError("unknown lock type")
        if len(out.payload) != 32:
            raise BlockError("output payload must be 32 bytes")
        if not 0 < out.value <= P.MAX_MONEY:
            raise BlockError("output value out of range")
        total_out += out.value
    if total_out > P.MAX_MONEY or total_out > total_in:
        raise BlockError("outputs exceed inputs")

    for outpoint in seen:
        del utxos[outpoint]
    txid = tx.txid()
    for idx, out in enumerate(tx.outputs):
        utxos[(txid, idx)] = Utxo(out.value, out.lock_type, out.payload,
                                  out.unlock_height, height, False)
    return total_in - total_out


def _apply_coinbase(utxos: dict, tx: Tx, height: int):
    txid = tx.txid()
    for idx, out in enumerate(tx.outputs):
        utxos[(txid, idx)] = Utxo(out.value, out.lock_type, out.payload,
                                  out.unlock_height, height, True)


# ---------------------------------------------------------------------------
# Genesis
# ---------------------------------------------------------------------------

DEV_PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "dev_payloads.json")


def load_dev_payloads():
    """Return (payloads, is_placeholder).

    If dove/dev_payloads.json exists (written by `python -m dove devkeys`), it must hold five
    hex-encoded 32-byte payloads.  Otherwise the public PLACEHOLDER keys are used.
    """
    if os.path.exists(DEV_PAYLOAD_FILE):
        with open(DEV_PAYLOAD_FILE) as f:
            items = json.load(f)
        payloads = [bytes.fromhex(x) for x in items]
        if len(payloads) != P.DEV_PAYOUT_PARTS or any(len(x) != 32 for x in payloads):
            raise ValueError("dev_payloads.json must hold five 32-byte hex payloads")
        return payloads, False
    return [placeholder_dev_payload(i) for i in range(P.DEV_PAYOUT_PARTS)], True


def placeholder_dev_payload(i: int) -> bytes:
    """PLACEHOLDER developer address payloads.

    These keys come from public strings, so ANYONE can derive them.  They exist
    only so the prototype has a complete genesis block.  Replace them with
    addresses from keys generated offline before any real launch.
    """
    seckey = sha256(b"DOVC-PLACEHOLDER-DEV-KEY-%d" % i)
    return pubkey_payload(bip340.pubkey_gen(seckey))


def placeholder_dev_seckey(i: int) -> bytes:
    return sha256(b"DOVC-PLACEHOLDER-DEV-KEY-%d" % i)


def make_genesis(network: str = "main") -> Block:
    cfg = P.NETWORKS[network]
    payout = cfg["payout"]                   # ((amount, unlock_height), ...); 0 = no timelock
    if network == "main":
        payloads, _ = load_dev_payloads()
    else:                                    # testnet payout keys are public on purpose
        payloads = [placeholder_dev_payload(i) for i in range(len(payout))]
    outputs = [
        TxOut(units, P.LOCK_P2PKH_HEIGHT if unlock else P.LOCK_P2PKH, payloads[i], unlock)
        for i, (units, unlock) in enumerate(payout)
    ]
    coinbase = Tx(
        inputs=[TxIn(ZERO32, 0)],
        outputs=outputs,
        coinbase_data=cfg["genesis_message"],
    )
    header = Header(1, ZERO32, merkle_root([coinbase.txid()]), P.GENESIS_TIMESTAMP, 0)
    return Block(header, [coinbase])


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

@dataclass
class _Entry:
    block: Block
    height: int
    parent_id: Optional[bytes]
    undo: Optional[tuple] = None      # (spent, created) while connected to the best chain
    invalid: bool = False


class Chain:
    """In-memory chain.  Longest valid chain wins; ties go to the first one seen."""

    def __init__(self, pow_memory_kib: Optional[int] = None, network: str = "main"):
        self.network_name = network
        self.pow_memory_kib = pow_memory_kib or P.NETWORKS[network]["pow_memory_kib"]
        genesis = make_genesis(network)
        gid = genesis.block_id()
        self.utxo: dict = {}                 # ONE set: the state at the best tip
        _apply_coinbase(self.utxo, genesis.txs[0], 0)
        created = [(genesis.txs[0].txid(), i) for i in range(len(genesis.txs[0].outputs))]
        self.entries = {gid: _Entry(genesis, 0, None, ([], created))}
        self.genesis_id = gid
        self.best_id = gid
        self.height_index = [gid]       # block id of the best chain at each height

    # -- queries -----------------------------------------------------------
    @property
    def height(self) -> int:
        return self.entries[self.best_id].height

    @property
    def tip(self) -> Block:
        return self.entries[self.best_id].block

    def utxos(self) -> dict:
        return self.utxo

    def median_time_past(self, entry_id: bytes) -> int:
        stamps = []
        entry = self.entries[entry_id]
        while True:
            stamps.append(entry.block.header.timestamp)
            if entry.parent_id is None or len(stamps) == P.MEDIAN_TIME_SPAN:
                break
            entry = self.entries[entry.parent_id]
        stamps.sort()
        return stamps[len(stamps) // 2]

    # -- validation --------------------------------------------------------
    def add_block(self, block: Block, now: Optional[int] = None, trusted: bool = False) -> bool:
        """Check a block and store it.  Returns True if it became the best tip.

        Cheap checks (size, timestamps, structure, Merkle root, proof of work) run now.  The full
        transaction check runs when the block is connected to the best chain; if that fails the
        block is marked invalid and BlockError is raised.  `trusted=True` (database replay) skips
        only the proof-of-work and future-timestamp checks; signatures are always verified.
        """
        now = int(time.time()) if now is None else now
        bid = block.block_id()
        if bid in self.entries:
            return False
        parent = self.entries.get(block.header.prev_hash)
        if parent is None:
            raise BlockError("unknown parent block")
        if parent.invalid:
            raise BlockError("parent block is invalid")
        height = parent.height + 1

        if block.size() > P.MAX_BLOCK_BYTES:
            raise BlockError("block is too large")
        if block.header.version != 1:
            raise BlockError("unknown block version")
        ts = block.header.timestamp
        if ts <= self.median_time_past(block.header.prev_hash):
            raise BlockError("timestamp is not after the median of recent blocks")
        if not trusted and ts > now + P.MAX_FUTURE_SECONDS:
            raise BlockError("timestamp is too far in the future")
        if not block.txs:
            raise BlockError("block has no transactions")
        txids = [tx.txid() for tx in block.txs]
        if len(set(txids)) != len(txids):
            raise BlockError("duplicate transaction in block")
        if merkle_root(txids) != block.header.merkle_root:
            raise BlockError("merkle root mismatch")
        if not trusted and not meets_target(block.header, height, self.pow_memory_kib):
            raise BlockError("proof of work does not meet the target")

        coinbase = block.txs[0]
        if not coinbase.is_coinbase():
            raise BlockError("first transaction must be the coinbase")
        if any(tx.is_coinbase() for tx in block.txs[1:]):
            raise BlockError("unexpected coinbase transaction")
        if coinbase.inputs[0].index != height:
            raise BlockError("coinbase must record its block height")
        if coinbase.inputs[0].pubkey != ZERO32 or coinbase.inputs[0].signature != ZERO64:
            raise BlockError("coinbase input must carry no key or signature")
        if len(coinbase.coinbase_data) > P.MAX_COINBASE_DATA:
            raise BlockError("coinbase data is too long")
        if not coinbase.outputs:
            raise BlockError("coinbase needs an output")
        for out in coinbase.outputs:
            if out.lock_type not in (P.LOCK_P2PKH, P.LOCK_P2PKH_HEIGHT) or len(out.payload) != 32:
                raise BlockError("bad coinbase output")
            if not 0 < out.value <= P.MAX_MONEY:
                raise BlockError("coinbase output value out of range")

        self.entries[bid] = _Entry(block, height, block.header.prev_hash)
        if height <= self.height:
            return False                      # a side branch: stored, checked if it ever wins
        self._reorganize_to(bid)
        return True

    # -- connecting blocks to the single UTXO set ---------------------------
    def _connect(self, entry: _Entry, verify_sigs: bool = True) -> None:
        """Apply a block to the UTXO set, recording what is needed to undo it."""
        block, height, utxos = entry.block, entry.height, self.utxo
        spent, created, created_set = [], [], set()
        try:
            fees = 0
            for tx in block.txs[1:]:
                before = [(op, utxos[op]) for op in ((i.prev_txid, i.index) for i in tx.inputs)
                          if op in utxos and op not in created_set]
                fees += check_and_apply_tx(utxos, tx, height, verify_sigs=verify_sigs)
                spent.extend(before)
                txid = tx.txid()
                for idx in range(len(tx.outputs)):
                    created.append((txid, idx))
                    created_set.add((txid, idx))
            coinbase = block.txs[0]
            if sum(o.value for o in coinbase.outputs) > schedule.subsidy(height) + fees:
                raise BlockError("coinbase pays more than subsidy plus fees")
            _apply_coinbase(utxos, coinbase, height)
            cb_id = coinbase.txid()
            created.extend((cb_id, idx) for idx in range(len(coinbase.outputs)))
        except BlockError:
            for op in created:
                utxos.pop(op, None)
            for op, utxo in spent:
                utxos[op] = utxo
            raise
        entry.undo = (spent, created)

    def _disconnect(self, entry: _Entry) -> None:
        spent, created = entry.undo
        for op in created:
            self.utxo.pop(op, None)
        for op, utxo in spent:
            self.utxo[op] = utxo
        entry.undo = None

    def _reorganize_to(self, new_id: bytes) -> None:
        """Make `new_id` the tip: undo the old branch, apply the new one, roll back on failure."""
        path, cur = [], new_id
        while True:
            e = self.entries[cur]
            if e.height < len(self.height_index) and self.height_index[e.height] == cur:
                break
            path.append(cur)
            cur = e.parent_id
        path.reverse()
        fork_height = self.entries[cur].height
        old = [self.height_index[h] for h in range(len(self.height_index) - 1, fork_height, -1)]
        for oid in old:
            self._disconnect(self.entries[oid])
        connected = []
        try:
            for nid in path:
                self._connect(self.entries[nid])
                connected.append(nid)
        except BlockError as exc:
            for cid in reversed(connected):
                self._disconnect(self.entries[cid])
            for oid in reversed(old):
                self._connect(self.entries[oid], verify_sigs=False)   # it was valid before
            bad = path[len(connected)]
            for iid in path[len(connected):]:
                self.entries[iid].invalid = True
            if bad == new_id:
                raise
            raise BlockError(f"block at height {self.entries[bad].height} of the new branch "
                             f"is invalid: {exc}")
        self._set_best(new_id)

    def _set_best(self, bid: bytes) -> None:
        """Make `bid` the best tip and rebuild the height index (handles reorgs)."""
        path = []
        cur = bid
        while True:
            entry = self.entries[cur]
            if entry.height < len(self.height_index) and self.height_index[entry.height] == cur:
                break
            path.append(cur)
            cur = entry.parent_id
        del self.height_index[entry.height + 1:]
        self.height_index.extend(reversed(path))
        self.best_id = bid

    # -- sync helpers ------------------------------------------------------
    def locator(self) -> List[bytes]:
        """Block ids from the tip back to genesis, with exponentially growing gaps."""
        ids, step, h = [], 1, self.height
        while h > 0:
            ids.append(self.height_index[h])
            if len(ids) >= 10:
                step *= 2
            h = max(0, h - step)
        ids.append(self.genesis_id)
        return ids

    def headers_after(self, locator: List[bytes], limit: int = 500) -> List[Header]:
        """Headers of the best chain following the first locator id we recognise."""
        start = 0
        for bid in locator:
            entry = self.entries.get(bid)
            if entry is not None and self.height_index[entry.height] == bid:
                start = entry.height
                break
        return [self.entries[self.height_index[h]].block.header
                for h in range(start + 1, min(start + 1 + limit, len(self.height_index)))]

    def block_by_id(self, bid: bytes) -> Optional[Block]:
        entry = self.entries.get(bid)
        return entry.block if entry else None

    def block_at_height(self, h: int) -> Optional[Block]:
        return self.entries[self.height_index[h]].block if 0 <= h < len(self.height_index) else None

    # -- mining ------------------------------------------------------------
    def build_block(self, payload: bytes, txs: Optional[List[Tx]] = None,
                    timestamp: Optional[int] = None, coinbase_data: bytes = b"") -> Block:
        """Assemble a block on the best tip (nonce not yet found)."""
        txs = list(txs or [])
        tip_id = self.best_id
        height = self.height + 1
        utxos = UtxoOverlay(self.utxos())
        fees = sum(check_and_apply_tx(utxos, tx, height) for tx in txs)
        reward = schedule.subsidy(height) + fees
        coinbase = Tx(
            inputs=[TxIn(ZERO32, height)],
            outputs=[TxOut(reward, P.LOCK_P2PKH, payload)],
            coinbase_data=coinbase_data,
        )
        if timestamp is None:
            timestamp = max(int(time.time()), self.median_time_past(tip_id) + 1)
        all_txs = [coinbase] + txs
        header = Header(1, tip_id, merkle_root([t.txid() for t in all_txs]), timestamp, 0)
        return Block(header, all_txs)

    def mine(self, block: Block, start_nonce: int = 0,
             max_attempts: Optional[int] = None) -> Tuple[Optional[Block], int]:
        """Search for a nonce.  Returns (block or None, attempts made)."""
        height = self.height + 1
        target = schedule.target_for_height(height)
        attempts = 0
        nonce = start_nonce
        while max_attempts is None or attempts < max_attempts:
            block.header.nonce = nonce
            attempts += 1
            value = int.from_bytes(pow_hash(block.header.serialize(), self.pow_memory_kib), "big")
            if value <= target:
                return block, attempts
            nonce += 1
        return None, attempts
