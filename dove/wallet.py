"""A minimal wallet for the prototype: one key, one address, signed payments."""

import os
from typing import List, Optional

from . import bech32m, bip340
from . import params as P
from .chain import Tx, TxIn, TxOut, pubkey_payload


class Wallet:
    def __init__(self, seckey: Optional[bytes] = None, hrp: Optional[str] = None):
        self.hrp = hrp or P.ADDRESS_HRP
        if seckey is None:
            while True:
                seckey = os.urandom(32)
                if 1 <= int.from_bytes(seckey, "big") < bip340.n:
                    break
        self.seckey = seckey
        self.pubkey = bip340.pubkey_gen(seckey)
        self.payload = pubkey_payload(self.pubkey)

    @property
    def address(self) -> str:
        return bech32m.encode_address(self.hrp, self.payload)

    def sign(self, tx: Tx) -> Tx:
        """Sign every input of `tx` (they must all belong to this wallet)."""
        for txin in tx.inputs:
            txin.pubkey = self.pubkey        # the txid commits to the public keys
        msg = tx.sighash()
        for txin in tx.inputs:
            txin.signature = bip340.schnorr_sign(msg, self.seckey, os.urandom(32))
        return tx

    def pay(self, outpoints: List[tuple], outputs: List[TxOut]) -> Tx:
        """Build and sign a transaction spending `outpoints` into `outputs`."""
        tx = Tx(inputs=[TxIn(txid, idx) for txid, idx in outpoints], outputs=outputs)
        return self.sign(tx)

    def balance_outpoints(self, utxos: dict) -> list:
        return [op for op, u in utxos.items() if u.payload == self.payload]


def address_to_payload(address: str, hrp: Optional[str] = None) -> Optional[bytes]:
    """Decode an address.  With `hrp` it must match exactly; without, any known network is accepted."""
    for known in ([hrp] if hrp else [n["hrp"] for n in P.NETWORKS.values()]):
        payload = bech32m.decode_address(known, address)
        if payload is not None:
            return payload
    return None


# ---------------------------------------------------------------------------
# Wallet file, amounts, and payment building
# ---------------------------------------------------------------------------

import json
from decimal import Decimal, InvalidOperation

DUST_UNITS = 1_000          # change smaller than this is added to the fee instead


class InsufficientFunds(Exception):
    pass


def parse_dovc(text: str) -> int:
    """Parse a DOVC amount such as '1.5' into base units (at most 8 decimals)."""
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ValueError(f"not a number: {text!r}")
    units = value * P.UNITS_PER_DOVC
    if units != units.to_integral_value() or units <= 0:
        raise ValueError("amount must be positive with at most 8 decimal places")
    return int(units)


def format_dovc(units: int) -> str:
    return f"{units // P.UNITS_PER_DOVC}.{units % P.UNITS_PER_DOVC:08d}"


def save_wallet(wallet: Wallet, path: str) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"{path} already exists; refusing to overwrite a wallet")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"seckey": wallet.seckey.hex(), "address": wallet.address}, f, indent=2)


def load_wallet(path: str) -> Wallet:
    with open(path) as f:
        data = json.load(f)
    return Wallet(bytes.fromhex(data["seckey"]), data["address"].rpartition("1")[0])


def classify(utxo: dict, tip_height: int) -> str:
    """'spendable', 'immature' (coinbase) or 'locked' (timelock) for a UTXO dict from the RPC."""
    nxt = tip_height + 1
    if utxo["coinbase"] and nxt - utxo["created_height"] < P.COINBASE_MATURITY:
        return "immature"
    if utxo["lock_type"] == P.LOCK_P2PKH_HEIGHT and nxt < utxo["unlock_height"]:
        return "locked"
    return "spendable"


def build_payment(wallet: Wallet, utxos: list, tip_height: int, to_payload: bytes,
                  amount: int, fee_rate: int = P.MIN_RELAY_FEE_PER_BYTE) -> Tx:
    """Select coins, add change, set the fee by transaction size, and sign."""
    spendable = sorted((u for u in utxos if classify(u, tip_height) == "spendable"),
                       key=lambda u: u["value"], reverse=True)

    def assemble(chosen, fee):
        total = sum(u["value"] for u in chosen)
        change = total - amount - fee
        outs = [TxOut(amount, P.LOCK_P2PKH, to_payload)]
        if change >= DUST_UNITS:
            outs.append(TxOut(change, P.LOCK_P2PKH, wallet.payload))
        tx = Tx(inputs=[TxIn(bytes.fromhex(u["txid"]), u["index"]) for u in chosen], outputs=outs)
        for txin in tx.inputs:
            txin.pubkey = wallet.pubkey
        return tx, total, change

    chosen, total = [], 0
    for u in spendable:
        chosen.append(u)
        total += u["value"]
        fee = 0
        for _ in range(3):                         # fee depends on size, size on change: settle it
            tx, _, change = assemble(chosen, fee)
            fee = len(tx.serialize()) * fee_rate
        if total >= amount + fee:
            tx, _, change = assemble(chosen, fee)
            if change < 0:
                continue
            return wallet.sign(tx)
    raise InsufficientFunds("not enough spendable coins (immature and timelocked coins can't be spent yet)")
