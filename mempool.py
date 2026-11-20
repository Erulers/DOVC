"""Mempool: transactions waiting to be mined.

Policy (not consensus): a transaction must pay at least P.MIN_RELAY_FEE_PER_BYTE base
units per byte, must not be huge, and must not conflict with another pending transaction.
"""

from dataclasses import dataclass
from typing import Iterable, List

from . import params as P
from .chain import BlockError, Chain, Tx, UtxoOverlay, check_and_apply_tx

MAX_TX_BYTES = 100_000
MAX_POOL_TXS = 5_000


@dataclass
class _Entry:
    tx: Tx
    fee: int
    size: int
    order: int

    @property
    def fee_rate(self) -> int:
        return self.fee * 1_000_000 // self.size


class Mempool:
    def __init__(self):
        self.txs = {}            # txid -> _Entry
        self.view = {}           # UTXO set as it would look after every pending transaction
        self._counter = 0

    def __len__(self) -> int:
        return len(self.txs)

    def __contains__(self, txid: bytes) -> bool:
        return txid in self.txs

    def get(self, txid: bytes):
        entry = self.txs.get(txid)
        return entry.tx if entry else None

    def add(self, tx: Tx, chain: Chain) -> int:
        """Validate and add a transaction.  Returns the fee.  Raises BlockError if rejected."""
        txid = tx.txid()
        if txid in self.txs:
            raise BlockError("already in the mempool")
        size = len(tx.serialize())
        if size > MAX_TX_BYTES:
            raise BlockError("transaction is too large")
        if len(self.txs) >= MAX_POOL_TXS:
            raise BlockError("mempool is full")

        height = chain.height + 1
        needed = {}
        for txin in tx.inputs:
            op = (txin.prev_txid, txin.index)
            if op in self.view:
                needed[op] = self.view[op]
        local = dict(needed)
        fee = check_and_apply_tx(local, tx, height)
        if fee < size * P.MIN_RELAY_FEE_PER_BYTE:
            raise BlockError("fee is below the relay floor")

        for op in needed:
            del self.view[op]
        for op, utxo in local.items():
            if op not in needed:
                self.view[op] = utxo
        self._counter += 1
        self.txs[txid] = _Entry(tx, fee, size, self._counter)
        return fee

    def reset(self, chain: Chain, extra: Iterable[Tx] = ()) -> None:
        """Rebuild after the tip changed: re-check everything against the new best chain.

        `extra` holds transactions from blocks that just left the best chain; they go
        first because they are older than anything already pending.
        """
        old = [e.tx for e in sorted(self.txs.values(), key=lambda e: e.order)]
        fresh = Mempool()                        # build the new state aside, then swap it in,
        fresh.view = UtxoOverlay(chain.utxos())  # so a reader never sees a half-empty pool
        for tx in list(extra) + old:
            try:
                fresh.add(tx, chain)
            except BlockError:
                pass
        self.view, self._counter, self.txs = fresh.view, fresh._counter, fresh.txs

    def select(self, chain: Chain, max_bytes: int = P.MAX_BLOCK_BYTES - 2_000) -> List[Tx]:
        """Pick transactions for a block: highest fee rate first, parents before children."""
        height = chain.height + 1
        view = UtxoOverlay(chain.utxos())
        pending = sorted(self.txs.values(), key=lambda e: e.fee_rate, reverse=True)
        chosen: List[Tx] = []
        used = 0
        progress = True
        while progress and pending:
            progress = False
            remaining = []
            for entry in pending:
                if used + entry.size > max_bytes:
                    continue
                try:
                    check_and_apply_tx(view, entry.tx, height, verify_sigs=False)
                except BlockError:
                    remaining.append(entry)      # may become valid once its parent is chosen
                    continue
                chosen.append(entry.tx)
                used += entry.size
                progress = True
            pending = remaining
        return chosen

    def summary(self) -> list:
        return [{"txid": txid.hex(), "fee": e.fee, "size": e.size}
                for txid, e in sorted(self.txs.items(), key=lambda kv: kv[1].order)]
