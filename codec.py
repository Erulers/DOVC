"""Parsing of transactions, headers and blocks from their binary form.

The writing side lives in chain.py (Tx.serialize, Block.serialize).  Every parse
error raises ValueError, which the network layer treats as a misbehaving peer.
"""

import struct
from typing import List

from . import params as P
from .chain import Block, Header, Tx, TxIn, TxOut

HEADER_SIZE = 80


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("unexpected end of data")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def varint(self) -> int:
        first = self.u8()
        if first < 0xFD:
            return first
        if first == 0xFD:
            return struct.unpack("<H", self.read(2))[0]
        if first == 0xFE:
            return struct.unpack("<I", self.read(4))[0]
        return struct.unpack("<Q", self.read(8))[0]

    def count(self, min_item_bytes: int) -> int:
        """A varint item count, bounded by how much data is left (stops memory abuse)."""
        n = self.varint()
        if n * min_item_bytes > self.remaining():
            raise ValueError("item count larger than the data")
        return n


def read_tx(r: Reader) -> Tx:
    version = r.u32()
    inputs = []
    for _ in range(r.count(32 + 4 + 32 + 64)):
        prev = r.read(32)
        index = r.u32()
        pubkey = r.read(32)
        sig = r.read(64)
        inputs.append(TxIn(prev, index, pubkey, sig))
    outputs = []
    for _ in range(r.count(8 + 1 + 32)):
        value = r.u64()
        lock_type = r.u8()
        payload = r.read(32)
        unlock = r.u32() if lock_type == P.LOCK_P2PKH_HEIGHT else 0
        outputs.append(TxOut(value, lock_type, payload, unlock))
    data_len = r.varint()
    if data_len > P.MAX_COINBASE_DATA:
        raise ValueError("coinbase data too long")
    coinbase_data = r.read(data_len)
    return Tx(inputs, outputs, version, coinbase_data)


def parse_tx(data: bytes) -> Tx:
    r = Reader(data)
    tx = read_tx(r)
    if r.remaining():
        raise ValueError("trailing bytes after transaction")
    return tx


def parse_header(data: bytes) -> Header:
    if len(data) != HEADER_SIZE:
        raise ValueError("bad header size")
    version, prev, merkle, ts, nonce = struct.unpack("<I32s32sIQ", data)
    return Header(version, prev, merkle, ts, nonce)


def parse_block(data: bytes) -> Block:
    if len(data) > P.MAX_BLOCK_BYTES:
        raise ValueError("block too large")
    r = Reader(data)
    header = parse_header(r.read(HEADER_SIZE))
    txs: List[Tx] = [read_tx(r) for _ in range(r.count(4 + 1 + 1 + 1))]
    if r.remaining():
        raise ValueError("trailing bytes after block")
    return Block(header, txs)
