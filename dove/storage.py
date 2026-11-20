"""Append-only block storage.

Every block the node accepts (including side branches) is appended to
`blocks.dat`, so replaying the file in order always has parents before children.
A torn write at the tail (power loss mid-write) is detected and cut off on load.
"""

import os
import struct
from typing import Iterator

from .chain import Block
from .codec import parse_block

RECORD_MAGIC = b"DOVB"


class BlockStore:
    def __init__(self, datadir: str):
        os.makedirs(datadir, exist_ok=True)
        self.path = os.path.join(datadir, "blocks.dat")
        open(self.path, "ab").close()

    def append(self, block: Block) -> None:
        raw = block.serialize()
        with open(self.path, "ab") as f:
            f.write(RECORD_MAGIC + struct.pack("<I", len(raw)) + raw)
            f.flush()
            os.fsync(f.fileno())

    def load(self) -> Iterator[Block]:
        """Yield stored blocks in order; truncate a damaged tail if one is found."""
        good_end = 0
        with open(self.path, "rb") as f:
            data = f.read()
        pos = 0
        while pos + 8 <= len(data):
            if data[pos:pos + 4] != RECORD_MAGIC:
                break
            (size,) = struct.unpack("<I", data[pos + 4:pos + 8])
            if pos + 8 + size > len(data):
                break
            try:
                block = parse_block(data[pos + 8:pos + 8 + size])
            except ValueError:
                break
            pos += 8 + size
            good_end = pos
            yield block
        if good_end < len(data):
            with open(self.path, "r+b") as f:
                f.truncate(good_end)
