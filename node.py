"""A Dove full node: validates and stores blocks, relays them, keeps a mempool, can mine,
and serves a small local HTTP RPC for wallets.

Concurrency model: one global RLock (`node.lock`) guards the chain, mempool and orphan
pool.  Network threads take it while handling a message; the miner takes it only to
build a template and to submit a found block, so hashing never blocks the node.
"""

import hmac
import json
import os
import secrets
import struct
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import params as P
from . import schedule
from .chain import (Block, BlockError, Chain, Header, Tx, load_dev_payloads, pow_hash,
                    sha256d, varint)
from .codec import HEADER_SIZE, Reader, parse_block, parse_header, parse_tx
from .mempool import Mempool
from .p2p import DEFAULT_PORT, PROTOCOL_VERSION, Network, Peer
from .storage import BlockStore
from .wallet import address_to_payload

INV_TX = 1
INV_BLOCK = 2
MAX_ORPHANS = 100
HEADERS_BATCH = 500


def _enc_items(items) -> bytes:
    return varint(len(items)) + b"".join(struct.pack("<B", t) + i for t, i in items)


def _dec_items(payload: bytes):
    r = Reader(payload)
    return [(r.u8(), r.read(32)) for _ in range(r.count(33))]


class Node:
    def __init__(self, datadir: str, host: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 rpc_port: Optional[int] = 8832, pow_memory_kib: Optional[int] = None,
                 seeds=(), mine_payload: Optional[bytes] = None, mine_threads: int = 1,
                 coinbase_data: bytes = b"", verbose: bool = False, network: str = "main"):
        self.datadir = datadir
        self.net_name = network
        self.rpc_token: Optional[str] = None
        self.verbose = verbose
        self.lock = threading.RLock()
        self.events: List[str] = []
        self.seeds = list(seeds)
        self.mine_payload = mine_payload
        self.mine_threads = max(1, mine_threads)
        self.coinbase_data = coinbase_data
        self._running = False
        self._mining = False
        self.orphans = {}                         # parent id -> [blocks waiting for it]
        self.seen_txids: "OrderedDict[bytes, bool]" = OrderedDict()

        self.store = BlockStore(datadir)
        self.chain = Chain(pow_memory_kib, network)
        self.mempool = Mempool()
        self._load_from_disk()

        self.network = Network(host, port, self.on_message, self.on_disconnect,
                               magic=P.NETWORKS[network]["magic"])
        self.rpc_port = rpc_port
        self._rpc: Optional[ThreadingHTTPServer] = None
        self.placeholder_dev_keys = load_dev_payloads()[1]

    # ------------------------------------------------------------------ logging
    def log(self, msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        self.events.append(line)
        del self.events[:-200]
        if self.verbose:
            print(line, file=sys.stderr, flush=True)

    # ------------------------------------------------------------------ startup
    def _load_from_disk(self) -> None:
        count = 0
        for block in self.store.load():
            try:
                self.chain.add_block(block, trusted=True)
                count += 1
            except BlockError as exc:
                self.log(f"skipping stored block: {exc}")
        self.mempool.reset(self.chain)
        if count:
            self.log(f"loaded {count} blocks from disk, height {self.chain.height}")

    def start(self) -> None:
        self._running = True
        self.network.start()
        if self.rpc_port is not None:
            self._start_rpc()
        threading.Thread(target=self._maintain_peers, daemon=True, name="maintain").start()
        if self.mine_payload is not None:
            self.start_mining()
        self.log(f"node started: p2p {self.network.port}, rpc {self.rpc_port}")
        if self.placeholder_dev_keys:
            self.log("WARNING: genesis uses PLACEHOLDER developer keys (run `devkeys` before launch)")

    def stop(self) -> None:
        self._running = False
        self._mining = False
        self.network.stop()
        if self._rpc:
            self._rpc.shutdown()
            self._rpc.server_close()

    def _maintain_peers(self) -> None:
        """Keep trying the configured seeds while we have no ready peers."""
        while self._running:
            if not self.network.ready_peers():
                for host, port in self.seeds:
                    if not self._running:
                        return
                    self.network.connect(host, port)
            for _ in range(100):
                if not self._running:
                    return
                time.sleep(0.1)

    # ------------------------------------------------------------------ p2p handlers
    def _version_payload(self) -> bytes:
        return struct.pack("<II32sQH", PROTOCOL_VERSION, self.chain.height, self.chain.genesis_id,
                           self.network.nonce, self.network.port)

    def on_disconnect(self, peer: Peer) -> None:
        pass

    def on_message(self, peer: Peer, command: str, payload: bytes) -> None:
        if command == "__connected__":
            peer.send("version", self._version_payload())
            return
        try:
            with self.lock:
                self._dispatch(peer, command, payload)
        except (ValueError, struct.error) as exc:
            self.log(f"dropping {peer.name}: malformed {command}: {exc}")
            self.network.ban(peer.addr[0])
            peer.close()

    def _dispatch(self, peer: Peer, command: str, payload: bytes) -> None:
        if command == "version":
            if peer.got_version:
                raise ValueError("duplicate version")
            proto, height, genesis, nonce, port = struct.unpack("<II32sQH", payload)
            if proto != PROTOCOL_VERSION or genesis != self.chain.genesis_id:
                self.log(f"dropping {peer.name}: different network")
                peer.close()
                return
            if nonce == self.network.nonce:
                peer.close()                       # we connected to ourselves
                return
            peer.height = height
            if peer.inbound:
                peer.listen_port = port
            peer.got_version = True
            peer.send("verack")
            self._maybe_ready(peer)
            return
        if command == "verack":
            peer.got_verack = True
            self._maybe_ready(peer)
            return
        if not peer.ready:
            raise ValueError("message before handshake finished")

        if command == "ping":
            peer.send("pong", payload)
        elif command == "pong":
            pass
        elif command == "getaddr":
            addrs = [f"{h}:{p}" for h, p in self._known_addresses()][:50]
            peer.send("addr", json.dumps(addrs).encode())
        elif command == "addr":
            self._on_addr(peer, payload)
        elif command == "getheaders":
            r = Reader(payload)
            locator = [r.read(32) for _ in range(r.count(32))]
            headers = self.chain.headers_after(locator, HEADERS_BATCH)
            peer.send("headers", varint(len(headers)) + b"".join(h.serialize() for h in headers))
        elif command == "headers":
            self._on_headers(peer, payload)
        elif command == "inv":
            self._on_inv(peer, payload)
        elif command == "getdata":
            for kind, ident in _dec_items(payload):
                if kind == INV_TX:
                    tx = self.mempool.get(ident)
                    if tx is not None:
                        peer.send("tx", tx.serialize())
                elif kind == INV_BLOCK:
                    block = self.chain.block_by_id(ident)
                    if block is not None:
                        peer.send("block", block.serialize())
        elif command == "block":
            self._on_block(peer, payload)
        elif command == "tx":
            tx = parse_tx(payload)
            try:
                self.accept_tx(tx, source=peer)
            except BlockError as exc:
                self.log(f"tx from {peer.name} rejected: {exc}")
        # unknown commands are ignored

    def _maybe_ready(self, peer: Peer) -> None:
        if peer.got_version and peer.got_verack and not peer.ready:
            peer.ready = True
            self.log(f"peer ready: {peer.name} (height {peer.height})")
            adv = peer.advertised()
            if adv:
                self.network.known_addrs.add(adv)
            peer.send("getaddr")
            if peer.height > self.chain.height:
                self._request_headers(peer)
            pool = list(self.mempool.txs)
            if pool:
                peer.send("inv", _enc_items([(INV_TX, t) for t in pool[:500]]))

    def _known_addresses(self):
        addrs = set(self.network.known_addrs)
        for p in self.network.ready_peers():
            if p.advertised():
                addrs.add(p.advertised())
        return sorted(addrs)

    def _on_addr(self, peer: Peer, payload: bytes) -> None:
        for text in json.loads(payload.decode())[:50]:
            host, _, port = str(text).rpartition(":")
            if not host or not port.isdigit():
                continue
            addr = (host, int(port))
            self.network.known_addrs.add(addr)
            if len([p for p in self.network.peers if not p.inbound]) < 8:
                threading.Thread(target=self.network.connect, args=addr, daemon=True).start()

    def _request_headers(self, peer: Peer, locator: Optional[List[bytes]] = None) -> None:
        locator = locator or self.chain.locator()
        peer.send("getheaders", varint(len(locator)) + b"".join(locator))

    def _on_headers(self, peer: Peer, payload: bytes) -> None:
        r = Reader(payload)
        headers = [parse_header(r.read(HEADER_SIZE)) for _ in range(r.count(HEADER_SIZE))]
        if not headers:
            return
        ids = [sha256d(h.serialize()) for h in headers]
        wanted = [i for i in ids if i not in self.chain.entries and i not in peer.pending_blocks]
        if wanted:
            peer.pending_blocks.update(wanted)
            peer.send("getdata", _enc_items([(INV_BLOCK, i) for i in wanted]))
        elif len(headers) >= HEADERS_BATCH:
            self._request_headers(peer, [ids[-1]])     # we already have this batch; ask for more

    def _on_inv(self, peer: Peer, payload: bytes) -> None:
        want = []
        for kind, ident in _dec_items(payload):
            if kind == INV_BLOCK and ident not in self.chain.entries and ident not in peer.pending_blocks:
                want.append((kind, ident))
                peer.pending_blocks.add(ident)
            elif kind == INV_TX and ident not in self.mempool and ident not in self.seen_txids:
                want.append((kind, ident))
        if want:
            peer.send("getdata", _enc_items(want[:500]))

    def _on_block(self, peer: Peer, payload: bytes) -> None:
        block = parse_block(payload)
        bid = block.block_id()
        peer.pending_blocks.discard(bid)
        try:
            status = self.accept_block(block, source=peer)
        except BlockError as exc:
            self.log(f"invalid block from {peer.name}: {exc}")
            self.network.ban(peer.addr[0])
            peer.close()
            return
        if status == "orphan":
            self._request_headers(peer)
        elif not peer.pending_blocks and peer.height > self.chain.height:
            self._request_headers(peer)               # keep syncing until we catch up

    # ------------------------------------------------------------------ accepting data
    def accept_block(self, block: Block, source: Optional[Peer] = None) -> str:
        """Validate, store and relay a block.  Returns 'known', 'orphan' or 'accepted'.

        Raises BlockError for an invalid block.
        """
        with self.lock:
            bid = block.block_id()
            if bid in self.chain.entries:
                return "known"
            old_best = self.chain.best_id
            try:
                became_best = self.chain.add_block(block)
            except BlockError as exc:
                if str(exc) == "unknown parent block":
                    if sum(len(v) for v in self.orphans.values()) < MAX_ORPHANS:
                        self.orphans.setdefault(block.header.prev_hash, []).append(block)
                    return "orphan"
                raise
            self.store.append(block)
            height = self.chain.entries[bid].height
            self.log(f"block {height} {bid.hex()[:16]} accepted"
                     f"{' (new tip)' if became_best else ' (side branch)'}")
            if became_best:
                self._tip_changed(old_best)
            self.network.broadcast("inv", _enc_items([(INV_BLOCK, bid)]), exclude=source)
            for child in self.orphans.pop(bid, []):
                try:
                    self.accept_block(child, source)
                except BlockError as exc:
                    self.log(f"orphan block rejected: {exc}")
            return "accepted"

    def _tip_changed(self, old_best: bytes) -> None:
        """Update the mempool after the best chain changed (including reorganizations)."""
        returned: List[Tx] = []
        cur = old_best
        while cur is not None:
            entry = self.chain.entries[cur]
            if self.chain.height_index[entry.height] == cur:
                break                                   # reached the common ancestor
            returned.extend(t for t in entry.block.txs[1:])
            cur = entry.parent_id
        if returned:
            self.log(f"reorganization: returning {len(returned)} transaction(s) to the mempool")
        returned.reverse()
        self.mempool.reset(self.chain, returned)

    def accept_tx(self, tx: Tx, source: Optional[Peer] = None) -> int:
        """Add a transaction to the mempool and relay it.  Raises BlockError if rejected."""
        with self.lock:
            txid = tx.txid()
            fee = self.mempool.add(tx, self.chain)
            self.seen_txids[txid] = True
            while len(self.seen_txids) > 10_000:
                self.seen_txids.popitem(last=False)
            self.log(f"tx {txid.hex()[:16]} accepted into the mempool (fee {fee})")
            self.network.broadcast("inv", _enc_items([(INV_TX, txid)]), exclude=source)
            return fee

    # ------------------------------------------------------------------ mining
    def start_mining(self) -> None:
        if self.mine_payload is None:
            raise ValueError("no mining address configured")
        if self._mining:
            return
        self._mining = True
        threading.Thread(target=self._mine_loop, daemon=True, name="miner").start()

    def stop_mining(self) -> None:
        self._mining = False

    @property
    def mining(self) -> bool:
        return self._mining

    def _mine_loop(self) -> None:
        while self._mining and self._running:
            with self.lock:
                tip_id = self.chain.best_id
                txs = self.mempool.select(self.chain)
                block = self.chain.build_block(self.mine_payload, txs, coinbase_data=self.coinbase_data)
                target = schedule.target_for_height(self.chain.height + 1)
                memory = self.chain.pow_memory_kib
                pool_size = len(self.mempool)
            found = self._search(block, target, memory, tip_id, pool_size)
            if found is None:
                continue
            with self.lock:
                if self.chain.best_id != tip_id:
                    continue
                try:
                    self.accept_block(found)
                except BlockError as exc:
                    self.log(f"our own block was rejected: {exc}")

    def _search(self, block: Block, target: int, memory: int, tip_id: bytes, pool_size: int):
        """Run mining workers until a nonce is found or the template goes stale."""
        h = block.header
        prefix = struct.pack("<I32s32sI", h.version, h.prev_hash, h.merkle_root, h.timestamp)
        found: List[int] = []
        stop = threading.Event()
        start = int.from_bytes(os.urandom(4), "big")

        def worker(offset: int) -> None:
            nonce = start + offset
            while not stop.is_set():
                digest = pow_hash(prefix + struct.pack("<Q", nonce), memory)
                if int.from_bytes(digest, "big") <= target:
                    found.append(nonce)
                    stop.set()
                    return
                nonce += self.mine_threads

        workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(self.mine_threads)]
        for t in workers:
            t.start()
        deadline = time.time() + 20
        while not stop.is_set():
            time.sleep(0.02)
            if (self.chain.best_id != tip_id or not self._mining or not self._running
                    or time.time() > deadline or len(self.mempool) != pool_size):
                stop.set()
        for t in workers:
            t.join()
        if found:
            block.header.nonce = found[0]
            return block
        return None

    # ------------------------------------------------------------------ queries (RPC)
    def status(self) -> dict:
        with self.lock:
            height = self.chain.height
            nxt = height + 1
            stage, _ = schedule.stage_of(nxt)
            return {
                "height": height,
                "best_block": self.chain.best_id.hex(),
                "genesis": self.chain.genesis_id.hex(),
                "peers": len(self.network.ready_peers()),
                "mempool": len(self.mempool),
                "mining": self._mining,
                "next_stage": stage,
                "next_difficulty": schedule.difficulty_q64(nxt) / 2 ** 64,
                "next_reward_units": schedule.subsidy(nxt),
                "placeholder_dev_keys": self.placeholder_dev_keys,
                "p2p_port": self.network.port,
                "network": self.net_name,
                "version": __version__,
            }

    def utxos_for(self, payload: bytes) -> list:
        with self.lock:
            return [{"txid": op[0].hex(), "index": op[1], "value": u.value,
                     "created_height": u.created_height, "coinbase": u.is_coinbase,
                     "lock_type": u.lock_type, "unlock_height": u.unlock_height}
                    for op, u in self.chain.utxos().items() if u.payload == payload]

    def block_json(self, block: Block, height: int) -> dict:
        return {
            "height": height, "id": block.block_id().hex(), "prev": block.header.prev_hash.hex(),
            "timestamp": block.header.timestamp, "nonce": block.header.nonce,
            "size": block.size(),
            "txs": [{"txid": t.txid().hex(), "coinbase": t.is_coinbase(),
                     "outputs": [{"value": o.value, "payload": o.payload.hex()} for o in t.outputs],
                     "message": t.coinbase_data.decode("utf-8", "replace") if t.coinbase_data else ""}
                    for t in block.txs],
        }

    # ------------------------------------------------------------------ RPC server
    def _start_rpc(self) -> None:
        node = self
        token_path = os.path.join(self.datadir, "rpc.token")
        if os.path.exists(token_path):
            with open(token_path) as f:
                self.rpc_token = f.read().strip()
        else:
            self.rpc_token = secrets.token_hex(32)
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(self.rpc_token)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):          # keep the console quiet
                pass

            def _authorized(self) -> bool:
                given = self.headers.get("Authorization", "")
                return hmac.compare_digest(given.encode(), f"Bearer {node.rpc_token}".encode())

            def _send(self, code: int, body) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                url = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                try:
                    if url.path == "/status":
                        self._send(200, node.status())
                    elif url.path == "/utxos":
                        payload = address_to_payload(q.get("address", ""))
                        if payload is None:
                            self._send(400, {"error": "invalid address"})
                            return
                        self._send(200, {"height": node.chain.height, "utxos": node.utxos_for(payload)})
                    elif url.path == "/mempool":
                        with node.lock:
                            self._send(200, node.mempool.summary())
                    elif url.path == "/peers":
                        self._send(200, [{"addr": p.name, "height": p.height, "inbound": p.inbound}
                                         for p in node.network.ready_peers()])
                    elif url.path == "/block":
                        with node.lock:
                            if "height" in q:
                                h = int(q["height"])
                                block = node.chain.block_at_height(h)
                            else:
                                blk = node.chain.block_by_id(bytes.fromhex(q.get("id", "")))
                                block, h = blk, (node.chain.entries[blk.block_id()].height if blk else 0)
                            if block is None:
                                self._send(404, {"error": "no such block"})
                            else:
                                self._send(200, node.block_json(block, h))
                    else:
                        self._send(404, {"error": "unknown endpoint"})
                except (ValueError, KeyError) as exc:
                    self._send(400, {"error": str(exc)})

            def do_POST(self):
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                    if self.path == "/tx":
                        tx = parse_tx(bytes.fromhex(body["hex"]))
                        fee = node.accept_tx(tx)
                        self._send(200, {"txid": tx.txid().hex(), "fee": fee})
                    elif self.path == "/connect":
                        peer = node.network.connect(body["host"], int(body["port"]))
                        self._send(200, {"connected": peer is not None})
                    elif self.path == "/mine":
                        node.start_mining() if body.get("on", True) else node.stop_mining()
                        self._send(200, {"mining": node.mining})
                    else:
                        self._send(404, {"error": "unknown endpoint"})
                except BlockError as exc:
                    self._send(400, {"error": str(exc)})
                except (ValueError, KeyError) as exc:
                    self._send(400, {"error": f"bad request: {exc}"})

        server = ThreadingHTTPServer(("127.0.0.1", self.rpc_port), Handler)
        self.rpc_port = server.server_address[1]
        self._rpc = server
        threading.Thread(target=server.serve_forever, daemon=True, name="rpc").start()
