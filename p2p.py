"""Peer-to-peer networking for Dove.

Wire format (every message):  magic(4) | command(12, NUL padded) | length(4) | checksum(4) | payload
checksum = first 4 bytes of SHA-256d(payload).  One thread per connection.

Messages: version, verack, ping, pong, inv, getdata, tx, block, getheaders, headers,
getaddr, addr.  The semantics live in node.py; this module only moves bytes.
"""

import os
import socket
import struct
import threading
import time
from typing import Callable, List, Optional, Tuple

from .chain import sha256d

MAGIC = b"DOVE"                      # network magic bytes [chosen default - review]
DEFAULT_PORT = 8833                  # [chosen default - review]
PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 4_000_000
MAX_INBOUND = 16
MAX_OUTBOUND = 8
MAX_CONTROL_MESSAGES_PER_SEC = 500     # block/headers/tx are exempt (their cost is bounded elsewhere)
BAN_SECONDS = 600

_HEADER = struct.Struct("<4s12sI4s")


class ProtocolError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    while n:
        chunk = sock.recv(min(n, 65536))
        if not chunk:
            raise ConnectionError("connection closed")
        chunks.append(chunk)
        n -= len(chunk)
    return b"".join(chunks)


def encode_message(command: str, payload: bytes = b"", magic: bytes = MAGIC) -> bytes:
    cmd = command.encode("ascii")
    return _HEADER.pack(magic, cmd.ljust(12, b"\0"), len(payload), sha256d(payload)[:4]) + payload


class Peer:
    def __init__(self, network: "Network", sock: socket.socket, addr: Tuple[str, int], inbound: bool):
        self.network = network
        self.sock = sock
        self.addr = addr
        self.inbound = inbound
        self.send_lock = threading.Lock()
        self.alive = True
        self.got_version = False
        self.got_verack = False
        self.ready = False                    # handshake finished
        self.height = 0
        self.listen_port: Optional[int] = None
        self.pending_blocks: set = set()      # block ids we asked this peer for
        self.thread: Optional[threading.Thread] = None

    @property
    def name(self) -> str:
        return f"{self.addr[0]}:{self.addr[1]}"

    def advertised(self) -> Optional[Tuple[str, int]]:
        """Where other nodes can reach this peer (its listening port), if known."""
        if self.listen_port is None:
            return None
        return (self.addr[0], self.listen_port)

    def send(self, command: str, payload: bytes = b"") -> bool:
        if not self.alive:
            return False
        try:
            with self.send_lock:
                self.sock.sendall(encode_message(command, payload, self.network.magic))
            return True
        except OSError:
            self.close()
            return False

    def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.network.remove_peer(self)

    def run(self) -> None:
        window_start, window_count = time.time(), 0
        try:
            while self.alive:
                header = _recv_exact(self.sock, _HEADER.size)
                magic, cmd, length, checksum = _HEADER.unpack(header)
                if magic != self.network.magic:
                    raise ProtocolError("wrong network magic")
                if length > MAX_MESSAGE_BYTES:
                    raise ProtocolError("message too large")
                payload = _recv_exact(self.sock, length) if length else b""
                if sha256d(payload)[:4] != checksum:
                    raise ProtocolError("bad checksum")
                command = cmd.rstrip(b"\0").decode("ascii", "replace")
                if command not in ("block", "headers", "tx"):
                    now = time.time()
                    if now - window_start >= 1:
                        window_start, window_count = now, 0
                    window_count += 1
                    if window_count > MAX_CONTROL_MESSAGES_PER_SEC:
                        raise ProtocolError("too many messages")
                self.network.on_message(self, command, payload)
        except ProtocolError:
            self.network.ban(self.addr[0])
        except (ConnectionError, OSError, ValueError, struct.error):
            pass
        finally:
            self.close()


class Network:
    def __init__(self, host: str, port: int, on_message: Callable, on_disconnect: Callable = None,
                 magic: bytes = MAGIC):
        self.host = host
        self.magic = magic
        self.banned: dict = {}               # ip -> time the ban ends
        self.port = port
        self.on_message = on_message
        self.on_disconnect = on_disconnect or (lambda peer: None)
        self.nonce = int.from_bytes(os.urandom(8), "big")
        self.peers: List[Peer] = []
        self.lock = threading.Lock()
        self.known_addrs: set = set()
        self._server: Optional[socket.socket] = None
        self._running = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self._running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(32)
        self.port = server.getsockname()[1]      # supports port 0 (pick a free port)
        self._server = server
        threading.Thread(target=self._accept_loop, daemon=True, name="p2p-accept").start()

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        for peer in list(self.peers):
            peer.close()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                sock, addr = self._server.accept()
            except OSError:
                return
            if self.is_banned(addr[0]):
                sock.close()
                continue
            with self.lock:
                inbound = sum(1 for p in self.peers if p.inbound)
            if inbound >= MAX_INBOUND:
                sock.close()
                continue
            self._add_peer(sock, addr, inbound=True)

    # -- peers -------------------------------------------------------------
    def _add_peer(self, sock: socket.socket, addr, inbound: bool) -> Peer:
        peer = Peer(self, sock, addr, inbound)
        with self.lock:
            self.peers.append(peer)
        peer.thread = threading.Thread(target=peer.run, daemon=True, name=f"peer-{peer.name}")
        peer.thread.start()
        self.on_connect(peer)
        return peer

    def on_connect(self, peer: Peer) -> None:
        self.on_message(peer, "__connected__", b"")

    def connect(self, host: str, port: int) -> Optional[Peer]:
        """Open an outbound connection; returns None if it fails or already exists."""
        if self.is_banned(host):
            return None
        with self.lock:
            outbound = sum(1 for p in self.peers if not p.inbound)
            for p in self.peers:
                if p.advertised() == (host, port) or p.addr == (host, port):
                    return None
        if outbound >= MAX_OUTBOUND or (port == self.port and host in ("127.0.0.1", "localhost", self.host)):
            return None
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.settimeout(None)
        except OSError:
            return None
        peer = self._add_peer(sock, (host, port), inbound=False)
        peer.listen_port = port
        return peer

    def ban(self, ip: str, seconds: int = BAN_SECONDS) -> None:
        """Refuse connections from an address for a while.  Loopback is never banned."""
        if ip.startswith("127.") or ip == "::1":
            return
        self.banned[ip] = time.time() + seconds

    def is_banned(self, ip: str) -> bool:
        until = self.banned.get(ip)
        if until is None:
            return False
        if until <= time.time():
            del self.banned[ip]
            return False
        return True

    def remove_peer(self, peer: Peer) -> None:
        with self.lock:
            if peer in self.peers:
                self.peers.remove(peer)
        self.on_disconnect(peer)

    def broadcast(self, command: str, payload: bytes, exclude: Optional[Peer] = None) -> None:
        with self.lock:
            targets = [p for p in self.peers if p.ready and p is not exclude]
        for peer in targets:
            peer.send(command, payload)

    def ready_peers(self) -> List[Peer]:
        with self.lock:
            return [p for p in self.peers if p.ready]
