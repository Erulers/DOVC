"""Command-line interface:  dove <command> ...   (or: python -m dove <command> ...)

    node      run a full node (optionally mining)
    wallet    new / address / balance / send
    status    ask a running node how it is doing
    devkeys   generate the five developer payout keys (do this OFFLINE, once)
    genesis   print a network's genesis block

Use --network test for experiments: it has its own genesis, ports, address prefix (tdovc),
and a small proof-of-work memory, and nothing on it has any value.
"""

import argparse
import json
import os
import signal
import threading
import urllib.error
import urllib.request

from . import __version__
from . import chain as C
from . import params as P
from .node import Node
from .wallet import (InsufficientFunds, Wallet, address_to_payload, build_payment, classify,
                     format_dovc, load_wallet, parse_dovc, save_wallet)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def client_settings(args):
    """Fill in the datadir and RPC address for the chosen network."""
    cfg = P.NETWORKS[args.network]
    if args.datadir is None:
        args.datadir = "./dove-data" if args.network == "main" else "./dove-data-test"
    if args.rpc is None:
        args.rpc = f"127.0.0.1:{cfg['rpc_port']}"


def load_token(args) -> str:
    if args.rpc_token:
        return args.rpc_token
    if os.environ.get("DOVE_RPC_TOKEN"):
        return os.environ["DOVE_RPC_TOKEN"]
    path = os.path.join(args.datadir, "rpc.token")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    raise SystemExit(f"no RPC token found (looked in {path}); pass --datadir of the node "
                     f"or --rpc-token")


def rpc(args, path: str, body=None):
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {load_token(args)}"}
    req = urllib.request.Request(f"http://{args.rpc}{path}", headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = json.loads(exc.read() or b"{}").get("error", exc.reason)
        raise SystemExit(f"node refused: {detail}")
    except (urllib.error.URLError, OSError) as exc:
        raise SystemExit(f"cannot reach a node at {args.rpc}: {exc}")


def parse_hostport(text: str, default_port: int):
    host, _, port = text.rpartition(":")
    return (host, int(port)) if host else (text, default_port)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_node(args):
    cfg = P.NETWORKS[args.network]
    if args.datadir is None:
        args.datadir = "./dove-data" if args.network == "main" else "./dove-data-test"
    port = args.port or cfg["p2p_port"]
    rpc_port = args.rpc_port or cfg["rpc_port"]
    memory = args.memory_kib or cfg["pow_memory_kib"]

    if args.network == "main":
        if memory != P.POW_MEMORY_KIB:
            raise SystemExit(f"mainnet requires --memory-kib {P.POW_MEMORY_KIB}; "
                             f"use --network test for experiments")
        if C.load_dev_payloads()[1] and not args.allow_placeholder_keys:
            raise SystemExit(
                "Refusing to start a MAINNET node: the genesis block still uses the public "
                "PLACEHOLDER developer keys, so anyone could spend the locked coins.\n"
                "Generate real keys offline with `dove devkeys`, or use --network test.")

    payload = None
    if args.mine:
        payload = address_to_payload(args.mine, cfg["hrp"])
        if payload is None:
            raise SystemExit(f"--mine needs a valid {cfg['hrp']} address for this network")
    node = Node(
        datadir=args.datadir, host=args.host, port=port, rpc_port=rpc_port,
        pow_memory_kib=memory, seeds=[parse_hostport(s, cfg["p2p_port"]) for s in args.seed],
        mine_payload=payload, mine_threads=args.threads,
        coinbase_data=args.note.encode()[:P.MAX_COINBASE_DATA], verbose=not args.quiet,
        network=args.network,
    )
    node.start()
    print(f"Dove {__version__} ({args.network})   p2p :{node.network.port}   "
          f"rpc 127.0.0.1:{node.rpc_port}   data {args.datadir}", flush=True)
    print(f'Genesis: "{cfg["genesis_message"].decode()}"', flush=True)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    last = -1
    while not stop.wait(5):
        s = node.status()
        if s["height"] != last:
            print(f"height {s['height']}  stage {s['next_stage']}  peers {s['peers']}  "
                  f"mempool {s['mempool']}  mining {s['mining']}", flush=True)
            last = s["height"]
    print("shutting down...", flush=True)
    node.stop()


def cmd_wallet(args):
    if args.action == "new":
        wallet = Wallet(hrp=P.NETWORKS[args.network]["hrp"])
        save_wallet(wallet, args.file)
        print(f"Created {args.file}\nAddress: {wallet.address}")
        print("The file holds your secret key in plain text. Back it up and keep it private.")
        return
    wallet = load_wallet(args.file)
    client_settings(args)
    if args.action == "address":
        print(wallet.address)
    elif args.action == "balance":
        data = rpc(args, f"/utxos?address={wallet.address}")
        totals = {"spendable": 0, "immature": 0, "locked": 0}
        for u in data["utxos"]:
            totals[classify(u, data["height"])] += u["value"]
        print(f"Address {wallet.address}   (chain height {data['height']})")
        print(f"  spendable  {format_dovc(totals['spendable'])} DOVC")
        print(f"  immature   {format_dovc(totals['immature'])} DOVC   (mining rewards wait "
              f"{P.COINBASE_MATURITY} blocks)")
        print(f"  locked     {format_dovc(totals['locked'])} DOVC   (timelocked)")
    elif args.action == "send":
        if not args.to or not args.amount:
            raise SystemExit("send needs --to and --amount")
        payload = address_to_payload(args.to, wallet.hrp)
        if payload is None:
            raise SystemExit(f"invalid destination: it must be a {wallet.hrp} address for this network")
        data = rpc(args, f"/utxos?address={wallet.address}")
        try:
            tx = build_payment(wallet, data["utxos"], data["height"], payload,
                               parse_dovc(args.amount), args.fee_rate)
        except (InsufficientFunds, ValueError) as exc:
            raise SystemExit(str(exc))
        result = rpc(args, "/tx", {"hex": tx.serialize().hex()})
        print(f"Sent {args.amount} DOVC to {args.to}\n  txid {result['txid']}\n"
              f"  fee  {format_dovc(result['fee'])} DOVC")


def cmd_status(args):
    client_settings(args)
    print(json.dumps(rpc(args, "/status"), indent=2))


def cmd_devkeys(args):
    if "site-packages" in C.DEV_PAYLOAD_FILE.replace("\\", "/"):
        raise SystemExit(
            "This copy of Dove is installed into Python's library folder, so the public key file "
            "would be written to the wrong place.\nRun it from your project folder instead:\n"
            "    cd <the folder that contains the `dove` folder>\n    python -m dove devkeys")
    if os.path.exists(C.DEV_PAYLOAD_FILE) and not args.force:
        raise SystemExit(f"{C.DEV_PAYLOAD_FILE} already exists. Delete it or pass --force.")
    if os.path.exists(args.secret_file):
        raise SystemExit(f"{args.secret_file} already exists; refusing to overwrite")
    wallets = [Wallet() for _ in range(P.DEV_PAYOUT_PARTS)]
    fd = os.open(args.secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump([{"part": i + 1, "unlock_height": P.DEV_UNLOCK_HEIGHTS[i],
                    "address": w.address, "seckey": w.seckey.hex()}
                   for i, w in enumerate(wallets)], f, indent=2)
    with open(C.DEV_PAYLOAD_FILE, "w") as f:
        json.dump([w.payload.hex() for w in wallets], f, indent=2)
    print(f"Wrote {args.secret_file}  <- SECRET. Move it offline NOW and make backups.")
    print(f"Wrote {C.DEV_PAYLOAD_FILE}  (public; every node must use the same file)\n")
    for i, w in enumerate(wallets):
        print(f"  payout address: {w.address}   (spendable after {P.COINBASE_MATURITY} blocks)")
    print(f"\nMainnet genesis id: {C.make_genesis().block_id().hex()}")
    print("If this key is lost, the coins are gone forever.")


def cmd_setpayout(args):
    """Install the (public) genesis payout address, so the owner never has to edit files by hand."""
    if "site-packages" in C.DEV_PAYLOAD_FILE.replace("\\", "/"):
        raise SystemExit("Run this from your project folder (the one containing the `dove` folder): "
                         "python -m dove setpayout <address>")
    payload = address_to_payload(args.address, P.NETWORKS["main"]["hrp"])
    if payload is None:
        raise SystemExit("that is not a valid mainnet address (it must start with dovc1)")
    if os.path.exists(C.DEV_PAYLOAD_FILE) and not args.force:
        raise SystemExit(f"{C.DEV_PAYLOAD_FILE} already exists. Pass --force to replace it "
                         f"(this changes the genesis id).")
    with open(C.DEV_PAYLOAD_FILE, "w") as f:
        json.dump([payload.hex()], f, indent=2)
    g = C.make_genesis()
    print(f"Genesis payout set: {format_dovc(g.txs[0].outputs[0].value)} DOVC to {args.address}")
    print(f"Mainnet genesis id: {g.block_id().hex()}")


def cmd_genesis(args):
    g = C.make_genesis(args.network)
    placeholder = args.network == "main" and C.load_dev_payloads()[1]
    print(f"network   {args.network}")
    print(f"id        {g.block_id().hex()}")
    print(f"message   {P.NETWORKS[args.network]['genesis_message'].decode()}")
    print(f"size      {g.size()} bytes")
    for i, out in enumerate(g.txs[0].outputs):
        rule = (f"locked until height {out.unlock_height}" if out.unlock_height
                else f"spendable after {P.COINBASE_MATURITY} blocks")
        print(f"output {i}  {format_dovc(out.value)} DOVC  {rule}")
    if placeholder:
        print("\nWARNING: mainnet is using PLACEHOLDER developer keys. Run `dove devkeys` first.")


# ---------------------------------------------------------------------------

def add_network(sp):
    sp.add_argument("--network", choices=sorted(P.NETWORKS), default="main",
                    help="main (real) or test (worthless, for experiments)")


def add_client_options(sp):
    sp.add_argument("--rpc", default=None, help="node RPC host:port (default depends on --network)")
    sp.add_argument("--datadir", default=None, help="the node's data folder (holds rpc.token)")
    sp.add_argument("--rpc-token", default=None, help="RPC token (or set DOVE_RPC_TOKEN)")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dove", description="Dove (DOVC) node and wallet")
    ap.add_argument("--version", action="version", version=f"dove {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    n = sub.add_parser("node", help="run a full node")
    add_network(n)
    n.add_argument("--datadir", default=None)
    n.add_argument("--host", default="127.0.0.1", help="listen address (0.0.0.0 to accept outside peers)")
    n.add_argument("--port", type=int, default=None)
    n.add_argument("--rpc-port", type=int, default=None)
    n.add_argument("--seed", action="append", default=[], help="host[:port] of a peer to connect to")
    n.add_argument("--mine", metavar="ADDRESS", help="mine, paying rewards to this address")
    n.add_argument("--threads", type=int, default=1, help="mining threads")
    n.add_argument("--note", default="", help="short text placed in each block you mine")
    n.add_argument("--memory-kib", type=int, default=None,
                   help="Argon2id memory (testnet experiments only; mainnet is fixed)")
    n.add_argument("--quiet", action="store_true", help="do not print log lines")
    n.add_argument("--allow-placeholder-keys", action="store_true",
                   help="start mainnet even though genesis uses public placeholder keys (never for real use)")
    n.set_defaults(fn=cmd_node)

    w = sub.add_parser("wallet", help="manage a wallet")
    w.add_argument("action", choices=["new", "address", "balance", "send"])
    add_network(w)
    add_client_options(w)
    w.add_argument("--file", default="wallet.json")
    w.add_argument("--to", help="destination address (send)")
    w.add_argument("--amount", help="amount in DOVC (send)")
    w.add_argument("--fee-rate", type=int, default=P.MIN_RELAY_FEE_PER_BYTE,
                   help="fee in base units per byte (send)")
    w.set_defaults(fn=cmd_wallet)

    s = sub.add_parser("status", help="show a running node's status")
    add_network(s)
    add_client_options(s)
    s.set_defaults(fn=cmd_status)

    d = sub.add_parser("devkeys", help="generate the developer payout keys (run once, offline)")
    d.add_argument("--secret-file", default="dev_keys_SECRET.json")
    d.add_argument("--force", action="store_true")
    d.set_defaults(fn=cmd_devkeys)

    sp = sub.add_parser("setpayout", help="set the genesis payout address (public) from a wallet address")
    sp.add_argument("address")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_setpayout)

    g = sub.add_parser("genesis", help="print a network's genesis block")
    add_network(g)
    g.set_defaults(fn=cmd_genesis)

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
