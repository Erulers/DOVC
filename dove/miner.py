"""Demo miner: mines blocks on a fresh in-memory chain and prints the stage system.

Usage:
    python -m dove.miner --blocks 30
    python -m dove.miner --blocks 150 --memory-kib 64     # fast, for watching the ramp
"""

import argparse
import time

from . import params as P
from . import schedule
from .chain import Chain
from .wallet import Wallet


def fmt_dovc(units: int) -> str:
    return f"{units // P.UNITS_PER_DOVC}.{units % P.UNITS_PER_DOVC:08d}"


def main():
    ap = argparse.ArgumentParser(description="Dove (DOVC) demo miner")
    ap.add_argument("--blocks", type=int, default=20, help="how many blocks to mine")
    ap.add_argument("--memory-kib", type=int, default=P.POW_MEMORY_KIB,
                    help="Argon2id memory in KiB (consensus value is 65536)")
    args = ap.parse_args()

    chain = Chain(pow_memory_kib=args.memory_kib)
    wallet = Wallet()

    print(f"Dove node (prototype)   ticker: {P.TICKER}   Argon2id memory: {args.memory_kib} KiB")
    print(f'Genesis block 0: "{P.GENESIS_MESSAGE.decode()}"')
    print(f"Genesis id: {chain.genesis_id.hex()}")
    print(f"Mining to {wallet.address}\n")

    last_stage = 0
    mined = 0
    started = time.time()
    while mined < args.blocks:
        height = chain.height + 1
        stage, offset = schedule.stage_of(height)
        if stage != last_stage:
            diff = schedule.difficulty_q64(height) / 2**64
            print(f"--- Stage {stage} of 6 begins at height {height}   "
                  f"difficulty {diff:,.2f}   reward {fmt_dovc(schedule.subsidy(height))} DOVC")
            last_stage = stage
        block = chain.build_block(wallet.payload)
        t0 = time.time()
        block, attempts = chain.mine(block)
        chain.add_block(block)
        mined += 1
        diff = schedule.difficulty_q64(height) / 2**64
        print(f"height {height:>7}  stage {stage}  difficulty {diff:>12,.3f}  "
              f"attempts {attempts:>5}  {time.time() - t0:6.2f}s  "
              f"reward {fmt_dovc(schedule.subsidy(height))}")

    total = sum(u.value for u in chain.utxos().values() if u.payload == wallet.payload)
    print(f"\nMined {mined} blocks in {time.time() - started:.1f}s; "
          f"wallet holds {fmt_dovc(total)} DOVC (coinbase rewards mature after "
          f"{P.COINBASE_MATURITY} blocks).")


if __name__ == "__main__":
    main()
