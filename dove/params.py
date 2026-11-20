"""Dove (DOVC) consensus constants.

Everything here comes from the locked design in the protocol spec (draft 0.1).
Items the spec marks "[Default - review]" are called out in comments.
"""

import hashlib
import math

# ---- Units ---------------------------------------------------------------
UNITS_PER_DOVC = 100_000_000          # 8 decimals
MAX_MONEY = (1 << 63) - 1             # sanity bound on any amount, in base units

# ---- Name ----------------------------------------------------------------
TICKER = "DOVC"
ADDRESS_HRP = "dovc"                  # [Default - review]

# ---- Stages --------------------------------------------------------------
# Heights are 1-based after the genesis block (height 0).
STAGE_LENGTHS = (100, 1_000, 10_000, 100_000, 1_000_000)   # stages 1-5; stage 6 is permanent
STAGE_STARTS = (1, 101, 1_101, 11_101, 111_101, 1_111_101)  # first height of stages 1..6

# Difficulty multiplier for stage k is (2k)!  -> 2!, 4!, 6!, 8!, 10!, 12!
MULTIPLIERS = tuple(math.factorial(2 * k) for k in range(1, 7))

# The last 30% of each stage ramps smoothly toward the next stage's multiplier.
RAMP_NUM, RAMP_DEN = 3, 10

# ---- Rewards -------------------------------------------------------------
# Stage k pays floor(R0 / k); stage 6 halves three times, every 160,000 blocks.
R0_UNITS = 7_517_713_950              # 75.17713950 DOVC
HALVING_INTERVAL = 160_000
HALVINGS = 3

# ---- Developer payout (genesis) ------------------------------------------
# Mainnet: ONE output of 1,240,000 DOVC paid to the owner's wallet with no timelock (spendable once
# it has the normal 100-block coinbase maturity).  Testnet keeps five timelocked parts so the
# timelock rule stays exercised by the tests.
DEV_PAYOUT_PARTS = 1
DEV_PAYOUT_PART_UNITS = 1_240_000 * UNITS_PER_DOVC
DEV_UNLOCK_HEIGHTS = (0,)             # 0 means no timelock
TEST_PAYOUT = tuple((248_000 * UNITS_PER_DOVC, h)
                    for h in (35_064, 70_128, 105_192, 140_256, 175_320))

GENESIS_MESSAGE = b"DOVC 11/16/2026 - Today's Wordle #1976 is DRAWL, let the doves fly! :3"
GENESIS_TIMESTAMP = 1_794_787_200     # 2026-11-16 00:00:00 UTC

# ---- Blocks and transactions ---------------------------------------------
MAX_BLOCK_BYTES = 1_000_000
COINBASE_MATURITY = 100               # [Default - review]
MAX_COINBASE_DATA = 100               # bytes of free text a miner may add
MEDIAN_TIME_SPAN = 11                 # [Default - review]
MAX_FUTURE_SECONDS = 2 * 60 * 60      # [Default - review]
TARGET_BLOCK_SECONDS = 15 * 60        # a target only; there is no retargeting

# ---- Proof of work (Argon2id) --------------------------------------------
POW_MEMORY_KIB = 65_536               # 64 MiB [Locked]
POW_TIME_COST = 3                     # [Locked] RFC 9106's recommended setting for 64 MiB
POW_LANES = 1                         # [Default - review]
POW_SALT = hashlib.sha256(b"DOVC-POW-SALT-v1").digest()[:16]   # [Default - review]

# ---- Locks ---------------------------------------------------------------
LOCK_P2PKH = 1                        # pay to SHA-256(x-only pubkey)
LOCK_P2PKH_HEIGHT = 2                 # same, plus an unlock height

# ---- Fee policy (node policy, NOT consensus) -----------------------------
MIN_RELAY_FEE_PER_BYTE = 1            # base units per byte [Default - review]


# ---- Networks --------------------------------------------------------------
# Mainnet is the real chain.  Testnet has its own genesis, magic bytes, ports and address
# prefix, a small Argon2id memory so it runs on anything, and public (worthless) keys.
NETWORKS = {
    "main": {"magic": b"DOVE", "p2p_port": 8833, "rpc_port": 8832, "pow_memory_kib": POW_MEMORY_KIB,
             "genesis_message": GENESIS_MESSAGE, "hrp": ADDRESS_HRP,
             "payout": ((DEV_PAYOUT_PART_UNITS, 0),)},
    "test": {"magic": b"DOVT", "p2p_port": 18833, "rpc_port": 18832, "pow_memory_kib": 1_024,
             "genesis_message": b"DOVC testnet - coins here are worthless", "hrp": "tdovc",
             "payout": TEST_PAYOUT},
}
