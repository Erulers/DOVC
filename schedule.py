"""Stage, reward and difficulty schedule for Dove (DOVC).

Everything in this module is consensus-critical and uses integers only, so
every node computes bit-identical results.  No floating point anywhere.

Difficulty D is the expected number of hash attempts per block, held as a
Q64.64 fixed-point integer (D * 2**64).  It depends only on block height.
"""

from functools import lru_cache

from . import params as P

# Internal precision for the ln/exp series.  Output is truncated to Q64.64.
_PREC = 128
_ONE = 1 << _PREC


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

def stage_of(height: int):
    """Return (stage_number 1..6, offset_within_stage) for a height >= 1."""
    if height < 1:
        raise ValueError("stages start at height 1 (height 0 is the genesis block)")
    for k in range(5, 0, -1):
        if height >= P.STAGE_STARTS[k]:
            return k + 1, height - P.STAGE_STARTS[k]
    return 1, height - P.STAGE_STARTS[0]


def stage_length(k: int):
    """Number of blocks in stage k (1..5); None for the permanent stage 6."""
    return P.STAGE_LENGTHS[k - 1] if k <= 5 else None


def ramp_length(k: int) -> int:
    """Blocks in the ramp at the end of stage k (1..5)."""
    return stage_length(k) * P.RAMP_NUM // P.RAMP_DEN


# ---------------------------------------------------------------------------
# Rewards
# ---------------------------------------------------------------------------

def subsidy(height: int) -> int:
    """Block subsidy in base units.  The genesis block pays no subsidy."""
    if height == 0:
        return 0
    k, _ = stage_of(height)
    if k <= 5:
        return P.R0_UNITS // k
    periods = min((height - P.STAGE_STARTS[5]) // P.HALVING_INTERVAL, P.HALVINGS)
    return (P.R0_UNITS // 6) >> periods


# ---------------------------------------------------------------------------
# Fixed-point ln / exp (integers only)
# ---------------------------------------------------------------------------

def _ln_1_to_2(m: int) -> int:
    """ln(m) for m in [1, 2], with m and the result scaled by 2**_PREC."""
    z = ((m - _ONE) << _PREC) // (m + _ONE)
    z2 = (z * z) >> _PREC
    term, total, j = z, 0, 0
    while term:
        total += term // (2 * j + 1)
        term = (term * z2) >> _PREC
        j += 1
    return 2 * total


_LN2 = _ln_1_to_2(2 * _ONE)


def _ln_int(x: int) -> int:
    """ln(x) * 2**_PREC for an integer x >= 1."""
    k = x.bit_length() - 1
    m = (x << _PREC) >> k            # x / 2**k, in [1, 2)
    return k * _LN2 + _ln_1_to_2(m)


def _exp(y: int) -> int:
    """exp(y) * 2**_PREC for y >= 0 scaled by 2**_PREC."""
    q = y // _LN2
    f = y - q * _LN2                 # 0 <= f < ln 2
    term, total, j = _ONE, _ONE, 1
    while term:
        term = ((term * f) >> _PREC) // j
        total += term
        j += 1
    return total << q


@lru_cache(maxsize=None)
def _ramp_log_ratio(k: int) -> int:
    """ln(M_{k+1} / M_k) * 2**_PREC for stage k (1..5)."""
    ratio, rem = divmod(P.MULTIPLIERS[k], P.MULTIPLIERS[k - 1])
    assert rem == 0
    return _ln_int(ratio)


# ---------------------------------------------------------------------------
# Difficulty
# ---------------------------------------------------------------------------

def difficulty_q64(height: int) -> int:
    """Difficulty at a height, as a Q64.64 integer (expected attempts * 2**64)."""
    k, offset = stage_of(height)
    m_k = P.MULTIPLIERS[k - 1]
    if k == 6:
        return m_k << 64
    n = ramp_length(k)
    flat = stage_length(k) - n
    if offset < flat:
        return m_k << 64
    i = offset - flat + 1            # 1..n inside the ramp
    if i == n:
        return P.MULTIPLIERS[k] << 64   # exact landing on the next stage's level
    y = i * _ramp_log_ratio(k) // n
    return (m_k * _exp(y)) >> (_PREC - 64)


def target_for_height(height: int) -> int:
    """Proof-of-work target: a hash (as a big-endian integer) must be <= this."""
    return (((1 << 256) - 1) << 64) // difficulty_q64(height)
