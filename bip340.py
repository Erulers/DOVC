"""BIP340 Schnorr signatures over secp256k1 (pure-Python reference version).

WARNING: this is the readable reference algorithm from BIP340.  It is slow and
NOT constant-time, so it is fine for a prototype and tests but must be replaced
by a vetted library (libsecp256k1) before real value is ever at stake.
"""

import hashlib

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], -1, p)) % p
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)


def _point_mul(point, k):
    result = None
    for i in range(256):
        if (k >> i) & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
    return result


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _bytes32(i: int) -> bytes:
    return i.to_bytes(32, "big")


def _x(point) -> bytes:
    return _bytes32(point[0])


def _has_even_y(point) -> bool:
    return point[1] % 2 == 0


def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def _lift_x(x: int):
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y % 2 == 0 else p - y)


def pubkey_gen(seckey: bytes) -> bytes:
    """32-byte x-only public key for a 32-byte secret key."""
    d0 = _int(seckey)
    if not 1 <= d0 <= n - 1:
        raise ValueError("secret key out of range")
    return _x(_point_mul(G, d0))


def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    """64-byte BIP340 signature of a 32-byte message."""
    if len(msg) != 32 or len(aux_rand) != 32:
        raise ValueError("msg and aux_rand must be 32 bytes")
    d0 = _int(seckey)
    if not 1 <= d0 <= n - 1:
        raise ValueError("secret key out of range")
    pub_point = _point_mul(G, d0)
    d = d0 if _has_even_y(pub_point) else n - d0
    t = bytes(a ^ b for a, b in zip(_bytes32(d), tagged_hash("BIP0340/aux", aux_rand)))
    k0 = _int(tagged_hash("BIP0340/nonce", t + _x(pub_point) + msg)) % n
    if k0 == 0:
        raise RuntimeError("nonce was zero; retry with different aux_rand")
    r_point = _point_mul(G, k0)
    k = k0 if _has_even_y(r_point) else n - k0
    e = _int(tagged_hash("BIP0340/challenge", _x(r_point) + _x(pub_point) + msg)) % n
    sig = _x(r_point) + _bytes32((k + e * d) % n)
    if not schnorr_verify(msg, _x(pub_point), sig):
        raise RuntimeError("produced an invalid signature")
    return sig


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(msg) != 32 or len(pubkey) != 32 or len(sig) != 64:
        return False
    pub_point = _lift_x(_int(pubkey))
    r = _int(sig[0:32])
    s = _int(sig[32:64])
    if pub_point is None or r >= p or s >= n:
        return False
    e = _int(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    r_point = _point_add(_point_mul(G, s), _point_mul(pub_point, n - e))
    if r_point is None or not _has_even_y(r_point) or r_point[0] != r:
        return False
    return True
