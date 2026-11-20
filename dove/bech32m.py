"""Bech32m (BIP350) encoding, used for DOVC addresses."""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _checksum(hrp, data):
    polymod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(hrp: str, data5: list) -> str:
    combined = data5 + _checksum(hrp, data5)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def decode(text: str):
    """Return (hrp, data5) or (None, None) if the string is invalid."""
    if any(ord(c) < 33 or ord(c) > 126 for c in text):
        return None, None
    if text.lower() != text and text.upper() != text:
        return None, None
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text) or len(text) > 90:
        return None, None
    if any(c not in CHARSET for c in text[pos + 1:]):
        return None, None
    hrp = text[:pos]
    data = [CHARSET.find(c) for c in text[pos + 1:]]
    if _polymod(_hrp_expand(hrp) + data) != BECH32M_CONST:
        return None, None
    return hrp, data[:-6]


def encode_address(hrp: str, payload: bytes) -> str:
    return encode(hrp, convertbits(payload, 8, 5))


def decode_address(hrp: str, text: str):
    """Return the payload bytes, or None if the address is invalid or has a different prefix."""
    got_hrp, data = decode(text)
    if got_hrp != hrp or data is None:
        return None
    raw = convertbits(data, 5, 8, pad=False)
    return bytes(raw) if raw is not None else None
