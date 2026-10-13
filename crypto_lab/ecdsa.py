"""ECDSA over secp256k1: signing, verification, key recovery -- and the attack.

The mathematics of ECDSA is short. Its dangers are entirely in the handling of
one value, the per-signature nonce `k`, and this module exists as much to
demonstrate what goes wrong as to show what goes right.

Signing:
    r = (k*G).x mod n
    s = k^-1 * (z + r*d) mod n

Verification:
    w  = s^-1 mod n
    u1 = z*w mod n,  u2 = r*w mod n
    accept iff (u1*G + u2*Q).x mod n == r
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .curve import (
    G,
    N,
    Point,
    add,
    inverse_mod,
    negate,
    private_to_public,
    scalar_mul,
)

# --------------------------------------------------------------------------- #
# Signature container
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Signature:
    r: int
    s: int
    #: Recovery identifier: 0..3. Encodes which of the candidate R points was
    #: used, so that the public key can be recomputed from the signature alone.
    #: Ethereum transmits this (as v = recovery_id + 27) instead of the key.
    recovery_id: int

    def to_bytes(self) -> bytes:
        """64-byte compact form: r || s."""
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big")

    def to_eth_vrs(self) -> tuple[int, int, int]:
        """Ethereum's (v, r, s) with the legacy v = recovery_id + 27."""
        return self.recovery_id + 27, self.r, self.s

    def to_der(self) -> bytes:
        """DER encoding, as used inside Bitcoin scriptSigs.

        Each integer is encoded big-endian with a leading 0x00 byte inserted
        when the high bit is set, because DER integers are signed.
        """

        def encode_int(value: int) -> bytes:
            raw = value.to_bytes((value.bit_length() + 8) // 8, "big") or b"\x00"
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            return b"\x02" + bytes([len(raw)]) + raw

        body = encode_int(self.r) + encode_int(self.s)
        return b"\x30" + bytes([len(body)]) + body


# --------------------------------------------------------------------------- #
# RFC 6979 deterministic nonce
# --------------------------------------------------------------------------- #


def _bits2int(data: bytes, qlen: int) -> int:
    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - qlen
    return value >> excess if excess > 0 else value


def _int2octets(value: int, rolen: int) -> bytes:
    return value.to_bytes(rolen, "big")


def _bits2octets(data: bytes, qlen: int, rolen: int) -> bytes:
    z1 = _bits2int(data, qlen)
    z2 = z1 - N
    return _int2octets(z2 if z2 >= 0 else z1, rolen)


def rfc6979_nonce(private_key: int, message_hash: bytes) -> int:
    """Derive `k` deterministically from the key and the message (RFC 6979).

    This eliminates the entire class of failures caused by a weak random number
    generator, while keeping `k` unpredictable to anyone without the private
    key. It is what every modern Bitcoin and Ethereum library uses, and it is
    the direct response to the incidents reproduced in `recover_private_key`
    below: the Sony PlayStation 3 code-signing key in 2010, and the Android
    wallet thefts of 2013.

    A pleasant side effect: signatures become reproducible, which makes them
    testable.
    """
    qlen = N.bit_length()
    holen = hashlib.sha256().digest_size
    rolen = (qlen + 7) // 8

    seed = _int2octets(private_key, rolen) + _bits2octets(message_hash, qlen, rolen)

    v = b"\x01" * holen
    k = b"\x00" * holen

    k = hmac.new(k, v + b"\x00" + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        t = b""
        while len(t) < rolen:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        candidate = _bits2int(t, qlen)
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# Signing and verification
# --------------------------------------------------------------------------- #


def sign(
    private_key: int,
    message_hash: bytes,
    *,
    nonce: int | None = None,
    enforce_low_s: bool = True,
) -> Signature:
    """Produce an ECDSA signature.

    `nonce` should be left as None in any realistic use; it is exposed solely so
    that the nonce-reuse attack in Part B of the lab can be demonstrated.

    `enforce_low_s` normalises s to the lower half of the order. Both (r, s) and
    (r, n-s) are valid signatures for the same message, because R and -R share
    an x-coordinate. Leaving both forms acceptable is signature malleability:
    a third party can re-encode a valid signature, changing the transaction
    hash without invalidating it. Bitcoin's low-s policy rule and Ethereum's
    EIP-2 both forbid the high form.
    """
    if not 1 <= private_key < N:
        raise ValueError("private key out of range")
    if len(message_hash) != 32:
        raise ValueError("message hash must be 32 bytes; hash it first")

    z = int.from_bytes(message_hash, "big")

    while True:
        k = nonce if nonce is not None else rfc6979_nonce(private_key, message_hash)
        point = scalar_mul(k, G)
        assert point.x is not None and point.y is not None

        r = point.x % N
        if r == 0:
            if nonce is not None:
                raise ValueError("supplied nonce yields r = 0")
            continue

        s = inverse_mod(k, N) * (z + r * private_key) % N
        if s == 0:
            if nonce is not None:
                raise ValueError("supplied nonce yields s = 0")
            continue

        # recovery_id bit 0: parity of R.y; bit 1: whether R.x exceeded n.
        recovery_id = (point.y & 1) | (2 if point.x >= N else 0)

        if enforce_low_s and s > N // 2:
            s = N - s
            recovery_id ^= 1  # flipping s corresponds to using -R

        return Signature(r=r, s=s, recovery_id=recovery_id)


def verify(public_key: Point, message_hash: bytes, signature: Signature) -> bool:
    """Verify a signature. Returns False rather than raising on bad input.

    The range checks on r and s are not optional decoration: accepting r = 0 or
    s = 0, or values above the order, opens the door to forgeries.
    """
    if not (1 <= signature.r < N and 1 <= signature.s < N):
        return False
    if public_key.is_infinity:
        return False

    z = int.from_bytes(message_hash, "big")
    w = inverse_mod(signature.s, N)
    u1 = z * w % N
    u2 = signature.r * w % N

    point = add(scalar_mul(u1, G), scalar_mul(u2, public_key))
    if point.is_infinity:
        return False
    assert point.x is not None
    return point.x % N == signature.r


def recover_public_key(message_hash: bytes, signature: Signature) -> Point:
    """Recompute the signer's public key from the signature (`ecrecover`).

        Q = r^-1 * (s*R - z*G)

    This is why an Ethereum transaction does not carry a public key: 33 bytes
    saved on every transaction, forever, on every node.

    The trade-off, discussed in the theory notes, is that it makes every
    Ethereum account that has ever transacted quantum-exposed, because the
    public key becomes derivable from on-chain data.
    """
    z = int.from_bytes(message_hash, "big")

    x = signature.r + (N if signature.recovery_id & 2 else 0)
    from .curve import B, P  # local import: only needed for the square root

    y_squared = (pow(x, 3, P) + B) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if y * y % P != y_squared:
        raise ValueError("invalid signature: no curve point for this r")
    if (y & 1) != (signature.recovery_id & 1):
        y = P - y

    r_point = Point(x, y)
    r_inv = inverse_mod(signature.r, N)
    result = scalar_mul(r_inv, add(scalar_mul(signature.s, r_point), negate(scalar_mul(z, G))))
    if result.is_infinity:
        raise ValueError("recovery produced the point at infinity")
    return result


# --------------------------------------------------------------------------- #
# The attack
# --------------------------------------------------------------------------- #


def recover_private_key_from_nonce_reuse(
    r: int, s1: int, hash1: bytes, s2: int, hash2: bytes
) -> int:
    """Recover the private key from two signatures that reused the same nonce.

    Note what the attacker needs: two signatures and the two messages. Nothing
    else. Not the nonce, not any side-channel, no computational effort beyond a
    modular inverse.

    The reuse is visible in plain sight, because equal nonces produce equal r
    values. Any observer scanning a blockchain for repeated r values across
    signatures by the same key is performing this attack at scale -- and people
    do exactly that.

        s1 = k^-1 (z1 + r*d)
        s2 = k^-1 (z2 + r*d)
        s1 - s2 = k^-1 (z1 - z2)          =>  k = (z1 - z2) / (s1 - s2)
        d = (s1*k - z1) / r

    Real victims: the Sony PlayStation 3 code-signing key (2010, a fixed nonce),
    and a number of Android Bitcoin wallets (2013, a broken SecureRandom).
    """
    z1 = int.from_bytes(hash1, "big")
    z2 = int.from_bytes(hash2, "big")
    r_inv = inverse_mod(r, N)

    # Low-s normalisation may have flipped either signature (s -> n-s, which
    # corresponds to k -> -k), so the sign relationship between the two is not
    # guaranteed. Trying all four combinations costs nothing and removes the
    # ambiguity: the correct candidate is the one whose public key verifies
    # both original signatures.
    for sa in (s1, (-s1) % N):
        for sb in (s2, (-s2) % N):
            if sa == sb:
                continue
            k = (z1 - z2) * inverse_mod(sa - sb, N) % N
            if k == 0:
                continue
            candidate = (sa * k - z1) * r_inv % N
            if not 1 <= candidate < N:
                continue
            public_key = private_to_public(candidate)
            if verify(public_key, hash1, Signature(r, s1, 0)) and verify(
                public_key, hash2, Signature(r, s2, 0)
            ):
                return candidate

    raise ValueError("could not recover a key; were these signatures really nonce-reusing?")


def looks_like_nonce_reuse(sig_a: Signature, sig_b: Signature) -> bool:
    """Detect the fingerprint of nonce reuse: an identical r across signatures."""
    return sig_a.r == sig_b.r
