"""Ethereum address derivation and the EIP-55 checksum.

An Ethereum address is the last 20 bytes of the Keccak-256 hash of the
uncompressed public key. That is the whole derivation -- and it contains no
checksum whatsoever, which means every 20-byte value is a syntactically valid
address. A single mistyped character sends funds to an address nobody holds a
key for, permanently.

EIP-55 retrofits a checksum into the CASE of the hexadecimal letters, which is
backwards compatible: an all-lowercase address still parses, merely unchecked.
"""

from __future__ import annotations

from Crypto.Hash import keccak

from .curve import Point


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as used by Ethereum.

    IMPORTANT: this is the ORIGINAL Keccak, not the standardised SHA3-256. The
    two differ in their padding rule and therefore produce different outputs.
    Python's `hashlib.sha3_256` is the standardised variant and is the WRONG
    function here. Solidity's historical `sha3()` alias caused the same
    confusion; the correct name is `keccak256`.
    """
    return keccak.new(digest_bits=256, data=data).digest()


def public_key_to_address(point: Point) -> bytes:
    """Derive the 20-byte address from a public key point.

    The uncompressed encoding is hashed WITHOUT its 0x04 prefix byte: exactly
    the 64 bytes of x || y.
    """
    if point.is_infinity:
        raise ValueError("cannot derive an address from the point at infinity")
    assert point.x is not None and point.y is not None
    payload = point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
    return keccak256(payload)[-20:]


def to_checksum_address(address: bytes | str) -> str:
    """Apply the EIP-55 mixed-case checksum.

    Algorithm: hash the LOWERCASE HEX STRING of the address (not the bytes),
    then upper-case each letter whose corresponding hex digit of the hash is
    >= 8.

    A 40-character address contains on average about 15 letters, each carrying
    one bit, so roughly one random typo in 32,000 slips through. Far from
    perfect -- but the alternative is no checking at all.
    """
    if isinstance(address, bytes):
        body = address.hex()
    else:
        body = address.lower().removeprefix("0x")

    if len(body) != 40:
        raise ValueError(f"address must be 20 bytes / 40 hex chars, got {len(body)}")

    digest = keccak256(body.encode("ascii")).hex()
    out = "".join(
        char.upper() if char.isalpha() and int(digest[i], 16) >= 8 else char
        for i, char in enumerate(body)
    )
    return "0x" + out


def is_valid_checksum_address(address: str) -> bool:
    """Verify an EIP-55 address.

    An all-lowercase or all-uppercase address carries no checksum, so it is
    accepted as "valid but unchecked" rather than rejected -- which is what the
    backwards-compatibility requirement of EIP-55 demands.
    """
    body = address.removeprefix("0x")
    if len(body) != 40:
        return False
    try:
        int(body, 16)
    except ValueError:
        return False
    if body == body.lower() or body == body.upper():
        return True
    return to_checksum_address(body) == ("0x" + body)


def address_from_private_key(private_key: int) -> str:
    """Convenience: private key -> checksummed address, in one step."""
    from .curve import private_to_public

    return to_checksum_address(public_key_to_address(private_to_public(private_key)))
