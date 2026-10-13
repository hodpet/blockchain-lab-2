"""BIP-39 / BIP-32 / BIP-44 hierarchical deterministic wallets.

One secret, an unbounded tree of keys. This module implements the three
standards that turn 128 bits of entropy into an entire multi-currency account
hierarchy, and it also implements the attack that explains why the standards
insist on hardened derivation at the top of the tree.
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
    private_to_public,
    scalar_mul,
    serialize_public_key,
)

HARDENED_OFFSET = 2**31


# --------------------------------------------------------------------------- #
# BIP-39
# --------------------------------------------------------------------------- #


def entropy_to_mnemonic(entropy: bytes, wordlist: list[str]) -> list[str]:
    """Encode entropy as mnemonic words with a checksum.

    Layout: ENT bits of entropy || CS bits of checksum, split into 11-bit groups
    indexing a 2048-word list. CS = ENT / 32, so 128 bits of entropy gives 4
    checksum bits and 12 words; 256 bits gives 8 bits and 24 words.

    The checksum detects typing errors -- a randomly assembled 12-word phrase is
    valid with probability only 1/16 -- but it does NOT correct them. It cannot
    tell you which word is wrong.
    """
    if len(wordlist) != 2048:
        raise ValueError(f"wordlist must contain exactly 2048 words, got {len(wordlist)}")
    ent_bits = len(entropy) * 8
    if ent_bits not in (128, 160, 192, 224, 256):
        raise ValueError(f"entropy must be 128-256 bits in 32-bit steps, got {ent_bits}")

    checksum_bits = ent_bits // 32
    digest = hashlib.sha256(entropy).digest()

    bits = int.from_bytes(entropy, "big") << checksum_bits
    bits |= digest[0] >> (8 - checksum_bits)

    total_bits = ent_bits + checksum_bits
    word_count = total_bits // 11
    return [
        wordlist[(bits >> (11 * (word_count - 1 - i))) & 0x7FF] for i in range(word_count)
    ]


def mnemonic_to_entropy(words: list[str], wordlist: list[str]) -> bytes:
    """Decode a mnemonic back to entropy, validating the checksum."""
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError(f"unexpected word count: {len(words)}")

    index = {w: i for i, w in enumerate(wordlist)}
    bits = 0
    for word in words:
        if word not in index:
            raise ValueError(f"word not in wordlist: {word!r}")
        bits = (bits << 11) | index[word]

    total_bits = len(words) * 11
    checksum_bits = total_bits // 33
    ent_bits = total_bits - checksum_bits

    entropy = (bits >> checksum_bits).to_bytes(ent_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if (bits & ((1 << checksum_bits) - 1)) != expected:
        raise ValueError("checksum mismatch: the phrase contains an error")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Stretch a mnemonic into the 512-bit seed (BIP-39).

    Note what the passphrase does: it enters the SALT, not the password. There
    is therefore no such thing as a wrong passphrase -- every passphrase opens a
    different, perfectly valid, usually empty wallet. That property is what
    makes plausible-deniability wallets possible, and it is also why a mistyped
    passphrase looks exactly like a stolen wallet.

    2048 iterations is low by modern standards. It is nevertheless adequate here
    because the mnemonic itself carries 128-256 bits of entropy; the stretching
    exists to protect the optional passphrase, not the phrase.

    Both inputs are NFKD-normalised so that visually identical Unicode strings
    produce the same seed.
    """
    import unicodedata

    normalised = unicodedata.normalize("NFKD", " ".join(mnemonic.split()))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512", normalised.encode("utf-8"), salt.encode("utf-8"), 2048, dklen=64
    )


# --------------------------------------------------------------------------- #
# BIP-32
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExtendedKey:
    """A private key (or public point) together with its chain code.

    The chain code is the part people forget. It is 256 bits of entropy
    independent of the key, mixed into every derivation so that the structure of
    the tree cannot be inferred from the outside. Without it, sibling keys would
    be trivially relatable.
    """

    key: int | None  # private scalar, or None for a public-only ("xpub") key
    public_point: Point
    chain_code: bytes
    depth: int = 0
    child_number: int = 0

    @property
    def is_private(self) -> bool:
        return self.key is not None

    def neuter(self) -> ExtendedKey:
        """Strip the private key, leaving the public equivalent (the xpub).

        Handing out an xpub lets a webshop generate a fresh receiving address
        per customer without ever exposing spending authority -- and is exactly
        what `recover_parent_private_key` below shows can go wrong.
        """
        return ExtendedKey(
            key=None,
            public_point=self.public_point,
            chain_code=self.chain_code,
            depth=self.depth,
            child_number=self.child_number,
        )


def master_key_from_seed(seed: bytes) -> ExtendedKey:
    """Derive the tree root from a BIP-39 seed."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    if key == 0 or key >= N:
        raise ValueError("invalid seed (probability of this is negligible)")
    return ExtendedKey(key=key, public_point=private_to_public(key), chain_code=digest[32:])


def derive_child(parent: ExtendedKey, index: int) -> ExtendedKey:
    """Derive one child key (CKDpriv or CKDpub, depending on what we hold).

    Two derivation modes:

      * NORMAL (index < 2^31) feeds the parent PUBLIC key into the HMAC, so the
        derivation also works with only an xpub. This is what makes watch-only
        wallets possible.

      * HARDENED (index >= 2^31) feeds the parent PRIVATE key instead, so it
        cannot be done publicly. It exists to stop the attack in
        `recover_parent_private_key`, and it is why BIP-44 hardens the first
        three levels of every path.
    """
    hardened = index >= HARDENED_OFFSET

    if hardened:
        if not parent.is_private:
            raise ValueError("hardened derivation requires the private key")
        assert parent.key is not None
        data = b"\x00" + parent.key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = serialize_public_key(parent.public_point, compressed=True) + index.to_bytes(
            4, "big"
        )

    digest = hmac.new(parent.chain_code, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= N:
        raise ValueError("derived tweak out of range; use the next index")

    if parent.is_private:
        assert parent.key is not None
        child_key = (tweak + parent.key) % N
        if child_key == 0:
            raise ValueError("derived key is zero; use the next index")
        return ExtendedKey(
            key=child_key,
            public_point=private_to_public(child_key),
            chain_code=digest[32:],
            depth=parent.depth + 1,
            child_number=index,
        )

    # Public-only derivation: K_i = IL*G + K_par
    child_point = add(scalar_mul(tweak, G), parent.public_point)
    if child_point.is_infinity:
        raise ValueError("derived point at infinity; use the next index")
    return ExtendedKey(
        key=None,
        public_point=child_point,
        chain_code=digest[32:],
        depth=parent.depth + 1,
        child_number=index,
    )


def parse_path(path: str) -> list[int]:
    """Parse a BIP-32 path such as ``m/44'/60'/0'/0/0`` into indices."""
    parts = path.strip().split("/")
    if parts[0] not in ("m", "M"):
        raise ValueError("path must start with 'm'")

    indices: list[int] = []
    for part in parts[1:]:
        if not part:
            continue
        if part.endswith(("'", "h", "H")):
            indices.append(int(part[:-1]) + HARDENED_OFFSET)
        else:
            indices.append(int(part))
    return indices


def derive_path(root: ExtendedKey, path: str) -> ExtendedKey:
    """Walk a full derivation path from a root key."""
    node = root
    for index in parse_path(path):
        node = derive_child(node, index)
    return node


def format_path(indices: list[int]) -> str:
    """Render indices back as a path string, for reporting."""
    parts = ["m"]
    for i in indices:
        parts.append(f"{i - HARDENED_OFFSET}'" if i >= HARDENED_OFFSET else str(i))
    return "/".join(parts)


# --------------------------------------------------------------------------- #
# The attack that motivates hardened derivation
# --------------------------------------------------------------------------- #


def recover_parent_private_key(
    parent_xpub: ExtendedKey, child_private_key: int, index: int
) -> int:
    """Recover a parent private key from its xpub plus ONE normal child key.

    This is the whole justification for hardened derivation, and it is worth
    working through, because the result is counter-intuitive: an xpub is
    supposed to be safe to publish.

        child = (IL + parent) mod n,  where IL = HMAC(chain_code, pubkey || i)

    The chain code is part of the xpub, and the public key and index are public,
    so the attacker can compute IL. Then:

        parent = (child - IL) mod n

    One leaked child key plus a published xpub therefore compromises the entire
    branch -- every sibling, and every descendant. Hardened derivation blocks it
    because IL then depends on the parent PRIVATE key, which the attacker does
    not have.
    """
    if index >= HARDENED_OFFSET:
        raise ValueError("hardened children are immune to this attack -- that is the point")

    data = serialize_public_key(parent_xpub.public_point, compressed=True) + index.to_bytes(
        4, "big"
    )
    digest = hmac.new(parent_xpub.chain_code, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")

    return (child_private_key - tweak) % N


# --------------------------------------------------------------------------- #
# Convenience
# --------------------------------------------------------------------------- #

#: The BIP-44 path Ethereum wallets actually use. Note that MetaMask keeps the
#: account level fixed at 0 and increments the ADDRESS index, whereas some
#: hardware wallets historically incremented the ACCOUNT index instead --
#: producing different addresses from the same mnemonic, and a steady supply of
#: "my funds disappeared" support tickets.
ETH_PATH_TEMPLATE = "m/44'/60'/0'/0/{index}"

#: SLIP-0044 coin types, for reference in reports.
COIN_TYPES = {"bitcoin": 0, "testnet": 1, "ethereum": 60, "solana": 501}


def ethereum_account(mnemonic: str, index: int = 0, passphrase: str = "") -> ExtendedKey:
    """Full pipeline: mnemonic -> seed -> master key -> m/44'/60'/0'/0/index."""
    seed = mnemonic_to_seed(mnemonic, passphrase)
    root = master_key_from_seed(seed)
    return derive_path(root, ETH_PATH_TEMPLATE.format(index=index))
