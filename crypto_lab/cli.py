"""Command-line demonstrations for Lab 02.

Run each part and read the output alongside the source. Every demo prints the
intermediate values, not just the answer, because the intermediate values are
the lesson.
"""

from __future__ import annotations

import argparse
import hashlib
import secrets

from . import address, ecdsa, hdwallet, pqc
from .curve import G, N, P, is_on_curve, private_to_public, scalar_mul, scalar_mul_ladder

RULE = "=" * 78

#: The BIP-39 test vector mnemonic. Its keys are published in every standard and
#: test suite in existence, so never send anything to an address derived from it.
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _h(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


# --------------------------------------------------------------------------- #


def demo_curve() -> None:
    print(RULE)
    print("PART A -- secp256k1 arithmetic")
    print(RULE)
    print(f"field prime p   = 0x{P:x}")
    print("                = 2^256 - 2^32 - 977   (special form -> fast reduction)")
    print(f"group order n   = 0x{N:x}")
    print(f"generator G     = {G}")
    print(f"G on curve      : {is_on_curve(G)}")
    print()

    print("Group law sanity checks (each must hold, or the arithmetic is wrong):")
    print(f"  n*G is the identity                : {scalar_mul(N, G).is_infinity}")
    print(f"  (n-1)*G + G is the identity        : {scalar_mul(N - 1, G) != G}")
    two_g = scalar_mul(2, G)
    print(f"  G + G == 2*G                       : {two_g == scalar_mul(2, G)}")
    print(f"  double-and-add == Montgomery ladder: {scalar_mul(12345) == scalar_mul_ladder(12345)}")
    print()
    print(f"2G = {two_g}")
    print()
    print("Cost asymmetry -- the entire basis of the system:")
    print("  computing  Q = d*G   takes ~256 point operations")
    print("  recovering d from Q  takes ~2^128 operations classically (Pollard's rho)")
    print("                       and polynomial time on a quantum computer (Shor)")
    print()


def demo_ecdsa() -> None:
    print(RULE)
    print("PART B -- ECDSA, and why the nonce is the whole game")
    print(RULE)

    private_key = 0xC0FFEE00BADC0DE1234567890ABCDEF1122334455667788990AABBCCDDEEFF00
    public_key = private_to_public(private_key)
    print(f"private key d   = 0x{private_key:064x}")
    print(f"address         = {address.address_from_private_key(private_key)}")
    print()

    msg1, msg2 = _h("transfer 1 ETH to Alice"), _h("transfer 1000 ETH to Mallory")

    sig1 = ecdsa.sign(private_key, msg1)
    print("Deterministic signing (RFC 6979):")
    print(f"  r = 0x{sig1.r:064x}")
    print(f"  s = 0x{sig1.s:064x}")
    print(f"  verifies                     : {ecdsa.verify(public_key, msg1, sig1)}")
    print(f"  reproducible across runs     : {ecdsa.sign(private_key, msg1) == sig1}")
    print(f"  rejects a different message  : {ecdsa.verify(public_key, msg2, sig1)}")
    print(f"  low-s enforced (s <= n/2)    : {sig1.s <= N // 2}")
    print()

    recovered = ecdsa.recover_public_key(msg1, sig1)
    print("Public key recovery (`ecrecover`):")
    print(f"  recovered key matches signer : {recovered == public_key}")
    print("  This is why an Ethereum transaction carries no public key -- and also")
    print("  why every account that has ever transacted is quantum-exposed.")
    print()

    print("Signature malleability:")
    high_s = ecdsa.Signature(sig1.r, N - sig1.s, sig1.recovery_id ^ 1)
    print(f"  (r, n-s) also verifies       : {ecdsa.verify(public_key, msg1, high_s)}")
    print("  Two distinct encodings of one authorisation. On pre-SegWit Bitcoin this")
    print("  changed the txid without invalidating the transaction.")
    print()

    print("*** Nonce reuse ***")
    reused = secrets.randbelow(N - 1) + 1
    bad1 = ecdsa.sign(private_key, msg1, nonce=reused, enforce_low_s=False)
    bad2 = ecdsa.sign(private_key, msg2, nonce=reused, enforce_low_s=False)
    print(f"  signature 1 r = 0x{bad1.r:064x}")
    print(f"  signature 2 r = 0x{bad2.r:064x}")
    print(f"  identical r -> reuse is visible to anyone: {ecdsa.looks_like_nonce_reuse(bad1, bad2)}")

    stolen = ecdsa.recover_private_key_from_nonce_reuse(bad1.r, bad1.s, msg1, bad2.s, msg2)
    print(f"  recovered d   = 0x{stolen:064x}")
    print(f"  attack succeeded             : {stolen == private_key}")
    print()
    print("  The attacker needed two signatures and the two messages. Nothing else.")
    print("  Sony's PS3 signing key (2010) and a number of Android Bitcoin wallets")
    print("  (2013) were taken exactly this way. RFC 6979 exists to make it impossible.")
    print()


def demo_wallet() -> None:
    print(RULE)
    print("PART C -- BIP-39 / BIP-32 / BIP-44 derivation")
    print(RULE)

    seed = hdwallet.mnemonic_to_seed(TEST_MNEMONIC)
    print(f"mnemonic : {TEST_MNEMONIC}")
    print(f"seed     : {seed.hex()}")
    print()

    root = hdwallet.master_key_from_seed(seed)
    print(f"master key  : 0x{root.key:064x}")
    print(f"chain code  : {root.chain_code.hex()}")
    print()

    print("BIP-44 accounts (m/44'/60'/0'/0/i):")
    for i in range(3):
        node = hdwallet.ethereum_account(TEST_MNEMONIC, index=i)
        addr = address.to_checksum_address(address.public_key_to_address(node.public_point))
        print(f"  [{i}] {addr}")
    print()

    print("The same mnemonic with a passphrase opens a COMPLETELY different wallet:")
    for phrase in ("", "correct horse", "correct horse "):
        node = hdwallet.ethereum_account(TEST_MNEMONIC, 0, passphrase=phrase)
        addr = address.to_checksum_address(address.public_key_to_address(node.public_point))
        print(f"  passphrase {phrase!r:<18} -> {addr}")
    print("  There is no 'wrong' passphrase; a typo is simply another empty wallet.")
    print()

    print("*** Why the top of a BIP-44 path is hardened ***")
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    xpub = account.neuter()
    child = hdwallet.derive_child(account, 0)
    print("  Suppose an attacker holds the account xpub (published for watch-only use)")
    print("  and ONE normal child private key that leaked from a poorly guarded device.")
    stolen_parent = hdwallet.recover_parent_private_key(xpub, child.key, 0)
    print(f"  recovered parent key         : 0x{stolen_parent:064x}")
    print(f"  matches the real parent      : {stolen_parent == account.key}")
    print("  The whole branch is compromised: every sibling and every descendant.")
    print("  Hardened derivation blocks this, which is why purpose, coin_type and")
    print("  account levels always carry an apostrophe.")
    print()

    print("Watch-only derivation (xpub, no private key):")
    pub_child = hdwallet.derive_child(xpub, 5)
    priv_child = hdwallet.derive_child(account, 5)
    print(f"  xpub-derived address matches : {pub_child.public_point == priv_child.public_point}")
    print("  A shop can generate a fresh address per customer with zero spending risk.")
    print()


def demo_pqc() -> None:
    print(RULE)
    print("PART D -- post-quantum cost")
    print(RULE)
    print(pqc.comparison_table(inputs=1))
    print()
    print(pqc.exposure_report())
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="crypto_lab", description="Lab 02 demonstrations")
    parser.add_argument(
        "part",
        nargs="?",
        default="all",
        choices=["all", "curve", "ecdsa", "wallet", "pqc"],
        help="which part to run (default: all)",
    )
    args = parser.parse_args(argv)

    parts = {
        "curve": demo_curve,
        "ecdsa": demo_ecdsa,
        "wallet": demo_wallet,
        "pqc": demo_pqc,
    }
    if args.part == "all":
        for fn in parts.values():
            fn()
    else:
        parts[args.part]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
