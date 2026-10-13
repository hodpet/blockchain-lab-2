"""Tests for Lab 02.

These are the specification for the `[STUDENT TASK]` implementation: if your own
code passes them, it satisfies the functional requirements of the lab.

Where possible the assertions use published test vectors (secp256k1 2G, the
BIP-39 zero-entropy mnemonic, the EIP-55 examples), so that a passing test means
agreement with the wider world rather than mere self-consistency.
"""

from __future__ import annotations

import hashlib
import secrets

import pytest

from crypto_lab import address, ecdsa, hdwallet, pqc
from crypto_lab.curve import (
    G,
    INFINITY,
    N,
    P,
    Point,
    add,
    deserialize_public_key,
    double,
    inverse_mod,
    is_on_curve,
    negate,
    private_to_public,
    scalar_mul,
    scalar_mul_ladder,
    serialize_public_key,
)

# --------------------------------------------------------------------------- #
# Curve arithmetic
# --------------------------------------------------------------------------- #

# Published value of 2G on secp256k1.
TWO_G = Point(
    0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
    0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
)


def test_field_prime_has_the_expected_form() -> None:
    assert P == 2**256 - 2**32 - 977


def test_generator_is_on_curve() -> None:
    assert is_on_curve(G)


def test_inverse_mod_is_a_true_inverse() -> None:
    for value in (1, 2, 3, 12345, P - 1):
        assert value * inverse_mod(value) % P == 1


def test_inverse_of_zero_is_rejected() -> None:
    with pytest.raises(ZeroDivisionError):
        inverse_mod(0)


def test_doubling_matches_published_2g() -> None:
    assert double(G) == TWO_G
    assert scalar_mul(2, G) == TWO_G


def test_identity_behaviour() -> None:
    assert add(G, INFINITY) == G
    assert add(INFINITY, G) == G
    assert double(INFINITY).is_infinity


def test_point_plus_its_negation_is_infinity() -> None:
    assert add(G, negate(G)).is_infinity


def test_order_of_the_generator() -> None:
    """n*G = O and (n-1)*G = -G: the defining property of the group order."""
    assert scalar_mul(N, G).is_infinity
    assert scalar_mul(N - 1, G) == negate(G)


def test_small_multiples_match_repeated_addition() -> None:
    """Double-and-Add must agree with the naive definition of k*G."""
    running = INFINITY
    for k in range(1, 12):
        running = add(running, G)
        assert scalar_mul(k, G) == running


def test_ladder_agrees_with_double_and_add() -> None:
    """The constant-time variant must be functionally identical."""
    for _ in range(5):
        k = secrets.randbelow(N - 1) + 1
        assert scalar_mul(k, G) == scalar_mul_ladder(k, G)


def test_all_derived_points_stay_on_the_curve() -> None:
    for _ in range(5):
        assert is_on_curve(private_to_public(secrets.randbelow(N - 1) + 1))


def test_private_key_range_is_enforced() -> None:
    for bad in (0, N, N + 1, -1):
        with pytest.raises(ValueError):
            private_to_public(bad)


@pytest.mark.parametrize("compressed", [True, False])
def test_public_key_serialisation_roundtrip(compressed: bool) -> None:
    point = private_to_public(0xDEADBEEF)
    encoded = serialize_public_key(point, compressed)
    assert len(encoded) == (33 if compressed else 65)
    assert deserialize_public_key(encoded) == point


def test_compressed_prefix_encodes_the_parity_of_y() -> None:
    point = private_to_public(0xDEADBEEF)
    assert point.y is not None
    encoded = serialize_public_key(point, compressed=True)
    assert encoded[0] == (0x03 if point.y & 1 else 0x02)


def test_off_curve_point_is_rejected() -> None:
    """Roughly half of all x values have no corresponding y; those must be refused.

    Accepting an off-curve point is the entry condition for invalid-curve
    attacks, which leak the private key over repeated operations.
    """
    # Find the smallest x for which x^3 + 7 is a quadratic non-residue mod p.
    x = 0
    while pow((pow(x, 3, P) + 7) % P, (P - 1) // 2, P) == 1:
        x += 1

    with pytest.raises(ValueError, match="not.*curve|does not correspond"):
        deserialize_public_key(b"\x02" + x.to_bytes(32, "big"))


def test_valid_x_is_accepted_and_lands_on_the_curve() -> None:
    point = deserialize_public_key(serialize_public_key(private_to_public(7), True))
    assert is_on_curve(point)


# --------------------------------------------------------------------------- #
# ECDSA
# --------------------------------------------------------------------------- #

PRIV = 0xC0FFEE00BADC0DE1234567890ABCDEF1122334455667788990AABBCCDDEEFF00
MSG_A = hashlib.sha256(b"message A").digest()
MSG_B = hashlib.sha256(b"message B").digest()


def test_sign_and_verify() -> None:
    sig = ecdsa.sign(PRIV, MSG_A)
    assert ecdsa.verify(private_to_public(PRIV), MSG_A, sig)


def test_signature_does_not_verify_for_another_message() -> None:
    sig = ecdsa.sign(PRIV, MSG_A)
    assert not ecdsa.verify(private_to_public(PRIV), MSG_B, sig)


def test_signature_does_not_verify_for_another_key() -> None:
    sig = ecdsa.sign(PRIV, MSG_A)
    assert not ecdsa.verify(private_to_public(PRIV + 1), MSG_A, sig)


def test_rfc6979_is_deterministic() -> None:
    """Same key and message must always give the same nonce, and so the same signature."""
    k1 = ecdsa.rfc6979_nonce(PRIV, MSG_A)
    k2 = ecdsa.rfc6979_nonce(PRIV, MSG_A)
    assert k1 == k2
    assert 1 <= k1 < N
    assert ecdsa.sign(PRIV, MSG_A) == ecdsa.sign(PRIV, MSG_A)


def test_rfc6979_nonce_differs_per_message_and_per_key() -> None:
    assert ecdsa.rfc6979_nonce(PRIV, MSG_A) != ecdsa.rfc6979_nonce(PRIV, MSG_B)
    assert ecdsa.rfc6979_nonce(PRIV, MSG_A) != ecdsa.rfc6979_nonce(PRIV + 1, MSG_A)


def test_low_s_is_enforced_by_default() -> None:
    for i in range(8):
        sig = ecdsa.sign(PRIV, hashlib.sha256(f"m{i}".encode()).digest())
        assert sig.s <= N // 2


def test_high_s_form_is_also_a_valid_signature() -> None:
    """Malleability: (r, s) and (r, n-s) both verify. Hence the low-s policy rule."""
    sig = ecdsa.sign(PRIV, MSG_A)
    flipped = ecdsa.Signature(sig.r, N - sig.s, sig.recovery_id ^ 1)
    assert ecdsa.verify(private_to_public(PRIV), MSG_A, flipped)
    assert flipped.s != sig.s


def test_out_of_range_signature_values_are_rejected() -> None:
    pub = private_to_public(PRIV)
    assert not ecdsa.verify(pub, MSG_A, ecdsa.Signature(0, 1, 0))
    assert not ecdsa.verify(pub, MSG_A, ecdsa.Signature(1, 0, 0))
    assert not ecdsa.verify(pub, MSG_A, ecdsa.Signature(N, 1, 0))


def test_public_key_recovery() -> None:
    sig = ecdsa.sign(PRIV, MSG_A)
    assert ecdsa.recover_public_key(MSG_A, sig) == private_to_public(PRIV)


def test_public_key_recovery_over_many_messages() -> None:
    """recovery_id must be correct in every case, including the s-flip."""
    for i in range(20):
        digest = hashlib.sha256(f"msg-{i}".encode()).digest()
        sig = ecdsa.sign(PRIV, digest)
        assert ecdsa.recover_public_key(digest, sig) == private_to_public(PRIV)


def test_der_encoding_is_well_formed() -> None:
    der = ecdsa.sign(PRIV, MSG_A).to_der()
    assert der[0] == 0x30  # SEQUENCE
    assert der[1] == len(der) - 2  # declared length matches
    assert der[2] == 0x02  # first INTEGER


def test_compact_signature_is_64_bytes() -> None:
    assert len(ecdsa.sign(PRIV, MSG_A).to_bytes()) == 64


def test_nonce_reuse_leaks_the_private_key() -> None:
    """The central attack of Part B."""
    k = secrets.randbelow(N - 1) + 1
    sig1 = ecdsa.sign(PRIV, MSG_A, nonce=k, enforce_low_s=False)
    sig2 = ecdsa.sign(PRIV, MSG_B, nonce=k, enforce_low_s=False)

    assert ecdsa.looks_like_nonce_reuse(sig1, sig2), "reuse is visible as an identical r"

    recovered = ecdsa.recover_private_key_from_nonce_reuse(
        sig1.r, sig1.s, MSG_A, sig2.s, MSG_B
    )
    assert recovered == PRIV


def test_nonce_reuse_attack_also_works_after_low_s_normalisation() -> None:
    """Real signatures are normalised; the attack must survive that."""
    k = secrets.randbelow(N - 1) + 1
    sig1 = ecdsa.sign(PRIV, MSG_A, nonce=k, enforce_low_s=True)
    sig2 = ecdsa.sign(PRIV, MSG_B, nonce=k, enforce_low_s=True)
    recovered = ecdsa.recover_private_key_from_nonce_reuse(
        sig1.r, sig1.s, MSG_A, sig2.s, MSG_B
    )
    assert recovered == PRIV


def test_distinct_nonces_do_not_leak() -> None:
    sig1 = ecdsa.sign(PRIV, MSG_A)
    sig2 = ecdsa.sign(PRIV, MSG_B)
    assert not ecdsa.looks_like_nonce_reuse(sig1, sig2)


def test_signing_rejects_a_non_32_byte_hash() -> None:
    with pytest.raises(ValueError):
        ecdsa.sign(PRIV, b"too short")


# --------------------------------------------------------------------------- #
# BIP-39 / BIP-32 / BIP-44
# --------------------------------------------------------------------------- #

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
#: Published BIP-39 vector: all-zero entropy, passphrase "TREZOR".
TREZOR_SEED = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a"
    "6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)
#: The first Ethereum account of the test mnemonic, used by every wallet's test suite.
TEST_MNEMONIC_ETH_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


def test_bip39_seed_matches_published_vector() -> None:
    assert hdwallet.mnemonic_to_seed(TEST_MNEMONIC, "TREZOR").hex() == TREZOR_SEED


def test_bip39_passphrase_changes_everything() -> None:
    a = hdwallet.mnemonic_to_seed(TEST_MNEMONIC, "")
    b = hdwallet.mnemonic_to_seed(TEST_MNEMONIC, "x")
    assert a != b


def test_seed_is_512_bits() -> None:
    assert len(hdwallet.mnemonic_to_seed(TEST_MNEMONIC)) == 64


def _synthetic_wordlist() -> list[str]:
    """A stand-in for the BIP-39 English list.

    The list is data, not logic. Using a synthetic one lets the encoding and
    checksum logic be tested exactly, offline, without shipping 2048 words --
    and it proves the implementation does not depend on the specific words.
    """
    return [f"w{i:04d}" for i in range(2048)]


@pytest.mark.parametrize(
    ("entropy_bytes", "expected_words"),
    [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)],
)
def test_entropy_length_determines_word_count(entropy_bytes: int, expected_words: int) -> None:
    words = hdwallet.entropy_to_mnemonic(b"\x00" * entropy_bytes, _synthetic_wordlist())
    assert len(words) == expected_words


def test_mnemonic_roundtrip_with_checksum() -> None:
    wordlist = _synthetic_wordlist()
    entropy = secrets.token_bytes(16)
    words = hdwallet.entropy_to_mnemonic(entropy, wordlist)
    assert hdwallet.mnemonic_to_entropy(words, wordlist) == entropy


def test_corrupted_mnemonic_is_detected() -> None:
    wordlist = _synthetic_wordlist()
    words = hdwallet.entropy_to_mnemonic(b"\x11" * 16, wordlist)
    words[3] = wordlist[(wordlist.index(words[3]) + 1) % 2048]
    with pytest.raises(ValueError, match="checksum"):
        hdwallet.mnemonic_to_entropy(words, wordlist)


def test_master_key_derivation_is_deterministic() -> None:
    seed = hdwallet.mnemonic_to_seed(TEST_MNEMONIC)
    assert hdwallet.master_key_from_seed(seed) == hdwallet.master_key_from_seed(seed)


def test_bip44_path_parsing() -> None:
    assert hdwallet.parse_path("m/44'/60'/0'/0/0") == [
        44 + hdwallet.HARDENED_OFFSET,
        60 + hdwallet.HARDENED_OFFSET,
        0 + hdwallet.HARDENED_OFFSET,
        0,
        0,
    ]
    assert hdwallet.format_path(hdwallet.parse_path("m/44'/60'/0'/0/0")) == "m/44'/60'/0'/0/0"


def test_derived_ethereum_address_matches_known_value() -> None:
    """End-to-end check of the whole pipeline against a universally published value."""
    node = hdwallet.ethereum_account(TEST_MNEMONIC, index=0)
    derived = address.to_checksum_address(address.public_key_to_address(node.public_point))
    assert derived == TEST_MNEMONIC_ETH_ADDRESS


def test_successive_indices_give_distinct_addresses() -> None:
    seen = {
        address.to_checksum_address(
            address.public_key_to_address(hdwallet.ethereum_account(TEST_MNEMONIC, i).public_point)
        )
        for i in range(5)
    }
    assert len(seen) == 5


def test_watch_only_derivation_matches_private_derivation() -> None:
    """xpub-based derivation must produce the same public keys."""
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    for index in (0, 1, 7):
        assert (
            hdwallet.derive_child(account.neuter(), index).public_point
            == hdwallet.derive_child(account, index).public_point
        )


def test_hardened_derivation_requires_the_private_key() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    with pytest.raises(ValueError, match="hardened"):
        hdwallet.derive_child(root.neuter(), hdwallet.HARDENED_OFFSET)


def test_parent_key_recovery_from_xpub_and_normal_child() -> None:
    """The attack that justifies hardened derivation."""
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    child = hdwallet.derive_child(account, 0)

    recovered = hdwallet.recover_parent_private_key(account.neuter(), child.key, 0)
    assert recovered == account.key


def test_hardened_children_are_immune_to_that_attack() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    with pytest.raises(ValueError, match="immune"):
        hdwallet.recover_parent_private_key(root.neuter(), 1, hdwallet.HARDENED_OFFSET)


# --------------------------------------------------------------------------- #
# Addresses and EIP-55
# --------------------------------------------------------------------------- #


def test_keccak256_is_not_sha3_256() -> None:
    """Guards against the single most common Ethereum hashing mistake."""
    assert address.keccak256(b"").hex() != hashlib.sha3_256(b"").hexdigest()
    assert (
        address.keccak256(b"").hex()
        == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


@pytest.mark.parametrize(
    "checksummed",
    [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ],
)
def test_eip55_published_vectors(checksummed: str) -> None:
    assert address.to_checksum_address(checksummed.lower()) == checksummed
    assert address.is_valid_checksum_address(checksummed)


def test_eip55_detects_a_wrong_case() -> None:
    good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    bad = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"  # one letter flipped
    assert address.is_valid_checksum_address(good)
    assert not address.is_valid_checksum_address(bad)


def test_all_lowercase_is_accepted_as_unchecked() -> None:
    """EIP-55 must remain backwards compatible with unchecked addresses."""
    assert address.is_valid_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")


def test_address_length_is_enforced() -> None:
    with pytest.raises(ValueError):
        address.to_checksum_address("0xdeadbeef")


def test_address_from_private_key_is_consistent() -> None:
    derived = address.address_from_private_key(PRIV)
    manual = address.to_checksum_address(address.public_key_to_address(private_to_public(PRIV)))
    assert derived == manual


# --------------------------------------------------------------------------- #
# Post-quantum analysis
# --------------------------------------------------------------------------- #


def test_pqc_schemes_are_classified_correctly() -> None:
    assert not pqc.SCHEMES["ecdsa"].quantum_safe
    assert not pqc.SCHEMES["schnorr"].quantum_safe
    assert pqc.SCHEMES["ml-dsa-44"].quantum_safe
    assert pqc.SCHEMES["slh-dsa-128s"].quantum_safe


def test_post_quantum_transactions_are_much_larger() -> None:
    assert pqc.size_multiplier("ml-dsa-44") > 10
    assert pqc.size_multiplier("slh-dsa-128s") > pqc.size_multiplier("ml-dsa-44")
    # Falcon is the compact option but still far above ECDSA.
    assert 5 < pqc.size_multiplier("fn-dsa-512") < pqc.size_multiplier("ml-dsa-44")


def test_throughput_falls_as_signatures_grow() -> None:
    assert pqc.throughput_tps("ml-dsa-44") < pqc.throughput_tps("ecdsa") / 10


def test_reports_render() -> None:
    assert "ML-DSA-44" in pqc.comparison_table()
    assert "Harvest Now" in pqc.exposure_report()
