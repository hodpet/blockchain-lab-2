"""Post-quantum impact analysis.

Shor's algorithm does not weaken elliptic-curve signatures, it ends them: given
the public key, the private key follows in polynomial time. Grover's algorithm
only halves the security of hash functions, which is repaired by doubling the
output size.

So post-quantum migration means replacing signatures. The obstacle is not that
the algorithms are missing -- NIST standardised three of them in 2024 -- but
that they are one to two orders of magnitude larger, and on a blockchain every
byte is stored forever on every node.

This module quantifies that, and classifies which coins are actually at risk.
"""

from __future__ import annotations

from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Signature schemes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Scheme:
    name: str
    standard: str
    public_key_bytes: int
    signature_bytes: int
    quantum_safe: bool
    note: str

    @property
    def witness_bytes(self) -> int:
        """What a spend actually costs on chain: signature plus public key."""
        return self.public_key_bytes + self.signature_bytes


SCHEMES: dict[str, Scheme] = {
    "ecdsa": Scheme(
        name="ECDSA (secp256k1)",
        standard="SEC 2 / SEC 1",
        public_key_bytes=33,  # compressed
        signature_bytes=72,  # DER-encoded, worst case
        quantum_safe=False,
        note="Today's Bitcoin and Ethereum. Broken outright by Shor.",
    ),
    "schnorr": Scheme(
        name="Schnorr (BIP-340)",
        standard="BIP-340",
        public_key_bytes=32,  # x-only
        signature_bytes=64,
        quantum_safe=False,
        note="Taproot. Aggregatable, provably secure -- but equally Shor-broken.",
    ),
    "ml-dsa-44": Scheme(
        name="ML-DSA-44 (Dilithium2)",
        standard="FIPS 204",
        public_key_bytes=1312,
        signature_bytes=2420,
        quantum_safe=True,
        note="Lattice-based. NIST's primary general-purpose recommendation.",
    ),
    "ml-dsa-65": Scheme(
        name="ML-DSA-65 (Dilithium3)",
        standard="FIPS 204",
        public_key_bytes=1952,
        signature_bytes=3309,
        quantum_safe=True,
        note="Higher security category than ML-DSA-44.",
    ),
    "slh-dsa-128s": Scheme(
        name="SLH-DSA-128s (SPHINCS+)",
        standard="FIPS 205",
        public_key_bytes=32,
        signature_bytes=7856,
        quantum_safe=True,
        note="Hash-based: security rests only on the hash function. Conservative, huge.",
    ),
    "fn-dsa-512": Scheme(
        name="FN-DSA-512 (Falcon)",
        standard="FIPS 206",
        public_key_bytes=897,
        signature_bytes=666,
        quantum_safe=True,
        note="Most compact PQ option; needs floating point, hard to make constant-time.",
    ),
}


# --------------------------------------------------------------------------- #
# Transaction size modelling
# --------------------------------------------------------------------------- #

#: Bytes of a P2WPKH transaction that are NOT signature or public key:
#: version, counts, outpoint, sequence, one output, locktime, overheads.
_TX_OVERHEAD_BYTES = 110

#: Rough current Bitcoin capacity, used only to express the impact as a ratio.
_BLOCK_CAPACITY_VBYTES = 1_000_000
_BLOCK_INTERVAL_SECONDS = 600


def transaction_size(scheme_key: str, inputs: int = 1) -> int:
    """Size in bytes of a single-output transaction with `inputs` signed inputs."""
    scheme = SCHEMES[scheme_key]
    return _TX_OVERHEAD_BYTES + inputs * scheme.witness_bytes


def size_multiplier(scheme_key: str, inputs: int = 1) -> float:
    """How much larger than today's ECDSA equivalent."""
    return transaction_size(scheme_key, inputs) / transaction_size("ecdsa", inputs)


def throughput_tps(scheme_key: str, inputs: int = 1) -> float:
    """Transactions per second at fixed block capacity."""
    per_block = _BLOCK_CAPACITY_VBYTES / transaction_size(scheme_key, inputs)
    return per_block / _BLOCK_INTERVAL_SECONDS


def comparison_table(inputs: int = 1) -> str:
    """Render the size and throughput comparison."""
    header = (
        f"{'scheme':<26}{'PQ':<5}{'pk':>7}{'sig':>8}{'tx':>8}{'x ECDSA':>10}{'tps':>9}"
    )
    lines = [header, "-" * len(header)]
    for key, scheme in SCHEMES.items():
        lines.append(
            f"{scheme.name:<26}"
            f"{'yes' if scheme.quantum_safe else 'no':<5}"
            f"{scheme.public_key_bytes:>7}"
            f"{scheme.signature_bytes:>8}"
            f"{transaction_size(key, inputs):>8}"
            f"{size_multiplier(key, inputs):>9.1f}x"
            f"{throughput_tps(key, inputs):>9.2f}"
        )
    lines.append("")
    lines.append(f"(single-output transaction, {inputs} signed input(s), 1 MB block, 10 min)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Exposure analysis
# --------------------------------------------------------------------------- #

EXPOSURE = {
    "p2pkh_unspent": (
        "PROTECTED (for now)",
        "Only HASH160(pubkey) is on chain. Shor needs the public key itself, and "
        "a hash cannot be inverted by Shor -- only Grover applies, and it is far "
        "too weak. The key becomes exposed the moment the output is spent.",
    ),
    "p2pk": (
        "EXPOSED",
        "The raw public key sits in the output script. This includes a large share "
        "of early mining rewards, among them roughly one million BTC attributed to "
        "Satoshi. These coins are readable by any future quantum adversary.",
    ),
    "reused_address": (
        "EXPOSED",
        "A previous spend already published the public key, and a balance remains. "
        "Address reuse converts a protected output into an exposed one.",
    ),
    "mempool_transaction": (
        "EXPOSED (briefly)",
        "Between broadcast and confirmation the public key is public but the coin "
        "has not moved. A sufficiently fast quantum attacker could race a "
        "competing spend into the same block.",
    ),
    "ethereum_any_active": (
        "EXPOSED",
        "Ethereum transmits (v, r, s) and recovers the public key with ecrecover, so "
        "the key of EVERY account that has ever sent a transaction is derivable from "
        "chain data. Ethereum's exposure is structurally worse than Bitcoin's.",
    ),
}


def exposure_report() -> str:
    lines = ["Which coins are actually at risk?", "=" * 78, ""]
    for key, (verdict, explanation) in EXPOSURE.items():
        lines.append(f"{key:<24} {verdict}")
        for chunk in _wrap(explanation, 74):
            lines.append(f"{'':<24} {chunk}")
        lines.append("")
    lines.append(
        "The decisive point is not WHEN a quantum computer arrives, but HOW LONG the "
        "value must stay protected. A public ledger is permanent, so an adversary can "
        "harvest every public key today and decrypt later -- 'Harvest Now, Decrypt "
        "Later'. For assets held over a decade, the migration decision is due now."
    )
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, line, out = text.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out
