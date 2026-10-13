# Lab 02 — Elliptic curves, ECDSA, HD wallets and post-quantum cost

**Theory:** [[04 - Cryptographic Foundations, PKI and Post-Quantum Risks]], [[05 - Keys, Addresses and Hierarchical Deterministic Wallets]]
**Stack:** Python 3.11+ (uv). One dependency: `pycryptodome`, only for Keccak-256.
**Points:** 20

---

## Objectives

You will build the cryptographic layer of a blockchain from modular arithmetic upward: finite-field operations, elliptic-curve point addition, scalar multiplication, ECDSA signing and verification. Then you will break it — recovering a private key from two signatures that reused a nonce — and then you will build the wallet infrastructure on top, deriving a full BIP-39/32/44 hierarchy and Ethereum addresses with EIP-55 checksums. Finally you will quantify what post-quantum signatures would cost.

The reason for implementing rather than reading is specific. The mathematics of ECDSA fits on half a page, and reading it produces the comfortable sense that it is simple. It *is* simple. What is not simple is that a single mishandled value destroys it completely, silently, with the signature still verifying. That asymmetry between the elegance of the scheme and the fragility of its implementation is the actual lesson, and it is not transmissible by reading.

> [!WARNING]
> Everything in this lab is **for teaching only**. The scalar multiplication is not constant-time, nothing is hardened against side channels, and the code has not been audited. Never use it to protect anything of value. Part A explains precisely why.

---

## Prerequisites

- `uv` installed (see `../README.md`)
- Weeks 4 and 5 of the theory notes read
- Comfort with modular arithmetic; no prior cryptography required

---

## Setup

```powershell
uv sync
uv run pytest
```

64 tests should pass in about eight seconds. They check against published vectors — the secp256k1 doubling of `G`, the BIP-39 zero-entropy seed, the four EIP-55 examples, the Keccak-256 empty-string digest — so a green run means agreement with the rest of the world, not merely with itself.

Run the demonstrations:

```powershell
uv run python -m crypto_lab           # everything
uv run python -m crypto_lab curve     # Part A
uv run python -m crypto_lab ecdsa     # Part B
uv run python -m crypto_lab wallet    # Part C
uv run python -m crypto_lab pqc       # Part D
```

---

## Part A — Curve arithmetic

**Read:** `crypto_lab/curve.py`. **Run:** `uv run python -m crypto_lab curve`.

The curve is

$$y^2 \equiv x^3 + 7 \pmod p, \qquad p = 2^{256} - 2^{32} - 977$$

Three things in the module are worth dwelling on.

**Division is modular inversion.** `inverse_mod` uses Fermat's little theorem, $a^{p-2} \equiv a^{-1}$, which holds because $p$ is prime. Writing a plain `/` where the formulas say division is the classic first-implementation bug, and it fails silently in a way that produces points that are not on the curve.

**Double-and-Add reduces $k \cdot P$ from $\mathcal{O}(k)$ to $\mathcal{O}(\log k)$.** With $k \approx 2^{256}$ this is the difference between impossible and instantaneous.

**The implementation leaks the key through timing.** Look at `scalar_mul`: the addition executes only when the current bit of $k$ is 1. An adversary measuring execution time or power draw reads the secret scalar bit by bit. `scalar_mul_ladder` shows the Montgomery ladder, which performs the same operations regardless of the bit. A test asserts the two agree on random inputs, which is the right way to introduce a hardened variant: prove functional equivalence first.

**For your report:** run the group-law checks and record the results. Explain in your own words why $n \cdot G = \mathcal{O}$ must hold, and what would be broken if the implemented order were wrong by one.

---

## Part B — ECDSA, and the nonce

**Read:** `crypto_lab/ecdsa.py`. **Run:** `uv run python -m crypto_lab ecdsa`.

Signing and verification are implemented directly from the definitions, plus three refinements that separate a toy from something resembling real code.

**RFC 6979 deterministic nonces.** `k` is derived by HMAC from the private key and the message hash, so it never depends on the quality of the system's entropy source, yet stays unpredictable to anyone without the key. A useful side effect: signatures become reproducible, and therefore testable.

**Low-s normalisation.** Both $(r, s)$ and $(r, n-s)$ verify, because $R$ and $-R$ share an x-coordinate. The demo prints both verifying. Bitcoin's policy rule and Ethereum's EIP-2 forbid the high form, and OpenZeppelin's `ECDSA` library enforces it — which is why the Week 10 `permit` implementation must use that library rather than raw `ecrecover`.

**Public-key recovery.** `recover_public_key` reconstructs the signer's key from the signature, which is why an Ethereum transaction carries no public key. Note the cost of that saving: it makes every account that has ever transacted quantum-exposed, a point Part D returns to.

### The attack

The centrepiece. Two signatures made with the same `k`:

$$s_1 - s_2 = k^{-1}(z_1 - z_2) \;\Longrightarrow\; k = \frac{z_1 - z_2}{s_1 - s_2}, \qquad d = \frac{s_1 k - z_1}{r}$$

The attacker needs the two signatures and the two messages. Not the nonce, no side channel, no computation beyond a modular inverse. And the reuse is **advertised in plain sight**, because equal nonces produce equal `r` values — anyone scanning a chain for repeated `r` under one key is running this attack at scale, and people do.

Two real cases: Sony's PlayStation 3 code-signing key in 2010 (a fixed nonce), and a series of Android Bitcoin wallets in 2013 (a broken `SecureRandom`).

**For your report:** run the demo, paste the recovered key next to the original, and explain why RFC 6979 removes the vulnerability without making `k` predictable to an attacker.

---

## Part C — HD wallets

**Read:** `crypto_lab/hdwallet.py`, `crypto_lab/address.py`. **Run:** `uv run python -m crypto_lab wallet`.

The full pipeline: mnemonic → PBKDF2 → 512-bit seed → HMAC-SHA512 master key → BIP-32 derivation → BIP-44 path → public key → Keccak-256 → EIP-55 address.

Points to observe in the output.

**The passphrase enters the salt, not the password.** There is therefore no wrong passphrase; each one opens a different, valid, usually empty wallet. The demo shows `'correct horse'` and `'correct horse '` — differing by one trailing space — producing entirely unrelated addresses. This is what makes plausible-deniability wallets possible and also what makes a mistyped passphrase indistinguishable from theft.

**Keccak-256 is not SHA3-256.** Ethereum uses the pre-standardisation Keccak, whose padding rule differs. `hashlib.sha3_256` is the wrong function and yields wrong addresses; a test asserts the two differ. Solidity's historical `sha3()` alias caused the same confusion.

**EIP-55 hashes the lowercase hex *string*, not the bytes.** About fifteen letters carry one bit each, so roughly one random typo in 32,000 slips through — weak, but the alternative was nothing at all, and it is backwards compatible.

### The parent-key recovery attack

`recover_parent_private_key` demonstrates why BIP-44 hardens `purpose`, `coin_type` and `account`. Given an account **xpub** — which is meant to be safe to publish, and is published, for watch-only wallets and shop payment addresses — plus **one** leaked non-hardened child private key:

$$\text{child} = (I_L + \text{parent}) \bmod n \;\Longrightarrow\; \text{parent} = (\text{child} - I_L) \bmod n$$

and $I_L$ is computable from the chain code and public key, both of which are in the xpub. One leaked child compromises the entire branch. Hardened derivation blocks it because $I_L$ then depends on the parent *private* key.

**For your report:** run the demo, and explain why the same attack fails against a hardened child. Then state which real deployment scenario the attack corresponds to.

---

## Part D — Post-quantum cost

**Read:** `crypto_lab/pqc.py`. **Run:** `uv run python -m crypto_lab pqc`.

Shor's algorithm does not weaken elliptic-curve signatures; it ends them. Grover's only halves hash security, repaired by doubling the output. So migration means replacing signatures — and the obstacle is size, not availability.

The module produces the size and throughput comparison across ECDSA, Schnorr and the NIST standards (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, FIPS 206 FN-DSA), plus an exposure report classifying which coins are actually at risk.

The exposure classification is the part most often got wrong in reports. An unspent P2PKH output publishes only `HASH160(pubkey)`, so Shor has nothing to work with — those coins are currently protected. Exposed are ancient P2PK outputs (including a substantial share of early mining rewards), reused addresses, transactions sitting in the mempool, and **every Ethereum account that has ever transacted**, because `ecrecover` makes the public key derivable from any signature on chain.

**For your report:** produce the comparison table, then answer: for an asset that must remain secure for fifteen years, is the migration decision due now or later? Justify using the harvest-now-decrypt-later argument rather than a forecast of quantum hardware.

---

## `[STUDENT TASK]` — What you must implement yourself

Submit your own implementation in a separate repository, satisfying:

1. **Field and curve arithmetic** — modular inverse, point addition, doubling, and scalar multiplication by Double-and-Add. Include a constant-time variant and assert equivalence on random inputs.
2. **SEC1 serialisation** — compressed and uncompressed, with y recovered from x on parse, and off-curve points rejected.
3. **ECDSA** — sign, verify, RFC 6979 nonce derivation, low-s normalisation, and public-key recovery with a correct recovery id.
4. **The nonce-reuse attack** — recovering the private key from two signatures, working correctly even when both were low-s normalised.
5. **BIP-32/39/44** — seed derivation, master key, hardened and normal child derivation, path parsing, and public-only (xpub) derivation.
6. **The parent-key recovery attack** on a non-hardened child.
7. **Ethereum addresses** with EIP-55 checksums.

The test suite in `tests/test_crypto.py` is a valid specification. If your implementation passes it unchanged, requirements 1 to 7 are met.

You may not use `ecdsa`, `coincurve`, `eth-keys`, `bip_utils` or any equivalent. `pycryptodome` for Keccak-256 and `hashlib`/`hmac` for SHA-256, SHA-512, HMAC and PBKDF2 are permitted — implementing hash functions is not the subject of this lab.

---

## Deliverables

A PDF report plus a repository link. The report must contain:

1. Part A group-law verification output, with the explanation requested above.
2. Part B nonce-reuse demonstration, showing the recovered key equals the original, and your account of why RFC 6979 fixes it.
3. Part C derivation output for three accounts, the passphrase demonstration, and the parent-key recovery result with an explanation of why hardening prevents it.
4. Part D comparison table and the fifteen-year migration argument.
5. A section of at most 400 words on **implementation risk**: identify three ways a correct-looking ECDSA implementation can leak the private key while producing signatures that verify. Your own code contains at least one of them; say which.

---

## Grading rubric (20 points)

| Criterion | Points |
|---|---|
| Curve arithmetic correct, including edge cases (identity, negation, doubling at y=0) | 3 |
| Constant-time variant implemented and proven equivalent | 2 |
| ECDSA sign/verify correct; RFC 6979 deterministic and in range | 3 |
| Low-s and recovery id handled correctly | 2 |
| Nonce-reuse attack works, including after low-s normalisation | 3 |
| BIP-32/39/44 derivation reaches the correct published address | 3 |
| Parent-key recovery attack demonstrated and explained | 2 |
| EIP-55 correct against published vectors | 1 |
| Report quality: correct terminology, honest implementation-risk section | 1 |

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'Crypto'`** — run `uv sync`. The package is `pycryptodome` but imports as `Crypto`.

**Addresses do not match any wallet** — you are almost certainly using `hashlib.sha3_256` instead of Keccak-256. They are different functions. A test guards this.

**`ValueError: x does not correspond to a point on the curve`** — roughly half of all x values have no y. On parse this is correct behaviour; if it happens on a key you generated, your scalar multiplication is wrong.

**Nonce-reuse recovery returns the wrong key** — you are not handling the low-s sign ambiguity. Flipping `s` corresponds to negating `k`, so both signatures may have been flipped independently; try all four combinations and keep the candidate whose public key verifies both signatures.

**Derived address differs from MetaMask** — check the path. MetaMask uses `m/44'/60'/0'/0/i`, incrementing the *address* index; some hardware wallets historically incremented the *account* index instead, giving different addresses from the same mnemonic.

**Tests are slow** — expected. Every scalar multiplication is ~256 Python-level point operations with 256-bit integers. Around eight seconds for the full suite is normal.
