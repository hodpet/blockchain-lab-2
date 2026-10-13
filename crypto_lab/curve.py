"""secp256k1 arithmetic, implemented from scratch.

Nothing here uses a cryptographic library. The point of the lab is that the
curve operations underlying every Bitcoin and Ethereum signature are a few dozen
lines of modular arithmetic, and that seeing them removes the mystique.

    y^2 = x^3 + 7   (mod p)

secp256k1 is a Koblitz curve: a = 0, b = 7, and the field prime has a special
form that permits fast reduction. Its parameters are "nothing up my sleeve" --
so simple that there is no degree of freedom in which a backdoor could hide,
which is the usual explanation for why Nakamoto chose it over the NIST curves.

WARNING: this implementation is for teaching. It is not constant-time and must
never be used to protect anything of value. See `scalar_mul_ladder` for the
discussion of why.
"""

from __future__ import annotations

from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Domain parameters (SEC 2, secp256k1)
# --------------------------------------------------------------------------- #

#: Field prime. Note the form 2^256 - 2^32 - 977, chosen for fast reduction.
P = 2**256 - 2**32 - 977

#: Curve coefficients: y^2 = x^3 + A*x + B
A = 0
B = 7

#: Order of the generator: the number of distinct points in the subgroup.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#: Cofactor. 1 means the curve group has no small subgroups, which removes a
#: whole family of implementation pitfalls that plague other curves.
H = 1

_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# --------------------------------------------------------------------------- #
# Field helpers
# --------------------------------------------------------------------------- #


def inverse_mod(value: int, modulus: int = P) -> int:
    """Modular multiplicative inverse.

    "Division" on an elliptic curve means multiplying by this. Forgetting that
    and writing a plain `/` is the single most common error in a first
    implementation.

    Fermat's little theorem gives a^(p-2) = a^-1 (mod p) for prime p, and
    Python's built-in pow does the modular exponentiation efficiently.
    """
    if value % modulus == 0:
        raise ZeroDivisionError("no inverse for 0 modulo a prime")
    return pow(value, modulus - 2, modulus)


# --------------------------------------------------------------------------- #
# Points
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Point:
    """An affine point on secp256k1, or the point at infinity.

    The point at infinity (the group identity) is represented by x = y = None.
    """

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __repr__(self) -> str:  # pragma: no cover - display only
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point(0x{self.x:064x}, 0x{self.y:064x})"


#: The point at infinity, identity element of the group.
INFINITY = Point(None, None)

#: The standard generator point.
G = Point(_GX, _GY)


def is_on_curve(point: Point) -> bool:
    """Check that a point satisfies the curve equation.

    Always validate points that arrive from outside. Accepting an off-curve
    point is the basis of invalid-curve attacks, which can leak the private key
    over repeated operations.
    """
    if point.is_infinity:
        return True
    assert point.x is not None and point.y is not None
    return (point.y * point.y - point.x**3 - A * point.x - B) % P == 0


def negate(point: Point) -> Point:
    """Reflection in the x-axis: the group inverse.

    This symmetry is also the origin of ECDSA's s-malleability, because R and -R
    share an x-coordinate and therefore produce the same r value.
    """
    if point.is_infinity:
        return INFINITY
    assert point.x is not None and point.y is not None
    return Point(point.x, (-point.y) % P)


def double(point: Point) -> Point:
    """Point doubling: the tangent line construction.

        lambda = (3*x^2 + a) / (2*y)
        x3 = lambda^2 - 2*x
        y3 = lambda*(x - x3) - y
    """
    if point.is_infinity:
        return INFINITY
    assert point.x is not None and point.y is not None

    # A point with y = 0 has a vertical tangent; doubling it gives infinity.
    if point.y == 0:
        return INFINITY

    lam = (3 * point.x * point.x + A) * inverse_mod(2 * point.y) % P
    x3 = (lam * lam - 2 * point.x) % P
    y3 = (lam * (point.x - x3) - point.y) % P
    return Point(x3, y3)


def add(p1: Point, p2: Point) -> Point:
    """Point addition: the chord construction.

        lambda = (y2 - y1) / (x2 - x1)
        x3 = lambda^2 - x1 - x2
        y3 = lambda*(x1 - x3) - y1

    with the two degenerate cases handled separately: adding the identity, and
    adding a point to its own negation (a vertical chord, meeting the curve at
    infinity).
    """
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1

    assert p1.x is not None and p1.y is not None
    assert p2.x is not None and p2.y is not None

    if p1.x == p2.x:
        if (p1.y + p2.y) % P == 0:
            # p2 == -p1: the chord is vertical.
            return INFINITY
        # p1 == p2: use the tangent instead of a chord.
        return double(p1)

    lam = (p2.y - p1.y) * inverse_mod(p2.x - p1.x) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


# --------------------------------------------------------------------------- #
# Scalar multiplication
# --------------------------------------------------------------------------- #


def scalar_mul(k: int, point: Point = G) -> Point:
    """Double-and-Add: compute k*P in O(log k) instead of O(k).

    Naively, k*P means adding P to itself k times. With k on the order of 2^256
    that is not merely slow, it is physically impossible. The binary expansion
    of k reduces it to about 256 doublings and at most 256 additions.

    THIS FUNCTION IS NOT CONSTANT-TIME. The addition executes only when the
    current bit is 1, so an attacker who can measure execution time or power
    consumption reads the secret scalar bit by bit. Production implementations
    use a Montgomery ladder or a fixed-window method with dummy operations --
    see `scalar_mul_ladder` below.
    """
    if k % N == 0 or point.is_infinity:
        return INFINITY
    if k < 0:
        return scalar_mul(-k, negate(point))

    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = add(result, addend)
        addend = double(addend)
        k >>= 1
    return result


def scalar_mul_ladder(k: int, point: Point = G) -> Point:
    """Montgomery ladder: the same result with a uniform operation sequence.

    Every iteration performs exactly one addition and one doubling regardless of
    the bit value, so the timing and power trace no longer depend on the secret.
    (Python's arbitrary-precision integers still leak through other channels, so
    this is illustrative rather than genuinely hardened.)

    Compare its output with `scalar_mul` -- they must agree for every input,
    which is a good property to assert in a fuzz test.
    """
    if k % N == 0 or point.is_infinity:
        return INFINITY
    if k < 0:
        return scalar_mul_ladder(-k, negate(point))

    r0, r1 = INFINITY, point
    for i in reversed(range(k.bit_length())):
        if (k >> i) & 1:
            r0, r1 = add(r0, r1), double(r1)
        else:
            r0, r1 = double(r0), add(r0, r1)
    return r0


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #


def private_to_public(private_key: int) -> Point:
    """Q = d*G. The entire asymmetry of the system is in this one line.

    Computing Q from d costs about 256 point operations. Recovering d from Q is
    the elliptic curve discrete logarithm problem: O(sqrt(N)) ~ 2^128 with the
    best known classical algorithm (Pollard's rho), and polynomial time on a
    sufficiently large quantum computer via Shor's algorithm.
    """
    if not 1 <= private_key < N:
        raise ValueError(f"private key must be in [1, N-1], got {private_key}")
    return scalar_mul(private_key, G)


def serialize_public_key(point: Point, compressed: bool = True) -> bytes:
    """SEC1 point encoding.

    Compressed form is 33 bytes: a prefix encoding the parity of y, then x.
    Since y can be recovered from x through the curve equation, storing y is
    redundant -- only its sign is needed. Uncompressed form is 65 bytes.

    The distinction matters in practice: the same private key yields DIFFERENT
    Bitcoin addresses depending on which encoding is hashed.
    """
    if point.is_infinity:
        raise ValueError("cannot serialise the point at infinity")
    assert point.x is not None and point.y is not None

    if compressed:
        prefix = b"\x03" if point.y & 1 else b"\x02"
        return prefix + point.x.to_bytes(32, "big")
    return b"\x04" + point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")


def deserialize_public_key(data: bytes) -> Point:
    """Parse a SEC1-encoded point, recovering y from x for compressed form."""
    if len(data) == 65 and data[0] == 0x04:
        point = Point(
            int.from_bytes(data[1:33], "big"),
            int.from_bytes(data[33:65], "big"),
        )
    elif len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")
        # y^2 = x^3 + 7, so y = (x^3 + 7)^((p+1)/4) because p = 3 (mod 4).
        y_squared = (pow(x, 3, P) + B) % P
        y = pow(y_squared, (P + 1) // 4, P)
        if y * y % P != y_squared:
            raise ValueError("x does not correspond to a point on the curve")
        # Choose the root with the parity indicated by the prefix.
        if (y & 1) != (data[0] & 1):
            y = P - y
        point = Point(x, y)
    else:
        raise ValueError(f"unrecognised public key encoding: {len(data)} bytes")

    if not is_on_curve(point):
        raise ValueError("point is not on the curve")
    return point
