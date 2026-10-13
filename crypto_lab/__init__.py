"""Lab 02 -- elliptic-curve cryptography, ECDSA, HD wallets and PQC impact.

Implemented from scratch on top of the standard library (plus pycryptodome for
Keccak-256, which the standard library does not provide). No cryptographic
library performs any of the mathematics.

FOR TEACHING ONLY. Nothing here is constant-time or side-channel hardened.
"""

from . import address, ecdsa, hdwallet, pqc  # noqa: F401
from .curve import G, N, P, Point, private_to_public, scalar_mul  # noqa: F401

__all__ = [
    "G",
    "N",
    "P",
    "Point",
    "address",
    "ecdsa",
    "hdwallet",
    "pqc",
    "private_to_public",
    "scalar_mul",
]

__version__ = "1.0.0"
