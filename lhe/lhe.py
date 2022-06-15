# pylint: disable=C0103# to allow capital letters in method signatures
"""
Python homomorphic encryption library supporting up
to three multiplications and unlimited additions.
"""
from __future__ import annotations
from typing import NamedTuple, Union, Optional, Tuple
import doctest
from mclbn256 import Fr, G1, G2, GT


def lhe(_: int) -> None:
    """
    >>> checks = []
    >>> for i in range(128):
    ...    lhe(i)
    ...    checks.append(True)
    >>> all(checks)
    True
    """


class CTG1(NamedTuple):
    """Ciphertext in strictly `G1 x G1` only."""
    g1r: G1
    g1m_pr: G1


class CTG2(NamedTuple):
    """Ciphertext in strictly `G2 x G2` only."""
    g2r: G2
    g2m_pr: G2


class CT1(NamedTuple):
    """All-purpose (dual) level-1 ciphertext making use of both G1 and G2."""
    ctg1: CTG1
    ctg2: CTG2


class CTGT(NamedTuple):
    """Level-2 ciphertext in $\textsf{GT}^{4}$."""
    z_r1_r2: GT
    z_r1_r2_m_s1: GT
    z_r1_r2_m_s2: GT
    z_r1_r2_mm_s1_s2: GT


g1 = G1().hash("Fixed public point in Group 1")
g2 = G2().hash("Fixed public point in Group 2")
z1 = g1 @ g2


def keygen1() -> Tuple[Fr, G1]:
    """Generate a G1 keypair."""
    s = Fr()
    p = g1 * s
    return s, p


def keygen2() -> Tuple[Fr, G2]:
    """Generate a G2 keypair."""
    s = Fr()
    p = g2 * s
    return s, p


def encrypt1(p: G1, m: int) -> CTG1:
    """Encrypt a plaintext to be a G1 ciphertext."""
    r = Fr()
    return CTG1(
        g1 * r,
        (g1 * Fr(m)) + (p * r)
    )


def encrypt2(p: G2, m: int) -> CTG2:
    """Encrypt a plaintext to be a G2 ciphertext."""
    r = Fr()
    return CTG2(
        g2 * r,
        (g2 * Fr(m)) + (p * r)
    )


def addG1(ct1: CTG1, ct2: CTG1) -> CTG1:
    """Homomorphically add two G1 ciphertexts in level 1."""
    return CTG1(
        ct1.g1r + ct2.g1r,
        ct1.g1m_pr + ct2.g1m_pr
    )


def addG2(ct1: CTG2, ct2: CTG2) -> CTG2:
    """Homomorphically add two G2 ciphertexts in level 1."""
    return CTG2(
        ct1.g2r + ct2.g2r,
        ct1.g2m_pr + ct2.g2m_pr
    )


def multiply(ct1: CTG1, ct2: CTG2) -> CTGT:
    """
    Homomorphically multiply two complementary level-1 ciphertexts
    and return a level-2 ciphertext of their product.
    """
    return CTGT(
        ct1.g1r @ ct2.g2r,
        ct1.g1r @ ct2.g2m_pr,
        ct1.g1m_pr @ ct2.g2r,
        ct1.g1m_pr @ ct2.g2m_pr
    )


def decryptG1(ct: CTG1, s1: Fr) -> Optional[int]:
    """Decrypt a G1 ciphertext to a plaintext."""
    z = (ct.g1r ** s1) * ct.g1m_pr
    return dlog(g1, z)


def decryptG2(ct: CTG2, s2: Fr) -> Optional[int]:
    """Decrypt a G2 ciphertext to a plaintext."""
    z = (ct.g2r ** s2) * ct.g2m_pr
    return dlog(g2, z)


def decryptGT(ct: CTGT, s1: Fr, s2: Fr):
    """
    Decrypt a level-2 ciphertext.

    >>> sk1, pk1 = keygen1()
    >>> sk2, pk2 = keygen2()

    >>> ct11 = encrypt1(pk1, 1)
    >>> ct12 = encrypt1(pk1, 2)
    >>> ct21 = encrypt2(pk2, 200)
    >>> ct22 = encrypt2(pk2, 22)

    >>> ct1 = addG1(ct11, ct12)
    >>> ct2 = addG2(ct21, ct22)

    >>> ct3 = multiply(ct1, ct2)

    >>> pt = decryptGT(ct3, sk1, sk2)
    >>> int(pt)
    666
    """
    z = \
        (ct.z_r1_r2 ** (s1 * s2)) * \
        (ct.z_r1_r2_m_s1 ** (-s1)) * \
        (ct.z_r1_r2_m_s2 ** (-s2)) * \
        ct.z_r1_r2_mm_s1_s2
    return dlog(z1, z)


def dlog(base: Union[Fr, G1, G2, GT], power: GT) -> Optional[Fr]:
    """
    Discrete logarithm on any group, either Fr, G1, G2, or GT.

    Can work with up to 20-bits before giving up.  The example below
    tests 16-bit exponents of each type (for efficiency).

    This helper may be replaced with Pollard's Kangaroo method for
    a big boost in performance.  That optimization is to be implemented.
    Alternatively, we may use a lookup table.

    >>> x = Fr()
    >>> a = Fr() % (2 ** 16)
    >>> dlog(x, x ** a) == a
    True

    >>> x = G1().randomize()
    >>> a = Fr() % (2 ** 16)
    >>> y = x * a
    >>> dlog(x, y) == a
    True

    >>> x = G2().randomize()
    >>> a = Fr() % (2 ** 16)
    >>> y = x * a
    >>> dlog(x, y) == a
    True

    >>> x = G1().randomize() @ G2().randomize()
    >>> a = Fr() % (2 ** 16)
    >>> y = x ** a
    >>> dlog(x, y) == a
    True
    """
    try:
        for exponent in map(Fr, range(pow(2, 20))):
            if base ** exponent == power:
                return exponent
    except TypeError:
        for exponent in map(Fr, range(pow(2, 20))):
            if base * exponent == power:
                return exponent
    # raise ValueError("No such exponent.")
    return None


# if __name__ == '__main__':
#     sk1, pk1 = keygen1()
#     sk2, pk2 = keygen2()
#
#     # ct1 = encrypt1(pk1, 5005)
#     # ct2 = encrypt2(pk2, 111)
#     ct1 = encrypt1(pk1, 3)
#     ct2 = encrypt2(pk2, 222)
#
#     ct3 = multiply(ct1, ct2)
#
#     pt = decryptGT(ct3, sk1, sk2)
#
#     print("This may take a bit of time for large plaintexts...")
#     print(pt)

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
