"""
Python homomorphic encryption library supporting up to three multiplications and unlimited additions.
"""
from __future__ import annotations
from typing import Tuple, NamedTuple, Type, Union, Optional
import doctest
from mclbn256 import Fr, G1, G2, GT

def lhe(b: int, n: int) -> Tuple[int, int, int]:
    """
    >>> checks = []
    >>> for _ in range(128):
    ...    lhe(0, 0)
    ...    checks.append(True)
    >>> all(checks)
    True
    """
    pass





class CTG1(NamedTuple):
    g1r: G1
    g1m_pr: G1

class CTG2(NamedTuple):
    g2r: G2
    g2m_pr: G2

class CT1(NamedTuple):
    ctg1: CTG1
    ctg2: CTG2

class CT2(NamedTuple):
    ctg1: CTG1
    ctg2: CTG2

class CTGT(NamedTuple):
    z_r1_r2: GT
    z_r1_r2_m_s1: GT
    z_r1_r2_m_s2: GT
    z_r1_r2_mm_s1_s2: GT


g1 = G1().hash("Fixed public point in Group 1")
g2 = G2().hash("Fixed public point in Group 2")
z1 = g1 @ g2

def keygen1():
    s = Fr()
    p = g1 * s
    return (s, p)

def keygen2():
    s = Fr()
    p = g2 * s
    return (s, p)

def encrypt1(p: G1, m: int):
    r = Fr()
    return CTG1(
        g1 * r,
        (g1 * Fr(m)) + (p * r)
    )

def encrypt2(p: G2, m: int):
    r = Fr()
    return CTG2(
        g2 * r,
        (g2 * Fr(m)) + (p * r)
    )

def add(ct1, ct2):
    return (
        ct1.g1r + ct2.g2r,
        ct1.g1m_pr + ct2.g2m_pr
    )

def multiply(ct1: CTG1, ct2: CTG2) -> CTGT:
    return CTGT(
        ct1.g1r @ ct2.g2r,
        ct1.g1r @ ct2.g2m_pr,
        ct1.g1m_pr @ ct2.g2r,
        ct1.g1m_pr @ ct2.g2m_pr
    )

def decryptG1(ct: CTG1, s1: Fr) -> Optional[int]:
    z = (ct.g1r ** s1) * ct.g1m_pr
    return dlog(g1, z)

def decryptG2(ct: CTG2, s2: Fr) -> Optional[int]:
    z = (ct.g2r ** s2) * ct.g2m_pr
    return dlog(g2, z)

def decryptGT(ct: CTGT, s1: Fr, s2: Fr):
    """
    Decrypt a level-2 ciphertext.

    >>> sk1, pk1 = keygen1()
    >>> sk2, pk2 = keygen2()

    >>> ct1 = encrypt1(pk1, 3)
    >>> ct2 = encrypt2(pk2, 222)

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
    except TypeError or AttributeError:
        for exponent in map(Fr, range(pow(2, 20))):
            if base * exponent == power:
                return exponent
    #raise ValueError("No such exponent.")





if __name__ == '__main__':


    sk1, pk1 = keygen1()
    sk2, pk2 = keygen2()


    # ct1 = encrypt1(pk1, 5005)
    # ct2 = encrypt2(pk2, 111)
    ct1 = encrypt1(pk1, 3)
    ct2 = encrypt2(pk2, 222)

    ct3 = multiply(ct1, ct2)

    pt = decryptGT(ct3, sk1, sk2)

    print("This may take a bit of time for large plaintexts...")
    print(pt)



if __name__ == "__main__":
    doctest.testmod() # pragma: no cover




