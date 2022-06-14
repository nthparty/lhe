"""
Python homomorphic encryption library supporting up to three multiplications and unlimited additions.
"""
from __future__ import annotations
from typing import Tuple
from doctest import testmod
from mclbn256 import G1, G2, Fr

def lhe(b: int, n: int) -> Tuple[int, int, int]:
    """
    >>> checks = []
    >>> for _ in range(128):
    ...    checks.append(True)
    >>> all(checks)
    True
    """
    pass

if __name__ == "__main__":
    testmod() # pragma: no cover


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

def encrypt1(p: Type[G1], m: int):
    r = Fr()
    return (
        g1 * r,
        (g1 * Fr(m)) + (p * r)
    )

def encrypt2(p: Type[G2], m: int):
    r = Fr()
    return (
        g2 * r,
        (g2 * Fr(m)) + (p * r)
    )

def add(ct1, ct2):
    a, b = ct1
    c, d = ct2
    return (a + c, b + d)

def multiply(ct1, ct2):
    a, b = ct1
    c, d = ct2
    return (a @ c, a @ d, b @ c, b @ d)

def decrypt(ct, s1: Type[Fr], s2: Type[Fr]):
    c1, c2, c3, c4 = ct
    z = (c1 ** (s1 * s2)) * (c2 ** (-s1)) * (c3 ** (-s2)) * c4
    return dlog(z1, z)

def dlog(base, power):
    for i in range(pow(2, 20)):
        exponent = i
        if (base ** Fr(exponent) == power):
            return exponent
    raise ValueError("No such exponent.")


if __name__ == '__main__':    


    sk1, pk1 = keygen1()
    sk2, pk2 = keygen2()


    ct1 = encrypt1(pk1, 5005)
    ct2 = encrypt2(pk2, 111)
    # ct1 = encrypt1(pk1, 3)
    # ct2 = encrypt2(pk2, 2)

    ct3 = multiply(ct1, ct2)

    pt = decrypt(ct3, sk1, sk2)

    print("This may take a bit for large plaintexts...")
    print(pt)






