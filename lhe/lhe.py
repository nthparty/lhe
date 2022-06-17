# pylint: disable=C0103# to allow capital letters in method signatures
"""
Python homomorphic encryption library supporting up
to three multiplications and unlimited additions.
"""
from __future__ import annotations
from typing import NamedTuple, Union, Optional, Tuple
import doctest
from mclbn256 import Fr, G1, G2, GT


class CTG1(NamedTuple):
    """Ciphertext in strictly `G1 x G1` only."""
    g1r: G1
    g1m_pr: G1


class CTG2(NamedTuple):
    """Ciphertext in strictly `G2 x G2` only."""
    g2r: G2
    g2m_pr: G2


class CTGT(NamedTuple):
    """Level-2 ciphertext in $\textsf{GT}^{4}$."""
    z_r1_r2: GT
    z_r1_r2_m_s1: GT
    z_r1_r2_m_s2: GT
    z_r1_r2_mm_s1_s2: GT


class CT1(NamedTuple):
    """All-purpose (dual) level-1 ciphertext making use of both G1 and G2."""
    ctg1: CTG1
    ctg2: CTG2


class CT2(NamedTuple):
    """Level-2 ciphertext (wrapper around GT^4)."""
    ctgt: CTGT


class KPG1(NamedTuple):
    """Keypair for G1-based encryption."""
    sk: Fr  # secret scalar
    pk: G1  # public point (in Group 1)


class KPG2(NamedTuple):
    """Keypair for G2-based encryption."""
    sk: Fr  # secret scalar
    pk: G2  # public point (in Group 2)


class SK(NamedTuple):
    """Dual secret key for decryption"""
    s1: Fr  # secret scalar
    s2: Fr


class PK(NamedTuple):
    """Dual public key for encryption (either 'dumb' group-agnostic, or optimal)"""
    p1: G1  # public point (in Group 1)
    p2: G2  # public point (in Group 2)


class PK_with_precomp(NamedTuple):
    """Dual public key for encryption (either 'dumb' group-agnostic, or optimal)"""
    p1: G1  # public point (in Group 1)
    p2: G2  # public point (in Group 2)
    z2: GT# = g1 @ p2
    z3: GT# = p1 @ g2
    z4: GT# = p1 @ p2


g1 = G1().hash("Fixed public point in Group 1")
g2 = G2().hash("Fixed public point in Group 2")
z1 = g1 @ g2


def keygen_G1() -> Tuple[Fr, G1]:
    """Generate a G1 keypair."""
    s = Fr()
    p = g1 * s
    return KPG1(s, p)


def keygen_G2() -> KPG2:
    """Generate a G2 keypair."""
    s = Fr()
    p = g2 * s
    return KPG2(s, p)


def keygen() -> Tuple[SK, PK]:
    """Generate a dual keypair."""
    s1, p1 = keygen_G1()
    s2, p2 = keygen_G2()
    return SK(s1, s2), PK(p1, p2)


def encrypt_G1(p: G1, m: int) -> CTG1:
    """Encrypt a plaintext to be a G1 ciphertext."""
    r = Fr()
    return CTG1(
        g1 * r,
        (g1 * Fr(m)) + (p * r)
    )


def encrypt_G2(p: G2, m: int) -> CTG2:
    """Encrypt a plaintext to be a G2 ciphertext."""
    r = Fr()
    return CTG2(
        g2 * r,
        (g2 * Fr(m)) + (p * r)
    )


def encrypt_GT(p1: G1, p2: G2, m: int) -> CTGT:
    """Encrypt a plaintext to be a GT ciphertext."""
    r = Fr()
    s = Fr()
    t = Fr()
    #1 = g1 @ g2
    z2 = g1 @ p2
    z3 = p1 @ g2
    z4 = p1 @ p2
    return CTGT(
        z1 ** (r + s - t),
        z2 ** r,
        z3 ** s,
        z4 ** t * (z1 ** Fr(m))
    )


def encrypt_lvl_1(pk: PK, m: int) -> CT1:
    """Encrypt a plaintext to be a dual ('dumb') ciphertext."""
    ct1 = encrypt_G1(pk.p1, m)
    ct2 = encrypt_G2(pk.p2, m)
    return CT1(ct1, ct2)


def encrypt_lvl_2(pk: PK, m: int) -> CT2:
    """Encrypt a level-2 ciphertext."""
    ct = encrypt_GT(pk.p1, pk.p2, m)
    return CT2(ct)


def add_G1(ct1: CTG1, ct2: CTG1) -> CTG1:
    """Homomorphically add two G1 ciphertexts in level 1."""
    return CTG1(
        ct1.g1r + ct2.g1r,
        ct1.g1m_pr + ct2.g1m_pr
    )


def add_G2(ct1: CTG2, ct2: CTG2) -> CTG2:
    """Homomorphically add two G2 ciphertexts in level 1."""
    return CTG2(
        ct1.g2r + ct2.g2r,
        ct1.g2m_pr + ct2.g2m_pr
    )


def add_GT(ct1: CTGT, ct2: CTGT) -> CTGT:
    """Homomorphically add two GT ciphertexts in level 2."""
    return CTGT(
        ct1.z_r1_r2 + ct2.z_r1_r2,
        ct1.z_r1_r2_m_s1 + ct2.z_r1_r2_m_s1,
        ct1.z_r1_r2_m_s2 + ct2.z_r1_r2_m_s2,
        ct1.z_r1_r2_mm_s1_s2 + ct2.z_r1_r2_mm_s1_s2
    )


def multiply_G1_G2(ct1: CTG1, ct2: CTG2) -> CTGT:
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


def decrypt_G1(s1: Fr, ct: CTG1) -> Optional[int]:
    """
    Decrypt a G1 ciphertext to a plaintext.

    >>> sk, pk = keygen_G1()
    >>> ct = encrypt_G1(pk, 737)
    >>> print(decrypt_G1(sk, ct))
    737
    """
    g1m = ct.g1m_pr - (ct.g1r * s1)  # remember, p = g^s
    return dlog(g1, g1m)


def decrypt_G2(s2: Fr, ct: CTG2) -> Optional[int]:
    """
    Decrypt a G2 ciphertext to a plaintext.

    >>> sk, pk = keygen_G2()
    >>> ct = encrypt_G2(pk, 747)
    >>> int(decrypt_G2(sk, ct))
    747
    """
    g2m = ct.g2m_pr - (ct.g2r * s2)  # remember, p = g^s
    return dlog(g2, g2m)


def decrypt_GT(s1: Fr, s2: Fr, ct: CTGT):
    """
    Decrypt a level-2 ciphertext.

    >>> sk1, pk1 = keygen_G1()
    >>> sk2, pk2 = keygen_G2()

    >>> ct11 = encrypt_G1(pk1, 1)
    >>> ct12 = encrypt_G1(pk1, 2)
    >>> ct21 = encrypt_G2(pk2, 200)
    >>> ct22 = encrypt_G2(pk2, 22)

    >>> ct1 = add_G1(ct11, ct12)
    >>> ct2 = add_G2(ct21, ct22)

    >>> ct3 = multiply_G1_G2(ct1, ct2)

    >>> pt = decrypt_GT(sk1, sk2, ct3)
    >>> int(pt)
    666
    """
    z = \
        (ct.z_r1_r2 ** (s1 * s2)) * \
        (ct.z_r1_r2_m_s1 ** (-s1)) * \
        (ct.z_r1_r2_m_s2 ** (-s2)) * \
        ct.z_r1_r2_mm_s1_s2
    return dlog(z1, z)


def decrypt(sk: SK, ct: Union[CT1, CT2, G1, G2, GT]):
    """
    Type-generic decryption helper

    >>> sk, pk = keygen()

    >>> pt_m = Fr() % (2 ** 12)
    >>> m = int(pt_m)
    >>> 0 <= m < 2 ** 12
    True

    >>> decrypt(sk, encrypt_G1(pk.p1, m)) == pt_m
    True

    >>> decrypt(sk, encrypt_G2(pk.p2, m)) == pt_m
    True

    >>> decrypt(sk, encrypt_GT(pk.p1, pk.p2, m)) == pt_m
    True

    >>> decrypt(sk, encrypt_lvl_1(pk, m)) == pt_m
    True

    >>> decrypt(sk, encrypt_lvl_2(pk, m)) == pt_m
    True

    """
    if type(ct) is CT2:
        return decrypt_GT(sk.s1, sk.s2, ct.ctgt)
    if type(ct) is CT1:
        pt = decrypt_G1(sk.s1, ct.ctg1)
        return pt or decrypt_G2(sk.s2, ct.ctg2)
        # `or` in case maybe one of them got corrupted?
    if type(ct) is CTGT:
        return decrypt_GT(sk.s1, sk.s2, ct)
    if type(ct) is CTG1:
        return decrypt_G1(sk.s1, ct)
    if type(ct) is CTG2:
        return decrypt_G2(sk.s2, ct)


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


if __name__ == '__main__':
    sk1, pk1 = keygen_G1()
    sk2, pk2 = keygen_G2()

    # ct1 = encrypt_G1(pk1, 5005)
    # ct2 = encrypt_G2(pk2, 111)
    ct1 = encrypt_G1(pk1, 3)
    ct2 = encrypt_G2(pk2, 222)

    ct3 = multiply_G1_G2(ct1, ct2)

    ct4 = add_GT(ct3, ct3)

    pt = decrypt_GT(sk1, sk2, ct3)

    print("This may take a bit of time for large plaintexts...")
    print(pt)

    # pt = decrypt_GT(ct4, sk1, sk2)

    # print("This may take a bit of time for large plaintexts...")
    # print(pt)

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
