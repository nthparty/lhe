# pylint: disable=C0103# to allow capital letters in method signatures
"""
Python homomorphic encryption library supporting up
to three multiplications and unlimited additions.
"""
from __future__ import annotations
from typing import NamedTuple, Union, Optional, Tuple
import doctest
import pickle
from lhe import elgamal


class CTI(NamedTuple):
    """Any-level ciphertext."""
    lvl: int
    inner: CTI
    extension: int


def keygen() -> Tuple[SK, PK]:
    """Generate a dual keypair."""
    s1, p1 = keygen_G1()
    s2, p2 = keygen_G2()
    return SK(s1, s2), PK(p1, p2)


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


def multiply_G1_G2(ct1: CTG1, ct2: CTG2) -> CTGT:
    """
    Homomorphically multiply two complementary level-1 ciphertexts
    and return a level-2 ciphertext of their product.
    """
    return CTGT(
        ct1.g1r @ ct2.g2r,  # z1 ** (r1 * r2)
        ct1.g1r @ ct2.g2m_pr,  # z1 ** (r1 * (m2 + (r2 * s2))) = z1 ** ((m2 + (s2 * r2)) * r1)
        ct1.g1m_pr @ ct2.g2r,  # z1 ** ((m1 + (s1 * r1)) * r2)
        ct1.g1m_pr @ ct2.g2m_pr  # e((g1 * m1) + (p1 * r1), (g2 * m2) + (p2 * r2))
                                 # = e((g1 * m1) + (g1 * s1 * r1), (g2 * m2) + (g2 * s2 * r2))
                                 # = e((g1 * m1) + (g1 * (s1 * r1)), (g2 * m2) + (g2 * (s2 * r2)))
                                 # = e(g1 * (m1 + (s1 * r1))), g2 * (m2 + (s2 * r2)))
                                 # = e(g1 * (m1 + (s1 * r1))), g2) ** (m2 + (s2 * r2))
                                 # = e(g1, g2) ** (m1 + (s1 * r1)) ** (m2 + (s2 * r2))
                                 # = z1 ** ((m1 + (s1 * r1)) * (m2 + (s2 * r2)))
                                 # = z1 ** (
                                 #     (m2 * r1 * s1) +
                                 #     (m1 * r2 * s2) +
                                 #     (r1 * r2 * s1 * s2) +
                                 #     (m1 * m2)
                                 #   )
                                 # = z1 ** (m2 * r1 * s1)
                                 # * z1 ** (m1 * r2 * s2)
                                 # * z1 ** (r1 * r2 * s1 * s2)
                                 # * z1 ** (m1 * m2)
        # dec: m1m2 = (r1r2)(s1s2) + r1(m2+s2r2)(-s1) + r2(m1+s1r1)(-s2) + (m1+s1r1)(m2+s2r2)
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

    >>> ct1 = ct11 + ct12
    >>> ct2 = ct21 + ct22

    >>> ct3 = ct1 * ct2

    >>> pt = decrypt_GT(sk1, sk2, ct3)
    >>> int(pt)
    666

    >>> sk, pk = keygen()

    >>> ct_1 = encrypt_lvl_1(pk, 1)
    >>> ct_2 = encrypt_lvl_1(pk, 2)
    >>> ct_200 = encrypt_lvl_1(pk, 200)
    >>> ct_22 = encrypt_lvl_1(pk, 22)

    >>> ct_3 = ct_1 + ct_2
    >>> ct_222 = ct_200 + ct_22

    >>> ct_666 = ct_3 * ct_222

    >>> pt = decrypt(sk, ct_666)
    >>> int(pt)
    666

    The goal is to unmask the last ciphertext component and get z1 ** (m1 * m2).

    Note that that component,
    z1 ** ((m1 + (s1 * r1)) * (m2 + (s2 * r2))),
    expands to equal
     = z1 ** (m2 * r1 * s1)
     * z1 ** (m1 * r2 * s2)
     * z1 ** (r1 * r2 * s1 * s2)
     * z1 ** (m1 * m2)
     for whose terms we already have the ingredients to construct.

    The z1 ** (r1 * r2 * s1 * s2) specifically cancels the last negative term
    in the ct.z_m2_s2_r2__r1 by ct.z_m1_s1_r1__r2 product.

    We have z1 to the power of,
    (m2 + r1 s1)(m1 + r2 s2) = (m1 m2) + (m1 r1 s1) + (m2 r2 s2) + (r1 r2 s1 s2).

    And z1 to the power of,
    (r1 r2)(s1 s2) + r1 (m1 + r2 s2)(-s1) + r2 (m2 + r1 s1)(-s2) = -(m1 r1 s1) + -(m2 r2 s2) + -(r1 r2 s2 s1).

    Thus, we may decrypt by add these exponents (by multiplying powers) to get m1*m2
    which can be extracted by a discrete log.
    """
    z1_m1_m2 = \
        (ct.z_r1_r2 ** (s1 * s2)) * \
        (ct.z_m2_s2_r2__r1 ** (-s1)) * \
        (ct.z_m1_s1_r1__r2 ** (-s2)) * \
        ct.z_m1_s1_r1__m2_s2_r2
    return dlog(z1, z1_m1_m2)


def decrypt(sk: SK, ct: Union[CT1, CT2, CTG1, CTG2, CTGT]) -> Fr:
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
    a big boost (~2x) in performance.  That optimization is unimplemented.
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


def main():
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

    pt = decrypt_GT(sk1, sk2, ct4)

    print("This may take a bit of time for large plaintexts...")
    print(pt)

# if __name__ == "__main__":
#     main()

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover

# alias for 'dumb' API
encrypt = encrypt_lvl_1
