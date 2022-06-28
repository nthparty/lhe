# pylint: disable=C0103# to allow capital letters in method signatures
"""
Python homomorphic encryption library supporting up
to three multiplications and unlimited additions.
"""
from __future__ import annotations

import warnings
from typing import NamedTuple, Union, Optional, Tuple, List
import doctest
import pickle
import secrets
from lhe import elgamal

SK = elgamal.SK
PK = elgamal.PK

_pk: PK = PK(None, None)
class CTD(NamedTuple):
    """An at-most-level-d ciphertext."""
    lvl: int
    masked: int
    enc_mask: Union[CTD, elgamal.CT1]#, elgamal.CT2]

    def __radd__(self, other: Union[CTD, int]) -> CTD:
        if type(other) == int:
            if other == 0:
                return self
            return self + encrypt_for_d(_pk, self.lvl, other)

    def __add__(self, other: Union[CTD, int]) -> CTD:
        if type(other) == int:
            if other == 0:
                return self
            return self + encrypt_for_d(_pk, self.lvl, other)

        assert(self.lvl == other.lvl)  # Could maybe raise (inefficiently) the lower one if differs.

        if self.lvl <= d:
            return CTD(
                self.lvl,
                (self.masked + self.masked) % pt_mod,
                self.enc_mask + other.enc_mask,
            )
        warnings.warn("Returned None")

    def __mul__(self, other: Union[CTD, int]) -> Union[CTD, CT2D]:
        if type(other) == int:
            return sum([self] * other)  # This could be improved by an add-and-double-style product.

        assert self.lvl <= d and other.lvl <= d

        if self.lvl + other.lvl <= d:
            return CTD(
                self.lvl + other.lvl,
                (self.masked * self.masked) % pt_mod,
                self.enc_mask * other.enc_mask +
                other.enc_mask * self.masked +
                self.enc_mask * other.masked
            )

        if self.lvl + other.lvl <= 2*d:
            return CT2D(
                self.lvl + other.lvl,
                # encrypt_for_d(_pk, self.lvl + other.lvl, self.masked * other.masked) +
                # encrypt_for_d(_pk, 2*d, self.masked * other.masked) +
                # encrypt_for_d(_pk, d, self.masked * other.masked) +
                encrypt_for_d(_pk, other.enc_mask.lvl, self.masked * other.masked) +
                other.enc_mask * self.masked +
                self.enc_mask * other.masked,
                [(self.enc_mask, other.enc_mask)]
            )
        warnings.warn("Returned None")

    def decrypt(self, sk: SK) -> int:
        return self.masked + self.enc_mask.decrypt(sk)


class CT2D(NamedTuple):
    """An at-most-level-2d ciphertext."""
    lvl: int
    enc_mask: Union[CTD, elgamal.CT1]
    enc_masks: List[Tuple[Union[CTD, elgamal.CT1], Union[CTD, elgamal.CT1]]]

    def __add__(self, other) -> CT2D:
        assert(self.lvl == other.lvl)  # Could maybe raise (inefficiently) the lower one if differs.

        if d < self.lvl <= 2*d:
            return CT2D(
                self.lvl,
                self.enc_mask + other.enc_mask,   # homomorphic addition
                self.enc_masks + other.enc_masks  # list concatenation
            )
        warnings.warn("Returned None")

    def __mul__(self, other: Union[CT2D, int]) -> CT2D:
        if type(other) == int:
            return sum([self] * other)  # This could be improved by an add-and-double-style product.
        warnings.warn("Returned None")

    def decrypt(self, sk: SK) -> int:
        return self.enc_mask.decrypt(sk) + sum(
            a.decrypt(sk) * b.decrypt(sk)
            for a, b in self.enc_masks
        )
        warnings.warn("Returned None")


d = 2
pt_mod = 2 ** 10
rand_pt = lambda: secrets.randbelow(pt_mod)


def keygen() -> Tuple[SK, PK]:
    """Generate a new keypair."""
    return elgamal.keygen()


def encrypt_for_d(pk: PK, _d: int, m: int) -> Union[elgamal.CT1, CTD, CT2D]:
    """Encrypt a ciphertext for the given level."""
    global _pk, d
    _pk = pk  # TODO: FIX
    d = max(_d, d)
    if _d == 1:
        return elgamal.encrypt_lvl(pk, 1, m)
    # if _d == 2:
    #     return elgamal.encrypt_for_d(pk, 2, m)
    else:
        b = rand_pt()
        return CTD(
            _d,
            (m - b) % pt_mod,
            encrypt_for_d(pk, _d-1, b)
        )


# def encrypt_lvl(pk: PK, lvl: int, m: int) -> Union[elgamal.CT1, CTD, CT2D]:
#     """Encrypt a ciphertext for the given level."""
#     _pk = pk  # TODO: FIX
#     if lvl == 1:
#         return elgamal.encrypt_lvl(pk, 1, m)
#     # if lvl == 2:
#     #     return elgamal.encrypt_lvl(pk, 2, m)
#     if lvl <= d:
#         b = rand_pt()
#         return CTD(
#             lvl,
#             (m - b) % pt_mod,
#             encrypt_lvl(pk, lvl-1, b)
#         )
#     else:
#         assert lvl <= d and "Not implemented yet."


def main():
    encrypt = encrypt_for_d  # from lhe.level_d import keygen, encrypt

    sk, pk = keygen()
    ct1 = encrypt(pk, _d=10, m=6)
    ct2 = encrypt(pk, _d=10, m=3)

    print((ct1 + ct2).decrypt(sk))
    print((ct1 * ct2).decrypt(sk))
    print(((ct1*2) + ct2).decrypt(sk))
    print(((ct1*2) * ct2).decrypt(sk))

    global _pk, d
    print(_pk, d)



    # sk1, pk1 = keygen_G1()
    # sk2, pk2 = keygen_G2()
    #
    # # ct1 = encrypt_G1(pk1, 5005)
    # # ct2 = encrypt_G2(pk2, 111)
    # ct1 = encrypt_G1(pk1, 3)
    # ct2 = encrypt_G2(pk2, 222)
    #
    # ct3 = multiply_G1_G2(ct1, ct2)
    #
    # ct4 = add_GT(ct3, ct3)
    #
    # pt = decrypt_GT(sk1, sk2, ct3)
    #
    # print("This may take a bit of time for large plaintexts...")
    # print(pt)
    #
    # pt = decrypt_GT(sk1, sk2, ct4)
    #
    # print("This may take a bit of time for large plaintexts...")
    # print(pt)
    pass

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover

# Alias for 'dumb' API
encrypt = encrypt_for_d
