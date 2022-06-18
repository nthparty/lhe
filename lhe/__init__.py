"""This library exports everything needed to perform level-4 homomorphic encryption."""
from lhe import elgamal, level_d


def get_exports():
    import types
    # class two_level(types.ModuleType):

    two_level = types.ModuleType('two-level fully homomorphic encryption')
    many_level = types.ModuleType('leveled fully homomorphic encryption')

    two_level.keygen = elgamal.keygen
    two_level.encrypt = elgamal.encrypt
    two_level.decrypt = elgamal.decrypt
    two_level.advanced = elgamal

    many_level.keygen = level_d.keygen
    many_level.encrypt = level_d.encrypt
    many_level.decrypt = level_d.decrypt
    many_level.advanced = level_d

    return two_level, many_level


two_level, many_level = get_exports()
del elgamal, level_d, get_exports
