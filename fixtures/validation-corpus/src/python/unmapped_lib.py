"""Uses a crypto library through an API the scanner has no rule for."""
from M2Crypto import EVP


def digest(data: bytes) -> bytes:
    md = EVP.MessageDigest('ripemd160')
    md.update(data)
    return md.final()
