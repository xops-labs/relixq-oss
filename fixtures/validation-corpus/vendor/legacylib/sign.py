"""Vendored third-party library - not our code, still our risk."""
from cryptography.hazmat.primitives.asymmetric import rsa


def vendored_keygen():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
