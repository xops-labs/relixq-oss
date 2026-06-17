"""Key generation service - asymmetric primitives."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, ed25519
from cryptography.hazmat.primitives.asymmetric import rsa as asym_r  # aliased import


def make_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_ecdsa_key():
    return ec.generate_private_key(ec.SECP256R1())


def make_ed25519_key():
    return ed25519.Ed25519PrivateKey.generate()


def make_dsa_key():
    return dsa.generate_private_key(key_size=2048)


def make_dh_params():
    return dh.generate_parameters(generator=2, key_size=2048)


def make_key_via_alias():
    # crypto reached through the aliased module name
    return asym_r.generate_private_key(public_exponent=65537, key_size=4096)
