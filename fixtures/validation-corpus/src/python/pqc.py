"""Post-quantum primitives via liboqs - none of this is quantum-vulnerable."""
import oqs


def kem_roundtrip():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pub = kem.generate_keypair()
        ct, shared_enc = kem.encap_secret(pub)
        shared_dec = kem.decap_secret(ct)
        return shared_enc == shared_dec


def sign_message(msg: bytes):
    with oqs.Signature("ML-DSA-65") as signer:
        pub = signer.generate_keypair()
        sig = signer.sign(msg)
        return pub, sig


def sphincs_sign(msg: bytes):
    with oqs.Signature("SPHINCS+-SHA2-128s-simple") as signer:
        signer.generate_keypair()
        return signer.sign(msg)
