# Intentionally vulnerable sample — DO NOT USE.
import hashlib
from Crypto.PublicKey import RSA

# MD5 for password hashing — broken.
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# SHA-1 — collision-broken.
def checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

# RSA-1024 — below NIST minimum and quantum-vulnerable.
def generate_keypair():
    return RSA.generate(1024)

# Hardcoded API secret.
API_SECRET = "EXAMPLE_PLACEHOLDER_not_a_real_key"
