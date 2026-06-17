"""Symmetric encryption + hashing helpers."""
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_aes128(data: bytes) -> bytes:
    key = get_random_bytes(16)  # 128-bit key
    cipher = AES.new(key, AES.MODE_GCM)
    ct, _tag = cipher.encrypt_and_digest(data)
    return ct


def encrypt_aes256(data: bytes) -> bytes:
    key = get_random_bytes(32)  # 256-bit key
    cipher = AES.new(key, AES.MODE_GCM)
    ct, _tag = cipher.encrypt_and_digest(data)
    return ct


def encrypt_3des(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def fingerprint_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def fingerprint_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def fingerprint_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_sha3(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()
