"""Hand-rolled textbook RSA - no crypto library imports at all."""
import random


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_keypair(bits: int = 1024):
    p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (n, e), (n, d)


def encrypt_int(message: int, public_key) -> int:
    n, e = public_key
    return pow(message, e, n)


def decrypt_int(ciphertext: int, private_key) -> int:
    n, d = private_key
    return pow(ciphertext, d, n)
