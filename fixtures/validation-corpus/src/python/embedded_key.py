"""Service identity - marker-only private key fixture (do not do this)."""

SERVICE_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
synthetic-marker-only-no-key-material
-----END RSA PRIVATE KEY-----"""


def get_identity():
    return SERVICE_PRIVATE_KEY
