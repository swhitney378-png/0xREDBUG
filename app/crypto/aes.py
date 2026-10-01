"""
AES-GCM encryption primitives.

GCM is used instead of plain CBC because it gives authenticated
encryption — tampering with ciphertext is detectable, which matters
a lot for medical records (you want to know if a record was altered,
not just keep it secret).
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import keys


def encrypt(plaintext: str, key_len: int = 32, key: bytes | None = None) -> dict:
    """
    Encrypt a plaintext string. key_len=16 -> AES-128-GCM, 32 -> AES-256-GCM.
    Returns a dict with everything needed to decrypt later — store this
    whole structure in the DB column (e.g. as JSON), not just the ciphertext.
    """
    salt = keys.new_salt() if key is None else None
    key = keys.derive_key(salt, key_len=key_len) if key is None else key
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data=None)

    return {
        "ciphertext": keys.encode(ciphertext),
        "nonce":      keys.encode(nonce),
        "salt":       keys.encode(salt) if salt else None,
        "alg":        "AES-128-GCM" if key_len == 16 else "AES-256-GCM",
    }


def decrypt(payload: dict, key: bytes | None = None) -> str:
    salt       = keys.decode(payload["salt"]) if payload.get("salt") else None
    nonce      = keys.decode(payload["nonce"])
    ciphertext = keys.decode(payload["ciphertext"])
    key_len    = 16 if payload["alg"] == "AES-128-GCM" else 32

    key = keys.derive_key(salt, key_len=key_len) if key is None else key
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode()
