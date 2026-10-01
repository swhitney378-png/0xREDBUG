"""
Key derivation and management.

Rule of thumb: never store a raw encryption key. Derive it from a
per-organisation master secret (kept outside the DB, e.g. in an env
var or real secrets manager) plus a per-record/per-user salt.
"""

import os
import base64
from argon2.low_level import hash_secret_raw, Type

# In production, load this from a secrets manager (AWS KMS, HashiCorp
# Vault, etc.) — never hardcode it and never commit it to source control.
MASTER_SECRET = os.environ.get("VAULTWARD_MASTER_SECRET", "").encode()

if not MASTER_SECRET:
    raise RuntimeError(
        "VAULTWARD_MASTER_SECRET is not set. Refusing to start without it."
    )


def derive_key(salt: bytes, key_len: int = 32) -> bytes:
    """
    Derive a symmetric key using Argon2id.
    key_len=16 -> AES-128, key_len=32 -> AES-256
    """
    return hash_secret_raw(
        secret=MASTER_SECRET,
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=2,
        hash_len=key_len,
        type=Type.ID,
    )


def new_salt() -> bytes:
    return os.urandom(16)


def encode(b: bytes) -> str:
    return base64.b64encode(b).decode()


def decode(s: str) -> bytes:
    return base64.b64decode(s.encode())
