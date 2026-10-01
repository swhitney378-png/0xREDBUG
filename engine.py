"""
Tier-aware encryption engine.

This is the piece that ties subscriptions to crypto strength. Call
encrypt_for_user() / decrypt_for_user() from your routes instead of
calling aes.py directly — it looks up the user's tier and applies the
right key length automatically, so a downgrade/upgrade in subscription
status changes protection level without touching route code.
"""

from . import aes

TIER_KEY_LENGTH = {
    "free": 16,        # AES-128-GCM
    "pro": 32,         # AES-256-GCM
    "enterprise": 32,  # AES-256-GCM (+ rotation/HSM handled elsewhere)
}


def encrypt_for_user(plaintext: str, tier: str) -> dict:
    key_len = TIER_KEY_LENGTH.get(tier, 16)
    payload = aes.encrypt(plaintext, key_len=key_len)
    payload["tier_at_encryption"] = tier
    return payload


def decrypt_for_user(payload: dict) -> str:
    # Decryption only needs what's stored in the payload (alg, salt,
    # nonce) — it doesn't need the current user's tier, since a record
    # encrypted under "pro" must still decrypt even if the user later
    # downgrades. Tier only ever gates what you're allowed to ENcrypt
    # going forward; it never locks you out of your own old data.
    return aes.decrypt(payload)
