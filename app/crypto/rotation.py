import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..models.key_version import KeyVersion
from . import aes, keys

ROTATING_TIERS = {"pro", "enterprise"}


def _wrap_key(raw_key: bytes) -> str:
    wrapping_key = keys.derive_key(b"vaultward-key-wrap", key_len=32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, raw_key, None)
    return json.dumps({"nonce": keys.encode(nonce), "ciphertext": keys.encode(ciphertext)})


def _unwrap_key(wrapped_key: str) -> bytes:
    wrapping_key = keys.derive_key(b"vaultward-key-wrap", key_len=32)
    payload = json.loads(wrapped_key)
    return AESGCM(wrapping_key).decrypt(
        keys.decode(payload["nonce"]), keys.decode(payload["ciphertext"]), None
    )


def ensure_active_key(session, tier: str) -> KeyVersion | None:
    if tier not in ROTATING_TIERS:
        return None
    active = session.query(KeyVersion).filter_by(tier=tier, active=True).first()
    if active:
        return active
    latest = session.query(KeyVersion).filter_by(tier=tier).order_by(KeyVersion.version.desc()).first()
    version = latest.version + 1 if latest else 1
    active = KeyVersion(tier=tier, version=version, wrapped_key=_wrap_key(os.urandom(32)), active=True)
    session.add(active)
    session.flush()
    return active


def encrypt_for_tier(plaintext: str, tier: str, session=None) -> dict:
    key_len = 16 if tier == "free" else 32
    active = ensure_active_key(session, tier) if session is not None else None
    raw_key = _unwrap_key(active.wrapped_key) if active else None
    payload = aes.encrypt(plaintext, key_len=key_len, key=raw_key)
    payload["tier_at_encryption"] = tier
    if active:
        payload["key_version"] = active.version
    return payload


def decrypt_payload(payload: dict, session=None) -> str:
    raw_key = None
    if payload.get("key_version"):
        if session is None:
            raise ValueError("A database session is required for versioned payloads")
        key_version = session.query(KeyVersion).filter_by(
            tier=payload.get("tier_at_encryption"), version=payload["key_version"]
        ).first()
        if not key_version:
            raise ValueError("Encryption key version is unavailable")
        raw_key = _unwrap_key(key_version.wrapped_key)
    return aes.decrypt(payload, key=raw_key)


def rotate_tier_keys(session, tier: str) -> dict:
    from ..models.patient import MedicalRecord

    if tier not in ROTATING_TIERS:
        return {"tier": tier, "rotated": False, "records_reencrypted": 0, "reason": "tier does not rotate"}
    try:
        old_active = ensure_active_key(session, tier)
        records = session.query(MedicalRecord).filter_by(encryption_tier=tier).all()
        plaintexts = []
        for record in records:
            notes = decrypt_payload(record.notes_payload, session) if record.notes_payload else None
            prescription = (
                decrypt_payload(record.prescription_payload, session)
                if record.prescription_payload
                else None
            )
            plaintexts.append(
                (record, decrypt_payload(record.diagnosis_payload, session), notes, prescription)
            )
        if old_active:
            old_active.active = False
        new_key = KeyVersion(
            tier=tier,
            version=(old_active.version + 1) if old_active else 1,
            wrapped_key=_wrap_key(os.urandom(32)),
            active=True,
        )
        session.add(new_key)
        session.flush()
        for record, diagnosis, notes, prescription in plaintexts:
            record.diagnosis_payload = encrypt_for_tier(diagnosis, tier, session)
            record.notes_payload = encrypt_for_tier(notes, tier, session) if notes else None
            record.prescription_payload = encrypt_for_tier(prescription, tier, session) if prescription else None
            record.key_version = new_key.version
        session.commit()
        return {"tier": tier, "rotated": True, "key_version": new_key.version, "records_reencrypted": len(records)}
    except Exception:
        session.rollback()
        raise
