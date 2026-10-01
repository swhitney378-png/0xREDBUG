import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import keys

BACKUP_FORMAT = "vaultward-encrypted-sqlite-v1"


def _sqlite_path(engine) -> Path:
    database = engine.url.database
    if not database or database == ":memory:":
        raise RuntimeError("Encrypted backups require a file-backed SQLite database")
    return Path(database).resolve()


def _backup_key(salt: bytes) -> bytes:
    return keys.derive_key(b"vaultward-backup:" + salt, key_len=32)


def create_encrypted_backup(engine, backup_dir: str) -> Path:
    source = _sqlite_path(engine)
    if not source.exists():
        raise FileNotFoundError(f"Database file does not exist: {source}")
    destination_dir = Path(backup_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as snapshot:
        snapshot_path = Path(snapshot.name)
    try:
        source_connection = sqlite3.connect(source)
        snapshot_connection = sqlite3.connect(snapshot_path)
        with snapshot_connection:
            source_connection.backup(snapshot_connection)
        snapshot_connection.close()
        source_connection.close()
        raw = snapshot_path.read_bytes()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        ciphertext = AESGCM(_backup_key(salt)).encrypt(nonce, raw, BACKUP_FORMAT.encode())
        created_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        envelope = {
            "format": BACKUP_FORMAT,
            "created_at": created_at,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "salt": keys.encode(salt),
            "nonce": keys.encode(nonce),
            "ciphertext": keys.encode(ciphertext),
        }
        filename = f"vaultward-{created_at.replace(':', '').replace('.', '')}.vwb"
        target = destination_dir / filename
        target.write_text(json.dumps(envelope), encoding="utf-8")
        return target
    finally:
        snapshot_path.unlink(missing_ok=True)


def decrypt_backup(path: str | Path) -> bytes:
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))
    if envelope.get("format") != BACKUP_FORMAT:
        raise ValueError("Unsupported backup format")
    raw = AESGCM(_backup_key(keys.decode(envelope["salt"]))).decrypt(
        keys.decode(envelope["nonce"]),
        keys.decode(envelope["ciphertext"]),
        BACKUP_FORMAT.encode(),
    )
    if hashlib.sha256(raw).hexdigest() != envelope["source_sha256"]:
        raise ValueError("Backup integrity check failed")
    return raw


def restore_encrypted_backup(engine, backup_path: str | Path) -> dict:
    raw = decrypt_backup(backup_path)
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as restored:
        restored_path = Path(restored.name)
        restored.write(raw)
    try:
        connection = sqlite3.connect(restored_path)
        result = connection.execute("PRAGMA integrity_check").fetchone()[0]
        connection.close()
        if result != "ok":
            raise ValueError(f"Restored database integrity check failed: {result}")
        target = _sqlite_path(engine)
        engine.dispose()
        shutil.copy2(restored_path, target)
        return {"restored": True, "path": str(target), "integrity": result}
    finally:
        restored_path.unlink(missing_ok=True)
