import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet, InvalidToken

from .crypto import KDFParams, b64e, b64d, derive_key

ISO = "%Y-%m-%dT%H:%M:%SZ"

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime(ISO)

class VaultError(Exception):
    pass

class Vault:
    """Encrypted password vault stored as JSON."""
    def __init__(self, path: str):
        self.path = path
        self.kdf: Optional[KDFParams] = None
        self._ciphertext: Optional[bytes] = None

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def save(self):
        if self.kdf is None or self._ciphertext is None:
            raise VaultError("Vault not ready to save (missing ciphertext or KDF)")
        blob = {"kdf": self.kdf.__dict__, "vault": b64e(self._ciphertext)}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(blob, f, indent=2)

    def load(self):
        if not self.exists():
            raise VaultError(f"Vault file not found: {self.path}")
        with open(self.path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        kdf = blob.get("kdf")
        if not kdf or "salt" not in kdf or "iterations" not in kdf:
            raise VaultError("Invalid vault: missing KDF params")
        self.kdf = KDFParams(
            name=kdf.get("name", "PBKDF2HMAC"),
            iterations=int(kdf["iterations"]),
            salt=kdf["salt"]
        )
        self._ciphertext = b64d(blob.get("vault", ""))
        if not self._ciphertext:
            raise VaultError("Invalid vault: missing ciphertext")

    def _encrypt(self, key: bytes, payload: Dict[str, Any]) -> bytes:
        return Fernet(key).encrypt(json.dumps(payload).encode("utf-8"))

    def _decrypt(self, key: bytes) -> Dict[str, Any]:
        try:
            raw = Fernet(key).decrypt(self._ciphertext)
        except InvalidToken:
            raise VaultError("Invalid master password or corrupted vault")
        return json.loads(raw.decode("utf-8"))

    def init_new(self, master_password: str, iterations: int = 390_000):
        if self.exists():
            raise VaultError(f"Refusing to overwrite existing file: {self.path}")
        self.kdf = KDFParams.new(iterations=iterations)
        data = {
            "version": 1,
            "created": now_iso(),
            "updated": now_iso(),
            "entries": {}
        }
        key = derive_key(master_password, self.kdf)
        self._ciphertext = self._encrypt(key, data)
        self.save()

    def _load_decrypted(self, master_password: str) -> Dict[str, Any]:
        self.load()
        key = derive_key(master_password, self.kdf)
        return self._decrypt(key)

    def _save_encrypted(self, master_password: str, data: Dict[str, Any]):
        key = derive_key(master_password, self.kdf)
        self._ciphertext = self._encrypt(key, data)
        self.save()

    def list_services(self, master_password: str):
        data = self._load_decrypted(master_password)
        return sorted(list(data["entries"].keys()))

    def get_entry(self, master_password: str, service: str) -> Dict[str, Any]:
        data = self._load_decrypted(master_password)
        entry = data["entries"].get(service)
        if not entry:
            raise VaultError(f"Service not found: {service}")
        return entry

    def set_entry(self, master_password: str, service: str, username: str, password: str, notes: str = ""):
        data = self._load_decrypted(master_password)
        data["entries"][service] = {
            "username": username,
            "password": password,
            "notes": notes,
            "updated": now_iso(),
        }
        data["updated"] = now_iso()
        self._save_encrypted(master_password, data)

    def delete_entry(self, master_password: str, service: str):
        data = self._load_decrypted(master_password)
        if service not in data["entries"]:
            raise VaultError(f"Service not found: {service}")
        del data["entries"][service]
        data["updated"] = now_iso()
        self._save_encrypted(master_password, data)

    def change_master(self, old_password: str, new_password: str, iterations: Optional[int] = None):
        data = self._load_decrypted(old_password)
        if iterations is None:
            iterations = self.kdf.iterations if self.kdf else 390_000
        self.kdf = KDFParams.new(iterations=iterations)
        self._save_encrypted(new_password, data)