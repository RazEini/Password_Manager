import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from cryptography.fernet import Fernet, InvalidToken

from .crypto import DEFAULT_ITERATIONS, KDFParams, b64e, b64d, derive_key

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
        """Write the vault atomically with owner-only permissions.

        The data goes to a temporary file in the same directory, is flushed
        and fsynced, and only then replaces the real vault with os.replace().
        A crash or error mid-write therefore leaves the previous vault intact
        instead of a truncated, undecryptable file.
        """
        if self.kdf is None or self._ciphertext is None:
            raise VaultError("Vault not ready to save (missing ciphertext or KDF)")
        blob = {"kdf": self.kdf.__dict__, "vault": b64e(self._ciphertext)}

        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp_path = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=directory)  # mode 0600 on POSIX
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(blob, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        try:
            os.chmod(self.path, 0o600)  # no-op on Windows beyond the read-only bit
        except OSError:
            pass

    def load(self):
        if not self.exists():
            raise VaultError(f"Vault file not found: {self.path}")
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                blob = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise VaultError(f"Vault file is corrupted or not a vault: {e}")
        if not isinstance(blob, dict):
            raise VaultError("Invalid vault: unexpected file structure")
        kdf = blob.get("kdf")
        if not kdf or "salt" not in kdf or "iterations" not in kdf:
            raise VaultError("Invalid vault: missing KDF params")
        self.kdf = KDFParams(
            name=kdf.get("name", "PBKDF2HMAC"),
            iterations=int(kdf["iterations"]),
            salt=kdf["salt"]
        )
        try:
            self._ciphertext = b64d(blob.get("vault", ""))
        except ValueError:
            raise VaultError("Invalid vault: ciphertext is not valid base64")
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

    def init_new(self, master_password: str, iterations: int = DEFAULT_ITERATIONS):
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
        """Re-encrypt under a new master password with a fresh salt.

        When `iterations` is omitted the work factor is raised to at least
        DEFAULT_ITERATIONS, so changing the master password also upgrades
        vaults that were created with an older, lower default.
        """
        data = self._load_decrypted(old_password)
        if iterations is None:
            iterations = max(self.kdf.iterations if self.kdf else 0, DEFAULT_ITERATIONS)
        self.kdf = KDFParams.new(iterations=iterations)
        self._save_encrypted(new_password, data)

    def export_entries(self, master_password: str) -> Dict[str, Dict[str, Any]]:
        """Return all entries decrypted (for CSV export)."""
        return dict(self._load_decrypted(master_password).get("entries", {}))

    def merge_entries(self, master_password: str, rows: Iterable[Dict[str, str]]) -> int:
        """Add or update entries from dict rows with one decrypt and one save.

        Rows without a `service` are skipped. Returns the number merged.
        """
        data = self._load_decrypted(master_password)
        entries = data.setdefault("entries", {})
        stamp = now_iso()
        count = 0
        for row in rows:
            svc = row.get("service")
            if not svc:
                continue
            entries[svc] = {
                "username": row.get("username", "") or "",
                "password": row.get("password", "") or "",
                "notes": row.get("notes", "") or "",
                "updated": stamp,
            }
            count += 1
        if count:
            data["updated"] = stamp
            self._save_encrypted(master_password, data)
        return count
