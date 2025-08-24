"""
Python Password Manager - CLI Tool
==================================

ניהול סיסמאות מאובטח בעזרת קובץ Vault מוצפן.

תכונות
-------
- סיסמת מאסטר → מפתח חזק (PBKDF2-HMAC-SHA256)
- הצפנת AES-128-GCM (Fernet)
- Vault יחיד בקובץ JSON (מוצפן כולו)
- פקודות לניהול: init, add, get, list, delete, change-master, generate, import-csv, export-csv
- תמיכה בהעתקה ל־Clipboard (אם מותקן pyperclip)

הוראות שימוש
-------------
1. יצירת Vault חדש:
    python password_manager.py init --vault myvault.json

2. הוספת סיסמה חדשה:
    python password_manager.py add --vault myvault.json --service gmail --user raz

3. קבלת סיסמה קיימת:
    python password_manager.py get --vault myvault.json --service gmail
    (ניתן להוסיף --copy כדי להעתיק ללוח)

4. הצגת כל השירותים הקיימים:
    python password_manager.py list --vault myvault.json

5. מחיקת סיסמה משירות:
    python password_manager.py delete --vault myvault.json --service gmail

6. שינוי סיסמת מאסטר:
    python password_manager.py change-master --vault myvault.json

7. יצירת סיסמה חזקה (בלי לשמור):
    python password_manager.py generate --length 24

8. ייבוא סיסמאות מקובץ CSV:
    python password_manager.py import-csv --vault myvault.json --path passwords.csv

9. ייצוא סיסמאות לקובץ CSV:
    python password_manager.py export-csv --vault myvault.json --path backup.csv

פורמט CSV
----------
service,username,password,notes
example.com,alice,Very$trongP@ss,optional note
"""

from __future__ import annotations
import argparse
import base64
import getpass
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import pyperclip  # optional
    HAS_PYPERCLIP = True
except Exception:
    HAS_PYPERCLIP = False

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# -------- Utilities --------

ISO = "%Y-%m-%dT%H:%M:%SZ"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime(ISO)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))


@dataclass
class KDFParams:
    name: str = "PBKDF2HMAC"
    iterations: int = 390_000  # modern, safe default
    salt: str = ""            # urlsafe base64

    @staticmethod
    def new(iterations: int = 390_000) -> "KDFParams":
        salt = os.urandom(16)
        return KDFParams(iterations=iterations, salt=b64e(salt))


class VaultError(Exception):
    pass


class Vault:
    """Encrypted password vault stored as JSON.

    On disk, the structure is:
    {
        "kdf": {"name": "PBKDF2HMAC", "iterations": 390000, "salt": "..."},
        "vault": "<base64 ciphertext>"
    }

    The decrypted payload structure is:
    {
        "version": 1,
        "created": "ISO8601",
        "updated": "ISO8601",
        "entries": {
            "service": {"username": str, "password": str, "notes": str, "updated": "ISO8601"}
        }
    }
    """

    def __init__(self, path: str):
        self.path = path
        self.kdf: Optional[KDFParams] = None
        self._ciphertext: Optional[bytes] = None
        self._data: Optional[Dict[str, Any]] = None

    # ---- File I/O ----
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
        self.kdf = KDFParams(name=kdf.get("name", "PBKDF2HMAC"),
                             iterations=int(kdf["iterations"]),
                             salt=kdf["salt"]) 
        self._ciphertext = b64d(blob.get("vault", ""))
        if not self._ciphertext:
            raise VaultError("Invalid vault: missing ciphertext")

    # ---- Crypto ----
    def _derive_key(self, master_password: str) -> bytes:
        if self.kdf is None:
            raise VaultError("KDF parameters not initialized")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b64d(self.kdf.salt),
            iterations=int(self.kdf.iterations),
        )
        key = kdf.derive(master_password.encode("utf-8"))
        return base64.urlsafe_b64encode(key)  # Fernet expects urlsafe-64

    def _encrypt(self, key: bytes, payload: Dict[str, Any]) -> bytes:
        token = Fernet(key).encrypt(json.dumps(payload).encode("utf-8"))
        return token

    def _decrypt(self, key: bytes) -> Dict[str, Any]:
        try:
            raw = Fernet(key).decrypt(self._ciphertext)
        except InvalidToken:
            raise VaultError("Invalid master password or corrupted vault")
        return json.loads(raw.decode("utf-8"))

    # ---- High-level ops ----
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
        key = self._derive_key(master_password)
        self._ciphertext = self._encrypt(key, data)
        self.save()

    def _load_decrypted(self, master_password: str) -> Dict[str, Any]:
        self.load()
        key = self._derive_key(master_password)
        data = self._decrypt(key)
        return data

    def _save_encrypted(self, master_password: str, data: Dict[str, Any]):
        key = self._derive_key(master_password)
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
        # Optionally refresh salt and/or iterations when changing master
        if iterations is None:
            iterations = self.kdf.iterations if self.kdf else 390_000
        self.kdf = KDFParams.new(iterations=iterations)
        self._save_encrypted(new_password, data)


# -------- Password generator --------
import secrets
import string

EXCLUDE_SIMILAR = {"l", "I", "1", "O", "0"}


def generate_password(length: int = 20, allow_symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("Minimum password length is 8")
    alphabet = set(string.ascii_letters + string.digits)
    if allow_symbols:
        # Safe-ish symbol set (avoid quotes & backslashes to reduce escape issues)
        alphabet.update("!@#$%^&*()_-+=[]{}:;.,?/|")
    # Remove visually similar characters
    alphabet.difference_update(EXCLUDE_SIMILAR)
    alphabet = "".join(sorted(alphabet))

    # Ensure diversity: at least one from each category
    categories = [
        [c for c in string.ascii_lowercase if c not in EXCLUDE_SIMILAR],
        [c for c in string.ascii_uppercase if c not in EXCLUDE_SIMILAR],
        [c for c in string.digits if c not in EXCLUDE_SIMILAR],
    ]
    if allow_symbols:
        categories.append(list("!@#$%^&*()_-+=[]{}:;.,?/|"))

    pwd_chars = [secrets.choice(cat) for cat in categories]
    while len(pwd_chars) < length:
        pwd_chars.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(pwd_chars)
    return "".join(pwd_chars[:length])


# -------- CLI --------

def prompt_master(confirm: bool = False) -> str:
    pw1 = getpass.getpass("Master password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match", file=sys.stderr)
            sys.exit(2)
    if len(pw1) < 8:
        print("Master password must be at least 8 characters.", file=sys.stderr)
        sys.exit(2)
    return pw1


def cmd_init(args):
    v = Vault(args.vault)
    master = prompt_master(confirm=True)
    iters = args.iterations
    v.init_new(master, iterations=iters)
    print(f"Initialized vault at {args.vault} with {iters} PBKDF2 iterations.")


def cmd_list(args):
    v = Vault(args.vault)
    master = prompt_master()
    services = v.list_services(master)
    if services:
        for s in services:
            print(s)
    else:
        print("(no entries)")


def cmd_get(args):
    v = Vault(args.vault)
    master = prompt_master()
    entry = v.get_entry(master, args.service)
    if args.copy:
        if not HAS_PYPERCLIP:
            print("pyperclip not installed; cannot copy to clipboard.")
        else:
            pyperclip.copy(entry["password"])
            print(f"Password for {args.service} copied to clipboard.")
    else:
        print(json.dumps(entry, indent=2))


def cmd_add(args):
    v = Vault(args.vault)
    master = prompt_master()
    username = args.user or input("Username: ")
    if args.generate:
        pwd = generate_password(length=args.length, allow_symbols=not args.no_symbols)
        print(f"Generated password ({len(pwd)} chars)")
    else:
        pwd = getpass.getpass("Password: ")
        if len(pwd) < 8:
            print("Password too short (min 8).", file=sys.stderr)
            sys.exit(2)
    notes = args.notes or ""
    v.set_entry(master, args.service, username, pwd, notes)
    print(f"Saved entry: {args.service}")


def cmd_delete(args):
    v = Vault(args.vault)
    master = prompt_master()
    v.delete_entry(master, args.service)
    print(f"Deleted entry: {args.service}")


def cmd_change_master(args):
    v = Vault(args.vault)
    old = prompt_master()
    new = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if new != confirm:
        print("New passwords do not match.", file=sys.stderr)
        sys.exit(2)
    if len(new) < 8:
        print("New master password must be at least 8 characters.", file=sys.stderr)
        sys.exit(2)
    v.change_master(old, new, iterations=args.iterations)
    print("Master password changed and vault re-encrypted with fresh salt.")


def cmd_generate(args):
    pwd = generate_password(length=args.length, allow_symbols=not args.no_symbols)
    print(pwd)


def cmd_export_csv(args):
    import csv
    v = Vault(args.vault)
    master = prompt_master()
    data = v._load_decrypted(master)
    entries = data.get("entries", {})
    with open(args.path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["service", "username", "password", "notes"])
        for svc, e in entries.items():
            w.writerow([svc, e.get("username", ""), e.get("password", ""), e.get("notes", "")])
    print(f"Exported {len(entries)} entries to {args.path}")


def cmd_import_csv(args):
    import csv
    v = Vault(args.vault)
    master = prompt_master()
    # load existing
    data = v._load_decrypted(master)
    entries = data.setdefault("entries", {})
    count = 0
    with open(args.path, "r", newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f)):
            svc = row.get("service")
            if not svc:
                print(f"Skipping row {i+2}: missing service")
                continue
            entries[svc] = {
                "username": row.get("username", ""),
                "password": row.get("password", ""),
                "notes": row.get("notes", ""),
                "updated": now_iso(),
            }
            count += 1
    data["updated"] = now_iso()
    v._save_encrypted(master, data)
    print(f"Imported/updated {count} entries from {args.path}")


# -------- Argparse wiring --------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Secure CLI password manager (single vault file)")
    p.add_argument("--vault", default="vault.json", help="Path to vault file (default: vault.json)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Initialize a new empty vault")
    sp.add_argument("--iterations", type=int, default=390_000, help="PBKDF2 iterations (default: 390000)")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("list", help="List all services in the vault")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("get", help="Get an entry by service name")
    sp.add_argument("--service", required=True)
    sp.add_argument("--copy", action="store_true", help="Copy password to clipboard (requires pyperclip)")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("add", help="Add or update an entry")
    sp.add_argument("--service", required=True, help="Service/site name (key)")
    sp.add_argument("--user", help="Username (will prompt if omitted)")
    sp.add_argument("--notes", help="Optional notes")
    sp.add_argument("--generate", action="store_true", help="Generate a strong random password")
    sp.add_argument("--length", type=int, default=20, help="Length for generated password")
    sp.add_argument("--no-symbols", action="store_true", help="Exclude symbols in generated password")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("delete", help="Delete an entry")
    sp.add_argument("--service", required=True)
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("change-master", help="Change master password and re-encrypt vault")
    sp.add_argument("--iterations", type=int, default=None, help="Optionally set new PBKDF2 iterations")
    sp.set_defaults(func=cmd_change_master)

    sp = sub.add_parser("generate", help="Generate a strong password and print it")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--no-symbols", action="store_true")
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("export-csv", help="Export all entries to CSV (plaintext)")
    sp.add_argument("--path", required=True, help="CSV file path")
    sp.set_defaults(func=cmd_export_csv)

    sp = sub.add_parser("import-csv", help="Import/update entries from CSV (plaintext)")
    sp.add_argument("--path", required=True, help="CSV file path")
    sp.set_defaults(func=cmd_import_csv)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
