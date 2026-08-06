from __future__ import annotations
import argparse
import getpass
import json
import sys

try:
    import pyperclip
    HAS_PYPERCLIP = True
except Exception:
    HAS_PYPERCLIP = False

from password_manager.core.crypto import generate_password
from password_manager.core.vault import Vault, VaultError


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
        pwd = generate_password(
            length=args.length,
            use_lower=not args.no_lower,
            use_upper=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
        )
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
    pwd = generate_password(
        length=args.length,
        use_lower=not args.no_lower,
        use_upper=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
    )
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
                "updated": v._load_decrypted(master).get("updated", ""),
            }
            count += 1
    v._save_encrypted(master, data)
    print(f"Imported/updated {count} entries from {args.path}")


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
    sp.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    sp.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    sp.add_argument("--no-digits", action="store_true", help="Exclude digits")
    sp.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("delete", help="Delete an entry")
    sp.add_argument("--service", required=True)
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("change-master", help="Change master password and re-encrypt vault")
    sp.add_argument("--iterations", type=int, default=None, help="Optionally set new PBKDF2 iterations")
    sp.set_defaults(func=cmd_change_master)

    sp = sub.add_parser("generate", help="Generate a strong password and print it")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    sp.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    sp.add_argument("--no-digits", action="store_true", help="Exclude digits")
    sp.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
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