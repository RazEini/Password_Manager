# Changelog

## 0.2.3

### Changed
- Releases are published with PyPI Trusted Publishing (short-lived OIDC credentials) instead of a stored API token, from a protected `pypi` environment.
- The release workflow runs with least-privilege permissions and `twine check --strict`.

## 0.2.2

### Fixed
- README rendering on PyPI: the custom-vault example no longer breaks, and the LICENSE link points to the repository instead of a dead PyPI path.

### Changed
- Package metadata: added a short description, classifiers, keywords and project links (source, issues, changelog), which PyPI shows in its header and sidebar.

## 0.2.1

### Added
- Warning when `init` or `change-master` is given a PBKDF2 iteration count below the recommended 600,000 (a stronger warning below 100,000).

### Changed
- The release workflow now runs the test suite and verifies that the git tag matches the package version before publishing.

## 0.2.0

### Security
- PBKDF2 default raised from 390,000 to 600,000 iterations (OWASP guidance). Older vaults keep opening; `change-master` upgrades them and the CLI prints a hint.
- Vaults are written atomically (temporary file, `fsync`, `os.replace`), so an interrupted save no longer corrupts the vault.
- Vault files and CSV exports are created owner-only (`0600` on Linux/macOS); `export-csv` warns that the output is plaintext.
- Copied passwords are cleared from the clipboard after 30 seconds (`--clear-after`), only if the clipboard still holds them.
- `.gitignore` patterns fixed: vault files and CSV exports are now actually ignored.

### Fixed
- The interactive banner claimed AES-128-GCM; the cipher is Fernet (AES-128-CBC + HMAC-SHA256).
- `import-csv` re-derived the key for every row; it now decrypts and saves once.
- A corrupted vault file now raises a clear error instead of a traceback.

### Removed
- `interactive.py`, an unused stub that was never wired into the CLI.

### Tests
- 54 tests (from 10) covering the cryptographic core, vault storage, clipboard handling and the CLI; coverage 27% to 76%.
