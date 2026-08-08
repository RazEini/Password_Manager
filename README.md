<div align="center">

# 🔐 Python Password Manager

A modular, secure, and easy-to-use password manager featuring a professional CLI interface, an **interactive menu (TUI)** with arrow-key navigation, full test coverage, and CI/CD.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![CLI](https://img.shields.io/badge/CLI-Executable-brightgreen)
![TUI](https://img.shields.io/badge/TUI-Interactive-purple?logo=windowsterminal)
![Encryption](https://img.shields.io/badge/Encryption-AES--128--GCM-red)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA256-orange) <br><br>
![License](https://img.shields.io/badge/License-MIT-blue)
![Tests](https://github.com/RazEini/Password_Manager/actions/workflows/test.yml/badge.svg)

</div>

---

## 🚀 Key Features

* **Modular Architecture:** Full separation between the cryptographic logic (`core`) and the CLI/storage interface.
* **Interactive Menu (TUI):** Running `passmgr` with no arguments opens an arrow-key navigation menu built with `questionary` and `rich`, offering List / Get / Add / Delete / Generate options directly from the menu.
* **Strong Security:** Key derivation via PBKDF2-HMAC-SHA256 (390,000 iterations by default) and AES-128-GCM encryption (Fernet).
* **Local Encrypted Storage:** The vault is stored in a single encrypted file (`vault.json`).
* **Dedicated CLI Shortcut:** Run the `passmgr` command directly from the terminal, with or without subcommands.
* **Clipboard Integration:** Quick password copying with a single keypress or a CLI flag (using `pyperclip`).
* **Testing & CI/CD:** Unit test coverage with `pytest`, run automatically via GitHub Actions.

---
<h2 align="center">Project Structure 📂</h2>
<div align="left">
  <pre><code>PASSWORD_MANAGER/
├── .github/
│   └── workflows/
│       └── test.yml
├── src/
│   └── password_manager/
│       ├── cli/
│       │   ├── __init__.py
│       │   └── main.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── crypto.py
│       │   └── vault.py
│       ├── __init__.py
│       └── interactive.py
├── tests/
│   ├── test_crypto.py
│   └── test_vault.py
├── .gitignore
├── LICENSE
├── pyproject.toml
├── README.md
└── requirements.txt</code></pre>
</div>
<br>
<hr>

## 📦 Installation & Running

**1. Clone the repository:**

```bash
git clone https://github.com/RazEini/Password_Manager.git
cd Password_Manager
```

**2. Install the package in editable mode:**

```bash
pip install -e .
```

**3. Run unit tests:**

```bash
pip install pytest
pytest
```

---

<h2 align="center">
  🖥️ Interactive Mode (TUI)
</h2>

<div align="center">

Running the `passmgr` command **without** a subcommand opens a full interactive menu (requires `rich` and `questionary`):

</div>

```bash
passmgr
# or with a specific vault file:
passmgr --vault myvault.json
```

The menu automatically detects whether the vault exists:

* If it **doesn't exist** — it will offer to create a new vault with a master password.
* If it **exists** — it will prompt for the master password to unlock it.

Once unlocked, an arrow-key navigation menu is displayed with the following options:

<div align="center">

<table>
  <thead>
    <tr>
      <th align="center">Menu Option</th>
      <th align="center">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center">List All Services</td>
      <td align="center">Display all services saved in the vault</td>
    </tr>
    <tr>
      <td align="center">Get Entry</td>
      <td align="center">View entry details, including an option to copy the password to the clipboard</td>
    </tr>
    <tr>
      <td align="center">Add / Update Entry</td>
      <td align="center">Add a new entry or update an existing one, with an option to generate a random password</td>
    </tr>
    <tr>
      <td align="center">Delete Entry</td>
      <td align="center">Delete an entry from the vault after confirmation</td>
    </tr>
    <tr>
      <td align="center">Generate Random Password</td>
      <td align="center">Generate a random password only, without saving it to the vault</td>
    </tr>
    <tr>
      <td align="center">Lock &amp; Exit</td>
      <td align="center">Lock the vault and exit the menu</td>
    </tr>
  </tbody>
</table>

</div>

---

<h2 align="center">
  💻 CLI – Main Commands (`passmgr`)
</h2>

<div align="center">

<table align="center">
  <thead>
    <tr>
      <th align="center">Command</th>
      <th align="center">Description</th>
      <th align="center">Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><code>(no command)</code></td>
      <td align="center">Open the interactive menu (TUI)</td>
      <td align="left"><code>passmgr</code></td>
    </tr>
    <tr>
      <td align="center"><code>init</code></td>
      <td align="center">Create a new encrypted Vault</td>
      <td align="left"><code>passmgr init</code></td>
    </tr>
    <tr>
      <td align="center"><code>add</code></td>
      <td align="center">Add or update a password for a service</td>
      <td align="left"><code>passmgr add --service github --user myusername</code></td>
    </tr>
    <tr>
      <td align="center"><code>get</code></td>
      <td align="center">Retrieve a password (with an option to copy to clipboard)</td>
      <td align="left"><code>passmgr get --service github --copy</code></td>
    </tr>
    <tr>
      <td align="center"><code>list</code></td>
      <td align="center">List all existing services in the vault</td>
      <td align="left"><code>passmgr list</code></td>
    </tr>
    <tr>
      <td align="center"><code>delete</code></td>
      <td align="center">Delete an entry from the vault</td>
      <td align="left"><code>passmgr delete --service github</code></td>
    </tr>
    <tr>
      <td align="center"><code>change-master</code></td>
      <td align="center">Change the master password and re-encrypt</td>
      <td align="left"><code>passmgr change-master</code></td>
    </tr>
    <tr>
      <td align="center"><code>generate</code></td>
      <td align="center">Generate a strong random password</td>
      <td align="left"><code>passmgr generate --length 20</code></td>
    </tr>
    <tr>
      <td align="center"><code>export-csv</code></td>
      <td align="center">Export passwords to a CSV file</td>
      <td align="left"><code>passmgr export-csv --path backup.csv</code></td>
    </tr>
    <tr>
      <td align="center"><code>import-csv</code></td>
      <td align="center">Import passwords from a CSV file</td>
      <td align="left"><code>passmgr import-csv --path backup.csv</code></td>
    </tr>
  </tbody>
</table>

</div>

---

## 🛡️ Security & Key Derivation

The application never stores the master password on disk at any stage. The cryptographic key is derived in real time from the master password and the dynamic Salt stored in the Vault file. Even in interactive mode, password entry is handled via `questionary.password`, which masks the characters as they're typed, just like `getpass` does in the standard CLI mode.

---

## 📄 License

This project is distributed under the **MIT** license – free to use, modify, and distribute. For more information, see the [LICENSE](LICENSE) file.

---

<h4 align="center">
  👨‍💻 Raz Eini (2026)
</h4>
