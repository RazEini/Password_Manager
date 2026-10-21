import pytest
from password_manager.core.vault import Vault, VaultError

@pytest.fixture
def temp_vault(tmp_path):
    vault_file = tmp_path / "test_vault.json"
    return Vault(str(vault_file))

def test_init_and_exists(temp_vault):
    assert not temp_vault.exists()
    temp_vault.init_new("MasterPass123", iterations=1000)
    assert temp_vault.exists()

def test_add_and_get_entry(temp_vault):
    master = "MasterPass123"
    temp_vault.init_new(master, iterations=1000)
    
    temp_vault.set_entry(master, "github", "user1", "pass123", "my notes")
    entry = temp_vault.get_entry(master, "github")
    
    assert entry["username"] == "user1"
    assert entry["password"] == "pass123"
    assert entry["notes"] == "my notes"

def test_invalid_master_password(temp_vault):
    temp_vault.init_new("CorrectPassword", iterations=1000)
    with pytest.raises(VaultError):
        temp_vault.list_services("WrongPassword")

def test_delete_entry(temp_vault):
    master = "MasterPass123"
    temp_vault.init_new(master, iterations=1000)
    temp_vault.set_entry(master, "github", "user1", "pass123")
    
    assert "github" in temp_vault.list_services(master)
    temp_vault.delete_entry(master, "github")
    assert "github" not in temp_vault.list_services(master)

def test_change_master(temp_vault):
    old_master = "OldPassword123"
    new_master = "NewPassword456"
    
    temp_vault.init_new(old_master, iterations=1000)
    temp_vault.set_entry(old_master, "github", "user1", "pass123")
    
    temp_vault.change_master(old_master, new_master, iterations=1000)
    
    # Old password should now fail
    with pytest.raises(VaultError):
        temp_vault.get_entry(old_master, "github")
        
    # New password should succeed
    entry = temp_vault.get_entry(new_master, "github")
    assert entry["username"] == "user1"

# ---------------------------------------------------------------------------
# Durability & file safety
# ---------------------------------------------------------------------------
import json
import os
import sys

from password_manager.core.crypto import DEFAULT_ITERATIONS

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


def test_failed_save_leaves_previous_vault_intact(temp_vault, monkeypatch, tmp_path):
    """Regression: save() used to truncate the vault before writing it."""
    master = "MasterPass123"
    temp_vault.init_new(master, iterations=1000)
    temp_vault.set_entry(master, "github", "user1", "pass123")
    before = (tmp_path / "test_vault.json").read_bytes()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("password_manager.core.vault.json.dump", boom)
    with pytest.raises(OSError):
        temp_vault.set_entry(master, "gitlab", "user2", "pass456")
    monkeypatch.undo()

    assert (tmp_path / "test_vault.json").read_bytes() == before
    assert Vault(str(tmp_path / "test_vault.json")).get_entry(master, "github")["password"] == "pass123"


def test_no_temp_files_are_left_behind(temp_vault, tmp_path):
    temp_vault.init_new("MasterPass123", iterations=1000)
    temp_vault.set_entry("MasterPass123", "a", "u", "password1")
    assert [p.name for p in tmp_path.iterdir()] == ["test_vault.json"]


@posix_only
def test_vault_file_is_owner_only(temp_vault, tmp_path):
    temp_vault.init_new("MasterPass123", iterations=1000)
    temp_vault.set_entry("MasterPass123", "a", "u", "password1")
    assert (tmp_path / "test_vault.json").stat().st_mode & 0o777 == 0o600


def test_vault_file_never_contains_plaintext_secrets(temp_vault, tmp_path):
    temp_vault.init_new("MasterPass123", iterations=1000)
    temp_vault.set_entry("MasterPass123", "github", "alice", "S3cretPassw0rd!")
    raw = (tmp_path / "test_vault.json").read_text()
    for secret in ("S3cretPassw0rd!", "alice", "github", "MasterPass123"):
        assert secret not in raw


def test_init_refuses_to_overwrite_existing_vault(temp_vault):
    temp_vault.init_new("MasterPass123", iterations=1000)
    with pytest.raises(VaultError):
        temp_vault.init_new("Another12345", iterations=1000)


def test_missing_and_corrupt_vault_raise_vaulterror(tmp_path):
    with pytest.raises(VaultError):
        Vault(str(tmp_path / "nope.json")).load()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(VaultError):
        Vault(str(bad)).load()
    bad.write_text(json.dumps({"kdf": {"salt": "abc", "iterations": 1}, "vault": "!!!"}))
    with pytest.raises(VaultError):
        Vault(str(bad)).load()
    bad.write_text("[]")
    with pytest.raises(VaultError):
        Vault(str(bad)).load()


def test_wrong_password_never_modifies_the_file(temp_vault, tmp_path):
    temp_vault.init_new("CorrectPassword", iterations=1000)
    before = (tmp_path / "test_vault.json").read_bytes()
    with pytest.raises(VaultError):
        temp_vault.set_entry("WrongPassword", "x", "u", "p")
    assert (tmp_path / "test_vault.json").read_bytes() == before


# ---------------------------------------------------------------------------
# Key-derivation upgrade path
# ---------------------------------------------------------------------------
def test_new_vaults_use_the_default_work_factor(tmp_path):
    v = Vault(str(tmp_path / "v.json"))
    v.init_new("MasterPass123")
    assert json.loads((tmp_path / "v.json").read_text())["kdf"]["iterations"] == DEFAULT_ITERATIONS


def test_vault_created_with_the_old_default_still_opens(tmp_path):
    path = str(tmp_path / "old.json")
    Vault(path).init_new("MasterPass123", iterations=390_000)
    legacy = Vault(path)
    legacy.set_entry("MasterPass123", "github", "u", "password1")
    assert Vault(path).get_entry("MasterPass123", "github")["password"] == "password1"


def test_change_master_upgrades_a_low_iteration_vault(tmp_path):
    path = str(tmp_path / "v.json")
    v = Vault(path)
    v.init_new("OldPassword123", iterations=1000)
    v.set_entry("OldPassword123", "github", "u", "password1")
    v.change_master("OldPassword123", "NewPassword456")  # no explicit iterations
    assert json.loads(open(path).read())["kdf"]["iterations"] == DEFAULT_ITERATIONS
    assert Vault(path).get_entry("NewPassword456", "github")["password"] == "password1"


def test_change_master_honours_explicit_iterations(tmp_path):
    path = str(tmp_path / "v.json")
    v = Vault(path)
    v.init_new("OldPassword123", iterations=1000)
    v.change_master("OldPassword123", "NewPassword456", iterations=2000)
    assert json.loads(open(path).read())["kdf"]["iterations"] == 2000


def test_change_master_issues_a_fresh_salt(tmp_path):
    path = str(tmp_path / "v.json")
    v = Vault(path)
    v.init_new("OldPassword123", iterations=1000)
    salt_before = json.loads(open(path).read())["kdf"]["salt"]
    v.change_master("OldPassword123", "NewPassword456", iterations=1000)
    assert json.loads(open(path).read())["kdf"]["salt"] != salt_before


# ---------------------------------------------------------------------------
# Bulk import / export
# ---------------------------------------------------------------------------
def test_merge_and_export_entries(temp_vault):
    master = "MasterPass123"
    temp_vault.init_new(master, iterations=1000)
    rows = [
        {"service": "github", "username": "u1", "password": "pw1", "notes": "n"},
        {"service": "", "username": "skipped", "password": "x"},
        {"service": "gitlab", "username": "u2", "password": "pw2"},
    ]
    assert temp_vault.merge_entries(master, rows) == 2
    exported = temp_vault.export_entries(master)
    assert set(exported) == {"github", "gitlab"}
    assert exported["github"]["notes"] == "n" and exported["gitlab"]["notes"] == ""


def test_merge_with_no_valid_rows_does_not_rewrite_the_file(temp_vault, tmp_path):
    temp_vault.init_new("MasterPass123", iterations=1000)
    before = (tmp_path / "test_vault.json").read_bytes()
    assert temp_vault.merge_entries("MasterPass123", [{"service": ""}]) == 0
    assert (tmp_path / "test_vault.json").read_bytes() == before
