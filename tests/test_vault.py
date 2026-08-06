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