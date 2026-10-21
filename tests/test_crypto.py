import pytest
from password_manager.core.crypto import generate_password, KDFParams, derive_key

def test_generate_password_length():
    pwd = generate_password(length=16)
    assert len(pwd) == 16

def test_generate_password_invalid_length():
    with pytest.raises(ValueError):
        generate_password(length=5)

def test_generate_password_no_categories():
    with pytest.raises(ValueError):
        generate_password(
            use_lower=False,
            use_upper=False,
            use_digits=False,
            use_symbols=False
        )

def test_kdf_derivation_consistency():
    params = KDFParams.new(iterations=1000)
    key1 = derive_key("MyMasterPassword123", params)
    key2 = derive_key("MyMasterPassword123", params)
    assert key1 == key2

def test_kdf_derivation_different_passwords():
    params = KDFParams.new(iterations=1000)
    key1 = derive_key("PasswordOne123", params)
    key2 = derive_key("PasswordTwo123", params)
    assert key1 != key2

def test_default_iterations_follow_owasp_guidance():
    from password_manager.core.crypto import DEFAULT_ITERATIONS
    assert DEFAULT_ITERATIONS >= 600_000
    assert KDFParams.new().iterations == DEFAULT_ITERATIONS
    assert KDFParams().iterations == DEFAULT_ITERATIONS


def test_each_vault_gets_a_fresh_salt():
    assert KDFParams.new(iterations=1000).salt != KDFParams.new(iterations=1000).salt
