import base64
import os
import secrets
import string
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

EXCLUDE_SIMILAR = {"l", "I", "1", "O", "0"}

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))

@dataclass
class KDFParams:
    name: str = "PBKDF2HMAC"
    iterations: int = 390_000
    salt: str = ""

    @staticmethod
    def new(iterations: int = 390_000) -> "KDFParams":
        salt = os.urandom(16)
        return KDFParams(iterations=iterations, salt=b64e(salt))

def derive_key(master_password: str, kdf_params: KDFParams) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b64d(kdf_params.salt),
        iterations=int(kdf_params.iterations),
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> str:
    if length < 8:
        raise ValueError("Minimum password length is 8")

    alphabet = ""
    categories = []

    if use_lower:
        lower = [c for c in string.ascii_lowercase if c not in EXCLUDE_SIMILAR]
        alphabet += "".join(lower)
        categories.append(lower)
    if use_upper:
        upper = [c for c in string.ascii_uppercase if c not in EXCLUDE_SIMILAR]
        alphabet += "".join(upper)
        categories.append(upper)
    if use_digits:
        digits = [c for c in string.digits if c not in EXCLUDE_SIMILAR]
        alphabet += "".join(digits)
        categories.append(digits)
    if use_symbols:
        symbols = list("!@#$%^&*()_-+=[]{}:;.,?/|")
        alphabet += "".join(symbols)
        categories.append(symbols)

    if not alphabet:
        raise ValueError("You must allow at least one character set!")

    pwd_chars = [secrets.choice(cat) for cat in categories]
    while len(pwd_chars) < length:
        pwd_chars.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(pwd_chars)
    return "".join(pwd_chars[:length])