import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# We use a persistent salt and a machine-specific secret if available, 
# or a default for the local user.
_SALT = b'\x12\xaf\x8c\x8e\xae\x8a\x0c\x11'

def _get_master_key() -> bytes:
    # Try to get a unique machine ID or use a fallback
    secret = os.getenv("PVEMCP_MASTER_SECRET", "pvemcp-local-secret-31337")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(secret.encode())

def encrypt(data: str) -> str:
    """Encrypt text using AES-256-GCM."""
    key = _get_master_key()
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    # Return iv + tag + ciphertext encoded in base64
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')

def decrypt(token: str) -> str:
    """Decrypt AES-256-GCM token."""
    try:
        data = base64.b64decode(token)
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        key = _get_master_key()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    except Exception:
        return ""

