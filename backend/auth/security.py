import os
import hashlib
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any

from cryptography.fernet import Fernet
import jwt

# Environment variables
ENCRYPTION_KEY = os.getenv("SECOPS_ENCRYPTION_KEY")
JWT_SECRET = os.getenv("SECOPS_JWT_SECRET", "secops-guardian-super-secret-jwt-signing-key-change-in-prod-32bytes")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("SECOPS_JWT_EXPIRATION_HOURS", "24"))

# Fernet cipher initialization
def _get_fernet() -> Fernet:
    if ENCRYPTION_KEY:
        try:
            return Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
        except Exception:
            pass
    # Generate deterministic 32-byte urlsafe base64 key from JWT_SECRET as fallback
    raw = hashlib.sha256(JWT_SECRET.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)

_fernet_instance = _get_fernet()


def encrypt_secret(plain_text: str) -> str:
    """Encrypts a plaintext string (e.g. client secrets) using Fernet."""
    if not plain_text:
        return ""
    return _fernet_instance.encrypt(plain_text.encode("utf-8")).decode("utf-8")


def decrypt_secret(cipher_text: str) -> str:
    """Decrypts a Fernet-encrypted ciphertext string."""
    if not cipher_text:
        return ""
    try:
        return _fernet_instance.decrypt(cipher_text.encode("utf-8")).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decrypt secret: {str(e)}")


def hash_api_key(raw_key: str) -> str:
    """Computes SHA-256 hash of an API key for safe database storage."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def generate_api_key(prefix: str = "secops_live_") -> Tuple[str, str]:
    """
    Generates a secure random API key and its SHA-256 hash.
    Returns: (raw_key, key_hash)
    """
    raw_token = secrets.token_urlsafe(32)
    raw_key = f"{prefix}{raw_token}"
    key_hash = hash_api_key(raw_key)
    return raw_key, key_hash


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT session token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT session token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.PyJWTError, Exception):
        return None
