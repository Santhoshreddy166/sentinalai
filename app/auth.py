"""
auth.py - Authentication module for Sentinal AI.

Provides user registration, login, and JWT token management.
Uses an in-memory user store (dict) — users are lost on server restart.
Password hashing uses hashlib with per-user salt for security.

NOTE: This uses Python 3.6-compatible syntax.
"""

import hashlib
import logging
import os
import time
import uuid
from typing import Dict, Optional, Tuple

try:
    import jwt
except ImportError:
    raise ImportError(
        "PyJWT is required for authentication. "
        "Install it with: pip install PyJWT"
    )

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

# Secret key for JWT signing. Use env var in production.
JWT_SECRET = os.environ.get("JWT_SECRET", "sentinal-ai-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24  # Token validity period

# ------------------------------------------------------------------
# In-Memory User Store
# ------------------------------------------------------------------
# Structure: { email: { "id": str, "name": str, "email": str,
#                        "password_hash": str, "salt": str,
#                        "created_at": float } }
_users = {}  # type: Dict[str, Dict]


# ------------------------------------------------------------------
# Password Hashing
# ------------------------------------------------------------------

def _generate_salt():
    # type: () -> str
    """Generate a random 32-byte hex salt."""
    return os.urandom(32).hex()


def _hash_password(password, salt):
    # type: (str, str) -> str
    """Hash a password with SHA-256 and the given salt."""
    salted = "{}:{}".format(salt, password)
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


def _verify_password(password, salt, password_hash):
    # type: (str, str, str) -> bool
    """Verify a password against a stored hash."""
    return _hash_password(password, salt) == password_hash


# ------------------------------------------------------------------
# JWT Token Management
# ------------------------------------------------------------------

def _create_token(user_id, email, name):
    # type: (str, str, str) -> str
    """Create a JWT token for the given user."""
    payload = {
        "sub": user_id,
        "email": email,
        "name": name,
        "iat": int(time.time()),
        "exp": int(time.time()) + (JWT_EXPIRY_HOURS * 3600),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token):
    # type: (str) -> Optional[Dict]
    """
    Decode and verify a JWT token.

    Returns the payload dict on success, or None on failure.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired.")
        return None
    except jwt.InvalidTokenError as exc:
        logger.warning("Invalid token: %s", exc)
        return None


# ------------------------------------------------------------------
# User Registration & Login
# ------------------------------------------------------------------

def register_user(name, email, password):
    # type: (str, str, str) -> Tuple[bool, str, Optional[Dict]]
    """
    Register a new user.

    Returns (success, message, user_data_with_token).
    """
    email_lower = email.lower().strip()

    # Check if user already exists
    if email_lower in _users:
        return (False, "An account with this email already exists.", None)

    # Validate inputs
    if not name or not name.strip():
        return (False, "Name is required.", None)
    if not email_lower or "@" not in email_lower:
        return (False, "A valid email address is required.", None)
    if len(password) < 6:
        return (False, "Password must be at least 6 characters.", None)

    # Create user
    user_id = str(uuid.uuid4())
    salt = _generate_salt()
    password_hash = _hash_password(password, salt)

    user = {
        "id": user_id,
        "name": name.strip(),
        "email": email_lower,
        "password_hash": password_hash,
        "salt": salt,
        "created_at": time.time(),
    }
    _users[email_lower] = user

    # Generate token
    token = _create_token(user_id, email_lower, name.strip())

    # Handle PyJWT version differences (v1 returns str, v2 returns bytes)
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    logger.info("New user registered: %s (%s)", name.strip(), email_lower)

    return (True, "Account created successfully.", {
        "token": token,
        "user": {
            "id": user_id,
            "name": name.strip(),
            "email": email_lower,
        },
    })


def login_user(email, password):
    # type: (str, str) -> Tuple[bool, str, Optional[Dict]]
    """
    Authenticate a user with email and password.

    Returns (success, message, user_data_with_token).
    """
    email_lower = email.lower().strip()

    user = _users.get(email_lower)
    if not user:
        return (False, "No account found with this email.", None)

    if not _verify_password(password, user["salt"], user["password_hash"]):
        return (False, "Incorrect password.", None)

    # Generate token
    token = _create_token(user["id"], user["email"], user["name"])

    # Handle PyJWT version differences
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    logger.info("User logged in: %s", email_lower)

    return (True, "Login successful.", {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
        },
    })
