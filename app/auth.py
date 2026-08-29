"""Authentication helpers: bcrypt password hashes and signed JWT access tokens."""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "proxy-panel-development-secret-change-this-value-immediately",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))

# auto_error=False lets us return the same JSON 401 response for a missing and
# an invalid Authorization header instead of exposing implementation details.
security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a password with bcrypt's deliberately expensive cost factor."""

    if not isinstance(password, str) or not password:
        raise ValueError("Password cannot be empty")
    # bcrypt only uses the first 72 bytes. Refusing longer secrets avoids silent
    # truncation, which is safer and easier to explain to administrators.
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    salt = bcrypt.gensalt(rounds=int(os.getenv("BCRYPT_ROUNDS", "12")))
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return False for malformed hashes rather than leaking a server error."""

    try:
        if not plain_password or not hashed_password:
            return False
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:  # pragma: no cover - bcrypt versions raise different types
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a short-lived signed bearer token."""

    now = datetime.utcnow()
    to_encode = dict(data)
    to_encode.update(
        {
            "iat": now,
            "exp": now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),
            "type": "access",
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access" or not payload.get("id"):
            return None
        return payload
    except jwt.PyJWTError:
        return None


def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    """FastAPI dependency used by every private endpoint."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="احراز هویت لازم است",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="توکن احراز هویت نامعتبر یا منقضی شده است",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload
