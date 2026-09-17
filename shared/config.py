"""
niyanta-IAM — Shared Configuration & JWT Utilities
Used by both the central server and the remote agents.
"""

import os
import datetime
import jwt  # PyJWT

# ─── Shared Secret ───────────────────────────────────────────────────────────
# In production, load from an environment variable or a vault.
SECRET_KEY = os.environ.get("NIYANTA_SECRET_KEY", "niyanta-iam-super-secret-key-2026")

# JWT settings
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30

# Agent default port
AGENT_PORT = 5001


# ─── Token helpers ───────────────────────────────────────────────────────────
def generate_token(payload: dict | None = None) -> str:
    """Generate a JWT token with an expiry claim."""
    now = datetime.datetime.utcnow()
    data = {
        "iss": "niyanta-iam-server",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES),
    }
    if payload:
        data.update(payload)
    return jwt.encode(data, SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Verify and decode a JWT token.
    Returns the decoded payload on success, or None on failure.
    """
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
