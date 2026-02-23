"""
Aegis-IAM — Shared Utility Functions
"""

import logging
import sys
from functools import wraps
from flask import request, jsonify

from shared.config import verify_token


# ─── Logging ─────────────────────────────────────────────────────────────────
def setup_logger(name: str, level=logging.INFO) -> logging.Logger:
    """Return a pre-configured logger that writes to stdout."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s ► %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
    return logger


# ─── Response helpers ────────────────────────────────────────────────────────
def success_response(message: str, data: dict | None = None, status: int = 200):
    body = {"status": "success", "message": message}
    if data is not None:
        body["data"] = data
    return jsonify(body), status


def error_response(message: str, status: int = 400):
    return jsonify({"status": "error", "message": message}), status


# ─── JWT Auth Decorator ─────────────────────────────────────────────────────
def require_auth(f):
    """Decorator that enforces a valid JWT in the Authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return error_response("Missing or malformed Authorization header.", 401)
        token = auth_header.split(" ", 1)[1]
        payload = verify_token(token)
        if payload is None:
            return error_response("Invalid or expired token.", 401)
        return f(*args, **kwargs)
    return decorated
