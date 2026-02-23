#!/usr/bin/env python3
"""
Aegis-IAM — Universal Agent
============================
A lightweight, cross-platform agent that runs on target machines (Linux / Windows).
It exposes a small Flask API authenticated via JWT so the central Aegis dashboard
can remotely manage local user accounts and pull audit data.

Usage:
    python universal_agent.py          # starts on 0.0.0.0:5001
"""

import platform
import subprocess
import re
import os
import sys

# ── Make the project root importable so `shared.*` works ──────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, request, jsonify
from shared.config import AGENT_PORT
from shared.utils import require_auth, success_response, error_response, setup_logger

# ── Setup ─────────────────────────────────────────────────────────────────────
app = Flask(__name__)
logger = setup_logger("aegis-agent")
CURRENT_OS = platform.system()  # "Linux" or "Windows"

logger.info(f"Aegis-IAM Agent starting on {CURRENT_OS}")


# ═══════════════════════════════════════════════════════════════════════════════
#  OS-SPECIFIC USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

def create_user(username: str, password: str) -> dict:
    """
    Create a local user account.
    • Linux  → useradd + chpasswd
    • Windows → PowerShell New-LocalUser
    Returns a dict with 'success' (bool) and 'message' (str).
    """
    logger.info(f"create_user → {username} (OS: {CURRENT_OS})")

    if CURRENT_OS == "Linux":
        try:
            # Create user with a home directory
            subprocess.run(
                ["useradd", "-m", "-s", "/bin/bash", username],
                check=True,
                capture_output=True,
                text=True,
            )
            # Set the password via chpasswd
            subprocess.run(
                ["chpasswd"],
                input=f"{username}:{password}",
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info(f"User '{username}' created successfully on Linux.")
            return {"success": True, "message": f"User '{username}' created on Linux."}
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            logger.error(f"Linux create_user error: {err}")
            return {"success": False, "message": err}

    elif CURRENT_OS == "Windows":
        try:
            # PowerShell command to create a local user
            ps_script = (
                f'$SecPass = ConvertTo-SecureString "{password}" -AsPlainText -Force; '
                f'New-LocalUser -Name "{username}" -Password $SecPass '
                f'-FullName "{username}" -Description "Managed by Aegis-IAM"'
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info(f"User '{username}' created successfully on Windows.")
            return {"success": True, "message": f"User '{username}' created on Windows."}
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            logger.error(f"Windows create_user error: {err}")
            return {"success": False, "message": err}

    return {"success": False, "message": f"Unsupported OS: {CURRENT_OS}"}


def delete_user(username: str) -> dict:
    """
    Delete a local user account.
    • Linux  → userdel -r
    • Windows → PowerShell Remove-LocalUser
    """
    logger.info(f"delete_user → {username} (OS: {CURRENT_OS})")

    if CURRENT_OS == "Linux":
        try:
            subprocess.run(
                ["userdel", "-r", username],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info(f"User '{username}' deleted on Linux.")
            return {"success": True, "message": f"User '{username}' deleted on Linux."}
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            logger.error(f"Linux delete_user error: {err}")
            return {"success": False, "message": err}

    elif CURRENT_OS == "Windows":
        try:
            ps_cmd = f'Remove-LocalUser -Name "{username}" -Confirm:$false'
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info(f"User '{username}' deleted on Windows.")
            return {"success": True, "message": f"User '{username}' deleted on Windows."}
        except subprocess.CalledProcessError as e:
            err = e.stderr.strip() if e.stderr else str(e)
            logger.error(f"Windows delete_user error: {err}")
            return {"success": False, "message": err}

    return {"success": False, "message": f"Unsupported OS: {CURRENT_OS}"}


def list_active_sessions() -> list[dict]:
    """
    List currently active / logged-in sessions.
    • Linux  → `who` command
    • Windows → `query user` command
    Returns a list of dicts with session details.
    """
    sessions = []
    logger.info(f"list_active_sessions (OS: {CURRENT_OS})")

    if CURRENT_OS == "Linux":
        try:
            result = subprocess.run(
                ["who"], capture_output=True, text=True, check=True,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    sessions.append({
                        "user": parts[0],
                        "terminal": parts[1],
                        "login_time": " ".join(parts[2:]),
                    })
        except subprocess.CalledProcessError as e:
            logger.error(f"list_active_sessions error: {e}")

    elif CURRENT_OS == "Windows":
        try:
            result = subprocess.run(
                ["query", "user"],
                capture_output=True, text=True, check=True,
            )
            lines = result.stdout.strip().splitlines()
            for line in lines[1:]:  # skip header
                cols = line.split()
                if len(cols) >= 4:
                    sessions.append({
                        "user": cols[0].lstrip(">"),
                        "session": cols[1],
                        "state": cols[3] if len(cols) > 3 else "Unknown",
                        "login_time": " ".join(cols[-2:]) if len(cols) >= 6 else "N/A",
                    })
        except subprocess.CalledProcessError:
            # 'query user' may fail if no other users are logged in
            logger.warning("query user returned no results or is unavailable.")
        except FileNotFoundError:
            logger.warning("'query' command not found on this Windows build.")

    return sessions


def get_audit_logs(max_entries: int = 50) -> list[dict]:
    """
    Fetch recent authentication / logon audit events.
    • Linux  → tail /var/log/auth.log
    • Windows → PowerShell Get-WinEvent for Event ID 4624 (Successful Logon)
    """
    logs = []
    logger.info(f"get_audit_logs (OS: {CURRENT_OS})")

    if CURRENT_OS == "Linux":
        auth_log = "/var/log/auth.log"
        if os.path.exists(auth_log):
            try:
                result = subprocess.run(
                    ["tail", "-n", str(max_entries), auth_log],
                    capture_output=True, text=True, check=True,
                )
                for line in result.stdout.strip().splitlines():
                    logs.append({"raw": line})
            except subprocess.CalledProcessError as e:
                logger.error(f"Error reading auth.log: {e}")
        else:
            # Some distros use /var/log/secure or journalctl
            try:
                result = subprocess.run(
                    ["journalctl", "-u", "ssh", "-n", str(max_entries), "--no-pager"],
                    capture_output=True, text=True, check=True,
                )
                for line in result.stdout.strip().splitlines():
                    logs.append({"raw": line})
            except Exception:
                logs.append({"raw": "auth.log not found and journalctl unavailable."})

    elif CURRENT_OS == "Windows":
        try:
            ps_cmd = (
                f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624}} "
                f"-MaxEvents {max_entries} | "
                f"Select-Object TimeCreated, Id, Message | "
                f"ConvertTo-Json -Depth 2"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, check=True,
            )
            import json as _json
            raw = result.stdout.strip()
            if raw:
                parsed = _json.loads(raw)
                # PowerShell may return a single object instead of an array
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for entry in parsed:
                    logs.append({
                        "time": str(entry.get("TimeCreated", "")),
                        "event_id": entry.get("Id", 4624),
                        "message": str(entry.get("Message", ""))[:300],
                    })
        except subprocess.CalledProcessError as e:
            logger.warning(f"Get-WinEvent error (may need admin): {e.stderr}")
            logs.append({"raw": "Could not read Security log. Run agent as Administrator."})
        except Exception as e:
            logger.error(f"Audit log parse error: {e}")

    return logs


# ═══════════════════════════════════════════════════════════════════════════════
#  FLASK API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    """Unauthenticated health-check endpoint."""
    return success_response("Agent is running.", {"os": CURRENT_OS})


@app.route("/create_user", methods=["POST"])
@require_auth
def api_create_user():
    """Create a local user. Expects JSON: { "username": "...", "password": "..." }"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return error_response("Both 'username' and 'password' are required.", 400)

    result = create_user(username, password)
    if result["success"]:
        return success_response(result["message"])
    return error_response(result["message"], 500)


@app.route("/delete_user", methods=["POST"])
@require_auth
def api_delete_user():
    """Delete a local user. Expects JSON: { "username": "..." }"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    if not username:
        return error_response("'username' is required.", 400)

    result = delete_user(username)
    if result["success"]:
        return success_response(result["message"])
    return error_response(result["message"], 500)


@app.route("/sessions", methods=["GET"])
@require_auth
def api_sessions():
    """Return active sessions on this machine."""
    sessions = list_active_sessions()
    return success_response("Active sessions retrieved.", {"sessions": sessions})


@app.route("/audit_logs", methods=["GET"])
@require_auth
def api_audit_logs():
    """Return recent audit / auth log entries."""
    logs = get_audit_logs()
    return success_response("Audit logs retrieved.", {"logs": logs})


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    logger.info(f"Starting Aegis-IAM Agent on port {AGENT_PORT} ...")
    app.run(host="0.0.0.0", port=AGENT_PORT, debug=False)
