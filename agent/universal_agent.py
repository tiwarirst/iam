#!/usr/bin/env python3
"""
niyanta-IAM — Universal Agent
============================
A lightweight, cross-platform agent that runs on target machines (Linux / Windows).
It exposes a small Flask API authenticated via JWT so the central niyanta-IAM dashboard
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
logger = setup_logger("niyanta-agent")
CURRENT_OS = platform.system()  # "Linux" or "Windows"

logger.info(f"niyanta-IAM Agent starting on {CURRENT_OS}")


# ═══════════════════════════════════════════════════════════════════════════════
#  OS-SPECIFIC USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

def _is_valid_username(username: str) -> bool:
    """Validate username format to prevent parameter injection and OS command corruption."""
    return bool(re.match(r"^[a-zA-Z0-9._-]{1,64}$", username))


def create_user(username: str, password: str) -> dict:
    """
    Create a local user account securely.
    • Linux   → useradd + chpasswd
    • Windows → PowerShell New-LocalUser via environment parameterization
    Returns a dict with 'success' (bool) and 'message' (str).
    """
    logger.info(f"create_user → {username} (OS: {CURRENT_OS})")

    if not _is_valid_username(username):
        return {"success": False, "message": "Invalid username format. Allowed: alphanumeric, '.', '_', '-' (max 64 chars)."}

    if CURRENT_OS == "Linux":
        try:
            # Create user with home directory
            proc = subprocess.run(
                ["useradd", "-m", "-s", "/bin/bash", username],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() or "useradd command failed"
                logger.error(f"Linux useradd error: {err}")
                return {"success": False, "message": err}

            # Set password via stdin pipeline
            chpasswd_proc = subprocess.run(
                ["chpasswd"],
                input=f"{username}:{password}\n",
                capture_output=True,
                text=True,
            )
            if chpasswd_proc.returncode != 0:
                err = chpasswd_proc.stderr.strip() or "chpasswd command failed"
                logger.error(f"Linux chpasswd error: {err}")
                return {"success": False, "message": err}

            logger.info(f"User '{username}' created successfully on Linux.")
            return {"success": True, "message": f"User '{username}' created on Linux."}
        except Exception as e:
            logger.error(f"Linux create_user exception: {e}")
            return {"success": False, "message": str(e)}

    elif CURRENT_OS == "Windows":
        try:
            # Secure execution: pass username & password via environment variables
            ps_script = (
                "$SecPass = ConvertTo-SecureString $env:NIYANTA_PROV_PASS -AsPlainText -Force; "
                "New-LocalUser -Name $env:NIYANTA_PROV_USER -Password $SecPass "
                "-FullName $env:NIYANTA_PROV_USER -Description 'Managed by niyanta-IAM'"
            )
            env = os.environ.copy()
            env["NIYANTA_PROV_USER"] = username
            env["NIYANTA_PROV_PASS"] = password
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                env=env,
            )
            if proc.returncode == 0:
                logger.info(f"User '{username}' created successfully on Windows.")
                return {"success": True, "message": f"User '{username}' created on Windows."}
            else:
                err = proc.stderr.strip() or proc.stdout.strip() or "PowerShell New-LocalUser failed"
                logger.error(f"Windows create_user error: {err}")
                return {"success": False, "message": err}
        except Exception as e:
            logger.error(f"Windows create_user exception: {e}")
            return {"success": False, "message": str(e)}

    return {"success": False, "message": f"Unsupported OS: {CURRENT_OS}"}


def delete_user(username: str) -> dict:
    """
    Delete a local user account.
    • Linux  → userdel -r
    • Windows → PowerShell Remove-LocalUser via environment parameterization
    """
    logger.info(f"delete_user → {username} (OS: {CURRENT_OS})")

    if not _is_valid_username(username):
        return {"success": False, "message": "Invalid username format."}

    if CURRENT_OS == "Linux":
        try:
            proc = subprocess.run(
                ["userdel", "-r", username],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                logger.info(f"User '{username}' deleted on Linux.")
                return {"success": True, "message": f"User '{username}' deleted on Linux."}
            else:
                err = proc.stderr.strip() or "userdel command failed"
                logger.error(f"Linux delete_user error: {err}")
                return {"success": False, "message": err}
        except Exception as e:
            logger.error(f"Linux delete_user exception: {e}")
            return {"success": False, "message": str(e)}

    elif CURRENT_OS == "Windows":
        try:
            ps_cmd = "Remove-LocalUser -Name $env:NIYANTA_PROV_USER -Confirm:$false"
            env = os.environ.copy()
            env["NIYANTA_PROV_USER"] = username
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                env=env,
            )
            if proc.returncode == 0:
                logger.info(f"User '{username}' deleted on Windows.")
                return {"success": True, "message": f"User '{username}' deleted on Windows."}
            else:
                err = proc.stderr.strip() or proc.stdout.strip() or "Remove-LocalUser failed"
                logger.error(f"Windows delete_user error: {err}")
                return {"success": False, "message": err}
        except Exception as e:
            logger.error(f"Windows delete_user exception: {e}")
            return {"success": False, "message": str(e)}

    return {"success": False, "message": f"Unsupported OS: {CURRENT_OS}"}


def list_active_sessions() -> list[dict]:
    """
    List currently active / logged-in sessions.
    • Linux  → `who` command
    • Windows → `query user` with column-shift compensation and CIM fallback
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
        # 1. Attempt query.exe first (standard RDS/Server environments)
        query_success = False
        try:
            result = subprocess.run(
                ["query", "user"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().splitlines()
                for line in lines[1:]:
                    cols = line.split()
                    if len(cols) >= 3:
                        u = cols[0].lstrip(">")
                        # Handle missing SESSIONNAME when session is disconnected/empty
                        if cols[1].isdigit():
                            # Pattern: USERNAME ID STATE IDLE_TIME LOGON_TIME
                            sess_name = "Console"
                            state = cols[2] if len(cols) > 2 else "Active"
                            login_time = " ".join(cols[3:]) if len(cols) > 3 else "N/A"
                        else:
                            # Pattern: USERNAME SESSIONNAME ID STATE IDLE_TIME LOGON_TIME
                            sess_name = cols[1]
                            state = cols[3] if len(cols) > 3 else "Active"
                            login_time = " ".join(cols[4:]) if len(cols) > 4 else "N/A"

                        sessions.append({
                            "user": u,
                            "session": sess_name,
                            "state": state,
                            "login_time": login_time,
                        })
                query_success = len(sessions) > 0
        except Exception:
            query_success = False

        # 2. Resilient Fallback: Query active interactive desktop console user via WMI/CIM
        if not query_success:
            try:
                ps_cmd = "(Get-CimInstance Win32_ComputerSystem).UserName"
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True, text=True, timeout=5,
                )
                logged_user = proc.stdout.strip()
                if logged_user:
                    # Strip domain/hostname prefix if present (e.g. WORKGROUP\Alice -> Alice)
                    clean_user = logged_user.split("\\")[-1]
                    sessions.append({
                        "user": clean_user,
                        "session": "Console",
                        "state": "Active",
                        "login_time": "Interactive Desktop Session",
                    })
            except Exception as e:
                logger.warning(f"Windows WMI session discovery fallback error: {e}")

    return sessions


def get_audit_logs(max_entries: int = 50) -> list[dict]:
    """
    Fetch recent authentication / logon audit events.
    • Linux  → tail /var/log/auth.log or journalctl
    • Windows → PowerShell Get-WinEvent (Event 4624) with graceful fallback
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
                f"$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624}} "
                f"-MaxEvents {max_entries} -ErrorAction SilentlyContinue; "
                f"if ($events) {{ $events | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 2 }}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True,
            )
            import json as _json
            raw = result.stdout.strip()
            if raw:
                parsed = _json.loads(raw)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for entry in parsed:
                    logs.append({
                        "time": str(entry.get("TimeCreated", "")),
                        "event_id": entry.get("Id", 4624),
                        "message": str(entry.get("Message", ""))[:300],
                    })
            else:
                logs.append({"raw": "No recent Event 4624 (Logon) records found in Security event stream."})
        except Exception as e:
            logger.error(f"Audit log query exception: {e}")
            logs.append({"raw": f"Could not harvest security event logs: {e}"})

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
    logger.info(f"Starting niyanta-IAM Agent on port {AGENT_PORT} ...")
    app.run(host="0.0.0.0", port=AGENT_PORT, debug=False)
