#!/usr/bin/env python3
"""
Aegis-IAM — Central Flask Dashboard
=====================================
Manages target machines, deploys/removes user accounts on remote agents,
and collects audit logs — all from a single web interface.

Usage:
    python server/app.py
"""

import os
import sys
import json
import datetime
import csv
import io

# ── Make the project root importable ──────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, Response, make_response,
)

from shared.config import generate_token, AGENT_PORT
from shared.utils import setup_logger
from server.models import (
    db, Role, Permission, ManagedUser, TargetMachine,
    AuditLog, Policy, Alert,
)

# ── App factory ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "aegis-dashboard-session-secret"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'aegis_iam.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
logger = setup_logger("aegis-server")


# ── Helper: call agent API ───────────────────────────────────────────────────
def _agent_request(ip: str, endpoint: str, method: str = "GET", json_data: dict | None = None):
    """Send an authenticated request to a remote agent."""
    token = generate_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    url = f"http://{ip}:{AGENT_PORT}/{endpoint.lstrip('/')}"
    try:
        if method.upper() == "POST":
            resp = requests.post(url, json=json_data, headers=headers, timeout=10)
        else:
            resp = requests.get(url, headers=headers, timeout=10)
        return resp.status_code < 400, resp.json()
    except requests.ConnectionError:
        return False, {"message": f"Cannot reach agent at {ip}:{AGENT_PORT}"}
    except Exception as e:
        return False, {"message": str(e)}


def _create_alert(title, message="", severity="info", source="system"):
    """Helper to create system alerts."""
    alert = Alert(title=title, message=message, severity=severity, source=source)
    db.session.add(alert)
    db.session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
#  CONTEXT PROCESSORS
# ═══════════════════════════════════════════════════════════════════════════════
@app.context_processor
def inject_globals():
    """Inject global variables into all templates."""
    unread_alerts = Alert.query.filter_by(is_read=False).count()
    total_machines = TargetMachine.query.count()
    total_users = ManagedUser.query.count()
    return {
        "unread_alerts": unread_alerts,
        "total_machines": total_machines,
        "total_users": total_users,
        "current_year": datetime.datetime.utcnow().year,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  API ENDPOINTS (JSON)
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/stats")
def api_stats():
    """Return dashboard statistics as JSON for charts."""
    machines = TargetMachine.query.all()
    users = ManagedUser.query.all()
    logs = AuditLog.query.all()
    roles = Role.query.all()

    # OS distribution
    os_dist = {"Linux": 0, "Windows": 0}
    for m in machines:
        os_dist[m.os_type] = os_dist.get(m.os_type, 0) + 1

    # Status distribution
    status_dist = {"active": 0, "inactive": 0}
    for m in machines:
        status_dist[m.status] = status_dist.get(m.status, 0) + 1

    # Event types
    event_counts = {}
    for log in logs:
        event_counts[log.event_type] = event_counts.get(log.event_type, 0) + 1

    # User per role
    role_counts = {}
    for r in roles:
        role_counts[r.name] = len(r.users)

    # Activity over last 7 days
    activity_labels = []
    activity_data = []
    for i in range(6, -1, -1):
        day = datetime.datetime.utcnow() - datetime.timedelta(days=i)
        day_str = day.strftime("%b %d")
        activity_labels.append(day_str)
        count = AuditLog.query.filter(
            AuditLog.timestamp >= day.replace(hour=0, minute=0, second=0),
            AuditLog.timestamp < (day + datetime.timedelta(days=1)).replace(hour=0, minute=0, second=0),
        ).count()
        activity_data.append(count)

    # User status distribution
    user_status = {"active": 0, "disabled": 0, "locked": 0}
    for u in users:
        user_status[u.status] = user_status.get(u.status, 0) + 1

    return jsonify({
        "os_distribution": os_dist,
        "status_distribution": status_dist,
        "event_counts": event_counts,
        "role_counts": role_counts,
        "activity": {"labels": activity_labels, "data": activity_data},
        "user_status": user_status,
        "totals": {
            "machines": len(machines),
            "users": len(users),
            "logs": len(logs),
            "roles": len(roles),
        },
    })


@app.route("/api/health_check/<int:machine_id>")
def api_health_check(machine_id):
    """Check if an agent is reachable."""
    machine = TargetMachine.query.get_or_404(machine_id)
    success, result = _agent_request(machine.ip_address, "/health")
    if success:
        machine.status = "active"
        machine.last_seen = datetime.datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "online", "data": result})
    else:
        machine.status = "inactive"
        db.session.commit()
        return jsonify({"status": "offline", "message": result.get("message", "Unreachable")}), 503


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts as JSON."""
    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": a.id,
        "title": a.title,
        "message": a.message,
        "severity": a.severity,
        "is_read": a.is_read,
        "source": a.source,
        "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    } for a in alerts])


@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
def api_mark_alert_read(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.is_read = True
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route("/api/alerts/read_all", methods=["POST"])
def api_mark_all_alerts_read():
    Alert.query.filter_by(is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route("/api/search")
def api_search():
    """Global search across machines, users, and logs."""
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify({"results": []})

    results = []
    # Search machines
    for m in TargetMachine.query.all():
        if q in m.hostname.lower() or q in m.ip_address.lower():
            results.append({"type": "machine", "title": m.hostname, "subtitle": m.ip_address, "url": url_for("machines")})
    # Search users
    for u in ManagedUser.query.all():
        if q in u.username.lower() or q in (u.full_name or "").lower():
            results.append({"type": "user", "title": u.username, "subtitle": u.full_name or "", "url": url_for("users_page")})
    # Search roles
    for r in Role.query.all():
        if q in r.name.lower():
            results.append({"type": "role", "title": r.name, "subtitle": r.description, "url": url_for("roles_page")})

    return jsonify({"results": results[:15]})


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Dashboard Home ───────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    machines = TargetMachine.query.all()
    users = ManagedUser.query.all()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    roles = Role.query.all()
    alerts = Alert.query.filter_by(is_read=False).order_by(Alert.created_at.desc()).limit(5).all()
    policies = Policy.query.filter_by(is_active=True).all()
    return render_template(
        "dashboard.html",
        machines=machines,
        users=users,
        recent_logs=recent_logs,
        roles=roles,
        alerts=alerts,
        policies=policies,
    )


# ── Machines ─────────────────────────────────────────────────────────────────
@app.route("/machines")
def machines():
    all_machines = TargetMachine.query.order_by(TargetMachine.registered_at.desc()).all()
    return render_template("machines.html", machines=all_machines)


@app.route("/add_machine", methods=["POST"])
def add_machine():
    hostname = request.form.get("hostname", "").strip()
    ip_address = request.form.get("ip_address", "").strip()
    os_type = request.form.get("os_type", "Linux").strip()
    description = request.form.get("description", "").strip()

    if not hostname or not ip_address:
        flash("Hostname and IP address are required.", "error")
        return redirect(url_for("machines"))

    existing = TargetMachine.query.filter_by(ip_address=ip_address).first()
    if existing:
        flash(f"Machine with IP {ip_address} already registered.", "warning")
        return redirect(url_for("machines"))

    machine = TargetMachine(hostname=hostname, ip_address=ip_address, os_type=os_type, description=description)
    db.session.add(machine)

    log = AuditLog(
        machine_id=1,  # placeholder, will update
        event_type="MACHINE_REGISTERED",
        severity="info",
        actor="admin",
        details=f"Machine '{hostname}' ({ip_address}) registered as {os_type}",
    )
    db.session.flush()  # get machine.id
    log.machine_id = machine.id
    db.session.add(log)
    db.session.commit()

    _create_alert(f"New machine registered: {hostname}", f"IP: {ip_address}, OS: {os_type}", "info", "machines")
    logger.info(f"Registered new machine: {hostname} ({ip_address})")
    flash(f"Machine '{hostname}' added successfully.", "success")
    return redirect(url_for("machines"))


@app.route("/delete_machine/<int:machine_id>", methods=["POST"])
def delete_machine(machine_id):
    machine = TargetMachine.query.get_or_404(machine_id)
    hostname = machine.hostname
    # Delete associated logs first
    AuditLog.query.filter_by(machine_id=machine_id).delete()
    ManagedUser.query.filter_by(machine_id=machine_id).delete()
    db.session.delete(machine)
    db.session.commit()
    _create_alert(f"Machine removed: {hostname}", severity="warning", source="machines")
    flash(f"Machine '{hostname}' removed.", "success")
    return redirect(url_for("machines"))


@app.route("/toggle_machine/<int:machine_id>", methods=["POST"])
def toggle_machine(machine_id):
    machine = TargetMachine.query.get_or_404(machine_id)
    machine.status = "inactive" if machine.status == "active" else "active"
    db.session.commit()
    flash(f"Machine '{machine.hostname}' marked as {machine.status}.", "success")
    return redirect(url_for("machines"))


@app.route("/check_all_machines")
def check_all_machines():
    """Ping all machines to update their status."""
    machines = TargetMachine.query.all()
    online = 0
    for machine in machines:
        success, _ = _agent_request(machine.ip_address, "/health")
        if success:
            machine.status = "active"
            machine.last_seen = datetime.datetime.utcnow()
            online += 1
        else:
            machine.status = "inactive"
    db.session.commit()
    flash(f"Health check complete: {online}/{len(machines)} machines online.", "success")
    return redirect(url_for("machines"))


# ── Deploy / Remove User ────────────────────────────────────────────────────
@app.route("/deploy")
def deploy_page():
    machines = TargetMachine.query.filter_by(status="active").all()
    all_machines = TargetMachine.query.all()
    roles = Role.query.all()
    managed_users = ManagedUser.query.order_by(ManagedUser.created_at.desc()).all()
    return render_template("deploy.html", machines=machines, all_machines=all_machines, roles=roles, managed_users=managed_users)


@app.route("/deploy_user", methods=["POST"])
def deploy_user():
    machine_id = request.form.get("machine_id", type=int)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role_id = request.form.get("role_id", type=int)
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()

    if not machine_id or not username or not password:
        flash("Machine, username, and password are required.", "error")
        return redirect(url_for("deploy_page"))

    machine = TargetMachine.query.get(machine_id)
    if not machine:
        flash("Target machine not found.", "error")
        return redirect(url_for("deploy_page"))

    # Password strength validation
    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "error")
        return redirect(url_for("deploy_page"))

    # Check if user already exists on this machine
    existing = ManagedUser.query.filter_by(username=username, machine_id=machine_id).first()
    if existing:
        flash(f"User '{username}' already exists on {machine.hostname}.", "warning")
        return redirect(url_for("deploy_page"))

    success, result = _agent_request(
        machine.ip_address, "/create_user", "POST",
        {"username": username, "password": password},
    )

    if success:
        managed = ManagedUser(
            username=username, role_id=role_id, machine_id=machine_id,
            full_name=full_name, email=email, status="active",
        )
        db.session.add(managed)
        log = AuditLog(
            machine_id=machine_id,
            event_type="USER_CREATED",
            severity="info",
            actor="admin",
            details=f"User '{username}' deployed on {machine.hostname} ({machine.ip_address})",
        )
        db.session.add(log)
        db.session.commit()
        _create_alert(f"User deployed: {username}", f"On {machine.hostname}", "info", "deploy")
        flash(f"User '{username}' deployed on {machine.hostname}.", "success")
    else:
        flash(f"Agent error: {result.get('message', 'Unknown error')}", "error")

    return redirect(url_for("deploy_page"))


@app.route("/remove_user", methods=["POST"])
def remove_user():
    machine_id = request.form.get("machine_id", type=int)
    username = request.form.get("username", "").strip()

    if not machine_id or not username:
        flash("Machine and username are required.", "error")
        return redirect(url_for("deploy_page"))

    machine = TargetMachine.query.get(machine_id)
    if not machine:
        flash("Target machine not found.", "error")
        return redirect(url_for("deploy_page"))

    success, result = _agent_request(
        machine.ip_address, "/delete_user", "POST",
        {"username": username},
    )

    if success:
        user_record = ManagedUser.query.filter_by(username=username, machine_id=machine_id).first()
        if user_record:
            db.session.delete(user_record)
        log = AuditLog(
            machine_id=machine_id,
            event_type="USER_REMOVED",
            severity="warning",
            actor="admin",
            details=f"User '{username}' removed from {machine.hostname}",
        )
        db.session.add(log)
        db.session.commit()
        _create_alert(f"User removed: {username}", f"From {machine.hostname}", "warning", "deploy")
        flash(f"User '{username}' removed from {machine.hostname}.", "success")
    else:
        flash(f"Agent error: {result.get('message', 'Unknown error')}", "error")

    return redirect(url_for("deploy_page"))


# ── Users ────────────────────────────────────────────────────────────────────
@app.route("/users")
def users_page():
    all_users = ManagedUser.query.order_by(ManagedUser.created_at.desc()).all()
    roles = Role.query.all()
    machines = TargetMachine.query.all()
    return render_template("users.html", users=all_users, roles=roles, machines=machines)


@app.route("/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    user = ManagedUser.query.get_or_404(user_id)
    if user.status == "active":
        user.status = "disabled"
    elif user.status == "disabled":
        user.status = "active"
    else:
        user.status = "active"
    db.session.commit()
    flash(f"User '{user.username}' status changed to {user.status}.", "success")
    return redirect(url_for("users_page"))


@app.route("/edit_user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    user = ManagedUser.query.get_or_404(user_id)
    user.full_name = request.form.get("full_name", user.full_name).strip()
    user.email = request.form.get("email", user.email).strip()
    new_role_id = request.form.get("role_id", type=int)
    if new_role_id:
        user.role_id = new_role_id
    db.session.commit()
    flash(f"User '{user.username}' updated.", "success")
    return redirect(url_for("users_page"))


# ── Roles ────────────────────────────────────────────────────────────────────
@app.route("/roles")
def roles_page():
    all_roles = Role.query.order_by(Role.created_at.desc()).all()
    return render_template("roles.html", roles=all_roles)


@app.route("/add_role", methods=["POST"])
def add_role():
    name = request.form.get("name", "").strip().lower()
    description = request.form.get("description", "").strip()
    color = request.form.get("color", "cyan").strip()

    if not name:
        flash("Role name is required.", "error")
        return redirect(url_for("roles_page"))

    if Role.query.filter_by(name=name).first():
        flash(f"Role '{name}' already exists.", "warning")
        return redirect(url_for("roles_page"))

    role = Role(name=name, description=description, color=color)
    db.session.add(role)
    db.session.commit()
    flash(f"Role '{name}' created.", "success")
    return redirect(url_for("roles_page"))


@app.route("/delete_role/<int:role_id>", methods=["POST"])
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    if role.users:
        flash(f"Cannot delete role '{role.name}' — it has {len(role.users)} assigned users.", "error")
        return redirect(url_for("roles_page"))
    db.session.delete(role)
    db.session.commit()
    flash(f"Role '{role.name}' deleted.", "success")
    return redirect(url_for("roles_page"))


@app.route("/edit_role/<int:role_id>", methods=["POST"])
def edit_role(role_id):
    role = Role.query.get_or_404(role_id)
    role.description = request.form.get("description", role.description).strip()
    role.color = request.form.get("color", role.color).strip()
    db.session.commit()
    flash(f"Role '{role.name}' updated.", "success")
    return redirect(url_for("roles_page"))


# ── Audit Logs ───────────────────────────────────────────────────────────────
@app.route("/audit")
def audit_page():
    page = request.args.get("page", 1, type=int)
    per_page = 25
    severity_filter = request.args.get("severity", "")
    event_filter = request.args.get("event_type", "")

    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if event_filter:
        query = query.filter_by(event_type=event_filter)

    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()
    total_pages = (total + per_page - 1) // per_page

    machines = TargetMachine.query.all()
    event_types = db.session.query(AuditLog.event_type).distinct().all()

    return render_template(
        "audit.html",
        machines=machines,
        local_logs=logs,
        page=page,
        total_pages=total_pages,
        total=total,
        severity_filter=severity_filter,
        event_filter=event_filter,
        event_types=[e[0] for e in event_types],
    )


@app.route("/fetch_audit/<int:machine_id>")
def fetch_audit(machine_id):
    machine = TargetMachine.query.get_or_404(machine_id)
    success, result = _agent_request(machine.ip_address, "/audit_logs")
    if success:
        remote_logs = result.get("data", {}).get("logs", [])
        for entry in remote_logs[:20]:
            log = AuditLog(
                machine_id=machine_id,
                event_type="REMOTE_AUTH",
                severity="info",
                actor="agent",
                details=entry.get("raw", "") or entry.get("message", ""),
            )
            db.session.add(log)
        db.session.commit()
        flash(f"Fetched {len(remote_logs)} audit entries from {machine.hostname}.", "success")
    else:
        flash(f"Error: {result.get('message', 'Unreachable')}", "error")
    return redirect(url_for("audit_page"))


@app.route("/export_audit")
def export_audit():
    """Export audit logs as CSV."""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["ID", "Timestamp", "Machine", "Event Type", "Severity", "Actor", "Details"])
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            log.machine.hostname if log.machine else "N/A",
            log.event_type,
            log.severity,
            log.actor,
            log.details,
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=aegis_audit_logs.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route("/clear_audit", methods=["POST"])
def clear_audit():
    AuditLog.query.delete()
    db.session.commit()
    flash("All audit logs cleared.", "success")
    return redirect(url_for("audit_page"))


# ── Sessions ─────────────────────────────────────────────────────────────────
@app.route("/sessions/<int:machine_id>")
def sessions(machine_id):
    machine = TargetMachine.query.get_or_404(machine_id)
    success, result = _agent_request(machine.ip_address, "/sessions")
    session_list = []
    if success:
        session_list = result.get("data", {}).get("sessions", [])
    else:
        flash(f"Error: {result.get('message', 'Unreachable')}", "error")
    return render_template("sessions.html", machine=machine, sessions=session_list)


# ── Policies ─────────────────────────────────────────────────────────────────
@app.route("/policies")
def policies_page():
    all_policies = Policy.query.order_by(Policy.created_at.desc()).all()
    return render_template("policies.html", policies=all_policies)


@app.route("/add_policy", methods=["POST"])
def add_policy():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    policy_type = request.form.get("policy_type", "password").strip()
    rules_str = request.form.get("rules", "{}").strip()

    if not name:
        flash("Policy name is required.", "error")
        return redirect(url_for("policies_page"))

    # Validate JSON
    try:
        json.loads(rules_str)
    except json.JSONDecodeError:
        flash("Rules must be valid JSON.", "error")
        return redirect(url_for("policies_page"))

    policy = Policy(name=name, description=description, policy_type=policy_type, rules=rules_str)
    db.session.add(policy)
    db.session.commit()
    flash(f"Policy '{name}' created.", "success")
    return redirect(url_for("policies_page"))


@app.route("/toggle_policy/<int:policy_id>", methods=["POST"])
def toggle_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    policy.is_active = not policy.is_active
    db.session.commit()
    status = "activated" if policy.is_active else "deactivated"
    flash(f"Policy '{policy.name}' {status}.", "success")
    return redirect(url_for("policies_page"))


@app.route("/delete_policy/<int:policy_id>", methods=["POST"])
def delete_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    db.session.delete(policy)
    db.session.commit()
    flash(f"Policy '{policy.name}' deleted.", "success")
    return redirect(url_for("policies_page"))


# ── Settings ─────────────────────────────────────────────────────────────────
@app.route("/settings")
def settings_page():
    from shared.config import JWT_ALGORITHM, JWT_EXPIRATION_MINUTES, AGENT_PORT as CFG_AGENT_PORT

    config_obj = {
        "JWT_ALGORITHM": JWT_ALGORITHM,
        "TOKEN_EXPIRY_MINUTES": JWT_EXPIRATION_MINUTES,
        "SERVER_PORT": 5000,
        "AGENT_PORT": CFG_AGENT_PORT,
    }
    roles = Role.query.all()
    policies = Policy.query.filter_by(is_active=True).all()
    return render_template("settings.html", config=config_obj, roles=roles, policies=policies)


# ═══════════════════════════════════════════════════════════════════════════════
#  BOOTSTRAP DB + SEED
# ═══════════════════════════════════════════════════════════════════════════════
def seed_roles():
    """Create default roles if they don't exist."""
    defaults = [
        ("admin", "Full administrative privileges", "red"),
        ("developer", "Development access", "purple"),
        ("viewer", "Read-only access", "cyan"),
        ("auditor", "Audit and compliance access", "yellow"),
        ("operator", "Operational access to machines", "green"),
    ]
    for name, desc, color in defaults:
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, description=desc, color=color))
    db.session.commit()


def seed_policies():
    """Create default security policies."""
    defaults = [
        ("Password Strength", "Enforce minimum password requirements", "password",
         json.dumps({"min_length": 8, "require_uppercase": True, "require_digit": True, "require_special": True})),
        ("Session Timeout", "Auto-logout after inactivity", "session",
         json.dumps({"timeout_minutes": 30, "max_sessions": 3})),
        ("Access Control", "Default access control policy", "access",
         json.dumps({"default_deny": True, "require_mfa": False})),
    ]
    for name, desc, ptype, rules in defaults:
        if not Policy.query.filter_by(name=name).first():
            db.session.add(Policy(name=name, description=desc, policy_type=ptype, rules=rules))
    db.session.commit()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_roles()
        seed_policies()
        logger.info("Database initialised and defaults seeded.")
    logger.info("Starting Aegis-IAM Dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
