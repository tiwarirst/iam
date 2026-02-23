"""
Aegis-IAM — SQLAlchemy Database Models
"""

import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ─── Role ────────────────────────────────────────────────────────────────────
class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256), default="")
    color = db.Column(db.String(20), default="cyan")  # UI color tag
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    users = db.relationship("ManagedUser", backref="role", lazy=True)
    permissions = db.relationship("Permission", backref="role", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Role {self.name}>"


# ─── Permission ──────────────────────────────────────────────────────────────
class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    action = db.Column(db.String(64), nullable=False)  # e.g. "create_user", "delete_user", "view_logs"
    resource = db.Column(db.String(64), default="*")   # e.g. "*" = all, "machines", "users"

    def __repr__(self):
        return f"<Permission {self.action} on {self.resource}>"


# ─── Managed User ───────────────────────────────────────────────────────────
class ManagedUser(db.Model):
    __tablename__ = "managed_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(256), default="")
    email = db.Column(db.String(256), default="")
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=True)
    machine_id = db.Column(db.Integer, db.ForeignKey("target_machines.id"), nullable=True)
    status = db.Column(db.String(16), default="active")  # active / disabled / locked
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_activity = db.Column(db.DateTime, nullable=True)

    machine = db.relationship("TargetMachine", backref="managed_users")

    def __repr__(self):
        return f"<ManagedUser {self.username}>"


# ─── Target Machine ─────────────────────────────────────────────────────────
class TargetMachine(db.Model):
    __tablename__ = "target_machines"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    os_type = db.Column(db.String(16), default="Linux")      # "Linux" or "Windows"
    status = db.Column(db.String(16), default="active")       # "active" / "inactive"
    description = db.Column(db.String(256), default="")
    last_seen = db.Column(db.DateTime, nullable=True)
    agent_version = db.Column(db.String(16), default="1.0")
    registered_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    audit_logs = db.relationship("AuditLog", backref="machine", lazy=True)

    def __repr__(self):
        return f"<TargetMachine {self.hostname} ({self.ip_address})>"


# ─── Audit Log ───────────────────────────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    machine_id = db.Column(db.Integer, db.ForeignKey("target_machines.id"), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(16), default="info")  # info / warning / critical
    actor = db.Column(db.String(128), default="system")  # who triggered the action
    details = db.Column(db.Text, default="")
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<AuditLog {self.event_type} @ {self.timestamp}>"


# ─── Policy ──────────────────────────────────────────────────────────────────
class Policy(db.Model):
    __tablename__ = "policies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    policy_type = db.Column(db.String(32), default="password")  # password / access / session
    rules = db.Column(db.Text, default="{}")  # JSON string of policy rules
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<Policy {self.name}>"


# ─── Alert ───────────────────────────────────────────────────────────────────
class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    message = db.Column(db.Text, default="")
    severity = db.Column(db.String(16), default="info")  # info / warning / critical
    is_read = db.Column(db.Boolean, default=False)
    source = db.Column(db.String(64), default="system")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<Alert {self.title}>"
