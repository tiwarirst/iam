# 🛡️ Aegis-IAM — Cross-Platform Identity & Access Management

A centralized **Flask Dashboard** to manage local user accounts on both **Ubuntu (Linux)** and **Windows 10/11** via lightweight Python agents. Features a dark cybersecurity-themed UI with real-time analytics, role-based access control, security policy management, and comprehensive audit logging.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Dashboard Analytics** | Interactive Chart.js charts (activity timeline, OS distribution, role breakdown) |
| **Machine Management** | Register, monitor, health-check, and toggle target machines |
| **User Deployment** | Deploy/remove OS-level users remotely with password strength validation |
| **Role Management** | CRUD roles with color tags, assigned-user counts, and permission tracking |
| **User Directory** | Browse all managed users, toggle status, edit profiles |
| **Security Policies** | Create password, access, and session policies with JSON rule definitions |
| **Audit Logging** | Filterable, paginated logs with CSV export and severity levels |
| **Session Viewer** | View active sessions on any registered machine in real time |
| **Global Search** | Instant search across machines, users, and roles |
| **Alert System** | System-wide notifications for key events (new machines, deployments, etc.) |
| **Responsive UI** | Mobile-friendly dark theme with glassmorphism, animations, and sidebar navigation |

---

## 📂 Project Structure

```
iam/
├── server/                  # Central Flask Dashboard
│   ├── app.py               # Main Flask application (~740 lines, 30+ routes)
│   ├── models.py            # SQLAlchemy models (Role, Permission, User, Machine, AuditLog, Policy, Alert)
│   ├── requirements.txt
│   ├── static/css/style.css # Dark cybersecurity theme v2.0 (~1400 lines)
│   └── templates/
│       ├── base.html        # Layout with sidebar, search, notifications, JS utilities
│       ├── dashboard.html   # Analytics overview with Chart.js charts
│       ├── machines.html    # Register & manage target machines
│       ├── deploy.html      # Deploy / remove users with password strength meter
│       ├── audit.html       # Paginated, filterable audit logs with CSV export
│       ├── sessions.html    # Active sessions on a machine
│       ├── roles.html       # Role CRUD with color picker
│       ├── users.html       # User directory with status toggle
│       ├── policies.html    # Security policy management
│       └── settings.html    # System configuration & maintenance
│
├── agent/                   # Lightweight Python agent (deploy to any VM)
│   ├── universal_agent.py   # OS-detecting agent with Flask API
│   └── requirements.txt
│
├── shared/                  # Shared utilities used by server & agent
│   ├── config.py            # JWT secret, token generation/verification
│   └── utils.py             # Logging, response helpers, @require_auth decorator
│
└── README.md
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  AEGIS-IAM DASHBOARD                     │
│              Flask + SQLite (Port 5000)                   │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Dashboard │  │ Machines │  │  Deploy  │  │  Audit   │ │
│  │ Overview  │  │ Manager  │  │  Users   │  │   Logs   │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│                       │                                  │
│       Sends JWT-authenticated HTTP requests              │
└───────────────────────┼──────────────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │ Agent (Linux)│ │Agent (Win)  │ │ Agent (...)  │
   │  Port 5001  │ │  Port 5001  │ │  Port 5001  │
   │  useradd    │ │ New-Local   │ │              │
   │  userdel    │ │ Remove-Local│ │              │
   │  auth.log   │ │ Event 4624  │ │              │
   └─────────────┘ └─────────────┘ └─────────────┘
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install flask flask-sqlalchemy PyJWT requests
```

### 2. Start the Dashboard (Server)

```bash
cd iam
python server/app.py
```

Open your browser at **http://127.0.0.1:5000**

### 3. Start an Agent (on a target machine)

Copy the `agent/` and `shared/` folders onto the target machine, then:

```bash
# Linux — run with sudo for useradd/userdel privileges
sudo python agent/universal_agent.py

# Windows — run as Administrator for New-LocalUser
python agent\universal_agent.py
```

The agent starts on **port 5001** and listens for JWT-authenticated commands.

### 4. Register the Machine

Go to the **Machines** page on the dashboard and register the agent's IP address.

### 5. Deploy a User

Navigate to **Deploy / Remove User**, select the target machine, enter a username and password, and click **Deploy User**.

---

## 🔐 Security

| Feature | Implementation |
|---|---|
| **Authentication** | JWT tokens with shared secret key |
| **Token Expiry** | 30-minute rolling window |
| **Header Format** | `Authorization: Bearer <token>` |
| **Secret Config** | `AEGIS_SECRET_KEY` environment variable (fallback to default) |

> **⚠️ Production Note:** Replace the default secret key by setting the `AEGIS_SECRET_KEY` environment variable.

---

## 📋 Agent API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/health` | ✗ | Health check |
| `POST` | `/create_user` | ✓ | Create a local user `{ "username": "...", "password": "..." }` |
| `POST` | `/delete_user` | ✓ | Delete a local user `{ "username": "..." }` |
| `GET`  | `/sessions` | ✓ | List active sessions |
| `GET`  | `/audit_logs` | ✓ | Fetch auth.log / Event ID 4624 |

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Flask 3.0+** — Web framework
- **Flask-SQLAlchemy** — ORM with SQLite
- **PyJWT** — JSON Web Tokens for server ↔ agent authentication
- **Chart.js 4.4** — Interactive dashboard charts (CDN)
- **Google Fonts** — Inter + JetBrains Mono
- **subprocess** — OS user management (useradd / PowerShell)

---

## 🖥️ Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Analytics overview with charts, timeline, alerts, quick actions |
| Machines | `/machines` | Register machines, health check, toggle active/inactive |
| Deploy | `/deploy` | Deploy/remove users with password strength meter |
| Audit | `/audit` | Paginated logs, filter by severity/event type, export CSV |
| Sessions | `/sessions/<id>` | Active sessions on a specific machine |
| Roles | `/roles` | Create/edit/delete roles with color tags |
| Users | `/users` | User directory with profile editing and status toggle |
| Policies | `/policies` | Security policy CRUD (password, access, session types) |
| Settings | `/settings` | System config, agent deployment guide, maintenance actions |

---

## 📜 License

MIT License — built for educational and security research purposes.
