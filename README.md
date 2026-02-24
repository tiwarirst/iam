# Aegis-IAM

**Cross-Platform Identity & Access Management System**

Manage local user accounts on **Linux** and **Windows** machines from a single web dashboard. A lightweight Python agent runs on each target machine and receives JWT-authenticated commands from the central Flask server.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0%2B-black?logo=flask)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

---

## Features

- **Remote User Management** — Create and delete OS-level users on remote machines via `useradd` (Linux) / `New-LocalUser` (Windows)
- **Machine Registry** — Register target machines, run health checks, toggle active/inactive
- **Role-Based Access Control** — Define roles with color tags, assign permissions, organize users
- **Security Policies** — Enforce password, access, and session policies with JSON rule definitions
- **Audit Logging** — Filterable, paginated logs with CSV export and severity levels
- **Session Viewer** — View active login sessions on any registered machine
- **Dashboard Analytics** — Interactive Chart.js charts for activity timeline, OS distribution, and role breakdown
- **Alert System** — System-wide notifications for key events
- **Dark Cybersecurity UI** — Responsive glassmorphism theme with sidebar navigation

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              AEGIS-IAM DASHBOARD                    │
│            Flask + SQLite (Port 5000)               │
│                                                     │
│   Dashboard · Machines · Deploy · Audit · Policies  │
│                                                     │
│         JWT-authenticated HTTP requests             │
└────────────────────────┬────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   ┌────────────┐  ┌────────────┐  ┌────────────┐
   │   Agent    │  │   Agent    │  │   Agent    │
   │  (Linux)   │  │ (Windows)  │  │   (...)    │
   │ Port 5001  │  │ Port 5001  │  │ Port 5001  │
   └────────────┘  └────────────┘  └────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- `pip` package manager
- **Agent machines**: root (Linux) or Administrator (Windows) privileges

### 1. Clone the repo

```bash
git clone https://github.com/tiwarirst/aegis-iam.git
cd aegis-iam
```

### 2. Start the Dashboard Server

```bash
pip install -r server/requirements.txt
python server/app.py
```

Open **http://127.0.0.1:5000** in your browser.

### 3. Deploy an Agent on a Target Machine

Copy `agent/` and `shared/` to the target machine, then:

```bash
pip install -r agent/requirements.txt

# Linux
sudo python agent/universal_agent.py

# Windows (run as Administrator)
python agent\universal_agent.py
```

The agent listens on **port 5001**.

### 4. Register & Use

1. Go to **Machines** → register the agent's IP address
2. Go to **Deploy** → select a machine, enter credentials, click **Deploy User**

---

## Project Structure

```
aegis-iam/
├── server/                   # Central Flask dashboard
│   ├── app.py                # Flask app (30+ routes)
│   ├── models.py             # SQLAlchemy models
│   ├── requirements.txt
│   ├── static/css/style.css  # Dark theme stylesheet
│   └── templates/            # Jinja2 HTML templates
│
├── agent/                    # Lightweight agent (deploy to target VMs)
│   ├── universal_agent.py    # Cross-platform agent with Flask API
│   └── requirements.txt
│
├── shared/                   # Shared code (server + agent)
│   ├── config.py             # JWT config & token helpers
│   └── utils.py              # Logging, auth decorator, response helpers
│
├── USER_MANUAL.md            # Detailed usage documentation
└── README.md
```

---

## Agent API

| Method | Endpoint | Auth | Description |
|--------|----------|:----:|-------------|
| `GET`  | `/health` | — | Health check (no auth required) |
| `POST` | `/create_user` | JWT | Create a local user account |
| `POST` | `/delete_user` | JWT | Delete a local user account |
| `GET`  | `/sessions` | JWT | List active login sessions |
| `GET`  | `/audit_logs` | JWT | Fetch authentication logs |

---

## Security

All server-to-agent communication is authenticated using **JWT tokens** (HS256, 30-min expiry).

Set a custom secret key before deploying:

```bash
export AEGIS_SECRET_KEY="your-secure-random-key"
```

> **Warning:** The default secret key is for development only. Always set `AEGIS_SECRET_KEY` in production.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python, Flask, SQLAlchemy, SQLite |
| Auth | PyJWT (HS256) |
| Frontend | Jinja2, Chart.js, CSS (custom dark theme) |
| Agent | Flask micro-API + subprocess (`useradd` / PowerShell) |

---

## Documentation

See [USER_MANUAL.md](USER_MANUAL.md) for detailed setup instructions, feature walkthroughs, API reference, troubleshooting, and FAQ.

---

## License

MIT — see [LICENSE](LICENSE) for details.
