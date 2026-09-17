# niyanta-IAM

**Distributed Cross-Platform Identity & Access Management (IAM) Orchestrator**

`niyanta-IAM` is a centralized Identity and Access Management control plane engineered to provision, audit, and govern local OS-level user accounts across heterogeneous infrastructure (**Linux POSIX** and **Windows NT**). Designed with an Agent-Controller topology, it abstracts operating system discrepancies and enforces uniform access governance through cryptographically authenticated execution channels.

---

## Technical Highlights

- **Unified Infrastructure Abstraction**: Single control plane orchestrating native OS account subsystems (`useradd`/`chpasswd`/`userdel` on POSIX; `Microsoft.PowerShell.LocalAccounts` on Windows NT).
- **Zero-Storage Credential Transport**: Transient credential transit—passwords pass through cryptographically signed envelopes directly to target agents for immediate ingestion, guaranteeing zero plaintext credential persistence in the controller database.
- **Mutual HMAC-SHA256 Authentication**: All inter-service telemetry and command execution between the control plane and node agents are authenticated using sliding-window JSON Web Tokens (JWT).
- **Granular RBAC Engine**: Fine-grained capability matrix decoupling access roles from operating system permissions, featuring custom color tagging and resource scoping.
- **Rule-Driven Policy Engine**: Declarative JSON security policies governing password entropy requirements, account life cycles, and session thresholds.
- **High-Fidelity Telemetry & Audit Stream**: Append-only transactional compliance logging capturing actor identity, target node, action payload, and severity vectors with streaming CSV export.
- **Active Session Inspector**: Real-time inspection of interactive terminal and desktop sessions (`who` / `query user`) directly from remote target nodes.

---

## System Architecture

```
                                 ┌────────────────────────────────────────┐
                                 │       niyanta-IAM Control Plane        │
                                 │        Flask + SQLAlchemy ORM          │
                                 │       Port: 5000 (Controller)          │
                                 └───────────────────┬────────────────────┘
                                                     │
                             HMAC-SHA256 Signed JWT  │ REST API (JSON)
                             Sliding Window Handshake│ Port: 5001
                                                     │
                     ┌───────────────────────────────┼───────────────────────────────┐
                     ▼                               ▼                               ▼
       ┌───────────────────────────┐   ┌───────────────────────────┐   ┌───────────────────────────┐
       │     Linux Target Node     │   │    Windows Target Node    │   │      Secondary Node       │
       │ ┌───────────────────────┐ │   │ ┌───────────────────────┐ │   │ ┌───────────────────────┐ │
       │ │   Universal Agent     │ │   │ │   Universal Agent     │ │   │ │   Universal Agent     │ │
       │ └───────────┬───────────┘ │   │ └───────────┬───────────┘ │   │ └───────────┬───────────┘ │
       │             │ (POSIX API) │   │             │ (PowerShell)│   │             │             │
       │             ▼             │   │             ▼             │   │             ▼             │
       │   /usr/sbin/useradd       │   │     New-LocalUser         │   │      OS Account Core      │
       │   /usr/sbin/userdel       │   │     Remove-LocalUser      │   │                           │
       │   /var/log/auth.log       │   │     query user (Console)  │   │                           │
       └───────────────────────────┘   └───────────────────────────┘   └───────────────────────────┘
```

### Component Topology

1. **Orchestration Server (`server/`)**: Central Flask application hosting administrative UI endpoints, role definitions, security policies, and SQLite persistence.
2. **Universal Node Agent (`agent/`)**: Daemon running on managed compute instances exposing an authenticated REST micro-API executing native platform commands.
3. **Shared Foundation (`shared/`)**: Cryptographic primitives, token minting/verification routines, and structured stdout logger pipelines.

---

## Repository Structure

```
iam/
├── server/
│   ├── app.py                  # Control plane router & administrative endpoints (30+ routes)
│   ├── models.py               # Declarative SQLAlchemy entity relational models
│   ├── requirements.txt        # Server-tier dependencies
│   ├── static/css/style.css    # High-density cybersecurity dark UI stylesheet
│   └── templates/              # Jinja2 rendering templates (Dashboard, RBAC, Machines, Audit)
│
├── agent/
│   ├── universal_agent.py      # Cross-platform edge daemon with OS-native execution logic
│   └── requirements.txt        # Agent micro-daemon dependencies
│
├── shared/
│   ├── config.py               # Shared cryptographic settings & JWT lifecycle utilities
│   └── utils.py                # Logging pipelines, API response formatters, auth decorators
│
└── USER_MANUAL.md              # In-depth operator guide, troubleshooting matrices & workflows
```

---

## Agent REST API Specification

Target node agents expose a lightweight HTTP daemon authenticated via bearer tokens. All mutating endpoints mandate valid HMAC-SHA256 JWT claims (`iss: niyanta-iam-server`).

| Method | Route | Authorization | Request Payload | Response Schema | Description |
|:-------|:------|:-------------:|:----------------|:----------------|:------------|
| `GET` | `/health` | Open | None | `{"status": "ok", "os": "<OS>"}` | Node connectivity & platform identification |
| `POST` | `/create_user` | `Bearer <JWT>` | `{"username": str, "password": str}` | `{"status": "success", "message": str}` | Provisions OS account with default home directory |
| `POST` | `/delete_user` | `Bearer <JWT>` | `{"username": str}` | `{"status": "success", "message": str}` | Purges OS account and user profile root |
| `GET` | `/sessions` | `Bearer <JWT>` | None | `{"status": "success", "data": {"sessions": list}}` | Enumerates active interactive terminal/desktop sessions |
| `GET` | `/audit_logs` | `Bearer <JWT>` | None | `{"status": "success", "data": {"logs": list}}` | Fetches tail of host authorization logs |

---

## Data Model & Schema Architecture

The persistence tier relies on relational entity abstractions managed via SQLAlchemy:

- **`TargetMachine`**: Compute node registry tracking IP addressing, hostnames, assigned agent ports, status flags, and health check heartbeats.
- **`ManagedUser`**: State machine (`active` | `disabled` | `locked`) mapping provisioned user accounts to physical nodes, associated metadata, and assigned roles.
- **`Role` & `Permission`**: Role groupings with UI color telemetry linked to granular action-resource capability pairs (`action`, `resource`).
- **`Policy`**: Dynamic rule sets defining operational guardrails (e.g. `password_complexity`, `session_inactivity_timeout`) stored as structured JSON.
- **`AuditLog`**: Tamper-evident ledger capturing operational event types (`USER_DEPLOY`, `USER_DELETE`, `POLICY_UPDATE`), severity gradients (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), actor identities, and detail strings.

---

## Quickstart & Deployment

### Prerequisites

- **Python Runtime**: Python 3.10 or higher
- **Node Permissions**: `root` / `sudo` (Linux) or elevated Administrator privileges (Windows PowerShell)

### 1. Repository Provisioning

```bash
git clone https://github.com/tiwarirst/iam.git
cd iam
```

### 2. Control Plane Initialization

```bash
# Install control plane dependencies
pip install -r server/requirements.txt

# (Optional) Export custom cryptographic secret
export NIYANTA_SECRET_KEY="your-high-entropy-secret-key"

# Launch Orchestrator
python server/app.py
```

*The control plane boots at `http://127.0.0.1:5000` and automatically provisions the SQLite database (`server/niyanta_iam.db`) with baseline seed data.*

### 3. Edge Node Agent Provisioning

Distribute `agent/` and `shared/` modules to target compute nodes:

```bash
pip install -r agent/requirements.txt

# (Required) Ensure secret key matches control plane
export NIYANTA_SECRET_KEY="your-high-entropy-secret-key"
```

#### Starting the Daemon:

- **Linux (POSIX)**:
  ```bash
  sudo python agent/universal_agent.py
  ```
- **Windows (NT)** *(Run PowerShell as Administrator)*:
  ```powershell
  $env:NIYANTA_SECRET_KEY="your-high-entropy-secret-key"
  python agent\universal_agent.py
  ```

*The agent binds to `0.0.0.0:5001` and awaits authenticated commands from the orchestrator.*

---

## Security Model & Cryptographic Pipeline

1. **Token Minting**: The control plane signs payloads containing issuer identification (`iss: niyanta-iam-server`), UTC issue timestamp (`iat`), and expiration boundary (`exp: +30min`).
2. **Signature Verification**: Target agents validate incoming bearer authorization against symmetric `NIYANTA_SECRET_KEY`. Invalid tokens immediately yield `401 Unauthorized` without invoking OS process trees.
3. **Execution Isolation**: Command invocation is strictly dispatched through parameterized sub-processes (`subprocess.run`), preventing shell-injection vulnerabilities.
4. **Credential Lifecycle**: Raw passwords exist purely in transient process memory during account creation commands and are never serialized or indexed into the controller's persistence layer.

---

## Configuration Matrix

| Parameter | Environment Variable | Default Value | Context |
|:----------|:---------------------|:--------------|:--------|
| Cryptographic Secret | `NIYANTA_SECRET_KEY` | `niyanta-iam-super-secret-key-2026` | Shared (Server + Agent) |
| Controller Port | — | `5000` | Server (`server/app.py`) |
| Agent Port | — | `5001` | Shared (`shared/config.py`) |
| Persistence Engine | — | `sqlite:///server/niyanta_iam.db` | Server (`server/app.py`) |
| Token Expiration | — | `30 Minutes` | Shared (`shared/config.py`) |
| Signing Algorithm | — | `HS256` | Shared (`shared/config.py`) |
