# 🛡️ Aegis-IAM — User Manual

**Version 2.0 | Cross-Platform Identity & Access Management System**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Installation & Setup](#3-installation--setup)
   - 3.1 [Installing the Dashboard Server](#31-installing-the-dashboard-server)
   - 3.2 [Installing the Agent on Target Machines](#32-installing-the-agent-on-target-machines)
4. [Getting Started](#4-getting-started)
5. [Dashboard Overview](#5-dashboard-overview)
6. [Machine Management](#6-machine-management)
   - 6.1 [Registering a Machine](#61-registering-a-machine)
   - 6.2 [Health Checks](#62-health-checks)
   - 6.3 [Toggling Machine Status](#63-toggling-machine-status)
   - 6.4 [Deleting a Machine](#64-deleting-a-machine)
7. [User Deployment & Removal](#7-user-deployment--removal)
   - 7.1 [Deploying a User](#71-deploying-a-user)
   - 7.2 [Removing a User](#72-removing-a-user)
8. [User Directory](#8-user-directory)
   - 8.1 [Viewing All Users](#81-viewing-all-users)
   - 8.2 [Editing a User](#82-editing-a-user)
   - 8.3 [Toggling User Status](#83-toggling-user-status)
9. [Role Management](#9-role-management)
   - 9.1 [Creating a Role](#91-creating-a-role)
   - 9.2 [Editing a Role](#92-editing-a-role)
   - 9.3 [Deleting a Role](#93-deleting-a-role)
10. [Audit Logs](#10-audit-logs)
    - 10.1 [Viewing Logs](#101-viewing-logs)
    - 10.2 [Fetching Remote Logs](#102-fetching-remote-logs)
    - 10.3 [Filtering Logs](#103-filtering-logs)
    - 10.4 [Exporting Logs](#104-exporting-logs)
    - 10.5 [Clearing Logs](#105-clearing-logs)
11. [Session Viewer](#11-session-viewer)
12. [Security Policies](#12-security-policies)
    - 12.1 [Creating a Policy](#121-creating-a-policy)
    - 12.2 [Activating / Deactivating Policies](#122-activating--deactivating-policies)
    - 12.3 [Deleting a Policy](#123-deleting-a-policy)
13. [Settings & System Configuration](#13-settings--system-configuration)
14. [Global Search](#14-global-search)
15. [Alerts & Notifications](#15-alerts--notifications)
16. [Security & Authentication](#16-security--authentication)
17. [Agent API Reference](#17-agent-api-reference)
18. [Troubleshooting](#18-troubleshooting)
19. [FAQ](#19-faq)

---

## 1. Introduction

**Aegis-IAM** is a centralized Identity and Access Management (IAM) system that allows administrators to manage local OS-level user accounts on remote **Linux (Ubuntu)** and **Windows (10/11)** machines from a single web dashboard.

### Key Capabilities

| Capability | Description |
|---|---|
| **Centralized Control** | Manage users across multiple machines from one dashboard |
| **Cross-Platform** | Supports both Linux (`useradd`/`userdel`) and Windows (`New-LocalUser`/`Remove-LocalUser`) |
| **Secure Communication** | JWT-authenticated REST API between server and agents |
| **Real-Time Analytics** | Interactive charts showing activity trends, OS distribution, and role breakdown |
| **Audit Trail** | Complete logging of all user management operations with export capability |
| **Role-Based Organization** | Assign color-coded roles to organize managed users |
| **Security Policies** | Define and enforce password, access, and session policies |
| **Health Monitoring** | Ping agents to verify machine availability in real time |

### Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                   AEGIS-IAM DASHBOARD                         │
│                Flask + SQLite (Port 5000)                      │
│                                                               │
│  Dashboard │ Machines │ Deploy │ Audit │ Roles │ Policies     │
│                                                               │
│            Sends JWT-authenticated HTTP requests               │
└──────────────────────────┬────────────────────────────────────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ Agent      │  │ Agent      │  │ Agent      │
     │ (Linux)    │  │ (Windows)  │  │ (...)      │
     │ Port 5001  │  │ Port 5001  │  │ Port 5001  │
     │ useradd    │  │ PowerShell │  │            │
     │ auth.log   │  │ Event Log  │  │            │
     └────────────┘  └────────────┘  └────────────┘
```

The **Dashboard Server** runs on your admin workstation and communicates with **Agents** deployed on each target machine. All communication uses JWT tokens for authentication.

---

## 2. System Requirements

### Dashboard Server (Admin Machine)

| Requirement | Minimum |
|---|---|
| **Python** | 3.10 or later |
| **OS** | Any (Windows, Linux, macOS) |
| **Browser** | Chrome, Firefox, Edge (modern versions) |
| **Network** | Must be able to reach agent machines on port 5001 |

### Target Machines (Agent)

| Requirement | Minimum |
|---|---|
| **Python** | 3.10 or later |
| **OS** | Ubuntu Linux or Windows 10/11 |
| **Privileges** | Root (Linux) or Administrator (Windows) |
| **Network** | Must accept incoming connections on port 5001 |

### Python Dependencies

| Package | Server | Agent | Purpose |
|---|---|---|---|
| `flask` | ✓ | ✓ | Web framework |
| `flask-sqlalchemy` | ✓ | — | Database ORM |
| `PyJWT` | ✓ | ✓ | JWT authentication |
| `requests` | ✓ | — | HTTP client for agent communication |

---

## 3. Installation & Setup

### 3.1 Installing the Dashboard Server

**Step 1 — Clone or copy the project:**

```bash
# Place the iam/ folder on your admin machine
cd iam
```

**Step 2 — Install Python dependencies:**

```bash
pip install flask flask-sqlalchemy PyJWT requests
```

Or using the requirements file:

```bash
pip install -r server/requirements.txt
```

**Step 3 — Start the dashboard:**

```bash
python server/app.py
```

You will see output confirming the database has been initialized:

```
[2026-02-23 10:00:00] INFO aegis-server ► Database initialised and defaults seeded.
[2026-02-23 10:00:00] INFO aegis-server ► Starting Aegis-IAM Dashboard on http://127.0.0.1:5000
```

**Step 4 — Open the dashboard:**

Navigate to **http://127.0.0.1:5000** in your web browser.

> **Note:** On first launch, the database (`server/aegis_iam.db`) is created automatically with default roles and security policies pre-seeded.

### 3.2 Installing the Agent on Target Machines

Each remote machine that you want to manage needs the Aegis-IAM agent running.

**Step 1 — Copy files to the target machine:**

Copy the following folders to the target machine:
- `agent/` — Contains `universal_agent.py`
- `shared/` — Contains `config.py` and `utils.py`

**Step 2 — Install dependencies on the target machine:**

```bash
pip install flask PyJWT
```

**Step 3 — Start the agent:**

On **Linux** (requires root for user management):
```bash
sudo python agent/universal_agent.py
```

On **Windows** (requires Administrator PowerShell):
```powershell
python agent\universal_agent.py
```

The agent starts on port **5001** and automatically detects the operating system.

> ⚠️ **Important:** The JWT secret key in `shared/config.py` must be **identical** on both the server and all agent machines. If they don't match, authentication will fail.

---

## 4. Getting Started

After installation, follow this workflow to start managing users:

```
1. Start Dashboard Server     →  python server/app.py
2. Start Agent on target(s)   →  sudo python agent/universal_agent.py
3. Register machines           →  Dashboard → Machines → Add Machine
4. Run health check            →  Verify agents are reachable
5. Deploy users                →  Dashboard → Deploy → Create user
6. Monitor activity            →  Dashboard → Audit Logs
```

---

## 5. Dashboard Overview

**URL:** `http://127.0.0.1:5000/`

The dashboard is your landing page and provides a complete overview of your IAM system at a glance.

### Sidebar Navigation

The left sidebar provides access to all sections:

| Section | Pages |
|---|---|
| **Overview** | Dashboard |
| **Management** | Machines, Users, Roles |
| **Actions** | Deploy Users, Audit Logs |
| **Security** | Policies |
| **System** | Settings |

The sidebar shows badge counters for the total number of machines and managed users. On mobile (screens ≤ 768px), the sidebar collapses and can be toggled with the hamburger menu (☰).

### Stat Cards

Six summary cards are displayed at the top:

| Card | Description |
|---|---|
| 🖥️ **Target Machines** | Total registered machines |
| 👥 **Managed Users** | Total deployed user accounts |
| 🏷️ **Roles Defined** | Number of roles |
| 📋 **Audit Events** | Total audit log entries |
| 🛡️ **Active Policies** | Number of active security policies |
| 🔔 **Alerts** | Number of unread system alerts |

### Interactive Charts

Three charts provide visual analytics (powered by Chart.js):

1. **Activity Over Time** — A line chart showing audit events per day over the last 7 days
2. **OS Distribution** — A doughnut chart breaking down machines by operating system (Linux vs. Windows)
3. **Users per Role** — A doughnut chart showing how many users are assigned to each role

Charts are loaded dynamically from the `/api/stats` endpoint.

### Machines Summary Table

A quick-reference table shows the most recently registered machines (up to 6) with hostname, IP, OS, and status.

### Activity Timeline

The most recent 8 audit log entries are displayed as a visual timeline with:
- Color-coded severity dots (green = info, yellow = warning, red = critical)
- Event type badge
- Timestamp
- Detail text

### Quick Actions

Six shortcut buttons for common tasks:
- Deploy User
- Add Machine
- Health Check All
- Export Audit Logs
- Manage Roles
- Security Policies

### Recent Alerts

Displays the latest unread system alerts with severity badge, title, timestamp, and source label.

---

## 6. Machine Management

**URL:** `http://127.0.0.1:5000/machines`

Machines are remote computers where the Aegis-IAM agent is running. You must register a machine before you can deploy users to it.

### 6.1 Registering a Machine

1. Navigate to **Machines** from the sidebar
2. Fill in the **Register New Machine** form:

   | Field | Required | Description | Example |
   |---|---|---|---|
   | **Hostname** | ✓ | A friendly name for the machine | `web-server-01` |
   | **IP Address** | ✓ | The machine's IP address (must be reachable from server) | `192.168.1.100` |
   | **OS Type** | ✓ | Operating system — Linux or Windows | `Linux` |
   | **Description** | — | Optional description | `Production web server` |

3. Click **⊕ Register Machine**
4. The machine appears in the table with status "active"

> **Note:** The IP address must be unique. Attempting to register a duplicate IP will show a warning.

An audit log entry (`MACHINE_REGISTERED`) and a system alert are automatically created.

### 6.2 Health Checks

Health checks verify that the agent on a target machine is reachable and responding.

**Single Machine Health Check:**
- In the machines table, click the **📡 Ping** button next to any machine
- The status badge updates in real time without page reload
- A green "online" badge means the agent is responding; red "offline" means unreachable

**All Machines Health Check:**
- Click the **🔍 Check All Machines** button in the page header
- Every registered machine is pinged sequentially
- A summary message shows how many machines are online (e.g., "3/5 machines online")
- Machine statuses and `last_seen` timestamps are updated

### 6.3 Toggling Machine Status

- Click the **Toggle** button (⏸ or ▶) for any machine to manually switch between `active` and `inactive`
- **Inactive machines** will not appear in the Deploy User machine dropdown
- This is useful for temporarily disabling a machine without deleting it

### 6.4 Deleting a Machine

1. Click the **🗑️ Delete** button next to the machine
2. Confirm the deletion in the pop-up dialog
3. The machine and all its associated **audit logs** and **managed user records** are permanently deleted

> ⚠️ **Warning:** Deleting a machine removes all related records from the dashboard. The actual OS-level user accounts on the remote machine are **not** removed.

---

## 7. User Deployment & Removal

**URL:** `http://127.0.0.1:5000/deploy`

This page has a two-column layout: **Deploy User** on the left and **Remove User** on the right.

### 7.1 Deploying a User

Deploying a user creates an actual OS-level user account on the target machine.

1. Navigate to **Deploy / Remove** from the sidebar
2. Fill in the **Deploy User** form:

   | Field | Required | Description | Rules |
   |---|---|---|---|
   | **Target Machine** | ✓ | Machine to deploy on | Only active machines shown |
   | **Username** | ✓ | OS username | Must start with a letter, 3–32 characters, letters/numbers/underscores only |
   | **Role** | — | Assign a role | Select from existing roles |
   | **Full Name** | — | User's display name | Free text |
   | **Email** | — | User's email | Valid email format |
   | **Password** | ✓ | Account password | Minimum 8 characters |

3. **Password Strength Meter:** As you type the password, a real-time strength indicator shows:
   - 🔴 **Weak** — Less than 8 characters
   - 🟠 **Fair** — 8+ characters
   - 🟡 **Good** — 12+ characters with mixed case
   - 🟢 **Strong** — 12+ characters with uppercase, lowercase, numbers, and special characters

4. Use the **👁️** button next to the password field to toggle password visibility

5. Click **🚀 Deploy User**

**What happens behind the scenes:**
1. The server validates all inputs (password length, duplicate check)
2. Sends a JWT-authenticated POST request to the agent on the target machine
3. The agent runs the OS-appropriate command:
   - **Linux:** `useradd -m -s /bin/bash <username>` then sets password via `chpasswd`
   - **Windows:** Creates user via `New-LocalUser` PowerShell cmdlet
4. On success: A `ManagedUser` record, audit log entry, and system alert are created
5. On failure: An error message from the agent is displayed

### 7.2 Removing a User

Removing a user deletes the OS-level account from the target machine.

1. In the **Remove User** section (right column):
   - Select the **Target Machine** (all machines shown, including inactive)
   - Enter the **Username** to remove
2. Click **⛔ Remove User**
3. Confirm the removal in the pop-up dialog

**What happens behind the scenes:**
1. The server sends a JWT-authenticated POST to the agent
2. The agent runs:
   - **Linux:** `userdel -r <username>` (removes home directory)
   - **Windows:** `Remove-LocalUser` PowerShell cmdlet
3. The `ManagedUser` record is deleted from the dashboard database
4. An audit log entry (`USER_REMOVED`) and alert are created

### Deployed Users Reference

Below the forms, a table shows the most recently deployed users (up to 10) with username, target machine, and role for quick reference.

---

## 8. User Directory

**URL:** `http://127.0.0.1:5000/users`

The User Directory provides a centralized view of all managed user accounts across all machines.

### 8.1 Viewing All Users

The page displays:

**Stat Cards:**
| Card | Description |
|---|---|
| Total Users | All managed user accounts |
| Active | Users with `active` status |
| Disabled | Users with `disabled` status |
| Locked | Users with `locked` status |

**User Table Columns:**
| Column | Description |
|---|---|
| Avatar | Colored initial circle based on username |
| Username | Displayed in monospace font |
| Full Name | Display name |
| Email | Email address |
| Role | Color-coded role badge |
| Machine | Hostname and IP of the target machine |
| Status | Active (green), Disabled (yellow), or Locked (red) |
| Created | Account creation date |
| Actions | Edit and Toggle buttons |

Use the **🔍 Filter** input above the table to search/filter users by any column.

### 8.2 Editing a User

1. Click the **✏️ Edit** button next to any user
2. A modal dialog opens with editable fields:
   - **Full Name** — Update the display name
   - **Email** — Update the email address
   - **Role** — Reassign to a different role
3. Click **💾 Save Changes**

> **Note:** The username and target machine cannot be changed after deployment. To move a user, remove them from the old machine and deploy on the new one.

### 8.3 Toggling User Status

- Click the **⏸ Disable** or **▶ Enable** button to toggle a user's dashboard status
- This cycles between: `active` → `disabled` → `active`
- This only updates the status in the Aegis-IAM database — it does **not** disable the OS-level account on the remote machine

---

## 9. Role Management

**URL:** `http://127.0.0.1:5000/roles`

Roles help organize managed users into logical groups. Each role has a color tag for easy visual identification.

### Default Roles

Aegis-IAM ships with five pre-configured roles:

| Role | Color | Description |
|---|---|---|
| `admin` | 🔴 Red | Full administrative privileges |
| `developer` | 🟣 Purple | Development access |
| `viewer` | 🔵 Cyan | Read-only access |
| `auditor` | 🟡 Yellow | Audit and compliance access |
| `operator` | 🟢 Green | Operational access to machines |

### 9.1 Creating a Role

1. Navigate to **Roles** from the sidebar
2. Fill in the **Create New Role** form:

   | Field | Required | Description |
   |---|---|---|
   | **Role Name** | ✓ | Lowercase identifier (letters, numbers, hyphens) |
   | **Description** | — | Brief description of the role's purpose |
   | **Color** | ✓ | Click one of 8 color options: cyan, green, purple, yellow, red, blue, orange, pink |

3. Click **⊕ Create Role**

### 9.2 Editing a Role

1. Click the **✏️ Edit** button on a role card
2. A modal opens to update:
   - **Description** — Modify the role description
   - **Color** — Change the color tag
3. Click **💾 Save**

> **Note:** The role name cannot be changed after creation.

### 9.3 Deleting a Role

1. Click the **🗑️ Delete** button on a role card
2. Confirm the deletion

> ⚠️ **Restriction:** A role cannot be deleted if it has users assigned to it. Reassign or remove users first.

### Role Card Information

Each role card displays:
- Role name with colored badge
- Description
- Number of assigned users
- Creation date
- List of assigned usernames (up to 5, with overflow indicator)

---

## 10. Audit Logs

**URL:** `http://127.0.0.1:5000/audit`

The audit log provides a complete history of all IAM operations for compliance and troubleshooting.

### 10.1 Viewing Logs

The audit page shows:

**Stat Cards:**
- Total Events — Number of log entries
- Page Info — Current page and total pages

**Log Table Columns:**
| Column | Description |
|---|---|
| Timestamp | When the event occurred |
| Machine | Which machine was involved |
| Event Type | Category badge (e.g., USER_CREATED, MACHINE_REGISTERED) |
| Severity | info (blue), warning (yellow), or critical (red) |
| Actor | Who performed the action (e.g., "admin", "agent", "system") |
| Details | Description of the event (truncated to 120 chars, full text on hover) |

Logs are **paginated** at 25 entries per page. Use the **Previous / Next** controls at the bottom to navigate.

### Automatic Event Types

| Event Type | When Generated |
|---|---|
| `MACHINE_REGISTERED` | A new machine is registered |
| `USER_CREATED` | A user is deployed to a machine |
| `USER_REMOVED` | A user is removed from a machine |
| `REMOTE_AUTH` | Auth logs fetched from a remote agent |

### 10.2 Fetching Remote Logs

To pull authentication logs from a remote machine's operating system:

1. In the **Fetch Remote Logs** section, find the target machine
2. Click the **📥 Fetch** button next to it
3. The system retrieves:
   - **Linux:** Last 50 lines from `/var/log/auth.log` (fallback: `journalctl -u ssh`)
   - **Windows:** Last 50 Security Event Log entries for Event ID  4624 (successful logons)
4. These are imported as `REMOTE_AUTH` events in the audit log

### 10.3 Filtering Logs

Use the filter bar above the log table:

| Filter | Options |
|---|---|
| **Severity** | All, Info, Warning, Critical |
| **Event Type** | Dynamic list of all event types in the database |

Click **Apply Filters** to filter, or **Clear** to reset.

Additionally, use the **🔍 text filter** input above the table for instant client-side filtering by any column text.

### 10.4 Exporting Logs

1. Click the **📥 Export CSV** button in the page header
2. A CSV file (`aegis_audit_logs.csv`) downloads with columns:
   - ID, Timestamp, Machine, Event Type, Severity, Actor, Details

### 10.5 Clearing Logs

1. Click the **🗑️ Clear All** button in the page header
2. Confirm the action in the pop-up dialog
3. **All** audit log entries are permanently deleted

> ⚠️ **Warning:** This action is irreversible. Consider exporting logs before clearing.

---

## 11. Session Viewer

**URL:** `http://127.0.0.1:5000/sessions/<machine_id>`

The Session Viewer shows currently active login sessions on a specific machine.

### Accessing Sessions

1. On the **Machines** page, click the **🔗 Sessions** button next to any machine
2. The system queries the agent in real time for active sessions

### Session Information

**Linux sessions** (from `who` command):
| Column | Description |
|---|---|
| User | Username with avatar initial |
| Terminal | Terminal device (e.g., `pts/0`, `tty1`) |
| Login Time | When the session started |

**Windows sessions** (from `query user`):
| Column | Description |
|---|---|
| User | Username with avatar initial |
| Session | Session name/ID |
| State | Active or Disconnected |
| Login Time | When the session started |

### Page Header

- **Machine info cards** showing hostname, session count, and operating system
- **← Back to Machines** button to return to the machines list
- **🔄 Refresh** button to re-query the agent

If the agent is unreachable, an error message is displayed with a **Retry** button.

---

## 12. Security Policies

**URL:** `http://127.0.0.1:5000/policies`

Security policies allow you to define rules for password requirements, access control, and session management.

### Default Policies

Three policies are pre-seeded on first run:

| Policy | Type | Rules |
|---|---|---|
| **Password Strength** | Password | min_length: 8, require_uppercase: true, require_digit: true, require_special: true |
| **Session Timeout** | Session | timeout_minutes: 30, max_sessions: 3 |
| **Access Control** | Access | default_deny: true, require_mfa: false |

### 12.1 Creating a Policy

1. Navigate to **Policies** from the sidebar
2. Fill in the **Create New Policy** form:

   | Field | Required | Description |
   |---|---|---|
   | **Policy Name** | ✓ | Descriptive name (e.g., "MFA Requirement") |
   | **Policy Type** | ✓ | 🔒 Password Policy, 🚪 Access Control, or ⏱️ Session Policy |
   | **Description** | — | Brief explanation of the policy |
   | **Rules (JSON)** | — | JSON object defining the policy rules |

3. Click **⊕ Create Policy**

**Example Rules JSON:**

Password Policy:
```json
{
    "min_length": 12,
    "require_uppercase": true,
    "require_digit": true,
    "require_special": true,
    "max_age_days": 90
}
```

Session Policy:
```json
{
    "timeout_minutes": 15,
    "max_sessions": 2,
    "require_reauthentication": true
}
```

Access Control Policy:
```json
{
    "default_deny": true,
    "require_mfa": true,
    "allowed_ips": ["192.168.1.0/24"],
    "time_restriction": "09:00-18:00"
}
```

> **Note:** The rules field must contain valid JSON. Invalid JSON will be rejected with an error message.

### 12.2 Activating / Deactivating Policies

Each policy card has a toggle button:
- **⏸ Deactivate** — Disables an active policy (card fades to 60% opacity)
- **▶ Activate** — Re-enables an inactive policy

### 12.3 Deleting a Policy

1. Click **🗑️ Delete** on the policy card
2. Confirm the deletion

### Policy Card Display

Each policy card shows:
- Policy type icon (🔒, 🚪, or ⏱️) and name
- Active/Inactive badge
- Description
- Type badge
- Creation date
- Rules displayed in formatted monospace JSON

---

## 13. Settings & System Configuration

**URL:** `http://127.0.0.1:5000/settings`

The Settings page displays read-only system configuration and provides maintenance actions.

### System Overview

Four summary cards showing total machines, managed users, roles, and active policies.

### Authentication Configuration

| Setting | Value | Description |
|---|---|---|
| JWT_SECRET_KEY | •••••••••••• (masked) | Shared secret for token signing |
| JWT_ALGORITHM | HS256 | Algorithm used for JWT encoding |
| TOKEN_EXPIRY | 30 minutes | Token time-to-live |

### Server Configuration

| Setting | Value | Description |
|---|---|---|
| SERVER_PORT | 5000 | Dashboard web server port |
| AGENT_PORT | 5001 | Default port for remote agents |
| DATABASE | aegis_iam.db | SQLite database file |
| FLASK_ENV | Debug Mode | Application environment |

### Agent Deployment Guide

Step-by-step commands for deploying agents on Linux and Windows, with a security reminder about JWT key matching.

### Maintenance Actions

| Action | Description |
|---|---|
| **🗑️ Clear Audit Logs** | Delete all audit log entries (with confirmation) |
| **📥 Export Audit CSV** | Download all logs as a CSV file |
| **🔍 Health Check All** | Ping every registered machine and update statuses |

---

## 14. Global Search

The top bar contains a **global search** bar available on every page.

### How to Use

1. Click the search input in the top bar (or start typing)
2. Enter at least **2 characters** of your search query
3. Results appear in a dropdown below the search bar in real time (debounced at 300ms)

### What is Searched

| Category | Fields Searched |
|---|---|
| 🖥️ Machines | Hostname, IP address |
| 👤 Users | Username, full name |
| 🏷️ Roles | Role name |

Results show a type icon, title, subtitle detail, and link directly to the relevant page. Up to **15 results** are shown.

---

## 15. Alerts & Notifications

The notification bell (🔔) in the top bar shows the count of unread alerts.

### Automatic Alert Generation

Alerts are created automatically when:
- A new machine is registered
- A user is deployed or removed
- System events occur

### Alert Properties

| Property | Description |
|---|---|
| Title | Brief event description |
| Message | Detailed information |
| Severity | info, warning, or critical |
| Source | Origin (machines, deploy, system) |
| Timestamp | When the alert was created |

Alerts appear on the dashboard in the **Recent Alerts** section and are accessible via the notification bell.

---

## 16. Security & Authentication

### JWT Authentication

All communication between the dashboard server and remote agents is secured with **JSON Web Tokens (JWT)**:

| Property | Value |
|---|---|
| **Algorithm** | HS256 (HMAC-SHA256) |
| **Token Lifetime** | 30 minutes |
| **Header Format** | `Authorization: Bearer <token>` |
| **Token Claims** | `iss` (issuer), `iat` (issued at), `exp` (expiration) |

### Changing the Secret Key

The default secret key is set in `shared/config.py`. **For production use**, override it with an environment variable:

```bash
# Linux / macOS
export AEGIS_SECRET_KEY="your-secure-random-key-here"

# Windows PowerShell
$env:AEGIS_SECRET_KEY = "your-secure-random-key-here"
```

> ⚠️ **Critical:** The key must be identical on the dashboard server and every agent. If they differ, all agent communication will fail with 401 Unauthorized errors.

### Password Requirements

When deploying users, the dashboard enforces:
- Minimum **8 characters** (server-validated)
- The password strength meter recommends 12+ characters with mixed case, numbers, and special characters

### Agent Endpoint Protection

| Endpoint | Auth Required |
|---|---|
| `/health` | ❌ No — allows unauthenticated health checks |
| `/create_user` | ✅ Yes — JWT required |
| `/delete_user` | ✅ Yes — JWT required |
| `/sessions` | ✅ Yes — JWT required |
| `/audit_logs` | ✅ Yes — JWT required |

---

## 17. Agent API Reference

The agent exposes a REST API on port 5001. All authenticated endpoints require a valid JWT `Authorization: Bearer <token>` header.

### GET `/health`

**Auth:** None required

Returns agent status and detected operating system.

```json
{
    "status": "success",
    "message": "Agent is running.",
    "data": { "os": "Linux" }
}
```

### POST `/create_user`

**Auth:** JWT required

Creates an OS-level user account.

**Request:**
```json
{
    "username": "jdoe",
    "password": "SecureP@ss123"
}
```

**Success Response:**
```json
{
    "status": "success",
    "message": "User 'jdoe' created successfully."
}
```

**OS Commands Used:**
- Linux: `useradd -m -s /bin/bash jdoe` + `echo "jdoe:password" | chpasswd`
- Windows: `New-LocalUser -Name jdoe -Password (ConvertTo-SecureString ...)`

### POST `/delete_user`

**Auth:** JWT required

Deletes an OS-level user account and their home directory.

**Request:**
```json
{
    "username": "jdoe"
}
```

**OS Commands Used:**
- Linux: `userdel -r jdoe`
- Windows: `Remove-LocalUser -Name jdoe -Confirm:$false`

### GET `/sessions`

**Auth:** JWT required

Lists currently active login sessions on the machine.

**Response (Linux):**
```json
{
    "status": "success",
    "data": {
        "sessions": [
            { "user": "admin", "terminal": "pts/0", "login_time": "2026-02-23 10:00" }
        ]
    }
}
```

**OS Commands Used:**
- Linux: `who` command
- Windows: `query user` command

### GET `/audit_logs`

**Auth:** JWT required

Fetches recent authentication logs from the OS.

**Sources:**
- Linux: Last 50 lines of `/var/log/auth.log` (fallback: `journalctl -u ssh`)
- Windows: Last 50 Security Event Log entries for Event ID 4624 (successful logons)

---

## 18. Troubleshooting

### Common Issues

#### "Cannot reach agent at X.X.X.X:5001"

**Cause:** The agent is not running, or a firewall is blocking port 5001.

**Solutions:**
1. Verify the agent is running on the target machine
2. Check firewall rules allow TCP port 5001
3. Ensure the IP address is correct and reachable from the server
4. Test connectivity manually: `curl http://<ip>:5001/health`

#### Agent returns 401 Unauthorized

**Cause:** JWT secret key mismatch between server and agent.

**Solution:** Ensure `shared/config.py` has the same `SECRET_KEY` value on both the server and agent machines.

#### "User already exists" error

**Cause:** A user with that username is already registered on the selected machine in the Aegis-IAM database.

**Solutions:**
1. If the user exists in the dashboard but not on the OS, remove the record first
2. Use a different username
3. Select a different target machine

#### Password rejected (< 8 characters)

**Cause:** Server-side validation requires passwords to be at least 8 characters.

**Solution:** Use a longer password. The strength meter recommends 12+ characters with mixed case, numbers, and special characters.

#### Database errors after update

**Cause:** Schema changes between versions.

**Solution:** Delete the old database file and restart the server:
```bash
# Delete the old database
rm server/aegis_iam.db        # Linux/macOS
del server\aegis_iam.db       # Windows

# Restart — database is recreated automatically
python server/app.py
```

#### Browser shows broken layout

**Cause:** Outdated browser or cached CSS.

**Solutions:**
1. Hard refresh: `Ctrl + Shift + R` (Windows) or `Cmd + Shift + R` (macOS)
2. Use a modern browser (Chrome, Firefox, or Edge)

#### Sessions page shows empty even though users are logged in

**Cause:** Agent uses `who` (Linux) or `query user` (Windows), which only shows interactive/console sessions.

**Solution:** SSH or RDP sessions should appear. Background service accounts typically don't show up.

---

## 19. FAQ

**Q: Does Aegis-IAM require internet access?**
A: No. The dashboard and agents communicate over your local network. The only external resources are CDN links for Chart.js and Google Fonts in the browser (the dashboard still functions without them, just without chart rendering and custom fonts).

**Q: Can I manage users on machines without an agent?**
A: No. An agent must be running on each target machine to execute OS-level commands.

**Q: Does the dashboard require login/authentication?**
A: The current version does not include dashboard login. It is designed for use within a trusted network. The JWT authentication secures server-to-agent communication.

**Q: Can I change the server or agent port?**
A: Yes. Modify `AGENT_PORT` in `shared/config.py` for the agent port. For the server port, change the `app.run(port=...)` call in `server/app.py`.

**Q: Are user passwords stored in the dashboard database?**
A: No. Passwords are sent to the agent for OS-level account creation and are never stored in the Aegis-IAM database.

**Q: What happens if I delete a machine from the dashboard?**
A: The machine record, its associated audit logs, and managed user records are removed from the dashboard database. The actual OS-level user accounts on the remote machine are **not** affected.

**Q: Can multiple administrators use the dashboard simultaneously?**
A: Yes. The Flask server handles concurrent requests. However, there is no multi-user access control for the dashboard itself in the current version.

**Q: How do I back up the system?**
A: Copy the `server/aegis_iam.db` file. This SQLite file contains all machines, users, roles, audit logs, policies, and alerts.

**Q: Does toggling a user's status in the User Directory disable their OS account?**
A: No. The status toggle only affects the dashboard record. To disable an OS-level account, you would need to do so directly on the target machine.

---

*Aegis-IAM v2.0 — User Manual*
*Last updated: February 2026*
