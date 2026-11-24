# Riskbyte SOC Platform — Presentation & Operation Guide

**Author:** Muhammad Nabil (F23CSC009)  
**Course:** Essentials of Cybersecurity  
**Date:** November 2026  
**Disclaimer:** *All scenarios and organizational profiles described here are educational simulations using reserved documentation IP ranges and invented accounts. Not affiliated with Meezan Bank, Salim Habib University, or Contour Software. No real data is used.*

---

## 1. What Riskbyte Is (In One Paragraph)

Riskbyte is a lightweight Security Operations Center (SOC) platform designed to ingest security logs, automatically detect cyber threats using community-standard Sigma rules, triage attacks with an AI-assisted investigation engine, propose containment actions with a mandatory human approval gate, and record every single action into an immutable, cryptographically chained SHA-256 audit ledger. Instead of overwhelming security analysts with thousands of raw logs, Riskbyte groups correlated events by host or user into incident cases and ensures no defensive action (such as quarantining a computer or blocking an IP address) can be taken without human verification and non-repudiable audit trails.

---

## 2. How to Start Riskbyte Step-by-Step on Windows

You can run Riskbyte in **Live Backend Mode** (recommended) or in **Offline In-Browser Simulation Mode** (no terminal needed).

### Method A: Live Backend Mode (Python Server)

1. **Open PowerShell or Command Prompt** on Windows.
2. **Navigate to the project root:**
   ```powershell
   cd c:\Users\nabil\Downloads\riskbyte-agent\riskbyte
   ```
3. **Verify Python 3.10+ is installed:**
   ```powershell
   python --version
   ```
4. **Start the Riskbyte service on port 8080:**
   ```powershell
   python -m riskbyte.main
   ```
   *You will see:*
   ```text
   INFO:riskbyte:Riskbyte starting on http://127.0.0.1:8080 (dev mode)
   INFO:riskbyte:Syslog UDP listener on 0.0.0.0:5514
   ```
5. **Open your web browser** and navigate to:
   ```text
   http://localhost:8080
   ```
6. **Log in:** Click **Security Analyst Dashboard** (or Administrator or Telemetry Ingest) on the liquid-glass auth card.

### Method B: In-Browser Standalone Simulation Mode (No Terminal Required)

If you are presenting on a computer without Python or port permissions:
1. Open `riskbyte/ui/index.html` (or `public/index.html`) directly in Google Chrome, Microsoft Edge, or Safari.
2. If prompted about server connection, click **"Switch to In-Browser Sim"** on the login screen or click the top-right toggle pill.
3. Everything works locally in your browser using an in-memory simulation engine.

---

## 3. Walkthrough of Every Page, Tab, and Button

### Top Navigation & Global Controls
- **Dynamic Island Pill (Top Center):** Shows the current system status (e.g., `Riskbyte • Live SOC Engine` or `Riskbyte • Switched to Admin`). Pulses red if a critical alert fires.
- **Role Badge (Top Right):** Displays your current active identity (e.g., `Analyst`, `Admin`, `Ingest`). Click it anytime to switch roles on the fly without signing out.
- **Server Toggle Pill (Top Right):** Toggles between **Live Backend (Port 8080)** and **In-Browser Sim**.
- **Sign Out Button (Top Right Icon):** Clears the session token and returns to the initial role selection screen.

---

### Tab 1: "Alerts" (Security Analyst View)
- **Left Column (Alerts Explorer):** Shows all detected security alerts sorted by timestamp.
  - Each card shows: Severity badge (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), Alert Title, Client Organization badge (e.g., `Meezan Bank`), Target Entity (host, user, or IP), and Alert Status (`triaged`, `executed`, `dismissed`).
  - **What to click:** Click any alert card to load its details into the right-hand Inspector.
- **Right Column (Alert Inspector & AI Triage View):**
  - **Hero Header:** Displays the rule ID (e.g., `rb-006`), client badge, severity, title, status, timestamp, and linked Case ID.
  - **Metadata Grid:** Host, User, and Source IP addresses.
  - **AI Triage Glass Card:**
    - Model engine used (`heuristic` or `gemini-1.5-flash`).
    - Verdict pill (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`).
    - Confidence percentage (e.g., `96%`).
    - Plain-English investigation summary.
    - Numbered investigation reasoning steps.
  - **Containment Response Card:**
    - Displays proposed automated mitigation (e.g., `isolate_host fin-lt-042` or `reset_password customer.tariq`).
    - **"Approve & Execute" Button:** Green tactile button. Clicking this authorizes the defensive mitigation.
    - **"Dismiss Alert" Button:** Gray tactile button. Closes the alert without executing containment.
  - **Correlated Telemetry Records Table:** Lists the exact raw logs that triggered this alert (timestamp, process name, action, and full command line).

---

### Tab 2: "Cases" (Entity Grouping)
- **What it does:** Displays grouped security incidents. In a real enterprise SOC, an adversary often triggers 5 or 10 alerts on the same laptop. Rather than investigating 10 separate alerts, Riskbyte groups them by host or user into a single Case.
- **Table Columns:** `Case ID`, `Client Organization`, `Target Entity`, `Severity`, `Status`, `Opened Time`.
- **What to click:** View open cases to understand which host or user is under active compromise.

---

### Tab 3: "Demo" (Interactive Attack Simulation Lab)
- **Client Organization Selector (Top Dropdown):**
  - Options:
    1. `Meezan Bank (Islamic Commercial Bank)`
    2. `Salim Habib University (Higher Education)`
    3. `Contour Software (Constellation Software)`
  - **What to click:** Select any of the three clients. Notice that the organization profile card and scenario cards instantly update.
- **Client Profile Card:**
  - Displays three columns: **What They Do**, **Digital Platforms & Assets**, and **Main Threat Surface & Risks**.
  - Displays the mandatory simulation disclaimer.
- **Scenario Cards Grid (4 per Client):**
  - Displays the attack title, severity, plain-English summary, and rule badge.
  - **"Run Attack" Button:** Blue button on each card.
  - **What to click:** Click **"Run Attack"** on any card.
- **Live 7-Step Execution Panel (Appears Below Grid):**
  - Automatically scrolls into view and executes real events through the backend pipeline:
    1. **Step 1: Attack Launched** — What the adversary did.
    2. **Step 2: Event Received & Normalized** — Shows accepted events, host, process, and time.
    3. **Step 3: Detection Rule Triggered** — Shows matched Sigma rule, rule ID, severity, and client.
    4. **Step 4: Threat Intelligence Cross-Reference** — Shows matched indicators from `intel/indicators.txt`.
    5. **Step 5: Autonomous AI Triage & Reasoning** — Shows AI model, verdict, confidence %, and reasoning summary.
    6. **Step 6: Proposed Containment & Approval Gate** — Shows proposed response with an **"Approve & Execute Action"** button.
    7. **Step 7: Cryptographic Audit Trail Record** — Appears immediately after clicking Approve, displaying the SHA-256 block hash, previous hash, actor, and client organization.
  - **Under EVERY step:** Displays:
    - `What this means:` (one plain-English sentence).
    - `Why this matters for <Client Name>:` (one sentence on business/operational risk).
  - **"What Happened?" Summary Box:** Blue card at the bottom explaining the entire incident in simple language.
- **"Reset Demo Data" Button:** Clears simulated demo alerts, cases, and logs, returning the SOC to a clean state.

---

### Tab 4: "Admin Overview" (SOC Administrator View)
- **Governance Metric Cards:**
  - `Total Telemetry Ingested`: Cumulative log count.
  - `Active Incidents`: Number of open cases.
  - `Triage AI Provider`: Model engine (`GEMINI`, `HEURISTIC`).
  - `Audit Forensic Ledger`: Displays `Intact ✓` (green) if the cryptographic hash chain is verified.
- **Active Sigma Detection Rules Table:** Lists all 10 registered detection rules, their MITRE ATT&CK technique IDs, severities, and mapped containment actions.

---

### Tab 5: "Audit Trail" (Cryptographic Ledger)
- **Table Columns:** `Timestamp`, `Client Organization`, `Actor / Role`, `Audit Event`, `Target Alert`, `Operation Detail`.
- **Top Badge:** Displays `Hash Chain: Intact (SHA-256)`. Every row is linked to the previous row's SHA-256 hash (like a private mini-blockchain). If any row in SQLite is modified or deleted, this badge immediately changes to red `Hash Chain: TAMPERED`.

---

### Tab 6: "License & Health"
- Displays cryptographic license status (RSA-2048 signed license), tier (Enterprise / Development), expiration days remaining, and licensed host quotas.

---

### Tab 7: "Telemetry Ingest" (Pipeline Monitor & Stream)
- **Ingest Health Cards:** Displays UDP Syslog port status (`5514`), REST ingest route (`POST /api/ingest`), and total processed logs.
- **Live Telemetry Stream Sub-Tab:** Displays raw normalized event logs with columns for `ID`, `Timestamp`, `Client`, `Source`, `Host`, `User`, `Process`, `Action`, `IP Address`, and `Message / Command`.
- **Direct Event Dispatcher Sub-Tab:** JSON console allowing manual transmission of custom telemetry batches. Includes three presets: `Syslog Authentication`, `Encoded PowerShell`, and `Phishing Link Click`.

---

## 4. The Three Roles (Checked in Code, Not Assumed)

In `riskbyte/api.py` (lines 16–150) and `riskbyte/config.py`, authentication is verified using constant-time `hmac.compare_digest` against Bearer tokens. Here is the strict enforcement in the code:

| Role | Development Token | Permissions Enforced in Code | Prohibited / Blocked in Code |
| :--- | :--- | :--- | :--- |
| **Telemetry Ingest** | `dev-ingest` | Allowed to call `POST /api/ingest` (submitting telemetry logs up to 1,000 events per request). In dev mode with the web console header, it can read the raw event stream. | **HTTP 403 Forbidden** on containment approval (`POST /api/alerts/<id>/approve`), alert dismissal (`POST /api/alerts/<id>/dismiss`), and administrative license modifications. Ingest accounts cannot make operational SOC decisions. |
| **Security Analyst** | `dev-analyst` | Full operational access to investigate: `GET /api/alerts`, `GET /api/alerts/<id>`, `GET /api/cases`, `GET /api/audit`, `GET /api/events`, `POST /api/ingest`. Allowed to approve containment (`POST /api/alerts/<id>/approve`) and dismiss alerts (`POST /api/alerts/<id>/dismiss`). All approvals record `analyst:<user>` in the audit trail. | Cannot modify license configuration or tamper with audit verification keys. |
| **SOC Administrator** | `dev-admin` | Super-user access. Can execute all analyst functions plus audit integrity verification (`Store.verify_audit()`), platform statistics, license inspection, and system resets. Approvals log `admin:<user>` in the audit trail. | Subject to the same SHA-256 hash chaining rules; an administrator cannot alter existing audit records without breaking the hash chain. |

---

## 5. The Three Clients and All 12 Demo Scenarios

### Client 1: Meezan Bank
*Category:* Islamic Commercial Bank (Pakistan, Est. 2002)  
*Platforms:* Mobile Banking App, Digital Account Opening, Internet Banking, WhatsApp Banking, SMS Gateway, ATMs, Raast Instant Settlement.  
*Core Risks:* Fake SMS/WhatsApp phishing, customer Account Takeover (ATO), Raast payment fraud, insider misuse, web banking brute force.

#### Scenario 1.1: Fake Bank Login Phishing (`meezan_phish`)
- **The Attack:** Adversary distributed spoofed SMS alerts impersonating Meezan Bank, luring customer `customer.tariq` to blacklisted domain `meezan-fake-login.com`, harvesting credentials from proxy IP `203.0.113.88`.
- **What Riskbyte Does:** Ingests the email/SMS proxy click and authentication logs, triggers rule `rb-006` (High), matches `meezan-fake-login.com` in threat intel, AI assigns 96% confidence malicious verdict, proposes `reset_password`, and logs the approved action into the audit ledger.
- **What to Say While Presenting:**  
  *"Here, an attacker targets Meezan Bank customers with fake SMS alerts. Riskbyte correlates the gateway link click with an external login from an untrusted proxy, flags the known phishing domain, and prompts the analyst to immediately reset the customer's credentials to prevent money theft."*

#### Scenario 1.2: Suspicious Overseas Staff Login (`meezan_anomalous_login`)
- **The Attack:** Stolen credentials for staff member `staff.farooq` were used to access the internal core banking VPN from foreign IP `198.51.100.99`.
- **What Riskbyte Does:** Ingests VPN authentication log, detects geographic anomaly deviating from staff baseline, triggers rule `rb-008` (High), correlates IP with threat feed, AI verifies lack of travel authorization, proposes `disable_user`, and records approval in the audit ledger.
- **What to Say While Presenting:**  
  *"Staff credentials for core banking should never connect from untrusted foreign IP addresses. Riskbyte catches this geo-anomaly immediately, and the AI agent recommends disabling the user account before the attacker can access internal banking databases."*

#### Scenario 1.3: Internet Banking Brute Force (`meezan_brute`)
- **The Attack:** Automated botnet launched repeated credential guessing attempts against the Meezan internet banking portal from IP `1.2.3.4`.
- **What Riskbyte Does:** Captures 6 failed login attempts in 30 seconds, sliding-window threshold rule `rb-001` (Medium) fires at 5 failures, threat intel identifies scanner IP, AI validates botnet behavior, and proposes `block_ip` at the perimeter firewall.
- **What to Say While Presenting:**  
  *"Automated credential stuffing exhausts web servers and endangers customer accounts. Riskbyte aggregates failed logins across web frontends and automatically proposes a firewall drop rule to block the attacker at the perimeter."*

#### Scenario 1.4: Raast Payment Settlement Anomaly (`meezan_transfer`)
- **The Attack:** Off-hours batch fund transfer ($500,000 equivalent) was dispatched through the Raast payment gateway to external recipient IP `198.51.100.44`.
- **What Riskbyte Does:** Ingests transaction settlement telemetry, triggers rule `rb-010` (Critical), matches destination against high-risk financial nodes, AI validates extreme off-hours volume deviation, proposes `disable_user` and holds the transfer batch.
- **What to Say While Presenting:**  
  *"Raast instant payments settle immediately, so fraudulent transactions cannot be reversed once cleared. Riskbyte's financial anomaly rule detects the unusual off-hours transfer and alerts the analyst to freeze the transaction before clearance."*

---

### Client 2: Salim Habib University (SHU)
*Category:* Higher Education Institution (Korangi Creek, Karachi)  
*Platforms:* Online Admissions Portal (`shu.edu.pk`), Student LMS, Campus Active Directory, Computer Labs, Faculty Research Systems.  
*Core Risks:* Phishing student/faculty accounts, admissions portal brute force, ransomware on lab computers, applicant document data theft.

#### Scenario 2.1: Admissions & Faculty Phishing (`shu_phish`)
- **The Attack:** Phishing email masquerading as SHU Academic Registrar luring faculty member `faculty.ahmed` to blacklisted domain `shu-admissions-phish.com`.
- **What Riskbyte Does:** Ingests link click and subsequent login event, triggers rule `rb-006` (High), confirms domain in threat intel, AI assigns 95% confidence malicious verdict, proposes `reset_password`.
- **What to Say While Presenting:**  
  *"University faculty accounts are prime targets because they hold exam papers and student grades. Riskbyte intercepts the phishing click, matches the fake domain, and enables immediate password revocation."*

#### Scenario 2.2: Admissions Portal Brute Force (`shu_brute`)
- **The Attack:** Automated script attempting password spraying against the SHU online admissions administrative server from IP `1.2.3.4`.
- **What Riskbyte Does:** Ingests failed administrative logins, triggers rule `rb-001` (Medium), AI classifies scanner traffic, proposes `block_ip`.
- **What to Say While Presenting:**  
  *"During admission season, universities face heavy automated scans trying to access applicant databases. Riskbyte flags the dictionary attack and blocks the scanner IP at the campus boundary."*

#### Scenario 2.3: Lab PC Ransomware & Shadow Deletion (`shu_ransomware`)
- **The Attack:** Trojanized software download on student lab machine `lab-pc-18` executes `vssadmin delete shadows /all /quiet` and starts bulk file encryption.
- **What Riskbyte Does:** Ingests shadow deletion and mass file renaming process logs, triggers Critical rule `rb-007`, correlates C2 domain `ransomware-c2.net`, AI assigns 98% confidence Critical verdict, proposes `isolate_host`.
- **What to Say While Presenting:**  
  *"Student lab computers are vulnerable to malware. When ransomware deletes Windows shadow backups and starts encrypting files, Riskbyte triggers a Critical alert and isolates the computer from the network to stop it from infecting other campus PCs."*

#### Scenario 2.4: Applicant Document Data Exfiltration (`shu_data_export`)
- **The Attack:** Unauthorized curl utility used to upload compressed applicant archives (`applicants_2026.zip`) from admissions server to external IP `198.51.100.44`.
- **What Riskbyte Does:** Ingests command-line network exfiltration telemetry, triggers rule `rb-009` (High), correlates staging IP, AI identifies unauthorized data export, proposes `isolate_host`.
- **What to Say While Presenting:**  
  *"Admissions servers store applicant CNIC copies and personal records. Riskbyte detects bulk outbound data transfers to untrusted external IPs and prompts the analyst to sever the server's connection immediately."*

---

### Client 3: Contour Software
*Category:* Enterprise Software Resource Center (Constellation Software subsidiary, offices in Karachi, Lahore, Islamabad)  
*Platforms:* Developer Workstations, CI/CD Jenkins & GitLab Runners, Source Code Repositories, Corporate VPN Gateways, Global Payroll Engines.  
*Core Risks:* Stolen developer credentials, source code theft, malware on laptops, software supply-chain attacks, VPN abuse.

#### Scenario 3.1: Encoded PowerShell on Dev Laptop (`contour_malware`)
- **The Attack:** Adversary executed hidden, Base64-encoded PowerShell command on developer laptop `dev-ws-042` communicating with C2 IP `198.51.100.99`.
- **What Riskbyte Does:** Ingests process execution with `-enc` flags, triggers rule `rb-002` (High), matches C2 IP in threat intel, AI triage confirms memory injection stager, proposes `isolate_host`.
- **What to Say While Presenting:**  
  *"Attackers use encoded PowerShell to hide in memory on developer machines. Riskbyte decodes and flags the evasion technique, checks the C2 address, and isolates the laptop so proprietary source code cannot be touched."*

#### Scenario 3.2: SSH Brute Force on CI Build Server (`contour_ssh_brute`)
- **The Attack:** Automated botnet attempting SSH password guessing against continuous integration build server `ci-build-01` from IP `1.2.3.4`.
- **What Riskbyte Does:** Detects 6 rapid failed logins targeting service account `jenkins_svc`, triggers rule `rb-001` (Medium), threat intel verifies scanner, proposes `block_ip`.
- **What to Say While Presenting:**  
  *"If an attacker breaches a CI/CD build server, they can insert backdoors into customer software releases. Riskbyte detects the brute-force sweep against the Jenkins account and locks the scanner out."*

#### Scenario 3.3: Suspicious Foreign VPN Login (`contour_vpn`)
- **The Attack:** Developer account `dev.bilal` authenticated to Contour corporate VPN from untrusted foreign IP `198.51.100.99`.
- **What Riskbyte Does:** Ingests VPN authentication log, triggers rule `rb-008` (High), checks threat intelligence, AI flags credential compromise, proposes `disable_user`.
- **What to Say While Presenting:**  
  *"With hundreds of remote developers, stolen VPN credentials are a top threat. Riskbyte correlates geographic location and untrusted IP ranges to quarantine the account before internal code servers are accessed."*

#### Scenario 3.4: Off-Hours Source Code Repository Clone (`contour_code_download`)
- **The Attack:** Mass git archive clone and export of proprietary software repositories (`enterprise-core.git`) piped to external host `198.51.100.44` during night hours.
- **What Riskbyte Does:** Ingests git server command-line export event, triggers rule `rb-009` (High), matches untrusted staging server, AI confirms off-hours data exfiltration, proposes `isolate_host`.
- **What to Say While Presenting:**  
  *"Source code is Contour's core intellectual property. When an off-hours script starts mass-exporting repositories to an external IP, Riskbyte detects the exfiltration pattern and isolates the staging server."*

---

## 6. What is Real vs. What is Simulated

| Feature | What is REAL in Riskbyte | What is SIMULATED / Mocked |
| :--- | :--- | :--- |
| **Ingestion Pipeline** | Real HTTP REST API (`POST /api/ingest`) and real UDP Syslog listener (RFC 3164) parsing raw logs into SQLite. | Simulated: The demo buttons generate sample security events (using documentation IP addresses) to feed into the real ingest pipeline. |
| **Detection Engine** | Real YAML Sigma rule engine (`detect.py`) evaluating conditions, sliding time windows, and threshold counts. | Simulated: None; rules are genuine Sigma detection signatures. |
| **Threat Intelligence** | Real indicator lookup cross-referencing IP addresses and domains against `intel/indicators.txt`. | Simulated: Indicators are documentation IPs (`198.51.100.x`, `203.0.113.x`, `1.2.3.4`). |
| **AI Triage Engine** | Real AI reasoning engine. If `GEMINI_API_KEY` is present in the environment, it makes real API calls to Gemini 1.5 Flash. If offline or no key, it runs an intelligent heuristic rule-based triage. Entity redaction (`[REDACTED_IP]`) is real. | Simulated: If no API key is provided, heuristics provide realistic structured reasoning. |
| **Audit Ledger** | Real cryptographic SHA-256 blockchain hash chaining in SQLite (`hash = SHA256(prev_hash + ts + actor + kind + detail)`). Real verification logic (`verify_audit()`). | Simulated: None; the mathematical hash chain is 100% genuine. |
| **Automated Containment** | Real HTTP approval API (`POST /api/alerts/<id>/approve`), state management, and audit recording. | Dry-Run Simulation: Actual network quarantine (`iptables` / Windows firewall drop) runs in dry-run mode (`dry-run: would execute action`) so running the demo does not disrupt your actual computer network. |

---

## 7. Known Problems, Errors (Including the 404), and Exact Fixes

### Problem 1: The "API route not found (404)" Error
- **Cause:** Previously, some front-end calls looked for routes that were either formatted differently in Vercel serverless rewrites (e.g. missing query path translation), or the backend returned a bare 404 without telling the user what failed.
- **How It Was Fixed in the Code:**
  1. All 12 front-end routes (`/healthz`, `/api/stats`, `/api/license`, `/api/alerts`, `/api/alerts/<id>`, `/api/alerts/<id>/approve`, `/api/alerts/<id>/dismiss`, `/api/cases`, `/api/audit`, `/api/events`, `/api/ingest`, `/api/demo/reset`) were explicitly mapped in `riskbyte/service.py` and `riskbyte/api.py`.
  2. Trailing slashes and query strings (`?__path=...`) are automatically stripped and normalized.
  3. When an unregistered route is requested, the backend returns a friendly JSON error listing the failed route, suggestion, and all 12 available routes.
  4. The frontend error handler displays the exact route and advice rather than a generic failure.
  5. An automated test (`test_all_frontend_routes_exist`) continuously verifies that every route returns a valid status.

### Problem 2: Port 8080 or UDP 5514 Already in Use
- **Error:** `OSError: [Errno 98] Address already in use` or Windows `WSAEADDRINUSE`.
- **Fix:** Another instance of Riskbyte is running in the background. In PowerShell, find and close it:
  ```powershell
  Get-Process -Name python | Stop-Process -Force
  ```
  Or change the port in `riskbyte/config.py` (e.g., set `port = 8081`).

### Problem 3: Vercel Serverless Read-Only Filesystem
- **Error:** `sqlite3.OperationalError: attempt to write a readonly database`.
- **Fix:** Vercel functions run in an ephemeral read-only environment. In `api/index.py`, SQLite databases are written to `/tmp/riskbyte.db`. For persistent cloud production, attach an external PostgreSQL database (e.g. Supabase or Neon).

---

## 8. "Not Working Yet / Be Honest" List

To maintain complete academic and engineering integrity, here is what is currently working vs. what is out of scope or planned for future versions:

1. **Host Isolation is Dry-Run Only:**  
   When you click "Approve" on `isolate_host`, Riskbyte executes the authorization logic and records the cryptographic audit hash, but it **does not** physically disconnect your laptop's Wi-Fi adapter or alter your Windows Defender firewall. This is intentional to ensure the demo is safe to run in a classroom without locking the presenter out of their own system.
2. **Offline Fallback is in Memory:**  
   If you switch to "In-Browser Sim" mode, all alerts and audit rows live in browser memory. Refreshing the browser page resets the simulation data. In "Live Backend" mode, everything persists in SQLite.
3. **No Active Directory Sync:**  
   User accounts (`customer.tariq`, `faculty.ahmed`, `dev.bilal`) are parsed from telemetry logs rather than synced from a live Microsoft Active Directory or LDAP server.
4. **License Quotas are Demonstration Keys:**  
   The licensing system uses real RSA-2048 cryptographic signatures, but the sample license file in `dev` mode is pre-generated for local demonstration.

---

## 9. 10 Likely Questions From a Professor With Short, Honest Answers

**Q1: What standard format do your detection rules follow?**  
*Answer:* "We use the Sigma rule standard in YAML format. Each rule specifies a detection condition, severity, MITRE ATT&CK technique ID, and sliding time window. It allows rules to be shared across different SIEM systems."

**Q2: What happens if an attacker tampers with the audit log in SQLite?**  
*Answer:* "The audit log uses a SHA-256 hash chain where each block's hash depends on the previous block's hash. If someone edits a row in the database, the hash chain breaks, and the SOC Administrator dashboard immediately turns red with a `TAMPERED` warning."

**Q3: Why do you have a human approval gate instead of 100% automated response?**  
*Answer:* "Fully automated containment can cause unintended operational outages—like isolating a hospital server or freezing legitimate transactions. In Riskbyte, the AI prepares the investigation and proposes containment, but an authorized human analyst must review and approve it."

**Q4: How does your AI triage avoid leaking confidential student or banking data to external APIs?**  
*Answer:* "Riskbyte has an automated entity redaction layer (`riskbyte/triage.py`). Before any log summary is sent to the LLM, internal IP addresses, user accounts, and hostnames are masked with pseudonyms like `[REDACTED_IP_1]`. The external LLM never sees real identifiers."

**Q5: What is the difference between an Alert and a Case?**  
*Answer:* "An Alert is a single detection event triggered by a rule. A Case groups all high-severity alerts related to the same host or user entity over time. This prevents alert fatigue by giving the analyst one consolidated investigation ticket."

**Q6: What happens if the Gemini API is down, rate-limited, or has no internet?**  
*Answer:* "Riskbyte automatically falls back to an internal heuristic triage engine. It analyzes rule severity, threat intel indicators, and entity history locally, so the SOC never stops working even during an internet blackout."

**Q7: How are client organizations segregated in Riskbyte?**  
*Answer:* "Every ingested event, triggered alert, case, and audit entry carries a `client` attribute in the database and API payloads. The UI displays client badges and allows filtering scenarios by client profile."

**Q8: Can an Ingest account approve containment actions?**  
*Answer:* "No. In `riskbyte/api.py`, tokens with the `ingest` role are restricted to `POST /api/ingest`. If an ingest token attempts to call `/api/alerts/<id>/approve`, the backend returns HTTP 403 Forbidden. Only `analyst` and `admin` roles can approve actions."

**Q9: Why are documentation IP ranges used in the demo?**  
*Answer:* "Per RFC 5737 and RFC 6890, IP blocks like `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` are globally reserved for documentation and simulation. Using them guarantees that educational simulations never interfere with real internet hosts."

**Q10: If a real ransomware attack occurred, how fast would Riskbyte detect it?**  
*Answer:* "Immediately upon log ingestion. Rule `rb-007` looks for the process invocation of `vssadmin delete shadows` or mass file modification flags. As soon as the endpoint agent emits the log, Riskbyte processes it in under 50 milliseconds."

---

## 10. Presentation Checklist (1 Hour Prep)

- [ ] Open PowerShell, start `python -m riskbyte.main`.
- [ ] Open browser to `http://localhost:8080`.
- [ ] Click **Security Analyst Dashboard**.
- [ ] Switch to **Demo** tab.
- [ ] Show the **Client Selector** (`Meezan Bank`, `Salim Habib University`, `Contour Software`).
- [ ] Select **Meezan Bank**, point out the profile card (what they do, risks).
- [ ] Click **"Run Attack"** on **Fake Bank Login Phishing**.
- [ ] Walk through the 7 steps as they appear, reading the "What this means" and "Why this matters" lines.
- [ ] Click **"Approve & Execute Action"** at Step 6; point out Step 7 showing the cryptographic SHA-256 block hash.
- [ ] Point out the **"What Happened?"** box at the end.
- [ ] Switch to **Audit Trail** tab to show the cryptographic hash chain marked `Intact ✓`.
- [ ] Switch to **Admin Overview** to show the 10 Sigma rules and platform metrics.
- [ ] Show the presentation credit: *"Muhammad Nabil • F23CSC009 • Essentials of Cybersecurity"*.
