# RepoTrace 

> GitHub-first Repository Intelligence & OSINT Platform for Malware Analysts, DFIR Teams, Threat Hunters, and CTI Analysts.

RepoTrace helps analysts investigate suspicious GitHub repositories dramatically faster by turning raw repository URLs into actionable intelligence.

Instead of manually:

* opening repositories,
* inspecting commit history,
* correlating infrastructure,
* extracting domains,
* tracking changed files,
* downloading suspicious archives,
* and documenting findings,

RepoTrace automates the workflow into a single analyst-friendly interface.

---

# Why RepoTrace?

Modern malware campaigns increasingly abuse:

* GitHub repositories
* GitLab repositories
* Public code hosting
* Archive-based payload delivery
* Infrastructure reuse
* Rapid commit updates
* Disposable developer accounts

Analysts investigating VirusTotal Livehunt alerts or malware infrastructure often waste valuable time manually pivoting across:

* GitHub
* VirusTotal
* Browserling
* commit history
* repository trees
* archive extraction
* infrastructure correlation

RepoTrace was built to reduce this workflow from:

```text
10–15 minutes per investigation
```

to:

```text
under 60 seconds
```

for initial triage and OSINT enrichment.

---

# Core Capabilities

## Repository Intelligence

* Repository metadata profiling
* Owner intelligence
* Public repo enumeration
* Commit activity analysis
* Contributor visibility
* File tree analysis
* Repository age detection
* Last update tracking
* Language detection
* Archive detection
* Commit delta monitoring

---

## Risk Profiling

RepoTrace automatically scores repositories based on indicators such as:

* Secret exposure
* Archive presence
* Suspicious extensions
* Infrastructure reuse
* Payload-related keywords
* Encoded content
* Suspicious domains/IPs
* Malware-related patterns
* Commit churn

Risk levels:

* Low
* Medium
* High
* Critical

---

## Cross-Repo Correlation

RepoTrace correlates indicators across repositories:

* Shared domains
* Shared emails
* Shared IPs
* Shared infrastructure
* Shared commit behavior
* Shared suspicious patterns

This helps identify:

* Campaign infrastructure
* Reused staging environments
* Malware distribution clusters
* Operator overlap

---

## Advanced Watch Mode

Track what changes over time.

RepoTrace can detect:

* New commits
* Added files
* Deleted files
* Modified files
* New domains
* New infrastructure
* Risk score changes
* Suspicious archive additions

Perfect for:

* Monitoring active malware repos
* Tracking evolving campaigns
* Following infrastructure growth
* Watching payload refreshes

---

## Delta Intelligence Dashboard

RepoTrace provides before/after comparison visibility:

* What changed?
* Which files were added?
* Which domains are new?
* Which commits appeared?
* Did the risk score increase?

This enables rapid campaign evolution tracking.

---

## Bulk Repository Scanning

Scan multiple repositories simultaneously.

Useful for:

* Campaign-wide analysis
* VT hunting operations
* Infra sweeps
* Threat intelligence enrichment
* Large-scale OSINT investigations

---

## Analyst Exporting

Export investigation results as:

* JSON
* Markdown Reports
* HTML Reports

---

# Use Cases

## VirusTotal Livehunt Investigations

Input:

* suspicious GitHub repo
* malware archive URL
* suspicious commit

Output:

* repo intelligence
* extracted infrastructure
* risk score
* suspicious files
* historical context
* watch-mode tracking

---

## Malware Infrastructure Tracking

Track:

* staging repositories
* phishing kits
* stealer repos
* loader infrastructure
* campaign refreshes

---

## Threat Hunting

Use RepoTrace to:

* identify suspicious repos
* correlate infrastructure
* discover reused payload delivery
* monitor threat actor updates

---

## DFIR / Incident Response

Quickly determine:

* what changed
* when payloads appeared
* whether infrastructure evolved
* if secrets or staging infra exist

---

# Platform Features

## Public Launch Controls

RepoTrace supports:

* Usage limits
* Public mode
* Search counters
* Rate limiting
* Payment unlock flow
* Razorpay integration
* UPI support
* Admin access

---

# Screenshots

## Main Dashboard

<img width="1390" height="930" alt="image" src="https://github.com/user-attachments/assets/da642f7c-750b-4973-b5cc-5e7f63caeee4" />
<img width="1414" height="945" alt="image" src="https://github.com/user-attachments/assets/ae5a34f8-0783-41b9-af07-4768ab587186" />
<img width="1397" height="740" alt="image" src="https://github.com/user-attachments/assets/3adb97ae-fa84-4a58-86c5-58526fb731f9" />

---

## Repository Intelligence View

<img width="1424" height="939" alt="image" src="https://github.com/user-attachments/assets/bd11e5da-75de-42ea-9915-5d7ec17d0045" />
<img width="1390" height="754" alt="image" src="https://github.com/user-attachments/assets/7e09d4ed-96a3-4459-8ae6-a93965a23cdf" />
<img width="1475" height="940" alt="image" src="https://github.com/user-attachments/assets/37c16d23-7d60-4696-b724-23ea8a2ed1a7" />
<img width="1500" height="917" alt="image" src="https://github.com/user-attachments/assets/f17154e9-92a5-4597-aa0d-d9ee0831d830" />

---

## Watch Mode

<img width="1026" height="909" alt="image" src="https://github.com/user-attachments/assets/65292b73-5fd8-4a51-83ed-02ff89343e80" />
<img width="1017" height="814" alt="image" src="https://github.com/user-attachments/assets/d98fe8c5-2f5e-4318-8bd5-fcc78d130b57" />
<img width="1095" height="1092" alt="image" src="https://github.com/user-attachments/assets/3fe8b865-93b5-42d2-8c9f-f426a0fd851c" />



---

## Delta Dashboard

<img width="1436" height="691" alt="image" src="https://github.com/user-attachments/assets/f96c1fba-2c8e-4d63-9663-aee6c37a3bc4" />
<img width="1401" height="805" alt="image" src="https://github.com/user-attachments/assets/39faa7e3-474f-4662-a1a5-b0818bcb0b58" />

---

## Bulk Scanning

<img width="1402" height="352" alt="image" src="https://github.com/user-attachments/assets/b2e523a2-469d-4248-a627-c808ec2ec608" />
<img width="1399" height="853" alt="image" src="https://github.com/user-attachments/assets/1fe46870-f571-4c68-ac4f-423050712ef5" />
<img width="1381" height="896" alt="image" src="https://github.com/user-attachments/assets/12f20ad3-171a-45c8-b1f6-d1508bc04ba5" />


---

# Architecture

```text
User Input
   ↓
Repo Parsing
   ↓
GitHub Intelligence Collection
   ↓
Commit + File Analysis
   ↓
Infrastructure Extraction
   ↓
Risk Scoring
   ↓
Cross-Repo Correlation
   ↓
Watch Snapshot Storage
   ↓
Delta Intelligence Engine
   ↓
Analyst Dashboard
```

---

# Supported Platforms

## Fully Supported

* GitHub

## Partial Support

* GitLab (public-mode limited)

---

# Tech Stack

* Python
* FastAPI
* HTML/CSS/JS
* GitHub API
* Razorpay
* Uvicorn
* Render

---

# Installation

## Clone Repo

```bash
git clone https://github.com/jaynagrecha/RepoTrace.git
cd RepoTrace
```

---

## Create Virtual Environment

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

---

## Install Requirements

```bash
pip install -r requirements.txt
```

---

## Configure Environment

Create `.env`:

```env
GITHUB_TOKEN=your_github_token
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_me
PUBLIC_MODE=true
FREE_DAILY_LIMIT=20
PRICE_PER_SEARCH=2
BURST_LIMIT_PER_MINUTE=12
PYTHON_VERSION=3.12.8
```

Optional:

```env
RAZORPAY_KEY_ID=your_key
RAZORPAY_KEY_SECRET=your_secret
UPI_ID=yourupi@bank
UPI_NAME=RepoTrace
```

---

## Run Locally

```bash
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

---

# Deployment

## Render Deployment

### Build Command

```text
pip install -r requirements.txt
```

### Start Command

```text
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

### Environment Variables

Configure:

* GITHUB_TOKEN
* ADMIN_USERNAME
* ADMIN_PASSWORD
* PUBLIC_MODE
* FREE_DAILY_LIMIT
* PRICE_PER_SEARCH
* BURST_LIMIT_PER_MINUTE
* PYTHON_VERSION

---

# Public Demo

```text
https://repotrace.onrender.com/
```

---

# Security & Safety

RepoTrace is designed for:

* defensive security research
* malware analysis
* OSINT investigations
* DFIR workflows
* threat hunting

RepoTrace:

* does not execute payloads
* does not detonate malware
* performs static intelligence collection only
* focuses on metadata and repository intelligence

Users are responsible for complying with:

* local laws
* organizational policies
* GitHub Terms of Service
* ethical security practices

---

# Project Status

RepoTrace is actively under development.

Current major milestones:

* v20 — Delta Intelligence Dashboard
* v21 — Public Launch Controls
* v22 — Smart Repository Summaries
* v22.1 — Production Hardening & Live Payments

---

# Contributing

Contributions, feature requests, issue reports, and analyst feedback are welcome.

Please open:

* Issues
* Pull Requests
* Enhancement Requests

---

# Creator

Created by Jay Nagrecha.

Built from real-world Cyber Fusion Center investigation workflows.

---

# License

MIT License
