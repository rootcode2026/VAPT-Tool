Absolutely. Since your project is already at the stage where the Nmap → Findings → Risk Assessment → PostgreSQL pipeline works, we can create a professional GitHub README that presents it as a serious VAPT/Security SaaS project without claiming features that aren't finished yet.

You can use this as your README.md:

# VAPT-Tool

A containerized Vulnerability Assessment and Penetration Testing (VAPT) platform designed to automate security scanning, vulnerability detection, risk assessment, and security reporting.

The platform is being developed as a modular security SaaS application with a FastAPI backend, Celery-based asynchronous scan processing, Dockerized security scanners, PostgreSQL persistence, and a planned web dashboard.

---

## 🚀 Project Overview

VAPT-Tool is designed to provide organizations with a centralized platform for:

- Managing security projects
- Managing targets
- Running security scans
- Processing scans asynchronously
- Parsing scanner results
- Detecting security findings
- Assigning severity and scores
- Calculating overall risk
- Storing scan results
- Tracking historical scans
- Generating security reports
- Providing a centralized security dashboard

The architecture is designed to support multiple security scanners rather than being tied to a single scanning engine.

---

## 🏗️ Current Architecture

```text
                         ┌──────────────────┐
                         │   Web Frontend   │
                         │    (Planned)     │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │    FastAPI API   │
                         │     Backend      │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │    PostgreSQL    │
                         │     Database     │
                         └──────────────────┘

                                  │
                                  │ Queue
                                  ▼
                         ┌──────────────────┐
                         │    RabbitMQ      │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Celery Worker  │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Scanner Manager  │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Dockerized Nmap  │
                         │     Scanner      │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Nmap Parser    │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Finding Engine   │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ Risk Assessment  │
                         │     Engine       │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │    PostgreSQL    │
                         └──────────────────┘


---

✨ Current Features

Project Management

The backend supports the foundation for managing:

Organizations

Projects

Targets

Scans



---

Target Management

Targets can be associated with projects and include:

Target value

Target type

Active/inactive state

Project association


Example target:

example.com

or:

192.168.1.100


---

🔍 Nmap Scanning

The first integrated scanner is Nmap.

Nmap runs inside a dedicated Docker container rather than directly inside the application container.

Current scanning uses service detection:

nmap -sV <target>

Example:

nmap -sV example.com

The scanner returns XML output which is then parsed by the application.


---

🐳 Dockerized Scanner Architecture

Security scanners are isolated from the main application.

Celery Worker
      │
      ▼
Scanner Manager
      │
      ▼
Docker Runner
      │
      ▼
Nmap Docker Container
      │
      ▼
XML Result

This architecture makes it possible to add additional scanners without tightly coupling them to the worker.


---

📄 Nmap Result Parsing

Nmap XML output is parsed into structured application data.

Example:

{
  "scanner": "nmap",
  "version": "7.93",
  "hosts": [
    {
      "status": "up",
      "addresses": [
        {
          "address": "104.20.23.154",
          "type": "ipv4"
        }
      ],
      "hostnames": [
        "example.com"
      ],
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "tcpwrapped"
        }
      ]
    }
  ]
}

Structured results allow the finding engine to analyze scanner output independently from the scanner implementation.


---

🛡️ Finding Engine

The Finding Engine analyzes parsed scanner results and identifies potential security findings.

Current examples include:

HTTP Service Exposed

Severity: Low
Score: 25
CWE: CWE-319

Service Exposed on Port 8080

Severity: Medium
Score: 45

Findings contain information such as:

Scanner

Title

Description

Severity

Score

Status

Evidence

Remediation

CVE

CWE



---

📊 Risk Assessment Engine

The Risk Assessment Engine calculates an overall security score based on detected findings.

Current severity weights:

Severity	Weight

Critical	60
High	30
Medium	15
Low	5


The initial score is:

100

Risk points are deducted based on the detected findings.

Risk Score = 100 - Risk Points

The score is constrained between:

0 - 100


---

Risk Grades

Score	Grade	Risk Level

90-100	A	Excellent
75-89	B	Good
50-74	C	Needs Attention
0-49	D	Critical


Example:

Findings:
- 1 Medium
- 1 Low

Risk Score: 80
Grade: B
Risk Level: Good


---

⚙️ Asynchronous Scan Processing

Scans are processed asynchronously using Celery.

FastAPI
   │
   ▼
Create Scan
   │
   ▼
RabbitMQ
   │
   ▼
Celery Worker
   │
   ▼
Security Scanner
   │
   ▼
Finding Engine
   │
   ▼
Risk Engine
   │
   ▼
PostgreSQL

This prevents long-running security scans from blocking API requests.


---

🗄️ Database

PostgreSQL is used as the primary database.

Current major tables include:

organizations
users
projects
targets
scans
scan_results
findings

Scan records contain:

risk_score
risk_grade
risk_level


---

🔄 Scan Lifecycle

A typical scan follows this flow:

Target Created
      │
      ▼
Scan Requested
      │
      ▼
Scan Queued
      │
      ▼
Celery Task
      │
      ▼
Nmap Execution
      │
      ▼
XML Parsing
      │
      ▼
Finding Detection
      │
      ▼
Risk Assessment
      │
      ▼
Database Storage
      │
      ▼
Scan Completed


---

🧰 Technology Stack

Backend

Python

FastAPI

SQLAlchemy

Alembic

PostgreSQL


Background Processing

Celery

RabbitMQ

Redis


Security

Nmap

Dockerized scanner execution


Infrastructure

Docker

Docker Compose


Planned Frontend

Modern web dashboard

Scan management

Findings management

Risk visualization

Security reports



---

📁 Project Structure

VAPT-Tool/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/
│   │   │       ├── projects.py
│   │   │       ├── targets.py
│   │   │       └── scans.py
│   │   │
│   │   ├── core/
│   │   ├── db/
│   │   ├── models/
│   │   ├── schemas/
│   │   └── main.py
│   │
│   └── alembic/
│
├── worker/
│   └── app/
│       ├── finding_engine/
│       ├── scanner/
│       │   ├── scanners/
│       │   ├── parsers/
│       │   ├── docker_runner.py
│       │   └── manager.py
│       │
│       ├── risk_engine/
│       ├── celery_app.py
│       └── tasks.py
│
├── docker-compose.yml
│
└── README.md


---

🚀 Running the Project

Prerequisites

Install:

Docker Desktop

Docker Compose

Git


The project is designed to run using Docker, so local installation of Nmap is not required for the scanner worker.


---

Clone the Repository

git clone <YOUR_REPOSITORY_URL>
cd VAPT-Tool


---

Start the Application

docker compose up -d --build

Check running containers:

docker compose ps


---

Check Worker

docker compose logs -f worker

A healthy worker should show:

celery ... ready


---

Run Database Migrations

docker compose run --rm backend alembic upgrade head


---

🧪 Testing

The project contains individual test modules for major components.

Scanner Test

docker compose exec worker python -m app.scanner_runner_test

Scanner Manager Test

docker compose exec worker python -m app.manager_test

Nmap Parser Test

docker compose exec worker python -m app.nmap_parser_test

Finding Engine Test

docker compose exec worker python -m app.finding_engine_test

Risk Engine Test

docker compose exec worker python -m app.risk_engine_test


---

🔐 Security & Responsible Usage

This project is intended for authorized security testing and vulnerability assessment.

Only scan:

Systems you own

Systems you have explicit permission to test

Authorized lab environments

Authorized penetration-testing targets


Do not use this software to scan or attack systems without authorization.


---

🛣️ Roadmap

Phase 1 — Core Scanning

[x] Docker environment

[x] FastAPI backend

[x] PostgreSQL database

[x] Alembic migrations

[x] Celery worker

[x] RabbitMQ integration

[x] Redis integration

[x] Scanner abstraction

[x] Docker scanner runner

[x] Nmap integration

[x] Nmap XML parser

[x] Finding Engine

[x] Findings persistence

[x] Risk Assessment Engine

[x] Risk score persistence


Phase 2 — API Layer

[ ] Scan findings API

[ ] Scan results API

[ ] Risk assessment API

[ ] Scan history API

[ ] Project-level scan summaries

[ ] Finding filtering

[ ] Finding severity filtering


Phase 3 — Additional Security Tools

[ ] Nuclei

[ ] Web application scanning

[ ] Additional reconnaissance tools

[ ] Tool-specific parsers

[ ] Unified scanner result format


Phase 4 — Frontend

[ ] Authentication UI

[ ] Dashboard

[ ] Project management

[ ] Target management

[ ] Scan management

[ ] Scan progress

[ ] Findings dashboard

[ ] Risk dashboard

[ ] Scan history

[ ] Finding details


Phase 5 — Reporting

[ ] PDF security reports

[ ] Executive summary

[ ] Technical findings

[ ] Risk scoring

[ ] Remediation recommendations

[ ] Report downloads


Phase 6 — SaaS Features

[ ] Multi-tenant architecture

[ ] Organization management

[ ] Role-based access control

[ ] User management

[ ] Scan scheduling

[ ] Notifications

[ ] Audit logging

[ ] Usage limits

[ ] Subscription plans



---

🎯 Long-Term Vision

The long-term goal of VAPT-Tool is to evolve into a centralized security assessment platform capable of combining multiple security tools into a unified workflow.

Instead of requiring security teams to manually execute multiple tools and interpret their outputs separately, the platform aims to provide:

Target
  ↓
Reconnaissance
  ↓
Port & Service Discovery
  ↓
Web Vulnerability Detection
  ↓
Security Findings
  ↓
Risk Assessment
  ↓
Prioritization
  ↓
Remediation
  ↓
Security Report

The scanner architecture is intentionally modular so additional security tools can be integrated without redesigning the entire platform.


---

📌 Project Status

Status: Active Development

The current backend successfully supports an end-to-end Nmap-based vulnerability assessment pipeline:

Nmap
 ↓
Parser
 ↓
Finding Engine
 ↓
Risk Engine
 ↓
PostgreSQL

Frontend development, additional scanner integrations, reporting, and SaaS functionality are currently planned/in development.


---

👨‍💻 Author

Naresh Prasanna

Built as a security engineering project focused on automated vulnerability assessment, scalable scan processing, and security risk analysis.


---

⚠️ Disclaimer

This project is intended for educational, research, and authorized security assessment purposes only.

The author is not responsible for misuse or unauthorized scanning of systems.

### One important change before you commit

Don't put this:

```text
git clone <YOUR_REPOSITORY_URL>

in the final README. Replace it with your actual GitHub repository URL.

Also, don't claim Nuclei, frontend, PDF reporting, authentication, or SaaS features as completed yet. Keeping the README honest about what's implemented vs. planned will make the project look much more credible to recruiters and potential users.
