# VAPT Tool

A containerized Vulnerability Assessment and Penetration Testing (VAPT) platform for managing projects, targets, security scans, findings, and risk assessments.

The platform currently integrates **Nmap** for network/service discovery and **Nuclei** for vulnerability and security misconfiguration detection.

---

## 🚀 Current Features

### Project Management

- Create projects
- View projects
- View project details
- Delete projects
- Associate targets with projects

### Target Management

Supports:

- Domains
- IP addresses
- URLs

Target functionality includes:

- Create targets
- View targets
- Filter targets by project
- Delete targets
- Active/inactive target status

### Security Scanning

Supported scan profiles:

- `quick`
- `web`
- `full`

Current scanner integrations:

- Nmap
- Nuclei

Scans are executed asynchronously using **Celery + RabbitMQ**.

### Nmap

Nmap is used for:

- Host discovery
- Port discovery
- Service detection
- Version detection

Nmap results are converted into normalized findings.

### Nuclei

Nuclei is used for:

- Vulnerability detection
- Security misconfiguration detection
- HTTP security checks
- TLS checks
- Technology detection
- Other template-based security checks

Nuclei JSONL output is parsed into normalized findings.

### Finding Engine

The Finding Engine converts scanner results into a common finding structure.

Each finding can contain:

- Scanner
- Title
- Description
- Severity
- Score
- Status
- Evidence
- Remediation
- CVE
- CWE

Supported scanners:

- Nmap
- Nuclei

### Risk Assessment

The Risk Assessment Engine calculates an overall security risk score based on detected findings.

The result includes:

- Risk score
- Risk grade
- Risk level
- Total findings
- Critical findings
- High findings
- Medium findings
- Low findings
- Informational findings

### Dashboard

The dashboard currently provides:

- Scan statistics
- Finding statistics
- Severity breakdown
- Average risk score
- Recent scan information

---

# 🏗️ Architecture

```text
                         ┌──────────────────┐
                         │     Frontend     │
                         │     Next.js      │
                         └────────┬─────────┘
                                  │
                                  │ HTTP REST API
                                  ▼
                         ┌──────────────────┐
                         │     Backend      │
                         │     FastAPI      │
                         └────────┬─────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             ┌──────────────┐           ┌──────────────┐
             │  PostgreSQL  │           │   RabbitMQ   │
             │   Database   │           │    Queue     │
             └──────────────┘           └──────┬───────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │    Celery    │
                                        │    Worker    │
                                        └──────┬───────┘
                                               │
                              ┌────────────────┴────────────────┐
                              │                                 │
                              ▼                                 ▼
                       ┌──────────────┐                  ┌──────────────┐
                       │     Nmap     │                  │    Nuclei    │
                       │    Scanner   │                  │    Scanner   │
                       └──────┬───────┘                  └──────┬───────┘
                              │                                 │
                              └────────────┬────────────────────┘
                                           ▼
                                  ┌──────────────────┐
                                  │ Finding Engine   │
                                  └────────┬─────────┘
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │  Risk Assessment │
                                  │      Engine      │
                                  └────────┬─────────┘
                                           │
                                           ▼
                                      PostgreSQL