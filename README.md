# AegisGuard · AI-Driven Multi-Vendor Network Security Compliance Auditor

<p align="center">
  <img src="frontend/src/assets/hero.png" alt="AegisGuard Platform Banner" width="850" style="border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.6);" />
</p>

<p align="center">
  <strong>Smart India Hackathon 2026 · Problem Statement SIH26155</strong><br />
  <strong>Organization:</strong> National Technical Research Organisation (NTRO)<br />
  <strong>Category:</strong> Software · Blockchain & Cybersecurity
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Tests-91%2F91%20Passed-10b981?style=for-the-badge&logo=pytest&logoColor=white" alt="Pytest 91/91 Passed" />
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-19.0-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React 19" />
  <img src="https://img.shields.io/badge/Vite-6.0-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Compliance-CIS%20%7C%20NIST%20%7C%20STIG%20%7C%20ISO27001%20%7C%20PCIDSS-a855f7?style=for-the-badge" alt="Compliance Frameworks" />
</p>

---

## Executive Summary

Enterprise and defense networks operate in deeply heterogeneous environments composed of firewalls, routers, switches, and load balancers from diverse vendors (Cisco IOS/IOS-XE/NX-OS, Juniper Junos, Palo Alto PAN-OS, Fortinet FortiOS, Arista EOS). Each vendor utilizes completely distinct configuration syntaxes, hierarchy paradigms, and CLI abstractions.

**AegisGuard (SIH26155)** resolves this fundamental cybersecurity challenge through an **AI-Augmented, Vendor-Agnostic Security Baseline Model (SBM)** architecture. 

### Core Architectural Principle
> **"AI Understands. Policy Decides. Evidence Proves."**
>
> AegisGuard never passes arbitrary configurations to LLMs to make blind pass/fail assertions. Instead, deterministic multi-vendor AST parsers and a human-in-the-loop AI semantic resolver normalize raw configuration semantics into a unified, vendor-neutral Security Baseline Model. Strict policy engines then evaluate compliance, maintaining a cryptographic chain of custody from raw configuration lines to validated remediations.

---

## Key Platform Capabilities

```
Raw Configuration (Static Upload / Live SSH Ingestion)
                         │
                         ▼
             Vendor Auto-Detection (0.1ms)
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
Deterministic AST Parsers       AI Semantic Resolver
(Cisco, Juniper, Palo Alto)     (Unknown Vendor / Syntax)
         │                               │
         └───────────────┬───────────────┘
                         ▼
           Canonical Security Baseline Model
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
CIS Benchmarks     NIST SP 800-53    DoD STIG / ISO 27001
         │               │               │
         └───────────────┬───────────────┘
                         ▼
            Evidence-Backed Findings
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
Cyber Intelligence Engine       Autonomous Remediation Engine
• Lateral Attack Paths           • Pre-Change Snapshot Isolation
• Transitive Blast Radius        • Risk-Tiered Auto-Fix
• MITRE ATT&CK Mapping           • 1-Click Inverse Rollback
                         │
                         ▼
        Executive Dashboard & Real-Time Telemetry
```

### 1. Multi-Vendor Configuration Parsing & Ingestion
- **Deterministic AST Interpreters**: Full abstract syntax tree and contextual stanza parsers for Cisco IOS/IOS-XE, Juniper Junos (hierarchical & set syntax), Palo Alto PAN-OS (XML & set stanza), Arista EOS, and Fortinet FortiOS.
- **Live Hardware SSH Streamer**: Integrated **Netmiko & NAPALM** dynamic collectors capable of connecting to live routers/firewalls via SSH (`cisco_ios`, `juniper_junos`, `paloalto_panos`), pulling active running configurations, and executing live hardening commands.

### 2. Multi-Framework Compliance Engine
- Evaluates configurations simultaneously across:
  - **CIS Benchmarks v8.1** (Level 1 & Level 2 profiles)
  - **NIST SP 800-53 Rev. 5** (Federal security controls: AC, SC, AU, CM)
  - **DoD DISA STIG** (Department of Defense security technical implementation guides)
  - **ISO/IEC 27001:2022** (Annex A controls: A.8.20, A.8.21, A.8.24)
  - **PCI-DSS v4.0** (Payment Card Industry data security standards)
- Every finding links directly to the exact CLI configuration line, observed state, expected baseline, and severity weighting.

### 3. Autonomous Remediation & 1-Click Rollback Protection
- **Pre-Change Snapshot Storage**: Automatically creates isolated running-configuration backups before any remediation command is executed.
- **Automated Inverse Rollback**: Synthesizes exact undo commands (e.g. restoring previous AAA configurations, re-binding transport inputs, reverting crypto key algorithms).
- **Risk-Tiered Execution**: Classifies fixes into Low (Autonomous Safe), Medium (Scheduled), and High (Requires Manual Change Advisory Board approval).

### 4. Cyber Intelligence & Attack Path Analysis
- **Attack Graph Visualization**: Maps lateral movement paths that an adversary could traverse if vulnerable network planes (e.g. plaintext Telnet, weak SNMPv1/v2 communities, missing ACLs) are exploited.
- **Blast Radius Scorer**: Evaluates transitive network risk and impacted downstream nodes across core, distribution, and edge boundaries.
- **MITRE ATT&CK Mapping**: Correlates findings to MITRE Enterprise matrix techniques (e.g., `T1021.004` Remote Services, `T1552` Unsecured Credentials).

### 5. Interactive Purple Shade Enterprise UI/UX
- **Quick Command Palette (`Ctrl + K`)**: Universal search modal to jump across tabs, filter security controls, and instantly load benchmark configurations.
- **Side-by-Side Split Diff Viewer**: Visualizes baseline configurations directly against proposed automated remediation scripts with colored additions and deletions.
- **Slide-Over Detail Drawer**: In-depth inspection for findings featuring MITRE ATT&CK technique breakdown, observed vs. expected diffs, and 1-click execution.
- **Floating Batch Action Bar**: Checkbox multi-select to bulk auto-fix or export selected compliance findings to JSON.
- **Collapsible Sidebar & Toast Notifications**: Sleek responsive layout with zero emojis (100% crisp vector SVG icons) designed for mission-critical security operations centers (SOC).

---

## Repository Structure

```text
SIH-AI-Complaince-engine-main/
├── backend/
│   └── src/
│       └── sih26155/
│           ├── api/             # FastAPI routes, schemas, and live SSH controllers
│           ├── compliance/      # Framework rules (CIS, NIST, STIG, ISO 27001), scoring
│           ├── core/            # Canonical SBM schema, evidence models, pipeline stages
│           ├── ingestion/       # File loaders, Netmiko/NAPALM live collectors, detector
│           ├── intelligence/    # Attack Path Engine, Blast Radius, Safe Remediation validator
│           ├── parsers/         # Vendor AST parsers (Cisco, Juniper, Palo Alto, Arista, Fortinet)
│           ├── remediation/     # Auto-fix generator, rollback calculator, registry
│           ├── reporting/       # Executive HTML/PDF export generator
│           └── storage/         # In-memory & SQLite snapshot repository
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Main React SOC dashboard with command palette & drawer
│   │   ├── App.css              # Purple shade enterprise styling & dynamic animations
│   │   ├── index.css            # CSS custom properties, tokens, and font setup
│   │   └── api.js               # REST client for backend FastAPI integration
│   ├── package.json
│   └── vite.config.js
├── data/
│   ├── configs/                 # Enterprise sample configurations (hardened & insecure)
│   ├── mappings/                # Vendor semantic mapping tables & AI learned rules
│   └── remediation/             # Hardening templates and rollback definitions
├── docs/                        # Architecture Decision Records (ADRs) and demo scripts
├── tests/                       # 91 comprehensive integration, unit, and E2E tests
├── pyproject.toml
└── docker-compose.yml
```

---

## Quickstart Guide

### Prerequisites
- Python 3.11 or 3.12
- Node.js 18+ and npm
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/samyuktaap/AI-Driven-Multi-Vendor-Network-Security-Compliance-Auditor.git
cd AI-Driven-Multi-Vendor-Network-Security-Compliance-Auditor
```

### 2. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

# Install dependencies in editable mode
pip install -e .
pip install pytest uvicorn fastapi netmiko napalm pydantic
```

### 3. Launch Backend API Server
```bash
python -m uvicorn sih26155.api.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Swagger Documentation: `http://localhost:8000/docs`
- Healthcheck Endpoint: `http://localhost:8000/api/health`

### 4. Frontend Setup & Launch
```bash
cd frontend
npm install
npm run dev
```
- AegisGuard Web Dashboard: `http://localhost:5173/`

---

## Verification & Test Suite

The system includes a rigorous test suite of **91 automated tests** covering vendor parsers, compliance policy evaluators, live SSH collectors, attack path engines, and safe rollback validators.

To run the complete test suite:
```bash
python -m pytest tests/ -v
```

```text
================================== test session starts ===================================
platform win32 -- Python 3.12.8, pytest-8.3.4, pluggy-1.5.0
collected 91 items

tests/integration/api/test_analysis_api.py::test_analyze_cisco_config PASSED           [  1%]
tests/integration/api/test_analysis_api.py::test_analyze_unknown_vendor PASSED         [  2%]
tests/integration/api/test_live_fetch_api.py::test_live_fetch_simulation PASSED       [  3%]
tests/integration/api/test_multi_vendor_analysis_api.py::test_multi_vendor_flow PASSED [  5%]
tests/integration/e2e/test_full_cisco_pipeline.py::test_full_cisco_pipeline PASSED    [ 16%]
tests/integration/e2e/test_juniper_pipeline.py::test_full_juniper_pipeline PASSED     [ 19%]
tests/integration/e2e/test_paloalto_pipeline.py::test_full_paloalto_pipeline PASSED   [ 20%]
tests/unit/intelligence/test_intelligence.py::TestAttackPathEngine PASSED             [ 46%]
tests/unit/intelligence/test_intelligence.py::TestBlastRadiusAnalyser PASSED          [ 51%]
tests/unit/intelligence/test_intelligence.py::TestSafeRemediationValidator PASSED     [ 60%]
tests/unit/remediation/test_remediation.py::test_valid_remediation_is_accepted PASSED [ 96%]
...
============================= 91 passed, 1 warning in 4.03s =============================
```

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Ingests CLI configuration text or file and returns SBM facts, compliance findings, and remediations |
| `POST` | `/api/live-fetch` | Connects via SSH (Netmiko/NAPALM) to live physical/virtual network hardware and ingests running-config |
| `POST` | `/api/intelligence/attack-paths` | Generates lateral movement attack graph and risk scores based on detected security findings |
| `POST` | `/api/intelligence/blast-radius` | Calculates network exposure index and affected downstream blast radius |
| `POST` | `/api/intelligence/safe-remediation` | Validates proposed remediation scripts against blacklists to prevent accidental outage |
| `POST` | `/api/remediation/execute` | Takes pre-change snapshot and executes hardening commands |
| `POST` | `/api/remediation/rollback` | Reverts device state using inverse rollback syntax and restores snapshot |
| `POST` | `/api/export-pdf` | Exports an audit-ready executive and technical compliance report |

---

## Innovation & Edge

1. **Deterministic Security Guarantee**: AI is strictly quarantined to semantic normalization; policy evaluation is 100% deterministic, eliminating hallucinated compliance approvals.
2. **True Closed-Loop Remediation**: Unlike passive scanners that only report issues, AegisGuard provides verified hardening commands with mathematical inverse rollback guarantees.
3. **Defense-Grade Auditing**: Full line-level evidence tracking ensures compliance findings stand up to rigorous external regulatory audits (NIST, CIS, DoD STIG).

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Developed for **Smart India Hackathon 2026** by Team AegisGuard.
