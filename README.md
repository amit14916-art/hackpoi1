# 🛡️ SecOps Guardian - AI-Powered Security Audit & DAST SaaS Platform

An enterprise-grade, automated web application security auditing and DAST platform with **legal guardrails** and **AI-driven remediation**.

---

## 🌟 Key Features

### 1. Attack Surface Discovery & Multi-Endpoint Spider (Phase 1)
- **Async Respectful Web Spider:** Crawls internal routes, links, forms, and JavaScript assets up to depth 2.
- **Form & Parameter Extraction:** Extracts query parameters (`?id=`, `?search=`, `?redirect=`) and form inputs for injection testing.

### 2. Client-Side Secret & Token Leak Detection (Phase 2)
- **Hardcoded Credential Scanner:** Inspects HTML and client-side JavaScript bundles for exposed keys:
  - Google Cloud / Firebase API Keys (`AIza...`) [CWE-798]
  - AWS Access Key IDs (`AKIA...`) [CWE-798]
  - GitHub Personal Access Tokens (`ghp_...`) [CWE-798]
  - Stripe Live Secret Keys (`sk_live_...`) [CWE-798]
  - Slack Webhooks and Private Cryptographic Keys [CWE-312]

### 3. Anti-False-Positive Canary Sensitive File Probing (Phase 3)
- **Baseline 404 Canary Engine:** Fingerprints baseline 404 response on randomized paths (`/__sec_canary_404__`) to completely eliminate false alarms on Single-Page Applications (Next.js, React, Vue) and CDNs.
- **Strict MIME & Syntax Validation:** Validates actual syntax for `/.env`, `/.git/HEAD`, `/docker-compose.yml`, `/backup.sql`, `/package.json`, and `/actuator/health`.

### 4. Domain & Email Security (SPF & DMARC Auditing) (Phase 4)
- **Email Spoofing (SPF):** Checks for missing SPF records or dangerous `+all` allowing spoofed phishing emails [CWE-290].
- **DMARC Enforcement:** Audits `_dmarc.{domain}` for missing records or weak `p=none` monitoring-only policies.

### 5. Verified Active DAST Testing (SQLi, XSS, Redirects) (Phase 5)
- **Safe SQL Injection Boundary Testing:** Injects safe syntax boundary characters (`'`, `"`) and flags database driver syntax leaks (MySQL, PostgreSQL, SQLite, MSSQL, Oracle) [CWE-89].
- **Harmless XSS Canary Reflection:** Injects unique alphanumeric canaries and validates whether inputs are reflected unescaped in HTML contexts [CWE-79].
- **Open Redirect Parameter Audit:** Verifies destination host validation on redirect parameters [CWE-601].
- **HTTP TRACE & Method Tampering:** Detects Cross-Site Tracing (XST) vectors [CWE-200].
- **Legal Guardrail:** Active DAST is restricted to verified domains (via DNS TXT or HTTP challenge) and local testbeds.

### 6. Industry-Standard Taxonomy & AI Remediation
- **Full Taxonomy:** Every finding includes **CWE IDs**, **OWASP Top 10 (2021)**, and **CVSS v3.1 vectors**.
- **Technical Request & Response Proofs:** Provides exact HTTP request probes and response proofs.
- **AI & Expert Remediation:** Generates copy-pasteable patches for **Nginx**, **Apache**, **Node.js (Express)**, and **Python (Django & FastAPI)**.

---

## 🏢 Enterprise Features

### 1. Database Persistence & Multi-Tenant RBAC Auth
- **PostgreSQL Database Storage (`backend/db/`):** Full migration from in-memory cache to a production PostgreSQL database via SQLAlchemy and Alembic migrations.
- **Organization-Based Authentication (`backend/auth/`):** Multi-tenant architecture with `Organization`, `User`, and `ApiKey` models.
- **Role-Based Access Control (RBAC):** Strict permission levels enforced on all API endpoints:
  - `admin`: Manage API keys, SSO settings, GitHub integration, webhook endpoints, and team users.
  - `member`: Trigger scans, verify domains, and export reports.
  - `viewer`: Read-only access to dashboard overviews, scan statuses, and findings.
- **Authentication Headers:** Supports `X-API-Key` or `Authorization: Bearer <key_or_jwt>`.

### 2. Auto-PR Remediation (Feature 1) (`backend/integrations/github_app.py`)
- **GitHub App Integration:** Authenticates via GitHub App ID and RSA private key (RS256 JWT) to request installation access tokens.
- **Domain-to-Repository Mapping:** Maps scanned domains to GitHub repositories (`POST /api/integrations/github/repos/map`).
- **Automated PR Lifecycle:** When a verified domain scan completes, for each vulnerability with an AI remediation patch:
  1. Creates branch `secops-fix/{finding_id}` from the default branch.
  2. Commits the synthesized patch to the target framework file (e.g. `nginx.conf`, `settings.py`, `.htaccess`).
  3. Opens a Pull Request titled `[SecOps Guardian] Fix: {finding.title}` containing technical proofs, CWE/OWASP metadata, and CVSS scores.
  4. Enforces a strict **no-auto-merge guardrail** requiring human review.
  5. Records the resulting PR URL and status directly on the finding record.
- **Setup & Endpoints:**
  - `POST /api/integrations/github/connect`: Generates App installation URL.
  - `POST /api/integrations/github/webhook`: Webhook receiver verifying `X-Hub-Signature-256`.

### 3. Continuous Scanning & CI/CD Webhooks (Feature 2) (`backend/integrations/cicd.py`)
- **Automated Deployment Scans:** Dedicated webhook trigger (`POST /api/webhooks/deploy/{org_id}`) for GitHub Actions, GitLab CI, or generic webhooks with secret token verification.
- **Finding Diffing Engine:** Automatically compares findings against the most recent completed scan for the same domain, generating lists of **new findings** and **resolved findings**.
- **Multi-Channel Alerting (`backend/notifications/`):**
  - **Slack:** Sends rich Block Kit cards with vulnerability details and severity emojis.
  - **Email:** Transmits responsive HTML security summaries via SMTP.
  - **Configurable Thresholds:** Alerting can be tuned per organization (`notify_on_new_findings`, `min_severity_to_notify`).

### 4. Regulatory Compliance Reports (Feature 3) (`backend/reporting/compliance.py`)
- **Framework Mapping Engine (`backend/reporting/compliance_mappings.py`):**
  - **SOC 2 Type II:** Maps findings to Trust Services Criteria (CC6.1, CC6.6, CC6.7, CC7.1, CC7.2, A1.2, C1.1).
  - **ISO/IEC 27001:2022:** Maps findings to Annex A technological controls (A.5.15, A.8.8, A.8.20, A.8.24, A.8.26, A.8.28).
- **PDF Report Generation:** Generates comprehensive PDF reports featuring cover pages, executive scorecards, control pass/fail matrices, and technical evidence appendices.
- **Legal Compliance Disclaimer:** Explicitly notes that reports serve as technical engineering aids and do not substitute for formal CPA or ISO audits.
- **Endpoint:**
  - `GET /api/scan/{scan_id}/export/compliance?framework=soc2|iso27001`

### 5. Organization Dashboard & Multi-Domain Fleet (Feature 4) (`backend/dashboard/`)
- **Domain Fleet Monitoring:** Track multiple domains per organization with real-time grade and score indicators.
- **Historical Risk Score Timelines:** Provides historical data points (`timestamp`, `score`, `grade`, `findings_count`) for frontend charting (Recharts, Chart.js).
- **Executive Overview Aggregation:** Calculates total domains, verified domains, average fleet risk score, open finding counts by severity, and 7-day / 30-day delta trends.
- **Endpoints:**
  - `POST /api/org/{org_id}/domains`: Track a new domain.
  - `GET /api/org/{org_id}/domains`: List tracked domains with latest security grades.
  - `GET /api/org/{org_id}/domains/{domain_id}/history`: Time-series risk score history.
  - `GET /api/org/{org_id}/overview`: Enterprise fleet security posture.

### 6. Enterprise SSO: SAML 2.0 & OIDC (Feature 5) (`backend/auth/sso.py`)
- **SAML 2.0 SP-Initiated Flow:** Supports standard corporate Identity Providers (Okta, Ping, Azure AD SAML).
  - SP Metadata URL: `GET /api/auth/saml/{org_id}/metadata`.
  - IdP Metadata Upload: `POST /api/auth/saml/{org_id}/metadata`.
- **OAuth / OIDC Integration:** Turnkey support for **Google Workspace** and **Microsoft Entra ID**.
- **At-Rest Secret Encryption:** All client secrets are encrypted using Fernet symmetric encryption (`SECOPS_ENCRYPTION_KEY`).
- **Just-in-Time (JIT) Auto-Provisioning:** On successful authentication, automatically provisions the user under the organization with the `member` role and issues a standardized JWT session token.
- **Endpoints:**
  - `GET /api/auth/sso/{org_id}/login`: Redirects to corporate IdP.
  - `GET /api/auth/sso/{org_id}/callback`: Processes authentication response and issues session JWT.

---

## ⚙️ Environment Variables Setup

Copy `.env.example` to `.env` and configure your environment:

```bash
# Database
DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/secops_guardian

# Authentication & Encryption
SECOPS_REQUIRE_AUTH=false
SECOPS_JWT_SECRET=your-jwt-secret-min-32-chars
SECOPS_ENCRYPTION_KEY=your-fernet-encryption-key-base64
SECOPS_BASE_URL=http://localhost:8000

# GitHub App Auto-PR
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY=./secrets/github-app.private-key.pem
GITHUB_APP_SLUG=secops-guardian
GITHUB_WEBHOOK_SECRET=your-github-webhook-secret

# Notifications (SMTP)
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@yourdomain.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=alerts@secopsguardian.io

# AI Engine
GEMINI_API_KEY=your-gemini-api-key
```

To run database migrations with Alembic:
```bash
alembic upgrade head
```

---

## 🚀 Quick Start

### 1. Run the Platform
```powershell
python run_server.py
```
Open your browser at **`http://localhost:8000`**.

### 2. Interactive Swagger API Documentation
Explore and test the full REST API at **`http://localhost:8000/docs`**.

---

## 🧪 Testing

Run the full automated test suite covering passive recon, canary probing, active DAST, database persistence, RBAC auth, and all 5 enterprise features:

```powershell
pytest
```
