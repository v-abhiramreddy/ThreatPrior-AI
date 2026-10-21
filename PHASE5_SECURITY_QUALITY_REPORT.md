# ThreatPrior AI — Phase 5: Security & Quality Assurance Completion Report

**Audit Date:** October 20, 2026  
**Auditor / Engine:** ThreatPrior AI Engineering & Security QA  
**Scope:** Frontend (React 19, TypeScript, Vite), Backend (FastAPI, Uvicorn, Python 3.12), Dual-Model AI Pipeline (Strands Decider 2B & Amazon Bedrock Claude Sonnet 4.6), Threat Intelligence Integrations (NIST NVD API 2.0, CISA KEV, FIRST.org EPSS), Deployment & Container Configuration.  
**Final Status:** **COMPLETE WITH ACCEPTED LIMITATIONS**

---

## 1. Executive Summary

Phase 5 of the ThreatPrior AI roadmap focused on comprehensive security hardening, API resilience, input validation, memory protection, secrets auditing, dependency vulnerability scanning, accessibility (a11y), and regression test verification.

All verification suites were successfully executed with zero failures:
- **Backend Test Suite:** **133 passed** (0 failed, 0 skipped) across unit, integration, decision engine, and security suites.
- **Frontend Linter (`oxlint`):** **0 errors, 0 warnings** across 17 source files.
- **Frontend Production Build (`vite build`):** **Pass** (TypeScript clean, optimized client bundle generated).
- **End-to-End Suite (`playwright`):** **35 passed** (0 failed, 0 flaky) covering all UI states, routing, dual-AI triage, and error handling.
- **Git Diff Audit (`git diff --check`):** **Clean** (0 trailing whitespace or conflict markers).

---

## 2. Verified Findings & Applied Hardening

| ID | Classification | Affected Component | Evidence & Mechanism | Applied Remediation | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **High** | `backend/app/routers/triage.py` | Rate limiter evaluated `request.client.host` prior to `X-Forwarded-For`. In reverse-proxy deployments (Blitz, Render, AWS ALB), all clients collapsed into a single proxy IP, causing legitimate users to trigger HTTP 429 prematurely. | Prioritized `X-Forwarded-For` client IP resolution before falling back to socket client host. | **Resolved** |
| **SEC-02** | **Medium** | `backend/app/routers/triage.py` | `InMemoryRateLimiter._requests` stored client IP keys in a `defaultdict` without eviction. Over long uptimes with varied client IPs, the dictionary grew unbounded. | Implemented automatic memory pruning: when tracked IPs exceed threshold (1,000), stale timestamps older than 60s are purged. | **Resolved** |
| **SEC-03** | **Medium** | `backend/app/main.py` | HTTP responses lacked defensive security headers, leaving clients susceptible to MIME-sniffing, framing/clickjacking, or unconstrained permissions. | Added global HTTP middleware enforcing `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and `X-XSS-Protection`. | **Resolved** |
| **SEC-04** | **Low** | `backend/app/routers/vulnerabilities.py`, `backend/app/routers/triage.py` | `CVE_REGEX` did not enforce an upper character boundary, permitting arbitrarily long strings (e.g., 50,000 chars) to enter regex evaluation. | Enforced strict `len(normalized_cve) > 30` input rejection, returning HTTP 400 before regex processing. | **Resolved** |
| **SEC-05** | **Low** | `backend/app/main.py` | Absence of centralized unhandled exception handler could allow unhandled Python runtime exceptions to disclose internal stack traces or paths. | Added `@app.exception_handler(Exception)` that logs the exception securely on the server and returns a sanitized JSON error response (`500 Internal Server Error`). | **Resolved** |
| **SEC-06** | **Low** | `src/pages/VulnerabilityAnalysis.tsx`, `src/pages/AnalysisHistory.tsx` | `#cve-input` and `#searchInput` lacked explicit `aria-label` or `<label>` elements, violating WCAG 2.1 SC 4.1.2. | Added `aria-label="Search CVE identifier"` and `aria-label="Search analysis history"` to both inputs. | **Resolved** |
| **SEC-07** | **Informational** | `index.html` | Root HTML template omitted `<meta name="description">` tag. | Added descriptive metadata tag summarizing the engine capabilities. | **Resolved** |
| **SEC-08** | **Informational** | `backend/app/services/cisa_client.py` | Official CISA KEV JSON feed returns HTTP 403 when requested from cloud hosting / datacenter IP ranges due to CDN edge WAF restrictions. | Verified cold-start bundled snapshot fallback (`cisa_kev_seed.json`), truthful stale-data disclosures, and explicit absence disclaimers. | **Accepted Limitation** |

---

## 3. Dependency Security Audit

### Python Dependencies (`backend/requirements.txt`)
- Core runtime versions inspected:
  - `fastapi` 0.143.2
  - `uvicorn` 0.54.0
  - `httpx` 0.28.1
  - `pydantic` 2.14.1
  - `boto3` 1.43.114
  - `botocore` 1.43.114
  - `strands-decider` 0.1.0
  - `starlette` 1.8.0
  - `jinja2` 3.1.6
  - `urllib3` 2.8.0
- **Vulnerability Query (OSV API):** Queried Open Source Vulnerabilities database for all active runtime packages; **0 known vulnerabilities found**.

### Node.js Dependencies (`package.json`, `package-lock.json`)
- Tool executed: `npm audit`
- Result: **0 vulnerabilities found** (0 low, 0 moderate, 0 high, 0 critical).

---

## 4. Secrets & Cloud Credential Audit

1. **Git Repository History:**
   - Full history check (`git log --all --full-history -- "**/backend/.env" "**/.env"`) confirmed `.env` has never been committed.
   - Checked `.gitignore`: Contains hardened rules covering `.env`, `.env.*`, `*.key`, `*.pem`, `.aws/`, and credentials files.
2. **Secret Scanning in Codebase:**
   - Regex scan for AWS Access Key patterns (`AKIA...`) across all source code, tests, and documentation returned only test mock fixtures (`AKIAIOSFODNN7EXAMPLE_SECRET_TOKEN` in scrubbing assertions).
3. **Frontend Bundle Verification:**
   - Evaluated compiled JavaScript bundle in `dist/assets/`: Confirmed zero AWS secrets, backend database keys, or private environment variables are included in the frontend bundle. Only public `VITE_API_BASE_URL` is referenced.

---

## 5. AI Decision Engine & Evidence Integrity

1. **Stage 1 Strands Decider 2B Invariant:**
   - Strands Decider 2B remains the sole authority for the initial priority choice (`Critical`, `High`, `Medium`, `Low`) and emergency mitigation (`requires_emergency_mitigation`).
   - If Stage 2 (Bedrock) attempts to propose a divergent priority, the decision engine overrides it to strictly preserve Stage 1's decision.
2. **Stage 2 Amazon Bedrock Claude Sonnet 4.6 Grounding:**
   - Claude Sonnet 4.6 synthesizes explainable rationale, risk factors, and recommended security actions strictly grounded in normalized evidence inside `<untrusted_evidence_data>` tags.
3. **Calibrated Confidence Honesty:**
   - Confidence is explicitly labelled as uncalibrated distribution concentration (`confidence_is_calibrated: false`) to avoid misrepresenting heuristic or model distribution concentration as calibrated statistical probability.
4. **Degraded & Fallback Mode Transparency:**
   - When Bedrock fails after Decider succeeds, the system truthfully outputs `engine: "decider-only"`, `bedrock_status: "failed"`, and renders the amber Decider-only badge.
   - When both fail or are unauthorized, the system degrades to deterministic baseline heuristic with explicit `(AI fallback active)` notice.
5. **Evidence-Based Risk Validation Disagreements:**
   - `risk_validator` never overwrites the AI decision. If the AI model deviates from the organizational policy ruleset, the UI displays an explicit disagreement indicator with auditable findings.

---

## 6. Upstream Intelligence Source Resilience

1. **NIST NVD API 2.0:**
   - Includes timeout guards, exponential retry backoff, and full CVSS v3.1/v3.0/v2.0 extraction.
2. **FIRST.org EPSS:**
   - Handles not-found, timeouts, and preserves the empirical 30-day forecast disclaimer (EPSS is predictive probability, not confirmation of weaponization).
3. **CISA KEV & Seed Fallback:**
   - Bundled snapshot [`backend/app/data/cisa_kev_seed.json`](file:///d:/ThreatPrior%20AI/backend/app/data/cisa_kev_seed.json) preloads 1,227+ CVE entries on cold start.
   - When upstream live refresh fails (e.g. HTTP 403 from CDN block), the catalog cache is marked `is_stale: True`, upstream failure is recorded in `evidence_limitations`, and absent CVEs are **never** declared `NOT_LISTED` or safe.

---

## 7. Frontend Accessibility & UX Quality

1. **WCAG Compliance:**
   - Accessible names provided for `#cve-input` (`aria-label="Search CVE identifier"`) and `#searchInput` (`aria-label="Search analysis history"`).
   - Accordions on evidence sections (`#nvd-toggle`, `#cisa-toggle`, `#epss-toggle`) feature `aria-expanded` and `aria-controls`.
   - Main navigation tabs feature `aria-current="page"`.
   - KPI tiles and status notices feature `role="status"` and accessible labels.
2. **Visual Consistency:**
   - High contrast dark mode tailored with curated tokens.
   - Responsive layouts verified on mobile, tablet, and desktop viewports.

---

## 8. Test Execution Verification Baseline

```text
Backend Test Suite (pytest)
============================= 133 passed in 65.23s =============================
- Aggregator & Normalization: PASSED
- Strands Decider 2B Client & Adapter (local, remote, mock): PASSED
- Decision Engine (dual-ai, decider-only, baseline fallback): PASSED
- Evidence-Based Risk Validation Policy: PASSED
- Upstream Intelligence Clients (NVD, CISA KEV, EPSS): PASSED
- Security QA (Headers, Exception Sanitization, Rate Limiter Pruning, Input Limits): PASSED

Frontend Linter (oxlint)
Found 0 warnings and 0 errors. Finished in 37ms on 17 files.

Frontend Production Build (Vite v8.3.4)
✓ built in 153ms (dist/ generated with index.html, JS, and CSS chunks).

Playwright End-to-End Suite
============================= 35 passed in 1.1m =============================
- Vulnerability Analysis: 6 passed
- Analysis History & Triage Queue: 5 passed
- Integration & Upstream Failure Handling: 8 passed
- Navigation & Deep Linking: 4 passed
- Visual Screenshots: 1 passed
- Dual-Model AI Triage & Fallback Verification: 11 passed
```

---

## 9. Accepted Limitations

1. **CISA KEV Live CDN Egress Blocking (HTTP 403):**
   - Certain cloud hosting datacenter IP blocks (e.g. Blitz/Render egress) are denied direct access to CISA's official feed URL by federal CDN edge policies.
   - **Mitigation & Acceptance:** ThreatPrior AI safely loads the bundled seed catalog, discloses stale catalog state, surfaces the query failure in evidence limitations, and refuses to mark unlisted CVEs as safe.

---

## 10. Conclusion

Phase 5 has verified the production readiness, security posture, and architectural integrity of ThreatPrior AI. The system reliably safeguards credentials, handles input securely, prevents memory exhaustion, enforces defensive HTTP headers, preserves dual-AI decision provenance, and provides accessible, truthful vulnerability triage.
