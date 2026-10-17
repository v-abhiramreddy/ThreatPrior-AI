# ThreatPrior AI

> **Explainable, Dual-Stage AI Vulnerability Prioritization with Strands Decider 2B, Amazon Bedrock, and Evidence-Based Risk Validation.**

ThreatPrior AI replaces static CVSS-based triage and hallucination-prone single-prompt LLM evaluation with a deterministic evidence aggregation layer, a verified local/remote System-1 fast choice model (**Strands Decider 2B**), an explainable System-2 reasoning synthesizer (**Amazon Bedrock**), and a deterministic organizational risk validation policy.

---

## Key Capabilities

1. **Multi-Source Threat Intelligence Synthesis**:
   - **NIST NVD**: Live CVSS v3.1 / v2 metrics, vector strings, published dates, and affected CPE configurations.
   - **CISA KEV**: Real-time detection of confirmed active in-the-wild exploitation under Binding Operational Directive 22-01.
   - **FIRST.org EPSS**: Empirical 30-day forward-looking predictive probability of weaponization.
   - Non-safety preservation: CISA KEV absence (`NOT_LISTED`) is explicitly treated as lack of confirmation, never as "safe."

2. **Dual-Stage AI Decision Architecture**:
   - **Stage 1 (System-1 Fast Decision)**: [Strands Decider 2B](https://github.com/strands-labs/strands-decider) (`StrandsAgents/strands-decider-2B-qwen3.5-v1-2610`) evaluates normalized evidence to output a constrained priority choice (`Critical`, `High`, `Medium`, `Low`), raw choice probabilities, uncalibrated distribution peakedness confidence, and emergency operational mitigation requirements.
   - **Stage 2 (System-2 Grounded Synthesis)**: Amazon Bedrock (`amazon.nova-lite-v1:0`, `au.anthropic.claude-sonnet-4-6`, `us.anthropic.claude-sonnet-4-6`, etc.) synthesizes explainable rationale, risk factors, and actionable remediation playbooks grounded strictly within `<untrusted_evidence_data>` guardrails.
   - **Graceful Truthful Degradation**: If Bedrock is unavailable or unauthorized, the engine cleanly degrades to `decider-only` mode; if both AI stages are bypassed, it falls back to a transparent deterministic baseline without misrepresenting AI participation.

3. **Evidence-Based Risk Policy Validation (v2026.1-policy)**:
   - Evaluates normalized telemetry against deterministic organizational policy rules.
   - Highlights policy alignment (`aligned`) or discrepancy (`disagreement`) between model output and policy findings.
   - Protects against false safety assumptions: failed KEV queries yield `insufficient_evidence` (never `NOT_LISTED`), and missing EPSS data is never assumed to be zero risk.

4. **Modern High-Density Security Operator UI**:
   - Real-time vulnerability analysis dashboard with telemetry chips, confidence explanations, and actionable remediation steps.
   - Audit trail history with search, filtering, and CSV export capabilities.

---

## Architecture Overview

```
[ Security Operator / API Request ]
                │
                ▼
      FastAPI Backend Engine
                │
   ┌────────────┴──────────────────────┐
   ▼                                   ▼
[ NVD REST v2 ]      [ CISA KEV JSON ]      [ FIRST.org EPSS v3 ]
   └────────────┬──────────────────────┘
                │ Normalized Telemetry & Provenance
                ▼
   ┌───────────────────────────────────────────────────┐
   │  Stage 1: Strands Decider 2B (System-1 Inference) │
   │  • Priority Choice Distribution                   │
   │  • Emergency Out-of-Band Mitigation Flag          │
   └────────────────────┬──────────────────────────────┘
                        │ Stage 1 Decision State
                        ▼
   ┌───────────────────────────────────────────────────┐
   │  Stage 2: Amazon Bedrock (System-2 Rationale)     │
   │  • Grounded Rationale Synthesis                   │
   │  • Actionable Remediation Guidance                │
   └────────────────────┬──────────────────────────────┘
                        │
                        ▼
   ┌───────────────────────────────────────────────────┐
   │  Evidence-Based Risk Validation Layer (v2026.1)   │
   │  • Deterministic Policy Audit                     │
   │  • Disagreement / Alignment Detection             │
   └────────────────────┬──────────────────────────────┘
                        │
                        ▼
           Vite + React UI Dashboard
```

---

## Quick Start

### 1. Prerequisites
- **Python**: 3.10 to 3.12 (Python 3.12 recommended)
- **Node.js**: v18+ (Node 20+ recommended)
- **Git**

### 2. Environment Setup

Clone the repository and copy the environment template:

```bash
git clone https://github.com/v-abhiramreddy/ThreatPrior-AI.git
cd ThreatPrior-AI

# Create backend .env from template
cp .env.example backend/.env
```

Edit `backend/.env` to configure your preferences:
- `STRANDS_DECIDER_MODE=local` (runs in-process CPU PyTorch inference) or `remote` (calls a running `strands-decider serve` instance).
- Optional: `NVD_API_KEY` for higher rate limits.
- AWS credentials and configuration for Bedrock (`AWS_REGION=ap-southeast-2` or `us-east-1`, and `BEDROCK_MODEL_ID=au.anthropic.claude-sonnet-4-6`, `us.anthropic.claude-sonnet-4-6`, or `amazon.nova-lite-v1:0`).

### 3. Backend Setup & Launch

```bash
cd backend
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-dev.txt

uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The API service is available at `http://127.0.0.1:8000`.  
Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

### 4. Frontend Setup & Launch

In a new terminal window from the repository root:

```bash
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## Production Single-Service Deployment (Render)

ThreatPrior AI supports single-service deployment where a single Render Web Service runs FastAPI/Uvicorn to serve both the compiled React frontend (`dist/`) and all `/api/*` REST endpoints on the assigned `$PORT`.

### Recommended Option: Render Docker Runtime (Deterministic)

Render natively supports multi-stage Docker builds, ensuring reproducible builds with both Node.js 20 (for compiling TypeScript/React) and Python 3.12 (for FastAPI and AI models):

1. **Service Type**: Web Service
2. **Environment**: `Docker`
3. **Dockerfile Path**: `Dockerfile`
4. **Docker Context**: `.`
5. **Environment Variables**:
   - `AWS_ACCESS_KEY_ID`: Your AWS access key ID
   - `AWS_SECRET_ACCESS_KEY`: Your AWS secret access key
   - `AWS_REGION`: `ap-southeast-2` (or `us-east-1`)
   - `BEDROCK_MODEL_ID`: `au.anthropic.claude-sonnet-4-6` (or `us.anthropic.claude-sonnet-4-6` / `amazon.nova-lite-v1:0`)
   - `STRANDS_DECIDER_MODE`: `auto` (or `local`)
   - `VITE_API_BASE_URL`: *(Leave empty / unset for single-service same-origin deployment)*

### Alternative Option: Render Native Shell (build.sh)

If using a native environment with both Node.js and Python available:
- **Build Command**: `chmod +x build.sh && ./build.sh`
- **Start Command**: `uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port $PORT`

---

## Running Tests

### Backend Unit & Regression Suite (`pytest`)

```bash
cd backend
pytest -v
```

Includes 70 automated tests covering:
- Aggregator and upstream API clients (NVD, CISA KEV, EPSS with failure handling).
- Strands Decider 2B adapter (local and remote modes, probability parsing, error recovery).
- Amazon Bedrock dual-model orchestration and prompt injection isolation.
- Evidence-based risk validation layer regression tests across all policy edge cases.

### Frontend Production Build & Linting

```bash
# Type check and build
npm run build

# Fast linter
npm run lint
```

### End-to-End Test Suite (`Playwright`)

```bash
npx playwright test
```

Includes 29 end-to-end tests verifying:
- Full vulnerability triage workflow and live telemetry presentation.
- Dual-model, decider-only, and baseline fallback states.
- Evidence-based risk validation alignment, disagreement badges, and missing data alerts.
- Triage queue filtering, search, and CSV export.

---

## Security & DevSecOps Principles

- **Zero Hardcoded Secrets**: All keys and credentials are read strictly from environment variables or `.env` files ignored by Git.
- **Fail-Safe Operation**: If external threat feeds or AI services fail, the service maintains complete transparency, logging upstream errors and degrading gracefully without hallucinating false safety.
- **Input Sanitization**: Strict CVE identifier syntax validation (`CVE-YYYY-NNNNN`) and prompt boundary enforcement (`<untrusted_evidence_data>`) prevent prompt injection attacks.

---

## License

This project is licensed under the Apache 2.0 License.
