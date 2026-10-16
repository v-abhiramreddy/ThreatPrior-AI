# Remote Strands Decider 2B Server Setup Guide

This document describes how to deploy the official [strands-decider](https://github.com/strands-labs/strands-decider) HTTP server in a supported Linux/WSL2 environment and connect ThreatPrior AI to it for genuine System-1 vulnerability triage inference.

---

## 1. Supported Platform & Hardware Requirements

| Requirement | Supported Specifications |
|---|---|
| **Operating System** | Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+) or Windows Subsystem for Linux (WSL2 with NVIDIA CUDA support) |
| **Python** | Python 3.10 – 3.12 |
| **Accelerator** | NVIDIA GPU (CUDA 12.1+, >=6 GB VRAM recommended), Apple Silicon (MPS), or CPU (>=8 threads) |
| **Model Checkpoint** | `StrandsAgents/strands-decider-2B-qwen3.5-v1-2610` (Hugging Face) |

> **Note on Windows Hosts:** Local in-process inference (`load_engine()`) on native Windows hosts is prevented by OS security policy restrictions on PyTorch native C++ runtime DLLs (`WinError 4551`). The remote HTTP server architecture documented here is the official and supported way to run genuine Strands Decider 2B alongside ThreatPrior AI on Windows.

---

## 2. Server Installation & Execution

### Step 2.1 — Create Virtual Environment and Install Dependencies

In your Linux/WSL environment:

```bash
# Create dedicated virtual environment
python3 -m venv ~/strands-decider-env
source ~/strands-decider-env/bin/activate

# Install PyTorch (select CUDA version matching your driver, or CPU)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu124

# Install official strands-decider package
pip install strands-decider
```

### Step 2.2 — Launch Official Strands Decider Server

Run the official server CLI command:

```bash
# NVIDIA GPU (CUDA)
strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8080 --device cuda

# Or via Python module execution:
python3 -m strands_decider.server StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8080 --device cuda

# CPU Fallback (if no dedicated GPU available)
strands-decider serve StrandsAgents/strands-decider-2B-qwen3.5-v1-2610 --port 8080 --device cpu --threads 8
```

The server binds to `127.0.0.1:8080` by default.

---

## 3. Security Requirements & Network Topology

> **CRITICAL SECURITY INVARIANT:**
> The official `strands-decider` HTTP server contains **no built-in authentication, authorization, rate limiting, or TLS encryption**.
> **NEVER expose the server port (`8080`) directly to the public internet or an untrusted local network.**

Use one of the following secure topologies:

### Topology A: Local Machine (WSL2 / Local Container on Same Host)
When running ThreatPrior AI and Strands Decider on the same physical workstation:
- Strands Decider listens on `127.0.0.1:8080` inside WSL2 or host.
- ThreatPrior AI connects directly via `http://127.0.0.1:8080` (or `http://localhost:8080`).

### Topology B: Remote Linux GPU Server via SSH Tunnel (Recommended)
When running Strands Decider on a remote cloud instance or homelab GPU server:
1. Leave the server bound strictly to `127.0.0.1:8080` on the remote server.
2. From the machine running ThreatPrior AI, establish an encrypted SSH local port forward:
   ```bash
   ssh -N -L 8080:127.0.0.1:8080 user@remote-gpu-server
   ```
3. ThreatPrior AI connects to `http://127.0.0.1:8080` locally through the encrypted, authenticated SSH tunnel.

### Topology C: Authenticated Private Overlay Network
If using a mesh VPN like Tailscale or WireGuard:
- Bind the server to the node's private WireGuard/Tailscale IP.
- Configure host firewall rules (`iptables` / `ufw`) to restrict port 8080 strictly to authorized ThreatPrior AI client IPs.

### Topology D: Authenticated Reverse Proxy
For production microservice deployment:
- Place an Nginx, Caddy, or Envoy reverse proxy in front of `127.0.0.1:8080`.
- Enforce TLS (HTTPS) and mTLS or Bearer token authorization headers.

---

## 4. ThreatPrior AI Configuration

Configure ThreatPrior AI backend environment variables in `backend/.env`:

```ini
# Strands Decider 2B Remote Server URL
STRANDS_DECIDER_URL=http://127.0.0.1:8080

# Strands Decider Mode:
# 'remote' - requires reachable remote server; raises error if unavailable
# 'auto'   - attempts remote server first; falls back to baseline/mock if unreachable
STRANDS_DECIDER_MODE=remote

# Strands Decider Checkpoint Model Identifier
STRANDS_DECIDER_MODEL_ID=StrandsAgents/strands-decider-2B-qwen3.5-v1-2610

# Strands Decider System-1 Inference Timeout (seconds)
STRANDS_DECIDER_TIMEOUT_SECONDS=8.0
```

---

## 5. Verification & Health Checks

### Step 5.1 — Verify Remote Server Health
Test the server health endpoint from the command line:

```bash
curl -s http://127.0.0.1:8080/health
```

Expected response (`200 OK`):
```json
{
  "status": "ok",
  "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
  "checkpoint": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
  "base_model": "Qwen/Qwen2.5-0.5B",
  "device": "cuda:0",
  "temperature": 1.0
}
```

### Step 5.2 — Smoke Test System-1 Endpoint
Test genuine inference via `POST /v1/systemone`:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/systemone \
  -H "Content-Type: application/json" \
  -d '{
    "state": "Vulnerability Identifier: CVE-2021-44228\nCVSS Base Score: 10.0\nCISA KEV Listed: YES\nEPSS Probability: 97.4%",
    "questions": {
      "priority": {
        "type": "choice",
        "instructions": "Assign the triage priority based on the observed threat telemetry.",
        "criteria": {
          "Critical": "Active exploitation in CISA KEV with critical CVSS.",
          "High": "Elevated exploit potential.",
          "Medium": "Moderate severity.",
          "Low": "Low severity rating."
        }
      },
      "requires_emergency_mitigation": {
        "type": "noul",
        "instructions": "Does this vulnerability require immediate out-of-band operational isolation?",
        "criteria": {
          "true": "Active exploitation requiring immediate isolation.",
          "false": "Standard patch assessment."
        }
      }
    }
  }'
```

Expected response:
```json
{
  "model": "StrandsAgents/strands-decider-2B-qwen3.5-v1-2610",
  "answers": {
    "priority": {
      "choice": "Critical",
      "probabilities": { "Critical": 0.96, "High": 0.03, "Medium": 0.005, "Low": 0.005 },
      "confidence": 0.9467
    },
    "requires_emergency_mitigation": {
      "noul": 0.98,
      "probabilities": { "true": 0.98, "false": 0.02 }
    }
  },
  "latency_ms": 14.8
}
```

### Step 5.3 — Verify ThreatPrior AI End-to-End Triage
With the server running and `STRANDS_DECIDER_URL=http://127.0.0.1:8080`, execute a triage request:

```bash
curl -s http://127.0.0.1:8000/api/vulnerabilities/CVE-2021-44228/triage
```

The response will contain:
- `engine_type`: `"dual-ai"` (when Amazon Bedrock is also configured) or `"decider-only"`
- `model_id`: `"StrandsAgents/strands-decider-2B-qwen3.5-v1-2610"`
- `strands_decider.status`: `"SUCCESS"`
- `strands_decider.confidence_is_calibrated`: `false` (uncalibrated probability concentration score)
- `strands_decider.priority_probabilities`: complete softmax distribution
- `strands_decider.requires_emergency_mitigation`: `true`
