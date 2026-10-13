# AI-Based Anomaly Detection for MCP Server Traffic — Working Prototype

A complete, runnable end-to-end system: fake MCP server → simulated normal/attack
traffic → feature engineering → Isolation Forest anomaly detector → evaluation.

## Project Structure

```
mcp-security-project/
├── server/
│   ├── mcp_server.py         # Fake MCP server (2 tools: order lookup, send email)
│   └── traffic_simulator.py  # Generates normal sessions + 4 attack types
├── data/
│   ├── traffic_log.jsonl     # Raw request-level log (auto-generated)
│   └── session_features.csv  # Session-level feature table (auto-generated)
├── model/
│   ├── build_features.py     # Converts raw logs into ML feature vectors
│   └── train_and_evaluate.py # Trains Isolation Forest, evaluates, plots results
└── results/
    ├── evaluation_report.txt # Precision/Recall/F1/ROC-AUC + confusion matrix
    ├── confusion_matrix.png  # Visual confusion matrix
    └── baseline_vs_model.png # Baseline (0% detection) vs your model
```

## How to Run It Yourself

```bash
# 1. Generate simulated traffic (400 normal sessions, 80 attack sessions)
python3 server/traffic_simulator.py

# 2. Build ML features from the raw traffic log
python3 model/build_features.py

# 3. Train the anomaly detector and evaluate it
python3 model/train_and_evaluate.py
```

## What Each Attack Type Simulates

| Attack type | What it represents |
|---|---|
| `bulk_exfiltration` | Prompt injection tricking the agent into fetching ALL customer orders and emailing them to an attacker address |
| `mismatched_recipient` | Normal-looking lookup, but the email is silently redirected to an attacker's address |
| `rapid_fire` | A scripted bot hammering the lookup tool at inhuman speed (no natural pauses) |
| `reconnaissance` | Sequential order-ID guessing/probing to discover valid records |

## Actual Results From This Run

- **Precision:** 0.595
- **Recall (attack detection rate):** 0.917
- **F1-score:** 0.721
- **ROC-AUC:** 0.976
- **Baseline (no detection system):** 0.00 — every attack succeeds silently
- **Your model:** catches 91.7% of attacks vs 0% for the undefended baseline

These are the numbers to report in your paper's Results/Evaluation section.
The confusion matrix and bar chart in `results/` are ready to paste directly
into your paper or presentation slides.

## How This Maps to Your Paper

- **Section: System Design** → describe `mcp_server.py` (the MCP tool infrastructure)
  and the 7 engineered features (`n_calls`, `max_records_requested`,
  `avg_time_between_calls`, `recipient_mismatch_rate`, etc.)
- **Section: Methodology** → Isolation Forest, trained only on normal-labeled
  training data (unsupervised anomaly detection), contamination rate = 0.10
- **Section: Experimental Setup** → 480 total sessions (400 normal / 80 attack),
  70/30 train-test split, stratified
- **Section: Results** → the precision/recall/F1/ROC-AUC table above, plus both
  saved plots
- **Section: Limitations (be upfront about this)** → traffic is simulated, not
  from a real production MCP deployment; ground-truth labels are derived from
  simulator rules rather than human-verified real-world incidents; future work
  should validate against real or honeypot-collected MCP traffic

## Part 2: Real AI Agent + Real MCP Protocol (New)

The `real_mcp/` folder contains a **genuine** MCP server (built with
Anthropic's official `mcp` SDK, real protocol, verified working) and a
**genuine** LLM-driven agent (via Ollama) that actually decides which
tools to call — not scripted. This lets you test real prompt injection
against a real model and observe real outcomes, then validate that your
anomaly detector (trained on the simulated data above) still catches the
resulting attack traffic.

See `real_mcp/SETUP_GUIDE.md` for full setup instructions (requires
installing Ollama on your own machine — this component needs local LLM
inference that cannot run in a sandboxed environment).

```
mcp-security-project/
├── real_mcp/
│   ├── real_mcp_server.py       # Real, protocol-compliant MCP server
│   ├── agent.py                 # Real LLM agent (Ollama-driven tool calling)
│   ├── attack_prompts.py        # Real prompt-injection attack messages
│   ├── run_real_attack_demo.py  # Runs attacks through the real agent
│   ├── evaluate_real_traffic.py # Scores real traffic with your trained model
│   └── SETUP_GUIDE.md           # Full setup instructions
```

## Part 3: MCP Guardian — The Deployable Extension (New)

The `mcp_guardian/` folder is the actual **productized tool**: a real-time,
per-request anomaly detector any MCP server can be protected with — either
via a Python decorator (if your server is Python) or a language-agnostic
**reverse proxy** (works with any MCP server, any language, zero code
changes to it).

**100% free, MIT licensed.** No paid APIs required to run it.

```
mcp_guardian/
├── guardian.py                 # Core detection engine (hybrid rules + ML)
├── realtime_model.joblib       # Pre-trained model (per-request granularity)
├── build_realtime_features.py  # Rebuilds training data at per-request level
├── train_realtime_model.py     # Retrains the model (contamination=0.06, tuned)
├── demo_live_protection.py     # Decorator usage demo
├── README.md                   # Full quickstart + integration guide
└── proxy/
    ├── proxy_server.py         # Language-agnostic reverse proxy (FastAPI)
    ├── cli.py                  # `mcp-guardian-proxy` installed CLI command
    ├── risk_profiles.py        # Generic, configurable per-tool risk signals
    ├── example_config.json     # Example risk profile config
    ├── fake_upstream_server.py # Test double for verifying the proxy
    ├── static/                 # Pre-built React dashboard (ready to serve)
    └── dashboard-react-src/    # React dashboard source (for customization)
```

**Install and run:**
```bash
pip install -e .
mcp-guardian-proxy --upstream http://localhost:YOUR_PORT --config mcp_guardian/proxy/example_config.json --port 8000
```
Then point your AI agent at `http://localhost:8000/mcp` instead of your real
server directly, and view live traffic at `http://localhost:8000/guardian/dashboard`.

**Automated tests** (`tests/test_guardian.py`, 10/10 passing) verify: normal
traffic passes, bulk/rapid-fire/redirected-email attacks are blocked, the
decorator genuinely prevents the wrapped function from executing when
blocked, sensitivity tuning shifts the decision boundary correctly, and
allow-listing works.

**Verified metrics after calibration fixes** (real-time, per-request model):
precision 0.832, recall 0.917, F1 0.872 — improved from an initial
precision of 0.673 after discovering and fixing an Isolation Forest
contamination-parameter miscalibration that was causing ~35% false
positives on the most common normal traffic pattern.

## Next Steps to Strengthen the Paper

1. **Tune the model:** try Random Forest (supervised) as a second model and
   compare — since you do have labels here, a supervised baseline is a fair
   comparison point against the unsupervised Isolation Forest.
2. **Add a real LLM case study:** run 5-10 real prompt-injection attempts
   through an actual LLM (e.g., via the Anthropic API) connected to a real
   MCP server, and show your detector catching the resulting abnormal traffic
   — this strengthens real-world credibility alongside the simulated bulk results.
3. **False-positive analysis:** manually inspect the 15 false positives (normal
   sessions wrongly flagged) to explain *why* they were flagged — useful
   discussion material for your paper.
