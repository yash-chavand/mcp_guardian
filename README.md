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
# Reproduce the synthetic benchmark over 30 generated datasets/seeds.
# Outputs are isolated from the legacy figures/reports under results/.
python model/research_experiment.py --runs 30 --seed-start 20261019 --output-dir artifacts/paper_reproduction
```

## What Each Attack Type Simulates

| Attack type | What it represents |
|---|---|
| `bulk_exfiltration` | Prompt injection tricking the agent into fetching ALL customer orders and emailing them to an attacker address |
| `mismatched_recipient` | Normal-looking lookup, but the email is silently redirected to an attacker's address |
| `rapid_fire` | A scripted bot hammering the lookup tool at inhuman speed (no natural pauses) |
| `reconnaissance` | Sequential order-ID guessing/probing to discover valid records |

## Research results status

The metrics and plots already committed under `results/` are legacy outputs
and are **withdrawn from research use**. The former feature builder derived
ground-truth labels from the same engineered features used by the classifiers,
creating circular evaluation. The current generator writes a separate
session-label manifest, and `model/research_experiment.py` runs repeated
synthetic trials against explicit-rule, supervised, unsupervised, and allow-all
baselines. Do not cite the legacy metrics. New synthetic results still do not
establish performance on real MCP deployments or AI agents.

## How This Maps to Your Paper

- **Section: System Design** → describe `mcp_server.py` (the MCP tool infrastructure)
  and the 7 engineered features (`n_calls`, `max_records_requested`,
  `avg_time_between_calls`, `recipient_mismatch_rate`, etc.)
- **Section: Methodology** → Isolation Forest, trained only on normal-labeled
  training data (unsupervised anomaly detection), contamination rate = 0.10
- **Experimental Setup** → report independent generated data seeds, scenario
  mix, stratified split, model settings, environment, and input hashes from
  each run manifest
- **Results** → use repeated-run summaries and per-run CSV output; include
  uncertainty and false-positive rates
- **Limitations** → traffic remains synthetic, attack patterns are narrow, and
  evaluation against independently authored real-agent traffic is still needed

## Part 2: MCP SDK and Ollama Example

The `real_mcp/` folder contains an example MCP server and an Ollama-backed
agent intended for exploratory testing. This path is separate from Guardian's
agent-client integration path and was not independently verified in the
current validation pass. Do not treat it as protocol-conformance evidence.
Record client, model, prompt, server, and SDK versions before interpreting
any results.

See `real_mcp/SETUP_GUIDE.md` for full setup instructions (requires
installing Ollama on your own machine — this component needs local LLM
inference that cannot run in a sandboxed environment).

```
real_mcp/
├── real_mcp_server.py       # MCP SDK server example
├── agent.py                 # Ollama-backed agent example
├── attack_prompts.py        # Exploratory prompt-injection cases
├── run_real_attack_demo.py  # Example agent run
├── evaluate_real_traffic.py # Scores example traffic
└── SETUP_GUIDE.md           # Local setup instructions
```

## Part 3: MCP Guardian — The Deployable Extension (New)

The `mcp_guardian/` folder contains an experimental security gateway with a
Python callable wrapper and HTTP/stdio proxy prototypes. The proxy protocol
behavior is not fully verified, and the Python wrapper protects only calls
that pass through it. See [`docs/TRANSPORT_COMPATIBILITY.md`](docs/TRANSPORT_COMPATIBILITY.md)
and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) before use.

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
    ├── cli.py                  # `mcp-guardian-shield-proxy` installed CLI command
    ├── risk_profiles.py        # Generic, configurable per-tool risk signals
    ├── example_config.json     # Example risk profile config
    ├── fake_upstream_server.py # Test double for verifying the proxy
    ├── static/                 # Pre-built React dashboard (ready to serve)
    └── dashboard-react-src/    # React dashboard source (for customization)
```

**Install and run:**
```bash
python -m pip install -e ".[proxy,ml]"
mcp-guardian-shield-proxy --upstream http://localhost:YOUR_PORT --config mcp_guardian/proxy/example_config.json --guardian-config examples/agent_configs/guardian-policy.json --port 8000
```
Then point your AI agent at `http://localhost:8000/mcp` instead of your real
server directly, and view live traffic at `http://localhost:8000/guardian/dashboard`.

The repository originally reported 10/10 tests for its prototype. The current
checkout has an expanded suite; see `docs/IMPLEMENTATION_AUDIT.md` for the
latest executed results. Those tests do not establish complete MCP protocol
compatibility or production security.

Previously reported synthetic metrics are retired because of the circular
labeling issue described above. New results must come from independent
simulator labels and the repeated-run experiment.

## Developer quickstart

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the Python SDK, JSON
configuration, approval flow, and CLI examples. The selected distribution
name is `mcp-guardian-shield`; it was not registered on PyPI when checked on
2026-10-19, but this project has not been published. See
[`docs/AGENT_TESTING.md`](docs/AGENT_TESTING.md) for setup flows and config
examples for Claude Desktop/Code, Cursor, and VS Code/Copilot.

## Paper-readiness checklist

The reproducibility harness improves the synthetic study, but a defensible
security paper still needs an independently authored test set, realistic benign
agent workflows, adaptive/evasion cases, cross-agent integration runs, an
ablation study, and repeated false-positive analysis. The current synthetic
benchmark alone is not sufficient evidence for broad security claims.
