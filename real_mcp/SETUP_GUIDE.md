# Real AI Agent + MCP Integration — Setup Guide

This folder contains a **genuine** MCP server and a **genuine** LLM-driven AI
agent — not simulated traffic. The server uses Anthropic's official `mcp`
Python SDK and speaks the real protocol; the agent uses a real local LLM
(via Ollama) that actually reads messages and decides which tools to call.
This is what lets you test REAL prompt injection: whether the attack
succeeds is not scripted, it's a genuine outcome of the LLM's own behavior.

## Files

| File | What it is |
|---|---|
| `real_mcp_server.py` | A real, spec-compliant MCP server (2 tools: order lookup, send email) |
| `agent.py` | The real AI agent: connects to the server via the actual MCP client protocol, uses Ollama for reasoning |
| `attack_prompts.py` | 5 real prompt-injection attack messages + 3 benign messages |
| `run_real_attack_demo.py` | Runs all messages through the real agent, reports which attacks fooled the LLM |
| `evaluate_real_traffic.py` | Scores the real traffic using your already-trained anomaly detector |

**Already verified working in this environment:** the MCP server itself
starts correctly, registers both tools per the real protocol, executes tool
calls, and logs them in the correct schema (confirmed via direct testing).
**Requires your machine to run:** the LLM reasoning step (Ollama), since
this sandboxed environment cannot download model weights.

## Setup (run on your own machine)

### 1. Install Ollama
Download and install from **https://ollama.com/download** (Windows/Mac/Linux).

### 2. Pull a tool-calling-capable model
```bash
ollama pull llama3.2
```
(Alternatives: `qwen2.5`, `mistral-nemo` — any Ollama model that supports
function/tool calling. Larger models generally follow instructions — and
resist injection — better, but `llama3.2` is a good free starting point.)

### 3. Install Python dependencies
```bash
pip install mcp ollama joblib
```

### 4. Confirm Ollama is running
```bash
ollama list
```
This should show `llama3.2` in the list. If `ollama serve` isn't already
running in the background, Ollama's installer typically starts it
automatically as a service.

## Running the Full Experiment

Run these **in order**, from the `mcp-security-project` root folder:

```bash
# 1. (If not already done) train the anomaly detector on simulated data
python model/train_and_evaluate.py

# 2. Run real benign + attack messages through the REAL agent
python real_mcp/run_real_attack_demo.py

# 3. Score the resulting REAL traffic with your trained detector
python real_mcp/evaluate_real_traffic.py
```

## What You'll Get

**From Step 2** (`results/real_agent_attack_report.json`):
- For each of the 5 attack messages, whether the LLM actually made a
  dangerous tool call (bulk fetch, or emailing an `evil.com` address)
- A summary: "LLM fooled by X/5 real prompt injection attempts"
- This is your **vulnerability demonstration** — proof the attack surface
  is real, not assumed

**From Step 3** (printed output + `data/real_traffic_scored.csv`):
- Every real session, scored by your anomaly detector, flagged as normal
  or attack
- This is your **defense demonstration** — proof your detector catches
  the dangerous sessions, including ones where the LLM itself was fooled

## Why This Matters for Your Paper

This closes the loop your professor is asking about:

1. **Real AI agent** — an actual LLM (not scripted) deciding tool calls
2. **Real MCP protocol** — genuine client/server communication, not a
   simplified stand-in
3. **Real attack outcomes** — you observe, rather than assume, whether
   prompt injection succeeds against a real model
4. **Real defense validation** — your detector (trained only on simulated
   data) is tested against genuinely LLM-generated traffic, showing it
   generalizes beyond its training distribution — a much stronger claim
   than testing only on simulated data

## Honest Limitations to State in Your Paper

- `llama3.2` (or whichever small local model you use) is less capable than
  production models like GPT-4 or Claude — it may be fooled more, or less,
  easily than a production agent would be. Note this as a scope limitation.
- The number of real attack trials (5 in `attack_prompts.py`) is small;
  for a stronger paper, expand this list to 20-30 varied injection attempts
  before your final experiments.
- You can freely add more messages to `attack_prompts.py` — the more
  variety, the more statistically meaningful your "LLM fooled rate" result.
