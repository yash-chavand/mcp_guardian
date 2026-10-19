# IEEE paper readiness

## Current assessment

The repository is not ready to support a strong empirical claim that MCP Guardian detects real-world attacks or outperforms other defenses. It now has reproducible synthetic results and a reusable policy library, but the main benchmark is intentionally simple: deterministic rules and supervised logistic regression score perfectly, while Isolation Forest has a 15.2% false-positive rate. The HTTP and stdio gateways have not passed full MCP protocol conformance or live multi-agent tests. The existing system-level risk-fusion path is not the object evaluated by the new harness.

The most defensible paper at this stage would describe the architecture and present the simulator study explicitly as a pilot, with no claim of production detection efficacy. A competitive security paper needs a sharper contribution and independent evidence.

## Work needed before making effectiveness claims

1. **State a testable contribution.** Specify what Guardian adds over MCP client approval prompts, server-side authorization, static policy engines, and generic anomaly detection. Identify the mechanism and why it is technically novel.
2. **Define the threat model.** Identify attacker access, prompt/tool poisoning assumptions, compromised agents or servers, protected assets, and out-of-scope attacks. Define the enforcement boundary and bypass paths.
3. **Validate transports.** Run official MCP SDK client/server conformance tests and record exact SDK/client versions. Cover initialization, protocol negotiation, tool discovery/call, error handling, notifications, timeouts, cancellation, reconnect/session behavior, and child process failure.
4. **Test real agent clients.** At minimum, exercise the same instrumented backend through multiple named clients and record tool traces, outcomes, versions, OS, and configuration. Separate agent policy refusals from Guardian blocks using upstream handler counters and Guardian decision logs.
5. **Build an independent evaluation set.** Include realistic benign multi-tool workflows and attacks authored independently from the detector features. Hold out entire attack families and servers, include adaptive/low-and-slow cases, and report labeling protocol and adjudication. Do not train/tune on the final test set.
6. **Compare appropriate methods.** Include least-privilege allowlists, explicit rules, a supervised reference when labels are available, Isolation Forest, and the complete Guardian system. Add ablations for rules, ML, session/graph signals, and fusion. Explain threshold selection and cost of false positives versus missed attacks.
7. **Report uncertainty and failures.** Use paired scenarios where possible, suitable confidence intervals or bootstrap procedures, per-family recall, false-positive rate, precision-recall curves, latency/throughput under realistic load, and all failures. Avoid one-run headline metrics.
8. **Document reproducibility and ethics.** Publish scripts/configs, hashes, software versions, random seeds, data-generation process, limitations, and a safe release of any collected traces. Do not publish secrets or sensitive prompts/logs.

## Suggested manuscript structure

Abstract; Introduction and contributions; Background and related work; Threat model and requirements; Guardian architecture and enforcement path; Policy/decision methods; Experimental design and datasets; Baselines and ablations; Results with uncertainty; Case studies and failure analysis; Performance; Limitations and validity threats; Ethics and responsible release; Conclusion; references.

Use an official IEEE conference template only after selecting a target venue and checking its current author instructions. Do not fill gaps with invented experiments, claims, or citations. The repository's current results and transport limitations are summarized in [RESEARCH_RESULTS.md](RESEARCH_RESULTS.md), [IMPLEMENTATION_AUDIT.md](IMPLEMENTATION_AUDIT.md), and [TRANSPORT_COMPATIBILITY.md](TRANSPORT_COMPATIBILITY.md).
