"""Measure local SDK overhead against a no-op callable; outputs raw environment metadata."""

import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_guardian import GuardianConfig, MCPGuardian, ToolCallContext, __version__


def percentile(values, pct):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * pct))]


def main(samples=100):
    guardian = MCPGuardian(
        verbose=False, log_path=None,
        config=GuardianConfig(enable_sqlite=False),
    )
    def direct(value):
        return value
    baseline_ns = []
    protected_ns = []
    for i in range(samples + 10):
        context = ToolCallContext("benchmark_lookup", {"value": i}, "bench", f"bench-{i}")
        start = time.perf_counter_ns()
        direct(i)
        elapsed_direct = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        guardian.invoke(context, direct)
        elapsed_protected = time.perf_counter_ns() - start
        if i >= 10:
            baseline_ns.append(elapsed_direct / 1_000_000)
            protected_ns.append(elapsed_protected / 1_000_000)
    output = {
        "samples": samples,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "mcp_guardian": __version__,
        "ml_model_loaded": guardian.ml_scorer.model is not None,
        "baseline_noop_ms": {"median": statistics.median(baseline_ns), "p95": percentile(baseline_ns, .95)},
        "protected_call_ms": {"median": statistics.median(protected_ns), "p95": percentile(protected_ns, .95)},
        "measured_median_overhead_ms": statistics.median(protected_ns) - statistics.median(baseline_ns),
        "warning": "Synthetic no-op microbenchmark; not representative of transport or production workload.",
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
