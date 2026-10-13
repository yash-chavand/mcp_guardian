"""
Evaluates the REAL agent's traffic (real_traffic_log.jsonl, produced by the
actual Ollama-driven agent talking to the real MCP server) using the SAME
anomaly detector that was trained on simulated data.

This is the key experiment that ties everything together: it shows whether
a model trained on simulated traffic generalizes to catch real attacks
against a real LLM agent -- including cases where the LLM itself was
fooled into making a bad tool call.

Run this AFTER:
    1. python model/train_and_evaluate.py         (trains + saves the model)
    2. python real_mcp/run_real_attack_demo.py     (generates real traffic)
"""

import json
import sys
import joblib
import pandas as pd
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "model"))
from build_features import session_features  # reuse the exact same feature logic

DATA_DIR = Path(__file__).parent.parent / "data"
MODEL_PATH = Path(__file__).parent.parent / "model" / "trained_isolation_forest.joblib"
REAL_LOG_PATH = DATA_DIR / "real_traffic_log.jsonl"


def main():
    if not REAL_LOG_PATH.exists():
        print(f"No real traffic log found at {REAL_LOG_PATH}")
        print("Run 'python real_mcp/run_real_attack_demo.py' first.")
        return

    if not MODEL_PATH.exists():
        print(f"No trained model found at {MODEL_PATH}")
        print("Run 'python model/train_and_evaluate.py' first.")
        return

    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_cols = bundle["feature_cols"]

    records = [json.loads(l) for l in open(REAL_LOG_PATH)]
    feat_df = session_features(records)

    X = feat_df[feature_cols]
    raw_preds = model.predict(X)
    feat_df["predicted_attack"] = (raw_preds == -1).astype(int)
    feat_df["anomaly_score"] = -model.decision_function(X)

    print("=" * 60)
    print("REAL AGENT TRAFFIC - ANOMALY DETECTION RESULTS")
    print("=" * 60)
    for _, row in feat_df.sort_values("anomaly_score", ascending=False).iterrows():
        flag = "🚩 FLAGGED AS ATTACK" if row["predicted_attack"] else "   normal"
        try:
            print(f"{flag}  | session={row['session_id'][:8]}  score={row['anomaly_score']:.3f}  "
                  f"calls={row['n_calls']}  max_records={row['max_records_requested']}  "
                  f"mismatch_rate={row['recipient_mismatch_rate']:.2f}")
        except UnicodeEncodeError:
            ascii_flag = "[FLAGGED AS ATTACK]" if row["predicted_attack"] else "   normal"
            print(f"{ascii_flag}  | session={row['session_id'][:8]}  score={row['anomaly_score']:.3f}  "
                  f"calls={row['n_calls']}  max_records={row['max_records_requested']}  "
                  f"mismatch_rate={row['recipient_mismatch_rate']:.2f}")

    out_path = DATA_DIR / "real_traffic_scored.csv"
    feat_df.to_csv(out_path, index=False)
    print(f"\nFull scored table saved to: {out_path}")


if __name__ == "__main__":
    main()
