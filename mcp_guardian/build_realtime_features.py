"""
Rebuilds the training dataset at PER-REQUEST granularity instead of
per-session. This is required for a real deployable tool: a session-level
detector can only judge an attack after it's already finished, but a real
security extension must score and block each request AS IT ARRIVES,
mid-session, before damage is done.

Each row = one tool call, with features computed only from that call plus
everything that happened earlier IN THE SAME SESSION (no lookahead into the
future -- this matches exactly what would be knowable in a live deployment).
"""

import json
import pandas as pd
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(__file__).parent.parent / "data"
LOG_PATH = DATA_DIR / "traffic_log.jsonl"


def build_realtime_features():
    records = [json.loads(l) for l in open(LOG_PATH)]
    df = pd.DataFrame(records).sort_values("timestamp")

    session_history = defaultdict(list)  # session_id -> list of past request dicts
    rows = []

    for _, r in df.iterrows():
        sid = r["session_id"]
        history = session_history[sid]

        # -- records requested by THIS call --
        if r["tool"] == "get_customer_order":
            records_this_call = r.get("records_requested", 1)
            if pd.isna(records_this_call):
                records_this_call = 1
        else:
            records_this_call = 0

        cumulative_records = sum(h["records"] for h in history) + records_this_call
        call_index = len(history) + 1

        time_since_last = -1
        if history:
            time_since_last = r["timestamp"] - history[-1]["ts"]

        recipient_mismatch = 0
        if r["tool"] == "send_email":
            val = r.get("recipient_matches_last_lookup")
            recipient_mismatch = 0 if val else 1

        tool_is_email = 1 if r["tool"] == "send_email" else 0

        rows.append({
            "session_id": sid,
            "request_id": r["request_id"],
            "call_index_in_session": call_index,
            "records_requested": records_this_call,
            "cumulative_records_in_session": cumulative_records,
            "time_since_last_call": time_since_last,
            "recipient_mismatch": recipient_mismatch,
            "tool_is_email": tool_is_email,
        })

        history.append({"ts": r["timestamp"], "records": records_this_call})

    feat_df = pd.DataFrame(rows)

    # ---- ground-truth label per REQUEST (for evaluation only) ----
    def label_row(row):
        return int(
            row["cumulative_records_in_session"] > 1
            or row["recipient_mismatch"] == 1
            or (row["time_since_last_call"] != -1 and row["time_since_last_call"] < 0.1)
            or row["call_index_in_session"] >= 5
        )

    feat_df["label"] = feat_df.apply(label_row, axis=1)

    out_path = DATA_DIR / "request_level_features.csv"
    feat_df.to_csv(out_path, index=False)
    print(f"Built {len(feat_df)} per-request feature rows -> {out_path}")
    print(feat_df["label"].value_counts().rename({0: "normal", 1: "attack-like"}))
    return feat_df


if __name__ == "__main__":
    build_realtime_features()
