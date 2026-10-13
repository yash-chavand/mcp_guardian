"""
Feature Engineering

Reads the raw request-level traffic log, groups requests into sessions,
and converts each session into a numeric feature vector the ML model
can learn from.

Ground-truth attack labels are inferred here ONLY for evaluation purposes
(we know which generator produced which session because we control the
simulator) -- the anomaly model itself never sees these labels during
training, since Isolation Forest is unsupervised.
"""

import json
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
LOG_PATH = DATA_DIR / "traffic_log.jsonl"


def load_raw_log():
    records = []
    with open(LOG_PATH) as f:
        for line in f:
            records.append(json.loads(line))
    return records


def session_features(records):
    """Group raw requests by session_id and compute per-session features."""
    df = pd.DataFrame(records)
    df = df.sort_values("timestamp")

    rows = []
    for sid, grp in df.groupby("session_id"):
        grp = grp.sort_values("timestamp")
        n_calls = len(grp)
        n_lookup = (grp["tool"] == "get_customer_order").sum()
        n_email = (grp["tool"] == "send_email").sum()

        max_records = grp.get("records_requested", pd.Series([1] * n_calls)).fillna(1).max()

        # timing features
        timestamps = grp["timestamp"].values
        if len(timestamps) > 1:
            deltas = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            avg_delta = sum(deltas) / len(deltas)
            min_delta = min(deltas)
        else:
            avg_delta = -1  # sentinel: single-call session
            min_delta = -1

        # email legitimacy feature
        email_rows = grp[grp["tool"] == "send_email"]
        if len(email_rows) > 0:
            recipient_mismatch_rate = 1 - email_rows["recipient_matches_last_lookup"].fillna(False).mean()
        else:
            recipient_mismatch_rate = 0

        rows.append({
            "session_id": sid,
            "n_calls": n_calls,
            "n_lookup_calls": n_lookup,
            "n_email_calls": n_email,
            "max_records_requested": max_records,
            "avg_time_between_calls": avg_delta,
            "min_time_between_calls": min_delta,
            "recipient_mismatch_rate": recipient_mismatch_rate,
        })

    return pd.DataFrame(rows)


def label_sessions(records, feature_df):
    """
    Infer ground-truth label per session using simple, transparent rules that
    match exactly how the simulator generated attacks (used ONLY for evaluation,
    never fed to the unsupervised model as a training signal).
    """
    labels = []
    for _, row in feature_df.iterrows():
        is_attack = (
            row["max_records_requested"] > 1                      # bulk exfiltration
            or row["recipient_mismatch_rate"] > 0                 # redirected email
            or (row["min_time_between_calls"] != -1 and row["min_time_between_calls"] < 0.1)  # rapid-fire bot
            or row["n_lookup_calls"] >= 5                          # reconnaissance / bulk pattern
        )
        labels.append(1 if is_attack else 0)
    feature_df = feature_df.copy()
    feature_df["label"] = labels
    return feature_df


def build_and_save():
    records = load_raw_log()
    feat_df = session_features(records)
    feat_df = label_sessions(records, feat_df)
    out_path = DATA_DIR / "session_features.csv"
    feat_df.to_csv(out_path, index=False)
    print(f"Built {len(feat_df)} session feature rows -> {out_path}")
    print(feat_df["label"].value_counts().rename({0: "normal", 1: "attack"}))
    return feat_df


if __name__ == "__main__":
    build_and_save()
