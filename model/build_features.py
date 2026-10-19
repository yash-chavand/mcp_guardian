"""
Feature Engineering

Reads the raw request-level traffic log, groups requests into sessions,
and converts each session into a numeric feature vector the ML model
can learn from.

Ground-truth attack labels are joined from a separate simulator manifest.
Feature construction does not infer or alter the ground-truth labels.
"""

import json
import argparse
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
LOG_PATH = DATA_DIR / "traffic_log.jsonl"


def load_raw_log(log_path=LOG_PATH):
    records = []
    with open(log_path, encoding="utf-8") as f:
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
            recipient_mismatch_rate = 1 - email_rows["recipient_matches_last_lookup"].astype("boolean").fillna(False).mean()
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


def label_sessions(feature_df, labels_path):
    """
    Join simulator-assigned ground truth by session ID, independently of features.
    """
    labels = pd.read_csv(labels_path)
    required = {"session_id", "scenario", "label"}
    if not required.issubset(labels.columns):
        raise ValueError(f"Ground-truth file must contain columns: {sorted(required)}")
    if labels["session_id"].duplicated().any():
        raise ValueError("Ground-truth file contains duplicate session IDs")
    if not set(labels["label"].unique()).issubset({0, 1}):
        raise ValueError("Ground-truth labels must be binary 0/1")
    observed = set(feature_df["session_id"])
    expected = set(labels["session_id"])
    if observed != expected:
        raise ValueError(
            f"Traffic and ground-truth sessions differ: "
            f"{len(observed - expected)} unlabeled, {len(expected - observed)} without traffic"
        )
    return feature_df.merge(labels, on="session_id", how="left", validate="one_to_one")


def build_and_save(log_path=LOG_PATH, labels_path=None, output_path=None):
    log_path = Path(log_path)
    labels_path = Path(labels_path) if labels_path else log_path.with_name("session_labels.csv")
    output_path = Path(output_path) if output_path else log_path.with_name("session_features.csv")
    records = load_raw_log(log_path)
    feat_df = session_features(records)
    feat_df = label_sessions(feat_df, labels_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    feat_df.to_csv(output_path, index=False)
    print(f"Built {len(feat_df)} session feature rows -> {output_path}")
    print(feat_df["label"].value_counts().rename({0: "normal", 1: "attack"}))
    return feat_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build per-session features and join independent labels")
    parser.add_argument("--log", default=str(LOG_PATH), help="Raw traffic JSONL path")
    parser.add_argument("--labels", default=None, help="Independent session label CSV (defaults beside log)")
    parser.add_argument("--output", default=None, help="Feature CSV output path (defaults beside log)")
    args = parser.parse_args()
    build_and_save(args.log, args.labels, args.output)
