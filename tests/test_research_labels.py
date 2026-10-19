import pandas as pd

from model.build_features import label_sessions
from server.traffic_simulator import generate_dataset


def test_feature_builder_joins_independent_ground_truth(tmp_path):
    features = pd.DataFrame([{
        "session_id": "s1",
        "n_calls": 99,
        "n_lookup_calls": 99,
        "n_email_calls": 0,
        "max_records_requested": 500,
        "avg_time_between_calls": 0.001,
        "min_time_between_calls": 0.001,
        "recipient_mismatch_rate": 1.0,
    }])
    labels_path = tmp_path / "labels.csv"
    labels_path.write_text("session_id,scenario,label\ns1,normal,0\n", encoding="utf-8")

    result = label_sessions(features, labels_path)

    assert result.loc[0, "label"] == 0
    assert result.loc[0, "scenario"] == "normal"


def test_simulator_writes_separate_session_label_manifest(tmp_path):
    log_path, labels_path = generate_dataset(n_normal=3, n_attack=5, output_dir=tmp_path, seed=19)
    labels = pd.read_csv(labels_path)

    assert log_path.is_file()
    assert labels["session_id"].is_unique
    assert labels["label"].value_counts().to_dict() == {0: 3, 1: 5}
    assert set(labels.loc[labels["label"] == 1, "scenario"]).issubset({
        "run_attack_bulk_exfiltration", "run_attack_mismatched_recipient",
        "run_attack_rapid_fire", "run_attack_reconnaissance",
    })


def test_simulator_repeats_exactly_for_same_seed(tmp_path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_log, first_labels = generate_dataset(n_normal=3, n_attack=5, output_dir=first_dir, seed=23)
    second_log, second_labels = generate_dataset(n_normal=3, n_attack=5, output_dir=second_dir, seed=23)

    assert first_log.read_bytes() == second_log.read_bytes()
    assert first_labels.read_bytes() == second_labels.read_bytes()
