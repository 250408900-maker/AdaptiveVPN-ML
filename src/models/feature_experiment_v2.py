
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    f1_score,
    recall_score,
)

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "data/processed/dataset_v2_clean.csv"

df = pd.read_csv(DATASET)

excluded = [
    "label",
    "capture_file",
    "window_start_s",
    "window_end_s",
]

all_features = [
    c for c in df.columns if c not in excluded
]

quality_features = [
    "avg_tcp_ack_rtt_ms",
    "std_tcp_ack_rtt_ms",
    "retransmission_rate",
    "reset_rate",
]

no_volume_features = [
    c for c in all_features
    if c not in [
        "packet_count",
        "total_bytes",
        "throughput_kbps",
        "tcp_packets",
        "udp_packets",
        "icmp_packets",
        "flow_count",
        "retransmissions",
    ]
]

experiments = {
    "ALL FEATURES": all_features,
    "QUALITY ONLY": quality_features,
    "WITHOUT TRAFFIC VOLUME": no_volume_features,
}

y = df["label"]
groups = df["capture_file"]

cv = LeaveOneGroupOut()
results = []

print("\n=== ADAPTIVEVPN-ML FEATURE EXPERIMENT ===")

for name, features in experiments.items():

    X = df[features].apply(
        pd.to_numeric, errors="raise"
    )

    if X.isna().any().any():
        raise ValueError(f"Missing values in {name}")

    predictions = pd.Series(
        index=df.index,
        dtype="str",
    )

    for train_idx, test_idx in cv.split(X, y, groups):

        model = RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )

        model.fit(
            X.iloc[train_idx],
            y.iloc[train_idx],
        )

        predictions.iloc[test_idx] = model.predict(
            X.iloc[test_idx]
        )

    accuracy = accuracy_score(y, predictions)
    balanced = balanced_accuracy_score(y, predictions)
    macro_f1 = f1_score(
        y, predictions, average="macro"
    )

    recalls = recall_score(
        y,
        predictions,
        labels=["NORMAL", "PACKET_LOSS"],
        average=None,
        zero_division=0,
    )

    results.append({
        "experiment": name,
        "features": len(features),
        "accuracy": round(accuracy * 100, 2),
        "balanced_accuracy": round(balanced * 100, 2),
        "macro_f1": round(macro_f1, 4),
        "normal_recall": round(recalls[0] * 100, 2),
        "loss_recall": round(recalls[1] * 100, 2),
    })

print("\n=== COMPARISON ===")
print(pd.DataFrame(results).to_string(index=False))

print("\n=== EXPERIMENT COMPLETE ===")
