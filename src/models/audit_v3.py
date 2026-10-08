
from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/processed/v3")
files = sorted(DATA_DIR.glob("*_features.csv"))

if not files:
    raise SystemExit("No V3 feature files found.")

frames = []

for file in files:
    df = pd.read_csv(file)

    if df.empty:
        print(f"WARNING: Empty file: {file.name}")
        continue

    df["capture_id"] = file.stem.replace("_features", "")
    frames.append(df)

if not frames:
    raise SystemExit("No usable V3 data.")

data = pd.concat(frames, ignore_index=True)

metrics = [
    "tcp_connect_mean_ms",
    "tcp_connect_std_ms",
    "tcp_failure_pct",
    "icmp_nonresponse_pct",
    "probe_sent",
]

for column in metrics:
    if column in data.columns:
        data[column] = pd.to_numeric(
            data[column], errors="coerce"
        )

print("\n" + "=" * 55)
print("ADAPTIVEVPN-ML — V3 DATA AUDIT")
print("=" * 55)

print(f"\nTotal windows: {len(data)}")
print(f"Total captures: {data['capture_id'].nunique()}")

print("\nWINDOWS BY CONDITION")
print(data.groupby("label").agg(
    windows=("label", "size"),
    captures=("capture_id", "nunique"),
).to_string())

print("\nNETWORK MEASUREMENTS BY CONDITION")

for metric in metrics:
    if metric not in data.columns:
        print(f"\nMissing metric: {metric}")
        continue

    print(f"\n{metric}")
    print(
        data.groupby("label")[metric]
        .agg(["mean", "std", "min", "max"])
        .round(2)
        .to_string()
    )

print("\nDATA QUALITY")

numeric = data.select_dtypes(include="number")
missing = numeric.isna().sum()
missing = missing[missing > 0]

if missing.empty:
    print("No missing numeric values.")
else:
    print("Missing numeric values:")
    print(missing.to_string())

if "window_start_s" in data.columns:
    duplicates = data.duplicated(
        subset=["capture_id", "window_start_s"]
    ).sum()
    print(f"Duplicate capture/windows: {duplicates}")

print("\nIMPORTANT:")
print("Raw probe counts depend on sampling frequency.")
print("Do not treat probe_sent as an independent")
print("network-quality measurement.")

print("\nAUDIT COMPLETE")
