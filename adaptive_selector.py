"""Adaptive protocol selection using a reproducible UCB1 multi-armed bandit.

This component reads historical network observations from network_data.csv and
uses them to warm-start a bandit over the VPN protocol arms: wireguard,
openvpn, and vless. The model focuses on quality metrics observed in the CSV,
normalizes missing values safely, and stores its learned state in
model/adaptive_selector_state.json.
"""

import argparse
import csv
import json
import math
import os
import sys
from collections import defaultdict

ARMS = ["wireguard", "openvpn", "vless"]
METRICS = [
    ("latency_ms", "lower"),
    ("packet_loss_percent", "lower"),
    ("jitter_ms", "lower"),
    ("download_mbps", "higher"),
    ("upload_mbps", "higher"),
]

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(PROJECT_ROOT, "network_data.csv")
STATE_PATH = os.path.join(PROJECT_ROOT, "model", "adaptive_selector_state.json")


def normalize_protocol_name(value):
    """Return a canonical lowercase protocol name for model tracking."""
    if value is None:
        return ""
    normalized = str(value).strip().lower()
    aliases = {
        "wireguard": "wireguard",
        "wg": "wireguard",
        "openvpn": "openvpn",
        "ovpn": "openvpn",
        "vless": "vless",
        "vless/xray": "vless",
        "xray": "vless",
        "direct": "direct",
        "none": "direct",
    }
    return aliases.get(normalized, normalized)


def read_csv_rows(csv_path):
    """Read rows from a CSV file, returning an empty list on failure."""
    try:
        with open(csv_path, "r", newline="", encoding="utf-8") as csv_file:
            return list(csv.DictReader(csv_file))
    except (FileNotFoundError, OSError):
        return []


def parse_float(value):
    """Convert CSV values to float or return None for empty/invalid values."""
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    try:
        number = float(text)
        if math.isnan(number) or math.isinf(number):
            return None
        return number
    except ValueError:
        return None


def metric_values_by_field(rows):
    """Collect valid numeric values for each metric across all rows."""
    values = defaultdict(list)
    for row in rows:
        for metric_name, _ in METRICS:
            parsed = parse_float(row.get(metric_name))
            if parsed is not None:
                values[metric_name].append(parsed)
    return values


def metric_score(value, metric_values, direction):
    """Convert a metric value to a 0..1 score according to its optimization direction."""
    if value is None:
        return 0.0
    if not metric_values:
        return 0.0
    minimum = min(metric_values)
    maximum = max(metric_values)
    if maximum == minimum:
        return 1.0

    normalized = (value - minimum) / (maximum - minimum)
    if direction == "lower":
        return 1.0 - normalized
    return normalized


def quality_reward(row, metric_lookup):
    """Calculate a 0..100 reward for a single row.

    We reject rows where latency and packet loss are both missing because they do
    not provide enough information for a reliable quality assessment.
    """
    latency = parse_float(row.get("latency_ms"))
    packet_loss = parse_float(row.get("packet_loss_percent"))
    if latency is None and packet_loss is None:
        return None

    available_metrics = []
    for metric_name, direction in METRICS:
        value = parse_float(row.get(metric_name))
        if value is not None:
            available_metrics.append((metric_name, direction, value))

    if not available_metrics:
        return None

    total_score = 0.0
    for metric_name, direction, value in available_metrics:
        values_for_metric = metric_lookup.get(metric_name, [])
        total_score += metric_score(value, values_for_metric, direction)

    weight = 1.0 / len(available_metrics)
    return total_score * weight * 100.0


def historical_rows_for_training(csv_path):
    """Return valid historical rows that can warm-start the bandit."""
    rows = read_csv_rows(csv_path)
    valid_rows = []
    metric_lookup = metric_values_by_field(rows)
    for row in rows:
        protocol = normalize_protocol_name(row.get("protocol"))
        if protocol not in ARMS:
            continue
        if quality_reward(row, metric_lookup) is None:
            continue
        valid_rows.append((protocol, row, metric_lookup))
    return valid_rows


def initialize_state():
    """Create a fresh bandit state with zero counts and rewards."""
    state = {arm: {"count": 0, "total_reward": 0.0, "average_reward": 0.0} for arm in ARMS}
    state["seen_observations"] = []
    return state


def ensure_parent_dir(path):
    """Ensure the parent directory for the JSON state exists."""
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def save_state(state, state_path=STATE_PATH):
    """Persist the bandit state JSON to disk."""
    ensure_parent_dir(state_path)
    with open(state_path, "w", newline="", encoding="utf-8") as output_file:
        json.dump(state, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def load_state(state_path=STATE_PATH):
    """Load the persisted bandit state, creating a new one if missing."""
    if not os.path.exists(state_path):
        state = initialize_state()
        save_state(state, state_path)
        return state

    try:
        with open(state_path, "r", encoding="utf-8") as input_file:
            state = json.load(input_file)
    except (OSError, ValueError):
        state = initialize_state()
        save_state(state, state_path)
        return state

    if not isinstance(state, dict):
        state = initialize_state()
        save_state(state, state_path)
        return state

    for arm in ARMS:
        entry = state.get(arm, {})
        if not isinstance(entry, dict):
            entry = {}
        entry.setdefault("count", 0)
        entry.setdefault("total_reward", 0.0)
        entry["average_reward"] = float(entry.get("total_reward", 0.0)) / max(1, int(entry.get("count", 0)))
        state[arm] = entry
    if "seen_observations" not in state or not isinstance(state["seen_observations"], list):
        state["seen_observations"] = []
    return state


def train_from_dataset(csv_path=DATASET_PATH, state_path=STATE_PATH, exclude_signature=None):
    """Warm-start the bandit from valid historical observations in the CSV."""
    rows = read_csv_rows(csv_path)
    if not rows:
        state = initialize_state()
        save_state(state, state_path)
        return state

    metric_lookup = metric_values_by_field(rows)
    state = initialize_state()
    for row in rows:
        protocol = normalize_protocol_name(row.get("protocol"))
        if protocol not in ARMS:
            continue
        signature = observation_signature(
            protocol,
            timestamp=row.get("timestamp"),
            host=row.get("target_host"),
            latency=row.get("latency_ms"),
            loss=row.get("packet_loss_percent"),
            jitter=row.get("jitter_ms"),
            download=row.get("download_mbps"),
            upload=row.get("upload_mbps"),
        )
        if exclude_signature is not None and signature == exclude_signature:
            continue
        reward = quality_reward(row, metric_lookup)
        if reward is None:
            continue
        state[protocol]["count"] += 1
        state[protocol]["total_reward"] += reward

    for arm in ARMS:
        count = state[arm]["count"]
        total = state[arm]["total_reward"]
        state[arm]["average_reward"] = total / count if count else 0.0
    save_state(state, state_path)
    return state


def select_ucb_arm(state):
    """Return the arm with the highest UCB1 score using deterministic tie-breaking."""
    total_trials = sum(state[arm]["count"] for arm in ARMS)
    if total_trials == 0:
        return ARMS[0]

    best_arm = None
    best_score = None
    for arm in ARMS:
        count = state[arm]["count"]
        avg = state[arm]["average_reward"]
        if count == 0:
            score = float("inf")
        else:
            exploration = math.sqrt((2.0 * math.log(total_trials)) / count)
            score = avg + exploration
        if best_score is None or score > best_score or (math.isclose(score, best_score) and arm < best_arm):
            best_arm = arm
            best_score = score

    return best_arm if best_arm is not None else ARMS[0]


def explain_ucb(state, arm=None):
    """Return a human-readable explanation of the UCB score for a given arm."""
    if arm is None:
        arm = select_ucb_arm(state)
    total_trials = sum(state[a]["count"] for a in ARMS)
    count = state[arm]["count"]
    avg = state[arm]["average_reward"]
    if count == 0:
        return f"{arm}: untried arm; default UCB score = infinity until an observation is recorded."
    exploration = math.sqrt((2.0 * math.log(total_trials)) / count)
    score = avg + exploration
    return (
        f"{arm}: average_reward={avg:.3f}, count={count}, exploration_bonus={exploration:.3f}, "
        f"UCB score={score:.3f}"
    )


def recommend_protocol(csv_path=DATASET_PATH, state_path=STATE_PATH):
    """Recommend the next protocol using the persisted state or a warm start."""
    if not os.path.exists(state_path):
        state = train_from_dataset(csv_path, state_path)
    else:
        state = load_state(state_path)
    arm = select_ucb_arm(state)
    return arm, state, explain_ucb(state, arm)


def canonicalize_value(value):
    """Normalize a metric or metadata value so duplicate checks are stable across CSV and in-memory forms."""
    if value is None:
        return ""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return ""
        numeric = parse_float(stripped)
        if numeric is not None:
            return f"{float(numeric):.2f}"
        return stripped
    numeric = parse_float(value)
    if numeric is not None:
        return f"{float(numeric):.2f}"
    return str(value).strip()


def observation_signature(protocol, timestamp=None, host=None, latency=None, loss=None, jitter=None, download=None, upload=None):
    """Create a deterministic signature for a measured observation to prevent duplicates."""
    payload = {
        "protocol": normalize_protocol_name(protocol),
        "timestamp": canonicalize_value(timestamp),
        "host": canonicalize_value(host),
        "latency_ms": canonicalize_value(latency),
        "packet_loss_percent": canonicalize_value(loss),
        "jitter_ms": canonicalize_value(jitter),
        "download_mbps": canonicalize_value(download),
        "upload_mbps": canonicalize_value(upload),
    }
    return json.dumps(payload, sort_keys=True)


def record_measurement_from_row(protocol, timestamp, host, latency=None, loss=None, jitter=None, download=None, upload=None, state_path=STATE_PATH):
    """Update the selector with a completed row once, preventing duplicate CSV rows."""
    normalized = normalize_protocol_name(protocol)
    if normalized not in ARMS:
        return False, None

    signature = observation_signature(
        normalized,
        timestamp=timestamp,
        host=host,
        latency=latency,
        loss=loss,
        jitter=jitter,
        download=download,
        upload=upload,
    )

    state = load_state(state_path)
    if signature in state.get("seen_observations", []):
        return False, None

    row = {
        "latency_ms": "" if latency is None else str(latency),
        "packet_loss_percent": "" if loss is None else str(loss),
        "jitter_ms": "" if jitter is None else str(jitter),
        "download_mbps": "" if download is None else str(download),
        "upload_mbps": "" if upload is None else str(upload),
    }
    metric_lookup = metric_values_by_field([row])
    reward = quality_reward(row, metric_lookup)
    if reward is None:
        return False, None

    state[normalized]["count"] += 1
    state[normalized]["total_reward"] += reward
    state[normalized]["average_reward"] = state[normalized]["total_reward"] / state[normalized]["count"]
    state["seen_observations"].append(signature)
    save_state(state, state_path)
    return True, reward


def update_state(protocol, latency=None, loss=None, jitter=None, download=None, upload=None, state_path=STATE_PATH):
    """Update the collapsed bandit state with a new observation."""
    normalized = normalize_protocol_name(protocol)
    if normalized not in ARMS:
        raise ValueError(f"Unsupported protocol: {protocol}")

    metrics = {
        "latency_ms": latency,
        "packet_loss_percent": loss,
        "jitter_ms": jitter,
        "download_mbps": download,
        "upload_mbps": upload,
    }
    row = {key: ("" if value is None else str(value)) for key, value in metrics.items()}

    metric_lookup = metric_values_by_field([row])
    reward = quality_reward(row, metric_lookup)
    if reward is None:
        raise ValueError("Reward could not be computed: latency and packet loss cannot both be missing.")

    state = load_state(state_path)
    state[normalized]["count"] += 1
    state[normalized]["total_reward"] += reward
    state[normalized]["average_reward"] = state[normalized]["total_reward"] / state[normalized]["count"]
    save_state(state, state_path)
    return state, reward


def print_status(state_path=STATE_PATH):
    """Print the current state and UCB context for each arm."""
    state = load_state(state_path)
    total_trials = sum(state[arm]["count"] for arm in ARMS)
    print("Adaptive selector status")
    print("-" * 50)
    print(f"State file: {state_path}")
    print(f"Total observations: {total_trials}")
    for arm in ARMS:
        count = state[arm]["count"]
        avg = state[arm]["average_reward"]
        print(f"{arm}: count={count}, average_reward={avg:.3f}")
    print("-" * 50)
    for arm in ARMS:
        print(explain_ucb(state, arm))


def main():
    """Parse CLI arguments and dispatch the correct bandit action."""
    parser = argparse.ArgumentParser(description="AdaptiveVPN-ML UCB1 protocol selector")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("train", help="Warm-start the bandit from historical network_data.csv observations")

    subparsers.add_parser("recommend", help="Recommend the next protocol using the current bandit state")

    subparsers.add_parser("status", help="Print the persisted bandit state and UCB scores")

    update_parser = subparsers.add_parser("update", help="Feed a single observation into the selector")
    update_parser.add_argument("--protocol", required=True, help="Protocol to update (wireguard, openvpn, or vless)")
    update_parser.add_argument("--latency", type=float, default=None, help="Observed latency in ms")
    update_parser.add_argument("--loss", type=float, default=None, help="Observed packet loss percentage")
    update_parser.add_argument("--jitter", type=float, default=None, help="Observed jitter in ms")
    update_parser.add_argument("--download", type=float, default=None, help="Observed download throughput in Mbps")
    update_parser.add_argument("--upload", type=float, default=None, help="Observed upload throughput in Mbps")

    args = parser.parse_args()

    if args.command == "train":
        state = train_from_dataset(DATASET_PATH, STATE_PATH)
        print("Trained adaptive selector from historical observations.")
        for arm in ARMS:
            entry = state[arm]
            print(f"{arm}: count={entry['count']}, average_reward={entry['average_reward']:.3f}")
        return 0

    if args.command == "recommend":
        arm, state, explanation = recommend_protocol(DATASET_PATH, STATE_PATH)
        print(f"Recommended protocol: {arm}")
        print(explanation)
        return 0

    if args.command == "status":
        print_status(STATE_PATH)
        return 0

    if args.command == "update":
        try:
            _, reward = update_state(
                args.protocol,
                latency=args.latency,
                loss=args.loss,
                jitter=args.jitter,
                download=args.download,
                upload=args.upload,
                state_path=STATE_PATH,
            )
            print(f"Updated {normalize_protocol_name(args.protocol)} with reward={reward:.3f}")
            print_status(STATE_PATH)
            return 0
        except ValueError as error:
            print(f"Error: {error}", file=sys.stderr)
            return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
