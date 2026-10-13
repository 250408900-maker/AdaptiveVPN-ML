import csv
import re
import socket
import statistics
import subprocess
import time
from pathlib import Path

TARGET = "10.200.1.2"
PORT = 8443
INTERFACE = "veth-host"
from datetime import datetime

OUTPUT = Path(
    "data/processed/v4/linux_unseen_"
    + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    + ".csv"
)

SCENARIOS = {
    "LATENCY_150": ["delay", "150ms"],
    "LATENCY_250": ["delay", "250ms"],
    "LATENCY_300": ["delay", "300ms"],
    "JITTER": ["delay", "200ms", "40ms"],
}


def run(*args):
    return subprocess.run(args, capture_output=True, text=True)

def reset():
    run("sudo", "tc", "qdisc", "del", "dev", INTERFACE, "root")

def collect(label):
    durations = []
    failures = 0

    for _ in range(30):
        start = time.perf_counter()
        try:
            with socket.create_connection((TARGET, PORT), timeout=1.5):
                durations.append((time.perf_counter() - start) * 1000)
        except OSError:
            failures += 1
        time.sleep(0.05)

    result = run("ping", "-n", "-c", "30", "-i", "0.2",
                 "-W", "1", TARGET)
    match = re.search(r"([\d.]+)% packet loss", result.stdout)

    if not match:
        raise RuntimeError("Could not parse ping results")

    return {
        "scenario": label,
        "tcp_connect_mean_ms": statistics.mean(durations) if durations else "",
        "tcp_connect_std_ms": statistics.pstdev(durations) if durations else "",
        "tcp_failure_pct": failures / 30 * 100,
        "icmp_nonresponse_pct": float(match.group(1)),
    }

def main():
    rows = []
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    try:
        for label, settings in SCENARIOS.items():
            reset()

            if settings:
                result = run("sudo", "tc", "qdisc", "replace",
                             "dev", INTERFACE, "root", "netem",
                             *settings)
                if result.returncode:
                    raise RuntimeError(result.stderr)

            print("Testing", label, flush=True)
            row = collect(label)
            rows.append(row)

            print(row, flush=True)

    finally:
        reset()

    with OUTPUT.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("Saved:", OUTPUT)

if __name__ == "__main__":
    main()

