import csv
import re
import subprocess
import time
from pathlib import Path

INTERFACE = "veth-host"
TARGET = "10.200.1.2"
OUTPUT = Path("data/processed/linux_netem_results.csv")

SCENARIOS = {
    "NORMAL": [],
    "HIGH_LATENCY": ["delay", "200ms"],
    "PACKET_LOSS": ["loss", "30%"],
    "JITTER": ["delay", "100ms", "40ms"],
}

def run(command):
    return subprocess.run(
        command, text=True, capture_output=True
    )

def clear():
    run(["sudo", "tc", "qdisc", "del",
         "dev", INTERFACE, "root"])

def measure(label):
    result = run([
        "ping", "-n", "-c", "30", "-i", "0.2",
        "-W", "1", TARGET
    ])
    output = result.stdout
    loss = re.search(r"([\d.]+)% packet loss", output)
    rtt = re.search(
        r"(?:rtt|round-trip) min/avg/max/mdev = "
        r"([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
        output
    )
    return {
        "scenario": label,
        "timestamp": int(time.time()),
        "packet_loss_pct": float(loss.group(1)) if loss else None,
        "rtt_avg_ms": float(rtt.group(2)) if rtt else None,
        "rtt_jitter_ms": float(rtt.group(4)) if rtt else None,
    }

def main():
    if not Path("/sys/class/net/" + INTERFACE).exists():
        raise SystemExit("Virtual interface missing: " + INTERFACE)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    try:
        for label, settings in SCENARIOS.items():
            clear()
            if settings:
                result = run([
                    "sudo", "tc", "qdisc", "replace",
                    "dev", INTERFACE, "root", "netem",
                    *settings
                ])
                if result.returncode:
                    raise RuntimeError(result.stderr)

            print("Testing", label, flush=True)
            row = measure(label)
            rows.append(row)
            print(row, flush=True)

    finally:
        clear()

    with OUTPUT.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("Saved:", OUTPUT)

if __name__ == "__main__":
    main()
