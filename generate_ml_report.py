"""Generate a visual summary and markdown report from the adaptive selector state.

The script reads the persisted UCB1 state JSON and writes two artifacts to the
reports directory:
- reports/ml_selector_summary.png
- reports/ml_selector_report.md

It intentionally reads the actual state file and never invents or overwrites the
model state itself.
"""

import argparse
import json
import math
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from adaptive_selector import ARMS, load_state, recommend_protocol

DEFAULT_STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "adaptive_selector_state.json")
DEFAULT_REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")


def protocol_ucb_score(state, arm):
    """Return the UCB1 score for a single protocol arm."""
    total_trials = sum(int(state.get(a, {}).get("count", 0)) for a in ARMS)
    count = int(state.get(arm, {}).get("count", 0))
    average_reward = float(state.get(arm, {}).get("average_reward", 0.0))

    if count == 0:
        return float("inf")
    if total_trials == 0:
        return float("inf")

    exploration = math.sqrt((2.0 * math.log(total_trials)) / count)
    return average_reward + exploration


def protocol_exploration_bonus(state, arm):
    """Return the exploration bonus used in the UCB1 formula."""
    total_trials = sum(int(state.get(a, {}).get("count", 0)) for a in ARMS)
    count = int(state.get(arm, {}).get("count", 0))
    if count == 0 or total_trials == 0:
        return float("inf")
    return math.sqrt((2.0 * math.log(total_trials)) / count)


def choose_recommended_arm(state):
    """Return the currently recommended protocol using the same UCB1 logic as the selector."""
    candidate_arms = list(ARMS)
    if not candidate_arms:
        return None

    best_arm = candidate_arms[0]
    best_score = protocol_ucb_score(state, best_arm)

    for arm in candidate_arms[1:]:
        current_score = protocol_ucb_score(state, arm)
        if current_score > best_score:
            best_arm = arm
            best_score = current_score
    return best_arm, best_score


def ensure_directory(path):
    """Create the target directory if it does not already exist."""
    Path(path).mkdir(parents=True, exist_ok=True)


def generate_summary_plot(state, output_path):
    """Create a PNG summary chart with reward, counts, and UCB score by protocol."""
    ensure_directory(os.path.dirname(output_path))

    protocols = list(ARMS)
    avg_rewards = [float(state.get(arm, {}).get("average_reward", 0.0)) for arm in protocols]
    counts = [int(state.get(arm, {}).get("count", 0)) for arm in protocols]
    ucb_scores = [protocol_ucb_score(state, arm) for arm in protocols]
    recommended_arm, _ = choose_recommended_arm(state)

    fig, axes = plt.subplots(2, 2, figsize=(12, 8), constrained_layout=True)
    fig.suptitle("AdaptiveVPN-ML Selector Summary", fontsize=14, fontweight="bold")

    ax1 = axes[0, 0]
    colors1 = ["gold" if arm == recommended_arm else "steelblue" for arm in protocols]
    ax1.bar(protocols, avg_rewards, color=colors1)
    ax1.set_title("Average reward by protocol")
    ax1.set_ylabel("Reward (0-100)")
    ax1.grid(axis="y", linestyle="--", alpha=0.3)

    ax2 = axes[0, 1]
    colors2 = ["gold" if arm == recommended_arm else "darkorange" for arm in protocols]
    ax2.bar(protocols, counts, color=colors2)
    ax2.set_title("Observation count by protocol")
    ax2.set_ylabel("Count")
    ax2.grid(axis="y", linestyle="--", alpha=0.3)

    ax3 = axes[1, 0]
    colors3 = ["gold" if arm == recommended_arm else "forestgreen" for arm in protocols]
    ax3.bar(protocols, ucb_scores, color=colors3)
    ax3.set_title("Current UCB score by protocol")
    ax3.set_ylabel("UCB score")
    ax3.grid(axis="y", linestyle="--", alpha=0.3)

    ax4 = axes[1, 1]
    ax4.axis("off")
    ax4.text(
        0.05,
        0.75,
        f"Recommended protocol: {recommended_arm}",
        fontsize=14,
        fontweight="bold",
        color="darkgreen",
    )
    ax4.text(
        0.05,
        0.45,
        "Preliminary UCB1 result based on current state only.",
        fontsize=11,
        color="dimgray",
    )
    ax4.text(
        0.05,
        0.20,
        "These results are not final research conclusions.",
        fontsize=10,
        color="dimgray",
    )

    plt.savefig(output_path, dpi=200)
    plt.close(fig)


def generate_markdown_report(state, output_path):
    """Write a Markdown explanation of the selector state and current recommendation."""
    ensure_directory(os.path.dirname(output_path))

    total_observations = sum(int(state.get(arm, {}).get("count", 0)) for arm in ARMS)
    recommended_arm, recommended_score = choose_recommended_arm(state)

    lines = []
    lines.append("# Adaptive Selector Report")
    lines.append("")
    lines.append("- algorithm: UCB1 online learning")
    lines.append(f"- total observations: {total_observations}")
    lines.append(f"- current recommendation: {recommended_arm} (UCB score={recommended_score:.3f})")
    lines.append("")
    lines.append("## Protocol breakdown")
    lines.append("")
    lines.append("| protocol | count | average reward | exploration bonus | UCB score |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")

    for arm in ARMS:
        count = int(state.get(arm, {}).get("count", 0))
        avg = float(state.get(arm, {}).get("average_reward", 0.0))
        bonus = protocol_exploration_bonus(state, arm)
        score = protocol_ucb_score(state, arm)
        if count == 0:
            avg_text = "0.000"
            bonus_text = "untried"
            score_text = "infinite"
        else:
            avg_text = f"{avg:.3f}"
            bonus_text = f"{bonus:.3f}"
            score_text = f"{score:.3f}"
        lines.append(f"| {arm} | {count} | {avg_text} | {bonus_text} | {score_text} |")

    lines.append("")
    lines.append("## Reward design")
    lines.append("")
    lines.append(
        "The adaptive selector assigns a 0–100 quality reward by combining latency, packet loss, jitter, download speed, and upload speed. Lower latency, packet loss, and jitter are better; higher download and upload throughput are better. Missing values are excluded from the active metric set and the remaining weights are renormalized across the available values, so no fabricated metric values are used."
    )
    lines.append("")
    lines.append("## Limitation")
    lines.append("")
    lines.append(
        "Historical protocols were not tested in fully controlled paired rounds, so these results are best interpreted as early, preliminary online-learning evidence rather than final research conclusions."
    )
    lines.append("")
    lines.append("## Preliminary interpretation")
    lines.append("")
    lines.append(
        "These numbers are preliminary results and should not be treated as final conclusions. The selector is intended to support adaptive selection as more comparable protocol measurements are collected over time."
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_reports(state_path=DEFAULT_STATE_PATH, output_dir=DEFAULT_REPORT_DIR):
    """Generate the PNG and Markdown artifacts for the selector state."""
    state = load_state(state_path)
    ensure_directory(output_dir)

    png_path = os.path.join(output_dir, "ml_selector_summary.png")
    md_path = os.path.join(output_dir, "ml_selector_report.md")

    generate_summary_plot(state, png_path)
    generate_markdown_report(state, md_path)

    return png_path, md_path


def main():
    """Command-line entry point for generating selector reports."""
    parser = argparse.ArgumentParser(description="Generate adaptive selector summary artifacts.")
    parser.add_argument("--state-path", default=DEFAULT_STATE_PATH, help="Path to the selector state JSON file.")
    parser.add_argument("--output-dir", default=DEFAULT_REPORT_DIR, help="Directory where report files are written.")
    args = parser.parse_args()

    png_path, md_path = generate_reports(args.state_path, args.output_dir)
    print(f"PNG report: {png_path}")
    print(f"Markdown report: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
