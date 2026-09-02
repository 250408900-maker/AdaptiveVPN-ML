# Adaptive Selector Report

- algorithm: UCB1 online learning
- total observations: 58
- current recommendation: vless (UCB score=90.796)

## Protocol breakdown

| protocol | count | average reward | exploration bonus | UCB score |
| --- | ---: | ---: | ---: | ---: |
| wireguard | 22 | 81.778 | 0.608 | 82.386 |
| openvpn | 15 | 58.595 | 0.736 | 59.331 |
| vless | 21 | 90.174 | 0.622 | 90.796 |

## Reward design

The adaptive selector assigns a 0–100 quality reward by combining latency, packet loss, jitter, download speed, and upload speed. Lower latency, packet loss, and jitter are better; higher download and upload throughput are better. Missing values are excluded from the active metric set and the remaining weights are renormalized across the available values, so no fabricated metric values are used.

## Limitation

Historical protocols were not tested in fully controlled paired rounds, so these results are best interpreted as early, preliminary online-learning evidence rather than final research conclusions.

## Preliminary interpretation

These numbers are preliminary results and should not be treated as final conclusions. The selector is intended to support adaptive selection as more comparable protocol measurements are collected over time.
