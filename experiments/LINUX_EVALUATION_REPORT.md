# Controlled Linux Network Evaluation — 2026-10-12

## Environment
- Windows development environment with Ubuntu WSL
- Isolated veth pair and network namespace
- tc netem used for controlled impairment
- Existing V3 Random Forest pipeline; no retraining

## Scenarios
- NORMAL: no configured impairment
- HIGH_LATENCY: 200 ms configured delay
- PACKET_LOSS: 30% configured random packet loss

## Repeated Evaluation
Five runs per scenario (15 scenario-level measurements).

| Scenario | Correct | Total |
|---|---:|---:|
| NORMAL | 5 | 5 |
| HIGH_LATENCY | 0 | 5 |
| PACKET_LOSS | 5 | 5 |

All five HIGH_LATENCY measurements were predicted NORMAL.

## Interpretation
The V3 model consistently failed to identify the controlled
HIGH_LATENCY scenario in this Linux environment.

This is preliminary evidence of a transfer/generalization problem,
not proof of its cause.

## Limitations
- One isolated virtual network, not five independent networks
- Linux TCP/ICMP measurements differ from Windows training conditions
- Small sample size
- Synthetic impairments are not equivalent to real-world VPN or DPI behavior
- Model probabilities are not necessarily calibrated

## Next Steps
1. Compare feature distributions with the V3 training dataset.
2. Investigate why high-latency samples are classified NORMAL.
3. Validate on additional independent network environments.
4. Evaluate improvements against this preserved baseline.
