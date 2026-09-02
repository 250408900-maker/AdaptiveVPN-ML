# AdaptiveVPN-ML

AdaptiveVPN-ML is a Windows-compatible research project designed to collect comparable network-performance measurements for direct internet access, WireGuard, OpenVPN, and VLESS traffic so that a machine-learning selector can recommend the most suitable protocol in real time. The project collects latency, packet loss, jitter, download throughput, and upload throughput from the active network path and learns from those observations using an online UCB1 multi-armed bandit.

## Supported protocols

- WireGuard
- OpenVPN
- VLESS
- Direct baseline

## Measured metrics

- Latency (ms)
- Packet loss (%)
- Jitter (ms)
- Download throughput (Mbps)
- Upload throughput (Mbps)

## UCB1 online-learning selector

The selector uses a UCB1 multi-armed bandit to balance exploitation of known-good protocols with exploration of under-tested options. Each protocol arm is updated with a quality reward derived from the latest observation. The algorithm chooses the protocol with the highest UCB score while retaining an exploration bonus for arms with fewer observations.

## 0–100 reward design

The selector calculates a normalized reward from 0 to 100 using the current observation values:

- Lower latency is better
- Lower packet loss is better
- Lower jitter is better
- Higher download speed is better
- Higher upload speed is better

Missing values are ignored for the active metric set, and the remaining weights are renormalized across the available metrics so that no fabricated values are introduced. The selector rejects rows where latency and packet loss are both missing.

## Setup and installation

From the project root:

```powershell
python -m pip install -r requirements.txt
```

Optional throughput testing uses `speedtest-cli` through the active proxy route when applicable.

## Training and selection commands

Train the selector from historical data:

```powershell
python .\adaptive_selector.py train
```

Recommend the next protocol using the current state:

```powershell
python .\adaptive_selector.py recommend
```

Print the current bandit status and per-protocol UCB information:

```powershell
python .\adaptive_selector.py status
```

Update the selector with a single observation manually:

```powershell
python .\adaptive_selector.py update --protocol wireguard --latency 40 --loss 0 --jitter 5 --download 50 --upload 15
```

## Live monitoring

Run a one-shot measurement with the selected protocol:

```powershell
python .\monitor.py --host 8.8.8.8 --count 4 --protocol vless --speed-test
```

Collect multiple measurements in a batch:

```powershell
python .\collect_data.py --host 8.8.8.8 --count 4 --measurements 5 --delay 5 --speed-test --protocol vless
```

## Current preliminary results

These figures are from the current persisted selector state and are preliminary only:

- WireGuard average reward: 81.778
- OpenVPN average reward: 58.595
- VLESS average reward: 90.174
- Current recommendation: VLESS

These results are preliminary because the measurements were not collected in fully controlled paired experiments across all protocols. They should be interpreted as early online-learning evidence rather than final research conclusions.

## Next steps

- Collect paired protocol measurements in narrow time windows for fair comparison
- Add contextual features such as time-of-day, target host, and route conditions
- Build a dashboard for live network-quality visualization
- Prepare the dataset and evaluation workflow for TÜBİTAK project reporting

## Repository hygiene

Sensitive files are excluded from Git by default, including VPN keys, certificates, environment files, local dataset copies, and Python bytecode.
