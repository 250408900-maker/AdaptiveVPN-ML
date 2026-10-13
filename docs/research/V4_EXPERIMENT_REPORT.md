# AdaptiveVPN-ML ? V4 Research Report

Date: 2026-10-13

## Methodology
Controlled network impairment using Linux WSL2, network namespaces,
virtual Ethernet interfaces, and tc netem.

The tests use local TCP and ICMP probes, not actual VPN traffic.

## Training dataset
- Observations: 25
- Collection groups: 7
- Class distribution: {'PACKET_LOSS': 9, 'NORMAL': 8, 'HIGH_LATENCY': 8}

## V4 exploratory grouped cross-validation
- Accuracy: 92% (23/25)
- NORMAL recall: 8/8
- HIGH_LATENCY recall: 8/8
- PACKET_LOSS recall: 7/9

## V3 vs V4 regression benchmark
- HIGH_LATENCY: V3 0/5, V4 5/5
- NORMAL: V3 5/5, V4 5/5
- PACKET_LOSS: V3 5/5, V4 5/5

## Limitations
- Small dataset from one isolated virtual network.
- Repeated sessions are not independent network environments.
- The benchmark informed V4 development.
- Grouped validation is exploratory due to scenario/group confounding.
- Real VPN switching and protocol performance were not tested.

## Conclusion
V4 corrected the previously observed 200 ms latency blind spot
in the controlled Linux regression benchmark.
Further independent testing is required before deployment.
