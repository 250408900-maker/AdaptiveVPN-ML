"""Interpret network reachability independently of ML predictions."""

import math


def assess_reachability(tcp_mean_ms, tcp_failure_pct):
    latency = float(tcp_mean_ms)
    failure = float(tcp_failure_pct)

    if not math.isfinite(failure) or not 0 <= failure <= 100:
        return "INVALID_MEASUREMENT"

    if failure == 100 and math.isnan(latency):
        return "PATH_UNREACHABLE"

    if not math.isfinite(latency) or latency < 0:
        return "INVALID_MEASUREMENT"

    if failure == 100:
        return "INVALID_MEASUREMENT"

    if failure > 0:
        return "DEGRADED_CONNECTIVITY"

    return "REACHABLE"
