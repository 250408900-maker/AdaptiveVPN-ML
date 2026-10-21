import math


def validate_window(row):
    errors = []

    try:
        attempts = int(row["tcp_attempts"])
        latency = float(row["tcp_connect_mean_ms"])
        failure = float(row["tcp_failure_pct"])
        icmp = float(row["icmp_nonresponse_pct"])

        if attempts < 1:
            errors.append("Invalid TCP attempt count")

        if not math.isfinite(failure) or not 0 <= failure <= 100:
            errors.append("Invalid TCP failure percentage")

        if not math.isfinite(icmp) or not 0 <= icmp <= 100:
            errors.append("Invalid ICMP nonresponse percentage")

        if failure < 100 and (
            not math.isfinite(latency) or latency < 0
        ):
            errors.append("Invalid TCP latency")

        if failure == 100 and math.isfinite(latency):
            errors.append("Latency present despite total TCP failure")

        if not str(row["timestamp_utc"]).strip():
            errors.append("Missing timestamp")

    except (KeyError, ValueError, TypeError) as exc:
        errors.append(f"Invalid or missing field: {exc}")

    return errors
