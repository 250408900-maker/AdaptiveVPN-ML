import math
import time


def validate_measurement(m, now=None, max_age_seconds=120):
    if now is None:
        now = time.time()

    if not math.isfinite(m.measured_at):
        return False, "Invalid timestamp"

    age = now - m.measured_at

    if age < -5:
        return False, "Future measurement"

    if age > max_age_seconds:
        return False, "Stale measurement"

    if not m.method or not m.target:
        return False, "Missing measurement method or target"

    return True, "Valid"


def comparable(a, b):
    return (
        a.method == b.method
        and a.target == b.target
    )
