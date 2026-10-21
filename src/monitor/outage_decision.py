"""Track sustained observed outages without switching routes."""


class OutageDecisionTracker:
    def __init__(self, required_windows=3):
        if required_windows < 1:
            raise ValueError("required_windows must be positive")

        self.required_windows = required_windows
        self.consecutive_outages = 0
        self.evaluation_issued = False

    def evaluate(self, reachability):
        if reachability == "PATH_UNREACHABLE":
            self.consecutive_outages += 1

            if (
                self.consecutive_outages >= self.required_windows
                and not self.evaluation_issued
            ):
                self.evaluation_issued = True
                return (
                    "EVALUATE_ALTERNATIVES",
                    "Sustained observed TCP outage",
                )

            return "MONITOR", "Observed TCP outage"

        self.consecutive_outages = 0
        self.evaluation_issued = False

        if reachability == "INVALID_MEASUREMENT":
            return "MONITOR", "Invalid measurement"

        return "KEEP", "No sustained outage"
