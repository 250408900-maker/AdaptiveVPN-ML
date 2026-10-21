"""Diagnostics for interpreting V4 network predictions."""


def diagnose_prediction(prediction, tcp_failure_pct, icmp_nonresponse_pct):
    if prediction != "PACKET_LOSS":
        return "NO_PACKET_LOSS_PREDICTION"

    if tcp_failure_pct > 0:
        return "TCP_FAILURES_OBSERVED"

    if icmp_nonresponse_pct > 0:
        return "ICMP_NONRESPONSE_OBSERVED"

    return "PACKET_LOSS_PREDICTION_UNCORROBORATED"
