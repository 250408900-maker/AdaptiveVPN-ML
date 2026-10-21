from src.monitor.prediction_diagnostics import diagnose_prediction


def test_tcp_failures_observed():
    assert diagnose_prediction("PACKET_LOSS", 40, 80) == (
        "TCP_FAILURES_OBSERVED"
    )


def test_icmp_nonresponse_observed():
    assert diagnose_prediction("PACKET_LOSS", 0, 20) == (
        "ICMP_NONRESPONSE_OBSERVED"
    )


def test_uncorroborated_prediction():
    assert diagnose_prediction("PACKET_LOSS", 0, 0) == (
        "PACKET_LOSS_PREDICTION_UNCORROBORATED"
    )


def test_normal_prediction():
    assert diagnose_prediction("NORMAL", 0, 0) == (
        "NO_PACKET_LOSS_PREDICTION"
    )
