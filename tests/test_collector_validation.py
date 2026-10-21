import pytest

from experiments.collect_windows_live import measure_window


@pytest.mark.parametrize(
    "window_seconds,attempts,port",
    [
        (0, 5, 443),
        (-1, 5, 443),
        (10, 0, 443),
        (10, -1, 443),
        (10, 5, 0),
        (10, 5, 65536),
    ],
)
def test_rejects_invalid_measurement_settings(
    window_seconds, attempts, port
):
    with pytest.raises(ValueError):
        measure_window(
            host="1.1.1.1",
            port=port,
            window_seconds=window_seconds,
            attempts=attempts,
        )
