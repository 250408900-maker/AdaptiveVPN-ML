import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import generate_ml_report
import monitor
from adaptive_selector import (
    ARMS,
    initialize_state,
    quality_reward,
    recommend_protocol,
    record_measurement_from_row,
    train_from_dataset,
    update_state,
)


class AdaptiveSelectorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.csv_path = os.path.join(self.temp_dir.name, "network_data.csv")
        self.state_path = os.path.join(self.temp_dir.name, "model", "adaptive_selector_state.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_csv(self, rows):
        with open(self.csv_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=[
                    "timestamp",
                    "target_host",
                    "protocol",
                    "vpn_status",
                    "connection_label",
                    "latency_ms",
                    "packet_loss_percent",
                    "jitter_ms",
                    "download_mbps",
                    "upload_mbps",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)

    def metric_lookup(self, rows):
        lookup = {}
        for field in [
            "latency_ms",
            "packet_loss_percent",
            "jitter_ms",
            "download_mbps",
            "upload_mbps",
        ]:
            values = []
            for row in rows:
                value = row.get(field)
                if value is not None and value != "":
                    try:
                        values.append(float(value))
                    except ValueError:
                        pass
            lookup[field] = values
        return lookup

    def test_reward_calculation_basic(self):
        rows = [
            {
                "protocol": "wireguard",
                "latency_ms": "10",
                "packet_loss_percent": "0",
                "jitter_ms": "1",
                "download_mbps": "80",
                "upload_mbps": "20",
            },
            {
                "protocol": "wireguard",
                "latency_ms": "100",
                "packet_loss_percent": "10",
                "jitter_ms": "20",
                "download_mbps": "10",
                "upload_mbps": "5",
            },
        ]
        lookup = self.metric_lookup(rows)
        better_reward = quality_reward(rows[0], lookup)
        worse_reward = quality_reward(rows[1], lookup)
        self.assertIsNotNone(better_reward)
        self.assertIsNotNone(worse_reward)
        self.assertGreater(better_reward, worse_reward)
        self.assertGreaterEqual(better_reward, 0.0)
        self.assertLessEqual(better_reward, 100.0)

    def test_missing_metric_handling(self):
        rows = [
            {
                "protocol": "openvpn",
                "latency_ms": "50",
                "packet_loss_percent": "",
                "jitter_ms": "8",
                "download_mbps": "30",
                "upload_mbps": "12",
            },
            {
                "protocol": "openvpn",
                "latency_ms": "40",
                "packet_loss_percent": "5",
                "jitter_ms": "",
                "download_mbps": "50",
                "upload_mbps": "10",
            },
        ]
        lookup = self.metric_lookup(rows)
        score = quality_reward(rows[0], lookup)
        self.assertIsNotNone(score)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)

    def test_training_creates_state(self):
        rows = [
            {"timestamp": "2024-01-01T00:00:00Z", "target_host": "8.8.8.8", "protocol": "wireguard", "vpn_status": "Connected", "connection_label": "vpn", "latency_ms": "20", "packet_loss_percent": "0", "jitter_ms": "2", "download_mbps": "40", "upload_mbps": "10"},
            {"timestamp": "2024-01-01T00:01:00Z", "target_host": "8.8.8.8", "protocol": "wireguard", "vpn_status": "Connected", "connection_label": "vpn", "latency_ms": "30", "packet_loss_percent": "1", "jitter_ms": "4", "download_mbps": "35", "upload_mbps": "9"},
            {"timestamp": "2024-01-01T00:02:00Z", "target_host": "8.8.8.8", "protocol": "openvpn", "vpn_status": "Connected", "connection_label": "vpn", "latency_ms": "60", "packet_loss_percent": "2", "jitter_ms": "5", "download_mbps": "20", "upload_mbps": "7"},
            {"timestamp": "2024-01-01T00:03:00Z", "target_host": "8.8.8.8", "protocol": "vless", "vpn_status": "Connected", "connection_label": "proxy", "latency_ms": "25", "packet_loss_percent": "0", "jitter_ms": "3", "download_mbps": "55", "upload_mbps": "12"},
        ]
        self.write_csv(rows)
        state = train_from_dataset(self.csv_path, self.state_path)
        self.assertTrue(os.path.exists(self.state_path))
        self.assertIn("wireguard", state)
        self.assertIn("openvpn", state)
        self.assertIn("vless", state)
        self.assertGreater(state["wireguard"]["count"], 0)

    def test_recommendation_uses_known_arm(self):
        rows = [
            {"timestamp": "2024-01-01T00:00:00Z", "target_host": "8.8.8.8", "protocol": "wireguard", "vpn_status": "Connected", "connection_label": "vpn", "latency_ms": "15", "packet_loss_percent": "0", "jitter_ms": "1", "download_mbps": "80", "upload_mbps": "20"},
            {"timestamp": "2024-01-01T00:01:00Z", "target_host": "8.8.8.8", "protocol": "wireguard", "vpn_status": "Connected", "connection_label": "vpn", "latency_ms": "25", "packet_loss_percent": "1", "jitter_ms": "5", "download_mbps": "70", "upload_mbps": "15"},
            {"timestamp": "2024-01-01T00:02:00Z", "target_host": "8.8.8.8", "protocol": "openvpn", "vpn_status": "Connected", "connection_label": "vpn", "latency_ms": "60", "packet_loss_percent": "2", "jitter_ms": "6", "download_mbps": "25", "upload_mbps": "8"},
            {"timestamp": "2024-01-01T00:03:00Z", "target_host": "8.8.8.8", "protocol": "vless", "vpn_status": "Connected", "connection_label": "proxy", "latency_ms": "40", "packet_loss_percent": "1", "jitter_ms": "9", "download_mbps": "50", "upload_mbps": "12"},
        ]
        self.write_csv(rows)
        state = train_from_dataset(self.csv_path, self.state_path)
        arm, _, description = recommend_protocol(self.csv_path, self.state_path)
        self.assertIn(arm, ARMS)
        self.assertIn("UCB score", description)

    def test_update_adds_new_observation(self):
        state = initialize_state()
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as state_file:
            json.dump(state, state_file)
        old_state = state.copy()
        updated_state, reward = update_state("wireguard", latency=40, loss=0, jitter=5, download=50, upload=15, state_path=self.state_path)
        self.assertEqual(updated_state["wireguard"]["count"], old_state["wireguard"]["count"] + 1)
        self.assertGreaterEqual(reward, 0.0)
        self.assertLessEqual(reward, 100.0)

    def test_record_measurement_from_row_updates_once(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as state_file:
            json.dump(initialize_state(), state_file)

        first_updated, first_reward = record_measurement_from_row(
            "wireguard",
            timestamp="2024-01-01T00:00:00Z",
            host="8.8.8.8",
            latency=40,
            loss=0,
            jitter=5,
            download=50,
            upload=15,
            state_path=self.state_path,
        )
        self.assertTrue(first_updated)
        self.assertGreaterEqual(first_reward, 0.0)

        second_updated, second_reward = record_measurement_from_row(
            "wireguard",
            timestamp="2024-01-01T00:00:00Z",
            host="8.8.8.8",
            latency=40,
            loss=0,
            jitter=5,
            download=50,
            upload=15,
            state_path=self.state_path,
        )
        self.assertFalse(second_updated)
        self.assertIsNone(second_reward)

        with open(self.state_path, "r", encoding="utf-8") as state_file:
            state = json.load(state_file)
        self.assertEqual(state["wireguard"]["count"], 1)

    def test_monitor_print_results_handles_string_metrics(self):
        metrics = {
            "latency_ms": "18.50",
            "packet_loss_pct": "0.00",
            "jitter_ms": "2.50",
        }
        try:
            monitor.print_results("8.8.8.8", metrics, protocol="vless", vpn_status="Connected")
        except Exception as exc:  # pragma: no cover - regression guard
            self.fail(f"string metrics should be normalized before formatting: {exc}")

    def test_generate_ml_report_creates_files(self):
        tmp_dir = tempfile.TemporaryDirectory()
        try:
            output_dir = os.path.join(tmp_dir.name, "reports")
            state_path = os.path.join(tmp_dir.name, "adaptive_selector_state.json")
            with open(state_path, "w", encoding="utf-8") as state_file:
                json.dump(
                    {
                        "wireguard": {"count": 3, "total_reward": 240.0, "average_reward": 80.0},
                        "openvpn": {"count": 2, "total_reward": 130.0, "average_reward": 65.0},
                        "vless": {"count": 4, "total_reward": 300.0, "average_reward": 75.0},
                        "seen_observations": [],
                    },
                    state_file,
                )

            png_path, md_path = generate_ml_report.generate_reports(state_path=state_path, output_dir=output_dir)
            self.assertTrue(os.path.exists(png_path))
            self.assertTrue(os.path.exists(md_path))
            with open(md_path, "r", encoding="utf-8") as report_file:
                contents = report_file.read()
            self.assertIn("Adaptive Selector Report", contents)
        finally:
            tmp_dir.cleanup()

    def test_monitor_cli_appends_row_and_updates_selector_once(self):
        root = tempfile.mkdtemp(prefix="adaptivevpn-monitor-")
        try:
            for name in ("monitor.py", "adaptive_selector.py"):
                source_path = os.path.join(os.path.dirname(__file__), name)
                shutil.copy2(source_path, os.path.join(root, name))

            bin_dir = os.path.join(root, "fakebin")
            os.makedirs(bin_dir, exist_ok=True)
            fake_ping_path = os.path.join(bin_dir, "ping.cmd")
            with open(fake_ping_path, "w", encoding="utf-8") as ping_file:
                ping_file.write(
                    "@echo off\r\n"
                    "echo PING 8.8.8.8: 32 data bytes\r\n"
                    "echo Reply from 8.8.8.8: bytes=32 time=15ms TTL=118\r\n"
                    "echo Reply from 8.8.8.8: bytes=32 time=18ms TTL=118\r\n"
                    "echo Reply from 8.8.8.8: bytes=32 time=14ms TTL=118\r\n"
                    "echo Reply from 8.8.8.8: bytes=32 time=16ms TTL=118\r\n"
                    "echo.\r\n"
                    "echo Ping statistics for 8.8.8.8:\r\n"
                    "echo     Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)\r\n"
                    "echo Approximate round trip times in milli-seconds:\r\n"
                    "echo     Minimum = 14ms, Maximum = 18ms, Average = 15ms\r\n"
                    "exit /b 0\r\n"
                )

            env = os.environ.copy()
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
            result = subprocess.run(
                [sys.executable, os.path.join(root, "monitor.py"), "--host", "8.8.8.8", "--count", "4", "--protocol", "vless"],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)

            csv_path = os.path.join(root, "network_data.csv")
            with open(csv_path, "r", newline="", encoding="utf-8") as csv_file:
                rows = list(csv.DictReader(csv_file))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["protocol"], "vless")

            state_path = os.path.join(root, "model", "adaptive_selector_state.json")
            with open(state_path, "r", encoding="utf-8") as state_file:
                state = json.load(state_file)
            self.assertEqual(state["vless"]["count"], 1)

            duplicate_row = {
                "timestamp": rows[0]["timestamp"],
                "target_host": rows[0]["target_host"],
                "protocol": rows[0]["protocol"],
                "vpn_status": rows[0]["vpn_status"],
                "connection_label": rows[0]["connection_label"],
                "latency_ms": rows[0]["latency_ms"],
                "packet_loss_percent": rows[0]["packet_loss_percent"],
                "jitter_ms": rows[0]["jitter_ms"],
                "download_mbps": rows[0]["download_mbps"],
                "upload_mbps": rows[0]["upload_mbps"],
            }
            updated, _ = monitor.update_selector_from_row(duplicate_row, csv_path=csv_path, state_path=state_path)
            self.assertFalse(updated)
            with open(state_path, "r", encoding="utf-8") as state_file:
                state_after = json.load(state_file)
            self.assertEqual(state_after["vless"]["count"], 1)
        finally:
            if os.path.exists(root):
                shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
