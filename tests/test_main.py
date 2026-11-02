"""Run with: python -m unittest discover -s tests -v"""

import csv
import json
import socket
import tempfile
import unittest
from pathlib import Path

from main import parse_ports, resolve_target, save_csv, save_json, scan_port, scan_ports


class PortParserTests(unittest.TestCase):
    def test_ranges_duplicates_and_sort(self):
        self.assertEqual(parse_ports("443,80,80,22-24"), [22, 23, 24, 80, 443])

    def test_single_port(self):
        self.assertEqual(parse_ports("65535"), [65535])

    def test_invalid_port_input(self):
        for spec in ("", "0", "65536", "80-22", "80,x", "80,", "1-5000", "--3"):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    parse_ports(spec)

    def test_loopback_allowed_by_default(self):
        self.assertEqual(resolve_target("127.0.0.1"), "127.0.0.1")

    def test_remote_target_needs_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            resolve_target("192.0.2.1")
        self.assertEqual(resolve_target("192.0.2.1", allow_remote=True), "192.0.2.1")


class ScanTests(unittest.TestCase):
    def test_detects_locally_open_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            result = scan_port("127.0.0.1", port, timeout=1)
            self.assertEqual(result.status, "OPEN")
            self.assertEqual(result.port, port)
            self.assertGreaterEqual(result.response_time_ms, 0)

    def test_results_sorted(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            results = scan_ports("127.0.0.1", [port, 1], timeout=1, workers=2)
            self.assertEqual([row.port for row in results], sorted([port, 1]))

    def test_report_exports(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            result = scan_port("127.0.0.1", listener.getsockname()[1], timeout=1)
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "csv" / "report.csv"
            json_path = Path(tmp) / "json" / "report.json"
            save_csv([result], "127.0.0.1", csv_path)
            save_json([result], "127.0.0.1", json_path)
            with csv_path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(rows[0]["status"], "OPEN")
            self.assertEqual(data["results"][0]["port"], result.port)


if __name__ == "__main__":
    unittest.main()
