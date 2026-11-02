"""Python TCP port scanner for devices you own or are authorized to test.

Standard-library only. Default target is the local computer (127.0.0.1).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

COMMON_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,8000,8080,8443"
MAX_PORT_COUNT = 4096
DEFAULT_REPORT = Path(__file__).resolve().parent / "reports" / "scan_results.csv"


@dataclass(frozen=True)
class ScanResult:
    port: int
    status: str
    service_hint: str
    response_time_ms: float


def parse_ports(spec: str) -> list[int]:
    """Parse e.g. '22,80,8000-8005', deduplicating and sorting."""
    if not spec or not spec.strip():
        raise ValueError("Port list cannot be empty")

    selected: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError("Empty port entry")
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not all(b.isdecimal() for b in bounds):
                raise ValueError(f"Invalid port range: {part}")
            start, end = map(int, bounds)
            if start > end:
                raise ValueError(f"Range must be ascending: {part}")
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Ports must be between 1 and 65535: {part}")
            if (end - start + 1) > MAX_PORT_COUNT:
                raise ValueError(f"A scan can contain at most {MAX_PORT_COUNT} ports")
            selected.update(range(start, end + 1))
        else:
            if not part.isdecimal():
                raise ValueError(f"Invalid port: {part}")
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range: {port}")
            selected.add(port)
        if len(selected) > MAX_PORT_COUNT:
            raise ValueError(f"A scan can contain at most {MAX_PORT_COUNT} ports")

    return sorted(selected)


def resolve_target(host: str, allow_remote: bool = False) -> str:
    """Resolve an IPv4 address and restrict scans to loopback by default."""
    try:
        ipv4 = socket.gethostbyname(host)
        address = ipaddress.ip_address(ipv4)
    except (socket.gaierror, ValueError, UnicodeError) as exc:
        raise ValueError(f"Cannot resolve IPv4 target '{host}': {exc}") from exc

    if not allow_remote and not address.is_loopback:
        raise ValueError(
            "For safety, remote targets are disabled by default. "
            "Use --allow-remote only when you own the target or have explicit permission."
        )
    return ipv4


def service_hint(port: int) -> str:
    """Return standard registered name, NOT verified service detection."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(target_ip: str, port: int, timeout: float = 0.5) -> ScanResult:
    start = time.perf_counter()
    status = "NOT OPEN"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                status = "OPEN"
    except OSError:
        status = "ERROR"
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    return ScanResult(port=port, status=status, service_hint=service_hint(port), response_time_ms=elapsed)


def scan_ports(target_ip: str, ports: list[int], timeout: float, workers: int) -> list[ScanResult]:
    results: list[ScanResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_port, target_ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda result: result.port)


def save_csv(results: list[ScanResult], target_ip: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["target", "port", "status", "service_hint", "response_time_ms"])
        for row in results:
            writer.writerow([target_ip, row.port, row.status, row.service_hint, row.response_time_ms])


def save_json(results: list[ScanResult], target_ip: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "target": target_ip,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan_type": "TCP connect",
        "note": "Service hints are conventional port labels, not service/version verification.",
        "results": [asdict(row) for row in results],
    }
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Python TCP Port Scanner - only scan hosts you own or have permission to test."
    )
    parser.add_argument("--target", default="127.0.0.1", help="IPv4 address/hostname (default: localhost)")
    parser.add_argument("--ports", default=COMMON_PORTS, help="Comma list and/or ranges, e.g. 22,80,8000-8010")
    parser.add_argument("--timeout", type=float, default=0.5, help="Seconds per connection (0.1-5, default 0.5)")
    parser.add_argument("--workers", type=int, default=40, help="Concurrent connections (1-128, default 40)")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT, help="CSV report output path")
    parser.add_argument("--json", action="store_true", help="Also write a JSON report beside the CSV")
    parser.add_argument("--show-all", action="store_true", help="Print all results, not just OPEN ports")
    parser.add_argument("--allow-remote", action="store_true", help="Enable scan of explicitly authorized remote target")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not 0.1 <= args.timeout <= 5:
            raise ValueError("--timeout must be between 0.1 and 5 seconds")
        if not 1 <= args.workers <= 128:
            raise ValueError("--workers must be between 1 and 128")
        ports = parse_ports(args.ports)
        ip = resolve_target(args.target, args.allow_remote)
    except ValueError as exc:
        parser.error(str(exc))

    print("=" * 54)
    print("       PYTHON NETWORK PORT SCANNER")
    print("=" * 54)
    print(f"Target: {args.target} ({ip})")
    print(f"Scan: TCP connect | Ports: {len(ports)} | Timeout: {args.timeout}s")
    print("Authorized use only. Starting scan...\n")

    started = time.perf_counter()
    results = scan_ports(ip, ports, args.timeout, args.workers)
    for row in results:
        if row.status == "OPEN" or args.show_all:
            print(f"  {row.port:5d}/tcp  {row.status:<9}  {row.service_hint}")

    try:
        save_csv(results, ip, args.output)
        if args.json:
            save_json(results, ip, args.output.with_suffix(".json"))
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        return 1

    open_count = sum(row.status == "OPEN" for row in results)
    print(f"\nFinished: {open_count} OPEN / {len(results)} checked in {time.perf_counter() - started:.2f}s")
    print(f"CSV report: {args.output.resolve()}")
    if args.json:
        print(f"JSON report: {args.output.with_suffix('.json').resolve()}")
    print("Note: 'NOT OPEN' can mean closed, filtered or unreachable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
