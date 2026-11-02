"""Reproducible demonstration using a temporary local-only listening socket."""

import socket
from pathlib import Path

from main import save_csv, save_json, scan_port


if __name__ == "__main__":
    # Bind to the OS-assigned ephemeral TCP port on loopback.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        result = scan_port("127.0.0.1", port, timeout=1)

    report = Path(__file__).resolve().parent / "reports" / "demo_scan.csv"
    save_csv([result], "127.0.0.1", report)
    save_json([result], "127.0.0.1", report.with_suffix(".json"))
    print("Local-only test server started successfully.")
    print(f"Detected 127.0.0.1:{port}/tcp as {result.status}")
    print(f"Demo reports saved under: {report.parent}")
    if result.status != "OPEN":
        raise SystemExit("Demo failed: the temporary local listening port was not detected")
