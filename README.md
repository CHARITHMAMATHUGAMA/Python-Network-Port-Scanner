# Python Network Port Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![No dependencies](https://img.shields.io/badge/Dependencies-Standard%20library-green) ![License](https://img.shields.io/badge/License-MIT-lightgrey)

A beginner-friendly, **Python-based TCP connect port scanner** designed for a cybersecurity internship portfolio. Uses sockets and concurrent workers to check whether ports are accepting TCP connections, then exports structured CSV and optional JSON reports.

**Author:** Charithma Mathugama · [GitHub](https://github.com/CHARITHMAMATHUGAMA) · [LinkedIn](https://www.linkedin.com/in/charithma-mathugama-3254a339a/)

> **Ethical use:** Scan only devices that you own or are explicitly permitted to assess. The default target is `127.0.0.1`. Remote scanning requires `--allow-remote` to remind you to obtain authorization.

## Features

- TCP connect scanning via Python's built-in `socket` library
- Configurable IP/hostname, port lists/ranges, connection timeout and worker count
- Multithreaded scanning with `concurrent.futures.ThreadPoolExecutor`
- Output with **OPEN**, **NOT OPEN**, or **ERROR** status
- Conventional service-name hints (not service/version identification)
- Sorts results, generates CSV and optional JSON reports
- Validates invalid port ranges, unauthorized default target, timeouts and worker settings
- Reproducible localhost demo + automated unit tests
- No third-party Python packages required

## Requirements

- Windows, macOS, or Linux
- Python 3.10 or newer (tested in a controlled environment with an available Python runtime)
- VS Code is optional

## Quick start (Windows PowerShell / VS Code Terminal)

```powershell
python --version
python main.py
```

If Windows does not recognize `python`, try `py main.py`. The default command checks common TCP ports **on your own computer only**.

### Test with a guaranteed open local port

```powershell
python demo.py
```

This script creates a temporary TCP listening socket on `127.0.0.1`, detects it as OPEN, exports reports and closes it. Unlike a random scan, this demonstrates that detection works even if no common ports are open on your computer.

### Common options

```powershell
# Scan specific ports on your own PC
python main.py --target 127.0.0.1 --ports 22,80,443,8080 --show-all

# Scan a range and save both reports
python main.py --ports 1-1024 --workers 40 --timeout 0.5 --json

# Remote target: only if you own the target or have explicit permission
python main.py --target 192.168.1.10 --ports 22,80,443 --allow-remote

# Choose where your CSV report goes
python main.py --ports 80,443 --output reports/custom_report.csv
```

To see all command options:

```powershell
python main.py --help
```

## Example output

The actual open ports depend on the machine. A safe reproducible demo output looks like:

```text
Local-only test server started successfully.
Detected 127.0.0.1:<dynamically assigned port>/tcp as OPEN
Demo reports saved under: .../reports
```

Default main script output reports scan target, ports scanned, number open, elapsed time, and report path. See [`docs/sample-output.txt`](docs/sample-output.txt) for a captured sample from the project test run.

## How it works

```text
User -> CLI arguments -> Input validation -> IPv4 / authorization check
                                               |
                                               v
                                      TCP connect on ports
                                               |
                                   Concurrent scan workers
                                               |
                                    Sorted status results
                                               |
                                         CSV / JSON
```

When the TCP connection succeeds, the port is classified **OPEN**. A failed connection is shown as **NOT OPEN** because a timeout or rejection cannot always be distinguished reliably; `ERROR` indicates a socket-level exception. A port number's registered service name is only a **hint**: it does not prove a particular application/version is present. This tool is **not a vulnerability scanner** and should not be presented as one.

## Project structure

```text
Python-Network-Port-Scanner/
├── main.py                       # Scanner CLI and report export
├── demo.py                       # Reproducible local TCP demo
├── tests/
│   └── test_main.py              # Automated unit tests
├── reports/
│   └── .gitkeep                  # Reports saved here when you run
├── docs/
│   └── sample-output.txt         # Captured test/demo output
├── .github/workflows/
│   └── tests.yml                 # GitHub Actions test workflow
├── .gitignore
├── LICENSE
├── README.md
└── UPLOAD_TO_GITHUB.md
```

## Run unit tests

```powershell
python -m unittest discover -s tests -v
```

## Possible future improvements

- Rich terminal table and web dashboard
- Timestamped report history and analysis
- Host discovery and additional scan techniques (with appropriate authorization)

## Portfolio / CV wording

**Python Network Port Scanner | Python, TCP/IP, Sockets, Multithreading**

- Developed a Python-based TCP port scanner to identify open ports on authorized systems using socket programming and concurrent workers.
- Implemented configurable scan parameters, service-name hints, input validation, and CSV/JSON reporting.
- Validated the scanner with a local test server and automated unit tests; documented usage, safety boundaries, and results in GitHub.

## License

MIT © 2026 Charithma Mathugama
