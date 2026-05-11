# Hunter Project: Threat Hunter V0.1

A Windows-focused static and live malware analysis tool built around `hunter.py`.
It performs PE analysis, string/IOC extraction, imported API correlation, disassembly heuristics, and live process memory/thread inspection.

## Features

- Static PE analysis for `.exe`, `.dll`, `.sys`
- Script and macro analysis for `.vbs`, `.bas`, `.cls`, `.frm`, `.vba`, `.ps1`, and text-based payloads
- Extracts URLs, IPs, PowerShell commands, registry keys, mutexes, and Base64 blobs
- Detects packed binaries, RWX sections, TLS callbacks, tiny import tables, and other suspicious PE anomalies
- Flags dangerous API combinations like process injection, dynamic API resolution, C2 communication, and ransomware behavior
- Live process analysis for RWX memory, injected threads, and reflective PE dumps
- Export reports to JSON and HTML

## Requirements

Install the Python dependencies using pip:

```powershell
pip install -r requirements.txt
```

## requirements.txt

- `pefile`
- `capstone`
- `psutil`

## Usage

From the project directory:

```powershell
python hunter.py -f C:\path\to\sample.exe
```

Or analyze a live process by PID:

```powershell
python hunter.py -p 1234
```

### Exporting reports

Generate a JSON report:

```powershell
python hunter.py -f C:\path\to\sample.exe --json
```

Generate an HTML report:

```powershell
python hunter.py -f C:\path\to\sample.exe --html
```

You can also use both flags together:

```powershell
python hunter.py -f C:\path\to\sample.exe --json --html
```

### Interactive mode

Run without arguments to use the built-in menu:

```powershell
python hunter.py
```

## Notes

- Designed for Windows environments.
- Run with elevated privileges for live process memory inspection.
- The tool uses `capstone` for disassembly and `pefile` for binary parsing.

## Project files

- `hunter.py` — main analysis engine
- `requirements.txt` — Python dependencies for installation
