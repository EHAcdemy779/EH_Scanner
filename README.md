# EH Scanner — EH Academy

A Python network-scanning and vulnerability-reference helper for **authorized security testing and lab learning**. Use only on systems you own or have explicit permission to assess.

## Source files

- `EH_Scanner_FINAL.py` — IPv4-capable version.
- `EH_Scanner_FINAL_IPv6.py` — IPv4/IPv6-aware version; IPv6 scan behavior depends on the installed Nmap build and network.
- `requirements.txt` — Python package dependencies.
- `REQUIREMENTS.txt` — platform-specific setup commands for Python and external tools.

## Features

- Nmap preset and manual scans, with IPv6 address-family selection in the IPv6 version.
- NSE script workflows and public vulnerability-reference lookups where available.
- Metasploit module configuration and interactive session.
- Netcat client/listener session with **no EH Scanner-imposed session timeout**. The session continues until Netcat exits, the peer/network closes it, or the user presses Ctrl+C.
- TXT, HTML, and PDF reports built from the same session report data, including exploit selection/configuration and Metasploit/Netcat session metadata.
- On POSIX systems where the `script` terminal utility is available, the app attempts to capture interactive terminal input/output. If unavailable or capture fails, the report says so; capture is not guaranteed on every OS/terminal.

## Quick start

Install Python dependencies with `python -m pip install -r requirements.txt`, install Nmap and any optional external tools you intend to use, then run one of the source files. Platform-specific commands and caveats are in `REQUIREMENTS.txt`.

```bash
python EH_Scanner_FINAL.py
# or
python EH_Scanner_FINAL_IPv6.py
```

## Reports and sensitive data

Reports are saved under `report/`. Interactive terminal transcripts may contain credentials, tokens, IP addresses, or other sensitive data. Review and redact reports before sharing them. Captured output can be incomplete, and a service/version or CVE reference does not prove a target is vulnerable.

## Validation status

Python syntax compilation and offline structural checks are performed before release. Live scans, API access, Metasploit interactive capture, Netcat capture, and every OS/terminal combination are not claimed as tested unless explicitly stated. Validate first against an authorized lab target.
