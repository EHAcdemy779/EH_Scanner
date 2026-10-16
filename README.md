EH Scanner
EH Scanner is a Python-based security assessment tool for authorized testing. It includes separate IPv4 and IPv6 scripts and uses command-line utilities for scanning and optional integrations.
Features
Separate IPv4 and IPv6 scanner scripts
Nmap-based scanning
Optional integrations with supporting network/security utilities
Scan/session information and report output
Requirements
Python 3
Nmap
Optional: Colorama for terminal colours
Any optional integration requires its corresponding tool to be installed separately
Installation
Kali Linux
Install Python, Git, and Nmap:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git nmap
```
Optional tools, if you need the related features:
```bash
sudo apt install -y netcat-openbsd netdiscover exploitdb
```
Metasploit is optional; install it separately if required and available in your Kali package sources.
Clone the repository and enter its directory:
```bash
git clone https://github.com/EHAcdemy779/EH_Scanner.git
cd EH_Scanner
```
Run the IPv4 scanner:
```bash
python3 EH_Scanner_FINAL.py
```
Run the IPv6 scanner:
```bash
python3 EH_Scanner_FINAL_IPv6.py
```
Windows 10 / 11
Install Python 3 from python.org. Enable Add Python to PATH during setup.
Install Nmap from the official Nmap download page.
Install Git from git-scm.com, or download the repository ZIP from GitHub.
Open PowerShell in the project directory.
Check the installations:
```powershell
py --version
nmap --version
```
Optional terminal colours:
```powershell
py -m pip install colorama
```
Run the IPv4 scanner:
```powershell
py -3 EH_Scanner_FINAL.py
```
Run the IPv6 scanner:
```powershell
py -3 EH_Scanner_FINAL_IPv6.py
```
Some optional tools available on Kali may need separate Windows installation or may not be available. IPv6 scanning also requires working IPv6 connectivity.
Termux (Android)
Install Termux from a trusted source, then run:
```bash
pkg update
pkg upgrade
pkg install python git nmap
```
Clone the repository and enter its directory:
```bash
git clone https://github.com/EHAcdemy779/EH_Scanner.git
cd EH_Scanner
```
Run the IPv4 scanner:
```bash
python EH_Scanner_FINAL.py
```
Run the IPv6 scanner:
```bash
python EH_Scanner_FINAL_IPv6.py
```
IPv6 scanning requires IPv6 connectivity on the device and network. Some optional desktop utilities may not be available in Termux.
Optional integrations
Nmap — required for Nmap scanning features.
Colorama — optional terminal colours; the scripts can use plain output without it.
Netdiscover, Netcat, SearchSploit, Metasploit — optional integrations; install and configure separately if you use the corresponding features.
Troubleshooting
Python command not found: install Python 3. On Kali use `python3`; on Windows try `py`; on Termux use `python`.
Nmap not found: install Nmap and ensure its executable is available in `PATH`. Restart the terminal after installation if necessary.
Permission or network errors: check local permissions, firewall settings, routing, and network access.
No IPv6 results: verify IPv6 is enabled and the target is reachable over IPv6.
Optional tool unavailable: install the tool for your operating system or skip the related feature.
Responsible use
Use EH Scanner only on systems and networks you own or have explicit permission to assess. You are responsible for obtaining authorization and complying with applicable laws.
License
Add a `LICENSE` file before publishing and replace this section with the license terms that apply to your repository.
