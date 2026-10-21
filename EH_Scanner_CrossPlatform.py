import subprocess
import socket
import ipaddress
import tempfile
import os
import re
import sys
import time
import shutil
import shlex
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
import builtins


class ExitRequested(BaseException):
    """Raised only after the user confirms exiting the entire application."""


class GUIStopRequested(BaseException):
    """Internal signal: the Web GUI user cancelled the active scanner task."""


def _register_gui_process(process):
    """Expose a live child process to the local Web GUI Stop button, when present."""
    processes = globals().get("GUI_ACTIVE_PROCESSES")
    if processes is not None:
        lock = globals().get("GUI_ACTIVE_PROCESSES_LOCK")
        if lock is not None:
            with lock:
                processes.add(process)
        else:
            processes.add(process)


def _unregister_gui_process(process):
    """Remove a completed child process from the Web GUI's active-process set."""
    processes = globals().get("GUI_ACTIVE_PROCESSES")
    if processes is not None:
        lock = globals().get("GUI_ACTIVE_PROCESSES_LOCK")
        if lock is not None:
            with lock:
                processes.discard(process)
        else:
            processes.discard(process)


_original_input = builtins.input

def _confirm_exit():
    """Ask once; a negative answer lets the caller continue its current flow."""
    while True:
        try:
            answer = _original_input("\nExit EH Scanner completely? (y/n): ").strip().lower()
        except KeyboardInterrupt:
            print("\nPlease answer y or n.")
            continue
        if answer in ("y", "yes"):
            raise ExitRequested()
        if answer in ("n", "no", ""):
            print("Continuing from the current menu/input.")
            return False
        print("Please enter y or n.")

def input(prompt=""):
    """Centralized input: Ctrl+C asks before exiting; menu 0/exit confirms exit."""
    while True:
        try:
            value = _original_input(prompt)
        except KeyboardInterrupt:
            _confirm_exit()
            continue
        # Only treat 0/exit as the global exit command at numbered menu prompts.
        if "select option" in str(prompt).lower() and value.strip().lower() in ("0", "exit"):
            _confirm_exit()
            continue
        return value

# ============================================================
# TERMINAL COLOR THEME
# ============================================================

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

if COLOR_ENABLED:
    C_RED = Fore.RED
    C_GREEN = Fore.GREEN
    C_YELLOW = Fore.YELLOW
    C_BLUE = Fore.BLUE
    C_CYAN = Fore.CYAN
    C_MAGENTA = Fore.MAGENTA
    C_WHITE = Fore.WHITE
    C_BRIGHT = Style.BRIGHT
    C_RESET = Style.RESET_ALL
elif os.environ.get("EH_SCANNER_WEB_GUI") == "1" or getattr(sys.stdout, "isatty", lambda: False)():
    # Standard ANSI fallback: keeps colors available without the optional colorama package.
    C_RED, C_GREEN, C_YELLOW = "\x1b[31m", "\x1b[32m", "\x1b[33m"
    C_BLUE, C_CYAN, C_MAGENTA, C_WHITE = "\x1b[34m", "\x1b[36m", "\x1b[35m", "\x1b[37m"
    C_BRIGHT, C_RESET = "\x1b[1m", "\x1b[0m"
else:
    C_RED = C_GREEN = C_YELLOW = C_BLUE = ""
    C_CYAN = C_MAGENTA = C_WHITE = C_BRIGHT = C_RESET = ""


def ctext(text, color="", bright=False):
    prefix = color + (C_BRIGHT if bright else "")
    return f"{prefix}{text}{C_RESET}"


def print_title(text):
    print(f"\n{C_CYAN}{C_BRIGHT}{text}{C_RESET}")


def print_success(text):
    print(f"{C_GREEN}{text}{C_RESET}")


def print_warning(text):
    print(f"{C_YELLOW}{text}{C_RESET}")


def print_error(text):
    print(f"{C_RED}{text}{C_RESET}")


def print_option(text, color=None):
    """Render menu options with clear visual hierarchy."""
    if color is None:
        color = C_WHITE
    print(f"  {color}{C_BRIGHT}▶  {text}{C_RESET}")


# ============================================================
# EH SCANNER - FINAL VERSION
# Public source lookups require an internet connection. VulnCheck requires an API key.
# Use only on systems you own or are explicitly authorized to assess.

# EH SCANNER - UI / BANNER
# ============================================================

def show_banner():
    print("\n")
    print(f"{C_BLUE}{C_BRIGHT}=============================================================={C_RESET}")
    print(f"{C_CYAN}{C_BRIGHT}                    E H   S C A N N E R{C_RESET}")
    print(f"{C_WHITE}              Ethical Hacking & Security Tool{C_RESET}")
    print(f"{C_RED}{C_BRIGHT}=============================================================={C_RESET}")
    print(f"{C_CYAN}{C_BRIGHT}                         EH Academy{C_RESET}")
    print(f"{C_BLUE}{C_BRIGHT}=============================================================={C_RESET}")
    print("\n")


def show_disclaimer():
    print(f"\n{C_YELLOW}{C_BRIGHT}====================== DISCLAIMER ======================{C_RESET}")
    print(f"{C_WHITE}EH Scanner is intended for authorized security testing,")
    print("educational purposes, and systems you own or have")
    print("explicit permission to assess.")
    print(f"{C_RED}Do not use this tool against unauthorized targets.{C_RESET}")
    print(f"{C_YELLOW}{C_BRIGHT}========================================================={C_RESET}\n")


# ============================================================
# REPORT DATA
# ============================================================

report_data = {
    "start_time": None,
    "target": None,
    "target_input": None,
    "scan_type": None,
    "scan_command": None,
    "scan_result": "",
    "network_discovery_result": "",
    "open_ports": [],
    "selected_port": None,
    "port_info": None,
    "exploit_search_query": None,
    "exploitdb_result": "",
    "metasploit_result": "",
    "selected_exploit": None,
    "configuration": None,
    "script_result": "",
    "metasploit_status": "",
    "metasploit_session": {"capture_status": "Not run", "start_time": None, "end_time": None, "output": "", "exit_code": None},
    "netcat_session": {"mode": None, "endpoint": None, "command": None, "start_time": None, "end_time": None, "status": "Not run", "exit_code": None, "capture_status": "Not run", "transcript": ""},
    "script_recommendation": None,
    "script_command": None,
    "script_type": None
}


def reset_report(target=None):
    global report_data

    report_data = {
        "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "target_input": target,
        "scan_type": None,
        "scan_command": None,
        "scan_result": "",
        "network_discovery_result": "",
        "open_ports": [],
        "selected_port": None,
        "port_info": None,
        "exploit_search_query": None,
        "exploitdb_result": "",
        "metasploit_result": "",
        "additional_source_results": {},
        "selected_exploit": None,
        "configuration": None,
        "script_result": "",
        "metasploit_status": "",
        "metasploit_session": {"capture_status": "Not run", "start_time": None, "end_time": None, "output": "", "exit_code": None},
        "netcat_session": {"mode": None, "endpoint": None, "command": None, "start_time": None, "end_time": None, "status": "Not run", "exit_code": None, "capture_status": "Not run", "transcript": ""},
        "script_recommendation": None,
        "script_command": None,
        "script_type": None
    }


# ============================================================
# PLATFORM / COMMAND HELPERS
# ============================================================

def is_windows():
    return os.name == "nt"


def command_exists(command):
    return shutil.which(command) is not None


def check_dependencies():
    print_title("========== Dependency Check ==========")

    required = ["nmap"]
    discovery_tools = [name for name in ("nmap", "netdiscover") if command_exists(name)]
    if os.environ.get("EH_SCANNER_WEB_GUI") == "1":
        # Keep the Web GUI checklist concise; CLI output remains unchanged.
        print(f"Network Discovery: {'FOUND' if discovery_tools else 'NOT FOUND'}")
    else:
        print(f"{'discovery':<12}: {', '.join(discovery_tools) if discovery_tools else 'No discovery tool found'}")
        print("              Network Discovery prefers Nmap; Netdiscover is a Linux/Unix fallback.")

    for command in required:
        status = "FOUND" if command_exists(command) else "NOT FOUND"
        print(f"{command:<12}: {status}")

    optional = ["searchsploit", "msfconsole"]

    for command in optional:
        status = "FOUND" if command_exists(command) else "NOT FOUND"
        print(f"{command:<12}: {status}")

    print("Platform     :", "Windows" if is_windows() else "Linux/Termux/Unix")


def run_command(command):
    """
    Cross-platform command execution.
    command may be a list or a string.
    """

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=isinstance(command, str)
        )
    except FileNotFoundError:
        return None


def run_with_animation(command):
    """Run a command with an animation, no time limit, and clean Ctrl+C handling.

    The user can wait as long as needed and press Ctrl+C to stop the running
    child process and return to EH Scanner. Captured output is returned so the
    calling scan/script workflow can save it in the TXT report.
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            shell=isinstance(command, str)
        )
    except FileNotFoundError:
        print_error("\nCommand not found. Check that the required tool is installed and on PATH.")
        return "", "Command not found.", 127
    except Exception as error:
        print_error(f"\nUnable to start command: {error}")
        return "", str(error), 1

    _register_gui_process(process)
    animation = ["|", "/", "-", "\\"]
    index = 0
    interrupted = False
    stdout = ""
    stderr = ""
    print("Press Ctrl+C (CLI) or use Stop task (Web GUI) to stop this operation.")
    try:
        while True:
            try:
                # The Web GUI injects this event into the scanner module. CLI mode
                # has no event and retains its normal Ctrl+C behavior.
                stop_event = globals().get("GUI_STOP_EVENT")
                if stop_event is not None and stop_event.is_set():
                    interrupted = True
                    break
                stdout, stderr = process.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                stop_event = globals().get("GUI_STOP_EVENT")
                if stop_event is not None and stop_event.is_set():
                    interrupted = True
                    break
                print(f"\r[ {animation[index]} ] Working... Stop task to cancel.", end="", flush=True)
                index = (index + 1) % len(animation)
        if interrupted and process.poll() is None:
            try:
                process.terminate()
                stdout, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
    except KeyboardInterrupt:
        interrupted = True
        print("\n\nStop requested. Stopping the running process...")
        if process.poll() is None:
            try:
                process.terminate()
                stdout, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            except Exception as error:
                stderr = (stderr or "") + f"\nCould not gracefully stop process: {error}"
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    stdout, extra_stderr = process.communicate(timeout=3)
                    stderr += extra_stderr or ""
                except Exception:
                    pass
        else:
            try:
                stdout, stderr = process.communicate()
            except Exception:
                pass

    if interrupted:
        print("[ ! ] Operation stopped by user.")
        stop_event = globals().get("GUI_STOP_EVENT")
        _unregister_gui_process(process)
        if stop_event is not None and stop_event.is_set():
            print("Returning to the EH Scanner main menu (Web GUI cancellation).")
            raise GUIStopRequested()
        # Ctrl+C while a child command runs cancels that command only.
        marker = "Stopped by user (GUI Stop/Ctrl+C)."
        stderr = ((stderr or "").rstrip() + "\n" + marker).strip()
        return stdout or "", stderr, 130

    _unregister_gui_process(process)
    if process.returncode == 0:
        print("\r[ ✓ ] Operation completed.                    ")
    else:
        print(f"\r[ ! ] Operation finished with exit code {process.returncode}.                    ")
    return stdout or "", stderr or "", process.returncode


# ============================================================
# FILE
# ============================================================

def save_file(filename, data):
    """Atomically save a report with read permissions for non-root users too.

    NamedTemporaryFile normally creates mode-0600 files. Because os.replace()
    preserves that mode, reports written as root could otherwise be unreadable
    by a regular user. Reports may contain sensitive scan/session details, so
    review and redact them before sharing on a multi-user machine.
    """
    directory = os.path.dirname(os.path.abspath(filename))
    os.makedirs(directory, mode=0o755, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=directory,
            prefix=".ehscanner_tmp_", suffix=".tmp", delete=False
        ) as file:
            temp_name = file.name
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        # Ensure the final report is readable regardless of whether root or a
        # regular account created it. Best-effort for platforms without chmod.
        try:
            os.chmod(temp_name, 0o644)
        except OSError:
            pass
        os.replace(temp_name, filename)
        try:
            os.chmod(filename, 0o644)
        except OSError:
            pass
    except Exception:
        if temp_name and os.path.exists(temp_name):
            try:
                os.remove(temp_name)
            except OSError:
                pass
        raise


# ============================================================
# AUTOMATIC PER-TARGET TXT REPORT
# ============================================================

def report_directory(kind=None):
    """Create three sibling report folders directly beneath report/."""
    report_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report")
    folders = {
        "TXT": os.path.join(report_root, "Default Report"),
        "PDF": os.path.join(report_root, "PDF Report"),
        "HTML": os.path.join(report_root, "HTML Report"),
    }
    os.makedirs(report_root, mode=0o755, exist_ok=True)
    for folder_path in folders.values():
        os.makedirs(folder_path, mode=0o755, exist_ok=True)
    # Keep the parent and report folders traversable/listable for non-root users
    # even when the scanner was previously run with elevated privileges.
    for folder_path in (report_root, *folders.values()):
        try:
            os.chmod(folder_path, 0o755)
        except OSError:
            pass
    folder_key = kind if kind in ("PDF", "HTML") else "TXT"
    return folders[folder_key]


def safe_target_filename(target):
    """Keep report filenames portable and prevent path traversal."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(target or "unknown")).strip("._-")
    return name or "unknown"


def has_report_content():
    """Do not create an empty report for a session that did no work."""
    return bool(
        report_data.get("scan_result", "").strip()
        or report_data.get("network_discovery_result", "").strip()
        or report_data.get("script_result", "").strip()
        or report_data.get("exploit_search_query")
        or report_data.get("metasploit_status", "").strip()
    )


def save_default_txt_report():
    if not report_data.get("target") or not has_report_content():
        return None
    folder = report_directory()
    filename = os.path.join(
        folder,
        safe_target_filename(report_data.get("target_input") or report_data["target"]) + ".txt",
    )
    # TXT is the session's canonical report: replace the same target's prior session.
    save_file(filename, build_report_text())
    print_success(f"Automatic TXT report saved: {filename}")
    return filename


# ============================================================
# SHOW LINES
# ============================================================

def show_lines(data):
    lines = data.splitlines()

    for i, line in enumerate(lines, start=1):
        print(f"{i}. {line}")

    return lines


# ============================================================
# TARGET SELECTION
# ============================================================

def nmap_address_family_args(target):
    """Return Nmap's IPv6 switch when the selected target is an IPv6 address."""
    try:
        address = ipaddress.ip_address(str(target).split("%", 1)[0])
    except ValueError:
        return []
    return ["-6"] if address.version == 6 else []


def select_target():
    print("\n========= Target Selection =========")
    print("Enter an IPv4/IPv6 address or domain name.")
    entered_target = input("Target IP/Domain: ").strip()

    if not entered_target:
        print("Target cannot be empty.")
        return None

    # Keep IPv4 preference for dual-stack domains to preserve existing behavior;
    # fall back to IPv6 when the domain has no IPv4 address.
    try:
        resolved_target = str(ipaddress.ip_address(entered_target))
    except ValueError:
        try:
            answers = socket.getaddrinfo(entered_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = []
            for answer in answers:
                candidate = answer[4][0]
                if candidate not in addresses:
                    addresses.append(candidate)
            resolved_target = next(
                (addr for addr in addresses if ipaddress.ip_address(addr.split("%", 1)[0]).version == 4),
                next((addr for addr in addresses if ipaddress.ip_address(addr.split("%", 1)[0]).version == 6), None)
            )
            if not resolved_target:
                raise socket.gaierror("No IPv4 or IPv6 address records found")
        except (socket.gaierror, UnicodeError, ValueError, IndexError):
            print_error("Could not resolve that domain to an IPv4 or IPv6 address.")
            return None

    print("\nSelected Target:")
    print(f"Input   : {entered_target}")
    print(f"Resolved: {resolved_target}")
    if nmap_address_family_args(resolved_target):
        print("Address family: IPv6 (Nmap will use -6 for supported scans)")

    reset_report(resolved_target)
    report_data["target_input"] = entered_target
    return resolved_target


# ============================================================
# SCAN MENU
# ============================================================

def scan_menu(target):
    scan_completed = False
    scan_result = ""

    while True:

        print(f"\n{C_CYAN}{C_BRIGHT}Choose Scan Type{C_RESET}")
        print_option("1. TCP Version OS Scan", C_GREEN)
        print_option("2. SYN Version OS Scan", C_YELLOW)
        print_option("3. Aggressive Scan", C_RED)
        print_option("4. Manual Nmap Scan", C_MAGENTA)
        print_option("5. Back", C_WHITE)
        print_option("0. Exit EH Scanner", C_RED)

        if scan_completed:
            print_option("6. Next Page", C_CYAN)

        try:
            option = int(input("Select option: "))

        except ValueError:
            print("Please enter a Number.")
            continue

        if option == 1:
            command = ["nmap"] + nmap_address_family_args(target) + ["-p-", "-sV", "-O", target]
            report_data["scan_type"] = "TCP Version OS Scan"

        elif option == 2:
            command = ["nmap"] + nmap_address_family_args(target) + ["-p-", "-sS", "-sV", "-O", target]
            report_data["scan_type"] = "SYN Version OS Scan"

        elif option == 3:
            command = ["nmap"] + nmap_address_family_args(target) + ["-p-", "-A", "-sV", "-O", target]
            report_data["scan_type"] = "Aggressive Scan"

        elif option == 4:
            extra_args = input("Enter Nmap arguments only (nmap and target are added automatically; type Back to cancel): ").strip()
            if extra_args.lower() == "back":
                continue
            if not extra_args:
                print_warning("No additional arguments entered; returning to scan menu.")
                continue
            # Parse user-supplied arguments without shell execution.
            import shlex
            try:
                parsed_args = shlex.split(extra_args, posix=not is_windows())
            except ValueError as error:
                print_error(f"Could not parse arguments: {error}")
                continue
            if not parsed_args:
                print_warning("Enter Nmap arguments, or type Back to cancel.")
                continue
            if any(os.path.basename(arg).lower() in ("nmap", "nmap.exe") for arg in parsed_args):
                print_warning("Enter Nmap arguments only. The application adds the nmap executable automatically.")
                continue
            if target in parsed_args:
                print_warning("Do not enter the target IP/domain; the application appends the selected target automatically.")
                continue
            # No scan flags are forced here: the user supplies all Nmap arguments.
            # Nmap itself and the currently selected target are added by the app.
            command = ["nmap"] + (nmap_address_family_args(target) if "-6" not in parsed_args else []) + parsed_args + [target]
            report_data["scan_type"] = "Manual Nmap Scan"

        elif option == 5:
            break

        elif option == 6 and scan_completed:
            next_page(target, scan_result)
            continue

        else:
            print("Invalid option")
            continue

        display_command = command_to_text(command)
        print("\nRunning:", display_command)

        report_data["scan_command"] = display_command

        try:
            result_stdout, result_stderr, return_code = run_with_animation(command)
        except GUIStopRequested:
            stop_event = globals().get("GUI_STOP_EVENT")
            if stop_event is not None:
                stop_event.clear()
            print_warning("Task stopped. You are still in the current scan menu.")
            continue

        scan_result = result_stdout
        report_data["scan_result"] = result_stdout
        if result_stderr:
            report_data["scan_result"] += "\n[STDERR]\n" + result_stderr

        print("\n" + scan_result)

        if result_stderr:
            print("\nError")
            print(result_stderr)

        if return_code != 0:
            print(f"\nNmap returned exit code: {return_code}")

        # Keep scan output in the in-memory report session; save a checkpoint after each scan attempt.
        scan_completed = return_code == 0 and bool(result_stdout.strip())
        save_default_txt_report()


def command_to_text(command):
    if isinstance(command, str):
        return command

    # Simple display representation for normal command arguments.
    return " ".join(str(item) for item in command)


# ============================================================
# NEXT PAGE
# ============================================================

def next_page(target, scan_result):

    print_title("======== Next Page ========")

    open_ports = []

    for line in scan_result.splitlines():

        line = line.strip()

        if "/tcp" in line or "/udp" in line:

            if "open" in line:
                open_ports.append(line)

    report_data["open_ports"] = open_ports

    if not open_ports:
        print("No open ports found")
        return

    print("\nOpening ports:\n")

    for index, line in enumerate(open_ports, start=1):
        print(f"{index}. {line}")

    try:
        number = int(input("\nSelect port number: "))

    except ValueError:
        print("Invalid input.")
        return

    if number < 1 or number > len(open_ports):
        print("Invalid port")
        return

    selected_line = open_ports[number - 1]

    port_info = extract_port_info(scan_result, selected_line)

    report_data["selected_port"] = selected_line
    report_data["port_info"] = port_info

    print_title("========= Port Info =========")
    print(f"Port        : {port_info['port']}")
    print(f"Protocol    : {port_info['protocol']}")
    print(f"State       : {port_info['state']}")
    print(f"Service     : {port_info['service']}")
    print(f"Version     : {port_info['version']}")

    exploit_search(target, port_info)


# ============================================================
# PORT INFORMATION
# ============================================================

def extract_port_info(scan_result, selected_line):

    parts = selected_line.split()

    port_info = {
        "port": None,
        "state": None,
        "service": None,
        "protocol": None,
        "version": None
    }

    if not parts:
        return port_info

    port_protocol = parts[0]

    if "/" in port_protocol:

        port, protocol = port_protocol.split("/", 1)

        port_info["port"] = port
        port_info["protocol"] = protocol

    if len(parts) >= 2:
        port_info["state"] = parts[1]

    if len(parts) >= 3:
        port_info["service"] = parts[2]

    if len(parts) >= 4:
        port_info["version"] = " ".join(parts[3:])

    return port_info


# ============================================================
# QUERY
# ============================================================

def build_query(port_info):

    query_parts = []

    if port_info["service"]:
        query_parts.append(port_info["service"])

    if port_info["version"]:
        query_parts.append(port_info["version"])

    return " ".join(query_parts).strip()


# ============================================================
# EXPLOIT-DB
# ============================================================

def exp_db(query):

    if not command_exists("searchsploit"):
        return "searchsploit was not found on this system."

    print("\nSearching Exploit_DB....\n")

    result = subprocess.run(
        ["searchsploit", query],
        capture_output=True,
        text=True
    )

    return result.stdout


# ============================================================
# METASPLOIT SEARCH
# ============================================================

def search_meta(query):

    if not command_exists("msfconsole"):
        return "msfconsole was not found on this system."

    print("\nSearching Metasploit....\n")

    command = f"search {query}; exit"

    result = subprocess.run(
        ["msfconsole", "-q", "-x", command],
        capture_output=True,
        text=True
    )

    return result.stdout


# ============================================================
# ADDITIONAL VULNERABILITY / EXPLOIT SOURCES
# ============================================================
# Session-only API key configuration. Keys are never written to reports or disk.
API_KEYS = {"VULNCHECK_API_KEY": os.environ.get("VULNCHECK_API_KEY", "").strip()}


def api_key_settings_menu():
    """Configure and verify the optional VulnCheck key for this run only."""
    while True:
        print_title("========== API Key Settings ==========")
        configured = bool(API_KEYS.get("VULNCHECK_API_KEY"))
        print("1. Add / Change VulnCheck API key")
        print("2. Verify VulnCheck API key")
        print("3. Remove VulnCheck API key")
        print_option("4. Back", C_WHITE)
        print_option("0. Exit EH Scanner", C_RED)
        print("Current status:", "Configured (hidden)" if configured else "Not configured")
        choice = input("Select option: ").strip()
        if choice == "1":
            import getpass
            token = getpass.getpass("Enter VulnCheck API key (input hidden): ").strip()
            if token:
                API_KEYS["VULNCHECK_API_KEY"] = token
                print_success("API key set for this session only; it was not saved to disk.")
            else:
                print_warning("Empty key not saved.")
        elif choice == "2":
            token = API_KEYS.get("VULNCHECK_API_KEY", "")
            if not token:
                print_warning("No key configured.")
                continue
            try:
                url = "https://api.vulncheck.com/v3/index/exploits?limit=1"
                web_get(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"}, timeout=12)
                print_success("VulnCheck accepted the request. (Key itself remains hidden.)")
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    print_error(f"VulnCheck rejected the key (HTTP {exc.code}).")
                elif exc.code == 429:
                    print_warning("VulnCheck rate limit reached (HTTP 429).")
                else:
                    print_warning(f"VulnCheck verification returned HTTP {exc.code}.")
            except Exception as exc:
                print_warning(f"Could not verify key due to connection/API error: {exc}")
        elif choice == "3":
            API_KEYS["VULNCHECK_API_KEY"] = ""
            print_success("VulnCheck key removed from this session.")
        elif choice == "4":
            return
        else:
            print_warning("Choose 1-4.")



def web_get(url, headers=None, timeout=12):
    """Fetch a public API/page using the Python standard library."""
    request_headers = {"User-Agent": "EH-Scanner/1.0 (authorized security research)"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_cves(text):
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text or "", re.IGNORECASE)))


def search_nvd(query):
    """Search NVD's public CVE API by keyword."""
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 5})
        data = json.loads(web_get(url, timeout=20))
        rows = data.get("vulnerabilities", [])
        if not rows:
            return "No matching CVE records returned by NVD."
        out = []
        for row in rows:
            cve = row.get("cve", {})
            desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_label = "CVSS: unavailable"
            for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_rows = metrics.get(metric_key, [])
                if metric_rows:
                    cvss_data = metric_rows[0].get("cvssData", {})
                    score_value = cvss_data.get("baseScore")
                    severity_value = metric_rows[0].get("baseSeverity", cvss_data.get("baseSeverity", "unknown"))
                    if score_value is not None:
                        cvss_label = f"CVSS: {score_value} ({severity_value})"
                    break
            out.append(f"{cve.get('id', 'Unknown CVE')} | Published: {cve.get('published', 'Unknown')} | {cvss_label}\n{desc[:500]}\nhttps://nvd.nist.gov/vuln/detail/{cve.get('id', '')}")
        return "\n\n".join(out)
    except Exception as exc:
        return f"NVD API search failed: {exc}"


def search_github_advisories(query):
    """Use GitHub's global advisory API for CVE identifiers; otherwise provide a query link."""
    cves = extract_cves(query)
    if not cves:
        url = "https://github.com/advisories?query=" + urllib.parse.quote(query)
        return "GitHub's advisory API needs a CVE/GHSA or package-specific query for a precise lookup.\nSearch link: " + url
    out = []
    for cve in cves[:3]:
        try:
            url = "https://api.github.com/advisories?" + urllib.parse.urlencode({"cve_id": cve, "per_page": 5})
            data = json.loads(web_get(url, headers={"Accept": "application/vnd.github+json"}, timeout=15))
            if not data:
                out.append(f"{cve}: no GitHub advisory returned.")
            for row in data[:5]:
                out.append(f"{row.get('ghsa_id', '')} | {row.get('summary', '')} | Severity: {row.get('severity', 'unknown')}\n{row.get('html_url', '')}")
        except Exception as exc:
            out.append(f"{cve}: GitHub API search failed: {exc}")
    return "\n\n".join(out)


def search_cisa_kev(query):
    """Search the public CISA Known Exploited Vulnerabilities catalog."""
    try:
        data = json.loads(web_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=20))
        terms = [x.lower() for x in re.findall(r"[a-zA-Z0-9_.+-]+", query) if len(x) > 1]
        rows = data.get("vulnerabilities", [])
        matches = []
        for row in rows:
            haystack = " ".join(str(row.get(k, "")) for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")).lower()
            if terms and all(term in haystack for term in terms):
                matches.append(row)
        if not matches:
            return "No matching entry found in CISA KEV. Note: KEV lists known exploited vulnerabilities, not all available exploits."
        out = []
        for row in matches[:10]:
            out.append(f"{row.get('cveID')} | {row.get('vendorProject')} {row.get('product')}\n{row.get('vulnerabilityName')}\nDate Added: {row.get('dateAdded')} | Required Action: {row.get('requiredAction')}\nhttps://nvd.nist.gov/vuln/detail/{row.get('cveID')}")
        return "\n\n".join(out)
    except Exception as exc:
        return f"CISA KEV search failed: {exc}"


def search_osv(query):
    """OSV is package/version-oriented; do not guess an ecosystem from an Nmap banner."""
    cves = extract_cves(query)
    if cves:
        out = []
        for cve in cves[:3]:
            try:
                data = json.loads(web_get("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(cve), timeout=12))
                out.append(f"{data.get('id', cve)} | {data.get('summary', 'No summary')}\nhttps://osv.dev/vulnerability/{data.get('id', cve)}")
            except urllib.error.HTTPError as exc:
                out.append(f"{cve}: OSV returned HTTP {exc.code}.")
            except Exception as exc:
                out.append(f"{cve}: OSV lookup failed: {exc}")
        return "\n\n".join(out)
    return "OSV requires a package name plus ecosystem/version for a reliable API query; an Nmap service banner alone is insufficient.\nSearch link: https://osv.dev/list?query=" + urllib.parse.quote(query)


def search_rapid7(query):
    url = "https://www.rapid7.com/db/?q=" + urllib.parse.quote(query)
    return "Rapid7's public module database search page (results can be reviewed there):\n" + url


def search_packetstorm(query):
    url = "https://packetstormsecurity.com/search/?q=" + urllib.parse.quote(query)
    return "Packet Storm search: " + url


def search_vulncheck(query):
    token = API_KEYS.get("VULNCHECK_API_KEY", "").strip()
    cves = extract_cves(query)
    if not token:
        return "Automatic VulnCheck API lookup requires a VulnCheck API token. Set VULNCHECK_API_KEY in the environment.\nSearch/docs: https://docs.vulncheck.com/"
    if not cves:
        return "VulnCheck exploit-index lookup is CVE-oriented; no CVE was detected in this query.\nSearch/docs: https://docs.vulncheck.com/"
    out = []
    for cve in cves[:3]:
        try:
            url = "https://api.vulncheck.com/v3/index/exploits?" + urllib.parse.urlencode({"cve": cve, "limit": 5})
            data = json.loads(web_get(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"}, timeout=15))
            records = data.get("data", [])
            if not records:
                out.append(f"{cve}: no VulnCheck exploit records returned.")
            for row in records[:5]:
                out.append(f"{cve} | {row.get('name', row.get('title', 'Exploit record'))}\n{row.get('url', row.get('source', ''))}")
        except Exception as exc:
            out.append(f"{cve}: VulnCheck API lookup failed: {exc}")
    return "\n\n".join(out)


def search_epss(query):
    cves = extract_cves(query)
    if not cves:
        return "FIRST EPSS scores are available per CVE; no CVE identifier was detected in the service/version query.\nSearch/docs: https://www.first.org/epss/"
    try:
        url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": ",".join(cves[:20])})
        data = json.loads(web_get(url, timeout=12))
        rows = data.get("data", [])
        if not rows:
            return "FIRST EPSS returned no scores for the CVE identifiers found."
        return "\n".join(f"{row.get('cve')} | EPSS: {row.get('epss')} | Percentile: {row.get('percentile')}" for row in rows)
    except Exception as exc:
        return f"FIRST EPSS lookup failed: {exc}"


def classify_source_status(result_text):
    """Classify a source response without treating API errors as empty results."""
    text = str(result_text or "").lower()
    if any(token in text for token in ("http 429", "rate limit", "rate-limited", "too many requests")):
        return "RATE LIMITED"
    if any(token in text for token in ("http 401", "http 403", "authentication required", "invalid api key", "rejected the key", "requires an api key", "requires a vulncheck api token", "no token configured", "not configured")):
        return "AUTHENTICATION / CONFIGURATION REQUIRED"
    if any(token in text for token in ("search failed", "lookup failed", "api search failed", "api lookup failed", "could not verify", "connection error", "unavailable", "command not found", "returned http 5")):
        return "UNAVAILABLE / ERROR"
    if any(token in text for token in ("no matching", "no results", "no advisory returned", "no records returned", "no scores", "no matching entry", "no cve identifier was detected")):
        return "NO MATCHING RESULTS"
    if "search link:" in text or "search/docs:" in text or "search link" in text:
        return "REFERENCE LINK ONLY (NOT A VERIFIED RESULT)"
    if not text.strip():
        return "NO RESULTS RETURNED"
    return "RESULTS / REFERENCES RETURNED (VALIDATION REQUIRED)"


def search_additional_sources(query, prior_source_results=None):
    """Search each additional source, then query EPSS for CVEs found across results.

    EPSS is a per-CVE probability score, so it is queried only after CVE IDs have
    been collected from the original query and the preceding source responses.
    """
    searches = [
        ("NVD", search_nvd),
        ("GitHub Security Advisories", search_github_advisories),
        ("CISA KEV", search_cisa_kev),
        ("OSV", search_osv),
        ("Rapid7", search_rapid7),
        ("Packet Storm", search_packetstorm),
        ("VulnCheck", search_vulncheck),
    ]
    results = {}
    statuses = {}
    for name, function in searches:
        print(f"\nSearching {name}...")
        try:
            raw_result = function(query)
        except Exception as exc:
            raw_result = f"Search failed: {exc}"
        status = classify_source_status(raw_result)
        statuses[name] = status
        results[name] = f"Source Status: {status}\n{raw_result or 'No results returned.'}"
        print(f"\n--- {name} Results | Status: {status} ---")
        print(raw_result or "No results returned.")

    # Aggregate CVE identifiers from the original query, Metasploit/Exploit-DB,
    # and the additional-source responses before requesting EPSS scores.
    prior_source_results = prior_source_results or {}
    aggregate_text = query + "\n" + "\n".join(
        [str(value) for value in prior_source_results.values()] + list(results.values())
    )
    cves = extract_cves(aggregate_text)
    epss_query = "\n".join(cves) if cves else aggregate_text
    print("\nSearching FIRST EPSS...")
    try:
        epss_result = search_epss(epss_query)
    except Exception as exc:
        epss_result = f"FIRST EPSS lookup failed: {exc}"
    epss_status = classify_source_status(epss_result)
    statuses["FIRST EPSS"] = epss_status
    results["FIRST EPSS"] = f"Source Status: {epss_status}\n{epss_result or 'No results returned.'}"
    print(f"\n--- FIRST EPSS Results | Status: {epss_status} ---")
    print(epss_result or "No results returned.")

    report_data["additional_source_statuses"] = statuses
    return results


# ============================================================
# SCORE
# ============================================================


# ============================================================
# SCORE
# ============================================================

def calc(text, port_info):

    score = 0

    text_lower = text.lower()

    service = port_info.get("service")
    version = port_info.get("version")

    if service and service.lower() in text_lower:
        score += 50

    if version and version.lower() in text_lower:
        score += 50

    return score


def get_recommendation(score):

    if score >= 70:
        return "High Match"

    elif score >= 50:
        return "Medium Match"

    return "Low Match"


# ============================================================
# EXPLOIT SEARCH
# ============================================================

def exploit_search(target, port_info):

    search_query = build_query(port_info)

    print_title("========= Exploit Search =========")
    print("Searching For:", search_query)

    report_data["exploit_search_query"] = search_query

    # Requested order: Metasploit first, then Exploit-DB, then extra sources.
    metasploit = search_meta(search_query)
    exploitdb = exp_db(search_query)
    additional_results = search_additional_sources(
        search_query,
        {"Metasploit": metasploit, "Exploit-DB": exploitdb}
    )

    report_data["metasploit_result"] = metasploit
    report_data["exploitdb_result"] = exploitdb
    report_data["additional_source_results"] = additional_results
    save_default_txt_report()

    return show_exploits(
        target,
        exploitdb,
        metasploit,
        port_info
    )


# ============================================================
# SHOW EXPLOITS
# ============================================================

def show_exploits(target, exploitdb, metasploit, port_info):

    exploits = []

    for line in exploitdb.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("-"):
            continue

        if line.startswith("Exploit Title"):
            continue

        if line.startswith("Shellcodes:"):
            continue

        if "|" in line:
            exploits.append({
                "source": "Exploit-DB",
                "name": line
            })

    for line in metasploit.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("Name"):
            continue

        if line.startswith("----"):
            continue

        parts = line.split()

        for part in parts:

            if part.startswith("exploit/"):
                exploits.append({
                    "source": "Metasploit",
                    "name": part
                })
                break

    unique_exploits = []
    seen = set()

    for exploit in exploits:

        key = (
            exploit["source"],
            exploit["name"]
        )

        if key not in seen:
            seen.add(key)
            unique_exploits.append(exploit)

    exploits = unique_exploits

    if not exploits:
        print_warning("\nExploit Not Found")
        print_warning("No matching Metasploit or Exploit-DB entries were parsed for this selected port.")

    if exploits:
        print_title("==== Available Exploits =====")

    for index, exploit in enumerate(exploits, start=1):

        score = calc(exploit["name"], port_info)
        recommendation = get_recommendation(score)

        print(f"{index}. [{exploit['source']}]")
        print(f"Exploit: {exploit['name']}")
        print(f"Match Score: {score}")
        print(f"Recommendation: {recommendation}")
        print("=========================")

    print("\n========= Select Exploit =========")
    if exploits:
        print_option("1. Select an Exploit", C_GREEN)
        print_option("2. Continue Without Selecting Exploit", C_YELLOW)
        print_option("3. Back", C_CYAN)
    else:
        print_option("1. Continue Without Selecting Exploit", C_GREEN)
        print_option("2. Back", C_CYAN)
    print_option("0. Back / Exit EH Scanner", C_RED)
    try:
        menu_choice = int(input("Select option: "))
    except ValueError:
        print("Invalid Selection.")
        return None

    if menu_choice == 0:
        return None

    if exploits:
        if menu_choice == 3:
            return None
        if menu_choice == 2:
            return continue_without_exploit(target, port_info, exploits)
        if menu_choice != 1:
            print("Invalid Selection.")
            return None
    else:
        if menu_choice == 0 or menu_choice == 2:
            return None
        if menu_choice != 1:
            print("Invalid Selection.")
            return None
        return continue_without_exploit(target, port_info, exploits)

    selection_text = input("Select Exploit number (or type Back to return): ").strip()
    if selection_text.lower() in ("back", "b", "0"):
        print("Returning to the previous menu.")
        return None
    try:
        selection = int(selection_text)
    except ValueError:
        print("Invalid Selection. Enter an exploit number or Back.")
        return None
    if selection < 1 or selection > len(exploits):
        print("Invalid Selection.")
        return None

    selected_exploit = exploits[selection - 1]

    score = calc(selected_exploit["name"], port_info)
    recommendation = get_recommendation(score)

    print_title("========== Selected Exploit ==========")
    print(f"Source: {selected_exploit['source']}")
    print(f"Exploit: {selected_exploit['name']}")
    print(f"Match Score: {score}")
    print(f"Recommendation: {recommendation}")

    report_data["selected_exploit"] = selected_exploit

    config = create_config(
        target,
        port_info,
        selected_exploit,
        score,
        recommendation
    )

    show_config(
        config,
        exploits,
        target,
        port_info
    )

    return config


def continue_without_exploit(target, port_info, exploits):
    report_data["selected_exploit"] = None
    report_data["exploit_search_query"] = report_data.get("exploit_search_query") or "Exploit search completed; user continued without selecting an exploit."
    print_success("Continuing to the next page without selecting an exploit.")
    config = create_config(target, port_info, None, 0, "No exploit selected")
    show_config(config, exploits, target, port_info)
    return config


# ============================================================
# CREATE CONFIG
# ============================================================

def create_config(target, port_info, exploit, score, recommendation):

    config = {
        "target": target,
        "port": port_info["port"],
        "state": port_info["state"],
        "protocol": port_info["protocol"],
        "service": port_info["service"],
        "match_score": score,
        "recommendation": recommendation,
        "version": port_info["version"],
        "exploit": exploit["name"] if exploit else None,
        "source": exploit["source"] if exploit else "None selected",
        "rhost": target,
        "rport": port_info["port"],
        "lhost": get_local_ip(),
        "lport": "4444"
    }

    report_data["configuration"] = config
    # Refresh the TXT report after exploit selection and configuration are known.
    try:
        save_default_txt_report()
    except Exception as exc:
        print_warning(f"Could not refresh the automatic TXT report: {exc}")

    return config


# ============================================================
# METASPLOIT HANDLER
# ============================================================

def clean_terminal_ansi(text):
    return re.sub(
        r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])',
        '',
        text
    ).strip()


def run_metasploit_handler(config):

    print_title("========== Metasploit Handler ==========")

    module = clean_terminal_ansi(config["exploit"])
    print("Selected Metasploit module:")
    print(module)
    print("\nTarget:")
    print(config["target"])
    print("Port:")
    print(config["port"])

    if not module.startswith("exploit/"):
        print_error("\nInvalid Metasploit module.")
        report_data["metasploit_status"] = "Invalid Metasploit module; session not launched."
        return False

    rc_content = (
        f"use {module}\n"
        f"set RHOSTS {config['rhost']}\n"
        f"set RPORT {config['rport']}\n"
        f"set LHOST {config['lhost']}\n"
        f"set LPORT {config['lport']}\n"
        f"show options\n"
    )
    rc_path = None
    transcript_path = None
    session = report_data.setdefault("metasploit_session", {})
    session["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    session["end_time"] = None
    session["output"] = ""
    session["capture_status"] = "Unavailable"

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False, encoding="utf-8") as rc_file:
            rc_file.write(rc_content)
            rc_path = rc_file.name

        command = ["msfconsole", "-q", "-r", rc_path]
        print("\nLaunching Metasploit...")
        print("The interactive terminal transcript may include commands and output.")
        print("Type 'exit' to return to EH Scanner. Use only on authorized systems.\n")
        report_data["metasploit_status"] = "Metasploit launched; session logging pending."

        interactive_runner = globals().get("GUI_INTERACTIVE_RUNNER")
        process = None
        if interactive_runner is not None:
            # The browser runner streams output live and forwards browser input to msfconsole.
            result = interactive_runner(command)
            session["output"] = clean_terminal_ansi(result.stdout or "")
            session["capture_status"] = "Captured interactive input/output through the local Web GUI."
        else:
            # Keep the CLI's existing terminal-based interaction unchanged.
            script_path = shutil.which("script") if not is_windows() else None
            if script_path:
                fd, transcript_path = tempfile.mkstemp(prefix="ehscanner_msf_", suffix=".log")
                os.close(fd)
                wrapped = [script_path, "-q", "-c", shlex.join(command), transcript_path]
                result = subprocess.run(wrapped, check=False)
                session["capture_status"] = "Capture attempted; verifying transcript file."
            else:
                result = subprocess.run(command, check=False)
                session["capture_status"] = "Unavailable: interactive terminal logging utility not found; output was not captured."

        if transcript_path and os.path.exists(transcript_path):
            try:
                with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
                    session["output"] = clean_terminal_ansi(f.read())
                if session["output"]:
                    session["capture_status"] = "Captured terminal transcript (script utility)."
                else:
                    session["capture_status"] = "Transcript file created but empty; no terminal input/output was captured."
            except OSError as exc:
                session["capture_status"] = f"Partial/unavailable: could not read transcript ({exc})."
        elif transcript_path:
            session["capture_status"] = "Unavailable: transcript file was not created; output was not captured."
        session["exit_code"] = result.returncode
        report_data["metasploit_status"] = f"Returned from Metasploit (exit code {result.returncode})."

    except FileNotFoundError:
        print_error("\nError: msfconsole was not found.")
        report_data["metasploit_status"] = "Metasploit was not found."
        session["capture_status"] = "Unavailable: msfconsole not found."
        return False
    except KeyboardInterrupt:
        report_data["metasploit_status"] = "Metasploit session interrupted by user."
        session["capture_status"] = session.get("capture_status", "Unavailable")
        print("\nMetasploit interrupted; returning to EH Scanner.")
    except Exception as error:
        print_error("\nMetasploit error:")
        print(error)
        report_data["metasploit_status"] = f"Metasploit error: {error}"
        session["capture_status"] = f"Unavailable due to error: {error}"
        return False
    finally:
        if "process" in locals() and process is not None:
            _unregister_gui_process(process)
        session["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if rc_path and os.path.exists(rc_path):
            try: os.remove(rc_path)
            except OSError: pass
        if transcript_path and os.path.exists(transcript_path):
            try: os.remove(transcript_path)
            except OSError: pass
        try:
            save_default_txt_report()
        except Exception as exc:
            print_warning(f"Could not refresh the automatic TXT report: {exc}")

    print("\nReturned from Metasploit.")
    return True


# ============================================================
# EXPLOIT-DB HANDLER
# ============================================================

def run_exploitdb_handler(config):

    print_title("========== Exploit-DB Handler ==========")
    print("Selected Exploit-DB entry:")
    print(config["exploit"])

    print("\nTarget:")
    print(config["target"])

    print("Port:")
    print(config["port"])

    print("\nService:")
    print(config["service"])

    print("Version:")
    print(config["version"])

    print("\nMatch Score:")
    print(config["match_score"])

    print("Recommendation:")
    print(config["recommendation"])

    print("\nExploit-DB source selected.")
    print("Metasploit will NOT be launched.")
    print("\nThis entry remains in the current terminal workflow.")

    return True


# ============================================================
# RUN EXPLOIT
# ============================================================

def run_exploit(config):

    print_title("========== Lab Run ==========")

    print("Source     :", config["source"])
    print("Exploit    :", config["exploit"])
    print("Target     :", config["target"])
    print("Port       :", config["port"])
    print("Protocol   :", config["protocol"])
    print("Service    :", config["service"])
    print("Version    :", config["version"])
    print("Match Score:", config["match_score"])
    print("Recommend. :", config["recommendation"])

    if config["source"] == "Metasploit":
        return run_metasploit_handler(config)

    elif config["source"] == "Exploit-DB":
        return run_exploitdb_handler(config)

    else:
        print("\nUnknown Exploit Source.")
        return False


# ============================================================
# NSE SCRIPT RECOMMENDATION
# ============================================================

SERVICE_SCRIPT_MAP = {
    "ftp": "ftp*",
    "ssh": "ssh*",
    "http": "http*",
    "https": "http*",
    "http-proxy": "http*",
    "smb": "smb*",
    "microsoft-ds": "smb*",
    "dns": "dns*",
    "domain": "dns*",
    "smtp": "smtp*",
    "submission": "smtp*",
    "imap": "imap*",
    "imaps": "imap*",
    "pop3": "pop3*",
    "pop3s": "pop3*",
    "mysql": "mysql*",
    "ms-sql": "ms-sql*",
    "mssql": "ms-sql*",
    "snmp": "snmp*",
    "ldap": "ldap*",
    "rdp": "rdp*",
    "telnet": "telnet*",
    "vnc": "vnc*",
    "nfs": "nfs*",
    "rpcbind": "rpc*"
}


def get_manual_script(service):
    if not service:
        return None
    return SERVICE_SCRIPT_MAP.get(service.lower())


def build_auto_script_command(config):
    """
    Nmap's built-in default NSE script scan.
    This is the Auto Script mode requested for the tool.
    """
    return [
        "nmap",
        *nmap_address_family_args(config["target"]),
        "-p", str(config["port"]),
        "-sC",
        config["target"]
    ]


def build_manual_script_command(config):
    """
    Service-aware NSE recommendation.
    It does not ask the beginner to configure a separate script menu.
    """
    script_name = get_manual_script(config.get("service"))

    if not script_name:
        return None

    return [
        "nmap",
        *nmap_address_family_args(config["target"]),
        "-p", str(config["port"]),
        "--script", script_name,
        config["target"]
    ]


def show_script_recommendations(config):
    print_title("========== NSE Script Recommendation ==========")

    target = config["target"]
    port = config["port"]
    protocol = config["protocol"]
    service = config["service"]
    version = config["version"]

    print(f"Target   : {target}")
    print(f"Port     : {port}")
    print(f"Protocol : {protocol}")
    print(f"Service  : {service}")
    print(f"Version  : {version}")

    auto_command = build_auto_script_command(config)
    manual_command = build_manual_script_command(config)

    auto_text = command_to_text(auto_command)

    print("\n[ AUTO SCRIPT SCAN ]")
    print("Nmap built-in default NSE scripts:")
    print(auto_text)

    report_data["script_recommendation"] = {
        "auto": auto_text,
        "manual": command_to_text(manual_command) if manual_command else None
    }

    if manual_command:

        manual_text = command_to_text(manual_command)

        print("\n[ MANUAL SCRIPT SCAN ]")
        print(f"Recommended for service '{service}':")
        print(manual_text)

        report_data["script_command"] = manual_text

    else:

        print("\n[ MANUAL SCRIPT SCAN ]")
        print("No service-specific NSE recommendation is available.")

        report_data["script_command"] = None


# ============================================================
# AUTO SCRIPT
# ============================================================

def auto_script(config):

    print_title("========== Auto Script ==========")

    show_script_recommendations(config)

    command = build_auto_script_command(config)

    print("\nAuto mode uses Nmap's built-in -sC NSE scan.")
    print("No exploit is automatically selected or launched.")

    confirm = input("\nRun Auto Script Scan? (y/n): ").strip().lower()

    if confirm != "y":
        print_warning("Auto Script Scan cancelled.")
        return

    report_data["script_type"] = "Auto NSE Script Scan"
    report_data["script_command"] = command_to_text(command)

    stdout, stderr, return_code = run_with_animation(command)

    print("\n========== Auto Script Output ==========")
    print(stdout)

    if stderr:
        print("\nError:")
        print(stderr)

    report_data["script_result"] += (
        "\nAuto NSE Script Scan:\n"
        + command_to_text(command)
        + "\n\nOutput:\n"
        + stdout
        + ("\n\nError / Status:\n" + stderr if stderr else "")
        + "\n"
    )

    if return_code != 0:
        report_data["script_result"] += f"Exit Code: {return_code}\n"
    save_default_txt_report()


# ============================================================
# MANUAL SCRIPT
# ============================================================

def manual_script(config):

    print_title("========== Manual Script ==========")

    show_script_recommendations(config)

    recommended = build_manual_script_command(config)

    if recommended:

        print("\nRecommended Manual NSE command:")
        print(command_to_text(recommended))

        print("\n1. Run Recommended Script")
        print("2. Enter Another NSE Script")
        print_option("3. Back", C_CYAN)
        print_option("0. Exit EH Scanner", C_RED)

        try:
            choice = int(input("\nSelect option: "))
        except ValueError:
            print("Invalid input.")
            return

        if choice == 3:
            return

        if choice == 1:
            command = recommended

        elif choice == 2:
            script = input(
                "\nEnter NSE script name/category (or Back): "
            ).strip()

            if script.lower() == "back":
                return

            if not script:
                print("No script entered.")
                return

            command = [
                "nmap",
                *nmap_address_family_args(config["target"]),
                "-p", str(config["port"]),
                "--script", script,
                config["target"]
            ]

        else:
            print("Invalid option.")
            return

    else:

        print(
            "\nNo service-specific recommendation is available."
        )

        script = input(
            "Enter an NSE script/category (or Back): "
        ).strip()

        if script.lower() == "back":
            return

        if not script:
            print("No script entered.")
            return

        command = [
            "nmap",
            *nmap_address_family_args(config["target"]),
            "-p", str(config["port"]),
            "--script", script,
            config["target"]
        ]

    display_command = command_to_text(command)

    print("\nSelected NSE command:")
    print(display_command)

    confirm = input(
        "\nRun this NSE command? (y/n): "
    ).strip().lower()

    if confirm != "y":
        print("Command cancelled.")
        return

    report_data["script_type"] = "Manual NSE Script Scan"
    report_data["script_command"] = display_command

    stdout, stderr, return_code = run_with_animation(command)

    print("\n========== Manual Script Output ==========")
    print(stdout)

    if stderr:
        print("\nError:")
        print(stderr)

    report_data["script_result"] += (
        "\nManual NSE Script Scan:\n"
        + display_command
        + "\n\nOutput:\n"
        + stdout
        + ("\n\nError / Status:\n" + stderr if stderr else "")
        + "\n"
    )

    if return_code != 0:
        report_data["script_result"] += f"Exit Code: {return_code}\n"
    save_default_txt_report()


# ============================================================
# REPORT TEXT
# ============================================================

def _web_gui_clean_metasploit_output(value):
    """Remove common console noise while retaining useful results and errors."""
    if not value:
        return ""
    noise = re.compile(
        r"(?:^|\s)(?:status(?:ed)?\s+in(?:put)?|ioctl\s+for\s+devices|"
        r"loading\s+.*(?:module|plugin|framework)|msf[0-9a-z]*\s*>\s*)",
        re.IGNORECASE,
    )
    kept = []
    for line in clean_terminal_ansi(str(value)).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if noise.search(stripped):
            continue
        kept.append(line.rstrip())
    return "\n".join(kept)


def build_report_text():

    data = report_data

    report = []

    report.append("============================================================")
    report.append("                    EH SCANNER REPORT")
    report.append("          Network Security Assessment Report")
    report.append("                         EH Academy")
    report.append("============================================================")
    report.append("")

    report.append(f"Report Time : {data['start_time']}")
    report.append(f"Target      : {data['target']}")
    if data.get("target_input") and data.get("target_input") != data.get("target"):
        report.append(f"Input Target: {data['target_input']}")
    report.append(f"Scan Type   : {data['scan_type']}")
    report.append("")

    if data.get("network_discovery_result"):
        report.append("============= NETWORK DISCOVERY RESULT =============")
        report.append(data["network_discovery_result"])
        report.append("")

    report.append("================ SCAN COMMAND =================")
    report.append(str(data["scan_command"]))
    report.append("")

    report.append("================ SCAN RESULT ===================")
    report.append(data["scan_result"])
    report.append("")

    report.append("================ OPEN PORTS ====================")

    for port in data["open_ports"]:
        report.append(port)

    report.append("")

    report.append("================ SELECTED PORT =================")
    report.append(str(data["selected_port"]))
    report.append("")

    report.append("================ PORT INFORMATION ==============")
    report.append(str(data["port_info"]))
    report.append("")

    report.append("============== NSE RECOMMENDATION ==============")
    report.append(str(data["script_recommendation"]))
    report.append("")

    report.append("================ SCRIPT COMMAND =================")
    report.append(str(data["script_command"]))
    report.append("")

    report.append("================ EXPLOIT SEARCH ================")
    report.append(f"Query: {data['exploit_search_query']}")
    report.append("")

    report.append("---------------- Metasploit ----------------")
    report.append(data["metasploit_result"])
    report.append("")

    report.append("---------------- Exploit-DB ----------------")
    report.append(data["exploitdb_result"])
    report.append("")

    report.append("========== ADDITIONAL VULNERABILITY SOURCES ==========")
    for source_name, source_result in data.get("additional_source_results", {}).items():
        report.append(f"---------------- {source_name} ----------------")
        report.append(str(source_result))
        report.append("")

    report.append("================ SELECTED EXPLOIT =============")
    report.append(str(data["selected_exploit"]))
    report.append("")

    report.append("================ CONFIGURATION ================")
    report.append(str(data["configuration"]))
    report.append("")

    report.append("================ SCRIPT RESULT =================")
    report.append(data["script_result"])
    report.append("")

    report.append("================ METASPLOIT STATUS =============")
    report.append(data["metasploit_status"])
    report.append("")

    msf_session = data.get("metasploit_session", {})
    report.append("============= METASPLOIT SESSION LOG ============")
    report.append(f"Capture status: {msf_session.get('capture_status', 'Not run')}")
    report.append(f"Start time: {msf_session.get('start_time')}")
    report.append(f"End time: {msf_session.get('end_time')}")
    report.append(f"Exit code: {msf_session.get('exit_code', 'N/A')}")
    report.append("Captured terminal input/output:")
    msf_output = msf_session.get("output", "")
    if os.environ.get("EH_SCANNER_WEB_GUI") == "1":
        msf_output = _web_gui_clean_metasploit_output(msf_output)
    report.append(msf_output or "No relevant terminal output captured.")
    report.append("")

    nc_session = data.get("netcat_session", {})
    report.append("================ NETCAT SESSION =================")
    for label, key in (("Mode", "mode"), ("Endpoint", "endpoint"), ("Command", "command"), ("Start time", "start_time"), ("End time", "end_time"), ("Status", "status"), ("Exit code", "exit_code"), ("Capture status", "capture_status")):
        report.append(f"{label}: {nc_session.get(key, 'Not run')}")
    report.append("Captured terminal input/output:")
    report.append(nc_session.get("transcript", "") or "No captured terminal transcript.")
    report.append("")

    report.append("NOTE: Session transcripts may contain credentials, tokens, or other sensitive data. Review/redact before sharing.")
    report.append("")
    report.append("================ END OF REPORT =================")

    return "\n".join(report)


def confirm_report_write(filename):
    """Return the output path using the requested collision policy.

    Y preserves the existing report and picks the next free _2, _3, ... name.
    N replaces the report at the original path.
    """
    if not os.path.exists(filename):
        return filename
    while True:
        answer = input(f"\nReport already exists: {filename}\nKeep old and save new as a numbered file? (Y/N): ").strip().lower()
        if answer in ("y", "yes"):
            stem, extension = os.path.splitext(filename)
            number = 2
            candidate = f"{stem}_{number}{extension}"
            while os.path.exists(candidate):
                number += 1
                candidate = f"{stem}_{number}{extension}"
            return candidate
        if answer in ("n", "no"):
            return filename
        print("Please enter Y or N.")


# ============================================================
# HTML REPORT
# ============================================================

def save_html_report():

    text = clean_terminal_ansi(build_report_text())

    escaped = (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>EH Scanner Report</title>
<style>
body {{
    background:#111;
    color:#eee;
    font-family:monospace;
    padding:30px;
}}
pre {{
    white-space:pre-wrap;
    line-height:1.5;
}}
</style>
</head>
<body>
<h1>EH Scanner Report</h1>
<pre>{escaped}</pre>
</body>
</html>
"""

    filename = os.path.join(report_directory("HTML"), safe_target_filename(report_data.get("target_input") or report_data.get("target")) + ".html")

    filename = confirm_report_write(filename)
    save_file(filename, html)

    print(f"\nHTML report saved: {filename}")


# ============================================================
# PDF REPORT
# ============================================================

def save_pdf_report():

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

    except ImportError:

        print("\nPDF requires reportlab.")
        print("Install it with: pip install reportlab")
        return

    filename = os.path.join(report_directory("PDF"), safe_target_filename(report_data.get("target_input") or report_data.get("target")) + ".pdf")
    filename = confirm_report_write(filename)
    text = clean_terminal_ansi(build_report_text())

    pdf = canvas.Canvas(filename, pagesize=A4)

    width, height = A4
    x = 40
    y = height - 40

    pdf.setFont("Courier", 8)

    max_chars = 105
    for original_line in text.splitlines():
        chunks = [original_line[i:i + max_chars] for i in range(0, max(len(original_line), 1), max_chars)]
        for line in chunks:
            if y < 40:
                pdf.showPage()
                pdf.setFont("Courier", 8)
                y = height - 40
            # ReportLab's built-in Courier font is not Unicode-complete; replace unsupported glyphs safely.
            pdf.drawString(x, y, line.encode("latin-1", "replace").decode("latin-1"))
            y -= 10

    pdf.save()
    try:
        os.chmod(filename, 0o644)
    except OSError:
        pass

    print(f"\nPDF report saved: {filename}")


# ============================================================
# REPORT MENU
# ============================================================

def report_menu():
    while True:
        print_title("========== Report ==========")
        print_option("1. PDF", C_GREEN)
        print_option("2. HTML", C_CYAN)
        print_option("3. All", C_YELLOW)
        print_option("4. Back", C_WHITE)
        print_option("0. Exit EH Scanner", C_RED)

        try:
            choice = int(input("\nSelect option: "))
        except ValueError:
            print("Please enter a number.")
            continue

        if choice == 1:
            save_pdf_report()
        elif choice == 2:
            save_html_report()
        elif choice == 3:
            save_pdf_report()
            save_html_report()
        elif choice == 4:
            print("\nReturning to previous process...")
            break
        else:
            print("Invalid option.")


# ============================================================
# NETCAT CONNECTION BUILDER
# ============================================================

def netcat_menu(config):
    """Run an interactive Netcat session without an EH Scanner-imposed timeout."""
    print_title("========== Netcat Connection Builder ==========")
    nc_path = shutil.which("nc") or shutil.which("netcat") or shutil.which("ncat")
    if not nc_path:
        print_error("Netcat/ncat was not found. Install a Netcat implementation and try again.")
        return

    target = str(config.get("target") or "").strip()
    scanned_port = str(config.get("port") or "").strip()
    print(f"Current target : {target or 'Not set'}")
    print(f"Selected port  : {scanned_port or 'Not set'}")
    print("1. Connect to the selected target and port (client)")
    print("2. Listen on a local port (listener)")
    print_option("3. Back", C_CYAN)
    choice = input("Select Netcat mode: ").strip()
    if choice == "3": return
    if choice == "1":
        if not target or not scanned_port:
            print_error("Current workflow has no selected target/port. Return to port selection first.")
            return
        host, port_text = target, scanned_port
    elif choice == "2":
        host, port_text = None, input("Local listening port (1-65535): ").strip()
    else:
        print_error("Invalid Netcat mode.")
        return
    try:
        port = int(port_text)
        if not 1 <= port <= 65535: raise ValueError
    except ValueError:
        print_error("Port must be an integer from 1 to 65535.")
        return

    if choice == "1":
        command = [nc_path, host, str(port)]
        mode, endpoint = "Client", f"{host}:{port}"
    else:
        command = [nc_path, "-l", "-p", str(port)]
        mode, endpoint = "Listener", f"local port {port}"

    print("Prepared command:", command_to_text(command))
    print(f"Mode            : {mode}")
    print(f"Endpoint        : {endpoint}")
    print("Session timeout : None (runs until manually stopped or remote/network closure)")
    print_warning("Use only on systems and ports you own or are authorized to test.")
    print_warning("Terminal transcripts can contain sensitive data and will be included in reports when captured.")
    if input("Start this Netcat session now? (y/n): ").strip().lower() != "y":
        print_warning("Netcat start cancelled.")
        return

    session = report_data.setdefault("netcat_session", {})
    session.update({"mode": mode, "endpoint": endpoint, "command": command_to_text(command),
                    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "end_time": None,
                    "status": "Running", "exit_code": None, "capture_status": "Unavailable", "transcript": ""})
    process = None
    transcript_path = None
    return_code = None
    status = "Unknown termination state"
    try:
        script_path = shutil.which("script") if not is_windows() else None
        if script_path:
            fd, transcript_path = tempfile.mkstemp(prefix="ehscanner_netcat_", suffix=".log")
            os.close(fd)
            wrapped = [script_path, "-q", "-c", shlex.join(command), transcript_path]
            process = subprocess.Popen(wrapped)
            _register_gui_process(process)
            session["capture_status"] = "Capture attempted; verifying transcript file."
        else:
            # Keep the original interactive terminal flow; report honestly that output isn't captured.
            process = subprocess.Popen(command)
            _register_gui_process(process)
            session["capture_status"] = "Unavailable: interactive terminal logging utility not found; output was not captured."
        print("\nNetcat is running with no automatic time limit.")
        print("Press Ctrl+C at any time to stop Netcat and return to EH Scanner.")
        try:
            return_code = process.wait()
            stop_event = globals().get("GUI_STOP_EVENT")
            if stop_event is not None and stop_event.is_set():
                status = "Stopped by user (Web GUI Stop)"
                stop_event.clear()
                print_warning("Netcat task stopped. Returning to the current configuration menu.")
            else:
                status = "Process exited normally" if return_code == 0 else f"Process exited with error (code {return_code})"
        except KeyboardInterrupt:
            status = "Stopped by user (Ctrl+C)"
            print("\nNetcat stopped by user; returning to EH Scanner.")
            if process.poll() is None:
                process.terminate()
                try: return_code = process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); return_code = process.wait()
            else:
                return_code = process.returncode
            # Ctrl+C cancelled the active Netcat session only.
    except KeyboardInterrupt:
        status = "Stopped by user (Ctrl+C)"
        print("\nNetcat interrupted; returning to EH Scanner.")
        if process is not None and process.poll() is None:
            process.terminate()
            try: return_code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); return_code = process.wait()
        # Ctrl+C cancelled the active Netcat session only.
    except OSError as exc:
        status = f"Could not start: {exc}"
        session["capture_status"] = f"Unavailable: {exc}"
        print_error(f"Could not start Netcat: {exc}")
    finally:
        session["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session["status"] = status
        session["exit_code"] = return_code
        if transcript_path and os.path.exists(transcript_path):
            try:
                with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
                    session["transcript"] = clean_terminal_ansi(f.read())
                if session["transcript"]:
                    session["capture_status"] = "Captured terminal transcript (script utility)."
                else:
                    session["capture_status"] = "Transcript file created but empty; no terminal input/output was captured."
            except OSError as exc:
                session["capture_status"] = f"Partial/unavailable: could not read transcript ({exc})."
            try: os.remove(transcript_path)
            except OSError: pass
        elif transcript_path:
            session["capture_status"] = "Unavailable: transcript file was not created; output was not captured."
        report_entry = (
            "\nNetcat Connection Builder:\n"
            f"Mode: {mode}\nEndpoint: {endpoint}\nCommand: {command_to_text(command)}\n"
            f"Start time: {session['start_time']}\nEnd time: {session['end_time']}\n"
            f"Status: {status}\nExit Code: {return_code if return_code is not None else 'N/A'}\n"
            f"Capture status: {session['capture_status']}\n"
        )
        report_data["script_result"] = str(report_data.get("script_result") or "") + report_entry
        try: save_default_txt_report()
        except Exception as exc: print_warning(f"Could not save the automatic TXT report: {exc}")


# ============================================================
# SELECTED CONFIGURATION
# ============================================================

def show_config(config, exploits, target, port_info):

    while True:

        print("\n========= Selected configuration =========")

        for key, value in config.items():
            print(f"{key}: {value}")

        print("\n1. Auto Script Run")
        print_option("2. Manual Script", C_YELLOW)
        print_option("3. Start Metasploit", C_RED)
        print_option("4. Report", C_CYAN)
        print_option("5. Netcat", C_MAGENTA)
        print_option("6. Back", C_WHITE)
        print_option("0. Exit EH Scanner", C_RED)

        try:
            choice = int(input("\nSelect option: "))

        except ValueError:
            print("Please enter a number.")
            continue

        if choice == 1:
            auto_script(config)

        elif choice == 2:
            manual_script(config)

        elif choice == 3:

            print("\nConfiguration Accepted.")
            print("\nRun option selected.")
            if not config.get("exploit"):
                print_warning("No exploit was selected. Returning to the configuration menu; no exploit will be run.")
                continue
            run_exploit(config)

            # After leaving Metasploit, remain in this menu instead of
            # jumping back to the scan menu or exploit list.
            if config.get("source") == "Metasploit":
                continue
            return config

        elif choice == 4:
            report_menu()

        elif choice == 5:
            netcat_menu(config)

        elif choice == 6:

            print("\nReturning to Exploit List.....")

            show_exploits_again(
                target,
                exploits,
                port_info
            )

            return config

        else:
            print("\nInvalid Option.")


# ============================================================
# EXPLOIT LIST AGAIN
# ============================================================

def show_exploits_again(target, exploits, port_info):

    print_title("======= Exploits List =======")

    for index, exploit in enumerate(exploits, start=1):

        score = calc(exploit["name"], port_info)
        recommendation = get_recommendation(score)

        print(f"{index}. [{exploit['source']}]")
        print(f"Exploit: {exploit['name']}")
        print(f"Match Score: {score}")
        print(f"Recommendation: {recommendation}")
        print("===========================")

    selection_text = input("\nSelect Exploit number (or type Back to return): ").strip()
    if selection_text.lower() in ("back", "b", "0"):
        print("Returning to the previous menu.")
        return None
    try:
        selection = int(selection_text)
    except ValueError:
        print("Invalid Selection. Enter an exploit number or Back.")
        return None

    if selection < 1 or selection > len(exploits):
        print("Invalid Selection.")
        return None

    selected_exploit = exploits[selection - 1]

    score = calc(selected_exploit["name"], port_info)
    recommendation = get_recommendation(score)

    config = create_config(
        target,
        port_info,
        selected_exploit,
        score,
        recommendation
    )

    show_config(
        config,
        exploits,
        target,
        port_info
    )


# ============================================================
# LOCAL IP
# ============================================================

def get_local_ip():

    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)

        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # UDP socket method does not send application data. Try IPv4 first, then IPv6.
    for family, address in (
        (socket.AF_INET, ("8.8.8.8", 80)),
        (socket.AF_INET6, ("2001:4860:4860::8888", 80, 0, 0)),
    ):
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.connect(address)
            ip = sock.getsockname()[0]
            if ip and ip not in ("127.0.0.1", "::1"):
                return ip
        except Exception:
            pass
        finally:
            if sock is not None:
                try: sock.close()
                except Exception: pass
    return "127.0.0.1"


# ============================================================
# NETWORK INTERFACE / SUBNET DISCOVERY
# ============================================================

def get_local_networks():
    """Return locally assigned IPv4 networks, preferring exact interface CIDRs.

    Uses psutil when installed, then native OS commands. A /24 guess is only a
    last-resort fallback and is clearly marked to the caller.
    """
    networks = []

    try:
        import psutil  # Optional dependency; no installation required.
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family != socket.AF_INET:
                    continue
                ip = address.address
                mask = address.netmask
                if not ip or ip.startswith("127.") or not mask:
                    continue
                try:
                    network = ipaddress.ip_interface(f"{ip}/{mask}").network
                except ValueError:
                    continue
                if network.num_addresses > 1 and network not in networks:
                    networks.append(network)
    except Exception:
        pass

    if not networks and is_windows() and command_exists("ipconfig"):
        try:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                    errors="replace", timeout=8)
            current_ip = current_mask = None
            for line in result.stdout.splitlines():
                ip_match = re.search(r"IPv4[^:]*:\s*([0-9.]+)", line, re.I)
                mask_match = re.search(r"Subnet Mask[^:]*:\s*([0-9.]+)", line, re.I)
                if ip_match:
                    current_ip = ip_match.group(1)
                if mask_match:
                    current_mask = mask_match.group(1)
                    if current_ip and not current_ip.startswith("127."):
                        try:
                            network = ipaddress.ip_interface(f"{current_ip}/{current_mask}").network
                            if network not in networks:
                                networks.append(network)
                        except ValueError:
                            pass
                    current_ip = current_mask = None
        except Exception:
            pass

    if not networks and not is_windows() and command_exists("ip"):
        try:
            result = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                                    capture_output=True, text=True, errors="replace", timeout=8)
            for line in result.stdout.splitlines():
                match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b", line)
                if match:
                    try:
                        interface = ipaddress.ip_interface(match.group(1))
                        if not interface.ip.is_loopback and interface.network not in networks:
                            networks.append(interface.network)
                    except ValueError:
                        pass
        except Exception:
            pass

    if not networks:
        local_ip = get_local_ip()
        try:
            address = ipaddress.ip_address(local_ip)
            if address.version == 4 and not address.is_loopback:
                networks.append(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        except ValueError:
            pass

    # Avoid scanning loopback and excessively large ranges accidentally.
    return [network for network in networks if network.version == 4 and not network.is_loopback]


def discover_local_hosts(network):
    """Discover IPv4 hosts on a user-selected local subnet using available tools."""
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if command_exists("nmap"):
        command = ["nmap", "-sn", "-n", str(network)]
        stdout, stderr, return_code = run_with_animation(command)
        discovered_ips = []
        for line in stdout.splitlines():
            match = re.search(r"Nmap scan report for (?:.*\()?((?:\d{1,3}\.){3}\d{1,3})\)?$", line.strip())
            if match:
                candidate = match.group(1)
                try:
                    ipaddress.IPv4Address(candidate)
                    if candidate not in discovered_ips:
                        discovered_ips.append(candidate)
                except ValueError:
                    pass
        return command, started, stdout, stderr, return_code, discovered_ips

    if not is_windows() and command_exists("netdiscover"):
        command = ["netdiscover", "-P", "-r", str(network)]
        stdout, stderr, return_code = run_with_animation(command)
        discovered_ips = []
        for line in stdout.splitlines():
            match = re.match(r"^\s*((?:\d{1,3}\.){3}\d{1,3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", line)
            if match:
                candidate = match.group(1)
                try:
                    ipaddress.IPv4Address(candidate)
                    if candidate not in discovered_ips:
                        discovered_ips.append(candidate)
                except ValueError:
                    pass
        return command, started, stdout, stderr, return_code, discovered_ips

    return [], started, "", "No compatible discovery tool found. Install Nmap (recommended) or Netdiscover on a supported Linux/Unix system.", 127, []


# ============================================================
# MAIN
# ============================================================

def main():

    show_banner()
    show_disclaimer()
    check_dependencies()

    while True:

        print_option("1. Discover Network", C_GREEN)
        print_option("2. Select Target", C_CYAN)
        print_option("3. API Key Settings", C_YELLOW)
        print_option("4. Exit", C_WHITE)
        print_option("0. Exit EH Scanner (with confirmation)", C_RED)

        try:
            option = int(input("Select option: "))

        except ValueError:
            print("Please enter a number.")
            continue

        if option == 1:
            networks = get_local_networks()
            if not networks:
                print_error("Could not determine a local IPv4 subnet. Connect to a network and try again.")
                continue

            if len(networks) == 1:
                network = networks[0]
            else:
                print_title("Available Local IPv4 Networks")
                for index, candidate_network in enumerate(networks, start=1):
                    print(f"{index}. {candidate_network}")
                print("0. Back")
                try:
                    network_choice = int(input("Select network: "))
                except ValueError:
                    print_error("Invalid selection.")
                    continue
                if network_choice == 0:
                    continue
                if not 1 <= network_choice <= len(networks):
                    print_error("Invalid selection.")
                    continue
                network = networks[network_choice - 1]

            print_warning("Only scan a local network you own or are authorized to assess.")
            print(f"\nDiscovering hosts on {network} ...")
            try:
                command, started, stdout, stderr, return_code, discovered_ips = discover_local_hosts(network)
            except GUIStopRequested:
                stop_event = globals().get("GUI_STOP_EVENT")
                if stop_event is not None:
                    stop_event.clear()
                print_warning("Discovery task stopped. Returning to the discovery/main menu without resetting the session.")
                continue

            if stdout.strip():
                print_title("Network Discovery Results")
                print(stdout.rstrip())
            if stderr.strip():
                print_warning("Discovery messages:")
                print(stderr.rstrip())

            if return_code != 0:
                print_error(f"Network discovery failed with exit code {return_code}.")
                continue

            reset_report(None)
            report_data["network_discovery_result"] = (
                f"Command: {' '.join(command)}\nNetwork: {network}\nStarted: {started}\n"
                f"Exit Code: {return_code}\n\n{stdout}"
                + (f"\n[STDERR]\n{stderr}" if stderr.strip() else "")
            )

            if not discovered_ips:
                print_warning("Discovery completed, but no selectable IPv4 hosts were found.")
                continue

            print_title("Select a Discovered Host (IP Address Only)")
            for index, ip in enumerate(discovered_ips, start=1):
                print(f"{index}. {ip}")
            print("0. Back")
            try:
                number = int(input("Select host number: "))
            except ValueError:
                print_error("Invalid selection.")
                continue
            if number == 0:
                continue
            if not 1 <= number <= len(discovered_ips):
                print_error("Invalid selection.")
                continue

            target = discovered_ips[number - 1]
            report_data["target"] = target
            report_data["target_input"] = target
            print_success(f"Selected IP: {target}")
            scan_menu(target)

        elif option == 2:

            target = select_target()

            if target:
                scan_menu(target)

        elif option == 3:
            api_key_settings_menu()

        elif option == 4:
            save_default_txt_report()
            print("Exit")
            break

        else:
            print("Invalid option")


if __name__ == "__main__":
    try:
        main()
    except ExitRequested:
        try:
            save_default_txt_report()
        except Exception as report_error:
            print_warning(f"Final report could not be saved: {report_error}")
        print("\nEH Scanner exited cleanly. Goodbye.")
