#!/usr/bin/env python3
"""Local browser UI for EH Scanner's existing interactive workflow.

Run beside EH_Scanner_CrossPlatform.py with: python EH_Scanner_Web_GUI.py
The HTTP server binds only to 127.0.0.1; it is not exposed to the LAN.
"""
import importlib.util
import json
import os
import queue
import threading
import time
import subprocess
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
SCANNER_PATH = BASE_DIR / "EH_Scanner_CrossPlatform.py"
HOST = "127.0.0.1"
PORT = 8765
output_lock = threading.Lock()
output_text = ""
input_queue = queue.Queue()
scanner_state = {"running": False, "finished": False, "error": None, "stopping": False}
stop_event = threading.Event()
active_processes = set()
active_processes_lock = threading.Lock()
interactive_lock = threading.Lock()
interactive_process = None
interactive_output = []
GUIStopRequested = None  # Set to the scanner module's internal cancellation signal at startup.


class OutputBuffer:
    def write(self, value):
        global output_text
        if value:
            with output_lock:
                output_text += str(value)
        return len(value)

    def flush(self):
        pass


def gui_input(prompt=""):
    """Replace terminal input with a prompt answered in the browser."""
    if prompt:
        print(prompt, end="", flush=True)
    value = input_queue.get()
    if value is None:
        if GUIStopRequested is not None:
            raise GUIStopRequested("Web GUI stop requested")
        raise KeyboardInterrupt("Web GUI stop requested")
    print(value, flush=True)
    return value


def gui_interactive_runner(command):
    """Run an interactive CLI child with live browser input/output forwarding."""
    global interactive_process, interactive_output
    if stop_event.is_set():
        raise GUIStopRequested("Web GUI stop requested")
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0, text=False
    )
    with active_processes_lock:
        active_processes.add(process)
    with interactive_lock:
        interactive_process = process
        interactive_output = []

    def read_output():
        try:
            while True:
                chunk = process.stdout.read(1024)
                if not chunk:
                    break
                decoded = chunk.decode("utf-8", errors="replace")
                with interactive_lock:
                    interactive_output.append(decoded)
                with output_lock:
                    global output_text
                    output_text += decoded
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        while process.poll() is None:
            if stop_event.wait(0.1):
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise GUIStopRequested("Web GUI stop requested")
        reader.join(timeout=2)
        with interactive_lock:
            captured = "".join(interactive_output)
        if stop_event.is_set():
            raise GUIStopRequested("Web GUI stop requested")
        return subprocess.CompletedProcess(command, process.returncode, captured, "")
    finally:
        with interactive_lock:
            if interactive_process is process:
                interactive_process = None
        with active_processes_lock:
            active_processes.discard(process)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def run_scanner():
    global GUIStopRequested
    module = None
    scanner_state["running"] = True
    scanner_state["finished"] = False
    scanner_state["error"] = None
    scanner_state["stopping"] = False
    stop_event.clear()
    writer = OutputBuffer()
    try:
        spec = importlib.util.spec_from_file_location("eh_scanner_web_import", SCANNER_PATH)
        module = importlib.util.module_from_spec(spec)
        previous_gui_color_flag = os.environ.get("EH_SCANNER_WEB_GUI")
        os.environ["EH_SCANNER_WEB_GUI"] = "1"
        try:
            spec.loader.exec_module(module)
        finally:
            if previous_gui_color_flag is None:
                os.environ.pop("EH_SCANNER_WEB_GUI", None)
            else:
                os.environ["EH_SCANNER_WEB_GUI"] = previous_gui_color_flag
        GUIStopRequested = module.GUIStopRequested
        module.input = gui_input
        module.GUI_STOP_EVENT = stop_event
        module.GUI_ACTIVE_PROCESSES = active_processes
        module.GUI_INTERACTIVE_RUNNER = gui_interactive_runner

        # Make subprocess.run operations cancellable from the browser Stop button.
        original_popen = module.subprocess.Popen
        def gui_cancellable_run(*args, **kwargs):
            if stop_event.is_set():
                raise module.GUIStopRequested("Web GUI stop requested")
            run_kwargs = dict(kwargs)
            capture_output = run_kwargs.pop("capture_output", False)
            if capture_output:
                run_kwargs.setdefault("stdout", subprocess.PIPE)
                run_kwargs.setdefault("stderr", subprocess.PIPE)
            check = run_kwargs.pop("check", False)
            timeout = run_kwargs.pop("timeout", None)
            process = original_popen(args[0], **run_kwargs)
            with active_processes_lock:
                active_processes.add(process)
            try:
                started = time.monotonic()
                while process.poll() is None:
                    if stop_event.wait(0.1):
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        break
                    if timeout is not None and time.monotonic() - started > timeout:
                        process.kill()
                        process.wait()
                        raise subprocess.TimeoutExpired(args[0], timeout)
                stdout, stderr = process.communicate()
                if stop_event.is_set():
                    raise module.GUIStopRequested("Web GUI stop requested")
                result = subprocess.CompletedProcess(args[0], process.returncode, stdout, stderr)
                if check and result.returncode:
                    raise subprocess.CalledProcessError(result.returncode, args[0], output=stdout, stderr=stderr)
                return result
            finally:
                with active_processes_lock:
                    active_processes.discard(process)
        module.subprocess.run = gui_cancellable_run

        # A cancellation unwinds the active operation, then starts the scanner again
        # at its top-level menu. Other exceptions remain visible in the GUI error state.
        with redirect_stdout(writer), redirect_stderr(writer):
            while True:
                try:
                    module.main()
                    break
                except module.GUIStopRequested:
                    stop_event.clear()
                    scanner_state["stopping"] = False
                    while True:
                        try:
                            input_queue.get_nowait()
                        except queue.Empty:
                            break
                    writer.write("\n[Web GUI] Task cancelled cleanly. Returning to the EH Scanner main menu.\n")
                    try:
                        module.save_default_txt_report()
                    except Exception as report_error:
                        writer.write(f"\n[Web GUI] Could not refresh the TXT report after cancellation: {report_error}\n")
                    continue
    except BaseException as exc:
        # Stop requests are handled above; this path reports unexpected failures without a traceback.
        if stop_event.is_set() and module is not None and isinstance(exc, module.GUIStopRequested):
            writer.write("\n[Web GUI] Task cancelled cleanly.\n")
        elif type(exc).__name__ == "ExitRequested" and module is not None:
            try:
                module.save_default_txt_report()
                writer.write("\nEH Scanner exited cleanly. Final TXT report saved if report data existed.\n")
            except Exception as report_error:
                writer.write(f"\nFinal report could not be saved: {report_error}\n")
        else:
            scanner_state["error"] = f"{type(exc).__name__}: {exc}"
            writer.write("\n[Web GUI] Scanner stopped: " + scanner_state["error"] + "\n")
    finally:
        scanner_state["running"] = False
        scanner_state["finished"] = True


PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EH Scanner — Local Web GUI</title>
<style>
:root{color-scheme:dark}body{margin:0;background:#0b1020;color:#e8eefc;font:16px system-ui,sans-serif}
main{max-width:1000px;margin:auto;padding:22px}.card{background:#131b30;border:1px solid #283653;border-radius:14px;padding:18px;margin:14px 0}
h1{margin:0 0 8px;color:#79d6ff}p{color:#b7c4dc}.status{font-size:13px;color:#a7e7c0}
#terminal{white-space:pre-wrap;overflow:auto;height:55vh;min-height:300px;background:#070b14;border:1px solid #26344d;border-radius:10px;padding:16px;font:16px/1.7 ui-monospace,monospace;overflow-wrap:anywhere;tab-size:4}
.menu-option{display:inline-block;font-weight:700;color:#f3f7ff}.option-number{display:inline-block;min-width:2ch;margin-right:5px;color:#79d6ff;font-weight:800}.ansi-red{color:#ff7777}.ansi-green{color:#6ee7a0}.ansi-yellow{color:#ffd166}.ansi-blue{color:#78aaff}.ansi-cyan{color:#79d6ff}.ansi-magenta{color:#e5a0ff}.ansi-white{color:#f3f7ff}.ansi-bold{font-weight:800}
form{display:flex;gap:10px;margin-top:12px}input{flex:1;min-width:0;background:#080d19;color:#fff;border:1px solid #40516f;border-radius:8px;padding:12px}
button{background:#177eaa;color:white;border:0;border-radius:8px;padding:12px 18px;font-weight:700;cursor:pointer}button:disabled{opacity:.45;cursor:default}
.small{font-size:12px;color:#93a3bf}.row{display:flex;gap:12px;flex-wrap:wrap} .row button{flex:1}
</style></head><body><main>
<h1>EH SCANNER</h1><p>Local browser interface · CLI workflow · live interactive Metasploit input/output · IPv4 discovery</p>
<div class="card"><div id="status" class="status">Starting scanner…</div><p class="small">This page connects to a server bound to 127.0.0.1 on this device only. Use the scanner only on systems and networks you are authorized to assess.</p>
<div class="row"><button id="stop" type="button" style="background:#b83232">Stop / Cancel task</button><button id="restart">Restart scanner session</button><button id="clear">Clear visible output</button></div></div>
<div class="card"><div id="terminal" aria-live="polite"></div><form id="answer"><input id="reply" autocomplete="off" placeholder="Enter a menu choice, exploit number, or type Back…" aria-label="Scanner input"><button id="send" type="submit">Send</button></form></div>
<p class="small">Tip: type Back at exploit selection to return. Metasploit prompts and output are forwarded live. Use Stop / Cancel task to interrupt the active task and return to the scanner main menu.</p></main>
<script>
let seen=0;const terminal=document.getElementById('terminal'),reply=document.getElementById('reply'),send=document.getElementById('send'),status=document.getElementById('status');
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function ansiHtml(raw){
  const codes={30:'ansi-white',31:'ansi-red',32:'ansi-green',33:'ansi-yellow',34:'ansi-blue',35:'ansi-magenta',36:'ansi-cyan',37:'ansi-white',90:'ansi-white',91:'ansi-red',92:'ansi-green',93:'ansi-yellow',94:'ansi-blue',95:'ansi-magenta',96:'ansi-cyan',97:'ansi-white'};
  const parts=raw.split(/(\x1b\[[0-9;]*m)/g);let classes=[];let html='';
  for(const part of parts){if(/^\x1b\[[0-9;]*m$/.test(part)){const vals=part.slice(2,-1).split(';').map(Number);for(const v of vals){if(v===0)classes=[];else if(v===1){if(!classes.includes('ansi-bold'))classes.push('ansi-bold')}else if(codes[v]){classes=classes.filter(c=>!c.startsWith('ansi-')||c==='ansi-bold');classes.push(codes[v])}}continue}if(!part)continue;
    const lines=part.split('\n');html+=lines.map((line,i)=>{let safe=esc(line);const m=line.match(/^(\s*)(\d{1,2})([.)])\s+(.*)$/);if(m){safe=esc(m[1])+'<span class="menu-option"><span class="option-number">'+esc(m[2]+m[3])+'</span>'+esc(m[4])+'</span>'}const cls=classes.length?' class="'+classes.join(' ')+'"':'';return (i?'\n':'')+'<span'+cls+'>'+safe+'</span>'}).join('')
  }return html;
}
async function poll(){try{let r=await fetch('/api/state',{cache:'no-store'}),d=await r.json();if(d.output.length!==seen){const wasBottom=terminal.scrollHeight-terminal.scrollTop-terminal.clientHeight<50;terminal.innerHTML=ansiHtml(d.output);seen=d.output.length;if(wasBottom)terminal.scrollTop=terminal.scrollHeight}status.textContent=d.stopping?'Stop requested — terminating the active external task…':(d.running?'Scanner running — enter a response when prompted.':(d.finished?'Scanner finished. Restart to begin a new session.':'Scanner ready.'));send.disabled=!d.running;reply.disabled=!d.running;document.getElementById('stop').disabled=!d.running||d.stopping}catch(e){status.textContent='Cannot reach local scanner server.'}setTimeout(poll,500)}
document.getElementById('answer').addEventListener('submit',async e=>{e.preventDefault();if(!reply.value.trim())return;await fetch('/api/input',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:reply.value})});reply.value='';reply.focus()});
document.getElementById('stop').addEventListener('click',async()=>{await fetch('/api/stop',{method:'POST'});});document.getElementById('restart').addEventListener('click',async()=>{await fetch('/api/restart',{method:'POST'});});document.getElementById('clear').addEventListener('click',()=>{terminal.innerHTML='';seen=-1});poll();
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_body(self, status, content, content_type="application/json; charset=utf-8"):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_body(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/state":
            with output_lock:
                snapshot = output_text
            self.send_body(200, json.dumps({**scanner_state, "output": snapshot}))
        else:
            self.send_body(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        global output_text
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            self.send_body(400, json.dumps({"error": "invalid JSON"}))
            return
        if path == "/api/input":
            value = str(payload.get("value", ""))[:2000]
            if not scanner_state["running"]:
                self.send_body(409, json.dumps({"error": "scanner is not running"}))
                return
            with interactive_lock:
                current_interactive = interactive_process
            if current_interactive is not None and current_interactive.poll() is None:
                try:
                    current_interactive.stdin.write((value + "\n").encode("utf-8"))
                    current_interactive.stdin.flush()
                    with interactive_lock:
                        interactive_output.append(value + "\n")
                    with output_lock:
                        output_text += value + "\n"
                    self.send_body(200, json.dumps({"ok": True, "interactive": True}))
                except (BrokenPipeError, OSError, ValueError):
                    self.send_body(409, json.dumps({"error": "interactive process is no longer accepting input"}))
            else:
                input_queue.put(value)
                self.send_body(200, json.dumps({"ok": True, "interactive": False}))
        elif path == "/api/stop":
            if not scanner_state["running"]:
                self.send_body(409, json.dumps({"error": "scanner is not running"}))
                return
            scanner_state["stopping"] = True
            stop_event.set()
            # Wake the scanner if it is waiting for a browser answer.
            input_queue.put(None)
            with active_processes_lock:
                processes = list(active_processes)
            for process in processes:
                try:
                    if process.poll() is None:
                        process.terminate()
                except Exception:
                    pass
            self.send_body(200, json.dumps({"ok": True, "stopping": True}))
        elif path == "/api/restart":
            if scanner_state["running"]:
                self.send_body(409, json.dumps({"error": "scanner is already running"}))
                return
            while True:
                try: input_queue.get_nowait()
                except queue.Empty: break
            with output_lock:
                output_text = ""
            threading.Thread(target=run_scanner, daemon=True).start()
            self.send_body(200, json.dumps({"ok": True}))
        else:
            self.send_body(404, json.dumps({"error": "not found"}))


def main():
    if not SCANNER_PATH.exists():
        raise SystemExit(f"Missing scanner file: {SCANNER_PATH}")
    threading.Thread(target=run_scanner, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"EH Scanner Web GUI: http://{HOST}:{PORT}")
    print("Server is local-only. Keep this terminal open while using the browser UI.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local Web GUI…")
    finally:
        server.shutdown()
        server.server_close()
        input_queue.put(None)


if __name__ == "__main__":
    main()
