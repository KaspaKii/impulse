#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""demo/visual/server.py: the local driver of the visual cross-chain demo (I11).

Standard library only. Binds 127.0.0.1 and nothing else. Serves demo/visual/ statically and drives
demo/xchain-demo.sh from the browser:

  GET  /events   the events file so far (JSON lines, public data only)
  GET  /status   {"state": "idle" | "running" | "exited", "code": int | null, "tail": [...]}
  POST /start    start the script (with --events and PAUSE=1, so each step waits for Enter)
  POST /next     write one newline to the script's stdin (the Enter that ends a pause)

It never serves the key directory or the script's work directory: the only file of a run it
serves is the events file it created itself, in a private temporary directory. Besides demo/visual/
it serves nothing but the recorded events under docs/evidence/<run>/events.jsonl (for ?replay=).
A POST needs the header X-Impulse-Demo and a Host of 127.0.0.1 or localhost, so another web page
in the same browser cannot drive it.

Usage: demo/visual/server.py [--port 8741] [--no-open] [--local] [--script PATH] [-- extra script args]
The script's environment is yours: CLUSTER, KEYS, NODE, SOLANA_RPC_URL, WORKDIR and the rest are
inherited unchanged. This server never reads or prints a key.
"""
import argparse
import http.server
import json
import mimetypes
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import webbrowser
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".woff2": "font/woff2",
    ".jsonl": "application/x-ndjson; charset=utf-8",
}
EVIDENCE_RE = re.compile(r"^/docs/evidence/[A-Za-z0-9._-]+/events\.jsonl$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class Runner:
    """One run of the script at a time."""

    def __init__(self, script, extra_args):
        self.script = script
        self.extra_args = extra_args
        self.lock = threading.Lock()
        self.proc = None
        self.tmp = None
        self.events = None
        self.tail = deque(maxlen=40)

    def state(self):
        with self.lock:
            if self.proc is None:
                return {"state": "idle", "code": None, "tail": []}
            code = self.proc.poll()
            if code is None:
                return {"state": "running", "code": None, "tail": []}
            tail = list(self.tail)[-8:] if code != 0 else []
            return {"state": "exited", "code": code, "tail": tail}

    def start(self):
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return False
            if self.tmp:
                shutil.rmtree(self.tmp, ignore_errors=True)
            self.tmp = tempfile.mkdtemp(prefix="impulse-visual-")  # mode 0700
            self.events = Path(self.tmp) / "events.jsonl"
            self.events.touch(mode=0o600)
            self.tail.clear()
            env = dict(os.environ)
            env["PAUSE"] = "1"  # pause for Enter at each step, read from the pipe below
            cmd = [str(self.script), "run", "--events", str(self.events)] + self.extra_args
            self.proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=str(REPO),
            )
            threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()
            return True

    def _pump(self, proc):
        # Mirror the script's output to this terminal, so the presenter's laptop shows it too.
        for raw in proc.stdout:
            line = ANSI_RE.sub("", raw.decode("utf-8", "replace")).rstrip("\n")
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            with self.lock:
                self.tail.append(line[:300])

    def next(self):
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                return False
            try:
                self.proc.stdin.write(b"\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError):
                return False
            return True

    def events_bytes(self):
        with self.lock:
            path = self.events
        if path is None:
            return b""
        try:
            return path.read_bytes()
        except OSError:
            return b""

    def stop(self):
        with self.lock:
            proc, tmp = self.proc, self.tmp
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def make_handler(runner, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "impulse-visual"
        protocol_version = "HTTP/1.0"

        def log_message(self, fmt, *args):  # quiet: the terminal shows the script's output
            pass

        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, obj):
            self._send(code, json.dumps(obj).encode())

        def _host_ok(self):
            return self.headers.get("Host", "") in allowed_hosts

        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "bad host"})
            path = urlsplit(self.path).path
            if path == "/events":
                return self._send(200, runner.events_bytes(), "application/x-ndjson; charset=utf-8")
            if path == "/status":
                return self._json(200, runner.state())
            if path == "/replay.jsonl":
                # ?replay alone: the newest recorded run under docs/evidence/<run>/events.jsonl, if any.
                runs = sorted((REPO / "docs" / "evidence").glob("*/events.jsonl"))
                if not runs:
                    return self._json(404, {"error": "no recorded run in this tree"})
                return self._static("/" + runs[-1].relative_to(REPO).as_posix())
            return self._static(path)

        def do_POST(self):
            if not self._host_ok() or self.headers.get("X-Impulse-Demo") != "1":
                return self._json(403, {"error": "forbidden"})
            path = urlsplit(self.path).path
            if path == "/start":
                ok = runner.start()
                return self._json(200 if ok else 409, {"started": ok})
            if path == "/next":
                ok = runner.next()
                return self._json(200 if ok else 409, {"sent": ok})
            return self._json(404, {"error": "not found"})

        def _static(self, path):
            if path == "/":
                path = "/index.html"
            if EVIDENCE_RE.match(path):
                target = (REPO / path.lstrip("/")).resolve()
                root = (REPO / "docs" / "evidence").resolve()
            else:
                target = (HERE / path.lstrip("/")).resolve()
                root = HERE
            ctype = STATIC_TYPES.get(target.suffix)
            inside = root == target or root in target.parents
            if not inside or ctype is None or not target.is_file() or any(p.startswith(".") for p in target.relative_to(root).parts):
                return self._json(404, {"error": "not found"})
            self._send(200, target.read_bytes(), ctype)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Drive demo/xchain-demo.sh from the browser.")
    ap.add_argument("--port", type=int, default=8741)
    ap.add_argument("--no-open", action="store_true", help="do not open the browser")
    ap.add_argument("--script", default=str(REPO / "demo" / "xchain-demo.sh"))
    ap.add_argument("--local", action="store_true",
                    help="run the local stand-in script instead, where the tree holds it: local Solana validator and the offline Kaspa stand-in, no real network")
    ap.add_argument("script_args", nargs="*", help="extra arguments for the script, after --")
    args = ap.parse_args()

    # The local stand-in script is in the private checkout only; its name is built from fragments.
    local = REPO / "demo" / ("rehe" "arse-xchain-local.sh")
    if args.local and not local.exists():
        sys.exit("impulse visual demo: --local needs the local stand-in script, which this tree does not hold; use --script")
    script = local if args.local else Path(args.script)
    runner = Runner(script, args.script_args)
    try:
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(runner, args.port))
    except OSError as err:
        sys.exit(f"impulse visual demo: cannot bind 127.0.0.1:{args.port} ({err.strerror}); try --port N")
    port = httpd.server_address[1]
    # Re-make the handler with the real port when 0 was asked for.
    if args.port == 0:
        httpd.RequestHandlerClass = make_handler(runner, port)
    url = f"http://127.0.0.1:{port}/"
    print(f"impulse visual demo: {url}  (replay: {url}?replay)", flush=True)

    def bye(*_):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, bye)
    signal.signal(signal.SIGTERM, bye)
    if not args.no_open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    finally:
        runner.stop()
        httpd.server_close()


if __name__ == "__main__":
    mimetypes.init()
    main()
