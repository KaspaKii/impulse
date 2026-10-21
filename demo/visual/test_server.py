#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Tests of demo/visual/server.py and of the replay file, standard library only, no network.

Run: python3 -I demo/visual/test_server.py
"""
import http.client
import http.server
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
# The recorded run the page replays with ?replay alone: the newest docs/evidence/<run>/events.jsonl.
# A tree may hold none (the public tree does not); its tests are then skipped.
_RUNS = sorted((REPO / "docs" / "evidence").glob("*/events.jsonl"))
RUN = _RUNS[-1] if _RUNS else None
RUN_URL = "/" + RUN.relative_to(REPO).as_posix() if RUN else None
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import server  # noqa: E402

FAKE = """#!/usr/bin/env bash
# a stand-in for xchain-demo.sh: two steps, a pause after each, events to --events
set -eu
ev=
while [ $# -gt 0 ]; do case "$1" in --events) ev=$2; shift ;; esac; shift; done
echo '{"seq":1,"phase":"ready","step":0}' >> "$ev"
echo '{"seq":2,"phase":"pause","step":0}' >> "$ev"
read -r _
echo '{"seq":3,"phase":"done","step":1}' >> "$ev"
echo "PAUSE=$PAUSE" >&2
exit 3
"""


def req(port, method, path, headers=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = dict(headers or {})
    if host:
        h["Host"] = host
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        script = Path(cls.tmp) / "fake.sh"
        script.write_text(FAKE)
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        cls.runner = server.Runner(script, [])
        # port 0: pick a free one, then build the handler for it
        probe = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler)
        cls.port = probe.server_address[1]
        probe.server_close()
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", cls.port), server.make_handler(cls.runner, cls.port))
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.runner.stop()

    def test_binds_loopback_only(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")

    def test_static_and_refusals(self):
        self.assertEqual(req(self.port, "GET", "/")[0], 200)
        self.assertEqual(req(self.port, "GET", "/app.js")[0], 200)
        bads = ["/server.py", "/test_server.py", "/../xchain-demo.sh", "/%2e%2e/xchain-demo.sh", "/.git/config",
                "/docs/evidence/../../Cargo.toml", "/docs/evidence/README.md"]
        if RUN:
            bads.append(RUN_URL[: -len("events.jsonl")] + "run.log")
        for bad in bads:
            self.assertEqual(req(self.port, "GET", bad)[0], 404, bad)
        if RUN:
            self.assertEqual(req(self.port, "GET", RUN_URL)[0], 200)
            self.assertEqual(req(self.port, "GET", "/replay.jsonl")[1], RUN.read_bytes())
        else:
            self.assertEqual(req(self.port, "GET", "/replay.jsonl")[0], 404)

    def test_host_and_header_checks(self):
        self.assertEqual(req(self.port, "GET", "/events", host="evil.example")[0], 403)
        self.assertEqual(req(self.port, "POST", "/start")[0], 403)  # no X-Impulse-Demo header
        self.assertEqual(req(self.port, "POST", "/next", {"X-Impulse-Demo": "1"})[0], 409)  # nothing running

    def test_start_next_and_exit(self):
        h = {"X-Impulse-Demo": "1"}
        self.assertEqual(req(self.port, "POST", "/start", h)[0], 200)
        self.assertEqual(req(self.port, "POST", "/start", h)[0], 409)  # one run at a time
        deadline = time.time() + 5
        while time.time() < deadline and b"pause" not in req(self.port, "GET", "/events")[1]:
            time.sleep(0.05)
        lines = req(self.port, "GET", "/events")[1].decode().splitlines()
        self.assertEqual([json.loads(x)["phase"] for x in lines], ["ready", "pause"])
        self.assertEqual(req(self.port, "POST", "/next", h)[0], 200)
        deadline = time.time() + 5
        st = {}
        while time.time() < deadline:
            st = json.loads(req(self.port, "GET", "/status")[1])
            if st["state"] == "exited" and "PAUSE=1" in st["tail"]:
                break
            time.sleep(0.05)
        self.assertEqual(st["state"], "exited")
        self.assertEqual(st["code"], 3)
        self.assertIn("PAUSE=1", st["tail"])  # the driver sets PAUSE=1, so the script reads Enter from the pipe
        self.assertEqual(len(req(self.port, "GET", "/events")[1].decode().splitlines()), 3)


class SecretCheckTests(unittest.TestCase):
    def run_check(self, events, secret):
        with tempfile.TemporaryDirectory() as d:
            e, s = Path(d) / "e.jsonl", Path(d) / "seller.secret"
            e.write_text(events)
            s.write_text(secret)
            return subprocess.run([sys.executable, "-I", str(HERE / "check-events-no-secret.py"), str(e), str(s)],
                                  capture_output=True, text=True)

    def test_clean_feed_passes(self):
        r = self.run_check('{"seq":1,"hash_lock":"04ce9d7a06c31aa263ac703a777c2794a33f882108812b7e0756ba65e3ab144d"}\n',
                           "5f3a9c1e77b2d4086ac1e9f03d5b7e21c4a8f6d09b3e5a7c1d2f4e6b8a0c9d3e\n")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_secret_in_any_form_fails(self):
        import base64
        sec = "5f3a9c1e77b2d4086ac1e9f03d5b7e21c4a8f6d09b3e5a7c1d2f4e6b8a0c9d3e"
        raw = bytes.fromhex(sec)
        for form in (sec, sec.upper(), base64.b64encode(raw).decode(), raw.hex()):
            r = self.run_check('{"text":"x %s y"}\n' % form, sec + "\n")
            self.assertEqual(r.returncode, 1, form)
            self.assertNotIn(sec, r.stdout + r.stderr)  # it never prints the secret

    def test_missing_or_empty_inputs_fail(self):
        self.assertNotEqual(self.run_check("", "5f3a9c1e77b2d4086a\n").returncode, 0)
        self.assertNotEqual(self.run_check("{}\n", "ab\n").returncode, 0)


@unittest.skipUnless(RUN, "no recorded run in this tree")
class ReplayFileTests(unittest.TestCase):
    PATH = RUN

    def events(self):
        return [json.loads(x) for x in self.PATH.read_text().splitlines()]

    def test_matches_the_run_log(self):
        out = subprocess.run([sys.executable, "-I", str(HERE / "make-replay.py"), str(self.PATH.with_name("run.log"))],
                             check=True, capture_output=True, text=True).stdout
        self.assertEqual(out, self.PATH.read_text(), "events.jsonl is stale: rerun demo/visual/make-replay.py")

    def test_shape_and_txids(self):
        ev = self.events()
        self.assertEqual([e["seq"] for e in ev], list(range(1, len(ev) + 1)))
        self.assertEqual(ev[0]["phase"], "ready")
        self.assertEqual(ev[-1]["phase"], "complete")
        self.assertTrue(ev[-1]["complete"])
        txids = {e["txid"] for e in ev if "txid" in e}
        self.assertEqual(len(txids), 4)
        for t in txids:
            self.assertGreater(len(t), 60)
        self.assertEqual(ev[-1]["bal"], {"kaspa": {"seller": 4, "buyer": 1}, "solana": {"seller": 100000, "buyer": 4900000}})

    def test_no_secret_field(self):
        text = self.PATH.read_text().lower()
        for word in ("preimage", "secret_hex", "secret_bytes", "seller.secret"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
