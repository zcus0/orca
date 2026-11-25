#!/usr/bin/env python3
"""Orca Rust Desktop debug-report receiver.

The desktop app POSTs renderer-crash payloads (plus the tail
of its bridge call log) here so the agent can debug from the
server copy — the user never has to paste logs by hand.

- POST /report with header X-Debug-Key; body is small JSON.
- Reports land as files in ./reports (newest 200 kept).
- If ./.github-token exists (a fine-grained PAT with
  issues:write on zcus0/orca), each report also becomes a
  GitHub issue. Without the file, filing is skipped.
"""
import json
import os
import re
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(BASE, "reports")
KEY = os.environ.get("DEBUG_REPORT_KEY", "")
MAX_BODY = 128 * 1024
KEEP = 200


def prune():
    try:
        files = sorted(
            (os.path.join(REPORTS, f) for f in os.listdir(REPORTS)),
            key=os.path.getmtime,
        )
    except OSError:
        return
    for path in files[:-KEEP]:
        try:
            os.unlink(path)
        except OSError:
            pass


def file_github_issue(report):
    token_path = os.path.join(BASE, ".github-token")
    try:
        with open(token_path) as fh:
            token = fh.read().strip()
    except OSError:
        return
    if not token:
        return
    crash = report.get("crash") or []
    first = crash[0] if crash and isinstance(crash[0], dict) else {}
    title = "Orca Rust Desktop crash: %s (%s)" % (
        first.get("errorMessage") or first.get("boundaryId") or "renderer error",
        report.get("version", "?"),
    )
    body = (
        "Automated crash report from Orca Rust Desktop %s on %s.\n\n"
        "Boundary: `%s`\n\n<details><summary>Bridge log tail</summary>\n\n```\n%s\n```\n</details>"
        % (
            report.get("version", "?"),
            report.get("platform", "?"),
            first.get("boundaryId", "?"),
            (report.get("logTail") or "")[-6000:],
        )
    )
    req = urllib.request.Request(
        "https://api.github.com/repos/zcus0/orca/issues",
        data=json.dumps({"title": title[:250], "body": body}).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "orca-debug-receiver",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/report":
            self.send_response(404)
            self.end_headers()
            return
        if not KEY or self.headers.get("X-Debug-Key") != KEY:
            self.send_response(403)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self.send_response(413)
            self.end_headers()
            return
        raw = self.rfile.read(length)
        try:
            report = json.loads(raw)
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return
        os.makedirs(REPORTS, exist_ok=True)
        crash = report.get("crash") or []
        first = crash[0] if crash and isinstance(crash[0], dict) else {}
        boundary = re.sub(r"[^A-Za-z0-9_.-]", "_", str(first.get("boundaryId") or "crash"))
        name = "%d-%s.json" % (int(time.time() * 1000), boundary[:60])
        with open(os.path.join(REPORTS, name), "wb") as fh:
            fh.write(raw)
        prune()
        file_github_issue(report)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 6791), Handler).serve_forever()
