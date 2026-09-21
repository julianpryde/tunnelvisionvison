"""Tiny localhost JSON API between the privileged daemon and per-user agents / CLI."""

from __future__ import annotations

import json
import os
import secrets
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import Config
from .util import IS_WINDOWS, log

TOKEN_NAME = "api-token"


def token_paths(cfg: Config) -> list[Path]:
    return [cfg.state_dir / TOKEN_NAME, Path.home() / ".tunnelvisionvision" / TOKEN_NAME]


def write_token(cfg: Config) -> Path:
    token = secrets.token_hex(24)
    for path in token_paths(cfg):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(token, encoding="utf-8")
            if not IS_WINDOWS:
                # Readable by local users so their agent can talk to the daemon; writable only by the daemon.
                os.chmod(path, 0o644)
            return path
        except OSError:
            continue
    raise RuntimeError("could not write API token to any state directory")


def read_token(cfg: Config) -> str:
    for path in token_paths(cfg):
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    raise RuntimeError("daemon API token not found — is the TunnelVisionVision daemon running?")


def serve(cfg: Config, monitor, token: str) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.debug("api: " + fmt, *args)

        def _reply(self, code: int, body: dict):
            data = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if not secrets.compare_digest(self.headers.get("X-TVV-Token", ""), token):
                self._reply(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self._authorized():
                return
            if self.path == "/status":
                self._reply(200, monitor.status(agent=self.headers.get("X-TVV-Agent")))
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self):
            if not self._authorized():
                return
            if self.path != "/action":
                return self._reply(404, {"error": "not found"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                result = monitor.perform(body.get("action", ""), body.get("alert_id"), by=body.get("by", "api"))
                self._reply(200, result)
            except ValueError as e:
                self._reply(400, {"error": str(e)})

    server = ThreadingHTTPServer((cfg.api_host, cfg.api_port), Handler)
    server.daemon_threads = True
    return server


def call(cfg: Config, path: str, body: dict | None = None, timeout: float = 120) -> dict:
    req = urllib.request.Request(
        f"http://{cfg.api_host}:{cfg.api_port}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-TVV-Token": read_token(cfg), "Content-Type": "application/json", "X-TVV-Agent": os.environ.get("USER") or os.environ.get("USERNAME", "?")},
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())
