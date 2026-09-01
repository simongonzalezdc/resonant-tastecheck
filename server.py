#!/usr/bin/env python3
"""addon.tastecheck local-service entry (http-json on 127.0.0.1:4894).

ResonantOS add-on contract: protocol http-json, healthCommand tastecheck.status.
Serves the FROZEN vendored TasteCheck skill pack (KyaniteLabs, MIT) in-process:
no subprocess, no shell, no secrets, no outbound network, no disk writes.

Honest surface: the pack's real interface is "an agent reads the skill
documents". Its checks are prose rules executed by the reading agent plus
browser-injectable auditors — none are runnable headless by this service, and
none are faked. What the service serves: the skill catalog, the skill
documents themselves, and the per-skill machine-readable contracts.

All responses are home-path-redacted; the service writes nothing to disk.

Exit codes: 0 normal stop; 78 port bind failure.
"""

import hashlib
import json
import os
import re
import socket
import sys
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("TASTECHECK_PORT", "4894"))  # dev override; manifest port 4894 is the contract
MAX_BODY = 64 * 1024
MAX_STR = 2048
MAX_FILE = 262144  # largest vendored pack file is ~11KB; cap is belt-and-braces

ADDON_ROOT = os.path.dirname(os.path.abspath(__file__))
VENDOR_ROOT = os.path.join(ADDON_ROOT, "vendor")
SKILLS_ROOT = os.path.join(VENDOR_ROOT, "skills")
SKILL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

with open(os.path.join(VENDOR_ROOT, "VENDOR-MANIFEST.json")) as _f:
    _VENDOR_META = json.load(_f)

_index_lock = threading.Lock()
_index = None  # skill_id -> {"name":..., "description":..., "class":..., "files": {rel: abs}}


def _parse_frontmatter(text):
    """Minimal frontmatter reader for the pack's `name`/`description` keys.

    Handles the two shapes the pack uses: plain scalars and block scalars
    (`>-` / `|`) with uniformly indented continuation lines. Returns raw
    strings; callers redact.
    """
    if not text.startswith("---"):
        return {}, text
    try:
        end = text.index("\n---", 3)
    except ValueError:
        return {}, text
    block = text[4:end]
    meta, key, mode, lines = {}, None, None, []
    for line in block.split("\n"):
        if mode is not None:
            if line.startswith("  ") and line.strip():
                lines.append(line.strip())
                continue
            meta[key] = " ".join(lines)
            key, mode, lines = None, None, []
        if not line.strip() or line.startswith("  "):
            continue
        if ":" in line:
            key, _, raw = line.partition(":")
            raw = raw.strip()
            if raw in (">-", "|", ">"):
                mode, lines = raw, []
            else:
                meta[key] = raw.strip("'\"")
                key = None
    if key is not None and lines:
        meta[key] = " ".join(lines)
    return meta, text


def _load_contract(path):
    try:
        with open(path) as f:
            contract = json.load(f)
    except (OSError, ValueError):
        return None
    return contract if isinstance(contract, dict) else None


def _build_index():
    idx = {}
    if not os.path.isdir(SKILLS_ROOT):
        return idx
    for entry in sorted(os.listdir(SKILLS_ROOT)):
        skill_dir = os.path.join(SKILLS_ROOT, entry)
        skill_md = os.path.join(skill_dir, "SKILL.md")
        if not os.path.isdir(skill_dir) or not os.path.isfile(skill_md):
            continue
        with open(skill_md) as f:
            meta, _ = _parse_frontmatter(f.read())
        contract = _load_contract(os.path.join(skill_dir, "contract.json"))
        files = {}
        for root, dirs, names in os.walk(skill_dir):
            dirs.sort()
            for name in sorted(names):
                abs_path = os.path.join(root, name)
                files[os.path.relpath(abs_path, skill_dir)] = abs_path
        idx[entry] = {
            "id": entry,
            "name": meta.get("name", entry),
            "description": meta.get("description", ""),
            "contract_class": contract.get("class") if contract else None,
            "files": files,
        }
    return idx


def _get_index():
    with _index_lock:
        if _index is None:
            return _build_index()
        return _index


_index = _build_index()  # frozen at startup; tests may rebuild via server._index = ...


def _redact_text(text):
    home = os.path.expanduser("~")
    return text.replace(home, "~") if home and home != "~" else text


def _redact_obj(obj):
    if isinstance(obj, str):
        return _redact_text(obj)
    if isinstance(obj, list):
        return [_redact_obj(item) for item in obj]
    if isinstance(obj, dict):
        return {key: _redact_obj(value) for key, value in obj.items()}
    return obj


def _read_pack_file(abs_path):
    if os.path.getsize(abs_path) > MAX_FILE:
        return None, "pack file exceeds size limit"
    with open(abs_path, "rb") as f:
        data = f.read()
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "pack file is not valid UTF-8 text"


def _validate_params(params, allowed, required):
    if not isinstance(params, dict):
        return None, "params must be an object"
    for key in params:
        if key not in allowed:
            return None, f"unknown field: {key}"
    for key in required:
        if key not in params:
            return None, f"missing field: {key}"
    for key, value in params.items():
        if not isinstance(value, str):
            return None, f"{key} must be a string"
        if not (0 < len(value) <= MAX_STR):
            return None, f"{key} must be 1..{MAX_STR} characters"
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):  # control chars never valid here
            return None, f"{key} contains control characters"
        if "/" in value and key == "skill":
            return None, "skill must be a bare skill id"
    return params, None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30  # a lying Content-Length must not pin a thread forever

    def _reply(self, code, payload, close=False):
        if close:
            self.close_connection = True  # never leave undrained bodies on a keep-alive connection
        body = json.dumps(_redact_obj(payload)).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._reply(200, self._status())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/":
            self._reply(404, {"error": "not found"}, close=True)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "bad content-length"}, close=True)
            return
        if length <= 0 or length > MAX_BODY:
            self._reply(413 if length > MAX_BODY else 400, {"error": "body must be 1..65536 bytes"}, close=True)
            return
        try:
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except (TimeoutError, socket.timeout, OSError):
            self._reply(408, {"error": "request body incomplete (timeout)"}, close=True)
            return
        except (ValueError, UnicodeDecodeError):
            self._reply(400, {"error": "body must be valid JSON"}, close=True)
            return
        if not isinstance(req, dict):
            self._reply(400, {"error": "body must be a JSON object"}, close=True)
            return
        method = req.get("method")
        params = req.get("params", {})
        for key in req:
            if key not in ("method", "params"):
                self._reply(400, {"error": f"unknown field: {key}"}, close=True)
                return
        if method == "tastecheck.status":
            self._reply(200, self._status())
        elif method == "tastecheck.skills":
            self._skills(params)
        elif method == "tastecheck.skill.get":
            self._skill_get(params)
        elif method == "tastecheck.skill.files":
            self._skill_files(params)
        elif method == "tastecheck.contract":
            self._contract(params)
        else:
            self._reply(404, {"error": f"unknown method: {method}"})

    def _status(self):
        idx = _get_index()
        upstream = _VENDOR_META["upstream"]
        return {
            "ok": True,
            "version": "0.1.0",
            "pack": {
                "name": upstream["name"],
                "version": upstream["pack_version"],
                "vendor": upstream["vendor"],
                "license": upstream["license"],
                "upstream_commit": upstream["commit"],
                "vendored_files": len(_VENDOR_META["files"]),
            },
            "skills_count": len(idx),
            "capabilities_requested": [],
            "headless_check_execution": False,
            "honesty_note": (
                "TasteCheck's checks are prose rules executed by the agent reading each SKILL.md, "
                "plus browser-injectable auditors that need a rendered page. This service serves the "
                "pack's documents; it does not run checks and does not fake verdicts."
            ),
        }

    def _skills(self, params):
        params, err = _validate_params(params, allowed=set(), required=set())
        if err:
            self._reply(400, {"error": err})
            return
        idx = _get_index()
        skills = [
            {
                "id": s["id"],
                "name": s["name"],
                "description": _redact_text(s["description"]),
                "class": s["contract_class"],
                "files": len(s["files"]),
            }
            for s in (idx[k] for k in sorted(idx))
        ]
        self._reply(200, {"ok": True, "count": len(skills), "skills": skills})

    def _resolve_skill(self, params):
        params, err = _validate_params(params, allowed={"skill"}, required={"skill"})
        if err:
            return None, err
        skill = params["skill"]
        if not SKILL_ID_RE.match(skill):
            return None, "skill must match ^[a-z0-9][a-z0-9-]{0,63}$"
        idx = _get_index()
        record = idx.get(skill)
        if record is None:
            return None, None  # 404
        return record, None

    def _skill_get(self, params):
        if not isinstance(params, dict):
            self._reply(400, {"error": "params must be an object"})
            return
        rel_path = params.pop("path", "SKILL.md")
        if not isinstance(rel_path, str) or not (0 < len(rel_path) <= MAX_STR):
            self._reply(400, {"error": "path must be a string of 1..2048 characters"})
            return
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in rel_path):
            self._reply(400, {"error": "path contains control characters"})
            return
        record, err = self._resolve_skill(params)
        if err:
            self._reply(400, {"error": err})
            return
        if record is None:
            self._reply(404, {"error": "unknown skill"})
            return
        abs_path = record["files"].get(rel_path)  # exact index match: traversal is impossible
        if abs_path is None:
            self._reply(404, {"error": "unknown path in skill; call tastecheck.skill.files for the list"})
            return
        text, ferr = _read_pack_file(abs_path)
        if ferr:
            self._reply(422, {"error": ferr})
            return
        self._reply(200, {
            "ok": True,
            "skill": record["id"],
            "path": rel_path,
            "size": len(text),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "content": _redact_text(text),
        })

    def _skill_files(self, params):
        record, err = self._resolve_skill(params)
        if err:
            self._reply(400, {"error": err})
            return
        if record is None:
            self._reply(404, {"error": "unknown skill"})
            return
        self._reply(200, {"ok": True, "skill": record["id"], "files": sorted(record["files"])})

    def _contract(self, params):
        record, err = self._resolve_skill(params)
        if err:
            self._reply(400, {"error": err})
            return
        if record is None:
            self._reply(404, {"error": "unknown skill"})
            return
        contract = _load_contract(os.path.join(SKILLS_ROOT, record["id"], "contract.json"))
        if contract is None:
            self._reply(404, {"error": "skill has no contract.json"})
            return
        self._reply(200, {"ok": True, "skill": record["id"], "contract": contract})

    def log_message(self, fmt, *args):  # keep service logs quiet and content-free
        sys.stderr.write("tastecheck-service: " + (fmt % args) + "\n")


def main():
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        sys.stderr.write(f"tastecheck-service: cannot bind 127.0.0.1:{PORT} ({exc}); manifest entrypoint expects this port\n")
        return 78
    sys.stderr.write(f"tastecheck-service: listening on http://127.0.0.1:{PORT}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
