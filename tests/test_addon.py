"""addon.tastecheck wrapper tests.

Run:  python3 -m unittest discover -s tests -v   (from the add-on root)

Covers: vendor hash-pin vs upstream HEAD, service surface honesty, strict
params, adversarial HTTP behavior, home-path redaction (responses AND the
whole tree incl. vendor), and the pack-index containment of skill.get.
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_ROOT = os.path.dirname(HERE)
UPSTREAM = os.path.expanduser("~/workspaces/tastecheck")
sys.path.insert(0, ADDON_ROOT)

import server  # noqa: E402

TEST_PORT = 4895
BASE = f"http://127.0.0.1:{TEST_PORT}"


def post(payload, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(BASE + "/", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())


def post_err(payload, raw=None):
    try:
        return post(payload, raw)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, json.loads(exc.read().decode())


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def raw_request(payload_bytes, headers=None, drain=True, timeout=10):
    """One raw socket request; returns (status_line, response_bytes|None)."""
    sock = socket.create_connection(("127.0.0.1", TEST_PORT), timeout=timeout)
    try:
        sock.sendall(payload_bytes)
        try:
            data = sock.recv(65536)
            return data.split(b"\r\n", 1)[0].decode(), data
        except (ConnectionResetError, BrokenPipeError):
            return "connection-closed", None
    finally:
        sock.close()


class Service:
    def __enter__(self):
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", TEST_PORT), server.Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestVendorPin(unittest.TestCase):
    """The vendored pack must be byte-identical to upstream commit b3cb115."""

    VENDOR_MANIFEST = os.path.join(ADDON_ROOT, "vendor", "VENDOR-MANIFEST.json")

    @classmethod
    def setUpClass(cls):
        with open(cls.VENDOR_MANIFEST) as f:
            cls.meta = json.load(f)
        try:
            cls.commit = subprocess.run(
                ["git", "-C", UPSTREAM, "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            cls.commit = None  # consumer machines may not carry the upstream clone

    def test_manifest_pins_expected_upstream(self):
        self.assertEqual(self.meta["upstream"]["name"], "tastecheck")
        self.assertEqual(self.meta["upstream"]["vendor"], "KyaniteLabs")
        self.assertEqual(self.meta["upstream"]["license"], "MIT")
        self.assertGreater(len(self.meta["files"]), 100)
        if self.commit is None:
            self.assertRegex(self.meta["upstream"]["commit"], r"^[0-9a-f]{40}$")
        elif self.commit != self.meta["upstream"]["commit"]:
            # A clone at any other commit verifies the wrong tree; the
            # recorded hash-pins above still enforce pack integrity.
            self.skipTest(
                f"local upstream clone is at {(self.commit or 'unknown')[:12]}, not the pinned "
                f"{self.meta['upstream']['commit'][:12]}; recorded hash-pins still "
                "enforce pack integrity (pull upstream to re-arm the live check)")
        else:
            self.assertEqual(self.meta["upstream"]["commit"], self.commit)

    def test_every_pinned_file_matches_recorded_hash(self):
        for rel, expected in self.meta["files"].items():
            path = os.path.join(ADDON_ROOT, "vendor", rel)
            self.assertTrue(os.path.isfile(path), f"missing vendored file: {rel}")
            with open(path, "rb") as f:
                self.assertEqual(sha256(f.read()), expected, f"vendor drift: {rel}")

    def test_no_unlisted_files_in_vendor(self):
        """Review finding: the pin must be complete. An unlisted file dropped
        under vendor/ would be served by skill.get (the index walks the live
        disk) without failing any hash check."""
        unlisted = []
        for root, dirs, names in os.walk(os.path.join(ADDON_ROOT, "vendor")):
            for n in names:
                rel = os.path.relpath(os.path.join(root, n), os.path.join(ADDON_ROOT, "vendor"))
                if rel != "VENDOR-MANIFEST.json" and rel not in self.meta["files"]:
                    unlisted.append(rel)
        self.assertEqual(unlisted, [])

    def test_vendored_bytes_identical_to_upstream_git_head(self):
        """Direct byte-identity vs the committed upstream tree (not the
        working tree, which may carry local uncommitted edits). Skipped on
        machines without the upstream clone OR with a clone at any other
        commit (it would verify the wrong tree); the recorded hash-pin above
        still guards integrity there."""
        if not os.path.isdir(os.path.join(UPSTREAM, ".git")):
            self.skipTest(f"upstream clone not present at {UPSTREAM}")
        if self.commit != self.meta["upstream"]["commit"]:
            self.skipTest(
                f"local upstream clone is at {(self.commit or 'unknown')[:12]}, not the pinned "
                f"{self.meta['upstream']['commit'][:12]}; recorded hash-pins still "
                "enforce pack integrity")
        for rel, expected in self.meta["files"].items():
            upstream_bytes = subprocess.run(
                ["git", "-C", UPSTREAM, "show", f"HEAD:{rel}"],
                capture_output=True, check=True,
            ).stdout
            self.assertEqual(sha256(upstream_bytes), expected, f"upstream HEAD drift: {rel}")
            with open(os.path.join(ADDON_ROOT, "vendor", rel), "rb") as f:
                self.assertEqual(sha256(f.read()), sha256(upstream_bytes), f"not byte-identical: {rel}")

    def test_pinned_pack_version_matches_vendored_package_json(self):
        with open(os.path.join(ADDON_ROOT, "vendor", "package.json")) as f:
            self.assertEqual(json.load(f)["version"], self.meta["upstream"]["pack_version"])

    def test_skill_index_covers_every_vendored_skill(self):
        idx = server._get_index()
        vendored_dirs = {
            d for d in os.listdir(os.path.join(ADDON_ROOT, "vendor", "skills"))
            if os.path.isfile(os.path.join(ADDON_ROOT, "vendor", "skills", d, "SKILL.md"))
        }
        self.assertEqual(set(idx), vendored_dirs)


class TestStatus(unittest.TestCase):
    def test_status_roundtrip(self):
        with Service():
            code, body = post({"method": "tastecheck.status"})
            self.assertEqual(code, 200)
            self.assertTrue(body["ok"])
            self.assertEqual(body["version"], "0.1.0")
            self.assertEqual(body["pack"]["name"], "tastecheck")
            self.assertEqual(body["pack"]["license"], "MIT")
            self.assertFalse(body["headless_check_execution"])  # honesty claim, tested
            self.assertIn("does not run checks", body["honesty_note"])
            self.assertEqual(body["capabilities_requested"], [])

    def test_get_health(self):
        with Service():
            with urllib.request.urlopen(BASE + "/health", timeout=10) as resp:
                body = json.loads(resp.read().decode())
            self.assertTrue(body["ok"])

    def test_skills_lists_the_pack(self):
        with Service():
            code, body = post({"method": "tastecheck.skills"})
            self.assertEqual(code, 200)
            self.assertEqual(body["count"], len(body["skills"]))
            ids = [s["id"] for s in body["skills"]]
            self.assertIn("tastecheck-pass", ids)
            self.assertIn("tasteroll", ids)  # in the pack even though the upstream README list omits it
            self.assertEqual(ids, sorted(ids))
            for s in body["skills"]:
                self.assertTrue(s["name"])
                self.assertTrue(s["description"])
                self.assertIsNotNone(s["class"])
                self.assertGreaterEqual(s["files"], 1)

    def test_skill_get_returns_document(self):
        with Service():
            code, body = post({"method": "tastecheck.skill.get", "params": {"skill": "tastecheck-pass"}})
            self.assertEqual(code, 200)
            self.assertEqual(body["skill"], "tastecheck-pass")
            self.assertEqual(body["path"], "SKILL.md")
            self.assertTrue(body["content"].startswith("---"))
            self.assertIn("name: tastecheck-pass", body["content"])
            self.assertEqual(body["sha256"], sha256(body["content"].encode()))

    def test_skill_get_reference_and_asset_paths(self):
        with Service():
            code, files = post({"method": "tastecheck.skill.files", "params": {"skill": "a11y-pass"}})
            self.assertEqual(code, 200)
            self.assertIn("assets/audit.js", files["files"])  # browser-injectable auditor ships with the pack
            code, body = post({"method": "tastecheck.skill.get",
                               "params": {"skill": "a11y-pass", "path": "assets/audit.js"}})
            self.assertEqual(code, 200)
            self.assertTrue(body["content"])

    def test_contract_returns_pack_contract(self):
        with Service():
            code, body = post({"method": "tastecheck.contract", "params": {"skill": "tastecheck-pass"}})
            self.assertEqual(code, 200)
            contract = body["contract"]
            self.assertEqual(contract["skill"], "tastecheck-pass")
            self.assertIn("trigger", contract)
            self.assertIn("stop_conditions", contract)


class TestStrictParams(unittest.TestCase):
    def test_unknown_method_404(self):
        with Service():
            code, _ = post_err({"method": "tastecheck.run"})
            self.assertEqual(code, 404)

    def test_unknown_field_in_envelope_400(self):
        with Service():
            code, _ = post_err({"method": "tastecheck.status", "extra": 1})
            self.assertEqual(code, 400)

    def test_unknown_param_field_400(self):
        with Service():
            code, _ = post_err({"method": "tastecheck.skill.get",
                                "params": {"skill": "deslop-ui", "evil": "../etc/passwd"}})
            self.assertEqual(code, 400)

    def test_control_chars_in_params_400(self):
        with Service():
            code, _ = post_err({"method": "tastecheck.skill.get", "params": {"skill": "des\x0blop-ui"}})
            self.assertEqual(code, 400)
            code, _ = post_err({"method": "tastecheck.contract", "params": {"skill": "a\x7fb"}})
            self.assertEqual(code, 400)

    def test_missing_required_param_400(self):
        with Service():
            code, _ = post_err({"method": "tastecheck.skill.get", "params": {}})
            self.assertEqual(code, 400)

    def test_non_object_body_400(self):
        with Service():
            code, _ = post_err(None, raw=b"[1,2,3]")
            self.assertEqual(code, 400)

    def test_invalid_json_400(self):
        with Service():
            code, _ = post_err(None, raw=b"{nope")
            self.assertEqual(code, 400)

    def test_bad_content_length_400(self):
        with Service():
            status, _ = raw_request(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: nope\r\n\r\n")
            self.assertTrue(status.startswith("HTTP/1.1 400"), status)

    def test_traversal_shapes_refused(self):
        with Service():
            for evil in ("../LICENSE", "../../server.py", "/etc/passwd", "references/../../../LICENSE"):
                code, _ = post_err({"method": "tastecheck.skill.get",
                                    "params": {"skill": "deslop-ui", "path": evil}})
                self.assertEqual(code, 404, evil)  # not in the index; nothing outside the pack is reachable
            code, _ = post_err({"method": "tastecheck.skill.get", "params": {"skill": "../vendor"}})
            self.assertEqual(code, 400)  # skill id pattern refuses separators outright

    def test_unknown_skill_404(self):
        with Service():
            code, _ = post_err({"method": "tastecheck.skill.get", "params": {"skill": "no-such-skill"}})
            self.assertEqual(code, 404)


class TestRedaction(unittest.TestCase):
    def test_redact_helpers(self):
        home = os.path.expanduser("~")
        self.assertEqual(server._redact_text("x" + home + "/y"), "x~/y")
        self.assertEqual(server._redact_obj({"a": [home + "/b"], "c": 3}), {"a": ["~/b"], "c": 3})

    def test_response_redaction_on_served_content(self):
        """skill.get must redact even if a pack file ever contained a home path."""
        home = os.path.expanduser("~")
        with tempfile.TemporaryDirectory() as tmp:
            probe = os.path.join(tmp, "SKILL.md")
            with open(probe, "w") as f:
                f.write("---\nname: probe\ndescription: probe skill\n---\nsecret: " + home + "/models/x")
            original = server._index
            try:
                server._index = {"probe": {"id": "probe", "name": "probe", "description": "probe skill",
                                           "contract_class": None, "files": {"SKILL.md": probe}}}
                with Service():
                    code, body = post({"method": "tastecheck.skill.get", "params": {"skill": "probe"}})
                    self.assertEqual(code, 200)
                    self.assertNotIn(home, body["content"])
                    self.assertIn("~/models/x", body["content"])
            finally:
                server._index = original

    def test_no_home_paths_in_whole_tree_including_vendor(self):
        needle = (os.sep + "Users" + os.sep).encode()  # built at runtime so this file stays clean
        for root, dirs, files in os.walk(ADDON_ROOT):
            # .git is VCS metadata: a clone's config legitimately embeds the
            # absolute origin URL, which is not shipped content.
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
            for name in files:
                if name.endswith(".pyc"):
                    continue
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    content = f.read()
                self.assertNotIn(needle, content, f"home path leaked in {path}")


class TestAdversarialHTTP(unittest.TestCase):
    def test_oversized_body_413_and_close(self):
        with Service():
            big = json.dumps({"method": "tastecheck.status", "pad": "x" * 100000}).encode()
            self.assertGreater(len(big), server.MAX_BODY)
            status, data = raw_request(
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: " + str(len(big)).encode()
                + b"\r\n\r\n" + big[:65536 + 1])
            self.assertTrue(status.startswith("HTTP/1.1 413"), status)
            self.assertIsNotNone(data)
            self.assertIn(b"Connection: close", data)  # advertised, not silent (gifts#4)

    def test_lying_content_length_408(self):
        """Declaring more bytes than sent must not hang or misparse: 408 + close.
        Handler timeout is patched to 1s so the suite stays fast; production
        uses 30s (same code path)."""
        original_timeout = server.Handler.timeout
        server.Handler.timeout = 1
        try:
            with Service():
                status, data = raw_request(
                    b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\n{\"method\":\"taste")
                self.assertTrue(status.startswith("HTTP/1.1 408"), status)
                self.assertIn(b"Connection: close", data)  # advertised, not silent (gifts#4)
        finally:
            server.Handler.timeout = original_timeout

    def test_chunked_encoding_400(self):
        with Service():
            status, _ = raw_request(
                b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"1a\r\n{\"method\":\"tastecheck.status\"}\r\n0\r\n\r\n")
            self.assertTrue(status.startswith("HTTP/1.1 400"), status)

    def test_request_flood_20_concurrent(self):
        errors = []

        def hit(n):
            try:
                code, body = post({"method": "tastecheck.status"})
                if code != 200 or not body["ok"]:
                    errors.append((n, code))
            except Exception as exc:  # noqa: BLE001
                errors.append((n, repr(exc)))

        with Service():
            threads = [threading.Thread(target=hit, args=(i,)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        self.assertEqual(errors, [])


class TestManifestParity(unittest.TestCase):
    """The manifest must promise exactly what server.py serves."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ADDON_ROOT, "addon.json")) as f:
            cls.manifest = json.load(f)

    def test_manifest_id_and_entrypoint(self):
        self.assertEqual(self.manifest["id"], "addon.tastecheck")
        self.assertEqual(self.manifest["service"]["entrypoint"], "http://127.0.0.1:4894")
        self.assertEqual(self.manifest["service"]["healthCommand"], "tastecheck.status")

    def test_every_declared_tool_is_served(self):
        methods = []
        src = open(os.path.join(ADDON_ROOT, "server.py")).read()
        for tool in self.manifest["tools"]:
            self.assertIn(f'"{tool["name"]}"', src, f"manifest tool not routed in server: {tool['name']}")
            self.assertIsInstance(tool["inputSchema"], dict)
            self.assertIsInstance(tool["outputSchema"], dict)
            methods.append(tool["name"])
        self.assertEqual(len(methods), len(set(methods)))

    def test_no_undeclared_tastecheck_methods_served(self):
        src = open(os.path.join(ADDON_ROOT, "server.py")).read()
        served = set(__import__("re").findall(r'"(tastecheck\.[a-z.]+)"', src))
        declared = {t["name"] for t in self.manifest["tools"]}
        self.assertEqual(served, declared, "server surface and manifest tools diverged")

    def test_zero_capabilities_claimed(self):
        self.assertEqual(self.manifest["requestedCapabilities"], [])
        for tool in self.manifest["tools"]:
            self.assertEqual(tool["requiredCapabilities"], [])


if __name__ == "__main__":
    unittest.main()
