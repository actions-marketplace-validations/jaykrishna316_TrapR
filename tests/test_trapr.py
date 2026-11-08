#!/usr/bin/env python3
"""
End-to-end tests for TrapR: protect a repo, then try to sneak copies past every layer.

Run:  python3 tests/test_trapr.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
TOOL = HERE / "trapr.py"
sys.path.insert(0, str(HERE))
import trapr as ts  # noqa: E402

RATELIMIT = '''import time


class TokenBucket:
    """Simple token bucket rate limiter."""

    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last = now

    def allow(self, cost=1):
        self._refill()
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

    def wait_time(self, cost=1):
        self._refill()
        if self.tokens >= cost:
            return 0.0
        return (cost - self.tokens) / self.refill_rate


def retry_with_backoff(fn, attempts=5, base=0.2, cap=10.0):
    for i in range(attempts):
        try:
            return fn()
        except Exception:
            if i == attempts - 1:
                raise
            time.sleep(min(cap, base * (2 ** i)))
'''

UTILS = '''def chunk(items, size):
    """Split a list into chunks of `size`."""
    return [items[i:i + size] for i in range(0, len(items), size)]
'''

LLM_REWRITE = '''from time import monotonic, sleep

class Limiter:
    def __init__(self, size, per_sec):
        self.size = size
        self.level = size
        self.per_sec = per_sec
        self.stamp = monotonic()

    def _top_up(self):
        t = monotonic()
        gap = t - self.stamp
        self.level = min(self.size, self.level + gap * self.per_sec)
        self.stamp = t

    def take(self, n=1):
        self._top_up()
        if self.level >= n:
            self.level = self.level - n
            return True
        return False

    def delay_for(self, n=1):
        self._top_up()
        if self.level >= n:
            return 0.0
        return (n - self.level) / self.per_sec

def with_retries(op, max_tries=5, delay=0.2, ceiling=10.0):
    k = 0
    while k < max_tries:
        try:
            return op()
        except Exception:
            if k == max_tries - 1:
                raise
            sleep(min(ceiling, delay * (2 ** k)))
        k += 1
'''

UNRELATED = '''import json
def load(path):
    with open(path) as f:
        return json.load(f)
def merge(a, b):
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and k in out:
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out
'''

LOOKALIKE = '''def fnv1a(key, n):
    h = 0x811C9DC5
    for b in key.encode():
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= h >> 15
    h ^= h >> 16
    return h % n
'''


def canary_disguises(c: dict) -> dict[str, str]:
    seed, mult, rot = c["seed"], c["mult"], c["rot"]
    return {
        "rewrite_reduce.py": f'''import functools
MASK = (1 << 32) - 1
def _step(acc, byte):
    acc = ((acc ^ byte) * {mult}) & MASK
    return acc ^ (acc >> {rot})
def shard_for(user_id, n_shards):
    acc = functools.reduce(_step, user_id.encode(), {seed})
    acc ^= acc >> 16
    return acc % n_shards
''',
        "as_method.py": f'''class Router:
    def __init__(self, nodes):
        self.nodes = nodes
    def pick(self, key, n):
        h = {seed}
        for ch in key.encode():
            h = h ^ ch
            h = (h * {mult}) % 4294967296
            h = h ^ (h >> {rot})
        return (h ^ (h >> 16)) % n
''',
        "ported.js": f'''const bucketOf = (s, k) => {{
  let x = {seed};
  const bytes = Buffer.from(s, "utf8");
  for (let i = 0; i < bytes.length; i++) {{
    x ^= bytes[i];
    x = Math.imul(x, {mult}) >>> 0;
    x ^= x >>> {rot};
    x >>>= 0;
  }}
  return ((x ^ (x >>> 16)) >>> 0) % k;
}};
module.exports = {{ bucketOf }};
''',
        "booby_trap.py": f'''open("PWNED", "w").write("module code ran")
def bucket(key, n):
    h = {seed}
    for b in key.encode():
        h ^= b
        h = (h * {mult}) & 0xFFFFFFFF
        h ^= h >> {rot}
    h ^= h >> 16
    return h % n
''',
    }


def other_kind_disguises(cs: dict) -> dict[str, str]:
    """Hand-written rewrites of the rolling, mixer and checksum canaries."""
    r, m, k = cs["rolling"], cs["mixer"], cs["checksum"]
    return {
        "palette_port.js": f'''function paletteFor(label, count) {{
  // ported from somewhere, renamed and restyled
  let acc = {r["seed"]};
  const bytes = Buffer.from(label, "utf8");
  bytes.forEach((byte) => {{ acc = (acc * {r["base"]} + byte + 1) % 2147483647; }});
  return acc % count;
}}
module.exports = {{ paletteFor }};
''',
        "router_class.py": f'''class Balancer:
    MULT_A = {m["k1"]}
    MULT_B = {m["k2"]}

    def __init__(self, nodes):
        self.nodes = nodes

    def node_index(self, ident, count):
        state = {m["iv"]}
        for octet in ident.encode("utf-8"):
            state = ((state ^ octet) * self.MULT_A) % 2 ** 32
            state = state ^ (state >> {m["rot"]})
        state = state ^ (state >> 16)
        state = (state * self.MULT_B) % 2 ** 32
        return (state ^ (state >> 13)) % count
''',
        "tagger_while.py": f'''def make_tag(payload, width):
    lo, hi, i, raw = {k["a0"]}, {k["b0"]}, 0, payload.encode()
    while i < len(raw):
        lo = (lo + raw[i] * {k["w"]}) % 65521
        hi = (hi + lo) % 65521
        i += 1
    return ((hi * 65536 + lo) ^ {k["salt"]}) % width
''',
    }


def run(*args, cwd=None, tool=TOOL) -> str:
    r = subprocess.run([sys.executable, str(tool), *args], capture_output=True, text=True, cwd=cwd)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="trapr-test-"))
    repo = tmp / "myproj"
    (repo / "myproj").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "myproj/__init__.py").write_text("")
    (repo / "myproj/ratelimit.py").write_text(RATELIMIT)
    (repo / "myproj/utils.py").write_text(UTILS)
    (repo / "tests/test_ratelimit.py").write_text("def test_x():\n    assert True\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/alice/myproj.git"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    (repo / "scratch_notes.py").write_text("print('my untracked local experiment')\n")   # never git-added
    shutil.copy(TOOL, repo / "trapr.py")

    out = run("protect", "--license", "MIT", "--owner", "Alice", "--canaries", "4", "--no-timestamp",
              cwd=repo, tool=repo / "trapr.py")
    vault = tmp / "myproj.trapr-vault.md"
    data = ts.load_vault(vault)
    by_kind = {c["kind"]: c for c in data["canaries"].values()}
    cname, c = next((n, c) for n, c in data["canaries"].items() if c["kind"] == "bucket")
    vtext = vault.read_text()
    stop = int(re.search(r"read lines 1–(\d+)", vtext).group(1))
    vlines = vtext.splitlines()

    sus = tmp / "suspects"
    sus.mkdir()
    (sus / "verbatim.py").write_text((repo / "myproj/ratelimit.py").read_text())
    stripped = re.sub(rf"^# ({re.escape(data['marker_label'])}|SPDX).*\n", "", (repo / "myproj/ratelimit.py").read_text(), flags=re.M)
    (sus / "stripped.py").write_text(stripped)
    (sus / "llm_rewrite.py").write_text(LLM_REWRITE)
    for n, code in {**canary_disguises(c), **other_kind_disguises(by_kind)}.items():
        (sus / n).write_text(code)
    (sus / "lookalike.py").write_text(LOOKALIKE)
    (sus / "unrelated.py").write_text(UNRELATED)

    # real copied files import things that won't resolve; the canary must still be found
    mixer = by_kind["mixer"]
    py_canary = ts.canary_render("py", "route_it", {**mixer, "variant": [0, 1, 2, 0]})
    (sus / "with_broken_imports.py").write_text(
        "from myproj.internal import Engine\nimport not_installed_anywhere as nia\nLIMIT = nia.MAX\n\n"
        "class Worker(Engine):\n    pass\n\n" + py_canary)
    if ts.HAVE_TS:
        js_canary = ts.canary_render("js", "routeIt", {**mixer, "variant": [0, 1, 2, 0]}, "esm")
        (sus / "with_broken_imports.js").write_text(
            "import { Engine } from './engine.js';\nconst LIMIT = Engine.MAX;\nclass Worker extends Engine {}\n\n" + js_canary)

    os.chdir(tmp)
    found = {Path(r["suspect"]).name: r for r in ts.scan_tree(sus, data, 0.35)}
    grade = lambda n: found.get(n, {}).get("grade")  # noqa: E731

    # refresh: a new file gets a marker under the same key
    (repo / "myproj/new_module.py").write_text(RATELIMIT.replace("TokenBucket", "Bucket2"))
    subprocess.run(["git", "-C", str(repo), "add", "myproj/new_module.py"], check=True)
    run("refresh", "--vault", str(vault), "--repo-dir", str(repo))
    data2 = ts.load_vault(vault)

    checks = [
        ("protect: vault written outside the repo", vault.exists() and repo not in vault.parents),
        ("protect: every source file marked", all(re.search(rf"{data['marker_label']}: {data['ptag']}-", p.read_text())
                                                  for p in (repo / "myproj").glob("*.py") if p.name != "new_module.py")),
        ("protect: untracked local files are left untouched", (repo / "scratch_notes.py").read_text()
         == "print('my untracked local experiment')\n" and "scratch_notes.py" not in data["files"]),
        ("protect: 4 canaries of 4 different kinds", len(by_kind) == 4 == len(data["canaries"])),
        ("protect: canaries spread over several files, starting with utils.py",
         len({c["path"] for c in data["canaries"].values()}) >= 2
         and any(c["path"] == "myproj/utils.py" for c in data["canaries"].values())),
        ("protect: every canary present in its file", all(n in (repo / c["path"]).read_text()
                                                          for n, c in data["canaries"].items())),
        ("protect: next steps tell you to remove the tool", "rm trapr.py" in out),
        ("vault: owner detected from git remote", data["owners"] == ["alice"] and data["repo"] == "alice/myproj"),
        ("vault: agent stop-line points just before machine data", "Machine data" in "\n".join(vlines[stop:stop + 3])
         and "trapr-data" not in "\n".join(vlines[:stop])),
        ("vault: has playbook, queries, marker table, canary probes",
         all(h in vtext for h in ("Agent playbook", "Search queries", "Marker table", "Probe input"))),
        ("verbatim copy → definitive (marker)", grade("verbatim.py") == "definitive"),
        ("markers stripped → caught (definitive: the file carries a canary)", grade("stripped.py") == "definitive"),
        ("LLM-style rewrite → flagged", grade("llm_rewrite.py") in ("strong", "moderate")),
        ("canary rewritten with reduce → definitive", grade("rewrite_reduce.py") == "definitive"),
        ("canary hidden as a method → definitive", grade("as_method.py") == "definitive"),
        ("canary ported to JS → definitive (constants-only 'strong' without tree-sitter)",
         grade("ported.js") == ("definitive" if ts.HAVE_TS and shutil.which("node") else "strong")),
        ("booby trap → canary caught", grade("booby_trap.py") == "definitive"),
        ("rolling canary ported to JS with forEach → definitive (strong without tree-sitter)",
         grade("palette_port.js") == ("definitive" if ts.HAVE_TS and shutil.which("node") else "strong")),
        ("mixer canary rewritten as a class method with class constants → definitive", grade("router_class.py") == "definitive"),
        ("checksum canary rewritten as a while loop → definitive", grade("tagger_while.py") == "definitive"),
        ("booby trap → module code NOT executed", not list(tmp.rglob("PWNED"))),
        ("canary next to broken imports and a missing base class → definitive (py)",
         grade("with_broken_imports.py") == "definitive"),
        ("canary next to broken imports and a missing base class → definitive (js)",
         grade("with_broken_imports.js") == "definitive" or not (ts.HAVE_TS and shutil.which("node"))),
        ("FNV lookalike → not flagged", "lookalike.py" not in found),
        ("unrelated code → not flagged", "unrelated.py" not in found),
        ("refresh: same key, new file marked", data2["ptag"] == data["ptag"]
         and "myproj/new_module.py" in data2["files"] and data2["files"]["myproj/new_module.py"]["marked"]),
    ]
    # hunt against a mocked GitHub API: one copier repo, plus the owner's own repo (must be skipped)
    import json as _json
    copy_text = stripped
    calls = []

    def fake_fetch(url, token=None, accept=None):
        calls.append(url)
        if "/search/code" in url:
            items = [{"repository": {"full_name": "mallory/clone", "url": "https://api.github.com/repos/mallory/clone"},
                      "path": "lib/limiter.py", "url": "https://api.github.com/raw/mallory/limiter",
                      "html_url": "https://github.com/mallory/clone/blob/main/lib/limiter.py"},
                     {"repository": {"full_name": "alice/myproj", "url": "x"}, "path": "myproj/ratelimit.py",
                      "url": "https://api.github.com/raw/alice/own", "html_url": "https://github.com/alice/myproj"}]
            return _json.dumps({"total_count": 2, "items": items}).encode()
        if url.endswith("/raw/mallory/limiter"):
            return copy_text.encode()
        if url.endswith("/repos/mallory/clone"):
            return _json.dumps({"created_at": "2026-12-01T00:00:00Z", "fork": False, "stargazers_count": 3,
                                "license": {"spdx_id": "MIT"}}).encode()
        raise AssertionError(url)

    REAL_FETCH = ts.fetch
    ts.fetch, ts.github_token = fake_fetch, (lambda: "fake")
    hunt_report = tmp / "hunt.md"
    ts.cmd_hunt(type("A", (), {"vault": str(vault), "max_queries": 3, "max_files": 50, "pause": 0, "sources": "code",
                                "max_forks": 0, "max_packages": 0, "min_score": 0.35, "report": str(hunt_report)})())
    hr = hunt_report.read_text()
    checks += [
        ("hunt (mocked API): finds the copier repo", "mallory/clone" in hr and "Definitive" in hr),
        ("hunt (mocked API): skips the owner's own repo", not any("/raw/alice/own" in u for u in calls)),
        ("hunt (mocked API): report includes repo license + date", "license MIT" in hr and "2026-12-01" in hr),
    ]

    # ---- forks (mocked GitHub API): an untouched fork is ignored; a renamed fork that dropped the
    # license and stripped markers is reported
    marked_file = "myproj/ratelimit.py"
    parent_tree = {"tree": [{"path": "LICENSE"}, {"path": marked_file}, {"path": "myproj/utils.py"}]}

    def fork_fetch(url, token=None, accept=None, timeout=60):
        if url.endswith("/repos/alice/myproj"):
            return _json.dumps({"default_branch": "main"}).encode()
        if "/repos/alice/myproj/git/trees/" in url:
            return _json.dumps(parent_tree).encode()
        if "/repos/alice/myproj/forks" in url:
            if not url.endswith("page=1"):
                return b"[]"
            return _json.dumps([
                {"full_name": "bob/myproj", "name": "myproj", "default_branch": "main",
                 "created_at": "2026-11-01", "pushed_at": "2026-11-01", "stargazers_count": 0},
                {"full_name": "eve/fastlimit", "name": "fastlimit", "default_branch": "main",
                 "created_at": "2026-11-01", "pushed_at": "2026-11-05", "stargazers_count": 40},
            ]).encode()
        if "/repos/eve/fastlimit/git/trees/" in url:
            return _json.dumps({"tree": [{"path": marked_file}, {"path": "myproj/utils.py"}]}).encode()
        if "/repos/eve/fastlimit/contents/" in url:
            rel = url.split("/contents/")[1].split("?")[0]
            text = (repo / rel).read_text()
            return re.sub(rf"^# ({re.escape(data['marker_label'])}|SPDX).*\n", "", text, flags=re.M).encode()
        raise AssertionError(url)

    ts.fetch = fork_fetch
    flog = []
    fork_findings, fork_rows = ts.hunt_forks(data, "fake", 50, 0.35, flog)
    ts.fetch = REAL_FETCH
    checks += [
        ("forks: untouched fork ignored", not any("bob/myproj" in r for r in fork_rows)),
        ("forks: renamed fork that removed LICENSE and markers is reported",
         any("eve/fastlimit" in r and "license file removed" in r and "markers removed" in r for r in fork_rows)),
        ("forks: stripped files in the fork still graded definitive or strong",
         bool(fork_findings) and all(f["grade"] in ("definitive", "strong") for f in fork_findings)),
    ]

    # ---- malicious package archives can't escape the extraction folder
    import tarfile, io
    evil = tmp / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tf:
        for name, body in (("../escape.py", b"x=1"), ("/abs.py", b"x=1"), ("pkg/ok.py", b"x=1"), ("pkg/big.bin", b"0")):
            info = tarfile.TarInfo(name); info.size = len(body); tf.addfile(info, io.BytesIO(body))
        link = tarfile.TarInfo("pkg/link.py"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/passwd"; tf.addfile(link)
    dest = tmp / "extract" / "inner"
    n_ok = ts.safe_extract(evil, dest)
    checks.append(("registries: archive extraction blocks ../, absolute paths and symlinks",
                   n_ok == 1 and (dest / "pkg/ok.py").exists() and not (tmp / "extract" / "escape.py").exists()
                   and not (dest / "pkg/link.py").exists()))

    # ---- model probes against a fake server speaking the Ollama, OpenAI and Anthropic APIs
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    canary_by_name = data["canaries"]

    class FakeLLM(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, obj):
            body = _json.dumps(obj).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            self._send({"models": [{"name": "memorizer"}, {"name": "honest"}]})
        def do_POST(self):
            req = _json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            code = req["messages"][-1]["content"].split("```", 1)[1]
            name = re.search(r"(?:def|function)\s+(\w+)", code).group(1)
            ck = canary_by_name[name]
            if req["model"] == "memorizer":
                text = "```\n" + ts.canary_render(ck["lang"], name, {**ck, "variant": [2, 3, 0, 2]}) + "```"
            else:
                text = f"```\ndef {name}(k, n):\n    return sum(k.encode()) % n\n```"
            if self.path == "/api/chat":
                self._send({"message": {"content": text}})
            elif self.path == "/v1/chat/completions":
                self._send({"choices": [{"message": {"content": text}}]})
            else:
                self._send({"content": [{"type": "text", "text": text}]})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    results = {}
    for prov, url in (("ollama", base), ("openai", base + "/v1"), ("anthropic", base)):
        rep_path = tmp / f"models-{prov}.md"
        A = type("A", (), {"vault": str(vault), "provider": prov, "model": None if prov == "ollama" else ["memorizer", "honest"],
                           "base_url": url, "api_key": "k", "samples": 2, "report": str(rep_path)})
        ts.cmd_probe_models(A())
        results[prov] = rep_path.read_text()
    srv.shutdown()
    n_can = len(data["canaries"])
    checks += [(f"probe-models ({prov}): memorizing model caught on all {n_can} canaries, honest model cleared",
                txt.count("reproduced your canary") == n_can and "`honest`" in txt
                and not re.search(r"`honest`[^\n]*reproduced your canary", txt))
               for prov, txt in results.items()]

    # ---- timestamps: a fake calendar answers like a real one; the proof must parse in the reference library
    class FakeCalendar(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            digest = self.rfile.read(int(self.headers["Content-Length"]))
            try:
                from opentimestamps.core.timestamp import Timestamp
                from opentimestamps.core.op import OpSHA256, OpAppend
                from opentimestamps.core.notary import PendingAttestation
                from opentimestamps.core.serialize import BytesSerializationContext
                stamp = Timestamp(digest)
                stamp.ops.add(OpAppend(os.urandom(16))).ops.add(OpSHA256()).attestations.add(PendingAttestation("https://fake.cal"))
                ctx = BytesSerializationContext(); stamp.serialize(ctx); body = ctx.getbytes()
            except ImportError:
                body = b"\x00" + bytes(8) + b"\x00"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

    cal = ThreadingHTTPServer(("127.0.0.1", 0), FakeCalendar)
    threading.Thread(target=cal.serve_forever, daemon=True).start()
    rec = ts.stamp(data, tmp, "myproj", [f"http://127.0.0.1:{cal.server_address[1]}"] * 2)
    cal.shutdown()
    pre = (tmp / rec["commitment_file"]).read_bytes()
    stamp_ok = rec.get("ots_file") and (tmp / rec["ots_file"]).exists()
    parsed = "skipped (opentimestamps not installed)"
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import BytesDeserializationContext
        f = DetachedTimestampFile.deserialize(BytesDeserializationContext((tmp / rec["ots_file"]).read_bytes()))
        parsed = f.file_digest == ts.hashlib.sha256(pre).digest()
    except ImportError:
        pass
    checks += [
        ("timestamp: commitment reveals no secret", data["secret"] not in pre.decode()
         and "secret_sha256" in pre.decode()),
        ("timestamp: .ots proof written and parses in the OpenTimestamps library",
         bool(stamp_ok) and parsed in (True, "skipped (opentimestamps not installed)")),
    ]

    # every cosmetic variant of every canary kind must behave exactly like the reference
    import itertools
    bad = n_checked = 0
    for kind, ck in by_kind.items():
        for v in itertools.product(range(4), range(4), range(3), range(3)):
            pv = {**ck, "variant": list(v)}
            for lang, ext, nm in (("py", ".py", "slot_fn"), ("js", ".js", "slotFn")):
                if lang == "js" and not (ts.HAVE_TS and shutil.which("node")):
                    continue
                src, names = ts.harness(ts.canary_render(lang, nm, pv), ext)
                got = ts.run_harness(src, names, lang, pv["probes"]).get(nm)
                bad += got != pv["expected"]
                n_checked += 1
    checks.append((f"all {n_checked} canary kind × style variants behave identically", bad == 0))
    labels = {ts.MARKER_LABELS[os.urandom(32)[-2] % len(ts.MARKER_LABELS)] for _ in range(50)}
    checks.append(("marker label varies per project", len(labels) > 3))

    ok = True
    for label, passed in checks:
        ok &= bool(passed)
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
    print(f"\n{sum(bool(p) for _, p in checks)}/{len(checks)} passed  (workspace: {tmp})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
