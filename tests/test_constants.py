#!/usr/bin/env python3
"""
Canary-constant grading: a copy keeps a canary's math, so all of its constants travel together, in source code.
A lone short constant, or any constant inside a data file, is a coincidence and must not be reported.
(Regression for the first live hunt, where one 7-digit constant matched 31 unrelated CSV/TXT/C++ files.)

Run:  python3 tests/test_constants.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import trapr as ts  # noqa: E402


def _vault() -> dict:
    d = Path(tempfile.mkdtemp(prefix="trapr-consttest-"))
    repo = d / "proj"
    repo.mkdir()
    (repo / "app.py").write_text("def total(xs):\n    s = 0\n    for x in xs:\n        s += x\n    return s\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"], cwd=repo, check=True)
    vault = d / "proj.trapr-vault.md"
    subprocess.run([sys.executable, str(HERE / "trapr.py"), "protect", "--repo-dir", str(repo), "--vault", str(vault),
                    "--canaries", "4", "--no-timestamp"], check=True, capture_output=True)
    return ts.load_vault(vault)


def _checks() -> list[tuple[str, bool]]:
    data = _vault()
    out: list[tuple[str, bool]] = []
    multi = [(n, ts.canary_consts(c)) for n, c in data["canaries"].items() if len(ts.canary_consts(c)) >= 2]
    name, consts = multi[0]
    vals = list(consts.values())
    filler = "\n".join(f"row_{i} = {i * 7919}" for i in range(40))

    both_py = f"A = {vals[0]}\nB = {vals[1]}\n{filler}\n"
    r = ts.scan_file(both_py, ".py", data)
    out.append(("all constants of a canary in source code: reported, strong", bool(r) and r["grade"] == "strong"))

    both_csv = f"id,value\n1,{vals[0]}\n2,{vals[1]}\n"
    out.append(("same constants in a CSV data file: not reported", ts.scan_file(both_csv, ".csv", data) is None))

    short = min(vals)
    one_py = f"X = {short}\n{filler}\n"
    expect_none = short < 10**8
    r = ts.scan_file(one_py, ".py", data)
    out.append((f"one lone constant ({len(str(short))} digits) in source: "
                f"{'not reported' if expect_none else 'kept (9+ digits)'}",
                (r is None) if expect_none else bool(r)))

    one_txt = "\n".join(str(short + i * 0) for i in range(1)) + "\n" + "\n".join(str(i) for i in range(5000))
    out.append(("one constant inside a big numeric TXT dump: not reported", ts.scan_file(one_txt, ".txt", data) is None))
    return out


if __name__ == "__main__":
    results = _checks()
    for label, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
    ok = all(p for _, p in results)
    print(f"\n{sum(bool(p) for _, p in results)}/{len(results)} passed")
    sys.exit(0 if ok else 1)
