#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Jayakrishna Ichapurapu
# build-id: 8113f5bb-315f02c9
"""Keep TrapR markers and fingerprints current on your protected repos.

Runs from your PRIVATE vaults repo (see trapr-sync.yml). For every project in trapr-sync.json and
every branch listed for it:
  1. shallow-clone the branch,
  2. run `trapr mark` with the project's vault: new files get markers and SPDX headers, and on the
     primary branch the fingerprints of changed files are refreshed,
  3. if any file changed, commit and push to the branch. If the push is refused (branch protection,
     or someone pushed in the meantime), push to `trapr/sync-<branch>` and open a pull request.
The vault files are updated in place; the workflow commits them afterwards.

Never prints the vault or its key. Needs GH_TOKEN with Contents and Pull requests read/write on the
protected repos.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAPR = HERE / "trapr.py"
BOT = ["-c", "user.name=trapr-bot", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com"]
MSG = "Add TrapR build references to new files"


def sh(*cmd, cwd=None, check=True, env=None) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        err = r.stderr.strip()[-400:]
        for k in ("GH_TOKEN", "GITHUB_TOKEN"):
            if os.environ.get(k):
                err = err.replace(os.environ[k], "***")
        raise RuntimeError(f"{cmd[0]} {cmd[1] if len(cmd) > 1 else ''} failed: {err}")
    return r


def remote_url(repo: str) -> str:
    base = os.environ.get("TRAPR_SYNC_BASE")          # tests point this at local bare repos
    if base:
        return f"{base}/{repo}.git"
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not tok:
        sys.exit("GH_TOKEN is not set.")
    return f"https://x-access-token:{tok}@github.com/{repo}.git"


def open_pr(repo: str, base: str, head: str) -> str:
    if os.environ.get("TRAPR_SYNC_BASE"):
        return "(pull request skipped in test mode)"
    existing = sh("gh", "pr", "list", "--repo", repo, "--head", head, "--base", base, "--state", "open",
                  "--json", "url", "--jq", ".[0].url", check=False).stdout.strip()
    if existing:
        return f"updated {existing}"
    r = sh("gh", "pr", "create", "--repo", repo, "--base", base, "--head", head, "--title", MSG,
           "--body", "Adds TrapR build-reference comments (and SPDX headers) to files that don't have "
                     "them yet. Comment lines only; no code changes.", check=False)
    return r.stdout.strip() or f"could not open a pull request: {r.stderr.strip()[-200:]}"


def open_prs(repo: str, bases: list[str]) -> list[dict]:
    """Open pull requests into the guarded branches whose head branch lives in the same repo."""
    if os.environ.get("TRAPR_SYNC_BASE"):
        return json.loads(os.environ.get("TRAPR_SYNC_TEST_PRS", "[]"))
    fields = "number,baseRefName,headRefName,isCrossRepository,state"
    only = os.environ.get("TRAPR_PR", "").strip()
    if only:   # asked for one pull request: fetch it directly instead of listing
        r = sh("gh", "pr", "view", only, "--repo", repo, "--json", fields, check=False)
        prs = [json.loads(r.stdout)] if r.returncode == 0 and r.stdout.strip() else []
    else:
        r = sh("gh", "pr", "list", "--repo", repo, "--state", "open", "--limit", "100", "--json", fields, check=False)
        prs = json.loads(r.stdout or "[]") if r.returncode == 0 else []
    if r.returncode != 0:
        print(f"::warning::{repo}: could not read pull requests: {r.stderr.strip()[-300:]}", flush=True)
    keep = [p for p in prs if p["baseRefName"] in bases and not p["isCrossRepository"] and p.get("state", "OPEN") == "OPEN"]
    for p in prs:
        if p not in keep:
            print(f"{repo}#{p['number']}: skipped (base {p['baseRefName']}, fork={p['isCrossRepository']}, "
                  f"state {p.get('state')})", flush=True)
    if only and not prs:
        print(f"{repo}#{only}: not found", flush=True)
    return keep


def sync_pr(proj: dict, pr: dict, work: Path) -> str:
    """Mark a pull request's own branch, so the trapr-gate check passes before it merges."""
    return sync_branch(proj, pr["headRefName"], work, pr=pr["number"])


def sync_branch(proj: dict, branch: str, work: Path, pr: int | None = None) -> str:
    repo = proj["repo"]
    vault = HERE.parent / proj["vault"]
    d = work / f"{repo.replace('/', '_')}-{branch.replace('/', '_')}"
    if d.exists():
        return f"{repo}@{branch}: already done in this run."
    sh("git", "clone", "-q", "--depth", "1", "--branch", branch, remote_url(repo), str(d))
    cmd = [sys.executable, str(TRAPR), "mark", "--vault", str(vault), "--repo-dir", str(d)]
    if proj.get("owner"):
        cmd += ["--owner", proj["owner"]]
    for inc in proj.get("include_dirs", []):
        cmd += ["--include-dir", inc]
    if branch == proj.get("primary", "main") and pr is None:
        cmd.append("--update-existing")
    out = sh(*cmd).stdout.strip()
    if not sh("git", "status", "--porcelain", "--untracked-files=no", cwd=d).stdout.strip():
        return f"{repo}@{branch}: up to date. {out}"
    sh("git", "add", "-u", cwd=d)
    sh("git", *BOT, "commit", "-q", "-m", MSG, cwd=d)
    where = f"{repo}#{pr} ({branch})" if pr else f"{repo}@{branch}"
    if sh("git", "push", "-q", "origin", f"HEAD:refs/heads/{branch}", cwd=d, check=False).returncode == 0:
        return f"{where}: pushed. {out}"
    if pr:
        return f"{where}: push refused (the branch moved on?); the next run retries. {out}"
    head = f"trapr/sync-{branch}"
    sh("git", "push", "-q", "--force", "origin", f"HEAD:refs/heads/{head}", cwd=d)
    return f"{repo}@{branch}: direct push refused, {open_pr(repo, branch, head)}. {out}"


def main() -> int:
    cfg = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else HERE.parent / "trapr-sync.json").read_text())
    failed = 0
    only_pr, only_repo = os.environ.get("TRAPR_PR", "").strip(), os.environ.get("TRAPR_PR_REPO", "").strip()
    with tempfile.TemporaryDirectory(prefix="trapr-sync-") as tmp:
        for proj in cfg["projects"]:
            if only_repo and proj["repo"] != only_repo:
                continue
            # pull requests first: marking them is what lets the gate pass before merge
            for pr in open_prs(proj["repo"], proj["branches"]):
                if only_pr and str(pr["number"]) != only_pr:
                    continue
                try:
                    print(sync_pr(proj, pr, Path(tmp)), flush=True)
                except Exception as e:
                    failed += 1
                    print(f"::error::{proj['repo']}#{pr['number']}: {e}", flush=True)
            if only_pr:
                continue
            # primary branch last, so its view of shared files is what the vault keeps
            prim = proj.get("primary", "main")
            for branch in sorted(proj["branches"], key=lambda b: b == prim):
                try:
                    print(sync_branch(proj, branch, Path(tmp)), flush=True)
                except Exception as e:  # keep going with the other branches
                    failed += 1
                    print(f"::error::{proj['repo']}@{branch}: {e}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
