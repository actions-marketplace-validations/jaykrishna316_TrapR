# Changelog

## 0.5.3 (2026-11-21)

- **Fewer false positives from canary constants.** The first live hunt across four projects flagged 31 unrelated
  files (CSV captures, ID lists, decompiled C++) because one 7-digit canary constant appeared in them by chance.
  Constants now count only in source code, and a lone constant counts only if it has 9 or more digits; a real copy
  keeps the canary's math, so its constants travel together. All 31 now clear, and the real test copy is still
  definitive. New regression test: `tests/test_constants.py`.
- **First fully live hunt.** GitHub code search, the fork crawl, PyPI and npm ran live from the GitHub Action across
  Neo, Braxis, TrapR and a demo repo. The fork crawl found the test fork that removed the LICENSE and markers.

## 0.5.2 (2026-11-21)

- **Fix:** when a hunt found evidence, the Action's "Open an issue" step could fail with "Body is too long", because
  GitHub caps an issue at 65,536 characters. The issue now leads with a table per project, keeps each project's
  report short, and links to the run's `trapr-reports` artifact for the full reports.

## 0.5.1 (2026-11-21)

- **Scheduled hunts with a weekly email:** the GitHub Action now writes one report per project and comments on a
  single "TrapR weekly hunt" issue after every run, with a row per project, all clear or not. GitHub emails each
  comment to watchers. New input `report-issue` (default "TrapR weekly hunt"; empty turns it off).
- Every vault in the repo is hunted automatically, so new projects are covered as soon as their vault is added.
- The example workflow now runs every Sunday.

## 0.5.0 (2026-11-21)

- **New `similarity` command:** compares your code with any folder, git URL or GitHub file, including after a port
  to another language. Keywords map to language-neutral tokens, type and modifier words are ignored, and distinctive
  string and number literals are compared separately (ports keep literals). Output is a lead for human review, never
  proof. Stdlib only.
- **Calibration:** 22 unrelated popular repos (incl. Python, JavaScript and Java rate limiters and a circuit breaker)
  and 14 held-out unrelated repos gave 0 false leads. The highest unrelated containment was 0.21. A real copy (a fork
  with markers and LICENSE removed) scored 1.00 containment and was flagged.
- **Fix:** `refresh` now gives newly marked files the same SPDX header lines as `protect` and `mark`.
- **Known recall limit:** a clean port of a short module that shares only one or two distinctive literals is not
  reported as a lead. The rules are precision-first on purpose.

## 0.4.2 (2026-11-09)

- **New `mark` command:** protect other branches with the same key. Run it on a checkout of any branch: files
  get exactly the header they have on main (so the branches still merge cleanly), and files that exist only on
  that branch are added to the vault index so their markers stay definitive. Existing vault entries are never
  changed. Canaries are left to main; branches pick them up when they merge it.
- The SPDX copyright owner is now stored in the vault, so `mark` can reuse it.

## 0.4.1 (2026-11-07)

- **Fix:** in a git repo, `protect` and `refresh` now touch only files git tracks. Before, they also marked
  untracked local files (scratch scripts, experiments) and fingerprinted them into the vault.
- **Python 3.10+.** Python 3.9 reached end of life in October 2025 and is no longer available on GitHub's
  Ubuntu 26.04 runners. CI now covers 3.10–3.14. GitHub Actions updated to their current Node 24 versions.
- **`probe-models` is more honest about non-answers.** A model that never returns a function that runs is now
  reported as "inconclusive" instead of "not reproduced". Ollama requests turn off thinking mode (falling back
  for older servers), allow longer answers, and wait up to 15 minutes for slow local CPUs.

## 0.4.0 (2026-11-07)

Harder to escape: more traps, more places searched, AI models checked, and provable dates.

- **Multiple canaries.** `protect` plants 3 by default (`--canaries 0-4`), each a different kind of useful helper:
  rollout bucket, colour index, shard router and checksum. They're spread over different core files. Each kind's
  name, docstring, parameters and style vary per project; all 1,152 kind × style combinations are verified in tests.
- **Wider hunt.** `hunt --sources code,forks,pypi,npm`: GitHub code search, the fork network (flags forks that removed
  the LICENSE or stripped markers), and PyPI and npm packages with similar names, downloaded into a sandboxed folder
  with path-traversal and symlink protection, never installed.
- **`probe-models`.** Asks local (Ollama) or cloud (OpenAI-compatible, Anthropic) models to finish each canary from
  its signature, then runs the answer on the secret probes. A full match means the model saw the code.
- **Timestamps.** `protect` and `timestamp` anchor a secret-free commitment in Bitcoin via OpenTimestamps; `--swh`
  also requests a Software Heritage archive of the public repo.
- **Sturdier verification.** Each definition in a suspect file loads independently, so canaries are found next to
  unresolvable imports and missing base classes. Methods run on a bare instance, so canaries that use class
  constants are found. Each function gets its own 2-second budget, results stream so one hang can't hide others,
  and the runner works without POSIX-only features (Windows).
- Canaries are excluded from structural fingerprints, which removes a rare false positive against ordinary
  FNV-style hashes.
- Local servers (Ollama, LM Studio) are always reached without an HTTP proxy.

## 0.3.0 (2026-11-07)

First public release.

- `protect`: one command plants per-file HMAC markers, optional SPDX headers, and a secret-keyed
  behavioral canary; fingerprints the repo; and writes a private vault outside the repo.
- The vault includes an AI-agent playbook, GitHub search queries with links, a marker table, the canary
  reference and the evidence-grading rules.
- `hunt` runs GitHub code search with the vault's queries and verifies every hit. `verify` takes a file,
  folder, git URL or GitHub file URL. `refresh` re-fingerprints with the same key.
- Five evidence layers: signed markers, canary behavior, canary constants, token winnowing, AST winnowing
  (tree-sitter optional, with stdlib `ast` for Python).
- Safe verification: suspect modules are never imported; only definitions are extracted and run in a
  limited subprocess.
- Per-project marker labels and canary names, docstrings, variable names and arithmetic style, so the
  public source gives copiers nothing fixed to search for.
- A GitHub Action for scheduled hunts from a private vaults repo.
- Validated on Neo and Braxis: every copy scenario was caught, and 10 unrelated popular repos produced
  0 false positives.
