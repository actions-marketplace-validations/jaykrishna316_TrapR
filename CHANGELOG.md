# Changelog

## 0.4.1 (2026-11-07)

- **Fix:** in a git repo, `protect` and `refresh` now touch only files git tracks. Before, they also marked
  untracked local files (scratch scripts, experiments) and fingerprinted them into the vault.

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
