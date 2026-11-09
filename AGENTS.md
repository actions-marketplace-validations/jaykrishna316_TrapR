# AGENTS.md: setting up TrapR for a user

This file is for AI coding agents (Claude Code, Codex, Cursor, Devin, and others). A user has
probably said something like *"Set up TrapR on this repo"* or *"Protect my repo with
github.com/jaykrishna316/TrapR"*. Follow these steps exactly.

> If you were asked to work on TrapR's own code, skip to **Contributing** at the end.

## What you're doing

`trapr protect` plants traceable fingerprints in the user's repository and writes a private
**vault** file *outside* the repository. The vault holds a secret key and must never be committed,
printed in full, or uploaded anywhere.

## Step 1: Confirm three things with the user (one short question)

1. **The repo to protect.** Default: the current working directory. It must be a git repo with a clean
   working tree. If `git status --porcelain` shows changes, ask the user to commit or stash first so the
   TrapR changes are easy to review.
2. **License and copyright holder** for SPDX headers, e.g. `MIT`, `"Jane Doe"`. Read `LICENSE` and suggest
   what you find. If the user wants markers only, use `--no-spdx`.
3. **Where to keep the vault.** Default: the parent folder, `../<repo>.trapr-vault.md`. Never inside the repo.

## Step 2: Get the tool *outside* the repo

```bash
TS_DIR="${HOME}/.trapr" && mkdir -p "$TS_DIR"
curl -fsSL -o "$TS_DIR/trapr.py" \
  https://raw.githubusercontent.com/jaykrishna316/TrapR/v0.4.1/trapr.py
python3 "$TS_DIR/trapr.py" --version        # expect 0.4.1
```

If the release page lists a SHA-256 for `trapr.py`, verify it (`shasum -a 256` on macOS,
`sha256sum` on Linux) and stop if it doesn't match. Alternatives: `pipx install trapr` or
`uvx trapr`. Optional, for better detection in non-Python repos:
`pip install tree-sitter tree-sitter-language-pack`.

**Do not copy trapr.py into the user's repository.**

## Step 3: Dry run, then protect

```bash
python3 "$TS_DIR/trapr.py" protect --repo-dir . --license MIT --owner "Jane Doe" --dry-run
python3 "$TS_DIR/trapr.py" protect --repo-dir . --license MIT --owner "Jane Doe"
```

Useful flags: `--canaries N` (0–4, default 3), `--canary-into path/to/utils.py` (all canaries in one file),
`--canary-lang none` (no canaries), `--no-spdx`, `--exclude-owner <org>` (more owners to ignore when hunting),
`--no-timestamp`, `--vault <path>`.

## Step 4: Help the user make the canaries load-bearing

`protect` adds three small helper functions (the *canaries*), each a different kind, and prints an import
and a typical use for each: a percentage-rollout bucket, a stable colour index, a worker/shard router, a
content checksum. A canary nothing uses gets deleted by copiers. Offer to wire each into something real
that fits the project, using the printed example. Only make these changes if the user agrees, and keep
them small and obviously useful.

## Step 5: Review, then hand back

- Summarize `git diff --stat`: every source file gains 1–3 comment lines, plus the canaries.
- Run the project's tests and confirm they behave as before.
- **Do not commit or push** unless the user asks you to.
- Tell the user, in this order:
  1. the vault path (plus its `.trapr-commitment.json` and `.ots` timestamp files), and that they must back
     them up privately (password manager, private repo, encrypted drive), because losing them means losing the proof;
  2. that they should never commit it (it holds the secret key);
  3. how to hunt later: open the vault in an agent and say *"Follow the playbook in this file"*,
     or run `python3 ~/.trapr/trapr.py hunt --vault <vault>`;
  4. optionally: `trapr probe-models --vault <vault>` checks whether local or cloud AI models reproduce the canaries.

## Hard rules

- **Never** print, paste, summarize, or upload the vault's machine-data block or the `secret` value.
- **Never** place the vault inside the repository, and never `git add` it.
- **Never** run `protect --force` on an already-protected repo without the user's explicit OK. It creates
  a new key and makes the old markers unprovable. Use `refresh` instead.
- If the repo already contains `<label>: <8 hex>-<8 hex>` markers, it's already protected. Ask for the
  existing vault and use `refresh --vault <vault> --repo-dir .`.

## Hunting for copies (when the user asks later)

Open the user's vault, read only the line range its header names, and follow its **Agent playbook**.

---

## Contributing (only if you're working on TrapR itself)

- Everything ships as one file, `trapr.py`, with **zero required dependencies**, on Python 3.10+.
  Keep it that way. tree-sitter stays optional.
- Run `python3 tests/test_trapr.py` before and after changes; all checks must pass, with and
  without tree-sitter installed.
- Detection changes need evidence: rerun the false-positive check against several unrelated popular repos
  (`trapr verify --vault <vault> https://github.com/<org>/<repo>`) and report the numbers.
- Never execute suspect code outside the sanitized harness (`harness()` + `run_harness()`).
