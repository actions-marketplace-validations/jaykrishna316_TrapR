# Security

## Reporting a vulnerability

Please report security problems privately through GitHub's
[private vulnerability reporting](https://github.com/jaykrishna316/TrapR/security/advisories/new)
rather than a public issue. Expect a reply within a week.

Especially welcome:
- a way for suspect code to execute anything outside the sanitized harness during `verify` or `hunt`
- a way to forge markers or canary outputs without the secret key
- a way to make TrapR leak vault contents (secret, probes, fingerprints)
- a package archive that writes outside its extraction folder during `hunt`

## Threat model

**Assets.** The vault's secret key, and the evidence TrapR produces.

**Assumed adversary.** A copier who has read TrapR's source and README and wants to reuse your code
without attribution, while avoiding detection.

| What the adversary does | Outcome |
|---|---|
| Copies files unchanged | Caught by signed markers (definitive) |
| Strips marker comments | Caught by structural fingerprints (strong) and the canary (definitive) |
| Renames identifiers, reformats, removes comments | Caught by token and AST winnowing |
| Rewrites the canary in another style or language | Caught by canary behavior (6 secret probes) |
| Deletes a canary | Possible. They must find every one (3 by default, of different kinds, in different files), and each costs whatever it was wired into |
| Publishes the copy as a PyPI or npm package | `hunt` downloads and scans similarly named packages without installing them |
| Forks, then strips the LICENSE and markers | `hunt` walks the fork network and flags exactly that |
| Reimplements the logic from scratch | Not detectable as copying, and arguably not copying |
| Forges your markers to frame someone | Not possible without your key (HMAC-SHA256) |
| Plants a booby trap in a suspect file | Suspect modules are never imported. Only definitions are extracted and run in a subprocess with memory and time limits and an empty environment. This is defense in depth, not a hardened sandbox |

**Your responsibilities.**
- Never commit the vault. It contains the secret key. The repo's `.gitignore` excludes `*.trapr-vault.md`.
- Back up the vault. Without it, your markers and canary can't be tied to you.
- Run unattended hunts (the GitHub Action) only in a **private** repository. The action refuses to run in a public one.
- Treat suspect repositories as untrusted. Don't install or run them to "check".

## What TrapR is not

It doesn't prevent copying, obfuscate code, or enforce licenses. It produces evidence. What you do with it
(ask for attribution, open an issue, consult a lawyer) is up to you. Nothing here is legal advice.
