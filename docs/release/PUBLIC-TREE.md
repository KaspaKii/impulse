# Public tree

Decision record for release gate B11 (public tree review). Owner decisions, 2026-10-17:

- The public repository is a clean export: a new repository holding one fresh commit of the scrubbed final tree, tagged `v0.4.0`. Internal history stays private.
- Public URL: https://github.com/kaspakii/impulse
- Security contact: GitHub private vulnerability reporting (Security tab, "Report a vulnerability"). There is no email address.

## What is excluded, and why

Policy: the public tree holds what a user, operator, integrator, contributor or reviewer needs: the code, the tests, the specifications, the user, operator and reference documents, the security documents, the evidence, the release documents, the scripts and CI. It states what the software does. It does not hold the maintainers' internal process material, the owner's personal material, or the owner's own test-network and mainnet runs and their records (owner instruction). The exact paths are the `excluded` list of `scripts/export-public.sh`, written there in fragments so that the script itself passes its own guard; this table names each entry by what it is, in the order of that list, because the public tree may not name the paths.

| Entry in `scripts/export-public.sh` | What it is | Why it is excluded |
| --- | --- | --- |
| 1 and 2 | The maintainers' build-tooling instructions (a file at the root) and the configuration directory of that tooling | Internal build process. The engineering rules they carried are public in `docs/ENGINEERING-RULES.md`. |
| 3 | The maintainers' local project notes directory (ignored in the private checkout; the export also drops its `.gitignore` line) | Internal notes and decision log. |
| 4 | Presentation decks | Owner decision: not part of the public tree. |
| 5 | Internal strategy note under `docs/reference/` | Marked not for the public tree. |
| 6 | The increment briefs directory | Internal work orders with their reports and review rounds. The design they implement is in `spec/`, the tests and mutation records are in the tree, and nothing shipped links into it. |
| 7 | The maintainers' plan under `docs/` | Internal plan: work sequence, roles and the open decisions. Its definition of done is the A rows of the maintainers' release checklist, which does not ship either (entry 14). |
| 8 | The owner's release run sheet directory under `docs/` | The owner's personal run sheet, with local preflight output. |
| 9 to 11 | Three presenter files under `demo/`: the live demonstration's presenter script, its stage cheat sheet and its run record | Live-stream presenter material, with local paths and timings. The demo itself (`demo/README.md`, the pages, the scripts and the tests) ships. |
| 12 | The ideas list under `docs/reference/` | Internal planning: ideas mapped to the increments they were scheduled in. |
| 13 | The owner's operating runbook under `docs/` | Owner runbook, with local paths and run order. Operators get the caution they need in `docs/OPERATIONS.md` and `docs/XCHAIN-SOLANA-USDC.md`. |
| 14 | The release checklist under `docs/` | Owner-only release gates and sign-off rows. |
| 15 | The mainnet runbook under `docs/` | The owner's ordered mainnet steps. |
| 16 | The draft bug bounty terms under `docs/release/` | Unpublished draft: no reward is offered, and `SECURITY.md` carries only the private reporting route. |
| 17 | The draft defensive publication proposal under `docs/reference/` | Unpublished draft. |
| 18 and 19 | The release notes of v0.1.0 under `docs/`, and their template under `docs/release/` | Notes of a release that was never made public; this tree starts at v0.4.0, and the known limits are in `docs/security/KNOWN-LIMITATIONS.md`. |
| 20 | A test-network run of the owner under `docs/evidence/` | The owner's own run. |
| 21 | An operator check run of the owner under `docs/evidence/` | The owner's own run. |
| 22 | A read-only node check run of the owner under `docs/evidence/` | The owner's own run. |
| 23 | The local cross-chain refund run under `docs/evidence/` | A run against earlier templates. |
| 24 | The Solana local validator run under `docs/evidence/` | A run against earlier templates. |
| 25 | The public Kaspa node check run under `docs/evidence/` | A run against earlier templates. |
| 26 and 27 | The release dry run and its self-test under `scripts/` | They check the owner documents of entries 13 to 19, which are not in the tree; `scripts/ci-local.sh` and the parity test skip them with a message where they are absent, and run them in the private checkout. |
| 28 | The review-scope document under the security documents directory | Prepared for a review of the code by others; the public tree states what the software does. |
| 29 | The mainnet run record template under `docs/release/` | The owner's own run record. |
| 30 to 32 | Two more owner test-network runs under `docs/evidence/` (the threshold-signing run and the cross-chain demo run) and the read-only node measurement under `docs/measurements/` | The owner's own runs. |
| 33 to 49 | The owner's run scripts under `scripts/` and `demo/`: the test-network scripts, the mainnet preparation scripts, the operator check script, the local cross-chain stand-in script, and the two shell libraries only they use | Scripts for the owner's own runs. Each prepares or plays the owner's trades; none is a tool a user needs, since the CLI does each step. |
| 50 to 60 | The self-tests of those scripts under `scripts/`, the private-only CI hook that runs them, and the private document that holds their design text | They test the scripts of entries 33 to 49. `scripts/ci-local.sh` skips the hook with a message where it is absent and runs it in the private checkout. The DAA sampling script stays, with its own test. |
| 61 | The brand kit directory under `docs/` (logo files, icons and brand rules) | Owner material. The pages ship only the wordmark and favicon they display, which NOTICE covers. |
| Files whose names start with the notes patterns in the script, wherever they sit | Internal notes files | Internal process. |

The security documents directory is renamed `docs/security` in the export, and every reference to it is rewritten.

Local home-directory paths in shipped files were replaced by neutral text (`~`, or the project and file for `docs/reference/BORROW-MAP.md`), and `docs/evidence/README.md` records that, with the attribution text replaced in raw logs.

## How to run the export

From a checkout with the release commit available as a ref, with `user.name` and `user.email` set to the identity that should author the commit:

```
scripts/export-public.sh <git-ref> <empty-output-dir> [tag]
```

The tag defaults to `v0.4.0`. The script archives the ref into the directory, removes the excluded paths, then refuses (non-zero exit, offending `file:line` listed) if the result holds:

- a macOS or Linux home-directory path;
- the name of the defence trees;
- an em dash;
- the banned status wording listed in the script (a release-stage label and review-status words, everywhere);
- a word that would talk about a review of the code by others, a test-network run of the owner or a mainnet run of the owner (case-insensitive; the list is `EP_SCOPE` in the script, held there in fragments; the dependency scanners cargo-audit and npm audit, their flags and files, are tools and are allowed);
- the all-capitals repository placeholder token;
- the name of an excluded path (case-sensitive);
- an internal build-process or tooling word, in a line or in a file name (case-insensitive; the list is `EP_INTERNAL` in the script, held there in fragments; the project web site `kaspa-kii.org` is allowed);
- a private-key block, or any finding of `gitleaks dir` (skipped with a warning if gitleaks is not installed; install it before the real run);
- a dangling relative link or anchor in the Markdown (`scripts/check-doc-links.sh`).

It also refuses a commit identity (`user.name`, `user.email`) that holds an internal word, so the public commit cannot carry the private relay address or a tooling name. Set a public identity before the run.

The release checkers `scripts/export-public.sh` and `scripts/test-export-public.sh` (and, in the private checkout, the release dry run and its self-test) hold the banned words as the patterns they search for, so the status-word and placeholder rules skip those files. They hold the excluded paths and the internal words only in fragments, so those rules, and the path, em dash and key rules, apply to them.

On success it runs `git init`, makes one commit "Impulse v0.4.0" in your git identity, tags `v0.4.0`, and prints the publishing commands. It never contacts a network. `scripts/test-export-public.sh` exercises it on a throwaway repository and runs in `scripts/ci-local.sh`.

## Owner steps to publish

0. The `.github/workflows/` files ship (`ci.yml` runs `scripts/ci-local.sh`, `release.yml` is the manual Linux release build; actions are pinned by commit SHA, permissions are read-only, no secrets).
1. Create the empty repository https://github.com/kaspakii/impulse (no README, licence or .gitignore from GitHub; keep it private until row C2).
2. Run the export on the release commit into a new empty directory, read the file list (`git -C <dir> ls-files`), and sign off row B11.
3. From the export directory, add the remote and push the branch with its tag:

```
cd <dir>
git remote add origin git@github.com:kaspakii/impulse.git
git push -u origin main --tags
```

4. Apply the settings below, then switch the repository to public (irreversible: the Apache-2.0 grant cannot be withdrawn and the tree cannot be unpublished).

## GitHub settings to switch on

- Settings, Code security: Private vulnerability reporting, enabled. Test it with a dummy report (row B2).
- Settings, Branches: a protection rule on `main` that requires a pull request and the CI status check, blocks force pushes and blocks deletion.
- Settings, Tags (rulesets): protect the pattern `v*` against deletion, update and force push, so a release tag cannot move.
- Settings, Code security: secret scanning and push protection, enabled.
