# Security policy

Use only values you can lose.

Impulse is non-custodial software: it holds no funds and no keys, and signing happens only on the key holder's machine. Nothing in it, or in this documentation, is financial, legal or tax advice, or an offer or solicitation to buy or sell anything. Impulse issues no asset and no token: any asset or token a trade moves is issued by someone else. Issuer terms, transfer restrictions and sanctions or other legal obligations that apply to an asset or a party stay the users' own responsibility, and Impulse does not check them.

## Supported versions

Security fixes are made on the latest release line only. Before the first tag, that is the `main` branch; from v0.1.0, the latest 0.1.x release.

## Reporting a vulnerability

Report vulnerabilities privately. Security contact: GitHub private vulnerability reporting at https://github.com/kaspakii/impulse/security/advisories/new (the repository's Security tab, "Report a vulnerability"). There is no email address. Do not open public issues for security findings. Expect acknowledgement within 72 hours.

Include the affected component and version or commit, the steps to reproduce (a failing test is best) and the impact: what value could be lost, locked or misdirected, and by whom.

Never send a private key, seed phrase or mnemonic, and never include one in a report. No one working on Impulse will ask for one.

## Review status

Reviewers will find the threat model (`docs/security/THREAT-MODEL.md`), the invariants and the test that pins each (`docs/security/INVARIANTS.md`) and the accepted limitations (`docs/security/KNOWN-LIMITATIONS.md`). Use only values you can lose.

## Scope

In scope: contracts/, crates/, demo/, and a design flaw in spec/. A published release artifact or npm package that does not match the tagged source is also in scope.

Out of scope: third-party dependencies, the Kaspa network itself.

## Verifying a release

Each release directory written by `scripts/release.sh` holds a `SHA256SUMS` file over the archives, the CycloneDX SBOMs and `BUILD-INFO.txt`. Check the files with `shasum -a 256 -c SHA256SUMS` (or `sha256sum -c SHA256SUMS`), and check the owner's detached signature of `SHA256SUMS` against the published public key. The build is reproducible from the tagged commit: run `scripts/release.sh --ref v<version>` on the same target, with the compiler and linker named in `BUILD-INFO.txt`, and compare `SHA256SUMS`. A mismatch is in scope.

## Testing

Test on TN10 or with funds you own. Do not test against anyone else's funds or against live trades.

## Disclosure

Please do not disclose a finding publicly before a fix is released. There is no fixed window: agree the date with us. Reporters are credited in the changelog unless they ask not to be.
