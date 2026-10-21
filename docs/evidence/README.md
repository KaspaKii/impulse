# Evidence

Raw evidence logs, one directory per run.

For the public tree, only attribution and location text was replaced in these logs, never a measured value:

- home paths were redacted to `~`, also inside the compressed logs (`*.log.gz`, recompressed);
- the names of the maintainers' local checkouts (`~/impulse-<work branch>`) read `~/impulse`, and their temporary directories read `/private/tmp/scratch` or `/private/tmp/`;
- in the process lists of the proving runs (`*-load-before.txt`), the executable path of a desktop application that was running on the build machine reads `<desktop app helper>` or `<desktop app helper (renderer)>`; the CPU figures beside it are unchanged;
- in the I20 mempool findings, the references to the owner's own runs are worded by what they check;
- in the README files, references to the owner's runbook and checklist are worded by what they are, without the file names, and work-branch names read as the release or work branch they were, and the maintainers' internal plan and records are named by what they are.

The `SHA256SUMS` files are the hashes taken at the time of each run, and are kept as recorded. A file redacted afterwards no longer matches its line; the unredacted originals are in the maintainers' private history.
