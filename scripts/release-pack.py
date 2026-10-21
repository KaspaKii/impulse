#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""Deterministic packaging steps of scripts/release.sh (I14 supply chain).

  release-pack.py tar OUT.tar.gz TOPDIR EPOCH NAME=PATH[:MODE] ...
      A gzip tar whose bytes depend only on the named files' contents and modes, TOPDIR and
      EPOCH: entries in name order, mtime EPOCH, owner and group 0 with empty names, ustar
      format, a gzip header with mtime EPOCH and no file name. MODE is octal (default 644).
  release-pack.py sbom IN.json OUT.json SRC_DIR EPOCH
      A CycloneDX JSON SBOM with every occurrence of the absolute build directory SRC_DIR
      replaced by /impulse, no serialNumber, metadata.timestamp set to EPOCH, and keys written in sorted order.
  release-pack.py sums DIR
      Writes DIR/SHA256SUMS: one "<sha256>  <name>" line per regular file of DIR, in name order,
      the format `shasum -a 256 -c` and `sha256sum -c` read. SHA256SUMS itself is not listed.

Exit 2 on misuse, 1 on a refused input. Reads no key material and writes only the named outputs.
"""
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time

NAME = re.compile(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*")


def die(code, msg):
    print("release-pack: " + msg, file=sys.stderr)
    sys.exit(code)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def cmd_tar(args):
    if len(args) < 4:
        die(2, "usage: tar OUT.tar.gz TOPDIR EPOCH NAME=PATH[:MODE] ...")
    out, top, epoch, specs = args[0], args[1], args[2], args[3:]
    if not NAME.fullmatch(top) or ".." in top.split("/"):
        die(1, "bad top directory name: %r" % top)
    if not epoch.isdigit():
        die(1, "EPOCH must be a non-negative integer: %r" % epoch)
    epoch = int(epoch)
    entries = {}
    for spec in specs:
        name, sep, rest = spec.partition("=")
        if not sep or not NAME.fullmatch(name) or ".." in name.split("/"):
            die(1, "bad entry name: %r" % spec)
        path, mode = rest, "644"
        m = re.fullmatch(r"(.*):([0-7]{3})", rest)
        if m:
            path, mode = m.group(1), m.group(2)
        if not os.path.isfile(path) or os.path.islink(path):
            die(1, "not a regular file: %r" % path)
        if name in entries:
            die(1, "entry named twice: %r" % name)
        entries[name] = (path, int(mode, 8))
    dirs = set()
    for name in entries:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))

    def info(name, kind, mode, size=0):
        ti = tarfile.TarInfo(top + "/" + name if name else top)
        ti.type, ti.mode, ti.size, ti.mtime = kind, mode, size, epoch
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        tf.addfile(info("", tarfile.DIRTYPE, 0o755))
        for name in sorted(set(entries) | dirs):
            if name in dirs:
                tf.addfile(info(name, tarfile.DIRTYPE, 0o755))
                continue
            path, mode = entries[name]
            with open(path, "rb") as f:
                data = f.read()
            tf.addfile(info(name, tarfile.REGTYPE, mode, len(data)), io.BytesIO(data))
    with open(out, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=epoch, compresslevel=9) as gz:
            gz.write(raw.getvalue())


def cmd_sbom(args):
    if len(args) != 4 or not args[3].isdigit():
        die(2, "usage: sbom IN.json OUT.json SRC_DIR EPOCH")
    src_in, out, src_dir, epoch = args
    src_dir = src_dir.rstrip("/")
    if not os.path.isabs(src_dir) or len(src_dir) < 2:
        die(1, "SRC_DIR must be an absolute path: %r" % src_dir)
    with open(src_in, encoding="utf-8") as f:
        text = f.read()
    try:
        # cargo-cyclonedx writes the resolved path (macOS: /private/var for /var), so replace both.
        real = os.path.realpath(src_dir)
        doc = json.loads(text.replace(real, "/impulse").replace(src_dir, "/impulse"))
    except ValueError as e:
        die(1, "not JSON: %s" % e)
    if doc.get("bomFormat") != "CycloneDX" or not isinstance(doc.get("components"), list):
        die(1, "not a CycloneDX SBOM with components")
    doc.pop("serialNumber", None)
    # The generator stamps the wall clock; a reproducible SBOM carries the commit time instead.
    if isinstance(doc.get("metadata"), dict) and "timestamp" in doc["metadata"]:
        doc["metadata"]["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))
    text = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if src_dir in text:
        die(1, "the build directory is still named in the SBOM")
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)


def cmd_sums(args):
    if len(args) != 1:
        die(2, "usage: sums DIR")
    d = args[0]
    names = sorted(n for n in os.listdir(d)
                   if n != "SHA256SUMS" and os.path.isfile(os.path.join(d, n))
                   and not os.path.islink(os.path.join(d, n)))
    if not names:
        die(1, "no files to sum in %s" % d)
    for n in names:
        if not NAME.fullmatch(n) or "/" in n:
            die(1, "file name not allowed in SHA256SUMS: %r" % n)
    with open(os.path.join(d, "SHA256SUMS"), "w", encoding="ascii") as f:
        for n in names:
            f.write("%s  %s\n" % (sha256(os.path.join(d, n)), n))


def main(argv):
    if len(argv) < 2 or argv[1] not in ("tar", "sbom", "sums"):
        die(2, "usage: release-pack.py tar|sbom|sums ...")
    {"tar": cmd_tar, "sbom": cmd_sbom, "sums": cmd_sums}[argv[1]](argv[2:])


if __name__ == "__main__":
    main(sys.argv)
