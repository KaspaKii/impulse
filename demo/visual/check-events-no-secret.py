#!/usr/bin/env python3
# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
"""demo/visual/check-events-no-secret.py <events.jsonl> <secret-file>...

Exits 1 if the events file contains the bytes of any given secret file (as the file holds them, as
the raw bytes, as hex of either case, or as base64), 0 if it does not. A file that is missing is
skipped; one that is empty or shorter than 8 bytes is an error, so the check cannot pass on nothing.
This reads the secret only to look for it: it prints no byte of it.
"""
import base64
import binascii
import sys


def main(argv):
    if len(argv) < 3:
        sys.exit("usage: check-events-no-secret.py <events.jsonl> <secret-file>...")
    events = open(argv[1], "rb").read()
    if not events.strip():
        sys.exit("check-events-no-secret: the events file is empty")
    checked = 0
    for path in argv[2:]:
        try:
            raw = open(path, "rb").read()
        except FileNotFoundError:
            continue
        text = raw.strip()
        forms = {text, raw}
        try:
            decoded = binascii.unhexlify(text)  # a hex file: the bytes it spells
            forms.add(decoded)
        except (binascii.Error, ValueError):
            decoded = text
        for b in (text, decoded):
            forms.add(binascii.hexlify(b))
            forms.add(binascii.hexlify(b).upper())
            forms.add(base64.b64encode(b))
            forms.add(base64.urlsafe_b64encode(b))
        if len(text) < 8:
            sys.exit(f"check-events-no-secret: {path} is too short to check against")
        for f in forms:
            if len(f) >= 8 and f in events:
                sys.exit("check-events-no-secret: FAIL: the events file contains secret material")
        checked += 1
    if checked == 0:
        sys.exit("check-events-no-secret: no secret file was found to check against")
    print(f"check-events-no-secret: ok ({checked} secret file(s) checked, none found in {len(events)} bytes of events)")


main(sys.argv)
