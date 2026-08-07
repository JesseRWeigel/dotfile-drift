#!/usr/bin/env python3
"""Materialise the synthetic fixture home into a temporary directory.

Why this exists rather than committing a ready-made home directory:

  * git records one permission bit. The mode drift scenario needs 0600 versus
    0644, which git cannot carry.
  * git can carry symlinks, but a checkout on a filesystem without symlink
    support turns them into text files and the symlink scenarios would then pass
    for the wrong reason.
  * credential-shaped fixtures must not exist in complete form on disk. GitHub
    push protection scans full history and a synthetic token that matches a real
    pattern blocks the push permanently. The tracked files hold `{FILL:36}`
    templates which this script expands deterministically at runtime.

This script imports nothing from `dotdrift`. It is shared input, not shared
derivation, so `scripts/check_independent.py` may use it without becoming a
second copy of the thing it is checking.

Usage: fixture_home.py <outdir> [--print-json]
"""

import hashlib
import json
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(os.path.dirname(HERE), "fixtures")

# A fixed timestamp keeps every derived artefact byte-identical between runs, so
# `verify.sh` can rebuild docs/index.html and diff it.
SYNCED_AT = "2026-02-14T09:30:00Z"

ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
B64 = ALNUM + "+/"

TEMPLATE_RX = re.compile(r"\{(FILL|FILLB64):(\d+)\}")

# The armour band of a PEM block is itself a credential pattern. GitHub push
# protection matches it, and so does `scripts/privacy_scan.py`, which is scanning
# this repository's own tracked files. The fixture private key therefore stores
# the bands as templates for the same reason it stores the body as `{FILLB64:64}`:
# no complete pattern exists on disk, and the exemption that would otherwise be
# needed does not exist to be abused later.
BAND_RX = re.compile(r"\{PEM(BEGIN|END):([A-Z ]{1,24})\}")


def expand_bands(text: str) -> str:
    return BAND_RX.sub(
        lambda m: "-" * 5 + m.group(1) + " " + m.group(2) + " PRIVATE KEY" + "-" * 5,
        text)

DIR_MODES = {".ssh": 0o700, ".gnupg": 0o700}


def _stream(seed: str):
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    while True:
        for b in h:
            yield b
        h = hashlib.sha256(h).digest()


def expand(text: str, rel: str) -> str:
    """Replace {FILL:n} / {FILLB64:n} deterministically from the path and index."""
    idx = [0]

    def sub(m):
        kind, n = m.group(1), int(m.group(2))
        charset = B64 if kind == "FILLB64" else ALNUM
        gen = _stream("%s|%d|%s" % (rel, idx[0], kind))
        idx[0] += 1
        return "".join(charset[next(gen) % len(charset)] for _ in range(n))

    return TEMPLATE_RX.sub(sub, text)


def read_expanded(tree: str, rel: str):
    """Return the expanded bytes of fixtures/<tree>/home/<rel>, or None."""
    p = os.path.join(FIXTURES, tree, "home", rel)
    if not os.path.isfile(p):
        return None
    with open(p, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    if "{FILL" not in text and "{PEM" not in text:
        return raw
    # Expansion works on text, and the fixture with CRLF endings has no
    # templates, so no line ending is disturbed here.
    return expand_bands(expand(text, rel)).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_scenario():
    with open(os.path.join(FIXTURES, "scenario.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _copy_tree(tree: str, dest: str):
    src = os.path.join(FIXTURES, tree, "home")
    for dirpath, _dirnames, filenames in os.walk(src):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src)
            out = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            data = read_expanded(tree, rel.replace(os.sep, "/"))
            with open(out, "wb") as fh:
                fh.write(data)
            os.chmod(out, 0o644)


def materialize(outdir: str) -> dict:
    outdir = os.path.abspath(outdir)
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    home = os.path.join(outdir, "home")
    repo = os.path.join(outdir, "repo")
    state = os.path.join(outdir, "state")
    outside = os.path.join(outdir, "outside")
    for d in (home, repo, state, outside):
        os.makedirs(d, exist_ok=True)

    _copy_tree("home", home)
    _copy_tree("repo", os.path.join(repo, "home"))
    shutil.copy2(os.path.join(FIXTURES, "repo", "dotdrift.json"),
                 os.path.join(repo, "dotdrift.json"))
    for name in sorted(os.listdir(os.path.join(FIXTURES, "outside"))):
        shutil.copy2(os.path.join(FIXTURES, "outside", name), os.path.join(outside, name))

    scenario = load_scenario()
    entries = {}
    for rel, spec in sorted(scenario["paths"].items()):
        hspec = spec.get("home", {})
        target = os.path.join(home, rel)

        if hspec.get("kind") == "absent":
            if os.path.lexists(target):
                os.remove(target)
        elif hspec.get("kind") == "symlink":
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.lexists(target):
                os.remove(target)
            os.symlink(hspec["target"], target)
        elif hspec.get("kind") == "file":
            if not os.path.isfile(target):
                raise SystemExit("scenario expects fixtures/home/home/%s to exist" % rel)
            os.chmod(target, int(hspec.get("mode", "0644"), 8))

        bspec = spec.get("base", {})
        src = bspec.get("from", "none")
        if src == "none":
            continue
        data = read_expanded(src, rel)
        if data is None:
            raise SystemExit("scenario baseline for %s points at fixtures/%s/home/%s "
                             "which does not exist" % (rel, src, rel))
        entry = {"kind": bspec.get("kind", "file"), "raw": sha256_hex(data)}
        if bspec.get("mode"):
            entry["mode"] = bspec["mode"]
        if bspec.get("target"):
            entry["target"] = bspec["target"]
        entries[rel] = entry

    for d, mode in DIR_MODES.items():
        p = os.path.join(home, d)
        if os.path.isdir(p):
            os.chmod(p, mode)

    manifest = {
        "version": 1,
        "synced_at": SYNCED_AT,
        "home": "<fixture home>",
        "repo": "<fixture repo>",
        "entries": dict(sorted(entries.items())),
    }
    with open(os.path.join(state, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    return {"root": outdir, "home": home, "repo": repo, "state": state, "outside": outside,
            "scenario": scenario}


def expectations(scenario, key="expect"):
    """(path, status) pairs the detector must produce, from the hand-written spec."""
    out = []
    for rel, spec in sorted(scenario["paths"].items()):
        for status in spec.get(key, spec.get("expect", [])):
            out.append((rel, status))
    return sorted(out)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    out = materialize(argv[0])
    if "--print-json" in argv:
        print(json.dumps({k: v for k, v in out.items() if k != "scenario"}, indent=2))
    else:
        print("fixture home materialised at %s" % out["root"])
        print("  home    %d entries" % len(os.listdir(out["home"])))
        print("  repo    %s" % os.path.basename(out["repo"]))
        print("  state   manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
