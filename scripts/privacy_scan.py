#!/usr/bin/env python3
"""Scan every tracked file for credentials and for real paths from this machine.

This project reads dotfiles, which is where credentials live, so the standing
risk is that something derived from a real home directory ends up committed. The
scan enforces two rules over `git ls-files`:

  1. no credential-shaped string,
  2. no path belonging to this machine, meaning the real home directory, the real
     username, or any absolute path under /home, /Users or /root.

Four design decisions, each one paid for by a failure recorded in AGENTS.md.

**Patterns are assembled from fragments.** A literal token pattern written out in
this file would be found by this file. That self-match has been hit repeatedly in
this workspace, once inside a comment that existed to explain the fix. Joining
fragments at runtime means no complete pattern exists on disk, so no exclusion is
needed and the scan stays armed over its own source.

**No file is ever exempted.** An exclusion disarms the check exactly where it is
tested. `scripts/sabotage.py` and this file both mention credential formats, and
both are scanned like everything else.

**Files are read as bytes in Python, never through grep.** One NUL byte makes git
and grep classify a file as binary, and `grep -I` then skips it silently. A real
token was committed inside such a file here and the scan reported clean.

**The positive control plants a credential in a temporary tree and runs the same
directory-walking code over it.** A scanner that reads nothing is silent in the
same way as a clean tree, so a scan that reports zero findings has proved nothing
until the planted one has been found by the same route.

Usage: privacy_scan.py [--verbose]
"""

import getpass
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)

# Below this, `git ls-files` is telling us the tree is empty rather than clean.
# Before the first commit it returns nothing at all and the scan would pass
# without opening a single file.
MIN_TRACKED_FILES = 20

# --- credential patterns, assembled so this file does not match itself --------
_A = "A" + "K" + "IA"
_GH = "gh" + "[opsu]_"
_NPM = "np" + "m_"
_ANT = "sk-" + "ant" + "-api"
_OR = "sk-" + "or-" + "v1-"
_OAI = "sk-" + "proj-"
_XOX = "xox" + "[abprs]" + "-"
_AIZA = "AI" + "za" + "Sy"
_PEM = "-----" + "BEGIN" + "[ A-Z]{0,24}PRIVATE KEY" + "-----"
_HOOK = "hooks\\." + "slack" + "\\.com/services/"
_B64 = "[A-Za-z0-9/+=]"

# Case-sensitive on purpose. AWS key ids are uppercase by definition, and a
# case-insensitive form matched ordinary base64 inside an inline PNG here.
CREDENTIAL_PATTERNS = [
    ("aws-access-key-id", re.compile(_A + "[0-9A-Z]{16}")),
    ("github-token", re.compile(_GH + "[A-Za-z0-9]{36,}")),
    ("npm-token", re.compile(_NPM + "[A-Za-z0-9]{36,}")),
    ("anthropic-key", re.compile(_ANT + "[A-Za-z0-9_-]{16,}")),
    ("openrouter-key", re.compile(_OR + "[a-f0-9]{32,}")),
    ("openai-key", re.compile(_OAI + "[A-Za-z0-9_-]{20,}")),
    ("slack-token", re.compile(_XOX + "[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(_AIZA + "[A-Za-z0-9_-]{33}")),
    ("private-key-block", re.compile(_PEM)),
    ("slack-webhook", re.compile(_HOOK + "[A-Za-z0-9/]{10,}")),
    ("jwt", re.compile("eyJ" + _B64 + "{10,}\\." + "eyJ" + _B64 + "{10,}\\." + _B64 + "{10,}")),
    ("basic-auth-url", re.compile("://[^/\\s:@]{1,64}:[^/\\s@]{6,}@")),
]


def machine_path_patterns():
    """Patterns for paths that belong to whoever is running this.

    The template placeholders in `fixtures/` are why the fixture tree can carry a
    file called `.ssh/id_ed25519` without carrying a key. Real paths have no such
    escape hatch: a `/home/<user>` string in a tracked file is private data and it
    is also unportable, which is the reason verify output gets `$HOME` collapsed
    to `~` before it reaches a README.
    """
    # The lookbehind is what makes this a check for ABSOLUTE paths. Without it,
    # the relative fixture path `../repo/home/.zshrc` matches on `/home/.zshrc`
    # and the scan drowns in false alarms from its own test data. An absolute
    # path starts at a boundary: start of line, a quote, whitespace, `=`, or a
    # preceding slash as in `file:///home/...`.
    boundary = "(?<![A-Za-z0-9._~-])"
    pats = [
        ("absolute-home-path",
         re.compile(boundary + "/(?:home|Users)/[A-Za-z0-9._-]{2,32}(?=[/\"'\\s:,)\\]]|$)")),
        ("root-home-path", re.compile(boundary + "/root/[A-Za-z0-9._-]")),
    ]
    user = None
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no controlling terminal, no passwd entry
        user = None
    if user and len(user) >= 3:
        # ONLY in a path-shaped context. A bare match on the username fails wherever the username
        # is an ordinary word: on GitHub's runners it is `runner`, which appears legitimately in
        # "the node test runner" and flagged three files that leak nothing. What is private is a
        # path that identifies the machine, not the word.
        u = re.escape(user)
        pats.append(("this-machine-username", re.compile(
            r"(?:/home/|/Users/|/var/home/|\\Users\\|~)" + u + r"(?![\w.-])"
            r"|(?<![\w.-])" + u + r"@[\w.-]+")))
    home = os.path.expanduser("~")
    if home and home not in ("/", "~") and len(home) >= 4:
        pats.append(("this-machine-home", re.compile(re.escape(home))))
    return pats


def scan_bytes(data: bytes, patterns):
    """Findings in one blob. Bytes in, so a NUL cannot make us skip anything."""
    text = data.decode("utf-8", "replace")
    out = []
    for lineno, line in enumerate(text.split("\n"), 1):
        for label, rx in patterns:
            m = rx.search(line)
            if m:
                hit = m.group(0)
                shown = hit[:6] + "..." + str(len(hit)) + " chars" if len(hit) > 12 else hit
                out.append((lineno, label, shown))
    return out


def scan_files(paths, patterns, root):
    """Findings across a list of files. This is the routine the positive control
    exercises, so a bug that stops files being opened fails the control too."""
    findings = []
    read = 0
    nul_files = 0
    for rel in paths:
        full = os.path.join(root, rel)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        with open(full, "rb") as fh:
            data = fh.read()
        read += 1
        if b"\x00" in data:
            nul_files += 1
        for lineno, label, hit in scan_bytes(data, patterns):
            findings.append((rel, lineno, label, hit))
    return findings, read, nul_files


def tracked_files():
    proc = subprocess.run(["git", "-C", PROJECT, "ls-files", "-z"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise SystemExit("git ls-files failed: %s" % proc.stderr.strip())
    return [p for p in proc.stdout.split("\0") if p]


def positive_control(patterns, verbose=False):
    """Plant credentials in a temporary tree and require the scan to find them.

    Each planted value is assembled here from fragments, for the same reason the
    patterns are: a complete synthetic token written into this file would trip
    GitHub push protection, which scans full history and cannot be undone by a
    later fix.

    One plant sits behind a NUL byte. That is the case a grep-based scan silently
    skips, so a control that only used plain text would pass on a scanner blind to
    the exact file shape that caused a real leak here.
    """
    plants = [
        ("plain.txt", ("aws_access_key_id = " + "A" + "K" + "IA" + "Q7" + "R3M2" + "XKLP9" + "WD4T2Z").encode()),
        ("nul-inside.bin", b"typeflag\x00marker\n" + ("token=" + "gh" + "p_" + "b" * 36).encode()),
        ("nested/deep.cfg", ("home = /home/" + "someoneelse" + "/dotfiles").encode()),
        ("pem.txt", ("-" * 5 + "BEGIN" + " OPENSSH PRIVATE KEY" + "-" * 5).encode()),
        # The absolute-home pattern carries a lookbehind so that a RELATIVE path
        # containing the word `home` does not match. That relaxation needs its own
        # control, otherwise a later edit could widen the lookbehind until the
        # pattern never fires and every run would still look green.
        ("boundaries.txt", ("/home/" + "atlinestart" + "/x\n"
                            "\"/home/" + "inquotes" + "\"\n"
                            "file:///home/" + "afterslashes" + "/y\n").encode()),
    ]
    # Lines that must NOT match. Relative fixture paths are full of `/home/`.
    negatives = [
        "../repo/home/.zshrc",
        "fixtures/home/home/.aws/credentials",
        "os.path.join(repo, 'home', rel)",
    ]
    with tempfile.TemporaryDirectory(prefix="dotdrift-poscontrol-") as tmp:
        rels = []
        for rel, data in plants:
            full = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)
            rels.append(rel)
        found, read, nul = scan_files(rels, patterns, tmp)

    problems = []
    if read != len(plants):
        problems.append("the control read %d of %d planted files" % (read, len(plants)))
    if nul != 1:
        problems.append("the control expected exactly one file containing a NUL byte, saw %d" % nul)
    hit_files = {f[0] for f in found}
    for rel, _ in plants:
        if rel not in hit_files:
            problems.append("planted credential in %s was NOT found, the scanner is blind" % rel)
    # The boundary file plants three shapes on three lines and all three must fire.
    boundary_lines = {ln for rel, ln, _, _ in found if rel == "boundaries.txt"}
    if boundary_lines != {1, 2, 3}:
        problems.append("absolute-home boundary control matched lines %s, expected 1, 2 and 3. "
                        "The lookbehind is too wide." % sorted(boundary_lines))
    for line in negatives:
        if scan_bytes(line.encode(), patterns):
            problems.append("relative path %r was flagged as an absolute machine path, which "
                            "would bury real findings in noise" % line)
    if verbose:
        for rel, lineno, label, hit in found:
            print("    control hit %s:%d %s %s" % (rel, lineno, label, hit))
    return problems, len(found), len(negatives)


def main(argv):
    verbose = "--verbose" in argv
    patterns = CREDENTIAL_PATTERNS + machine_path_patterns()
    failures = []

    print("1. positive control: plant credentials and require them to be found")
    problems, n, n_neg = positive_control(patterns, verbose=verbose)
    if problems:
        failures.extend(problems)
        for p in problems:
            print("   FAIL %s" % p)
    else:
        print("   ok, %d planted hits found, one of them behind a NUL byte, and %d "
              "relative paths correctly left alone" % (n, n_neg))

    print("2. tracked files")
    files = tracked_files()
    if len(files) < MIN_TRACKED_FILES:
        failures.append("only %d tracked files, below the floor of %d. An empty index "
                        "makes this scan pass without opening anything."
                        % (len(files), MIN_TRACKED_FILES))
        print("   FAIL %s" % failures[-1])
    else:
        print("   ok, git reports %d tracked files" % len(files))

    print("3. scan for credentials and machine paths")
    found, read, nul = scan_files(files, patterns, PROJECT)
    print("   read %d files (%d containing a NUL byte, scanned anyway)" % (read, nul))
    if found:
        for rel, lineno, label, hit in found:
            failures.append("%s:%d %s %s" % (rel, lineno, label, hit))
            print("   FAIL %s:%d  %s  %s" % (rel, lineno, label, hit))
    else:
        print("   ok, no credential-shaped string and no path from this machine")

    print("4. the scan read its own source and the sabotage script")
    for must in ("scripts/privacy_scan.py", "scripts/sabotage.py"):
        if must not in files:
            failures.append("%s is not tracked, so the scan never opened it" % must)
            print("   FAIL %s is not tracked" % must)
        else:
            print("   ok, %s is tracked and was scanned with no exemption" % must)

    print()
    if failures:
        print("PRIVACY SCAN FAILED with %d problem(s)" % len(failures))
        return 1
    print("PRIVACY SCAN PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
