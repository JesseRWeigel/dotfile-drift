#!/usr/bin/env python3
"""Check the README, which is a claim like any other.

Twelve verify scripts in this fleet pass without ever looking at their README,
which means a project can report a screen of green checks while the README still
says "TODO: replace with a real description". This closes that gap.

THE FENCED-BLOCK RULE. The Status section holds the pasted transcript of the
verify run, so a naive scaffold-marker search matches its own output: the string
`TODO` appears inside the sentence "no TODO left in it", and the transcript of
this very check would contain every marker it looks for. Four separate checks in
this fleet did exactly that in one day.

The fix is to strip fenced code blocks before searching the prose, never to add
an exclusion for the file or the line. An exclusion disarms the check precisely
where it is being tested. Fences are stripped, prose is searched, and the Status
transcript is then examined separately for the things it must contain.

Usage: check_readme.py [path/to/README.md]
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)

# Case matters for some of these and not for others, so each carries its own
# flag. The lowercase `0 todo` came from a test runner's summary line.
SCAFFOLD_MARKERS = [
    ("TODO", True), ("FIXME", True), ("XXX", True),
    ("TBD", True), ("<one line description>", False),
    ("replace with a real", False), ("NOT YET VERIFIED", True),
    ("lorem ipsum", False), ("PLACEHOLDER", True),
]

FENCE_RX = re.compile(r"^\s*(```|~~~)")

# The line verify.sh prints on success. The Status section has to contain it, so
# a README cannot claim a pass that was never observed.
SUCCESS_RX = re.compile(r"^VERIFY PASSED: (\d+)/\1 checks$", re.M)


def split_fences(text: str):
    """Return (prose, fenced). Lines inside ``` blocks go to `fenced`."""
    prose, fenced = [], []
    in_fence = False
    marker = None
    for line in text.split("\n"):
        m = FENCE_RX.match(line)
        if m and not in_fence:
            in_fence, marker = True, m.group(1)
            fenced.append(line)
            continue
        if m and in_fence and m.group(1) == marker:
            in_fence = False
            fenced.append(line)
            continue
        (fenced if in_fence else prose).append(line)
    if in_fence:
        # An unclosed fence would silently swallow the rest of the file, which is
        # the same fail-open shape the tool itself refuses for local fences.
        raise SystemExit("README has an unclosed code fence, so the prose check "
                         "would silently skip everything after it")
    return "\n".join(prose), "\n".join(fenced)


def main(argv):
    path = argv[0] if argv else os.path.join(PROJECT, "README.md")
    if not os.path.isfile(path):
        print("FAIL %s does not exist" % path)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    prose, fenced = split_fences(text)
    problems = []

    # Deliberately not printing line counts. The Status section holds this
    # script's own transcript, so any number that grows when the transcript is
    # pasted makes the README impossible to bring to a fixed point.
    print("  prose and fenced blocks separated")

    if fenced.strip() == "":
        problems.append("no fenced code block at all. The Status section is "
                        "supposed to hold a pasted transcript, and its absence "
                        "means this check has nothing to verify against.")

    for marker, cased in SCAFFOLD_MARKERS:
        hay = prose if cased else prose.lower()
        needle = marker if cased else marker.lower()
        if needle in hay:
            for i, line in enumerate(prose.split("\n"), 1):
                probe = line if cased else line.lower()
                if needle in probe:
                    problems.append("scaffold marker %r in prose at line %d: %s"
                                    % (marker, i, line.strip()[:70]))

    for heading in ("## What this is", "## Status"):
        if heading not in text:
            problems.append("missing section %r" % heading)

    body = text.split("## Status", 1)[1] if "## Status" in text else ""
    m = SUCCESS_RX.search(body)
    if not m:
        problems.append("the Status section does not contain verify.sh's own success "
                        "line, which has the shape 'VERIFY PASSED: N/N checks'. "
                        "Paste the real output rather than describing it.")
    else:
        print("  Status carries a real success line: %d of %d checks"
              % (int(m.group(1)), int(m.group(1))))

    # The transcript must show the steps actually running, not just the verdict.
    for needed in ("=== unit tests ===", "=== privacy scan ===", "=== sabotage ===",
                   "=== tree not modified ==="):
        if needed not in body:
            problems.append("the Status transcript does not show %r, so it is not "
                            "the output of a full run" % needed)

    if "```" not in body:
        problems.append("the Status output is not inside a fenced block")

    for section in ("## Unfinished", "## How it decides"):
        if section not in text:
            problems.append("missing section %r" % section)

    if problems:
        for p in problems:
            print("  FAIL %s" % p)
        print("README CHECK FAILED with %d problem(s)" % len(problems))
        return 1
    print("  README has every required section, no scaffold markers in prose, and a "
          "real transcript")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
