#!/usr/bin/env python3
"""Generate docs/index.html from the synthetic fixture home.

The published page is derived, never hand-edited. `scripts/verify.sh` runs this
into a temporary file and diffs against the tracked copy, so a stale page is a
verify failure rather than something a reader discovers months later.

Determinism matters for that diff to mean anything. Three sources of variance are
removed here:

  * the fixture materialiser seeds every generated credential from the path, so
    the same bytes come out on every run,
  * the baseline timestamp is a constant in `fixture_home.py` rather than the
    clock,
  * the home and repo roots are a temporary directory, so they are replaced with
    fixed labels through `--home-label` and `--repo-label`. Without that the page
    would carry a real absolute path from whichever machine built it.

Usage: build_docs.py [output.html] [--check]

`--check` writes nothing and exits 1 when the tracked page is out of date.
"""

import argparse
import difflib
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
DEFAULT_OUT = os.path.join(PROJECT, "docs", "index.html")

HOME_LABEL = "<synthetic fixture home>"
REPO_LABEL = "<synthetic fixture dotfiles repo>"


def _load_fixture_builder():
    spec = importlib.util.spec_from_file_location(
        "fixture_home_docs", os.path.join(HERE, "fixture_home.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def render() -> str:
    """Materialise the fixture home and return the report page as text."""
    builder = _load_fixture_builder()
    with tempfile.TemporaryDirectory(prefix="dotdrift-docs-") as tmp:
        paths = builder.materialize(os.path.join(tmp, "tree"))
        out = os.path.join(tmp, "page.html")
        proc = subprocess.run(
            [sys.executable, os.path.join(PROJECT, "bin", "dotdrift"), "html",
             "--home", paths["home"], "--repo", paths["repo"], "--state", paths["state"],
             "--quote", "--home-label", HOME_LABEL, "--repo-label", REPO_LABEL,
             "-o", out],
            capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            raise SystemExit("dotdrift html failed (exit %d):\n%s"
                             % (proc.returncode, proc.stderr))
        with open(out, "r", encoding="utf-8") as fh:
            page = fh.read()

    # A page that carries the build machine's temporary directory would differ on
    # every run and would also leak a real path. Refuse rather than publish it.
    for bad in (tmp, os.path.expanduser("~"), "/tmp/"):
        if bad and bad in page:
            raise SystemExit("the generated page contains the build path %r. The label "
                             "overrides did not cover every place a root is printed." % bad)
    return page


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", nargs="?", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true",
                    help="compare against the tracked page and exit 1 if it is stale")
    args = ap.parse_args(argv)

    page = render()

    if args.check:
        if not os.path.isfile(args.output):
            print("FAIL %s does not exist. Run scripts/build_docs.py."
                  % os.path.relpath(args.output, PROJECT))
            return 1
        with open(args.output, "r", encoding="utf-8") as fh:
            have = fh.read()
        if have != page:
            diff = list(difflib.unified_diff(
                have.splitlines(), page.splitlines(),
                fromfile="tracked", tofile="regenerated", lineterm=""))
            print("FAIL %s is stale, %d differing diff lines. Run scripts/build_docs.py."
                  % (os.path.relpath(args.output, PROJECT), len(diff)))
            for line in diff[:40]:
                print("  " + line)
            return 1
        print("ok, %s matches a fresh build (%d bytes)"
              % (os.path.relpath(args.output, PROJECT), len(page)))
        return 0

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(page)
    print("wrote %d bytes to %s" % (len(page), os.path.relpath(args.output, PROJECT)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
