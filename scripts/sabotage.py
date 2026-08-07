#!/usr/bin/env python3
"""Break the detector on purpose and require the checks to notice.

A verify command that passes on a broken implementation is the default failure
mode, so this harness measures how much of the implementation the suite actually
holds down.

THE THREE-GATE RULE. A sabotage counts only when all three hold:

  gate 1  APPLIES        the patch changed the file. A patch that silently missed
                         is a no-op with a confident write-up attached.
  gate 2  CHANGES OUTPUT the tool's observable behaviour moved. Measured as a
                         fingerprint over the CLI's own report.
  gate 3  CAUGHT         the checks fail.

Only a sabotage that clears all three says anything about the suite.

THE NULL CONTROL RUNS FIRST. Before any patch, an unmodified copy of the tree is
fingerprinted in a second directory and must match the baseline exactly. If it
does not, the measurement is a function of where the code lives rather than of
the code, gate 2 passes for free for every sabotage, and the whole run is void.
That happened in this fleet on 2026-08-06 and invalidated eleven sabotages, the
culprit being an absolute temporary path printed in the output being hashed. This
harness therefore hashes only the report body, with roots replaced by fixed
labels, and runs every command with relative paths from inside the copied tree.

GUARDS INVERT GATE 2. Code that is dormant when the input is correct cannot
change the output when you disable it. The redactor is exactly that: it fires
only on content that is already secret-shaped. For a guard the requirement is the
opposite and stricter, output UNCHANGED and the unit suite FAILS. A "guard" that
does change the output was never a guard and is rerun as a plain attack.

Usage: sabotage.py [--verbose] [--only NAME]
Exit 0 means every sabotage was caught.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)

COPY_EXCLUDE = {".git", "__pycache__", ".pytest_cache", "docs", "dotdrift-capture"}

ATTACK = "attack"
GUARD = "guard"


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------

def copy_tree(dest: str):
    """A working copy of the project, without git or caches."""
    def ignore(_dirpath, names):
        return [n for n in names if n in COPY_EXCLUDE or n.endswith(".pyc")]
    shutil.copytree(PROJECT, dest, ignore=ignore, symlinks=True)
    return dest


def _load_builder(tree: str):
    spec = importlib.util.spec_from_file_location(
        "fixture_home_sab", os.path.join(tree, "scripts", "fixture_home.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# How the observable output is sampled. Each entry is one CLI invocation.
#
# The default samples the tool BOTH ways round. A single `--quote` run cannot see
# a sabotage that removes the `--quote` requirement, because with the flag passed
# the behaviour is identical either way. That is the "corpus too clean" shape from
# AGENTS.md: the no-op was the measurement's fault, not the sabotage's.
MEASURE_DEFAULT = (
    ("quoted", ("--quote",)),
    ("hash-only", ()),
)

# A dormant guard needs input that does NOT wake it. `.config/apprc` carries a
# credential-shaped line on purpose, so any measurement including it makes the
# redactor active and the guard classification meaningless. These three paths are
# quotable and clean, which is what "normal output" means for a redactor.
MEASURE_NO_SECRETS = (
    ("quoted-clean-subset",
     ("--quote", "--only", ".config/blockrc", "--only", ".tmux.conf", "--only", ".gitconfig")),
)


def _one_run(tree, paths, extra):
    """Run the CLI once and return the text that will be hashed."""
    proc = subprocess.run(
        [sys.executable, os.path.join("bin", "dotdrift"), "check",
         "--home", os.path.relpath(paths["home"], tree),
         "--repo", os.path.relpath(paths["repo"], tree),
         "--state", os.path.relpath(paths["state"], tree),
         "--json"] + extra,
        capture_output=True, text=True, cwd=tree, timeout=180)

    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        return "CRASH exit=%d\n%s" % (proc.returncode, proc.stderr.strip()[-2000:]), None

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return "UNPARSEABLE %s\n%s" % (exc, proc.stdout[:2000]), None

    data["home"] = "<home>"
    data["repo"] = "<repo>"
    # The exit code is observable output and belongs in the hash. Without it a
    # sabotage that makes `check` always exit 0, so a cron hook reports a clean
    # machine forever, scores as a no-op while being the worst bug in the tool.
    body = "exit %d\n" % proc.returncode + json.dumps(data, indent=2, sort_keys=True)
    return body, data


def fingerprint(tree: str, workdir: str, measure=MEASURE_DEFAULT):
    """Hash the tool's report over the fixture home.

    Two rules keep this a function of the CODE and not of the DIRECTORY:

      * the fixture home is built inside `workdir`, and every absolute path in
        the output is rewritten to a fixed label before hashing,
      * the CLI is invoked with paths relative to `tree`, with `tree` as cwd.

    Returns (digest, summary_text). A crash is itself an observable outcome and
    gets a digest of its own, because a sabotage that makes the tool explode has
    certainly changed the output.
    """
    builder = _load_builder(tree)
    paths = builder.materialize(os.path.join(workdir, "fx"))

    chunks = []
    notes = []
    for label, extra in measure:
        body, data = _one_run(tree, paths, list(extra))
        chunks.append("### %s\n%s" % (label, body))
        if data is None:
            notes.append("%s=%s" % (label, body.split("\n", 1)[0]))
        else:
            notes.append("%s findings=%d ignored=%d"
                         % (label, len(data["findings"]), len(data["ignored"])))

    text = "\n".join(chunks)
    # Scrub every path that could vary between runs. The 2026-08-06 incident was
    # exactly this: a per-run temporary directory inside the hashed text.
    for varying in (workdir, tree, os.path.realpath(workdir), os.path.realpath(tree),
                    tempfile.gettempdir(), PROJECT):
        text = text.replace(varying, "<scrubbed>")

    summary = "  ".join(notes)
    if "CRASH" in text:
        summary = "CRASH " + summary
    return hashlib.sha256(text.encode()).hexdigest()[:16], summary


def run_units(tree: str):
    """The unit suite, as verify.sh runs it. Returns (passed, tail)."""
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", ".", "-t", "."],
        capture_output=True, text=True, cwd=os.path.join(tree, "tests"), timeout=600)
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip().splitlines()[-1:]


def run_independent(tree: str):
    proc = subprocess.run(
        [sys.executable, os.path.join("scripts", "check_independent.py")],
        capture_output=True, text=True, cwd=tree, timeout=600)
    return proc.returncode == 0


def run_docs_check(tree: str):
    """docs/ is excluded from the copy, so this rebuilds against the tracked page."""
    proc = subprocess.run(
        [sys.executable, os.path.join(tree, "scripts", "build_docs.py"),
         os.path.join(PROJECT, "docs", "index.html"), "--check"],
        capture_output=True, text=True, cwd=tree, timeout=300)
    return proc.returncode == 0


# --------------------------------------------------------------------------
# The patches
# --------------------------------------------------------------------------

def patch(rel, old, new, count=1):
    """A textual substitution. Returns a function that reports whether it applied."""
    def apply(tree):
        full = os.path.join(tree, rel)
        with open(full, "r", encoding="utf-8") as fh:
            src = fh.read()
        if src.count(old) < count:
            return False, "anchor %r appears %d times in %s, needed %d" % (
                old[:60], src.count(old), rel, count)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(src.replace(old, new, count))
        return True, "patched %s" % rel
    return apply


SABOTAGES = [
    # ---- the three-way logic, which is the point of the tool ----------------
    dict(name="direction-flip", kind=ATTACK,
         why="Swap local_edit and upstream_change. The tool still reports drift on "
             "the same paths and still exits 1, but every safe action is now the "
             "one that destroys the newer side.",
         apply=patch("dotdrift/compare.py",
                     '    if home_changed and not repo_changed:\n        return "local_edit"\n'
                     '    if repo_changed and not home_changed:\n        return "upstream_change"\n',
                     '    if home_changed and not repo_changed:\n        return "upstream_change"\n'
                     '    if repo_changed and not home_changed:\n        return "local_edit"\n')),

    dict(name="ignore-the-baseline", kind=ATTACK,
         why="Collapse the three-way comparison to two-way by treating every "
             "difference as unsynced. This is the bug the whole project exists to "
             "avoid, and a two-way test suite would not notice it.",
         apply=patch("dotdrift/compare.py",
                     "    if base_raw is None:\n",
                     "    if True:\n")),

    dict(name="conflict-becomes-local-edit", kind=ATTACK,
         why="Report a genuine divergence as a plain local edit, so the advice "
             "becomes `capture` and the upstream change is silently discarded.",
         apply=patch("dotdrift/compare.py",
                     '        # Both moved. If they had converged we would have returned above.\n'
                     '        return "conflict"\n',
                     '        return "local_edit"\n')),

    # ---- shape and permissions, invisible to a content diff -----------------
    dict(name="symlink-blindness", kind=ATTACK,
         why="Stop noticing that a symlink became a regular file. Content still "
             "matches so a content-only comparison calls the machine clean, which "
             "is the common state after an installer runs.",
         apply=patch("dotdrift/compare.py",
                     "    if base_kind == safeio.KIND_SYMLINK and obs.home.kind == safeio.KIND_FILE:",
                     "    if False and base_kind == safeio.KIND_SYMLINK and obs.home.kind == safeio.KIND_FILE:")),

    dict(name="mode-blindness", kind=ATTACK,
         why="Ignore permission drift. `.ssh/config` at 0644 has identical bytes "
             "and a broken ssh.",
         apply=patch("dotdrift/compare.py",
                     "    if base_mode is not None and obs.home.mode is not None and base_mode != obs.home.mode:",
                     "    if False:")),

    dict(name="insecure-mode-blindness", kind=ATTACK,
         why="Drop the standalone permission policy, so a world-readable private "
             "key stops being a finding in its own right.",
         apply=patch("dotdrift/compare.py",
                     "    if mask is not None and obs.home.mode is not None and (obs.home.mode & mask):",
                     "    if False:")),

    # ---- privacy ------------------------------------------------------------
    dict(name="denylist-disabled", kind=ATTACK,
         why="Let `quotable` override the denylist. The fixture lists .npmrc as "
             "quotable precisely to prove the denylist wins, so this prints a "
             "registry token into the report.",
         apply=patch("dotdrift/policy.py",
                     "        denied = self.deny_reason(rel)\n        if denied:\n",
                     "        denied = None\n        if denied:\n")),

    dict(name="quote-without-the-flag", kind=ATTACK,
         why="Quote content even when --quote was not passed. Hash-only is the "
             "default posture and this removes it.",
         apply=patch("dotdrift/compare.py",
                     '    if not opts.quote:\n        return {"shown": False, '
                     '"reason": "content quoting not requested (pass --quote)"}\n',
                     "")),

    dict(name="fence-contents-leak", kind=ATTACK,
         why="Diff the raw bytes instead of the canonical form, so anything inside "
             "a machine-local fence gets printed rather than the placeholder.",
         apply=patch("dotdrift/compare.py",
                     '    a = obs.repo_canon.data.decode("utf-8", "replace").split("\\n")\n'
                     '    b = obs.home_canon.data.decode("utf-8", "replace").split("\\n")\n',
                     '    a = obs.repo.data.decode("utf-8", "replace").split("\\n")\n'
                     '    b = obs.home.data.decode("utf-8", "replace").split("\\n")\n')),

    dict(name="follow-the-escaping-symlink", kind=ATTACK,
         why="Read a symlink whose target resolves outside the home and repo "
             "roots. The fixture points one at a file carrying a marker string, "
             "and the independent check greps the report for that marker.",
         apply=patch("dotdrift/safeio.py",
                     "        if not contained_in_any(allowed_roots, resolved):",
                     "        if False:")),

    # These two are guards: they are dormant unless a symlink actually sits at a
    # middle component, which the drifted fixture does not contain, so the report
    # is unchanged and the unit suite carries them. Both were real holes found by
    # probing rather than by reading, and both had a test nearby that passed
    # because it exercised the `contained` helper instead of its caller.
    dict(name="middle-symlink-read", kind=GUARD,
         why="Drop the parent-directory containment check in read_entry. lstat "
             "declines to follow only the FINAL component, so with ~/.config "
             "symlinked elsewhere the tool reads and hashes a file from outside "
             "the tracked tree and calls it an ordinary dotfile.",
         apply=patch("dotdrift/safeio.py",
                     "    if not contained_in_any(allowed_roots, parent):\n"
                     "        e.kind = KIND_OTHER\n"
                     "        e.unreadable = UNREADABLE_ESCAPES\n"
                     "        return e\n",
                     "    if False:\n        pass\n")),

    dict(name="write-outside-the-home", kind=GUARD,
         why="Drop the containment check on apply's destination. The tool takes "
             "care never to READ outside the tracked tree and would then WRITE "
             "outside it, which is the worse direction of the two.",
         apply=patch("dotdrift/actions.py",
                     "        if not safeio.contained(home_root, parent):",
                     "        if False:")),

    # ---- normalisation ------------------------------------------------------
    # The first anchor tried here was the `normalize: bool = True` DEFAULT in the
    # signature, and it scored as a no-op. The default is never consulted: every
    # caller passes the value as a keyword. That is the AGENTS.md trap of setting
    # something the code path under test does not read. The fix was a better
    # anchor, not a weaker check.
    dict(name="eol-noise-becomes-drift", kind=ATTACK,
         why="Stop normalising line endings, so a CRLF checkout reports every file "
             "as drifted and the report becomes noise nobody reads.",
         apply=patch("dotdrift/normalize.py",
                     "    if normalize:\n        work = normalize_eol(work)\n",
                     "    if False:\n        work = normalize_eol(work)\n")),

    dict(name="fence-swallows-the-file", kind=ATTACK,
         why="Treat an unterminated fence as if it closed at EOF. The rest of the "
             "file then vanishes from the comparison and real drift below a typo "
             "in a marker goes unreported.",
         apply=patch("dotdrift/normalize.py",
                     "    if depth != 0:\n",
                     "    if False:\n")),

    # ---- reporting ----------------------------------------------------------
    dict(name="drift-never-exits-nonzero", kind=ATTACK,
         why="Make `check` always exit 0. A cron hook then reports a clean machine "
             "forever, which is the silent-failure shape that matters most here.",
         apply=patch("dotdrift/compare.py",
                     'return any(f.severity in ("high", "warn") for f in self.findings)',
                     "return False")),

    dict(name="untracked-scan-off", kind=ATTACK,
         why="Stop listing tracked directories, so a file an installer dropped next "
             "to your config is never mentioned.",
         apply=patch("dotdrift/compare.py",
                     "    if opts.untracked:\n",
                     "    if False:\n")),

    # ---- the guard ----------------------------------------------------------
    # Dormant on correct input, so gate 2 is INVERTED: output must NOT move and
    # the unit suite must fail. See the module docstring.
    dict(name="redactor-disabled", kind=GUARD,
         why="Turn the redactor into a pass-through. It is the last line before a "
             "secret reaches the page, and it only fires on content that is "
             "already secret-shaped, so disabling it cannot change the output of a "
             "run whose quoted files are clean. The fixture deliberately plants a "
             "credential-shaped line in a quotable file, so the unit suite must "
             "fail even though the shape of the report is unchanged.",
         measure=MEASURE_NO_SECRETS,
         apply=patch("dotdrift/redact.py",
                     "def redact_line(line: str):",
                     "def redact_line(line: str):\n    return line, []\n\n\ndef _unused(line: str):")),
]


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------

def score_one(sab, baselines, verbose=False):
    with tempfile.TemporaryDirectory(prefix="dotdrift-sab-") as tmp:
        tree = copy_tree(os.path.join(tmp, "tree"))
        work = os.path.join(tmp, "work")
        os.makedirs(work)

        applied, note = sab["apply"](tree)
        if not applied:
            return dict(name=sab["name"], kind=sab["kind"], gate1=False, gate2=None,
                        gate3=None, verdict="NO-OP", note=note)

        measure = sab.get("measure", MEASURE_DEFAULT)
        digest, summary = fingerprint(tree, work, measure)
        moved = digest != baselines[measure]

        units_pass, units_tail = run_units(tree)
        indep_pass = run_independent(tree)
        docs_pass = run_docs_check(tree)
        caught_by = [n for n, ok in
                     (("unit suite", units_pass), ("independent check", indep_pass),
                      ("docs freshness", docs_pass)) if not ok]

        if verbose:
            print("      fingerprint %s  %s" % (digest, summary))
            if units_tail:
                print("      units: %s" % units_tail[0])

        if sab["kind"] == GUARD:
            # Inverted gate 2: a guard that moves the output was never a guard.
            if moved:
                return dict(name=sab["name"], kind=GUARD, gate1=True, gate2=False,
                            gate3=bool(caught_by), verdict="MISCLASSIFIED",
                            note="output moved (%s), so this is a plain attack, not a "
                                 "dormant guard. Rerun it as one." % digest,
                            caught_by=caught_by)
            if not units_pass:
                return dict(name=sab["name"], kind=GUARD, gate1=True, gate2=True,
                            gate3=True, verdict="CAUGHT",
                            note="output unchanged as a guard requires, and the unit "
                                 "suite failed", caught_by=caught_by)
            return dict(name=sab["name"], kind=GUARD, gate1=True, gate2=True, gate3=False,
                        verdict="MISSED",
                        note="output unchanged and the unit suite still passed, so "
                             "nothing tests this guard", caught_by=caught_by)

        if not moved:
            return dict(name=sab["name"], kind=ATTACK, gate1=True, gate2=False, gate3=None,
                        verdict="NO-OP",
                        note="the patch applied but the report is byte-identical. Either "
                             "the fixture never exercises this code path or the change is "
                             "not observable. Add a fixture rather than deleting the "
                             "sabotage.",
                        caught_by=caught_by)
        if caught_by:
            return dict(name=sab["name"], kind=ATTACK, gate1=True, gate2=True, gate3=True,
                        verdict="CAUGHT", note="caught by " + ", ".join(caught_by),
                        caught_by=caught_by)
        return dict(name=sab["name"], kind=ATTACK, gate1=True, gate2=True, gate3=False,
                    verdict="MISSED",
                    note="the report changed (%s) and every check still passed" % digest,
                    caught_by=[])


def null_control(baselines, verbose=False):
    """An unmodified copy must fingerprint identically to the baseline.

    Run for EVERY measurement set in use, not only the default one. A guard
    measured a different way would otherwise get an unvalidated gate 2, which is
    the same hole the null control exists to close.

    Returns a list of (label, baseline, copy) for the sets that disagreed.
    """
    bad = []
    with tempfile.TemporaryDirectory(prefix="dotdrift-null-") as tmp:
        tree = copy_tree(os.path.join(tmp, "tree"))
        for i, (measure, base) in enumerate(baselines.items()):
            work = os.path.join(tmp, "work%d" % i)
            os.makedirs(work)
            digest, summary = fingerprint(tree, work, measure)
            label = ",".join(m[0] for m in measure)
            if verbose:
                print("   copy [%s] %s  %s" % (label, digest, summary))
            if digest != base:
                bad.append((label, base, digest))
    return bad


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--only", default=None, help="run one sabotage by name")
    args = ap.parse_args(argv)

    todo = [s for s in SABOTAGES if args.only is None or s["name"] == args.only]
    if not todo:
        print("no sabotage named %r" % args.only)
        return 2

    measures = []
    for s in todo:
        m = s.get("measure", MEASURE_DEFAULT)
        if m not in measures:
            measures.append(m)

    print("baseline: fingerprint the unmodified project in place")
    baselines = {}
    for i, measure in enumerate(measures):
        with tempfile.TemporaryDirectory(prefix="dotdrift-base-") as tmp:
            digest, summary = fingerprint(PROJECT, tmp, measure)
        label = ",".join(m[0] for m in measure)
        baselines[measure] = digest
        print("   [%s] %s  %s" % (label, digest, summary))
        if summary.startswith("CRASH"):
            print("\nABORT: the unmodified tool does not run. Nothing below would mean anything.")
            print(summary)
            return 2

    print()
    print("NULL CONTROL: an untouched copy in a different directory must match")
    bad = null_control(baselines, verbose=args.verbose)
    if bad:
        for label, base, copy in bad:
            print("   FAIL [%s] baseline=%s copy=%s" % (label, base, copy))
        print()
        print("ABORT: the measurement tracks the working directory rather than the code.")
        print("Gate 2 would pass for free for every sabotage and the scores would be")
        print("meaningless. Scrub the path out of the fingerprint before rerunning.")
        return 2
    print("   ok, all %d measurement set(s) reproduce exactly. Gate 2 measures the code."
          % len(baselines))

    print()
    print("running %d sabotage(s)" % len(todo))
    results = []
    for i, sab in enumerate(todo, 1):
        print("  %2d/%d %-28s [%s]" % (i, len(todo), sab["name"], sab["kind"]))
        r = score_one(sab, baselines, verbose=args.verbose)
        results.append(r)
        print("      %-14s %s" % (r["verdict"], r["note"]))

    print()
    print("%-28s %-7s %-6s %-6s %-6s %s" % ("SABOTAGE", "KIND", "GATE1", "GATE2", "GATE3", "VERDICT"))
    def g(v):
        return "-" if v is None else ("yes" if v else "NO")
    for r in results:
        print("%-28s %-7s %-6s %-6s %-6s %s"
              % (r["name"], r["kind"], g(r["gate1"]), g(r["gate2"]), g(r["gate3"]), r["verdict"]))

    caught = [r for r in results if r["verdict"] == "CAUGHT"]
    bad = [r for r in results if r["verdict"] != "CAUGHT"]
    print()
    print("%d of %d caught" % (len(caught), len(results)))
    if bad:
        for r in bad:
            print("  %-14s %-28s %s" % (r["verdict"], r["name"], r["note"]))
        print()
        print("SABOTAGE RUN FAILED")
        return 1
    print("SABOTAGE RUN PASSED, every sabotage applied, moved the measured output "
          "(or stayed dormant as a guard must), and was caught")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
