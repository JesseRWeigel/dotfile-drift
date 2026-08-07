#!/usr/bin/env bash
#
# The verify command. Its EXIT CODE is the result.
#
# Three rules this script holds to, each one written down because a project in
# this fleet shipped without it:
#
#   * A step that cannot run is a FAILURE, never a skip. A skipped check and a
#     passing check look identical in a log a week later.
#   * The run must not modify the tree. Every tracked file is digested before and
#     after, and a mutation is a named failure. A verify that edits the repo can
#     pass on a later run for reasons an earlier run created.
#   * The README is checked too, because a project can report thirty green checks
#     while its README still says "TODO: replace with a real description".
#
# Usage: bash scripts/verify.sh [--quick]
#   --quick skips the sabotage harness, which takes a few minutes. Everything
#   else runs. CI runs the full thing.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
PROJECT="$PWD"

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

PASS=0
FAIL=0
FAILED_STEPS=()

# One scratch directory for the whole run, cleaned once on exit.
#
# The first version of this script gave each step its own `trap 'rm -rf "$tmp"'
# RETURN`. A bash RETURN trap is not scoped to the function that set it, so the
# trap outlived its function and fired inside an unrelated one, where `tmp` was
# unbound and `set -u` turned a cleanup into a spurious failure. One trap at the
# top has no such edge.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/dotdrift-verify-XXXXXX")" || exit 2
trap 'rm -rf "$SCRATCH"' EXIT

scratch() {
  local d="$SCRATCH/$1"
  rm -rf "$d"
  mkdir -p "$d"
  printf '%s' "$d"
}

# Collapse $HOME to a tilde. The replacement needs the BACKSLASH: bash
# tilde-expands the replacement in ${var/#$HOME/~} so the unescaped form
# substitutes $HOME for $HOME and silently does nothing. Verify output is pasted
# into the README and an absolute /home/<user> path there is private and
# unportable.
tilde() { printf '%s' "${1/#$HOME/\~}"; }

step() {
  local name="$1"; shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    printf 'ok   %s\n' "$name"
    PASS=$((PASS + 1))
  else
    printf 'FAIL %s\n' "$name"
    FAIL=$((FAIL + 1))
    FAILED_STEPS+=("$name")
  fi
}

# --------------------------------------------------------------------------
# Preflight. A missing dependency is a failure with an actionable message, not
# a skip, and not a message that only teaches people to ignore the check.
# --------------------------------------------------------------------------
preflight() {
  local bad=0
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is not on PATH. Install it with: sudo apt install python3"
    echo "Without it nothing in this suite can run. There is no partial mode."
    bad=1
  else
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
      echo "python3 is $(python3 -V), but dotdrift uses PEP 604 unions and needs 3.10 or newer."
      bad=1
    }
    echo "python3 $(python3 -V 2>&1 | cut -d' ' -f2)"
  fi
  if ! command -v git >/dev/null 2>&1; then
    echo "git is not on PATH. The privacy scan enumerates tracked files with"
    echo "git ls-files and cannot fall back to a directory walk, because a walk"
    echo "would also read untracked scratch files and report on things that are"
    echo "not being published. Install git."
    bad=1
  fi
  if ! git -C "$PROJECT" rev-parse --git-dir >/dev/null 2>&1; then
    echo "not a git repository, so the privacy scan has no file list to check."
    bad=1
  fi
  # The tool is stdlib only by design. Prove it rather than asserting it.
  python3 - <<'PY' || bad=1
import pathlib, sys, ast
roots = set()
for p in sorted(pathlib.Path("dotdrift").glob("*.py")):
    for node in ast.walk(ast.parse(p.read_text())):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and not node.level:
            roots.add((node.module or "").split(".")[0])
extra = sorted(r for r in roots if r and r not in sys.stdlib_module_names)
if extra:
    print("dotdrift imports non-stdlib modules: %s" % ", ".join(extra))
    print("This project promises zero dependencies. Either vendor it or drop it.")
    sys.exit(1)
print("dotdrift imports %d stdlib modules and nothing else" % len(roots))
PY
  return $bad
}

# --------------------------------------------------------------------------
# Tree digest, before and after.
# --------------------------------------------------------------------------
digest_tree() {
  git -C "$PROJECT" ls-files -z \
    | xargs -0 -r sha256sum 2>/dev/null \
    | LC_ALL=C sort
}

# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------
unit_tests() {
  # unittest discovery needs the tests directory as its own top level, because
  # the test modules import `support` by bare name.
  local out
  out="$(cd "$PROJECT/tests" && python3 -m unittest discover -s . -t . 2>&1)"
  local rc=$?
  printf '%s\n' "$out" | tail -3
  if [ $rc -ne 0 ]; then
    printf '%s\n' "$out" | tail -40
    return 1
  fi
  # The count in the README is a claim like any other, so assert it here rather
  # than letting a pasted number go stale the moment somebody adds a test.
  local n
  n="$(printf '%s\n' "$out" | sed -n 's/^Ran \([0-9]*\) tests.*/\1/p')"
  if [ -z "$n" ]; then
    echo "could not parse the test count out of the runner output"
    return 1
  fi
  if ! grep -qF "$n unit tests" "$PROJECT/README.md"; then
    echo "the suite ran $n tests but README.md does not say \"$n unit tests\"."
    echo "Update the README rather than deleting this check."
    return 1
  fi
  echo "$n tests, and README.md agrees"
}

end_to_end() {
  # Exercise the real CLI over the fixture home. Exit 1 means drift found, which
  # is the correct answer for a fixture built to contain drift. Exit 0 there
  # would mean the tool went blind.
  local tmp rc
  tmp="$(scratch e2e)" || return 1

  python3 scripts/fixture_home.py "$tmp/fx" >/dev/null || return 1

  python3 bin/dotdrift check --home "$tmp/fx/home" --repo "$tmp/fx/repo" \
    --state "$tmp/fx/state" --quiet
  rc=$?
  if [ $rc -ne 1 ]; then
    echo "check over the drifted fixture exited $rc, expected 1 (drift found)."
    return 1
  fi
  echo "drifted fixture: exit 1 as expected"

  # NEGATIVE CONTROL. Record the machine as the baseline and copy the repo over
  # the home, then the same command must exit 0 with no findings. A detector
  # that answers "drift" to everything passes every test built from drifted
  # input and fails right here.
  rm -rf "$tmp/clean"
  mkdir -p "$tmp/clean/home" "$tmp/clean/repo" "$tmp/clean/state"
  cp -r "$tmp/fx/repo/home/." "$tmp/clean/home/"
  cp -r "$tmp/fx/repo/." "$tmp/clean/repo/"
  # cp gives everything 0644, and `insecure_mode` is a standing policy finding
  # rather than a drift finding, so it fires on a converged tree too. That is the
  # tool being right. Set the mode ssh actually demands so this control tests
  # convergence and not the permission policy, which has its own coverage.
  chmod 700 "$tmp/clean/home/.ssh"
  chmod 600 "$tmp/clean/home/.ssh/config"
  python3 bin/dotdrift sync --home "$tmp/clean/home" --repo "$tmp/clean/repo" \
    --state "$tmp/clean/state" >/dev/null || return 1
  python3 bin/dotdrift check --home "$tmp/clean/home" --repo "$tmp/clean/repo" \
    --state "$tmp/clean/state" --quiet
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "the converged tree exited $rc, expected 0. Printing what it found:"
    python3 bin/dotdrift check --home "$tmp/clean/home" --repo "$tmp/clean/repo" \
      --state "$tmp/clean/state"
    return 1
  fi
  echo "converged tree: exit 0, zero findings"

  # A tool that cannot check must not report a clean machine. Exit 2, never 0.
  python3 bin/dotdrift check --home "$tmp/does-not-exist" --repo "$tmp/fx/repo" \
    --state "$tmp/fx/state" --quiet 2>/dev/null
  rc=$?
  if [ $rc -ne 2 ]; then
    echo "a missing home exited $rc, expected 2. Could-not-check must never"
    echo "share an exit code with a clean machine."
    return 1
  fi
  echo "missing home: exit 2, distinct from both clean and drifted"
  return 0
}

quoting_posture() {
  # The privacy promise, asserted against the real CLI rather than a unit test.
  local tmp out rc=0
  tmp="$(scratch quoting)" || return 1
  python3 scripts/fixture_home.py "$tmp/fx" >/dev/null || return 1

  # 1. Without --quote nothing is quoted at all.
  out="$(python3 bin/dotdrift check --home "$tmp/fx/home" --repo "$tmp/fx/repo" \
        --state "$tmp/fx/state")"
  if printf '%s' "$out" | grep -q '^     content:'; then
    echo "content was quoted without --quote being passed"
    rc=1
  else
    echo "hash-only by default: no content block without --quote"
  fi

  # 2. With --quote, the denylisted .npmrc is still withheld even though the
  #    fixture config lists it as quotable.
  out="$(python3 bin/dotdrift check --home "$tmp/fx/home" --repo "$tmp/fx/repo" \
        --state "$tmp/fx/state" --quote)"
  if ! printf '%s' "$out" | grep -q "content withheld: denylisted by '.npmrc'"; then
    echo ".npmrc is listed as quotable and was NOT withheld by the denylist"
    rc=1
  else
    echo "denylist beats quotable for .npmrc"
  fi

  # 3. The redactor fired, and the raw secret is nowhere in the output.
  if ! printf '%s' "$out" | grep -q 'REDACTED:github-token'; then
    echo "the redactor did not fire on the planted credential in .config/apprc."
    echo "That is the positive control for the last line of defence."
    rc=1
  else
    echo "redactor fired on .config/apprc"
  fi

  # The raw value is read out of the materialised fixture, so this compares
  # against the actual bytes on disk rather than against a copy of them.
  local secret
  secret="$(sed -n 's/^github_token = //p' "$tmp/fx/home/.config/apprc")"
  if [ -z "$secret" ]; then
    echo "could not read the planted credential out of the fixture, so this"
    echo "check would pass without testing anything"
    rc=1
  elif printf '%s' "$out" | grep -qF "$secret"; then
    echo "the raw credential appears in the report"
    rc=1
  else
    echo "the raw credential (${#secret} chars) appears nowhere in the report"
  fi

  # 4. Nothing from inside a machine-local fence is printed.
  if printf '%s' "$out" | grep -q 'MACHINE_LOCAL_SECRET'; then
    echo "content from inside a machine-local fence reached the report"
    rc=1
  else
    echo "fenced machine-local content is never printed"
  fi

  # 5. The file outside the tracked roots was never opened.
  if printf '%s' "$out" | grep -q 'DOTDRIFT_MUST_NEVER_READ_THIS_MARKER'; then
    echo "a file outside the home and repo roots was read and quoted"
    rc=1
  else
    echo "the escaping symlink was reported without its target being read"
  fi
  return $rc
}

single_read_path() {
  # Every read of a SCANNED path goes through safeio.read_entry, which is the one
  # place the containment and no-follow rules live. A second reader elsewhere
  # would be a hole no unit test necessarily finds.
  #
  # Exempting whole files here was the first attempt and it was nearly vacuous:
  # five of the eight modules were on the exemption list, so the check could only
  # fire in the three that never open anything anyway. Instead every filesystem
  # read call in the package is COUNTED and pinned. A new one fails the check and
  # has to be justified by editing this table, which is the point. The rationale
  # for each entry says why it is not a scanned path.
  python3 - <<'PY'
import ast, collections, pathlib, sys

# (module, call): (count, why this is not a read of a scanned path)
EXPECTED = {
    ("safeio.py", "open"):      (1, "os.open with O_NOFOLLOW, the only scanned-path read"),
    ("safeio.py", "read"):      (1, "the read on that one descriptor"),
    ("safeio.py", "scandir"):   (1, "lists names in an already-tracked directory, no content"),
    ("compare.py", "walk"):     (1, "walks the REPO to enumerate tracked names, not the home"),
    ("policy.py", "open"):      (3, "dotdrift.json in the repo root, our own config"),
    ("manifest.py", "open"):    (2, "the baseline manifest in the state directory"),
    ("actions.py", "open"):     (2, "writes during capture and apply, which are opt-in commands"),
    ("cli.py", "open"):         (1, "writes the html report to the path the user named with -o"),
}
WATCHED = ("open", "read_bytes", "read_text", "walk", "scandir", "listdir", "read")

seen = collections.Counter()
sites = collections.defaultdict(list)
for p in sorted(pathlib.Path("dotdrift").glob("*.py")):
    for node in ast.walk(ast.parse(p.read_text())):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
        if name in WATCHED:
            seen[(p.name, name)] += 1
            sites[(p.name, name)].append(node.lineno)

problems = []
for key in sorted(set(seen) | set(EXPECTED)):
    got = seen.get(key, 0)
    want = EXPECTED.get(key, (0, ""))[0]
    if got != want:
        problems.append("%s calls %s() %d time(s), the pinned count is %d (lines %s). "
                        "If this is deliberate, add it to EXPECTED with a reason."
                        % (key[0], key[1], got, want, sites.get(key, [])))
if problems:
    for p in problems:
        print("  " + p)
    sys.exit(1)
print("%d filesystem read sites, all pinned; the only scanned-path read is "
      "safeio._open_regular_nofollow" % sum(seen.values()))
PY
}

readme_check() {
  python3 scripts/check_readme.py
}

pages_workflow() {
  local f=".github/workflows/pages.yml"
  [ -f "$f" ] || { echo "$f is missing"; return 1; }
  if grep -qE '^\s*group:\s*pages\s*$' "$f"; then
    echo "the workflow uses 'group: pages'. One wedged run holds that shared lock"
    echo "and every later deploy queues behind it. Use pages-\${{ github.run_id }}."
    return 1
  fi
  grep -q 'pages-\${{ github.run_id }}' "$f" || {
    echo "the concurrency group is not pages-\${{ github.run_id }}"
    return 1
  }
  echo "concurrency group is per-run"
  [ -f docs/index.html ] || { echo "docs/index.html is missing"; return 1; }
  echo "docs/index.html present"
}

published_page() {
  # The page is derived from the fixture, so a stale copy is a failure. This is
  # also the only check that would notice the renderer changing shape without
  # anybody regenerating the page.
  python3 scripts/build_docs.py --check || return 1
  python3 - <<'PY'
import pathlib, sys
page = pathlib.Path("docs/index.html").read_text()
# Assert on something the RENDERER must have produced. A page that exists and
# parses is not evidence that any data reached it.
problems = []
for needle in ("dotdrift example report", "symlink_replaced_by_copy",
               "insecure_mode", "conflict", "REDACTED:github-token",
               "dotdrift:local-block:0"):
    if needle not in page:
        problems.append("the page does not contain %r" % needle)
if "content withheld" not in page:
    problems.append("the page shows no withheld content, so the default posture "
                    "is not visible on it")
# Nothing that should have been withheld may appear.
for forbidden in ("MACHINE_LOCAL_SECRET", "DOTDRIFT_MUST_NEVER_READ_THIS_MARKER",
                  "BEGIN OPENSSH PRIVATE KEY"):
    if forbidden in page:
        problems.append("the page leaks %r" % forbidden)
if problems:
    for p in problems:
        print("  " + p)
    sys.exit(1)
print("the page carries real rendered findings and leaks nothing withheld")
PY
}

independent_check() {
  python3 scripts/check_independent.py
}

privacy_scan() {
  python3 scripts/privacy_scan.py
}

sabotage_run() {
  if [ "$QUICK" = "1" ]; then
    echo "SKIPPED by --quick, which makes this run NOT a full verification."
    echo "A skipped check reports the same success as one that ran, so this"
    echo "counts as a failure. Re-run without --quick."
    return 1
  fi
  python3 scripts/sabotage.py
}

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
echo "dotdrift verify"
echo "repo $(tilde "$PROJECT")"

BEFORE="$(digest_tree)"
BEFORE_N="$(printf '%s\n' "$BEFORE" | grep -c . || true)"
echo "$BEFORE_N tracked files digested before the run"

step "preflight"                    preflight
step "unit tests"                   unit_tests
step "end to end over the fixture"  end_to_end
step "quoting posture"              quoting_posture
step "single read path"             single_read_path
step "independent recomputation"    independent_check
step "privacy scan"                 privacy_scan
step "published page"               published_page
step "pages workflow"               pages_workflow
step "README"                       readme_check
step "sabotage"                     sabotage_run

printf '\n=== tree not modified ===\n'
AFTER="$(digest_tree)"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "ok   all $BEFORE_N tracked files unchanged"
  PASS=$((PASS + 1))
else
  echo "FAIL the verify run modified the tree:"
  diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") | head -20
  FAIL=$((FAIL + 1))
  FAILED_STEPS+=("tree not modified")
fi

printf '\n----------------------------------------\n'
if [ "$FAIL" -eq 0 ]; then
  echo "VERIFY PASSED: $PASS/$PASS checks"
  exit 0
fi
echo "VERIFY FAILED: $FAIL of $((PASS + FAIL)) checks failed"
for s in "${FAILED_STEPS[@]}"; do echo "  - $s"; done
exit 1
