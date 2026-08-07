# dotfile-drift

Three-way dotfile drift detector that reports what changed without quoting your secrets.

Catalog task: `CLI-035`. One of a public catalog of build ideas: https://github.com/JesseRWeigel/722-things-to-build

## What this is

`dotdrift` compares the dotfiles your machine actually has against the dotfiles your
repository says it should have, and tells you which direction each difference goes and what
the safe action is.

It reports by hash. A drift report that quotes a changed line will sooner or later quote a
secret, because dotfiles are exactly where credentials live: `.aws/credentials`, `.netrc`,
`.npmrc` tokens, `.git-credentials`, SSH keys, shell history, `.env`. So the default output
says a file changed, in which direction, and what to run about it, and shows no content at
all.

Zero dependencies, Python 3.10 or newer, stdlib only. It sends nothing anywhere.

## How it decides

### Three-way, because two-way cannot tell you what to do

Comparing the repo against the machine tells you two files differ. It cannot tell you which
one is newer, so the obvious next sentence, "restore from the repo", is the one that deletes
work somebody did on the machine three weeks ago and forgot to commit.

`dotdrift` keeps a third input: a baseline recorded by `dotdrift sync`, holding what both
sides looked like the last time they agreed. The baseline stores sha256 hashes, file kind,
symlink target and mode. It never stores content.

| repo vs baseline | machine vs baseline | status | direction | safe action |
|---|---|---|---|---|
| same | changed | `local_edit` | machine ahead | capture into the repo |
| changed | same | `upstream_change` | repo ahead | apply to the machine |
| changed | changed, disagree | `conflict` | diverged | merge by hand, restore destroys work |
| changed | changed, agree | `converged` | none | refresh the baseline |
| any | any, no baseline | `unsynced_differs` | **unknown** | inspect both sides yourself |

No finding whose direction is `unknown` or `diverged` ever suggests a command that
overwrites anything. There is a test asserting that across the whole status table.

### Symlink versus copy

A symlink pointing at the right target is not drift. A symlink that an installer replaced
with a regular file is drift, and it is the common failure after running an installer: the
content still matches, so a content-only comparison calls the machine clean while future
repo changes silently stop reaching it. `dotdrift` reports `symlink_replaced_by_copy`,
`symlink_retargeted` and `copy_replaced_by_symlink` as their own statuses.

### Mode bits

`.ssh/config` at 0644 with byte-identical content is a real problem, because ssh refuses a
config or key that others can read. Modes are compared against the baseline
(`mode_drift`), and separately against a builtin policy of bits that must never be set
(`insecure_mode`), so a loose private key is a finding even when nothing drifted.

### Machine-specific blocks are legitimate

Every dotfile setup grows a block that differs per machine. Fence it and it stops being
drift:

```bash
# dotdrift:local-begin
export PATH="$HOME/.local/bin:$PATH"
# dotdrift:local-end
```

The fenced region is replaced by a placeholder before comparison, so it is invisible to the
diff and cannot be printed even when the file is quotable. An **unterminated** fence is an
error that disables stripping for that file, because failing open would let one stray
marker hide the rest of the file from the comparison.

### Line endings are normalised, and it says so

CRLF, lone CR and a missing trailing newline are suppressed by default. They are still
listed in an `ignored as noise` section, so you can see the noise exists rather than
discovering later that something was hidden. `--no-normalize` promotes them back to
findings.

## Privacy model

Four layers, and the default answer at every one of them is no.

1. **Hash only by default.** Content is shown for a path only when the user listed it in
   `quotable` in `dotdrift.json` **and** `--quote` was passed on this run. Both, not either.
2. **A denylist that is not overridable.** `.aws/credentials`, `.ssh/**`, `.netrc`,
   `.npmrc`, `.git-credentials`, `*_history`, `.env*`, `*secret*`, `*token*` and roughly
   fifty more patterns are never quoted. `quotable: ["*"]` plus `.aws/credentials` still
   prints nothing, and there is a test for exactly that.
3. **Redaction of anything about to be quoted.** Content that survives the first two layers
   is still scanned for credential shapes and masked. Every pattern is assembled from string
   fragments at import time, so no complete credential pattern exists on disk to trip
   GitHub push protection or to be matched by this project's own privacy scan.
4. **No symlink is followed out of the tracked tree.** A link resolving outside the home and
   repo roots is reported and never opened. The fixture points one at a file containing a
   marker string, and both `scripts/verify.sh` and `scripts/check_independent.py` fail if
   that marker ever appears in the output.

Every withheld path says why: `content withheld: denylisted by '.npmrc'`. A report that
silently shows nothing is indistinguishable from a report that found nothing.

Only synthetic fixture dotfiles are committed. Credential-shaped fixtures are stored as
templates such as `{FILL:36}` and `{PEMBEGIN:OPENSSH}` which the loader expands at runtime,
so no complete pattern is ever on disk or in git history. `scripts/privacy_scan.py` fails
the build if any real path from a real machine appears in a tracked file.

## Running it

```bash
# Report drift. Exit 0 nothing to do, 1 drift found, 2 could not check.
python3 bin/dotdrift check --home ~ --repo ~/dotfiles

# Record the current machine as the baseline, once the two sides agree.
python3 bin/dotdrift sync --home ~ --repo ~/dotfiles

# Show content for paths you marked quotable. The denylist still wins.
python3 bin/dotdrift check --repo ~/dotfiles --quote

# Write the report as a self-contained page.
python3 bin/dotdrift html --repo ~/dotfiles -o report.html
```

Your dotfiles repo holds a `home/` directory mirroring your home tree, plus an optional
`dotdrift.json`. The baseline lives in `$XDG_STATE_HOME/dotdrift`, not in the repo, because
it describes one machine and would itself be drift.

### Try it without touching your own dotfiles

```bash
python3 scripts/fixture_home.py /tmp/fx
python3 bin/dotdrift check --home /tmp/fx/home --repo /tmp/fx/repo --state /tmp/fx/state --quote
```

An example report over that same fixture home is published at `docs/index.html`.

## Verify

```bash
bash scripts/verify.sh
```

Its exit code is the result. Twelve checks over 160 unit tests, and a step that cannot run
is a failure rather than a skip. It digests every tracked file before and after and fails if
the run modified the tree. The test count in that sentence is asserted against the runner on
every run, so it cannot go stale silently.

| script | what it does |
|---|---|
| `scripts/verify.sh` | the whole suite, exit code is the result |
| `scripts/fixture_home.py` | materialises the synthetic home, repo, baseline and an outside-the-tree file |
| `scripts/check_independent.py` | recomputes the classification without importing the package, proved with `ast` |
| `scripts/privacy_scan.py` | credential and real-path scan over tracked files, with a positive control |
| `scripts/sabotage.py` | breaks the detector seventeen ways under the three-gate rule |
| `scripts/build_docs.py` | regenerates `docs/index.html`, `--check` fails if it is stale |
| `scripts/check_readme.py` | this file, ignoring fenced code blocks |

The fixture home covers unchanged, locally edited, upstream changed, both changed, converged,
symlink still correct, symlink replaced by a copy, symlink retargeted outside the tree, mode
loosened, deleted from the machine, deleted from the repo, never installed, newly added,
unterminated fence, no baseline at all, and a difference confined to a marker block. Four of
its paths are **negative controls** that must produce zero findings, so a detector that
answers "drift" to everything fails.

`scripts/sabotage.py` runs a null control first: an unmodified copy of the tree must
fingerprint identically to the baseline, otherwise the measurement tracks the working
directory rather than the code and the run is void. It then applies seventeen patches and
requires each to change the observable output and be caught. The redactor is scored as a
**guard**: it is dormant on clean input, so disabling it must leave normal output unchanged
while the unit suite fails.

## Status

Pasted output of `bash scripts/verify.sh`, exit 0, run 2026-08-07.

```
$ bash scripts/verify.sh
dotdrift verify
repo ~/Projects/thousand/projects/dotfile-drift
77 tracked files digested before the run

=== preflight ===
python3 3.12.3
dotdrift imports 12 stdlib modules and nothing else
ok   preflight

=== unit tests ===
Ran 160 tests in 0.411s

OK
160 tests, and README.md agrees
ok   unit tests

=== end to end over the fixture ===
drifted fixture: exit 1 as expected
converged tree: exit 0, zero findings
missing home: exit 2, distinct from both clean and drifted
ok   end to end over the fixture

=== quoting posture ===
hash-only by default: no content block without --quote
denylist beats quotable for .npmrc
redactor fired on .config/apprc
the raw credential (40 chars) appears nowhere in the report
fenced machine-local content is never printed
the escaping symlink was reported without its target being read
ok   quoting posture

=== single read path ===
12 filesystem read sites, all pinned; the only scanned-path read is safeio._open_regular_nofollow
ok   single read path

=== independent recomputation ===
1. import graph (ast, not grep)
   ok, nothing in this script's import graph reaches 'dotdrift'
2. content classification, recomputed with blake2b over line tuples
   ok, 8 content classifications agree
3. structural axes: kind, mode, existence, containment
   ok, symlink kind change,         1 path(s)
   ok, mode change,                 2 path(s)
   ok, missing from the machine,    2 path(s)
   ok, missing from the repo,       2 path(s)
   ok, escaping symlink,            1 path(s)
   ok, converged,                   1 path(s)
4. both against the hand-written scenario expectations
   ok, 18 paths match scenario.json
5. negative controls
   ok, .bashrc is clean in both computations
   ok, .editorconfig is clean in both computations
   ok, .profile is clean in both computations
   ok, .zshrc is clean in both computations
6. the escaped file's content never appears in the tool's output
   ok, marker absent

INDEPENDENT CHECK PASSED
ok   independent recomputation

=== privacy scan ===
1. positive control: plant credentials and require them to be found
   ok, 7 planted hits found, one of them behind a NUL byte, and 3 relative paths correctly left alone
2. tracked files
   ok, git reports 77 tracked files
3. scan for credentials and machine paths
   read 77 files (0 containing a NUL byte, scanned anyway)
   ok, no credential-shaped string and no path from this machine
4. the scan read its own source and the sabotage script
   ok, scripts/privacy_scan.py is tracked and was scanned with no exemption
   ok, scripts/sabotage.py is tracked and was scanned with no exemption

PRIVACY SCAN PASSED
ok   privacy scan

=== scan is username independent ===
  ok   as user 'runner': clean across 77 tracked files
  ok   as user 'build': clean across 77 tracked files
  ok   as user 'test': clean across 77 tracked files
  ok   as user 'admin': clean across 77 tracked files
  ok   as user 'node': clean across 77 tracked files
  ok   as user 'user': clean across 77 tracked files
ok   scan is username independent

=== published page ===
ok, docs/index.html matches a fresh build (46775 bytes)
the page carries real rendered findings and leaks nothing withheld
ok   published page

=== pages workflow ===
concurrency group is per-run
docs/index.html present
ok   pages workflow

=== README ===
  prose and fenced blocks separated
  Status carries a real success line: 13 of 13 checks
  README has every required section, no scaffold markers in prose, and a real transcript
ok   README

=== sabotage ===
baseline: fingerprint the unmodified project in place
   [quoted,hash-only] 9e593fc32c9b39a8  quoted findings=22 ignored=2  hash-only findings=22 ignored=2
   [quoted-clean-subset] 64a1c067622eb17c  quoted-clean-subset findings=3 ignored=0

NULL CONTROL: an untouched copy in a different directory must match
   ok, all 2 measurement set(s) reproduce exactly. Gate 2 measures the code.

running 17 sabotage(s)
   1/17 direction-flip               [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
   2/17 ignore-the-baseline          [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
   3/17 conflict-becomes-local-edit  [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
   4/17 symlink-blindness            [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
   5/17 mode-blindness               [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
   6/17 insecure-mode-blindness      [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
   7/17 denylist-disabled            [attack]
      CAUGHT         caught by unit suite, docs freshness
   8/17 quote-without-the-flag       [attack]
      CAUGHT         caught by unit suite
   9/17 fence-contents-leak          [attack]
      CAUGHT         caught by unit suite, docs freshness
  10/17 follow-the-escaping-symlink  [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
  11/17 middle-symlink-read          [guard]
      CAUGHT         output unchanged as a guard requires, and the unit suite failed
  12/17 write-outside-the-home       [guard]
      CAUGHT         output unchanged as a guard requires, and the unit suite failed
  13/17 eol-noise-becomes-drift      [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
  14/17 fence-swallows-the-file      [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
  15/17 drift-never-exits-nonzero    [attack]
      CAUGHT         caught by unit suite
  16/17 untracked-scan-off           [attack]
      CAUGHT         caught by unit suite, independent check, docs freshness
  17/17 redactor-disabled            [guard]
      CAUGHT         output unchanged as a guard requires, and the unit suite failed

SABOTAGE                     KIND    GATE1  GATE2  GATE3  VERDICT
direction-flip               attack  yes    yes    yes    CAUGHT
ignore-the-baseline          attack  yes    yes    yes    CAUGHT
conflict-becomes-local-edit  attack  yes    yes    yes    CAUGHT
symlink-blindness            attack  yes    yes    yes    CAUGHT
mode-blindness               attack  yes    yes    yes    CAUGHT
insecure-mode-blindness      attack  yes    yes    yes    CAUGHT
denylist-disabled            attack  yes    yes    yes    CAUGHT
quote-without-the-flag       attack  yes    yes    yes    CAUGHT
fence-contents-leak          attack  yes    yes    yes    CAUGHT
follow-the-escaping-symlink  attack  yes    yes    yes    CAUGHT
middle-symlink-read          guard   yes    yes    yes    CAUGHT
write-outside-the-home       guard   yes    yes    yes    CAUGHT
eol-noise-becomes-drift      attack  yes    yes    yes    CAUGHT
fence-swallows-the-file      attack  yes    yes    yes    CAUGHT
drift-never-exits-nonzero    attack  yes    yes    yes    CAUGHT
untracked-scan-off           attack  yes    yes    yes    CAUGHT
redactor-disabled            guard   yes    yes    yes    CAUGHT

17 of 17 caught
SABOTAGE RUN PASSED, every sabotage applied, moved the measured output (or stayed dormant as a guard must), and was caught
ok   sabotage

=== tree not modified ===
ok   all 77 tracked files unchanged

----------------------------------------
VERIFY PASSED: 13/13 checks
```

## Unfinished

- `dotdrift apply` restores content, mode and symlinks, and takes a backup first, but it has
  no undo command. The backup directory is printed and you move files back by hand.
- Untracked-file detection lists directories that are already tracked plus anything in
  `watch_dirs`. It does not walk your whole home directory, which is deliberate, so a new
  file in a directory dotdrift has never seen is not reported.
- The baseline has no per-machine namespacing. Two machines sharing an `XDG_STATE_HOME` over
  a network mount would overwrite each other's baseline.
- Windows is untested. The mode and symlink logic assumes POSIX semantics.
- There is no file-watching or scheduling. Run it from cron or a shell hook; the 0/1/2 exit
  split exists for that.
