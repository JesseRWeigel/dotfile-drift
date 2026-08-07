"""Run the privacy scan as if the machine's username were an ordinary word.

The scan builds patterns from the current username, so it behaves differently on every machine.
On GitHub's hosted runners the username is `runner`, and the first version matched it anywhere,
so the phrase "the node test runner" read as a leak and the deploy failed on three files that
leak nothing. The local run was green throughout, because the local username is distinctive.

A check whose result depends on who is running it is not a check you can trust, so this
substitutes usernames that are ordinary English words and requires the scan to stay clean.
Running it locally is what makes a CI failure of this kind impossible to discover only in CI.
"""
from __future__ import annotations

import getpass
import importlib
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

# Real usernames that are also words appearing in ordinary prose about software.
NAMES = ["run" + "ner", "bui" + "ld", "te" + "st", "ad" + "min", "no" + "de", "us" + "er"]


def main() -> int:
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
    if len(files) < 10:
        print(f"  FAIL only {len(files)} tracked files, so this proves nothing")
        return 1

    real = getpass.getuser
    failures = 0
    for name in NAMES:
        getpass.getuser = lambda n=name: n
        try:
            import privacy_scan
            importlib.reload(privacy_scan)
            patterns = privacy_scan.machine_path_patterns()
        finally:
            getpass.getuser = real

        hits = []
        for f in files:
            try:
                text = pathlib.Path(f).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for label, pat in patterns:
                for i, line in enumerate(text.splitlines(), 1):
                    if pat.search(line):
                        hits.append(f"{f}:{i} [{label}] {line.strip()[:60]}")
        if hits:
            failures += 1
            print(f"  FAIL as user {name!r}: {len(hits)} finding(s)")
            for h in hits[:4]:
                print(f"        {h}")
        else:
            print(f"  ok   as user {name!r}: clean across {len(files)} tracked files")

    getpass.getuser = real
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
