"""The last-sync baseline, which is the third leg of the comparison.

Two-way drift ("the repo says X, the machine says Y") cannot tell a local edit
from an upstream change. That distinction is the whole point: telling somebody to
"restore from the repo" when the machine holds the newer version destroys their
work. So we record what both sides looked like the last time they agreed.

The manifest stores RAW sha256 only, never content, plus the file kind, symlink
target and mode. It is written to the state directory rather than into the
dotfiles repo, because it describes one machine and would itself be drift.
"""

import json
import os
import time

VERSION = 1


def default_state_dir() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(base, "dotdrift")


def manifest_path(state_dir: str) -> str:
    return os.path.join(state_dir, "manifest.json")


def load(state_dir: str):
    """Return (entries, meta). A missing manifest is not an error, it is the
    honest state 'never synced', and the report says so rather than guessing."""
    p = manifest_path(state_dir)
    if not os.path.isfile(p):
        return {}, {"exists": False, "path": p}
    with open(p, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("version") != VERSION:
        raise ValueError(
            "manifest at %s has version %r, this build writes version %d"
            % (p, data.get("version"), VERSION)
        )
    meta = {
        "exists": True,
        "path": p,
        "synced_at": data.get("synced_at"),
        "home": data.get("home"),
        "repo": data.get("repo"),
    }
    return data.get("entries", {}), meta


def save(state_dir: str, entries: dict, home: str, repo: str) -> str:
    os.makedirs(state_dir, exist_ok=True)
    p = manifest_path(state_dir)
    payload = {
        "version": VERSION,
        "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # Stored as a note for the human reading the file. Nothing compares them,
        # so moving your home directory does not invalidate the baseline.
        "home": home,
        "repo": repo,
        "entries": dict(sorted(entries.items())),
    }
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, p)
    return p


def entry_for(kind: str, raw_sha256: str | None, mode: int | None, target: str | None = None) -> dict:
    e = {"kind": kind}
    if raw_sha256:
        e["raw"] = raw_sha256
    if mode is not None:
        e["mode"] = format(mode, "04o")
    if target:
        e["target"] = target
    return e


def entry_mode(entry: dict):
    m = entry.get("mode")
    if m is None:
        return None
    return int(m, 8)
