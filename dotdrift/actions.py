"""The three things you can do about drift: record it, capture it, apply it.

`sync`    write the baseline. This is the only way the tool learns direction.
`capture` copy machine-ahead files into a staging directory for review.
`apply`   write repo-ahead files onto the machine, after taking a backup.

`capture` and `apply` both refuse to touch anything whose direction is unknown or
diverged. A tool that guesses in those cases is a tool that eventually deletes an
afternoon of work.
"""

import os
import shutil
import time

from . import compare, manifest, safeio

CAPTURABLE = ("local_edit", "untracked_added", "converged")
APPLICABLE = ("upstream_change", "never_installed", "missing_locally",
              "symlink_replaced_by_copy", "symlink_retargeted", "mode_drift")
NEVER_AUTOMATIC = ("conflict", "unsynced_differs", "symlink_escape", "unreadable")


def sync(home_root: str, repo_root: str, policy, state_dir: str, opts: compare.Options,
         previous: dict | None = None):
    """Record what the machine has right now as the baseline.

    Paths where the repo and the machine still disagree are recorded too, and the
    caller is told how many, because a baseline taken over an unreconciled tree
    will report every one of those as an upstream change tomorrow.
    """
    tracked_root = os.path.join(repo_root, policy.tracked_subdir)
    previous = previous or {}
    paths = compare.build_tracked_set(tracked_root, previous, policy, opts.only)
    entries = dict(previous) if opts.only else {}
    disagree = []
    skipped = []
    for rel in paths:
        obs = compare.observe(home_root, tracked_root, repo_root, rel, previous, policy, opts)
        if not obs.home.exists:
            entries.pop(rel, None)
            skipped.append(rel)
            continue
        if obs.home.unreadable and not obs.home.read_ok:
            skipped.append(rel)
            continue
        entries[rel] = manifest.entry_for(
            obs.home.kind, obs.home.raw_sha256, obs.home.mode, obs.home.link_target)
        if (obs.repo_canon is not None and obs.home_canon is not None
                and obs.repo_canon.data != obs.home_canon.data):
            disagree.append(rel)
    path = manifest.save(state_dir, entries, home_root, repo_root)
    return {"path": path, "entries": len(entries), "disagree": disagree, "skipped": skipped}


def capture(home_root: str, repo_root: str, res: compare.Result, policy, dest: str,
            include_untracked: bool = False):
    """Stage machine-ahead files so the user can review and commit them.

    Denylisted paths are never staged. Copying `.aws/credentials` into a staging
    directory next to a git repo is exactly the accident this tool exists to
    avoid, so the answer is no even when the file genuinely drifted.
    """
    staged, refused, skipped = [], [], []
    for f in res.findings:
        if f.status not in CAPTURABLE:
            continue
        if f.status == "untracked_added" and not include_untracked:
            skipped.append((f.path, "untracked, pass --include-untracked"))
            continue
        denied = policy.deny_reason(f.path)
        if denied:
            refused.append((f.path, "denylisted by %r" % denied))
            continue
        e = safeio.read_entry(home_root, f.path, [home_root, repo_root], policy.max_read_bytes)
        if not e.read_ok:
            refused.append((f.path, e.unreadable or "unreadable"))
            continue
        out = os.path.join(dest, f.path)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(e.data)
        os.chmod(out, e.mode if e.mode is not None else 0o600)
        staged.append(f.path)
    return {"staged": staged, "refused": refused, "skipped": skipped, "dest": dest}


def apply(home_root: str, repo_root: str, res: compare.Result, policy, state_dir: str,
          confirm: bool = False):
    """Write repo-ahead content onto the machine. Dry run unless `confirm`."""
    tracked_root = os.path.join(repo_root, policy.tracked_subdir)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_dir = os.path.join(state_dir, "backups", stamp)
    planned, refused, done = [], [], []

    for f in res.findings:
        if f.status in NEVER_AUTOMATIC:
            refused.append((f.path, "direction %s, resolve this one by hand" % f.direction))
            continue
        if f.status not in APPLICABLE:
            continue
        planned.append((f.path, f.status))

    if not confirm:
        return {"planned": planned, "refused": refused, "applied": [], "dry_run": True,
                "backup_dir": None}

    for rel, status in planned:
        dst = os.path.join(home_root, rel)
        base = res.baseline.get(rel) or {}
        # Back up whatever is there now, including a symlink, before touching it.
        if os.path.lexists(dst):
            bpath = os.path.join(backup_dir, rel)
            os.makedirs(os.path.dirname(bpath), exist_ok=True)
            if os.path.islink(dst):
                os.symlink(os.readlink(dst), bpath)
            else:
                shutil.copy2(dst, bpath)
        os.makedirs(os.path.dirname(dst) or home_root, exist_ok=True)

        if status in ("symlink_replaced_by_copy", "symlink_retargeted") and base.get("target"):
            if os.path.lexists(dst):
                os.remove(dst)
            os.symlink(base["target"], dst)
            done.append((rel, "relinked to %s" % base["target"]))
            continue
        if status == "mode_drift":
            want = manifest.entry_mode(base)
            if want is not None:
                os.chmod(dst, want)
                done.append((rel, "mode restored to %s" % format(want, "04o")))
            continue
        src_entry = safeio.read_entry(tracked_root, rel, [tracked_root], policy.max_read_bytes)
        if not src_entry.read_ok:
            refused.append((rel, "repo side unreadable: %s" % src_entry.unreadable))
            continue
        if os.path.islink(dst):
            os.remove(dst)
        with open(dst, "wb") as fh:
            fh.write(src_entry.data)
        if src_entry.mode is not None:
            os.chmod(dst, src_entry.mode)
        done.append((rel, "written from repo"))

    return {"planned": planned, "refused": refused, "applied": done, "dry_run": False,
            "backup_dir": backup_dir if done else None}
