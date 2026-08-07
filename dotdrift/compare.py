"""The three-way comparison.

Three inputs per path:

  repo   what your dotfiles repository says the file should be
  home   what the machine actually has right now
  base   what both sides looked like at the last `dotdrift sync`

`base` is what makes the output actionable. With only repo and home you can say
"these differ" and nothing more, and the obvious next sentence, "restore from the
repo", is the one that deletes work somebody did on the machine three weeks ago
and forgot to commit.

Every finding carries a DIRECTION and a SAFE ACTION. A finding whose direction is
`unknown` never suggests overwriting anything.
"""

import difflib
import os
from dataclasses import dataclass, field

from . import normalize, redact, safeio
from .manifest import entry_mode

SKIP_REPO_NAMES = {".git", ".github", "dotdrift.json", ".dotdrift.json", "README.md", "LICENSE"}

# status -> (direction, severity, summary, action, command_template, destructive)
STATUS_TABLE = {
    "local_edit": (
        "machine_ahead", "warn",
        "changed on this machine since the last sync, repo untouched",
        "Capture the machine version into your dotfiles repo and commit it.",
        "dotdrift capture --only {p}", False,
    ),
    "upstream_change": (
        "repo_ahead", "warn",
        "changed in the repo since the last sync, machine untouched",
        "Apply the repo version to the machine. A backup of the live file is written first.",
        "dotdrift apply --only {p} --yes", True,
    ),
    "conflict": (
        "diverged", "high",
        "both sides changed since the last sync and they no longer agree",
        "Merge by hand. Do not restore from the repo, that would discard the machine edit.",
        "dotdrift check --only {p} --quote", False,
    ),
    "converged": (
        "none", "info",
        "both sides changed since the last sync and now agree",
        "Nothing to do beyond refreshing the baseline.",
        "dotdrift sync --only {p}", False,
    ),
    "unsynced_differs": (
        "unknown", "high",
        "repo and machine differ and there is no baseline to say which is newer",
        "Inspect both sides yourself. dotdrift will not guess a direction without a baseline.",
        "dotdrift check --only {p} --quote", False,
    ),
    "missing_locally": (
        "machine_ahead", "warn",
        "tracked file is gone from the machine",
        "If you deleted it on purpose, drop it from the repo. Otherwise reinstall it.",
        "dotdrift apply --only {p} --yes", False,
    ),
    "missing_in_repo": (
        "repo_ahead", "warn",
        "the repo no longer carries this file but the machine still has it",
        "Confirm the removal was intended before deleting the live file.",
        "dotdrift sync --only {p}", False,
    ),
    "missing_both": (
        "none", "info",
        "baseline mentions a file that neither side has",
        "Stale baseline entry, refresh it.",
        "dotdrift sync", False,
    ),
    "never_installed": (
        "repo_ahead", "warn",
        "the repo carries this file and the machine has never had it",
        "Install it from the repo.",
        "dotdrift apply --only {p} --yes", False,
    ),
    "untracked_added": (
        "machine_ahead", "info",
        "new file in a tracked directory, never opened by dotdrift",
        "Add it to the repo if it should be tracked, or add it to `ignore`.",
        "dotdrift capture --only {p}", False,
    ),
    "symlink_replaced_by_copy": (
        "machine_ahead", "high",
        "was a symlink into the repo at last sync, now a regular file",
        "An installer overwrote the link. Re-link it so repo changes reach this machine again.",
        "dotdrift apply --only {p} --yes", True,
    ),
    "symlink_retargeted": (
        "machine_ahead", "high",
        "symlink now points somewhere else",
        "Check what installed it, then re-link.",
        "dotdrift apply --only {p} --yes", True,
    ),
    "copy_replaced_by_symlink": (
        "machine_ahead", "warn",
        "was a regular file at last sync, now a symlink",
        "Confirm the new link target is the one you want.",
        "dotdrift sync --only {p}", False,
    ),
    "symlink_escape": (
        "unknown", "high",
        "symlink resolves outside the home and repo roots, so it was NOT read",
        "Point it back inside the tracked tree, or add it to `ignore`.",
        "dotdrift deny '{p}'", False,
    ),
    "symlink_broken": (
        "unknown", "high",
        "symlink target does not exist",
        "Re-link or remove it.",
        "dotdrift apply --only {p} --yes", False,
    ),
    "mode_drift": (
        "machine_ahead", "warn",
        "permission bits changed since the last sync",
        "Restore the recorded mode, or sync if the new mode is intended.",
        "dotdrift apply --only {p} --yes", False,
    ),
    "insecure_mode": (
        "none", "high",
        "permissions are looser than this kind of file allows",
        "Tighten the mode. ssh refuses to use a config or key that others can read.",
        "chmod go-rwx <path>", False,
    ),
    "local_fence_error": (
        "none", "warn",
        "machine-local fence markers are unbalanced, so the whole file was compared",
        "Close the marker. Until then the local block is not being skipped.",
        "dotdrift check --only {p}", False,
    ),
    "unreadable": (
        "unknown", "high",
        "could not be read, so nothing about it was checked",
        "This is not a clean result. Fix the access problem and re-run.",
        "dotdrift check --only {p}", False,
    ),
}

SEVERITY_ORDER = {"high": 0, "warn": 1, "info": 2}


@dataclass
class Finding:
    path: str
    status: str
    direction: str
    severity: str
    summary: str
    action: str
    command: str
    destructive: bool
    detail: dict = field(default_factory=dict)
    quote: dict | None = None

    def to_json(self):
        d = {
            "path": self.path,
            "status": self.status,
            "direction": self.direction,
            "severity": self.severity,
            "summary": self.summary,
            "action": self.action,
            "command": self.command,
            "destructive": self.destructive,
            "detail": self.detail,
        }
        if self.quote is not None:
            d["quote"] = self.quote
        return d


@dataclass
class Ignored:
    path: str
    reasons: tuple
    note: str

    def to_json(self):
        return {"path": self.path, "reasons": list(self.reasons), "note": self.note}


@dataclass
class Observation:
    rel: str
    repo: safeio.Entry
    home: safeio.Entry
    base: dict | None
    repo_canon: normalize.Canonical | None = None
    home_canon: normalize.Canonical | None = None


@dataclass
class Options:
    quote: bool = False
    normalize: bool = True
    strip_local: bool = True
    untracked: bool = True
    only: tuple = ()


@dataclass
class Result:
    findings: list = field(default_factory=list)
    ignored: list = field(default_factory=list)
    checked: int = 0
    unchanged: int = 0
    baseline: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    @property
    def drift(self) -> bool:
        return any(f.severity in ("high", "warn") for f in self.findings)

    def counts(self):
        c = {}
        for f in self.findings:
            c[f.status] = c.get(f.status, 0) + 1
        return dict(sorted(c.items()))

    def severity_counts(self):
        c = {"high": 0, "warn": 0, "info": 0}
        for f in self.findings:
            c[f.severity] += 1
        return c


def _tracked_from_repo(tracked_root: str):
    """Every regular file the dotfiles repo carries, as home-relative paths."""
    out = []
    if not os.path.isdir(tracked_root):
        return out
    for dirpath, dirnames, filenames in os.walk(tracked_root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_REPO_NAMES)
        for name in sorted(filenames):
            if name in SKIP_REPO_NAMES:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, tracked_root).replace(os.sep, "/")
            out.append(rel)
    return sorted(out)


def safe_rel(rel: str) -> bool:
    """Reject anything that could climb out of the home root. Repo walking cannot
    produce such a path, but the baseline is a JSON file on disk and a `..`
    component there would turn every read into an escape."""
    if not rel or rel.startswith("/") or rel.startswith("~"):
        return False
    parts = rel.replace("\\", "/").split("/")
    return not any(p in ("", ".", "..") for p in parts)


def build_tracked_set(tracked_root: str, baseline: dict, policy, only=()):
    paths = set(_tracked_from_repo(tracked_root)) | set(baseline)
    paths = {p for p in paths if safe_rel(p) and not policy.is_ignored(p)}
    if only:
        keep = set()
        for p in paths:
            for sel in only:
                if p == sel or p.startswith(sel.rstrip("/") + "/"):
                    keep.add(p)
        paths = keep
    return sorted(paths)


def observe(home_root: str, tracked_root: str, repo_root: str, rel: str, baseline: dict, policy, opts: Options):
    repo_e = safeio.read_entry(tracked_root, rel, [tracked_root], policy.max_read_bytes)
    home_e = safeio.read_entry(home_root, rel, [home_root, repo_root], policy.max_read_bytes)
    obs = Observation(rel=rel, repo=repo_e, home=home_e, base=baseline.get(rel))
    if repo_e.read_ok:
        obs.repo_canon = normalize.canonicalize(
            repo_e.data, normalize=opts.normalize, begin=policy.fence_begin,
            end=policy.fence_end, strip_local=opts.strip_local)
    if home_e.read_ok:
        obs.home_canon = normalize.canonicalize(
            home_e.data, normalize=opts.normalize, begin=policy.fence_begin,
            end=policy.fence_end, strip_local=opts.strip_local)
    return obs


def _mk(status: str, path: str, detail: dict, *, summary_extra: str = "", severity: str | None = None):
    direction, sev, summary, action, cmd, destructive = STATUS_TABLE[status]
    if summary_extra:
        summary = summary + ". " + summary_extra
    return Finding(
        path=path, status=status, direction=direction, severity=severity or sev,
        summary=summary, action=action, command=cmd.format(p=path),
        destructive=destructive, detail=detail,
    )


def _detail(obs: Observation):
    d = {
        "repo_hash": safeio.short(obs.repo.raw_sha256),
        "home_hash": safeio.short(obs.home.raw_sha256),
        "base_hash": safeio.short((obs.base or {}).get("raw")),
        "repo_kind": obs.repo.kind,
        "home_kind": obs.home.kind,
        "base_kind": (obs.base or {}).get("kind"),
        "home_mode": safeio.mode_str(obs.home.mode),
        "base_mode": (obs.base or {}).get("mode"),
    }
    if obs.home.link_target:
        d["home_link_target"] = obs.home.link_target
    if obs.base and obs.base.get("target"):
        d["base_link_target"] = obs.base["target"]
    return d


def _content_status(obs: Observation):
    """The content axis. Returns a status string, or None when the two sides are
    identical once line-ending noise and machine-local blocks are removed."""
    base_raw = (obs.base or {}).get("raw")
    home_raw = obs.home.raw_sha256
    repo_raw = obs.repo.raw_sha256

    canon_equal = (
        obs.home_canon is not None
        and obs.repo_canon is not None
        and obs.home_canon.data == obs.repo_canon.data
    )
    if canon_equal:
        if base_raw is not None and home_raw != base_raw and repo_raw != base_raw:
            # Both sides moved and landed on the same content. Nothing to
            # reconcile, but the baseline is stale and should be refreshed.
            return "converged"
        # `ignored_for` records why they differ raw when they do.
        return None

    if base_raw is None:
        # No baseline. We can see that they differ and we cannot see which one is
        # newer, so we say exactly that and refuse to suggest an overwrite.
        return "unsynced_differs"

    home_changed = home_raw != base_raw
    repo_changed = repo_raw != base_raw

    if home_changed and not repo_changed:
        return "local_edit"
    if repo_changed and not home_changed:
        return "upstream_change"
    if home_changed and repo_changed:
        # Both moved. If they had converged we would have returned above.
        return "conflict"
    # Neither side moved from the baseline yet they differ, which means the
    # baseline was recorded from one side only, after a partial sync.
    return "unsynced_differs"


def _quote_for(obs: Observation, policy, opts: Options, status: str):
    """Build the quote block. The default answer is 'no', with a reason."""
    allowed, reason = policy.quote_allowed(obs.rel)
    if not opts.quote:
        return {"shown": False, "reason": "content quoting not requested (pass --quote)"}
    if not allowed:
        return {"shown": False, "reason": reason}
    if obs.home_canon is None or obs.repo_canon is None:
        return {"shown": False, "reason": "one side could not be read"}
    if obs.home_canon.is_binary or obs.repo_canon.is_binary:
        return {"shown": False, "reason": "binary content is never quoted"}
    if max(len(obs.home_canon.data), len(obs.repo_canon.data)) > policy.max_quote_bytes:
        return {"shown": False, "reason": "larger than max_quote_bytes"}

    # The diff is taken over the CANONICAL form, so anything inside a
    # machine-local fence is already a placeholder and cannot be printed.
    a = obs.repo_canon.data.decode("utf-8", "replace").split("\n")
    b = obs.home_canon.data.decode("utf-8", "replace").split("\n")
    diff = list(difflib.unified_diff(a, b, fromfile="repo/" + obs.rel, tofile="home/" + obs.rel, lineterm=""))
    truncated = False
    if len(diff) > policy.max_quote_lines:
        diff = diff[: policy.max_quote_lines]
        truncated = True
    text, labels = redact.redact_text("\n".join(diff))
    return {
        "shown": True,
        "reason": reason,
        "redacted": bool(labels),
        "redaction_labels": labels,
        "truncated": truncated,
        "diff": text.split("\n"),
    }


def analyze_one(obs: Observation, policy, opts: Options):
    """All findings for one path. A path can produce several, for example a
    content change and a mode change, because they need different actions."""
    out = []
    rel = obs.rel
    base = obs.base
    detail = _detail(obs)

    # --- read failures come first. "could not check" is never "clean". -----
    for side, e in (("home", obs.home), ("repo", obs.repo)):
        if e.unreadable == safeio.UNREADABLE_ESCAPES and side == "home":
            out.append(_mk("symlink_escape", rel, dict(detail, resolved_outside=True)))
            return out
        if e.unreadable == safeio.UNREADABLE_BROKEN and side == "home":
            out.append(_mk("symlink_broken", rel, detail))
            return out
        if e.exists and not e.read_ok and e.unreadable not in (None, safeio.UNREADABLE_NOT_REQUESTED):
            out.append(_mk("unreadable", rel, dict(detail, side=side, reason=e.unreadable)))
            return out

    # --- existence --------------------------------------------------------
    if not obs.home.exists and not obs.repo.exists:
        if base:
            out.append(_mk("missing_both", rel, detail))
        return out
    if not obs.home.exists:
        out.append(_mk("missing_locally" if base else "never_installed", rel, detail))
        return out
    if not obs.repo.exists:
        if base:
            out.append(_mk("missing_in_repo", rel, detail))
        else:
            out.append(_mk("untracked_added", rel, detail))
        # The file is still on the machine, so its permissions are still our
        # business. A private key that the repo does not carry is exactly the
        # kind of file whose mode is worth checking.
        out.extend(_mode_findings(obs, policy, detail))
        return out

    # --- link shape, which content comparison cannot see ------------------
    base_kind = (base or {}).get("kind")
    if base_kind == safeio.KIND_SYMLINK and obs.home.kind == safeio.KIND_FILE:
        same = obs.home.raw_sha256 == obs.repo.raw_sha256
        extra = ("Content still matches the repo, so nothing is lost yet, but future "
                 "repo changes will no longer reach this machine.") if same else \
                ("Content also differs from the repo.")
        out.append(_mk("symlink_replaced_by_copy", rel, detail,
                       summary_extra=extra, severity="warn" if same else "high"))
    elif base_kind == safeio.KIND_SYMLINK and obs.home.kind == safeio.KIND_SYMLINK:
        want = (base or {}).get("target")
        if want and obs.home.link_target and os.path.normpath(want) != os.path.normpath(obs.home.link_target):
            out.append(_mk("symlink_retargeted", rel, detail))
    elif base_kind == safeio.KIND_FILE and obs.home.kind == safeio.KIND_SYMLINK:
        out.append(_mk("copy_replaced_by_symlink", rel, detail))

    # --- fence errors -----------------------------------------------------
    for side, canon in (("home", obs.home_canon), ("repo", obs.repo_canon)):
        if canon is not None and canon.errors:
            out.append(_mk("local_fence_error", rel, dict(detail, side=side, errors=list(canon.errors))))

    # --- content ----------------------------------------------------------
    status = _content_status(obs)
    if status is not None:
        f = _mk(status, rel, detail)
        f.quote = _quote_for(obs, policy, opts, status)
        out.append(f)

    # --- modes ------------------------------------------------------------
    out.extend(_mode_findings(obs, policy, detail))
    return out


def _mode_findings(obs: Observation, policy, detail: dict):
    """Permission findings, which are independent of content.

    `.ssh/config` at 0644 with byte-identical content is a real problem: ssh
    refuses to use a key whose config or key file is group or world readable, so
    the machine is broken while a content-only comparison calls it clean.
    """
    out = []
    rel = obs.rel
    base_mode = entry_mode(obs.base) if obs.base else None
    if base_mode is not None and obs.home.mode is not None and base_mode != obs.home.mode:
        looser = (obs.home.mode & ~base_mode) != 0
        out.append(_mk("mode_drift", rel,
                       dict(detail, from_mode=safeio.mode_str(base_mode),
                            to_mode=safeio.mode_str(obs.home.mode), looser=looser),
                       severity="high" if looser else "warn"))
    mask, pat = policy.forbidden_mode_bits(rel)
    if mask is not None and obs.home.mode is not None and (obs.home.mode & mask):
        out.append(_mk("insecure_mode", rel,
                       dict(detail, policy=pat, forbidden_bits=format(mask, "04o"),
                            offending_bits=format(obs.home.mode & mask, "04o"))))
    return out


def ignored_for(obs: Observation, policy, opts: Options):
    """Differences suppressed by normalisation. Reported so the user knows the
    noise is there rather than discovering later that we hid something."""
    if obs.home.data is None or obs.repo.data is None:
        return None
    if obs.home.raw_sha256 == obs.repo.raw_sha256:
        return None
    if obs.home_canon is None or obs.repo_canon is None:
        return None
    if obs.home_canon.data != obs.repo_canon.data:
        return None
    reasons = normalize.why_equal(obs.home.data, obs.repo.data,
                                  begin=policy.fence_begin, end=policy.fence_end)
    notes = {
        "eol_only": "line endings or the trailing newline differ, nothing else does",
        "local_block_only": "differs only inside your machine-local fence markers",
    }
    note = "; ".join(notes.get(r, r) for r in reasons)
    return Ignored(path=obs.rel, reasons=reasons, note=note)


def scan_untracked(home_root: str, tracked: list, policy, baseline: dict):
    """Names that appeared in a directory we already track. lstat only, no reads.

    The home root itself is scanned for dotfiles only. Listing every ordinary
    file in somebody's home directory is not this tool's business.
    """
    # Filter again here. `tracked` is already clean, but `baseline` is a JSON
    # file on disk, and one absolute path in it would otherwise turn
    # os.path.join(home, "/etc") into "/etc" and list somebody's system config.
    known = {p for p in (set(tracked) | set(baseline)) if safe_rel(p)}
    dirs = {os.path.dirname(p) for p in known}
    dirs |= {d for d in policy.watch_dirs if safe_rel(d)}
    found = []
    for d in sorted(dirs):
        for name, is_dir, _is_link in safeio.list_dir_names(home_root, d):
            if is_dir:
                continue
            rel = (d + "/" + name) if d else name
            if rel in known or policy.is_ignored(rel):
                continue
            if d == "" and not name.startswith("."):
                continue
            found.append(rel)
    return sorted(found)


def run(home_root: str, repo_root: str, policy, baseline: dict, opts: Options) -> Result:
    tracked_root = os.path.join(repo_root, policy.tracked_subdir)
    res = Result(baseline=dict(baseline))
    paths = build_tracked_set(tracked_root, baseline, policy, opts.only)

    for rel in paths:
        obs = observe(home_root, tracked_root, repo_root, rel, baseline, policy, opts)
        res.checked += 1
        fs = analyze_one(obs, policy, opts)
        ig = ignored_for(obs, policy, opts)
        if ig is not None:
            res.ignored.append(ig)
        if not fs:
            res.unchanged += 1
        res.findings.extend(fs)

    if opts.untracked:
        for rel in scan_untracked(home_root, paths, policy, baseline):
            if opts.only and not any(rel == s or rel.startswith(s.rstrip("/") + "/") for s in opts.only):
                continue
            e = safeio.read_entry(home_root, rel, [home_root, repo_root],
                                  policy.max_read_bytes, want_content=False)
            res.findings.append(_mk("untracked_added", rel, {
                "home_kind": e.kind, "home_mode": safeio.mode_str(e.mode),
                "home_hash": "not read", "repo_kind": "missing", "base_kind": None,
            }))

    res.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.path, f.status))
    res.ignored.sort(key=lambda i: i.path)
    return res
