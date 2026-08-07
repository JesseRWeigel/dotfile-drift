"""Filesystem access with the two privacy rules enforced in one place.

Rule 1: never follow a symlink out of the tracked tree.
Rule 2: never read a file the caller did not name.

Everything that opens a file in this package goes through `read_entry`. There is
no other `open()` on a user path anywhere in `dotdrift/`, and `scripts/verify.sh`
greps for that.

The failure modes are values, not exceptions swallowed into None. A caller must
be able to tell "checked, identical" from "could not check", because collapsing
those two is how an advisory tool ends up quietly reporting a clean machine.
"""

import hashlib
import os
import stat
from dataclasses import dataclass, field

KIND_FILE = "file"
KIND_SYMLINK = "symlink"
KIND_DIR = "dir"
KIND_MISSING = "missing"
KIND_OTHER = "other"

# Reasons a read did not happen. Each one is surfaced in the report.
UNREADABLE_ESCAPES = "symlink_target_outside_tracked_roots"
UNREADABLE_BROKEN = "broken_symlink"
UNREADABLE_NOT_REGULAR = "not_a_regular_file"
UNREADABLE_TOO_LARGE = "larger_than_max_read_bytes"
UNREADABLE_DENIED = "permission_denied"
UNREADABLE_VANISHED = "vanished_during_scan"
UNREADABLE_NOT_REQUESTED = "not_in_the_tracked_set"


@dataclass
class Entry:
    """What we know about one path. `data` is None whenever we did not read it."""

    rel: str
    kind: str = KIND_MISSING
    mode: int | None = None
    size: int | None = None
    link_target: str | None = None
    link_resolved: str | None = None
    data: bytes | None = None
    raw_sha256: str | None = None
    unreadable: str | None = None
    notes: list = field(default_factory=list)

    @property
    def exists(self) -> bool:
        return self.kind != KIND_MISSING

    @property
    def read_ok(self) -> bool:
        return self.data is not None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short(digest: str | None, n: int = 12) -> str:
    if not digest:
        return "-"
    return digest[:n]


def contained(root: str, target: str) -> bool:
    """True if `target` is `root` or lives underneath it. Both are compared after
    full resolution, so a symlink halfway up the path cannot smuggle you out."""
    root = os.path.realpath(root)
    target = os.path.realpath(target)
    if target == root:
        return True
    return target.startswith(root.rstrip(os.sep) + os.sep)


def contained_in_any(roots, target: str) -> bool:
    return any(contained(r, target) for r in roots if r)


def _open_regular_nofollow(abspath: str, max_bytes: int):
    """Open and read a regular file, refusing to follow a symlink at the final
    component. Returns (data, reason). Exactly one of the two is None."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(abspath, flags)
    except PermissionError:
        return None, UNREADABLE_DENIED
    except FileNotFoundError:
        return None, UNREADABLE_VANISHED
    except OSError:
        # ELOOP lands here when the final component became a symlink between the
        # lstat and the open. That is a real TOCTOU race, so we decline the read.
        return None, UNREADABLE_NOT_REGULAR
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, UNREADABLE_NOT_REGULAR
        if st.st_size > max_bytes:
            return None, UNREADABLE_TOO_LARGE
        return os.read(fd, max_bytes), None
    except OSError:
        return None, UNREADABLE_DENIED
    finally:
        os.close(fd)


def read_entry(root: str, rel: str, allowed_roots, max_bytes: int, want_content: bool = True) -> Entry:
    """Inspect `root/rel`.

    `allowed_roots` bounds symlink resolution. A link whose resolved target sits
    outside every allowed root is recorded and never opened.

    `want_content=False` does lstat only. That is how untracked additions are
    handled: we report that a file appeared without ever reading it.
    """
    e = Entry(rel=rel)
    abspath = os.path.join(root, rel)

    # A symlink at a MIDDLE component escapes just as effectively as one at the
    # end, and lstat does not notice: it declines to follow only the FINAL
    # component. With `~/.config` symlinked to a shared drive, which is an
    # ordinary setup, `lstat(~/.config/apprc)` reports a plain regular file and
    # the read below would happily return content from outside the tracked tree.
    #
    # `contained` realpaths both sides, so resolving the parent closes the whole
    # class. There was a test for this, and it exercised `contained` directly
    # rather than `read_entry`, so the helper was correct and the caller was not.
    parent = os.path.dirname(abspath) or abspath
    if not contained_in_any(allowed_roots, parent):
        e.kind = KIND_OTHER
        e.unreadable = UNREADABLE_ESCAPES
        return e

    try:
        st = os.lstat(abspath)
    except FileNotFoundError:
        return e
    except (PermissionError, OSError):
        e.kind = KIND_OTHER
        e.unreadable = UNREADABLE_DENIED
        return e

    e.mode = stat.S_IMODE(st.st_mode)

    if stat.S_ISLNK(st.st_mode):
        e.kind = KIND_SYMLINK
        try:
            e.link_target = os.readlink(abspath)
        except OSError:
            e.link_target = None
        resolved = os.path.realpath(abspath)
        e.link_resolved = resolved
        if not os.path.exists(resolved):
            e.unreadable = UNREADABLE_BROKEN
            return e
        if not contained_in_any(allowed_roots, resolved):
            e.unreadable = UNREADABLE_ESCAPES
            # The link's own 0777 mode says nothing, and we will not stat the
            # target, so report no mode rather than a misleading one.
            e.mode = None
            return e
        try:
            tst = os.stat(resolved)
        except OSError:
            e.unreadable = UNREADABLE_BROKEN
            return e
        if not stat.S_ISREG(tst.st_mode):
            e.unreadable = UNREADABLE_NOT_REGULAR
            return e
        e.size = tst.st_size
        # The link target's own mode is what ssh and friends actually check.
        e.mode = stat.S_IMODE(tst.st_mode)
        if want_content:
            data, reason = _open_regular_nofollow(resolved, max_bytes)
            if reason:
                e.unreadable = reason
            else:
                e.data = data
                e.raw_sha256 = sha256_hex(data)
        else:
            e.unreadable = UNREADABLE_NOT_REQUESTED
        return e

    if stat.S_ISDIR(st.st_mode):
        e.kind = KIND_DIR
        return e

    if not stat.S_ISREG(st.st_mode):
        # A fifo would block forever on open, a device would be worse. Never touch it.
        e.kind = KIND_OTHER
        e.unreadable = UNREADABLE_NOT_REGULAR
        return e

    e.kind = KIND_FILE
    e.size = st.st_size
    if not want_content:
        e.unreadable = UNREADABLE_NOT_REQUESTED
        return e
    data, reason = _open_regular_nofollow(abspath, max_bytes)
    if reason:
        e.unreadable = reason
    else:
        e.data = data
        e.raw_sha256 = sha256_hex(data)
    return e


def list_dir_names(root: str, rel: str):
    """Names inside one directory. No recursion, no reads, no stat of contents
    beyond the type flag already carried by the directory entry."""
    if rel.startswith("/") or rel.startswith("~"):
        # os.path.join(root, "/etc") is "/etc". Refuse rather than list it.
        return []
    abspath = os.path.join(root, rel) if rel else root
    # Same middle-component escape as in read_entry. Listing a directory reached
    # through a symlink out of the tree would put foreign filenames, which are
    # themselves private, into the report.
    if not contained(root, abspath):
        return []
    out = []
    try:
        with os.scandir(abspath) as it:
            for de in it:
                out.append((de.name, de.is_dir(follow_symlinks=False), de.is_symlink()))
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []
    out.sort()
    return out


def mode_str(mode: int | None) -> str:
    if mode is None:
        return "----"
    return format(mode, "04o")
