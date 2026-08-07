"""Glob matching for home-relative paths.

`fnmatch` treats `/` as an ordinary character, so `.ssh/*` would match
`.ssh/keys/id_ed25519` and `*` would match everything including separators.
Both behaviours are wrong for a denylist, so we translate globs ourselves.

Rules:
  *   matches anything except `/`
  **  matches anything including `/`
  ?   matches one character except `/`
  [..] character class, passed through
  a pattern with no `/` also matches against the basename alone
"""

import re

_CACHE = {}


def _translate(pattern: str) -> str:
    out = ["(?s:"]
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # `**/` should also match zero directories, so `.ssh/**` covers
                # `.ssh/config` and `**/x` covers a bare `x`.
                if i + 2 < n and pattern[i + 2] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape("["))
                i += 1
            else:
                body = pattern[i + 1 : j]
                if body.startswith(("!", "^")):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append(")\\Z")
    return "".join(out)


def compile_glob(pattern: str):
    rx = _CACHE.get(pattern)
    if rx is None:
        rx = re.compile(_translate(pattern))
        _CACHE[pattern] = rx
    return rx


def match(rel_path: str, pattern: str) -> bool:
    """True if the home-relative posix path matches the glob."""
    rel_path = rel_path.lstrip("./") if rel_path.startswith("./") else rel_path
    if compile_glob(pattern).match(rel_path):
        return True
    if "/" not in pattern:
        base = rel_path.rsplit("/", 1)[-1]
        if compile_glob(pattern).match(base):
            return True
    return False


def match_any(rel_path: str, patterns) -> str | None:
    """Return the first matching pattern, or None. The pattern is returned so a
    report can say WHICH rule suppressed a quote, which matters when a user is
    trying to work out why their file was not shown."""
    for p in patterns:
        if match(rel_path, p):
            return p
    return None
