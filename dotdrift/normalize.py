"""Canonicalisation: line endings, trailing newline, and machine-local fences.

Two kinds of difference are noise rather than drift:

1. Line endings and a missing final newline. A file edited on Windows or written
   by an installer that forgot the trailing byte is not a config change.
2. A block the user marked as machine-specific. Every dotfile manager grows one
   of these, because `.gitconfig` needs a different email at work and `.bashrc`
   needs a different PATH on a laptop.

Both are suppressed by default and both are reported in an "ignored" section, so
the user can see the noise exists without it drowning the real findings.
`--no-normalize` promotes line-ending noise back to a finding.

The fence markers are matched as substrings of a line, because they live inside
whatever comment syntax the file uses:

    # dotdrift:local-begin
    export PATH="$HOME/.cargo/bin:$PATH"
    # dotdrift:local-end

An unterminated fence is an ERROR and disables stripping for that file. Failing
open would mean one stray marker silently hides the rest of the file from the
comparison, which is the worst possible failure for a drift tool.
"""

from dataclasses import dataclass

DEFAULT_BEGIN = "dotdrift:local-begin"
DEFAULT_END = "dotdrift:local-end"

# Placeholder substituted for each stripped block. It carries the block index so
# that adding or removing a block still changes the canonical form.
PLACEHOLDER = "[dotdrift:local-block:{i}]"

ERR_UNCLOSED = "unclosed_local_fence"
ERR_NESTED = "nested_local_fence"
ERR_STRAY_END = "local_fence_end_without_begin"


@dataclass
class Canonical:
    """The comparable form of a file plus what we had to do to get there."""

    data: bytes
    is_binary: bool = False
    eol_normalised: bool = False
    blocks_stripped: int = 0
    errors: tuple = ()

    @property
    def ok(self) -> bool:
        return not self.errors


def is_binary(data: bytes) -> bool:
    # A single NUL is the standard signal, and it is also the byte that makes
    # grep-based scanners go blind, so we handle these files explicitly rather
    # than letting them fall through the text path.
    return b"\x00" in data


def normalize_eol(data: bytes) -> bytes:
    out = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if out and not out.endswith(b"\n"):
        out += b"\n"
    return out


def strip_fences(text: str, begin: str, end: str):
    """Replace each fenced block with a placeholder line.

    Returns (text, blocks_stripped, errors)."""
    lines = text.split("\n")
    out = []
    errors = []
    depth = 0
    count = 0
    for line in lines:
        has_begin = begin in line
        has_end = end in line
        if has_begin and has_end:
            # One line carrying both markers is an empty block. Accept it.
            if depth == 0:
                out.append(PLACEHOLDER.format(i=count))
                count += 1
            continue
        if has_begin:
            if depth > 0:
                errors.append(ERR_NESTED)
            else:
                out.append(PLACEHOLDER.format(i=count))
                count += 1
            depth += 1
            continue
        if has_end:
            if depth == 0:
                errors.append(ERR_STRAY_END)
                out.append(line)
                continue
            depth -= 1
            continue
        if depth == 0:
            out.append(line)
    if depth != 0:
        errors.append(ERR_UNCLOSED)
    return "\n".join(out), count, tuple(dict.fromkeys(errors))


def canonicalize(data: bytes, *, normalize: bool = True, begin: str = DEFAULT_BEGIN,
                 end: str = DEFAULT_END, strip_local: bool = True) -> Canonical:
    if is_binary(data):
        return Canonical(data=data, is_binary=True)

    work = data
    eol_done = False
    if normalize:
        work = normalize_eol(work)
        eol_done = work != data

    blocks = 0
    errors: tuple = ()
    if strip_local:
        try:
            text = work.decode("utf-8")
        except UnicodeDecodeError:
            text = work.decode("latin-1")
        if begin in text or end in text:
            stripped, blocks, errors = strip_fences(text, begin, end)
            if errors:
                # Fail closed: keep the full text so the difference is reported.
                blocks = 0
            else:
                work = stripped.encode("utf-8")

    return Canonical(data=work, eol_normalised=eol_done, blocks_stripped=blocks, errors=errors)


def why_equal(a: bytes, b: bytes, *, begin: str = DEFAULT_BEGIN, end: str = DEFAULT_END):
    """Given two byte strings that differ raw but match canonically, say which
    step was responsible. Returns a tuple of reason strings.

    This is what lets the report say "differs only inside your local block"
    instead of the useless "differs"."""
    reasons = []
    if a == b:
        return ()
    if normalize_eol(a) == normalize_eol(b):
        return ("eol_only",)
    ca = canonicalize(a, normalize=False, begin=begin, end=end)
    cb = canonicalize(b, normalize=False, begin=begin, end=end)
    if ca.ok and cb.ok and ca.data == cb.data:
        return ("local_block_only",)
    reasons.append("eol_only")
    reasons.append("local_block_only")
    return tuple(reasons)
