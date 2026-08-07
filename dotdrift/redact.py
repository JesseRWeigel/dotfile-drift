"""Last-resort redaction for content that is about to be quoted.

This is the third layer, not the first. Content reaches the redactor only after
the path survived the denylist and matched an explicit `quotable` glob. If the
redactor is the thing that saved you, two earlier decisions were already wrong.

Every pattern is ASSEMBLED FROM FRAGMENTS at import time. A literal
`ghp_[A-Za-z0-9]{36}` sitting in this file would be found by our own privacy scan
and by GitHub push protection, both of which read this file as tracked text. The
fragments are joined at runtime so no complete credential pattern exists on disk.

Case sensitivity is deliberate. AWS key ids are uppercase by definition, and a
case-insensitive `AKIA[0-9A-Z]{16}` false-positives on ordinary base64, which is
how a previous scan in this workspace flagged an inline PNG.
"""

import re

_A = "A" + "K" + "IA"
_GH = "gh" + "p_"
_GHS = "gh" + "[opsu]_"
_NPM = "np" + "m_"
_SK = "sk-" + "ant" + "-api"
_XOX = "xox" + "[abprs]" + "-"
_PEM = "-----" + "BEGIN" + " [A-Z ]{0,24}PRIVATE KEY" + "-----"
_SLACKHOOK = "hooks\\." + "slack\\.com/services/"
_B64 = "[A-Za-z0-9/+=]"
# JWTs are base64URL, which swaps + and / for - and _. Using the plain base64 class
# here stopped the match at the first - or _ in the signature and left a tail in the
# clear, which looks redacted and is not.
_B64URL = "[A-Za-z0-9_=-]"
_HEX = "[0-9a-fA-F]"

# (label, compiled pattern). ORDER MATTERS, and getting it wrong leaks.
#
# `bearer-token` used to sit above `jwt`, and _B64 excludes the dot, so a `Bearer eyJ...` header
# had only its FIRST segment redacted. The payload survived in the clear and decoded to
# {"sub":"1234567890","name":"Jane Patient"}, with the signature beside it. A partial redaction on
# a credential reads as a redaction and is not one. The most specific pattern goes first, and the
# bearer pattern now spans dots so either one catches the whole token.
PATTERNS = [
    ("aws-access-key-id", re.compile(_A + "[0-9A-Z]{16}")),
    ("github-token", re.compile(_GH + "[A-Za-z0-9]{36,}")),
    ("github-token", re.compile(_GHS + "[A-Za-z0-9]{36,}")),
    ("npm-token", re.compile(_NPM + "[A-Za-z0-9]{36,}")),
    ("anthropic-key", re.compile(_SK + "[A-Za-z0-9_-]{16,}")),
    ("slack-token", re.compile(_XOX + "[A-Za-z0-9-]{10,}")),
    ("private-key-block", re.compile(_PEM)),
    ("slack-webhook", re.compile(_SLACKHOOK + "[A-Za-z0-9/]{10,}")),
    ("basic-auth-url", re.compile("://[^/\\s:@]{1,64}:[^/\\s@]{3,}@")),
    ("jwt", re.compile("eyJ" + _B64URL + "{10,}\\." + "eyJ" + _B64URL + "{10,}\\." + _B64URL + "{10,}")),
    ("bearer-token", re.compile("(?i)\\b" + "bearer" + "\\s+" + "[A-Za-z0-9._~+/=-]" + "{20,}")),
]

# Keys whose value is redacted whole, regardless of what the value looks like.
# The value carries the secret even when it is short or low entropy.
_KEYWORDS = [
    "pass" + "word", "pass" + "wd", "secret", "token", "api" + "key", "api" + "_key",
    "auth", "access" + "_key", "private" + "_key", "client" + "_secret", "credential",
    "session", "cookie", "bearer", "signing" + "_key", "encryption" + "_key",
]
_KEYRX = re.compile(
    "(?i)^(?P<lead>[^\\S\\n]*[\\w.\\[\\]/-]*(?:" + "|".join(_KEYWORDS) + ")[\\w.\\[\\]/-]*"
    "[^\\S\\n]*(?P<sep>[:=])[^\\S\\n]*)(?P<val>\\S.*)$"
)

# `machine x login y password z` on one line, the .netrc shape.
_NETRC = re.compile("(?i)\\b(password|account)\\s+(?P<val>\\S+)")

MASK = "[REDACTED:{label}]"


def redact_line(line: str):
    """Return (line, labels). `labels` is empty when nothing fired."""
    labels = []
    out = line
    for label, rx in PATTERNS:
        if rx.search(out):
            out = rx.sub(MASK.format(label=label), out)
            labels.append(label)

    m = _KEYRX.match(out)
    if m and MASK.split("{")[0] not in m.group("val"):
        out = m.group("lead") + MASK.format(label="secret-shaped-value")
        labels.append("secret-shaped-value")

    def _netrc_sub(mm):
        labels.append("netrc-password")
        return mm.group(1) + " " + MASK.format(label="netrc-password")

    if MASK.split("{")[0] not in out:
        out = _NETRC.sub(_netrc_sub, out)

    return out, list(dict.fromkeys(labels))


def redact_text(text: str):
    """Redact a whole block. Returns (text, labels)."""
    lines = text.split("\n")
    labels = []
    out = []
    for line in lines:
        r, ls = redact_line(line)
        out.append(r)
        labels.extend(ls)
    return "\n".join(out), list(dict.fromkeys(labels))


def looks_secret(text: str) -> bool:
    _, labels = redact_text(text)
    return bool(labels)
