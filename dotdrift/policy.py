"""What may be quoted, what must never be quoted, and which modes are unsafe.

The default posture is HASH ONLY. A file is quoted only when all of these hold:

  1. the user listed it in `quotable`,
  2. it does not match the builtin or user denylist,
  3. the caller passed --quote on this run,
  4. it is text, and small enough to be worth showing.

The denylist is not overridable. `quotable: ["*"]` plus `.aws/credentials` still
does not print your AWS keys, and there is a test for exactly that.
"""

import json
import os
from dataclasses import dataclass, field

from . import globs

# Paths that are never quoted, no matter what the config says. This list is meant
# to be added to. `dotdrift deny '<glob>'` appends to the user config, and user
# entries are unioned with these rather than replacing them.
BUILTIN_NEVER_QUOTE = (
    # cloud and package registry credentials
    ".aws/credentials", ".aws/config", ".aws/sso/**", ".azure/**", ".config/gcloud/**",
    ".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc", ".git-credentials",
    ".cargo/credentials*", ".gem/credentials", ".bundle/config", ".composer/auth.json",
    ".docker/config.json", ".kube/config", ".config/rclone/rclone.conf",
    ".terraform.d/credentials.tfrc.json", ".config/hub", ".config/gh/hosts.yml",
    ".netlify/config.json", ".config/doctl/config.yaml", ".config/fly/config.yml",
    # keys and key material
    ".ssh/**", ".gnupg/**", ".pki/**", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
    "*.keystore", "*.ovpn", "id_*", "*.gpg", "*.asc",
    # database and mail
    ".pgpass", ".my.cnf", ".mylogin.cnf", ".pgadmin/**", ".msmtprc", ".fetchmailrc",
    ".offlineimaprc", ".mbsyncrc",
    # anything that is a shell or tool history
    "*_history", ".*history", ".lesshst", ".sqlite_history", ".rediscli_history",
    # environment files
    ".env", ".env.*", "*.env", ".envrc", ".direnvrc",
    # browsers, chat clients, password stores
    ".mozilla/**", ".thunderbird/**", ".config/Slack/**", ".config/discord/**",
    ".password-store/**", ".local/share/keyrings/**", ".config/Bitwarden*/**",
    # generic name shapes
    "*secret*", "*credential*", "*token*", "*passwd*", "*password*",
)

# Modes that are a finding in themselves, independent of any drift. The value is
# the mask of bits that must NOT be set.
BUILTIN_MODE_POLICY = {
    ".ssh/config": 0o077,
    ".ssh/id_*": 0o077,
    ".ssh/*_rsa": 0o077,
    ".ssh/*_ed25519": 0o077,
    ".ssh/authorized_keys": 0o022,
    ".ssh/known_hosts": 0o022,
    ".netrc": 0o077,
    "_netrc": 0o077,
    ".aws/credentials": 0o077,
    ".pgpass": 0o077,
    ".my.cnf": 0o077,
    ".git-credentials": 0o077,
    ".gnupg/**": 0o077,
}

DEFAULTS = {
    "tracked_subdir": "home",
    "quotable": [],
    "never_quote": [],
    "watch_dirs": [],
    "normalize_eol": True,
    "strip_local_blocks": True,
    "fence_begin": "dotdrift:local-begin",
    "fence_end": "dotdrift:local-end",
    "max_read_bytes": 1048576,
    "max_quote_bytes": 65536,
    "max_quote_lines": 40,
    "mode_policy": {},
    "ignore": [],
}

CONFIG_NAMES = ("dotdrift.json", ".dotdrift.json")


@dataclass
class Policy:
    config_path: str | None = None
    tracked_subdir: str = DEFAULTS["tracked_subdir"]
    quotable: tuple = ()
    never_quote: tuple = ()
    watch_dirs: tuple = ()
    normalize_eol: bool = True
    strip_local_blocks: bool = True
    fence_begin: str = DEFAULTS["fence_begin"]
    fence_end: str = DEFAULTS["fence_end"]
    max_read_bytes: int = DEFAULTS["max_read_bytes"]
    max_quote_bytes: int = DEFAULTS["max_quote_bytes"]
    max_quote_lines: int = DEFAULTS["max_quote_lines"]
    mode_policy: dict = field(default_factory=dict)
    ignore: tuple = ()
    warnings: tuple = ()

    # --- quoting decision -------------------------------------------------
    def deny_reason(self, rel: str):
        """Return the denylist glob that forbids quoting `rel`, or None."""
        return globs.match_any(rel, self.never_quote)

    def quote_allowed(self, rel: str):
        """Return (allowed, reason). `reason` always explains the decision, which
        is what stops users from assuming the tool found nothing to show."""
        denied = self.deny_reason(rel)
        if denied:
            return False, "denylisted by %r" % denied
        allow = globs.match_any(rel, self.quotable)
        if allow:
            return True, "matched quotable %r" % allow
        return False, "not listed in quotable"

    def is_ignored(self, rel: str) -> bool:
        return globs.match_any(rel, self.ignore) is not None

    def forbidden_mode_bits(self, rel: str):
        """Return (mask, pattern) for the strictest policy that matches, or (None, None)."""
        best = None
        best_pat = None
        for pat, mask in self.mode_policy.items():
            if globs.match(rel, pat):
                if best is None or mask > best:
                    best, best_pat = mask, pat
        return best, best_pat


def _as_int_mode(v):
    if isinstance(v, int):
        return v
    return int(str(v), 8)


def load_policy(repo_root: str, overrides: dict | None = None) -> Policy:
    """Read `dotdrift.json` from the dotfiles repo root. Missing config is fine
    and yields the defaults, which quote nothing at all."""
    cfg = dict(DEFAULTS)
    warnings = []
    used = None
    for name in CONFIG_NAMES:
        p = os.path.join(repo_root, name)
        if os.path.isfile(p):
            used = p
            with open(p, "r", encoding="utf-8") as fh:
                try:
                    loaded = json.load(fh)
                except json.JSONDecodeError as exc:
                    raise ValueError("%s is not valid JSON: %s" % (p, exc)) from exc
            unknown = sorted(set(loaded) - set(DEFAULTS))
            if unknown:
                warnings.append("ignored unknown config keys: %s" % ", ".join(unknown))
            cfg.update({k: v for k, v in loaded.items() if k in DEFAULTS})
            break

    if overrides:
        cfg.update({k: v for k, v in overrides.items() if v is not None})

    mode_policy = {k: _as_int_mode(v) for k, v in BUILTIN_MODE_POLICY.items()}
    for k, v in (cfg.get("mode_policy") or {}).items():
        mode_policy[k] = _as_int_mode(v)

    return Policy(
        config_path=used,
        tracked_subdir=cfg["tracked_subdir"],
        quotable=tuple(cfg["quotable"]),
        never_quote=tuple(BUILTIN_NEVER_QUOTE) + tuple(cfg["never_quote"]),
        watch_dirs=tuple(cfg["watch_dirs"]),
        normalize_eol=bool(cfg["normalize_eol"]),
        strip_local_blocks=bool(cfg["strip_local_blocks"]),
        fence_begin=cfg["fence_begin"],
        fence_end=cfg["fence_end"],
        max_read_bytes=int(cfg["max_read_bytes"]),
        max_quote_bytes=int(cfg["max_quote_bytes"]),
        max_quote_lines=int(cfg["max_quote_lines"]),
        mode_policy=mode_policy,
        ignore=tuple(cfg["ignore"]),
        warnings=tuple(warnings),
    )


def append_never_quote(repo_root: str, pattern: str) -> str:
    """Add a glob to the user denylist, creating the config if needed."""
    path = None
    for name in CONFIG_NAMES:
        p = os.path.join(repo_root, name)
        if os.path.isfile(p):
            path = p
            break
    if path is None:
        path = os.path.join(repo_root, CONFIG_NAMES[0])
        data = {}
    else:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    entries = list(data.get("never_quote", []))
    if pattern not in entries:
        entries.append(pattern)
    data["never_quote"] = entries
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
