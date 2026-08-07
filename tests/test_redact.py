"""Positive controls for the redactor.

Every credential here is assembled at runtime from a prefix plus a deterministic
filler, for the same reason `dotdrift/redact.py` assembles its patterns from
fragments: a complete credential-shaped literal in a tracked file trips our own
privacy scan and GitHub push protection, and push protection scans full history
so a later fix does not help.
"""

import pathlib
import unittest

import support  # noqa: F401
from dotdrift import redact


def filler(n, charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
    return "".join(charset[i % len(charset)] for i in range(n))


class TestPositiveControls(unittest.TestCase):
    def assert_fires(self, text, label):
        out, labels = redact.redact_text(text)
        self.assertIn(label, labels, "redactor did not fire on %r, got %r" % (text, labels))
        return out

    def test_github_token(self):
        secret = "gh" + "p_" + filler(36)
        out = self.assert_fires("token = " + secret, "github-token")
        self.assertNotIn(secret, out)

    def test_aws_access_key_id(self):
        secret = "AK" + "IA" + filler(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        out = self.assert_fires("aws_access_key_id = " + secret, "aws-access-key-id")
        self.assertNotIn(secret, out)

    def test_npm_token(self):
        secret = "np" + "m_" + filler(36)
        out = self.assert_fires("//registry.example.invalid/:_authToken=" + secret, "npm-token")
        self.assertNotIn(secret, out)

    def test_anthropic_key(self):
        secret = "sk-" + "ant" + "-api" + "03-" + filler(40)
        out = self.assert_fires("key: " + secret, "anthropic-key")
        self.assertNotIn(secret, out)

    def test_private_key_header(self):
        line = "-----" + "BEGIN" + " OPENSSH PRIVATE KEY" + "-----"
        out = self.assert_fires(line, "private-key-block")
        self.assertNotIn("BEGIN OPENSSH", out)

    def test_basic_auth_in_a_url(self):
        secret = "https://user:" + filler(20) + "@example.invalid/repo.git"
        out = self.assert_fires(secret, "basic-auth-url")
        self.assertNotIn(filler(20), out)

    def test_jwt(self):
        tok = "eyJ" + filler(20) + ".eyJ" + filler(20) + "." + filler(20)
        out = self.assert_fires(tok, "jwt")
        self.assertNotIn(tok, out)

    def test_bearer_header(self):
        tok = "Bearer " + filler(30)
        out = self.assert_fires(tok, "bearer-token")
        self.assertNotIn(filler(30), out)

    def test_netrc_password_line(self):
        out = self.assert_fires("machine example.invalid login bob password hunter2",
                                "netrc-password")
        self.assertNotIn("hunter2", out)
        self.assertIn("bob", out)  # only the password is masked

    def test_short_low_entropy_secret_is_caught_by_the_key_name(self):
        # No pattern matches "hunter2". The key name is what gives it away.
        out = self.assert_fires("password=hunter2", "secret-shaped-value")
        self.assertNotIn("hunter2", out)

    def test_slack_token(self):
        secret = "xox" + "b-" + filler(24)
        out = self.assert_fires(secret, "slack-token")
        self.assertNotIn(secret, out)


class TestNegativeControls(unittest.TestCase):
    """A redactor that masks everything is as useless as one that masks nothing."""

    CLEAN = [
        "set -g history-limit 50000",
        "export EDITOR=vi",
        "[core]\n\tautocrlf = input",
        "alias ll='ls -lah'",
        "indent_size = 2",
        "Host build\n  HostName build.example.invalid\n  User deploy",
        "# a comment about tokens in general",
        "theme = dark",
    ]

    def test_ordinary_config_is_untouched(self):
        for text in self.CLEAN:
            out, labels = redact.redact_text(text)
            self.assertEqual(labels, [], "false positive on %r" % text)
            self.assertEqual(out, text)

    def test_looks_secret_agrees(self):
        self.assertFalse(redact.looks_secret("export PAGER=less"))
        self.assertTrue(redact.looks_secret("api_key: " + filler(24)))

    def test_line_structure_is_preserved(self):
        text = "a\nb\npassword=x\nc"
        out, _ = redact.redact_text(text)
        self.assertEqual(len(out.split("\n")), 4)


class TestCaseSensitivity(unittest.TestCase):
    def test_lowercase_akia_in_base64_is_not_an_aws_key(self):
        # This exact false positive happened in this workspace with grep -i over
        # an inline PNG. AWS key ids are uppercase by definition.
        _, labels = redact.redact_text("iVBORw0AkIAqaMkgIem1yaUXNKiJ2Mw")
        self.assertNotIn("aws-access-key-id", labels)


if __name__ == "__main__":
    unittest.main()


class JwtIsRedactedWhole(unittest.TestCase):
    """A partial redaction on a credential reads as a redaction and is not one.

    Two real defects lived here. `bearer-token` was ordered above `jwt` and its character class
    excluded the dot, so `Bearer eyJ...` had only its header segment replaced and the payload
    survived in the clear. Then the jwt pattern itself used the plain base64 class, so it stopped
    at the first `-` or `_` in a base64url signature and left a tail behind.
    """

    # Assembled so no complete credential-shaped literal sits on disk in this repository.
    HEADER = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    PAYLOAD = "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgUGF0aWVudCJ9"
    SIGNATURE = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV" + "_adQssw5c"
    JWT = f"{HEADER}.{PAYLOAD}.{SIGNATURE}"

    def assert_nothing_survives(self, line):
        out, found = redact.redact_line(line)
        self.assertTrue(found, f"nothing was redacted in {line!r}")
        for fragment in (self.HEADER[:10], self.PAYLOAD[:10], self.SIGNATURE[:10],
                         self.SIGNATURE[-8:]):
            self.assertNotIn(fragment, out,
                             f"{fragment!r} survived redaction in {out!r}")

    def test_behind_a_bearer_header(self):
        self.assert_nothing_survives("Authorization: Bearer " + self.JWT)

    def test_bare_in_a_config_value(self):
        self.assert_nothing_survives("token: " + self.JWT)

    def test_the_signature_tail_does_not_survive(self):
        # base64url, so the signature ends in characters the plain base64 class does not match.
        out, _ = redact.redact_line("token: " + self.JWT)
        self.assertNotIn("_adQssw5c", out)

    def test_an_opaque_bearer_token_is_still_caught(self):
        # The negative control for the reordering: a bearer token that is not a JWT must still be
        # redacted by the bearer pattern, which now sits below jwt.
        out, found = redact.redact_line("Authorization: Bearer " + "A" * 40)
        self.assertIn("bearer-token", found)
        self.assertNotIn("A" * 40, out)

    def test_ordinary_dotfile_lines_are_left_alone(self):
        # Widening the bearer class to span dots could have started matching prose. It did not.
        for line in ("export EDITOR=vim", "Host github.com", "  IdentityFile ~/.ssh/id_ed25519",
                     "alias gs='git status'", "[user]", "  name = A Person", "set -o vi"):
            with self.subTest(line):
                self.assertEqual(redact.redact_line(line)[0], line)


class UsernameOnlyLeaksInAPath(unittest.TestCase):
    """The machine-username pattern must need a path context.

    A bare match on the username fails wherever the username is an ordinary word. On GitHub's
    hosted runners it is `runner`, and the CI deploy failed on three files whose only offence was
    the phrase "the node test runner". What identifies a machine is a path, not a word.
    """

    def pattern(self):
        import sys
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
        import getpass
        import importlib
        real = getpass.getuser
        getpass.getuser = lambda: self.WHO
        try:
            import privacy_scan
            importlib.reload(privacy_scan)
            return dict(privacy_scan.machine_path_patterns())["this-machine-username"]
        finally:
            getpass.getuser = real

    # Assembled, because the repository privacy scan reads this file and has a generic pattern
    # for an absolute home path. A literal one here is indistinguishable from a real leak, and
    # exempting the file would disarm the scanner exactly where it is tested.
    HOME = "/" + "ho" + "me"
    USERS = "/" + "Us" + "ers"
    # The username under test is assembled too. On GitHub's hosted runners the real username IS
    # this string, so writing it after a tilde here is a genuine match for the scanner reading
    # this file, and CI failed on exactly that after the first fix. A test for a scanner
    # necessarily contains what the scanner looks for, so assembling is the only fix that
    # keeps the scanner armed instead of exempting the file it is tested in.
    WHO = "run" + "ner"

    def test_a_home_path_is_flagged(self):
        pat = self.pattern()
        for text in (f"{self.HOME}/{self.WHO}/work/x", f"{self.USERS}/{self.WHO}/notes",
                     f"~{self.WHO}/dotfiles", f"{self.WHO}@github-hosted"):
            with self.subTest(text):
                self.assertTrue(pat.search(text), f"{text!r} should be flagged")

    def test_the_bare_word_is_not(self):
        pat = self.pattern()
        for text in (f"the node test {self.WHO}", f"a {self.WHO} process",
                     f"{self.WHO}s and riders", f"scripts/verify.sh uses the {self.WHO} shell"):
            with self.subTest(text):
                self.assertIsNone(pat.search(text), f"{text!r} is not a leak")
