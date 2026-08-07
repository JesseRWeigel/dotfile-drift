"""Positive controls for the redactor.

Every credential here is assembled at runtime from a prefix plus a deterministic
filler, for the same reason `dotdrift/redact.py` assembles its patterns from
fragments: a complete credential-shaped literal in a tracked file trips our own
privacy scan and GitHub push protection, and push protection scans full history
so a later fix does not help.
"""

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
