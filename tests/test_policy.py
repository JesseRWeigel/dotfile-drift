import json
import os
import tempfile
import unittest

import support  # noqa: F401
from dotdrift import policy as P


class TestDenylist(unittest.TestCase):
    def setUp(self):
        self.pol = P.load_policy("/nonexistent-repo")

    def test_default_quotes_nothing(self):
        allowed, reason = self.pol.quote_allowed(".bashrc")
        self.assertFalse(allowed)
        self.assertIn("not listed in quotable", reason)

    def test_denylist_beats_a_wildcard_quotable(self):
        """The requirement in one test: `quotable: ["*"]` must not print secrets."""
        pol = P.Policy(quotable=("*", "**"), never_quote=P.BUILTIN_NEVER_QUOTE)
        for path in (".aws/credentials", ".netrc", ".npmrc", ".git-credentials",
                     ".ssh/id_ed25519", ".ssh/config", ".bash_history", ".env",
                     ".env.production", ".pgpass", ".config/gh/hosts.yml",
                     ".kube/config", ".docker/config.json", "work.pem",
                     ".gnupg/private-keys-v1.d/x.key", ".password-store/a.gpg",
                     ".mozilla/firefox/x/logins.json", ".my.cnf",
                     ".config/rclone/rclone.conf", ".zsh_history"):
            allowed, reason = pol.quote_allowed(path)
            self.assertFalse(allowed, "%s would have been quoted" % path)
            self.assertIn("denylisted", reason)

    def test_denylist_names_the_rule_that_fired(self):
        _, reason = self.pol.quote_allowed(".aws/credentials")
        self.assertIn(".aws/credentials", reason)

    def test_ordinary_dotfile_is_quotable_when_listed(self):
        pol = P.Policy(quotable=(".bashrc",), never_quote=P.BUILTIN_NEVER_QUOTE)
        allowed, reason = pol.quote_allowed(".bashrc")
        self.assertTrue(allowed)
        self.assertIn("quotable", reason)

    def test_user_denylist_is_added_to_the_builtin_one(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "dotdrift.json"), "w") as fh:
                json.dump({"never_quote": ["work/**"], "quotable": ["*"]}, fh)
            pol = P.load_policy(d)
            self.assertFalse(pol.quote_allowed("work/notes.txt")[0])
            self.assertFalse(pol.quote_allowed(".netrc")[0])
            self.assertTrue(pol.quote_allowed(".bashrc")[0])


class TestModePolicy(unittest.TestCase):
    def test_ssh_config_forbids_group_and_other_bits(self):
        pol = P.load_policy("/nonexistent-repo")
        mask, pat = pol.forbidden_mode_bits(".ssh/config")
        self.assertEqual(mask, 0o077)
        self.assertEqual(pat, ".ssh/config")
        self.assertTrue(0o644 & mask)
        self.assertFalse(0o600 & mask)

    def test_unlisted_path_has_no_mode_policy(self):
        pol = P.load_policy("/nonexistent-repo")
        self.assertEqual(pol.forbidden_mode_bits(".bashrc"), (None, None))

    def test_config_can_add_a_mode_policy(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "dotdrift.json"), "w") as fh:
                json.dump({"mode_policy": {".secrets/*": "0077"}}, fh)
            pol = P.load_policy(d)
            self.assertEqual(pol.forbidden_mode_bits(".secrets/a")[0], 0o077)


class TestConfigLoading(unittest.TestCase):
    def test_missing_config_is_not_an_error(self):
        pol = P.load_policy("/nonexistent-repo")
        self.assertIsNone(pol.config_path)
        self.assertEqual(pol.quotable, ())

    def test_bad_json_raises_rather_than_defaulting_silently(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "dotdrift.json"), "w") as fh:
                fh.write("{not json")
            with self.assertRaises(ValueError):
                P.load_policy(d)

    def test_unknown_keys_are_reported_as_warnings(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "dotdrift.json"), "w") as fh:
                json.dump({"qoutable": [".bashrc"]}, fh)
            pol = P.load_policy(d)
            self.assertTrue(any("qoutable" in w for w in pol.warnings))

    def test_append_never_quote_creates_and_extends(self):
        with tempfile.TemporaryDirectory() as d:
            p = P.append_never_quote(d, "work/**")
            self.assertTrue(os.path.isfile(p))
            P.append_never_quote(d, "notes/**")
            P.append_never_quote(d, "work/**")  # idempotent
            with open(p) as fh:
                data = json.load(fh)
            self.assertEqual(data["never_quote"], ["work/**", "notes/**"])
            self.assertFalse(P.load_policy(d).quote_allowed("work/x")[0])


class TestIgnore(unittest.TestCase):
    def test_ignore_globs(self):
        pol = P.Policy(ignore=(".cache/**",))
        self.assertTrue(pol.is_ignored(".cache/a/b"))
        self.assertFalse(pol.is_ignored(".bashrc"))


if __name__ == "__main__":
    unittest.main()
