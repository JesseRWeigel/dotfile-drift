import unittest

import support  # noqa: F401  (puts the project on sys.path)
from dotdrift import globs


class TestGlobs(unittest.TestCase):
    def test_star_does_not_cross_a_separator(self):
        # fnmatch would say yes here, and that is why we do not use fnmatch.
        self.assertFalse(globs.match(".ssh/keys/id_ed25519", ".ssh/*"))
        self.assertTrue(globs.match(".ssh/config", ".ssh/*"))

    def test_double_star_crosses_separators(self):
        self.assertTrue(globs.match(".ssh/keys/id_ed25519", ".ssh/**"))
        self.assertTrue(globs.match(".ssh/config", ".ssh/**"))

    def test_double_star_slash_matches_zero_directories(self):
        self.assertTrue(globs.match("id_rsa", "**/id_*"))
        self.assertTrue(globs.match("a/b/id_rsa", "**/id_*"))

    def test_bare_pattern_also_matches_the_basename(self):
        self.assertTrue(globs.match(".config/app/secret.json", "*secret*"))
        self.assertTrue(globs.match("deep/dir/.bash_history", "*_history"))

    def test_pattern_with_a_slash_does_not_fall_back_to_basename(self):
        self.assertFalse(globs.match("other/credentials", ".aws/credentials"))

    def test_character_class(self):
        self.assertTrue(globs.match("file.pem", "*.[pk]em"))
        self.assertFalse(globs.match("file.zem", "*.[pk]em"))

    def test_question_mark_does_not_cross_a_separator(self):
        self.assertFalse(globs.match("a/b", "a?b"))
        self.assertTrue(globs.match("axb", "a?b"))

    def test_match_any_returns_the_pattern(self):
        self.assertEqual(globs.match_any(".netrc", ["*.pem", ".netrc"]), ".netrc")
        self.assertIsNone(globs.match_any(".bashrc", ["*.pem", ".netrc"]))

    def test_literal_dot_is_not_a_wildcard(self):
        self.assertFalse(globs.match("xnetrc", ".netrc"))


if __name__ == "__main__":
    unittest.main()
