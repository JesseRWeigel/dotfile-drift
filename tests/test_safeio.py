"""The containment and read rules, tested directly rather than through the CLI."""

import os
import re
import tempfile
import unittest

import support
from dotdrift import safeio


class TestContainment(unittest.TestCase):
    def test_contained(self):
        with tempfile.TemporaryDirectory() as d:
            inner = os.path.join(d, "a", "b")
            os.makedirs(inner)
            self.assertTrue(safeio.contained(d, inner))
            self.assertTrue(safeio.contained(d, d))
            self.assertFalse(safeio.contained(inner, d))

    def test_a_sibling_with_a_shared_prefix_is_not_contained(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "home"))
            os.makedirs(os.path.join(d, "homework"))
            self.assertFalse(safeio.contained(os.path.join(d, "home"),
                                              os.path.join(d, "homework")))

    def test_symlink_in_the_middle_cannot_smuggle_you_out(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, "root")
            other = os.path.join(d, "other")
            os.makedirs(root)
            os.makedirs(other)
            with open(os.path.join(other, "f"), "w") as fh:
                fh.write("x")
            os.symlink(other, os.path.join(root, "link"))
            self.assertFalse(safeio.contained(root, os.path.join(root, "link", "f")))


class TestMiddleComponentEscape(unittest.TestCase):
    """Regression: the test above only exercised the `contained` HELPER.

    `read_entry` did not call it for a plain regular file, because `lstat`
    declines to follow only the FINAL component. With `~/.config` symlinked
    somewhere else, an ordinary setup, the tool read and hashed a file from
    outside the tracked tree and reported it as a normal dotfile.
    """

    def _tree(self, d):
        home = os.path.join(d, "home")
        outside = os.path.join(d, "outside")
        os.makedirs(home)
        os.makedirs(outside)
        with open(os.path.join(outside, "apprc"), "w") as fh:
            fh.write("SECRET_FROM_OUTSIDE_THE_TREE\n")
        os.symlink(outside, os.path.join(home, ".config"))
        return home, outside

    def test_a_symlinked_parent_directory_is_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            home, _ = self._tree(d)
            e = safeio.read_entry(home, ".config/apprc", [home], 1 << 20)
            self.assertEqual(e.unreadable, safeio.UNREADABLE_ESCAPES)
            self.assertIsNone(e.data)
            self.assertFalse(e.read_ok)
            self.assertIsNone(e.raw_sha256)

    def test_the_escaped_content_is_nowhere_in_the_entry(self):
        with tempfile.TemporaryDirectory() as d:
            home, _ = self._tree(d)
            e = safeio.read_entry(home, ".config/apprc", [home], 1 << 20)
            self.assertNotIn("SECRET_FROM_OUTSIDE_THE_TREE", repr(e))

    def test_a_symlinked_parent_directory_is_not_listed(self):
        with tempfile.TemporaryDirectory() as d:
            home, _ = self._tree(d)
            # Filenames outside the tree are private too, so the listing that
            # finds newly added files must not reach through the link either.
            self.assertEqual(safeio.list_dir_names(home, ".config"), [])

    def test_an_ordinary_nested_directory_still_reads(self):
        # NEGATIVE CONTROL. The fix must not refuse legitimate subdirectories,
        # which would make every .config/* path unreadable and the tool useless.
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "home")
            os.makedirs(os.path.join(home, ".config"))
            with open(os.path.join(home, ".config", "apprc"), "w") as fh:
                fh.write("theme = dark\n")
            e = safeio.read_entry(home, ".config/apprc", [home], 1 << 20)
            self.assertTrue(e.read_ok)
            self.assertEqual(e.data, b"theme = dark\n")
            self.assertEqual([n for n, _, _ in safeio.list_dir_names(home, ".config")],
                             ["apprc"])


class TestEscapeIsNotRead(unittest.TestCase):
    def test_escaping_symlink_is_reported_and_never_opened(self):
        with support.Fixture() as fx:
            e = safeio.read_entry(fx.home, ".config/escape.conf",
                                  [fx.home, fx.repo], 1 << 20)
            self.assertEqual(e.kind, safeio.KIND_SYMLINK)
            self.assertEqual(e.unreadable, safeio.UNREADABLE_ESCAPES)
            self.assertIsNone(e.data)
            self.assertIsNone(e.raw_sha256)

    def test_the_same_link_is_read_when_the_target_root_is_allowed(self):
        """Proves the previous test failed for the containment rule and not
        because the file happened to be unreadable."""
        with support.Fixture() as fx:
            e = safeio.read_entry(fx.home, ".config/escape.conf",
                                  [fx.home, fx.repo, fx.outside], 1 << 20)
            self.assertIsNone(e.unreadable)
            self.assertIn(support.OUTSIDE_MARKER.encode(), e.data)

    def test_symlink_inside_the_tree_is_followed(self):
        with support.Fixture() as fx:
            e = safeio.read_entry(fx.home, ".zshrc", [fx.home, fx.repo], 1 << 20)
            self.assertEqual(e.kind, safeio.KIND_SYMLINK)
            self.assertIsNone(e.unreadable)
            self.assertIn(b"setopt", e.data)


class TestRefusals(unittest.TestCase):
    def test_broken_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            os.symlink("nowhere", os.path.join(d, "l"))
            e = safeio.read_entry(d, "l", [d], 1 << 20)
            self.assertEqual(e.unreadable, safeio.UNREADABLE_BROKEN)

    def test_fifo_is_never_opened(self):
        # Opening a fifo for reading blocks until a writer appears. A tool that
        # walks a home directory and opens whatever it finds hangs forever here.
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(os.path.join(d, "pipe"))
            e = safeio.read_entry(d, "pipe", [d], 1 << 20)
            self.assertEqual(e.kind, safeio.KIND_OTHER)
            self.assertEqual(e.unreadable, safeio.UNREADABLE_NOT_REGULAR)
            self.assertIsNone(e.data)

    def test_oversized_file_is_refused_not_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "big"), "wb") as fh:
                fh.write(b"x" * 5000)
            e = safeio.read_entry(d, "big", [d], 1000)
            self.assertEqual(e.unreadable, safeio.UNREADABLE_TOO_LARGE)
            self.assertIsNone(e.data)

    def test_unreadable_file_is_a_reason_not_a_silent_none(self):
        if os.geteuid() == 0:
            self.skipTest("running as root, permission bits do not apply")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "locked")
            with open(p, "w") as fh:
                fh.write("x")
            os.chmod(p, 0o000)
            try:
                e = safeio.read_entry(d, "locked", [d], 1 << 20)
                self.assertEqual(e.unreadable, safeio.UNREADABLE_DENIED)
                self.assertTrue(e.exists)
                self.assertFalse(e.read_ok)
            finally:
                os.chmod(p, 0o600)

    def test_want_content_false_does_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "f"), "w") as fh:
                fh.write("visible")
            e = safeio.read_entry(d, "f", [d], 1 << 20, want_content=False)
            self.assertEqual(e.kind, safeio.KIND_FILE)
            self.assertIsNone(e.data)
            self.assertEqual(e.unreadable, safeio.UNREADABLE_NOT_REQUESTED)

    def test_missing_file_is_missing_not_unreadable(self):
        with tempfile.TemporaryDirectory() as d:
            e = safeio.read_entry(d, "nope", [d], 1 << 20)
            self.assertEqual(e.kind, safeio.KIND_MISSING)
            self.assertIsNone(e.unreadable)
            self.assertFalse(e.exists)


class TestModeAndListing(unittest.TestCase):
    def test_mode_is_the_target_mode_for_a_symlink(self):
        with support.Fixture() as fx:
            os.chmod(os.path.join(fx.repo, "home", ".zshrc"), 0o600)
            e = safeio.read_entry(fx.home, ".zshrc", [fx.home, fx.repo], 1 << 20)
            self.assertEqual(e.mode, 0o600)

    def test_list_dir_names_does_not_recurse(self):
        with support.Fixture() as fx:
            names = [n for n, _d, _l in safeio.list_dir_names(fx.home, ".config")]
            self.assertIn("newtool.conf", names)
            self.assertNotIn("apprc/", names)

    def test_list_dir_names_on_a_missing_directory_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(safeio.list_dir_names(d, "nope"), [])

    def test_mode_str(self):
        self.assertEqual(safeio.mode_str(0o600), "0600")
        self.assertEqual(safeio.mode_str(None), "----")

    def test_directory_is_reported_as_a_directory(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "sub"))
            e = safeio.read_entry(d, "sub", [d], 1 << 20)
            self.assertEqual(e.kind, safeio.KIND_DIR)
            self.assertIsNone(e.data)


WRITE_MODE = re.compile(r"""open\([^)]*["'][wxa]b?\+?["']""")
READ_CALL = re.compile(r"(?<![\w.])open\(")

# safeio owns reads of user dotfiles. policy and manifest read the tool's own
# config and state files, which the user pointed us at explicitly.
OPEN_ALLOWED = {"safeio.py", "policy.py", "manifest.py"}


class TestNoOtherOpens(unittest.TestCase):
    def test_read_entry_is_the_only_place_that_reads_a_user_path(self):
        """A structural guard, kept in the suite so it runs on every change.

        `verify.sh` runs the same check. Having it here too means a contributor
        finds out before the commit rather than after."""
        import glob
        offenders = []
        for path in sorted(glob.glob(os.path.join(support.PROJECT, "dotdrift", "*.py"))):
            name = os.path.basename(path)
            if name in OPEN_ALLOWED:
                continue
            with open(path, "r", encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    if not READ_CALL.search(line) or line.strip().startswith("#"):
                        continue
                    if WRITE_MODE.search(line):
                        continue  # writing an output file is not reading a dotfile
                    offenders.append("%s:%d %s" % (name, i, line.strip()))
        self.assertEqual(offenders, [], "unexpected read-mode open() outside safeio")


if __name__ == "__main__":
    unittest.main()
