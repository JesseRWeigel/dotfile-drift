"""sync, capture and apply. These are the parts that write, so they are the
parts where being wrong costs the user something."""

import os
import unittest

import support
from dotdrift import actions, compare, manifest, policy as policymod

read = support.read_text


def result(fx, **kw):
    pol = policymod.load_policy(fx.repo)
    base, _ = manifest.load(fx.state)
    return compare.run(fx.home, fx.repo, pol, base, compare.Options(**kw)), pol, base


class TestSync(unittest.TestCase):
    def test_sync_records_the_machine_and_clears_the_easy_findings(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            before, _ = manifest.load(fx.state)
            out = actions.sync(fx.home, fx.repo, pol, fx.state, compare.Options(),
                               previous=before)
            # 21 tracked paths, minus three that are not on the machine, minus the
            # one whose symlink escapes the tree and is therefore never read.
            self.assertEqual(out["entries"], 17)
            base, meta = manifest.load(fx.state)
            self.assertTrue(meta["exists"])
            res = compare.run(fx.home, fx.repo, pol, base, compare.Options())
            statuses = {s for _, s in ((f.path, f.status) for f in res.findings)}
            # Everything that was a direction question is settled.
            self.assertNotIn("conflict", statuses)
            self.assertNotIn("local_edit", statuses)
            self.assertNotIn("unsynced_differs", statuses)
            # And everything that is a genuine repo-versus-machine difference
            # is now honestly labelled as the repo being ahead.
            self.assertIn("upstream_change", statuses)

    def test_sync_reports_the_paths_that_still_disagree(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            base, _ = manifest.load(fx.state)
            out = actions.sync(fx.home, fx.repo, pol, fx.state, compare.Options(),
                               previous=base)
            self.assertIn(".tmux.conf", out["disagree"])
            self.assertIn(".gitconfig", out["disagree"])
            self.assertNotIn(".bashrc", out["disagree"])

    def test_sync_drops_files_that_are_gone(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            prev, _ = manifest.load(fx.state)
            actions.sync(fx.home, fx.repo, pol, fx.state, compare.Options(), previous=prev)
            base, _ = manifest.load(fx.state)
            self.assertNotIn(".inputrc", base)
            self.assertNotIn(".gone-everywhere", base)

    def test_sync_records_symlinks_as_symlinks(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            prev, _ = manifest.load(fx.state)
            actions.sync(fx.home, fx.repo, pol, fx.state, compare.Options(), previous=prev)
            base, _ = manifest.load(fx.state)
            self.assertEqual(base[".zshrc"]["kind"], "symlink")
            self.assertEqual(base[".zshrc"]["target"], "../repo/home/.zshrc")
            self.assertEqual(base[".aliases"]["kind"], "file")

    def test_sync_only_leaves_the_rest_of_the_baseline_alone(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            before, _ = manifest.load(fx.state)
            actions.sync(fx.home, fx.repo, pol, fx.state,
                         compare.Options(only=(".gitconfig",)), previous=before)
            after, _ = manifest.load(fx.state)
            self.assertNotEqual(before[".gitconfig"]["raw"], after[".gitconfig"]["raw"])
            self.assertEqual(before[".tmux.conf"]["raw"], after[".tmux.conf"]["raw"])


class TestCapture(unittest.TestCase):
    def test_capture_stages_machine_ahead_files(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            dest = os.path.join(fx.dir, "capture")
            out = actions.capture(fx.home, fx.repo, res, pol, dest)
            self.assertIn(".gitconfig", out["staged"])
            self.assertTrue(os.path.isfile(os.path.join(dest, ".gitconfig")))
            with open(os.path.join(dest, ".gitconfig")) as fh:
                self.assertIn("lg = log", fh.read())

    def test_capture_refuses_denylisted_paths_outright(self):
        """Copying `.npmrc` into a staging directory next to a git repo is the
        accident this tool exists to prevent, so the answer is no even though the
        file genuinely drifted."""
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            dest = os.path.join(fx.dir, "capture2")
            out = actions.capture(fx.home, fx.repo, res, pol, dest)
            refused = dict(out["refused"])
            self.assertIn(".npmrc", refused)
            self.assertIn("denylisted", refused[".npmrc"])
            self.assertNotIn(".npmrc", out["staged"])
            self.assertFalse(os.path.exists(os.path.join(dest, ".npmrc")))

    def test_capture_never_stages_a_conflict(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            dest = os.path.join(fx.dir, "capture3")
            out = actions.capture(fx.home, fx.repo, res, pol, dest)
            self.assertNotIn(".tmux.conf", out["staged"])

    def test_untracked_files_need_an_explicit_flag(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            out = actions.capture(fx.home, fx.repo, res, pol, os.path.join(fx.dir, "c4"))
            self.assertIn(".config/newtool.conf", dict(out["skipped"]))
            out2 = actions.capture(fx.home, fx.repo, res, pol, os.path.join(fx.dir, "c5"),
                                   include_untracked=True)
            self.assertIn(".config/newtool.conf", out2["staged"])


class TestApply(unittest.TestCase):
    def test_dry_run_writes_nothing(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            before = read(os.path.join(fx.home, ".vimrc"))
            out = actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=False)
            self.assertTrue(out["dry_run"])
            self.assertIn((".vimrc", "upstream_change"), out["planned"])
            self.assertEqual(read(os.path.join(fx.home, ".vimrc")), before)

    def test_apply_writes_the_repo_version_and_keeps_a_backup(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            before = read(os.path.join(fx.home, ".vimrc"))
            out = actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            self.assertFalse(out["dry_run"])
            after = read(os.path.join(fx.home, ".vimrc"))
            self.assertIn("undofile", after)
            self.assertNotEqual(before, after)
            backup = os.path.join(out["backup_dir"], ".vimrc")
            self.assertTrue(os.path.isfile(backup))
            self.assertEqual(read(backup), before)

    def test_apply_refuses_a_conflict_and_says_why(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            before = read(os.path.join(fx.home, ".tmux.conf"))
            out = actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            refused = dict(out["refused"])
            self.assertIn(".tmux.conf", refused)
            self.assertIn("by hand", refused[".tmux.conf"])
            self.assertEqual(read(os.path.join(fx.home, ".tmux.conf")), before)

    def test_apply_refuses_when_there_is_no_baseline(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            before = read(os.path.join(fx.home, ".no-baseline.conf"))
            actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            self.assertEqual(read(os.path.join(fx.home, ".no-baseline.conf")), before)

    def test_apply_relinks_a_symlink_that_was_replaced_by_a_copy(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            self.assertFalse(os.path.islink(os.path.join(fx.home, ".aliases")))
            actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            self.assertTrue(os.path.islink(os.path.join(fx.home, ".aliases")))
            self.assertEqual(os.readlink(os.path.join(fx.home, ".aliases")),
                             "../repo/home/.aliases")

    def test_apply_restores_a_drifted_mode(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            p = os.path.join(fx.home, ".ssh", "config")
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)
            actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_apply_reinstalls_a_missing_file(self):
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            self.assertTrue(os.path.isfile(os.path.join(fx.home, ".inputrc")))
            self.assertTrue(os.path.isfile(os.path.join(fx.home, ".newfile-from-repo")))

    def test_the_tree_is_quiet_after_apply_then_sync(self):
        """End to end: fix what can be fixed automatically, record the rest, and
        the only things left are the ones a human has to decide."""
        with support.Fixture() as fx:
            res, pol, _ = result(fx)
            actions.apply(fx.home, fx.repo, res, pol, fx.state, confirm=True)
            base, _ = manifest.load(fx.state)
            res2 = compare.run(fx.home, fx.repo, pol, base, compare.Options())
            left = sorted({(f.path, f.status) for f in res2.findings})
            for path, status in left:
                self.assertIn(status, ("conflict", "unsynced_differs", "symlink_escape",
                                       "untracked_added", "missing_in_repo", "missing_both",
                                       "converged", "insecure_mode", "local_fence_error",
                                       "local_edit"),
                              "%s left as %s" % (path, status))
            self.assertNotIn((".vimrc", "upstream_change"), left)
            self.assertNotIn((".aliases", "symlink_replaced_by_copy"), left)
            self.assertNotIn((".ssh/config", "mode_drift"), left)


if __name__ == "__main__":
    unittest.main()
