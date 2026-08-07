"""The detector against the synthetic fixture home.

The expected result is not a golden file captured from a previous run. It is the
hand-written `expect` list inside `fixtures/scenario.json`, next to the prose
describing each scenario. Four of the paths expect ZERO findings. A detector that
answers "drift" to everything passes a suite built only from drifted files, and
fails here.
"""

import unittest

import support
from dotdrift import compare, manifest, policy as policymod


def run_fixture(fx, **kw):
    pol = policymod.load_policy(fx.repo)
    base, meta = manifest.load(fx.state)
    opts = compare.Options(**kw)
    res = compare.run(fx.home, fx.repo, pol, base, opts)
    return res, pol, meta


def pairs(res):
    return sorted((f.path, f.status) for f in res.findings)


class TestFixtureExpectations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = support.Fixture()
        cls.res, cls.pol, cls.meta = run_fixture(cls.fx)

    @classmethod
    def tearDownClass(cls):
        cls.fx.close()

    def test_findings_match_the_hand_written_scenario_exactly(self):
        expected = support.expectations(self.fx.scenario)
        self.assertEqual(pairs(self.res), expected)

    def test_negative_controls_produce_nothing_at_all(self):
        clean = [rel for rel, spec in self.fx.scenario["paths"].items()
                 if not spec.get("expect")]
        self.assertGreaterEqual(len(clean), 4, "the suite needs real negative controls")
        flagged = {p for p, _ in pairs(self.res)}
        for rel in clean:
            self.assertNotIn(rel, flagged, "%s is a negative control and was flagged" % rel)

    def test_every_scenario_path_is_actually_exercised(self):
        """Guards against a scenario entry that the tracked set never reaches, in
        which case its expectations would be vacuously satisfied."""
        seen = {f.path for f in self.res.findings}
        seen |= {i.path for i in self.res.ignored}
        # Unchanged paths appear in neither list, so check the tracked set too.
        tracked = set(compare.build_tracked_set(
            self.fx.repo + "/home", self.res.baseline, self.pol))
        for rel in self.fx.scenario["paths"]:
            self.assertTrue(rel in seen or rel in tracked,
                            "%s is declared in scenario.json but never looked at" % rel)

    def test_counts(self):
        self.assertTrue(self.res.drift)
        self.assertEqual(self.res.unchanged, 4)
        self.assertEqual(self.res.checked, 21)


class TestDirections(unittest.TestCase):
    """"Differs" is not actionable. Every finding says which way it drifted."""

    @classmethod
    def setUpClass(cls):
        cls.fx = support.Fixture()
        cls.res, _, _ = run_fixture(cls.fx)
        cls.by = {}
        for f in cls.res.findings:
            cls.by.setdefault((f.path, f.status), f)

    @classmethod
    def tearDownClass(cls):
        cls.fx.close()

    def test_local_edit_points_at_the_machine(self):
        self.assertEqual(self.by[(".gitconfig", "local_edit")].direction, "machine_ahead")

    def test_upstream_change_points_at_the_repo(self):
        self.assertEqual(self.by[(".vimrc", "upstream_change")].direction, "repo_ahead")

    def test_conflict_is_diverged_and_refuses_to_suggest_a_restore(self):
        f = self.by[(".tmux.conf", "conflict")]
        self.assertEqual(f.direction, "diverged")
        self.assertFalse(f.destructive)
        self.assertIn("Do not restore", f.action)

    def test_no_baseline_means_unknown_direction_and_no_destructive_command(self):
        f = self.by[(".no-baseline.conf", "unsynced_differs")]
        self.assertEqual(f.direction, "unknown")
        self.assertFalse(f.destructive)

    def test_no_unknown_or_diverged_finding_suggests_overwriting_anything(self):
        for f in self.res.findings:
            if f.direction in ("unknown", "diverged"):
                self.assertFalse(f.destructive,
                                 "%s (%s) offers a destructive action without a direction"
                                 % (f.path, f.status))

    def test_every_finding_has_an_action_and_a_command(self):
        for f in self.res.findings:
            self.assertTrue(f.action.strip())
            self.assertTrue(f.command.strip())
            self.assertIn(f.severity, ("high", "warn", "info"))


class TestSymlinkAxis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = support.Fixture()
        cls.res, _, _ = run_fixture(cls.fx)

    @classmethod
    def tearDownClass(cls):
        cls.fx.close()

    def test_correct_symlink_is_not_drift(self):
        self.assertNotIn(".zshrc", {p for p, _ in pairs(self.res)})

    def test_symlink_replaced_by_an_identical_copy_is_still_drift(self):
        """The case a content comparison cannot see. The bytes match, and the
        machine has quietly stopped tracking the repo."""
        f = [f for f in self.res.findings if f.path == ".aliases"][0]
        self.assertEqual(f.status, "symlink_replaced_by_copy")
        self.assertEqual(f.detail["repo_hash"], f.detail["home_hash"])
        self.assertIn("nothing is lost yet", f.summary)

    def test_escaping_symlink_is_reported_and_its_content_never_appears(self):
        from dotdrift import report
        f = [f for f in self.res.findings if f.path == ".config/escape.conf"][0]
        self.assertEqual(f.status, "symlink_escape")
        ctx = {"home_label": "~", "repo_label": "repo", "baseline": {"exists": True}}
        for text in (report.render_text(ctx, self.res),
                     report.render_json(ctx, self.res),
                     report.render_html(ctx, self.res)):
            self.assertNotIn(support.OUTSIDE_MARKER, text)


class TestModeAxis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = support.Fixture()
        cls.res, _, _ = run_fixture(cls.fx)

    @classmethod
    def tearDownClass(cls):
        cls.fx.close()

    def test_mode_drift_on_identical_content(self):
        f = [f for f in self.res.findings
             if f.path == ".ssh/config" and f.status == "mode_drift"][0]
        self.assertEqual(f.detail["from_mode"], "0600")
        self.assertEqual(f.detail["to_mode"], "0644")
        self.assertEqual(f.detail["repo_hash"], f.detail["home_hash"])
        self.assertEqual(f.severity, "high", "loosening permissions is not a nit")

    def test_insecure_mode_is_reported_separately_from_drift(self):
        f = [f for f in self.res.findings
             if f.path == ".ssh/config" and f.status == "insecure_mode"][0]
        self.assertEqual(f.detail["offending_bits"], "0044")

    def test_mode_is_checked_even_when_the_repo_does_not_carry_the_file(self):
        got = {s for p, s in pairs(self.res) if p == ".ssh/id_ed25519"}
        self.assertEqual(got, {"missing_in_repo", "mode_drift", "insecure_mode"})


class TestNoiseHandling(unittest.TestCase):
    def test_line_ending_noise_is_ignored_by_default_and_still_reported(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx)
            ig = {i.path: i for i in res.ignored}
            self.assertIn(".editorconfig", ig)
            self.assertEqual(ig[".editorconfig"].reasons, ("eol_only",))
            self.assertNotIn(".editorconfig", {p for p, _ in pairs(res)})

    def test_no_normalize_promotes_line_ending_noise_to_a_finding(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx, normalize=False)
            expected = support.expectations(fx.scenario, key="expect_no_normalize")
            self.assertIn((".editorconfig", "local_edit"), pairs(res))
            self.assertIn((".editorconfig", "local_edit"), expected)

    def test_local_block_difference_is_ignored_by_default(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx)
            ig = {i.path: i for i in res.ignored}
            self.assertIn(".profile", ig)
            self.assertEqual(ig[".profile"].reasons, ("local_block_only",))

    def test_no_local_blocks_promotes_the_local_block_to_a_finding(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx, strip_local=False)
            self.assertIn((".profile", "local_edit"), pairs(res))

    def test_unbalanced_fence_is_reported_rather_than_swallowing_the_file(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx)
            got = {s for p, s in pairs(res) if p == ".badfence"}
            self.assertEqual(got, {"local_fence_error", "local_edit"})


class TestUntracked(unittest.TestCase):
    def test_new_file_is_found_without_being_read(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx)
            f = [f for f in res.findings if f.path == ".config/newtool.conf"][0]
            self.assertEqual(f.status, "untracked_added")
            self.assertEqual(f.detail["home_hash"], "not read")
            self.assertIsNone(f.quote)

    def test_untracked_scanning_can_be_switched_off(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx, untracked=False)
            self.assertNotIn(".config/newtool.conf", {p for p, _ in pairs(res)})


class TestBaselineIsRequiredForDirection(unittest.TestCase):
    def test_without_a_baseline_nothing_gets_a_direction(self):
        """Two-way comparison is the easy half and it is not enough. With the
        baseline removed, the local edit and the upstream change become
        indistinguishable, which is exactly the point of keeping one."""
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            res = compare.run(fx.home, fx.repo, pol, {}, compare.Options())
            statuses = dict(pairs(res))
            self.assertEqual(statuses[".gitconfig"], "unsynced_differs")
            self.assertEqual(statuses[".vimrc"], "unsynced_differs")
            self.assertEqual(statuses[".tmux.conf"], "unsynced_differs")
            for f in res.findings:
                if f.status == "unsynced_differs":
                    self.assertEqual(f.direction, "unknown")

    def test_with_a_baseline_the_same_three_paths_get_three_different_answers(self):
        with support.Fixture() as fx:
            res, _, _ = run_fixture(fx)
            statuses = dict(pairs(res))
            self.assertEqual(statuses[".gitconfig"], "local_edit")
            self.assertEqual(statuses[".vimrc"], "upstream_change")
            self.assertEqual(statuses[".tmux.conf"], "conflict")


class TestPathSafety(unittest.TestCase):
    def test_a_baseline_entry_that_climbs_out_of_home_is_dropped(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            base, _ = manifest.load(fx.state)
            base["../../etc/passwd"] = {"kind": "file", "raw": "0" * 64}
            base["/etc/shadow"] = {"kind": "file", "raw": "0" * 64}
            res = compare.run(fx.home, fx.repo, pol, base, compare.Options())
            for f in res.findings:
                self.assertNotIn("..", f.path)
                self.assertFalse(f.path.startswith("/"))

    def test_safe_rel(self):
        self.assertTrue(compare.safe_rel(".ssh/config"))
        for bad in ("", "/abs", "../x", "a/../b", "~/x", "a//b", "./x"):
            self.assertFalse(compare.safe_rel(bad), bad)


if __name__ == "__main__":
    unittest.main()
