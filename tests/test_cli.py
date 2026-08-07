"""The command line surface, driven the way a weekly hook drives it.

Exit codes matter more than output here. A cron job that cannot distinguish
"clean" from "crashed" is worse than no cron job.
"""

import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

import support
from dotdrift import EXIT_DRIFT, EXIT_ERROR, EXIT_OK, cli

BIN = os.path.join(support.PROJECT, "bin", "dotdrift")


def call(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue(), err.getvalue()


def base_args(fx, *extra):
    return ["--home", fx.home, "--repo", fx.repo, "--state", fx.state] + list(extra)


class TestExitCodes(unittest.TestCase):
    def test_drift_exits_one(self):
        with support.Fixture() as fx:
            code, out, _ = call(["check"] + base_args(fx, "--quiet"))
            self.assertEqual(code, EXIT_DRIFT)
            self.assertEqual(out, "")

    def test_a_clean_subset_exits_zero(self):
        with support.Fixture() as fx:
            for clean in (".bashrc", ".zshrc", ".profile", ".editorconfig"):
                code, _, _ = call(["check"] + base_args(fx, "--quiet", "--only", clean))
                self.assertEqual(code, EXIT_OK, "%s should be clean" % clean)

    def test_all_four_negative_controls_together_are_still_clean(self):
        with support.Fixture() as fx:
            args = base_args(fx, "--quiet")
            for clean in (".bashrc", ".zshrc", ".profile", ".editorconfig"):
                args += ["--only", clean]
            self.assertEqual(call(["check"] + args)[0], EXIT_OK)

    def test_a_missing_home_is_an_error_not_a_clean_result(self):
        with support.Fixture() as fx:
            code, _, err = call(["check", "--home", os.path.join(fx.dir, "nope"),
                                 "--repo", fx.repo, "--state", fx.state])
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("does not exist", err)

    def test_a_repo_without_the_tracked_subdir_is_an_actionable_error(self):
        with support.Fixture() as fx:
            code, _, err = call(["check", "--home", fx.home, "--repo", fx.dir,
                                 "--state", fx.state])
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("tracked_subdir", err)

    def test_no_arguments_prints_help_and_fails(self):
        code, out, _ = call([])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("usage", out)

    def test_info_only_findings_do_not_count_as_drift(self):
        with support.Fixture() as fx:
            code, _, _ = call(["check"] + base_args(fx, "--quiet", "--only", ".converged.conf"))
            self.assertEqual(code, EXIT_OK)


class TestJsonOutput(unittest.TestCase):
    def test_shape(self):
        with support.Fixture() as fx:
            code, out, _ = call(["check"] + base_args(fx, "--json"))
            self.assertEqual(code, EXIT_DRIFT)
            data = json.loads(out)
            for key in ("tool", "version", "checked", "findings", "ignored",
                        "severity_counts", "status_counts", "quoting", "baseline"):
                self.assertIn(key, data)
            self.assertEqual(data["tool"], "dotdrift")
            self.assertEqual(len(data["findings"]),
                             len(support.expectations(fx.scenario)))
            f = data["findings"][0]
            for key in ("path", "status", "direction", "severity", "action", "command"):
                self.assertIn(key, f)

    def test_json_says_the_quoting_mode(self):
        with support.Fixture() as fx:
            _, out, _ = call(["check"] + base_args(fx, "--json"))
            self.assertEqual(json.loads(out)["quoting"]["mode"], "hash only")


class TestBaselineWarning(unittest.TestCase):
    def test_a_missing_baseline_produces_a_loud_warning(self):
        with support.Fixture() as fx:
            os.remove(os.path.join(fx.state, "manifest.json"))
            code, out, _ = call(["check"] + base_args(fx))
            self.assertEqual(code, EXIT_DRIFT)
            self.assertIn("baseline MISSING", out)
            self.assertIn("no difference can be given a direction", out)

    def test_a_manifest_from_a_future_version_is_an_error(self):
        with support.Fixture() as fx:
            p = os.path.join(fx.state, "manifest.json")
            with open(p) as fh:
                data = json.load(fh)
            data["version"] = 99
            with open(p, "w") as fh:
                json.dump(data, fh)
            code, _, err = call(["check"] + base_args(fx))
            self.assertEqual(code, EXIT_ERROR)
            self.assertIn("version", err)


class TestSubcommands(unittest.TestCase):
    def test_sync_then_check_is_quieter(self):
        with support.Fixture() as fx:
            before = json.loads(call(["check"] + base_args(fx, "--json"))[1])
            code, out, _ = call(["sync"] + base_args(fx))
            self.assertEqual(code, EXIT_OK)
            self.assertIn("baseline written", out)
            after = json.loads(call(["check"] + base_args(fx, "--json"))[1])
            self.assertLess(len(after["findings"]), len(before["findings"]))

    def test_deny_appends_to_the_repo_config(self):
        with support.Fixture() as fx:
            code, out, _ = call(["deny", "--repo", fx.repo, "work/**"])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("never_quote", out)
            with open(os.path.join(fx.repo, "dotdrift.json")) as fh:
                self.assertIn("work/**", json.load(fh)["never_quote"])

    def test_capture_prints_what_it_refused(self):
        with support.Fixture() as fx:
            dest = os.path.join(fx.dir, "cap")
            code, out, _ = call(["capture"] + base_args(fx, "--dest", dest))
            self.assertEqual(code, EXIT_OK)
            self.assertIn("staged   .gitconfig", out)
            self.assertIn("refused  .npmrc", out)

    def test_apply_is_a_dry_run_without_yes(self):
        with support.Fixture() as fx:
            code, out, _ = call(["apply"] + base_args(fx))
            self.assertEqual(code, EXIT_OK)
            self.assertIn("dry run", out)
            self.assertIn("would apply  .vimrc", out)

    def test_html_writes_a_self_contained_page(self):
        with support.Fixture() as fx:
            outp = os.path.join(fx.dir, "r.html")
            code, _, _ = call(["html"] + base_args(fx, "-o", outp, "--home-label", "~",
                                                   "--repo-label", "dotfiles"))
            self.assertEqual(code, EXIT_OK)
            page = support.read_text(outp)
            self.assertIn("<!doctype html>", page)
            self.assertNotIn("http://", page.replace("http://www.w3.org", ""))
            self.assertNotIn("<script", page)
            self.assertNotIn(fx.home, page)
            self.assertIn("dotdrift example report", page)


class TestOnlyFilter(unittest.TestCase):
    def test_only_restricts_the_report(self):
        with support.Fixture() as fx:
            _, out, _ = call(["check"] + base_args(fx, "--json", "--only", ".ssh"))
            data = json.loads(out)
            self.assertTrue(data["findings"])
            for f in data["findings"]:
                self.assertTrue(f["path"].startswith(".ssh/"))

    def test_only_a_single_file(self):
        with support.Fixture() as fx:
            _, out, _ = call(["check"] + base_args(fx, "--json", "--only", ".gitconfig"))
            data = json.loads(out)
            self.assertEqual([f["path"] for f in data["findings"]], [".gitconfig"])


class TestSubprocessEntryPoint(unittest.TestCase):
    """The importable path and the executable path can diverge. Run the real
    script the way a cron hook would."""

    def test_bin_script_runs_from_an_unrelated_working_directory(self):
        with support.Fixture() as fx:
            proc = subprocess.run(
                [sys.executable, BIN, "check", "--home", fx.home, "--repo", fx.repo,
                 "--state", fx.state, "--quiet"],
                cwd=fx.dir, capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, EXIT_DRIFT, proc.stderr)
            self.assertEqual(proc.stdout, "")

    def test_module_entry_point(self):
        with support.Fixture() as fx:
            proc = subprocess.run(
                [sys.executable, "-m", "dotdrift", "check", "--home", fx.home,
                 "--repo", fx.repo, "--state", fx.state, "--quiet"],
                cwd=support.PROJECT, capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, EXIT_DRIFT, proc.stderr)

    def test_version_flag(self):
        proc = subprocess.run([sys.executable, BIN, "--version"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("dotdrift", proc.stdout)


if __name__ == "__main__":
    unittest.main()
