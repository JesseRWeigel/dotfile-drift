"""What the report is allowed to print.

The three layers, tested in order: hash-only by default, denylist over the
user's own quotable list, redactor over whatever survives both.
"""

import unittest

import support
from dotdrift import compare, manifest, policy as policymod, report


def run(fx, **kw):
    pol = policymod.load_policy(fx.repo)
    base, _ = manifest.load(fx.state)
    return compare.run(fx.home, fx.repo, pol, base, compare.Options(**kw)), pol


def quotes(res):
    return {f.path: f.quote for f in res.findings if f.quote is not None}


class TestDefaultIsHashOnly(unittest.TestCase):
    def test_nothing_is_quoted_without_the_flag(self):
        with support.Fixture() as fx:
            res, _ = run(fx)
            for path, q in quotes(res).items():
                self.assertFalse(q["shown"], "%s was quoted without --quote" % path)
                self.assertIn("--quote", q["reason"])

    def test_the_report_still_says_which_files_changed(self):
        with support.Fixture() as fx:
            res, _ = run(fx)
            ctx = {"home_label": "~", "repo_label": "dotfiles", "baseline": {"exists": True}}
            text = report.render_text(ctx, res)
            self.assertIn(".gitconfig", text)
            self.assertIn("local_edit", text)
            self.assertNotIn("lg = log --oneline", text)


class TestDenylistBeatsQuotable(unittest.TestCase):
    def test_npmrc_is_listed_as_quotable_and_still_withheld(self):
        with support.Fixture() as fx:
            res, pol = run(fx, quote=True)
            self.assertIn(".npmrc", pol.quotable)
            q = quotes(res)[".npmrc"]
            self.assertFalse(q["shown"])
            self.assertIn("denylisted", q["reason"])

    def test_the_withheld_content_appears_nowhere_in_any_rendering(self):
        with support.Fixture() as fx:
            res, _ = run(fx, quote=True)
            with open(fx.home + "/.npmrc", "r", encoding="utf-8") as fh:
                token_line = [l for l in fh if "authToken" in l][0].strip()
            secret = token_line.split("=", 1)[1]
            self.assertGreater(len(secret), 30)
            ctx = {"home_label": "~", "repo_label": "d", "baseline": {"exists": True}}
            for rendering in (report.render_text(ctx, res), report.render_json(ctx, res),
                              report.render_html(ctx, res)):
                self.assertNotIn(secret, rendering)


class TestRedactorPositiveControl(unittest.TestCase):
    def test_a_quotable_file_with_a_credential_gets_redacted_not_withheld(self):
        with support.Fixture() as fx:
            res, _ = run(fx, quote=True)
            q = quotes(res)[".config/apprc"]
            self.assertTrue(q["shown"])
            self.assertTrue(q["redacted"])
            self.assertIn("github-token", q["redaction_labels"])
            body = "\n".join(q["diff"])
            self.assertIn("[REDACTED:github-token]", body)
            # the surrounding, harmless change is still visible
            self.assertIn("theme = light", body)

    def test_the_raw_token_is_absent_from_every_rendering(self):
        with support.Fixture() as fx:
            res, _ = run(fx, quote=True)
            with open(fx.home + "/.config/apprc", "r", encoding="utf-8") as fh:
                token = [l for l in fh if "github_token" in l][0].split("=", 1)[1].strip()
            self.assertTrue(token.startswith("gh"))
            ctx = {"home_label": "~", "repo_label": "d", "baseline": {"exists": True}}
            for rendering in (report.render_text(ctx, res), report.render_json(ctx, res),
                              report.render_html(ctx, res)):
                self.assertNotIn(token, rendering)


class TestFencedContentIsNeverQuoted(unittest.TestCase):
    def test_the_diff_shows_the_placeholder_and_not_the_block(self):
        """The diff runs over the canonical form, so anything inside a
        machine-local fence has already been replaced before rendering."""
        with support.Fixture() as fx:
            res, _ = run(fx, quote=True)
            q = quotes(res)[".config/blockrc"]
            self.assertTrue(q["shown"])
            body = "\n".join(q["diff"])
            self.assertIn("[dotdrift:local-block:0]", body)
            self.assertIn("timeout = 60", body)
            self.assertNotIn("region = local-lab", body)
            with open(fx.home + "/.config/blockrc", "r", encoding="utf-8") as fh:
                key = [l for l in fh if "api_key" in l][0].split("=", 1)[1].strip()
            self.assertGreater(len(key), 20)
            self.assertNotIn(key, body)


class TestQuoteLimits(unittest.TestCase):
    def test_a_large_file_is_not_quoted(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            pol.max_quote_bytes = 10
            base, _ = manifest.load(fx.state)
            res = compare.run(fx.home, fx.repo, pol, base, compare.Options(quote=True))
            q = quotes(res)[".gitconfig"]
            self.assertFalse(q["shown"])
            self.assertIn("max_quote_bytes", q["reason"])

    def test_truncation_is_announced(self):
        with support.Fixture() as fx:
            pol = policymod.load_policy(fx.repo)
            pol.max_quote_lines = 3
            base, _ = manifest.load(fx.state)
            res = compare.run(fx.home, fx.repo, pol, base, compare.Options(quote=True))
            q = quotes(res)[".gitconfig"]
            self.assertTrue(q["shown"])
            self.assertTrue(q["truncated"])
            self.assertEqual(len(q["diff"]), 3)


class TestNoAbsolutePathsLeak(unittest.TestCase):
    def test_findings_carry_home_relative_paths_only(self):
        with support.Fixture() as fx:
            res, _ = run(fx, quote=True)
            for f in res.findings:
                self.assertFalse(f.path.startswith("/"))
            ctx = {"home_label": "~", "repo_label": "dotfiles", "baseline": {"exists": True}}
            text = report.render_text(ctx, res)
            self.assertNotIn(fx.home, text)
            self.assertNotIn(fx.repo, text)


if __name__ == "__main__":
    unittest.main()
