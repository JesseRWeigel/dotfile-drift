import unittest

import support  # noqa: F401
from dotdrift import normalize as N


class TestEol(unittest.TestCase):
    def test_crlf_becomes_lf(self):
        self.assertEqual(N.normalize_eol(b"a\r\nb\r\n"), b"a\nb\n")

    def test_lone_cr_becomes_lf(self):
        self.assertEqual(N.normalize_eol(b"a\rb\r"), b"a\nb\n")

    def test_missing_trailing_newline_is_added(self):
        self.assertEqual(N.normalize_eol(b"a"), b"a\n")

    def test_empty_stays_empty(self):
        self.assertEqual(N.normalize_eol(b""), b"")

    def test_canonicalize_reports_that_it_changed_the_endings(self):
        c = N.canonicalize(b"a\r\n")
        self.assertTrue(c.eol_normalised)
        self.assertFalse(N.canonicalize(b"a\n").eol_normalised)

    def test_no_normalize_leaves_the_bytes_alone(self):
        c = N.canonicalize(b"a\r\n", normalize=False)
        self.assertEqual(c.data, b"a\r\n")


class TestFences(unittest.TestCase):
    BEG, END = N.DEFAULT_BEGIN, N.DEFAULT_END

    def body(self, inner):
        return ("keep\n# %s\n%s\n# %s\ntail\n" % (self.BEG, inner, self.END)).encode()

    def test_block_contents_do_not_reach_the_canonical_form(self):
        c = N.canonicalize(self.body("SECRET_VALUE_INSIDE"))
        self.assertTrue(c.ok)
        self.assertNotIn(b"SECRET_VALUE_INSIDE", c.data)
        self.assertEqual(c.blocks_stripped, 1)
        self.assertIn(b"keep", c.data)
        self.assertIn(b"tail", c.data)

    def test_two_files_differing_only_inside_the_block_are_equal(self):
        a = N.canonicalize(self.body("one")).data
        b = N.canonicalize(self.body("two\nthree")).data
        self.assertEqual(a, b)

    def test_removing_a_whole_block_still_changes_the_canonical_form(self):
        a = N.canonicalize(self.body("one")).data
        b = N.canonicalize(b"keep\ntail\n").data
        self.assertNotEqual(a, b)

    def test_unclosed_fence_is_an_error_and_disables_stripping(self):
        c = N.canonicalize(("keep\n# %s\nrest\n" % self.BEG).encode())
        self.assertIn(N.ERR_UNCLOSED, c.errors)
        self.assertFalse(c.ok)
        # Failing closed: the tail is still compared rather than silently hidden.
        self.assertIn(b"rest", c.data)

    def test_end_without_begin_is_an_error(self):
        c = N.canonicalize(("keep\n# %s\n" % self.END).encode())
        self.assertIn(N.ERR_STRAY_END, c.errors)

    def test_nested_begin_is_an_error(self):
        c = N.canonicalize(("# %s\n# %s\n# %s\n" % (self.BEG, self.BEG, self.END)).encode())
        self.assertIn(N.ERR_NESTED, c.errors)

    def test_custom_markers(self):
        data = b"a\n# LOCAL-ON\nx\n# LOCAL-OFF\nb\n"
        c = N.canonicalize(data, begin="LOCAL-ON", end="LOCAL-OFF")
        self.assertEqual(c.blocks_stripped, 1)
        self.assertNotIn(b"x\n", c.data)

    def test_strip_local_can_be_turned_off(self):
        c = N.canonicalize(self.body("inside"), strip_local=False)
        self.assertIn(b"inside", c.data)


class TestBinary(unittest.TestCase):
    def test_nul_byte_marks_the_file_binary_and_skips_line_handling(self):
        data = b"a\x00b\r\n"
        c = N.canonicalize(data)
        self.assertTrue(c.is_binary)
        self.assertEqual(c.data, data)


class TestWhyEqual(unittest.TestCase):
    def test_eol_only(self):
        self.assertEqual(N.why_equal(b"a\r\nb\r\n", b"a\nb\n"), ("eol_only",))

    def test_local_block_only(self):
        a = ("x\n# %s\n1\n# %s\n" % (N.DEFAULT_BEGIN, N.DEFAULT_END)).encode()
        b = ("x\n# %s\n2\n# %s\n" % (N.DEFAULT_BEGIN, N.DEFAULT_END)).encode()
        self.assertEqual(N.why_equal(a, b), ("local_block_only",))

    def test_identical_input_has_no_reason(self):
        self.assertEqual(N.why_equal(b"a\n", b"a\n"), ())


if __name__ == "__main__":
    unittest.main()
