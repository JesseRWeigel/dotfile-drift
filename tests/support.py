"""Shared test helpers. Materialises the fixture home into a temp directory."""

import importlib.util
import os
import shutil
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

_spec = importlib.util.spec_from_file_location(
    "fixture_home", os.path.join(PROJECT, "scripts", "fixture_home.py"))
fixture_home = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture_home)


class Fixture:
    """A materialised fixture home that cleans itself up."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="dotdrift-test-")
        self.paths = fixture_home.materialize(os.path.join(self.dir, "tree"))
        self.home = self.paths["home"]
        self.repo = self.paths["repo"]
        self.state = self.paths["state"]
        self.outside = self.paths["outside"]
        self.scenario = self.paths["scenario"]

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def expectations(scenario, key="expect"):
    return fixture_home.expectations(scenario, key)


OUTSIDE_MARKER = "DOTDRIFT_MUST_NEVER_READ_THIS_MARKER"


def read_text(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()
