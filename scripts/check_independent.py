#!/usr/bin/env python3
"""Recompute the drift classification without using the package under test.

Two rules make this worth running:

  1. It imports nothing from `dotdrift`. The proof is not a grep, which a comment
     satisfies and `importlib.import_module` defeats. This script walks its own
     import graph with the `ast` module, follows the one dynamic import it is
     allowed to make, and fails if anything reaches the package.
  2. It arrives at the answer differently. `dotdrift` canonicalises by rewriting
     bytes and hashing them with sha256. This walks the tree with `pathlib`,
     tokenises into a tuple of surviving lines with `splitlines`, and fingerprints
     with blake2b. Same question, different machinery, so a bug in one is
     unlikely to be reproduced by the other.

It then compares three things against each other: what the tool reported, what
this script computed, and what `fixtures/scenario.json` says by hand. A validator
that only compares two derivations passes when both are wrong together, so the
hand-written expectations are the third leg.

Usage: check_independent.py [--verbose]
Exit code 0 means all three agree.
"""

import ast
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
PROJECT = HERE.parent
FORBIDDEN_PACKAGE = "dotdrift"

# The single dynamic import this script is permitted to make. It loads shared
# INPUT (the fixture materialiser), never shared DERIVATION.
ALLOWED_DYNAMIC = {str((HERE / "fixture_home.py").resolve())}

FENCE_BEGIN = "dotdrift:local-begin"
FENCE_END = "dotdrift:local-end"


# --------------------------------------------------------------------------
# Part 1: prove the import graph is clean, using ast rather than grep.
# --------------------------------------------------------------------------

def _eval_path(node, env, srcfile):
    """Fold the small subset of path expressions this project uses.

    Only enough to resolve `str(HERE / "fixture_home.py")` at parse time. Anything
    it cannot fold returns None, and the caller treats that as a failure rather
    than as permission.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return os.path.abspath(srcfile)
        return env.get(node.id)
    if isinstance(node, ast.Attribute):
        if node.attr == "parent":
            base = _eval_path(node.value, env, srcfile)
            return os.path.dirname(base) if base else None
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _eval_path(node.left, env, srcfile)
        right = _eval_path(node.right, env, srcfile)
        return os.path.join(left, right) if left and right else None
    if isinstance(node, ast.Call):
        f = node.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
        if name in ("str", "resolve", "absolute"):
            target = node.args[0] if node.args else (f.value if isinstance(f, ast.Attribute) else None)
            return _eval_path(target, env, srcfile) if target is not None else None
        if name == "Path":
            return _eval_path(node.args[0], env, srcfile) if node.args else None
        if name in ("join", "abspath", "dirname"):
            parts = [_eval_path(a, env, srcfile) for a in node.args]
            if not all(parts):
                return None
            if name == "join":
                return os.path.join(*parts)
            if name == "abspath":
                return os.path.abspath(parts[0])
            return os.path.dirname(parts[0])
    return None


def _module_env(tree, srcfile):
    env = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            val = _eval_path(node.value, env, srcfile)
            if val:
                env[node.targets[0].id] = val
    return env


class ImportWalk:
    def __init__(self):
        self.static = {}          # module name -> [(file, lineno)]
        self.dynamic = []         # (file, lineno, kind, resolved paths, all_args_known)
        self.visited = set()

    def visit_file(self, path: str):
        path = str(pathlib.Path(path).resolve())
        if path in self.visited:
            return
        self.visited.add(path)
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        env = _module_env(tree, path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.static.setdefault(alias.name, []).append((path, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    # A relative import inside a script would resolve against the
                    # script's own directory. Record it so it cannot hide.
                    name = "." * node.level + (node.module or "")
                else:
                    name = node.module or ""
                self.static.setdefault(name, []).append((path, node.lineno))
            elif isinstance(node, ast.Call):
                kind = _dynamic_kind(node)
                if kind:
                    args = list(node.args) + [kw.value for kw in node.keywords]
                    folded = [_eval_path(a, env, path) for a in args]
                    resolved = {os.path.realpath(v) for v in folded if v}
                    resolved |= {v for v in folded if v}
                    self.dynamic.append((path, node.lineno, kind, resolved,
                                         all(v is not None for v in folded)))


def _dynamic_kind(node: ast.Call):
    f = node.func
    if isinstance(f, ast.Name) and f.id in ("__import__", "exec", "eval", "compile"):
        return f.id
    if isinstance(f, ast.Attribute):
        if f.attr in ("import_module", "spec_from_file_location", "exec_module",
                      "module_from_spec", "load_module", "SourceFileLoader"):
            return f.attr
    return None


def prove_no_package_imports(entry: str, verbose=False):
    walk = ImportWalk()
    walk.visit_file(entry)
    # Follow the one dynamic file load we allow, so its imports are checked too.
    for path in sorted(ALLOWED_DYNAMIC):
        walk.visit_file(path)

    problems = []
    for name, sites in sorted(walk.static.items()):
        root = name.lstrip(".").split(".")[0]
        for f, ln in sites:
            rel = os.path.relpath(f, PROJECT)
            if root == FORBIDDEN_PACKAGE:
                problems.append("%s:%d imports %s" % (rel, ln, name))
            elif name.startswith("."):
                problems.append("%s:%d uses a relative import, which could resolve into "
                                "the package" % (rel, ln))
            elif root not in sys.stdlib_module_names:
                # Nothing here recurses into third-party or local modules, so an
                # import that is not stdlib is an unproved edge in the graph. A
                # module we do not walk could import the package on our behalf.
                problems.append("%s:%d imports %r, which is neither stdlib nor walked, "
                                "so its own imports are unproved" % (rel, ln, name))

    for f, ln, kind, resolved, all_known in walk.dynamic:
        rel = os.path.relpath(f, PROJECT)
        if kind in ("exec", "eval", "compile", "__import__"):
            problems.append("%s:%d uses %s(), which can import anything" % (rel, ln, kind))
            continue
        if kind in ("exec_module", "module_from_spec"):
            continue  # these take a spec produced by an already-checked call
        if not all_known:
            problems.append("%s:%d calls %s() with an argument this checker cannot fold, "
                            "so the import graph cannot be proved" % (rel, ln, kind))
            continue
        if not (resolved & ALLOWED_DYNAMIC):
            problems.append("%s:%d dynamically loads %s, which is not on the allow list"
                            % (rel, ln, sorted(resolved)))

    if verbose:
        print("  import graph: %d files, %d distinct static imports, %d dynamic calls"
              % (len(walk.visited), len(walk.static), len(walk.dynamic)))
        print("  files walked: %s"
              % ", ".join(sorted(os.path.relpath(p, PROJECT) for p in walk.visited)))
        print("  static imports: %s" % ", ".join(sorted(walk.static)))
    return problems


# --------------------------------------------------------------------------
# Part 2: recompute the classification by a different route.
# --------------------------------------------------------------------------

def load_fixture_builder():
    spec = importlib.util.spec_from_file_location(
        "fixture_home_indep", str(HERE / "fixture_home.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def inside(root: pathlib.Path, target: pathlib.Path) -> bool:
    try:
        return os.path.commonpath([str(root.resolve()), str(target.resolve())]) == \
            str(root.resolve())
    except ValueError:
        return False


def token_fingerprint(data: bytes):
    """Canonical form as a tuple of surviving lines, fingerprinted with blake2b.

    `splitlines` handles CRLF, lone CR and the missing final newline in one step,
    which is a different mechanism from the byte rewriting the package does.
    """
    if b"\x00" in data:
        return "binary:" + hashlib.blake2b(data, digest_size=16).hexdigest()
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    kept, blocks, depth, broken = [], 0, 0, False
    for line in lines:
        if FENCE_BEGIN in line and FENCE_END in line:
            if depth == 0:
                blocks += 1
            continue
        if FENCE_BEGIN in line:
            if depth == 0:
                blocks += 1
            depth += 1
            continue
        if FENCE_END in line:
            if depth == 0:
                broken = True
                kept.append(line)
                continue
            depth -= 1
            continue
        if depth == 0:
            kept.append(line)
    if depth != 0 or broken:
        # Unbalanced markers: fall back to every line, matching the fail-closed rule.
        kept, blocks = list(lines), 0
    payload = repr((tuple(kept), blocks)).encode("utf-8")
    return hashlib.blake2b(payload, digest_size=16).hexdigest()


def raw_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect(home: pathlib.Path, repo_tracked: pathlib.Path, rel: str, roots):
    """Return a small record for one path, reading only what containment allows."""
    p = home / rel
    rec = {"kind": "missing", "mode": None, "raw": None, "token": None,
           "target": None, "escapes": False}
    if not p.is_symlink() and not p.exists():
        return rec
    if p.is_symlink():
        rec["kind"] = "symlink"
        rec["target"] = os.readlink(p)
        real = pathlib.Path(os.path.realpath(p))
        if not any(inside(r, real) for r in roots):
            rec["escapes"] = True
            return rec
        if not real.exists():
            return rec
        rec["mode"] = real.stat().st_mode & 0o777
        data = real.read_bytes()
    else:
        if p.is_dir():
            rec["kind"] = "dir"
            return rec
        rec["kind"] = "file"
        rec["mode"] = p.stat().st_mode & 0o777
        data = p.read_bytes()
    rec["raw"] = raw_sha256(data)
    rec["token"] = token_fingerprint(data)
    return rec


CONTENT_LABEL = {
    (True, False): "local_edit",
    (False, True): "upstream_change",
    (True, True): "conflict",
    (False, False): "unsynced_differs",
}


def recompute(paths):
    home = pathlib.Path(paths["home"])
    repo = pathlib.Path(paths["repo"])
    tracked = repo / "home"
    state = pathlib.Path(paths["state"])
    with open(state / "manifest.json", "r", encoding="utf-8") as fh:
        baseline = json.load(fh)["entries"]

    rels = sorted({str(p.relative_to(tracked)) for p in tracked.rglob("*") if p.is_file()}
                  | set(baseline))
    roots = [home, repo]

    out = {"content": {}, "kind_changed": set(), "mode_changed": set(),
           "insecure": set(), "missing_local": set(), "missing_repo": set(),
           "escapes": set(), "converged": set(), "unchanged": set()}

    for rel in rels:
        h = inspect(home, tracked, rel, roots)
        r_path = tracked / rel
        base = baseline.get(rel)

        if h["escapes"]:
            out["escapes"].add(rel)
            continue
        r_exists = r_path.is_file()
        if h["kind"] == "missing" and not r_exists:
            continue
        if h["kind"] == "missing":
            out["missing_local"].add(rel)
            continue
        if not r_exists:
            out["missing_repo"].add(rel)
        else:
            r_data = r_path.read_bytes()
            r_raw, r_tok = raw_sha256(r_data), token_fingerprint(r_data)
            if h["token"] == r_tok:
                if base and h["raw"] != base.get("raw") and r_raw != base.get("raw"):
                    out["converged"].add(rel)
                else:
                    out["unchanged"].add(rel)
            elif base is None:
                out["content"][rel] = "unsynced_differs"
            else:
                out["content"][rel] = CONTENT_LABEL[
                    (h["raw"] != base.get("raw"), r_raw != base.get("raw"))]

        if base:
            if base.get("kind") != h["kind"]:
                out["kind_changed"].add(rel)
            bm = base.get("mode")
            if bm is not None and h["mode"] is not None and int(bm, 8) != h["mode"]:
                out["mode_changed"].add(rel)
        if h["mode"] is not None and (h["mode"] & 0o077) and rel.startswith(".ssh/"):
            out["insecure"].add(rel)
    return out


def tool_report(paths):
    """Run the CLI as a subprocess. Running a program is not importing it."""
    proc = subprocess.run(
        [sys.executable, str(PROJECT / "bin" / "dotdrift"), "check",
         "--home", paths["home"], "--repo", paths["repo"], "--state", paths["state"],
         "--json"],
        capture_output=True, text=True, timeout=180)
    if proc.returncode not in (0, 1):
        raise SystemExit("the tool failed to run (exit %d):\n%s"
                         % (proc.returncode, proc.stderr))
    return json.loads(proc.stdout)


def main(argv):
    verbose = "--verbose" in argv
    failures = []

    print("1. import graph (ast, not grep)")
    problems = prove_no_package_imports(__file__, verbose=verbose)
    if problems:
        failures.extend(problems)
        for p in problems:
            print("   FAIL %s" % p)
    else:
        print("   ok, nothing in this script's import graph reaches %r" % FORBIDDEN_PACKAGE)

    builder = load_fixture_builder()
    with tempfile.TemporaryDirectory(prefix="dotdrift-indep-") as tmp:
        paths = builder.materialize(os.path.join(tmp, "tree"))
        scenario = paths["scenario"]
        mine = recompute(paths)
        theirs = tool_report(paths)

        by_path = {}
        for f in theirs["findings"]:
            by_path.setdefault(f["path"], set()).add(f["status"])

        print("2. content classification, recomputed with blake2b over line tuples")
        content_statuses = set(CONTENT_LABEL.values())
        theirs_content = {p: (s & content_statuses).pop()
                          for p, s in by_path.items() if s & content_statuses}
        if theirs_content != mine["content"]:
            for p in sorted(set(theirs_content) | set(mine["content"])):
                a, b = theirs_content.get(p), mine["content"].get(p)
                if a != b:
                    failures.append("content mismatch %s: tool=%s independent=%s" % (p, a, b))
                    print("   FAIL %s tool=%s independent=%s" % (p, a, b))
        else:
            print("   ok, %d content classifications agree" % len(mine["content"]))

        print("3. structural axes: kind, mode, existence, containment")
        checks = [
            ("symlink kind change", mine["kind_changed"],
             {p for p, s in by_path.items()
              if s & {"symlink_replaced_by_copy", "copy_replaced_by_symlink",
                      "symlink_retargeted"}}),
            ("mode change", mine["mode_changed"],
             {p for p, s in by_path.items() if "mode_drift" in s}),
            ("missing from the machine", mine["missing_local"],
             {p for p, s in by_path.items() if s & {"missing_locally", "never_installed"}}),
            ("missing from the repo", mine["missing_repo"],
             {p for p, s in by_path.items() if "missing_in_repo" in s}),
            ("escaping symlink", mine["escapes"],
             {p for p, s in by_path.items() if "symlink_escape" in s}),
            ("converged", mine["converged"],
             {p for p, s in by_path.items() if "converged" in s}),
        ]
        for label, a, b in checks:
            if a != b:
                failures.append("%s: independent=%s tool=%s" % (label, sorted(a), sorted(b)))
                print("   FAIL %s independent=%s tool=%s" % (label, sorted(a), sorted(b)))
            else:
                print("   ok, %-28s %d path(s)" % (label + ",", len(a)))

        print("4. both against the hand-written scenario expectations")
        expected = {}
        for rel, spec in scenario["paths"].items():
            for st in spec.get("expect", []):
                expected.setdefault(rel, set()).add(st)
        if expected != by_path:
            for p in sorted(set(expected) | set(by_path)):
                if expected.get(p, set()) != by_path.get(p, set()):
                    failures.append("scenario mismatch %s: expected=%s tool=%s"
                                    % (p, sorted(expected.get(p, [])), sorted(by_path.get(p, []))))
                    print("   FAIL %s expected=%s tool=%s"
                          % (p, sorted(expected.get(p, [])), sorted(by_path.get(p, []))))
        else:
            print("   ok, %d paths match scenario.json" % len(expected))

        print("5. negative controls")
        clean = [rel for rel, spec in scenario["paths"].items() if not spec.get("expect")]
        if len(clean) < 4:
            failures.append("fewer than four negative controls in the fixture")
        for rel in sorted(clean):
            flagged = rel in by_path or rel in mine["content"]
            if flagged:
                failures.append("negative control %s was flagged" % rel)
                print("   FAIL %s was flagged" % rel)
            else:
                print("   ok, %s is clean in both computations" % rel)

        print("6. the escaped file's content never appears in the tool's output")
        marker = "DOTDRIFT_MUST_NEVER_READ_THIS_MARKER"
        blob = json.dumps(theirs)
        if marker in blob:
            failures.append("content of a file outside the tracked tree reached the report")
            print("   FAIL marker found in the report")
        else:
            print("   ok, marker absent")

    print()
    if failures:
        print("INDEPENDENT CHECK FAILED with %d problem(s)" % len(failures))
        return 1
    print("INDEPENDENT CHECK PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
