"""Command line interface.

    dotdrift check     compare, print, exit 1 if anything drifted
    dotdrift sync      record the current machine state as the baseline
    dotdrift capture   stage machine-ahead files for review
    dotdrift apply     write repo-ahead files onto the machine
    dotdrift deny      add a glob to the never-quote list
    dotdrift html      write the report as a self-contained page

Exit codes: 0 nothing to do, 1 drift found, 2 the tool could not do its job.
The 1-versus-2 split is what makes a weekly cron hook useful. A crash and a clean
machine must never share an exit code.
"""

import argparse
import json
import os
import sys

from . import EXIT_DRIFT, EXIT_ERROR, EXIT_OK, __version__, actions, compare, manifest, policy as policymod, report


def _add_common(p):
    p.add_argument("--home", default=None, help="home directory to inspect (default: $HOME)")
    p.add_argument("--repo", default=None, help="dotfiles repo root (default: $DOTDRIFT_REPO or cwd)")
    p.add_argument("--state", default=None, help="state directory holding the baseline manifest")
    p.add_argument("--only", action="append", default=[], metavar="PATH",
                   help="restrict to this home-relative path or directory, repeatable")
    p.add_argument("--no-normalize", action="store_true",
                   help="treat line-ending and trailing-newline differences as drift")
    p.add_argument("--no-local-blocks", action="store_true",
                   help="compare inside machine-local fences too")
    p.add_argument("--no-untracked", action="store_true",
                   help="skip the directory listing that finds newly added files")


def build_parser():
    p = argparse.ArgumentParser(prog="dotdrift", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="dotdrift " + __version__)
    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser("check", help="report drift")
    _add_common(c)
    c.add_argument("--quote", action="store_true",
                   help="show content for paths you marked quotable (denylist still wins)")
    c.add_argument("--json", action="store_true", help="machine-readable output")
    c.add_argument("--quiet", action="store_true", help="print nothing, use the exit code")
    c.add_argument("--hide-ignored", action="store_true", help="omit the noise section")

    s = sub.add_parser("sync", help="record the current machine state as the baseline")
    _add_common(s)

    cap = sub.add_parser("capture", help="stage machine-ahead files for review")
    _add_common(cap)
    cap.add_argument("--dest", default=None, help="staging directory (default: ./dotdrift-capture)")
    cap.add_argument("--include-untracked", action="store_true")

    ap = sub.add_parser("apply", help="write repo-ahead files onto the machine")
    _add_common(ap)
    ap.add_argument("--yes", action="store_true", help="actually do it, otherwise dry run")

    d = sub.add_parser("deny", help="add a glob to the never-quote list")
    d.add_argument("pattern")
    d.add_argument("--repo", default=None)

    h = sub.add_parser("html", help="write the report as a self-contained page")
    _add_common(h)
    h.add_argument("--quote", action="store_true")
    h.add_argument("-o", "--output", required=True)
    h.add_argument("--home-label", default=None, help="what to print instead of the real home path")
    h.add_argument("--repo-label", default=None)
    return p


def resolve_roots(args):
    home = os.path.abspath(os.path.expanduser(args.home or os.environ.get("DOTDRIFT_HOME") or "~"))
    repo = os.path.abspath(os.path.expanduser(
        args.repo or os.environ.get("DOTDRIFT_REPO") or os.getcwd()))
    state = args.state or os.environ.get("DOTDRIFT_STATE") or manifest.default_state_dir()
    return home, repo, os.path.abspath(os.path.expanduser(state))


def load_all(args):
    home, repo, state = resolve_roots(args)
    if not os.path.isdir(home):
        raise SystemExit2("home directory does not exist: %s" % report.collapse_home(home))
    if not os.path.isdir(repo):
        raise SystemExit2("repo directory does not exist: %s" % report.collapse_home(repo))
    pol = policymod.load_policy(repo)
    tracked_root = os.path.join(repo, pol.tracked_subdir)
    if not os.path.isdir(tracked_root):
        raise SystemExit2(
            "repo has no '%s' directory. dotdrift expects your dotfiles under "
            "<repo>/%s mirroring your home tree, or set tracked_subdir in dotdrift.json."
            % (pol.tracked_subdir, pol.tracked_subdir))
    base, meta = manifest.load(state)
    opts = compare.Options(
        quote=getattr(args, "quote", False),
        normalize=not args.no_normalize,
        strip_local=not args.no_local_blocks,
        untracked=not args.no_untracked,
        only=tuple(args.only),
    )
    return home, repo, state, pol, base, meta, opts


class SystemExit2(Exception):
    pass


def _context(home, repo, pol, meta, opts, home_label=None, repo_label=None):
    return {
        "home_label": home_label or report.collapse_home(home),
        "repo_label": repo_label or report.collapse_home(repo),
        "baseline": meta,
        "quoting": {
            "mode": "content shown only for quotable paths" if opts.quote else "hash only",
            "quotable_globs": len(pol.quotable),
            "denylist_globs": len(pol.never_quote),
            "normalize_eol": opts.normalize,
            "strip_local_blocks": opts.strip_local,
        },
    }


def cmd_check(args):
    home, repo, state, pol, base, meta, opts = load_all(args)
    res = compare.run(home, repo, pol, base, opts)
    res.warnings.extend(pol.warnings)
    if not meta.get("exists"):
        res.warnings.append(
            "no baseline at %s, so no difference can be given a direction. "
            "Run `dotdrift sync` once the repo and this machine agree."
            % report.collapse_home(meta.get("path", "")))
    ctx = _context(home, repo, pol, meta, opts)
    if args.json:
        sys.stdout.write(report.render_json(ctx, res))
    elif not args.quiet:
        sys.stdout.write(report.render_text(ctx, res, show_ignored=not args.hide_ignored))
    return EXIT_DRIFT if res.drift else EXIT_OK


def cmd_sync(args):
    home, repo, state, pol, base, meta, opts = load_all(args)
    out = actions.sync(home, repo, pol, state, opts, previous=base)
    print("baseline written to %s" % report.collapse_home(out["path"]))
    print("%d entries recorded, %d paths skipped" % (out["entries"], len(out["skipped"])))
    if out["disagree"]:
        print("note: %d paths still differ between repo and machine. They were recorded as"
              % len(out["disagree"]))
        print("      the machine has them, so they will report as upstream_change until you")
        print("      reconcile them: %s" % ", ".join(out["disagree"][:10]))
    return EXIT_OK


def cmd_capture(args):
    home, repo, state, pol, base, meta, opts = load_all(args)
    res = compare.run(home, repo, pol, base, opts)
    dest = os.path.abspath(args.dest or os.path.join(os.getcwd(), "dotdrift-capture"))
    out = actions.capture(home, repo, res, pol, dest, include_untracked=args.include_untracked)
    print("staged %d files under %s" % (len(out["staged"]), report.collapse_home(dest)))
    for p in out["staged"]:
        print("  staged   %s" % p)
    for p, why in out["refused"]:
        print("  refused  %s  (%s)" % (p, why))
    for p, why in out["skipped"]:
        print("  skipped  %s  (%s)" % (p, why))
    if out["refused"]:
        print("Refused paths are never copied. Move them by hand if you really want them in a repo.")
    return EXIT_OK


def cmd_apply(args):
    home, repo, state, pol, base, meta, opts = load_all(args)
    res = compare.run(home, repo, pol, base, opts)
    out = actions.apply(home, repo, res, pol, state, confirm=args.yes)
    if out["dry_run"]:
        print("dry run, nothing was written. Add --yes to perform these:")
        for p, st in out["planned"]:
            print("  would apply  %s  (%s)" % (p, st))
    else:
        print("backups under %s" % report.collapse_home(out["backup_dir"] or "(none needed)"))
        for p, what in out["applied"]:
            print("  applied  %s  (%s)" % (p, what))
    for p, why in out["refused"]:
        print("  refused  %s  (%s)" % (p, why))
    return EXIT_OK


def cmd_deny(args):
    repo = os.path.abspath(os.path.expanduser(
        args.repo or os.environ.get("DOTDRIFT_REPO") or os.getcwd()))
    path = policymod.append_never_quote(repo, args.pattern)
    print("added %r to never_quote in %s" % (args.pattern, report.collapse_home(path)))
    return EXIT_OK


def cmd_html(args):
    home, repo, state, pol, base, meta, opts = load_all(args)
    res = compare.run(home, repo, pol, base, opts)
    ctx = _context(home, repo, pol, meta, opts, args.home_label, args.repo_label)
    out = report.render_html(ctx, res)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(out)
    print("wrote %d bytes to %s" % (len(out), os.path.basename(args.output)))
    return EXIT_OK


HANDLERS = {
    "check": cmd_check, "sync": cmd_sync, "capture": cmd_capture,
    "apply": cmd_apply, "deny": cmd_deny, "html": cmd_html,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    if not argv:
        parser.print_help()
        return EXIT_ERROR
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help()
        return EXIT_ERROR
    try:
        return HANDLERS[args.cmd](args)
    except SystemExit2 as exc:
        sys.stderr.write("dotdrift: %s\n" % exc)
        return EXIT_ERROR
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        # Never let a failure to check look like a clean machine.
        sys.stderr.write("dotdrift: could not complete the check: %s\n" % exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
