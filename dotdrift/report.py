"""Rendering. Text for humans, JSON for hooks, HTML for a published page.

Paths are always printed home-relative. The roots appear once in the header, with
`$HOME` collapsed to `~`, because verify output and example reports get pasted
into READMEs and an absolute `/home/<user>/...` there is both private and
unportable.
"""

import html
import json
import os

from . import __version__

SEV_LABEL = {"high": "HIGH", "warn": "WARN", "info": "INFO"}


def collapse_home(path: str) -> str:
    home = os.path.expanduser("~")
    if home and path == home:
        return "~"
    if home and path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def header_lines(ctx, res):
    base = ctx.get("baseline") or {}
    if base.get("exists"):
        b = "baseline %s (%d entries)" % (base.get("synced_at") or "unknown time", len(res.baseline))
    else:
        b = "baseline MISSING, direction cannot be determined for any difference"
    return [
        "dotdrift %s" % __version__,
        "home %s" % ctx["home_label"],
        "repo %s" % ctx["repo_label"],
        b,
    ]


def to_json(ctx, res):
    return {
        "tool": "dotdrift",
        "version": __version__,
        "home": ctx["home_label"],
        "repo": ctx["repo_label"],
        "baseline": {
            "present": bool((ctx.get("baseline") or {}).get("exists")),
            "synced_at": (ctx.get("baseline") or {}).get("synced_at"),
            "entries": len(res.baseline),
        },
        "checked": res.checked,
        "unchanged": res.unchanged,
        "severity_counts": res.severity_counts(),
        "status_counts": res.counts(),
        "findings": [f.to_json() for f in res.findings],
        "ignored": [i.to_json() for i in res.ignored],
        "warnings": list(res.warnings),
        "quoting": ctx.get("quoting", {}),
    }


def render_json(ctx, res) -> str:
    return json.dumps(to_json(ctx, res), indent=2, sort_keys=True) + "\n"


def render_text(ctx, res, show_ignored: bool = True) -> str:
    out = []
    for line in header_lines(ctx, res):
        out.append(line)
    sc = res.severity_counts()
    out.append("checked %d paths, %d clean, %d high, %d warn, %d info"
               % (res.checked, res.unchanged, sc["high"], sc["warn"], sc["info"]))
    for w in res.warnings:
        out.append("warning: %s" % w)
    out.append("")

    if not res.findings:
        out.append("no drift")
    for f in res.findings:
        out.append("%-4s %s" % (SEV_LABEL[f.severity], f.path))
        out.append("     %s [%s]" % (f.summary, f.status))
        d = f.detail
        bits = []
        if d.get("repo_hash") or d.get("home_hash") or d.get("base_hash"):
            bits.append("repo %s  home %s  base %s"
                        % (d.get("repo_hash", "-"), d.get("home_hash", "-"), d.get("base_hash", "-")))
        kinds = "%s/%s/%s" % (d.get("repo_kind") or "-", d.get("home_kind") or "-", d.get("base_kind") or "-")
        bits.append("kind repo/home/base %s" % kinds)
        if d.get("from_mode"):
            bits.append("mode %s -> %s" % (d["from_mode"], d["to_mode"]))
        elif d.get("home_mode") and d.get("base_mode"):
            bits.append("mode %s (baseline %s)" % (d["home_mode"], d["base_mode"]))
        if d.get("offending_bits"):
            bits.append("forbidden bits %s set" % d["offending_bits"])
        if d.get("home_link_target"):
            bits.append("link -> %s" % d["home_link_target"])
        if d.get("errors"):
            bits.append("errors %s" % ",".join(d["errors"]))
        if d.get("reason"):
            bits.append("reason %s" % d["reason"])
        out.append("     %s" % "  ".join(bits))
        out.append("     direction %s -> %s" % (f.direction, f.action))
        out.append("     run: %s%s" % (f.command, "   (overwrites the live file)" if f.destructive else ""))
        if f.quote is not None:
            if f.quote.get("shown"):
                note = " (redacted: %s)" % ", ".join(f.quote["redaction_labels"]) if f.quote.get("redacted") else ""
                out.append("     content%s:" % note)
                for line in f.quote["diff"]:
                    out.append("       | %s" % line)
                if f.quote.get("truncated"):
                    out.append("       | ... truncated at max_quote_lines")
            else:
                out.append("     content withheld: %s" % f.quote["reason"])
        out.append("")

    if show_ignored and res.ignored:
        out.append("ignored as noise (%d):" % len(res.ignored))
        for i in res.ignored:
            out.append("  %s  %s" % (i.path, i.note))
        out.append("  re-run with --no-normalize to treat line-ending noise as drift")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def render_html(ctx, res) -> str:
    """A self-contained page. No external requests, light and dark, and it never
    prints anything the text report would have withheld."""
    data = to_json(ctx, res)
    e = html.escape
    sc = data["severity_counts"]
    rows = []
    for f in data["findings"]:
        d = f["detail"]
        quote_html = ""
        q = f.get("quote")
        if q and q.get("shown"):
            note = ""
            if q.get("redacted"):
                note = '<p class="redact">redactor fired: %s</p>' % e(", ".join(q["redaction_labels"]))
            quote_html = '<div class="quote">%s<pre>%s</pre></div>' % (
                note, e("\n".join(q["diff"])))
        elif q:
            quote_html = '<p class="withheld">content withheld: %s</p>' % e(q["reason"])
        rows.append(
            '<article class="f {sev}">'
            '<header><span class="sev">{sevl}</span><code>{path}</code>'
            '<span class="status">{status}</span></header>'
            '<p class="summary">{summary}</p>'
            '<p class="meta">repo <code>{rh}</code> home <code>{hh}</code> base <code>{bh}</code>'
            ' &middot; kind repo/home/base <code>{kinds}</code>'
            ' &middot; direction <b>{dir}</b></p>'
            '<p class="action">{action}</p>'
            '<p class="cmd"><code>{cmd}</code>{destr}</p>'
            '{quote}</article>'.format(
                sev=e(f["severity"]), sevl=e(SEV_LABEL[f["severity"]]), path=e(f["path"]),
                status=e(f["status"]), summary=e(f["summary"]),
                rh=e(d.get("repo_hash", "-")), hh=e(d.get("home_hash", "-")),
                bh=e(d.get("base_hash", "-")),
                kinds=e("%s/%s/%s" % (d.get("repo_kind") or "-", d.get("home_kind") or "-",
                                      d.get("base_kind") or "-")),
                dir=e(f["direction"]), action=e(f["action"]), cmd=e(f["command"]),
                destr=' <span class="destr">overwrites the live file</span>' if f["destructive"] else "",
                quote=quote_html))

    ignored = "".join(
        '<li><code>%s</code> %s</li>' % (e(i["path"]), e(i["note"])) for i in data["ignored"])
    if ignored:
        ignored = ('<section id="ignored"><h2>Ignored as noise</h2><ul>%s</ul>'
                   '<p class="hint">Re-run with <code>--no-normalize</code> to treat line-ending '
                   'noise as drift.</p></section>' % ignored)

    quoting = data.get("quoting", {})
    qsummary = ("<li>%s</li>" % e(k + ": " + str(v)) for k, v in sorted(quoting.items()))

    return TEMPLATE.format(
        checked=data["checked"], clean=data["unchanged"],
        high=sc["high"], warn=sc["warn"], info=sc["info"],
        home=e(data["home"]), repo=e(data["repo"]),
        baseline=e(str(data["baseline"]["synced_at"] or "missing")),
        entries=data["baseline"]["entries"],
        rows="".join(rows), ignored=ignored, quoting="".join(qsummary),
        json_blob=e(json.dumps(data, indent=2, sort_keys=True)),
    )


TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dotdrift example report</title>
<style>
:root {{
  color-scheme: light dark;
  --bg: #fbfaf7; --fg: #1c1b19; --muted: #5f5b54; --line: #ddd8cf; --card: #fff;
  --high: #a3231b; --warn: #8a5a00; --info: #3a5f7d; --code: #f2efe9;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg: #14150f; --fg: #e9e6df; --muted: #a09a90; --line: #2f312a;
           --card: #1b1d16; --high: #ef6f65; --warn: #d7a44a; --info: #7fb0d1; --code: #23261e; }}
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
main {{ max-width: 62rem; margin: 0 auto; padding: 2rem 1.1rem 4rem; }}
h1 {{ font-size: 1.5rem; margin: 0 0 .3rem; }}
h2 {{ font-size: 1.05rem; margin: 2rem 0 .6rem; text-transform: uppercase;
  letter-spacing: .09em; color: var(--muted); }}
p.lede {{ color: var(--muted); margin: 0 0 1.4rem; max-width: 46rem; }}
.tiles {{ display: grid; gap: .6rem; grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr)); }}
.tile {{ border: 1px solid var(--line); background: var(--card); padding: .7rem .8rem; border-radius: 3px; }}
.tile b {{ display: block; font-size: 1.5rem; line-height: 1.1; }}
.tile span {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .07em; }}
dl.ctx {{ display: grid; grid-template-columns: auto 1fr; gap: .15rem .9rem; margin: 1.2rem 0 0; }}
dl.ctx dt {{ color: var(--muted); }}
dl.ctx dd {{ margin: 0; }}
article.f {{ border: 1px solid var(--line); border-left: 4px solid var(--info);
  background: var(--card); padding: .7rem .9rem; margin: .6rem 0; border-radius: 3px; }}
article.high {{ border-left-color: var(--high); }}
article.warn {{ border-left-color: var(--warn); }}
article.f header {{ display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }}
.sev {{ font-weight: 700; font-size: .78rem; letter-spacing: .08em; }}
.high .sev {{ color: var(--high); }} .warn .sev {{ color: var(--warn); }} .info .sev {{ color: var(--info); }}
.status {{ color: var(--muted); font-size: .8rem; }}
.summary {{ margin: .35rem 0; }}
.meta, .cmd, .action {{ margin: .2rem 0; color: var(--muted); font-size: .87rem; }}
.action {{ color: var(--fg); }}
code {{ background: var(--code); padding: .05rem .3rem; border-radius: 2px; }}
.destr {{ color: var(--high); }}
.withheld {{ color: var(--muted); font-style: italic; margin: .3rem 0 0; }}
.quote {{ margin-top: .5rem; }}
.redact {{ color: var(--warn); margin: 0 0 .3rem; font-size: .85rem; }}
pre {{ background: var(--code); padding: .7rem .8rem; border-radius: 3px;
  overflow-x: auto; margin: 0; font-size: .85rem; }}
ul {{ padding-left: 1.2rem; }}
.hint {{ color: var(--muted); font-size: .85rem; }}
details pre {{ max-height: 26rem; overflow: auto; }}
footer {{ margin-top: 3rem; color: var(--muted); font-size: .82rem; border-top: 1px solid var(--line);
  padding-top: 1rem; }}
</style>
</head>
<body>
<main>
<h1>dotdrift example report</h1>
<p class="lede">Generated over the synthetic fixture home that ships with the repository. No file
from a real machine was read to produce this page. Content is withheld by default: a path is
quoted only when the user listed it as quotable, it is not on the denylist, and the redactor has
passed over it.</p>

<div class="tiles">
  <div class="tile"><b>{checked}</b><span>paths checked</span></div>
  <div class="tile"><b>{clean}</b><span>clean</span></div>
  <div class="tile"><b>{high}</b><span>high</span></div>
  <div class="tile"><b>{warn}</b><span>warn</span></div>
  <div class="tile"><b>{info}</b><span>info</span></div>
</div>

<dl class="ctx">
  <dt>home</dt><dd><code>{home}</code></dd>
  <dt>repo</dt><dd><code>{repo}</code></dd>
  <dt>baseline</dt><dd>{baseline} &middot; {entries} entries</dd>
</dl>

<h2>Findings</h2>
{rows}
{ignored}
<section id="quoting"><h2>Quoting decisions</h2><ul>{quoting}</ul></section>
<section><h2>Raw JSON</h2>
<details><summary>the same report as machine-readable output</summary>
<pre>{json_blob}</pre></details></section>
<footer>dotdrift is a local tool. It sends nothing anywhere. This page is regenerated by
<code>scripts/build_docs.py</code> and <code>scripts/verify.sh</code> fails if it is stale.</footer>
</main>
</body>
</html>
"""
