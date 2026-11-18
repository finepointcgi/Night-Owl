#!/usr/bin/env python3
"""Builds the Night Owl documentation site into ./public (what GitLab Pages serves).

No dependencies: pages are HTML fragments in site/pages, wrapped in one layout.
Run:  python3 site/build.py            (writes public/)
      python3 site/build.py --check    (also fails on broken internal links)
"""
import html, pathlib, re, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT.parent / "public"

# (slug, nav title, one-line summary). Order = reading order.
PAGES = [
    ("index", "Overview", "What Night Owl is and what it replaces"),
    ("getting-started", "Getting started", "Install, run your first scan, read the results"),
    ("tutorial", "Worked example", "A real scan, line by line, from findings to a passing build"),
    ("how-it-works", "How it works", "Engines, findings, fingerprints and the scan pipeline"),
    ("findings", "Findings and reports", "The finding model, JSON and SARIF formats, merging"),
    ("commands", "Command reference", "Every command and option"),
    ("configuration", "Configuration reference", "Every file, key and environment variable"),
    ("policy", "Policy and gates", "Decide what fails a build; triage; noise control"),
    ("engines", "Engines", "What scans what, in which languages"),
    ("rules", "Rule catalog", "Every built-in code rule, generated from the rule files"),
    ("staying-current", "Staying current", "Signed updates, the watch bot, canary and rollback"),
    ("ci", "CI and editors", "GitHub, GitLab, pre-commit hook, VS Code"),
    ("dashboard", "The dashboard", "Overview, history, tags, exports and STIG checklists"),
    ("sbom", "SBOM, monitoring and fixes", "SBOM, VEX, reachability, history, auto-fix"),
    ("ai-pentest", "AI review and pen testing", "Exploitability review and authorized active testing"),
    ("troubleshooting", "FAQ and troubleshooting", "Common problems, limits and the roadmap"),
    ("glossary", "Glossary", "Plain-language definitions of every term"),
]

LAYOUT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Night Owl</title>
<meta name="description" content="{summary}">
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<header class="top">
  <a class="brand" href="{root}index.html"><span class="logo" aria-hidden="true">🦉</span> Night Owl</a>
  <a class="gh" href="https://github.com/finepointcgi/Night-Owl">Source</a>
</header>
<div class="shell">
  <nav class="side" aria-label="Documentation">
    <ul>
{nav}
    </ul>
  </nav>
  <main>
    <article>
{body}
    </article>
    <footer class="pager">{prev}{next}</footer>
    <p class="foot">Night Owl is Apache-2.0 licensed. Each engine keeps its own license.</p>
  </main>
</div>
</body>
</html>
"""


REPO = ROOT.parent


def rules_tables():
    """Builds the rule catalog from the rule files, so the page can never drift from the code."""
    out = []
    for f in sorted((REPO / "src/NightOwl.Engines/Rules").glob("*.yaml")):
        rows = []
        for blk in re.split(r"\n  - id: ", f.read_text(encoding="utf-8"))[1:]:
            rid = blk.split("\n")[0].strip()
            sev = re.search(r"severity: (\w+)", blk)
            lang = re.search(r"languages: \[(.*?)\]", blk)
            msg = re.search(r"message: (.+)", blk)
            cwe = re.search(r"(CWE-\d+)", blk)
            kind = "taint" if "mode: taint" in blk else "pattern"
            text = (msg.group(1) if msg else "").strip().strip("\"'")
            sev_name = {"ERROR": "high", "WARNING": "medium"}.get(sev.group(1) if sev else "", "low")
            rows.append(
                f"<tr><td><code>{html.escape(rid)}</code></td><td>{kind}</td><td>{html.escape(lang.group(1) if lang else '')}</td>"
                f"<td>{sev_name}</td><td>{html.escape(cwe.group(1) if cwe else '')}</td><td>{html.escape(text)}</td></tr>")
        out.append(f"<h3 id=\"file-{f.stem}\"><code>{f.name}</code> <span class=\"pill\">{len(rows)} rules</span></h3>"
                   "<table><tr><th>Rule id</th><th>Kind</th><th>Languages</th><th>Severity</th><th>CWE</th><th>What it flags and how to fix it</th></tr>"
                   + "".join(rows) + "</table>")
    return "\n".join(out)


def engine_versions():
    import json
    data = json.loads((REPO / "engines/engines.json").read_text(encoding="utf-8"))
    rows = "".join(f"<tr><td>{html.escape(e['name'])}</td><td><code>{html.escape(e['version'])}</code></td><td><code>{html.escape(e['image'])}</code></td></tr>"
                   for e in data["engines"])
    return "<table><tr><th>Engine</th><th>Pinned version</th><th>Container image</th></tr>" + rows + "</table>"


def nav_html(current):
    items = []
    for slug, title, _ in PAGES:
        cls = ' class="current"' if slug == current else ""
        items.append(f'      <li><a{cls} href="{slug}.html">{html.escape(title)}</a></li>')
    return "\n".join(items)


def build():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    shutil.copy(ROOT / "style.css", OUT / "style.css")
    names = [p[0] for p in PAGES]
    for i, (slug, title, summary) in enumerate(PAGES):
        src = ROOT / "pages" / f"{slug}.html"
        body = src.read_text(encoding="utf-8")
        body = body.replace("{{RULES}}", rules_tables()).replace("{{ENGINE_VERSIONS}}", engine_versions())
        prev = nxt = ""
        if i > 0:
            p = PAGES[i - 1]
            prev = f'<a class="prev" href="{p[0]}.html"><small>Previous</small>{html.escape(p[1])}</a>'
        if i < len(PAGES) - 1:
            n = PAGES[i + 1]
            nxt = f'<a class="next" href="{n[0]}.html"><small>Next</small>{html.escape(n[1])}</a>'
        page = LAYOUT.format(title=html.escape(title), summary=html.escape(summary), root="",
                             nav=nav_html(slug), body=body, prev=prev, next=nxt)
        (OUT / f"{slug}.html").write_text(page, encoding="utf-8")
    return names


def check(names):
    bad = []
    for f in OUT.glob("*.html"):
        text = f.read_text(encoding="utf-8")
        ids = set(re.findall(r'id="([^"]+)"', text))
        for href in re.findall(r'href="([^"]+)"', text):
            if href.startswith(("http://", "https://", "mailto:")):
                continue
            target, _, frag = href.partition("#")
            if target == "":
                if frag and frag not in ids:
                    bad.append(f"{f.name}: missing anchor #{frag}")
                continue
            t = OUT / target
            if not t.exists():
                bad.append(f"{f.name}: broken link {href}")
            elif frag and f'id="{frag}"' not in t.read_text(encoding="utf-8"):
                bad.append(f"{f.name}: missing anchor {href}")
    return bad


if __name__ == "__main__":
    names = build()
    print(f"built {len(names)} pages into {OUT}")
    problems = check(names)
    for p in problems:
        print("PROBLEM:", p)
    if problems and "--check" in sys.argv:
        sys.exit(1)
