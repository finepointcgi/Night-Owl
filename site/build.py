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
    ("how-it-works", "How it works", "Engines, findings, fingerprints and the scan pipeline"),
    ("commands", "Command reference", "Every command and option"),
    ("policy", "Policy and gates", "Decide what fails a build; triage; noise control"),
    ("engines", "Engines and rules", "What scans what, in which languages"),
    ("staying-current", "Staying current", "Signed updates, the watch bot, canary and rollback"),
    ("ci", "CI and editors", "GitHub, GitLab, pre-commit hook, VS Code"),
    ("sbom", "SBOM, monitoring and fixes", "SBOM, VEX, reachability, history, auto-fix"),
    ("ai-pentest", "AI review and pen testing", "Exploitability review and authorized active testing"),
    ("troubleshooting", "FAQ and troubleshooting", "Common problems, limits and the roadmap"),
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
