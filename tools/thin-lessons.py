#!/usr/bin/env python3
"""thin-lessons.py — find lessons that are thin by REAL content words.

The previous pass counted the '## Квиз' section (and its fenced ```quiz block)
and the '## Где пригодится' section as lesson content. Those are NOT lesson
content — they are assessment/navigation boilerplate. This script strips them
before counting, so a lesson that looks "big" only because of a 5-question quiz
is correctly reported as thin.

Real content words = body words, EXCLUDING:
  * the '## Квиз' section and everything after it up to the next '## ' heading
    (this removes the fenced ```quiz block too),
  * the '## Где пригодится' section,
  * fenced code blocks are counted (they ARE practice) but markdown syntax
    tokens (```, table pipes/dashes) are stripped to avoid inflating the count.

A navigational staging-module roadmap is skipped (it is intentionally short):
  * title starts with 'Модуль:' or contains 'навигатор'/'roadmap', OR
  * body mentions 'что в этом этапе' / 'этап-навигатор' AND has <=4 '## '
    sections AND contains no fenced code block (no deep tooling).

Usage:
    python3 tools/thin-lessons.py [--content DIR] [--threshold 900]
                                  [--json] [--list] [--per-category]

Exit status: 0 always (reporting tool); the caller decides what to do.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict

CONTENT_CATEGORIES = [
    "web", "crypto", "pwn", "reversing", "forensics", "osint",
    "stego", "network", "cloud", "mobile", "hardware", "misc",
]

# Sections that are boilerplate, not teaching content.
QUIZ_HEADING = "## Квиз"
WHERE_HEADING = "## Где пригодится"

ROADMAP_MARKERS = (
    "этап-навигатор", "roadmap", "что в этом этапе",
    "навигатор", "этот этап покрывает",
    "что покрывает эта ступень", "как проходить ступень",
    "почему такой порядок", "что вы будете уметь",
    "эта ступень", "этап покрывает",
)


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def split_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter-ish header lines, body). Body = after closing ---."""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    # first line is '---'
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}, text
    header = "\n".join(lines[1:end])
    body = "\n".join(lines[end + 1:])
    return {"header": header}, body


def fm_field(header: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.*)$", header, re.MULTILINE)
    if not m:
        return ""
    return m.group(1).strip().strip('"').strip("'")


def split_sections(body: str) -> list[tuple[str, str]]:
    """Split on lines starting exactly with '## '. Returns [(heading, text)]."""
    sections: list[tuple[str, str]] = []
    current_heading = ""  # intro before first '## '
    current: list[str] = []
    for line in body.splitlines():
        if line.startswith("## "):
            sections.append((current_heading, "\n".join(current)))
            current_heading = line.strip()
            current = []
        else:
            current.append(line)
    sections.append((current_heading, "\n".join(current)))
    return sections


def strip_code_and_markdown(text: str) -> str:
    """Remove markdown syntax noise that is not a real word.

    We keep table cell text and code content (they are practice), but drop
    pure-syntax tokens: fenced-code delimiter lines and table separator rows.
    Everything else is counted by whitespace split.
    """
    # Remove fenced code delimiter lines (``` or ```lang) but keep the code.
    text = re.sub(r"^\s*```[a-zA-Z0-9_+-]*\s*$", " ", text, flags=re.MULTILINE)
    # Remove markdown table separator rows like |---|---| or |:--:|--:|
    text = re.sub(r"^\s*\|?[\s:|-]+\|?\s*$", " ", text, flags=re.MULTILINE)
    return text


def real_content_words(body: str) -> int:
    """Count words in the teaching body, excluding Квиз and Где пригодится."""
    total = 0
    for heading, text in split_sections(body):
        h = heading.strip()
        if h == QUIZ_HEADING or h == WHERE_HEADING:
            continue
        # A combined heading like '## Квиз и Где пригодится' is also boilerplate.
        if h.startswith(QUIZ_HEADING) or h.startswith(WHERE_HEADING):
            continue
        cleaned = strip_code_and_markdown(text)
        total += len(cleaned.split())
    return total


def is_roadmap(header: str, body: str) -> bool:
    title = fm_field(header, "title")
    if title.startswith("Модуль:") or "модуль:" in title.lower():
        return True
    # Explicit roadmap tag is the strongest signal.
    tags = fm_field(header, "tags").lower()
    if "roadmap" in tags:
        return True
    lowered = body.lower()
    has_marker = any(m in lowered for m in ROADMAP_MARKERS)
    # Count real teaching sections only (exclude quiz / где пригодится) and
    # ignore the fenced quiz block when deciding whether deep tooling exists.
    sections = [h for h, _ in split_sections(body)
                if h.strip() and h.strip() not in (QUIZ_HEADING, WHERE_HEADING)]
    content_no_quiz = "\n".join(
        text for h, text in split_sections(body)
        if h.strip() not in (QUIZ_HEADING, WHERE_HEADING)
    )
    has_code = "```" in content_no_quiz
    if has_marker and len(sections) <= 5 and not has_code:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--content", default="content")
    ap.add_argument("--threshold", type=int, default=900)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--list", action="store_true", help="print thin file list")
    ap.add_argument("--per-category", action="store_true")
    args = ap.parse_args()

    per_cat_total: dict[str, int] = defaultdict(int)
    per_cat_thin: dict[str, int] = defaultdict(int)
    thin: list[dict] = []
    skipped_roadmap: list[str] = []

    for cat in CONTENT_CATEGORIES:
        d = os.path.join(args.content, cat)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if not name.endswith((".md", ".markdown")):
                continue
            if name.startswith(".") or name.startswith("_"):
                continue
            path = os.path.join(d, name)
            raw = read_file(path)
            fm, body = split_frontmatter(raw)
            header = fm.get("header", "")
            per_cat_total[cat] += 1
            words = real_content_words(body)
            if is_roadmap(header, body):
                skipped_roadmap.append(f"{cat}/{name}")
                continue
            if words < args.threshold:
                per_cat_thin[cat] += 1
                thin.append({
                    "category": cat,
                    "file": f"{cat}/{name}",
                    "path": path,
                    "real_words": words,
                    "title": fm_field(header, "title"),
                })

    thin.sort(key=lambda x: x["real_words"])

    if args.json:
        print(json.dumps({
            "threshold": args.threshold,
            "per_category_total": dict(per_cat_total),
            "per_category_thin": dict(per_cat_thin),
            "thin_count": len(thin),
            "thin": thin,
            "skipped_roadmaps": skipped_roadmap,
        }, ensure_ascii=False, indent=2))
        return 0

    print(f"=== thin-lessons.py (real content < {args.threshold} words) ===")
    print(f"total lessons: {sum(per_cat_total.values())}")
    print(f"thin lessons : {len(thin)}")
    print(f"skipped (roadmap/staging): {len(skipped_roadmap)}")
    print()
    print(f"{'category':<12} {'total':>6} {'thin':>6}")
    for cat in CONTENT_CATEGORIES:
        if per_cat_total.get(cat, 0) == 0:
            continue
        print(f"{cat:<12} {per_cat_total[cat]:>6} {per_cat_thin.get(cat, 0):>6}")
    print()
    if args.list:
        print("--- thin lessons (ascending real words) ---")
        for t in thin:
            print(f"{t['real_words']:>5}  {t['file']}  — {t['title'][:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
