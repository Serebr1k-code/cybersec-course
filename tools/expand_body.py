#!/usr/bin/env python3
"""expand_body.py — replace a lesson's TEACHING BODY, preserving frontmatter,
the trailing '## Квиз' section (with its fenced ```quiz block) and the
'## Где пригодится' section.

Usage:
    python3 tools/expand_body.py <lesson.md> <body_file.md> [--minutes N]

The body file contains the new teaching body ONLY: it must NOT contain the
'## Квиз' or '## Где пригодится' headings. Everything from the first
'## Квиз' heading to EOF is kept verbatim.

estimated_minutes is set to N (default 40).
"""
from __future__ import annotations
import argparse
import re
import sys


def split_frontmatter(text: str):
    if not text.startswith("---"):
        raise SystemExit("no frontmatter")
    lines = text.splitlines(keepends=True)
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        raise SystemExit("unterminated frontmatter")
    header = "".join(lines[: end + 1])  # includes both --- lines
    rest = "".join(lines[end + 1:])
    return header, rest


def set_minutes(header: str, minutes: int) -> str:
    if re.search(r"^estimated_minutes:.*$", header, re.MULTILINE):
        return re.sub(r"^estimated_minutes:.*$", f"estimated_minutes: {minutes}",
                      header, flags=re.MULTILINE)
    # insert before closing ---
    return header.replace("\n---\n", f"\nestimated_minutes: {minutes}\n---\n", 1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("lesson")
    ap.add_argument("body")
    ap.add_argument("--minutes", type=int, default=40)
    args = ap.parse_args()

    lesson = open(args.lesson, encoding="utf-8").read()
    body = open(args.body, encoding="utf-8").read().rstrip("\n")

    header, rest = split_frontmatter(lesson)

    m = re.search(r"^## Квиз\s*$", rest, re.MULTILINE)
    if not m:
        raise SystemExit("no '## Квиз' heading in " + args.lesson)
    tail = rest[m.start():]

    if "## Квиз" in body or "## Где пригодится" in body:
        raise SystemExit("body file must not contain Квиз/Где пригодится headings")

    header = set_minutes(header, args.minutes)
    out = header + "\n" + body + "\n\n" + tail
    open(args.lesson, "w", encoding="utf-8").write(out)
    print(f"updated {args.lesson}: body {len(body.split())} tokens, minutes={args.minutes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
