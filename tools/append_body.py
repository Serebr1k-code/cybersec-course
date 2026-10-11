#!/usr/bin/env python3
"""append_body.py — insert extra teaching sections into a lesson, just before
the '## Квиз' heading, preserving frontmatter and the trailing quiz/где.

Usage:
    python3 tools/append_body.py <lesson.md> <additions_file.md> [--minutes N]

The additions file contains ONLY new '## ' sections (no Квиз/Где пригодится).
If --minutes is given, estimated_minutes is updated.
"""
from __future__ import annotations
import argparse
import re
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("lesson")
    ap.add_argument("additions")
    ap.add_argument("--minutes", type=int, default=0)
    args = ap.parse_args()

    lesson = open(args.lesson, encoding="utf-8").read()
    add = open(args.additions, encoding="utf-8").read().rstrip("\n")
    if "## Квиз" in add or "## Где пригодится" in add:
        raise SystemExit("additions must not contain Квиз/Где пригодится")

    m = re.search(r"^## Квиз\s*$", lesson, re.MULTILINE)
    if not m:
        raise SystemExit("no '## Квиз' heading")

    out = lesson[:m.start()] + add + "\n\n" + lesson[m.start():]
    if args.minutes:
        out = re.sub(r"^estimated_minutes:.*$", f"estimated_minutes: {args.minutes}",
                     out, count=1, flags=re.MULTILINE)
    open(args.lesson, "w", encoding="utf-8").write(out)
    print(f"appended {len(add.split())} tokens to {args.lesson}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
