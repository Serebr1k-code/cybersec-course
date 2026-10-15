#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_topup_gap.py — shared engine for the tree-wide thin-lesson top-up.

Given a mapping {lesson_id: [(heading, text), ...]}, insert the new teaching
sections into content/<category>/<lesson_id>.md just BEFORE the lesson's final
content summary ('## Что мы теперь знаем') so the new material reads as body,
not as an afterthought pasted after the summary.

Idempotent: if the first new heading is already present, the lesson is skipped.
Preserves frontmatter, quiz, '## Куда дальше' and '## Где пригодится'.
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ANCHORS = ("## Что мы теперь знаем", "## Квиз")


def _anchor_index(text: str) -> int:
    best = -1
    for a in ANCHORS:
        m = re.search(r"^" + re.escape(a) + r"\s*$", text, re.MULTILINE)
        if m and (best == -1 or m.start() < best):
            best = m.start()
    return best


def apply(extra: dict, category: str, dry_run: bool = False) -> int:
    changed = 0
    for lesson, sections in extra.items():
        path = os.path.join(ROOT, "content", category, lesson + ".md")
        if not os.path.isfile(path):
            print(f"  !! missing: {path}")
            continue
        text = open(path, encoding="utf-8").read()
        first_head = sections[0][0]
        if re.search(r"^" + re.escape(first_head) + r"\s*$", text, re.MULTILINE):
            print(f"  == skip (already present): {category}/{lesson}")
            continue
        idx = _anchor_index(text)
        if idx < 0:
            print(f"  !! no anchor in {category}/{lesson}")
            continue
        block = "\n".join(f"{h}\n\n{t}\n" for h, t in sections).rstrip() + "\n\n"
        out = text[:idx] + block + text[idx:]
        if not dry_run:
            open(path, "w", encoding="utf-8").write(out)
        words = sum(len(t.split()) for _, t in sections)
        print(f"  ++ {category}/{lesson}: +{words} words ({len(sections)} sections)")
        changed += 1
    print(f"[{category}] updated {changed} lessons")
    return changed


if __name__ == "__main__":
    print("import this module and call apply(EXTRA, category)")
    sys.exit(0)
