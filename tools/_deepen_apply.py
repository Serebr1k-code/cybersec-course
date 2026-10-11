#!/usr/bin/env python3
"""_deepen_apply.py — replace the TEACHING BODY of a lesson while preserving
its frontmatter and the trailing '## Квиз' + '## Где пригодится' sections.

Usage:
    python3 tools/_deepen_apply.py <lesson.md> <new_body.md> [--quiz-from <file>]

The new body must contain NO '## Квиз' and NO '## Где пригодится' section.
Everything from the first '## Квиз' (or '## Где пригодится' if no quiz) of the
ORIGINAL file is appended verbatim (the quiz answers stay hidden/unchanged).
estimated_minutes in the frontmatter is updated to max(estimated, words//180 + 2).
"""
import argparse
import os
import re
import sys


def split_frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, text
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return lines[: i + 1], "\n".join(lines[i + 1:])
    return None, text


def tail_from(body):
    """Return (teaching_body, tail) where tail starts at '## Квиз'."""
    m = re.search(r"^## Квиз\b", body, re.MULTILINE)
    if not m:
        m = re.search(r"^## Где пригодится\b", body, re.MULTILINE)
    if not m:
        return body, ""
    return body[: m.start()].rstrip() + "\n", body[m.start():].strip() + "\n"


def real_content_words(body):
    parts = re.split(r"^## (Квиз|Где пригодится)\b.*$", body, flags=re.MULTILINE)
    teaching = parts[0]
    teaching = re.sub(r"^\s*```[a-zA-Z0-9_+-]*\s*$", " ", teaching, flags=re.MULTILINE)
    teaching = re.sub(r"^\s*\|?[\s:|-]+\|?\s*$", " ", teaching, flags=re.MULTILINE)
    return len(teaching.split())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("lesson")
    ap.add_argument("body")
    ap.add_argument("--quiz-from", default=None)
    args = ap.parse_args()

    lesson = open(args.lesson, encoding="utf-8").read()
    fm, body = split_frontmatter(lesson)
    if fm is None:
        print("ERROR: no frontmatter in", args.lesson, file=sys.stderr)
        return 2

    src = args.quiz_from or args.lesson
    _, srcbody = split_frontmatter(open(src, encoding="utf-8").read())
    _, tail = tail_from(srcbody)
    if not tail.strip():
        print("ERROR: no Квиз/Где пригодится tail found in", src, file=sys.stderr)
        return 3

    newbody = open(args.body, encoding="utf-8").read().strip() + "\n\n" + tail
    if "## Квиз" in newbody.split("## Квиз")[0] and args.quiz_from is None:
        pass

    # update estimated_minutes
    rw = real_content_words(newbody)
    est = rw // 180 + 2
    fm_text = "\n".join(fm)
    m = re.search(r"^estimated_minutes:\s*(\d+)\s*$", fm_text, re.MULTILINE)
    if m:
        old = int(m.group(1))
        new = max(old, est)
        fm_text = re.sub(r"^estimated_minutes:\s*\d+\s*$",
                         f"estimated_minutes: {new}", fm_text, flags=re.MULTILINE)
    else:
        fm_text = fm_text[:-3] + f"estimated_minutes: {est}\n---"

    out = fm_text + "\n" + newbody
    open(args.lesson, "w", encoding="utf-8").write(out)
    print(f"{args.lesson}: real_words={rw} estimated_minutes~{est}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
