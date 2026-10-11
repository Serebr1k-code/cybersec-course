#!/usr/bin/env python3
"""expand_lesson.py — replace a lesson's TEACHING BODY while preserving the
frontmatter, the '## Квиз' section (verbatim) and the '## Где пригодится'
section (verbatim).

The new teaching body is read from a file (--body). It must contain only
'## '-sections that are NOT '## Квиз' / '## Где пригодится'. The tool then
re-emits: frontmatter + new body + preserved '## Квиз' + preserved
'## Где пригодится', and recomputes estimated_minutes from real content words.

Usage:
    python3 tools/expand_lesson.py --file content/stego/01-intro.md --body /tmp/body.md
"""
from __future__ import annotations
import argparse, os, re, sys

QUIZ = "## Квиз"
WHERE = "## Где пригодится"


def split_frontmatter(text: str):
    if not text.startswith("---"):
        return "", text
    lines = text.splitlines(keepends=True)
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "".join(lines[: i + 1]), "".join(lines[i + 1:])
    return "", text


def split_sections(body: str):
    """Return list of (heading_line, content_including_heading)."""
    out = []
    cur_head = None
    cur = []
    for line in body.splitlines(keepends=True):
        if line.startswith("## "):
            if cur_head is not None:
                out.append((cur_head, "".join(cur)))
            elif cur:
                out.append(("", "".join(cur)))
            cur_head = line.strip()
            cur = [line]
        else:
            cur.append(line)
    if cur_head is not None:
        out.append((cur_head, "".join(cur)))
    elif cur:
        out.append(("", "".join(cur)))
    return out


def real_words(body: str) -> int:
    total = 0
    for h, sec in split_sections(body):
        hs = h.strip()
        if hs == QUIZ or hs == WHERE or hs.startswith(QUIZ) or hs.startswith(WHERE):
            continue
        # strip code fences + table separators
        t = re.sub(r"^\s*```[a-zA-Z0-9_+-]*\s*$", " ", sec, flags=re.MULTILINE)
        t = re.sub(r"^\s*\|?[\s:|-]+\|?\s*$", " ", t, flags=re.MULTILINE)
        total += len(t.split())
    return total


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--body", required=True)
    args = ap.parse_args()

    raw = open(args.file, encoding="utf-8").read()
    fm, body = split_frontmatter(raw)
    if not fm:
        print(f"ERROR: no frontmatter in {args.file}", file=sys.stderr)
        return 2

    new_body = open(args.body, encoding="utf-8").read().strip("\n")

    # Extract preserved sections from ORIGINAL body.
    quiz_sec = where_sec = ""
    for h, sec in split_sections(body):
        hs = h.strip()
        if hs == QUIZ or hs.startswith(QUIZ):
            quiz_sec = sec.strip("\n")
        elif hs == WHERE or hs.startswith(WHERE):
            where_sec = sec.strip("\n")

    if not quiz_sec:
        print(f"WARNING: no '## Квиз' section found in {args.file}", file=sys.stderr)
    if not where_sec:
        print(f"WARNING: no '## Где пригодится' section found in {args.file}", file=sys.stderr)

    # Recompute estimated_minutes from real content words of new body.
    w = real_words(new_body)
    minutes = max(20, round(w / 40))

    # Patch estimated_minutes in frontmatter.
    if re.search(r"^estimated_minutes:.*$", fm, flags=re.MULTILINE):
        fm = re.sub(r"^estimated_minutes:.*$", f"estimated_minutes: {minutes}", fm, count=1, flags=re.MULTILINE)
    else:
        # insert before closing ---
        fm = fm.rstrip("\n")
        assert fm.endswith("---")
        fm = fm[:-3].rstrip("\n") + f"\nestimated_minutes: {minutes}\n---\n"

    parts = [fm.rstrip("\n"), "", new_body.strip("\n")]
    if quiz_sec:
        parts += ["", quiz_sec.strip("\n")]
    if where_sec:
        parts += ["", where_sec.strip("\n")]
    out = "\n".join(parts).rstrip("\n") + "\n"

    with open(args.file, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"OK {args.file}: real_words={w} estimated_minutes={minutes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
