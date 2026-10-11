#!/usr/bin/env python3
"""audit-content.py — reusable content auditor for the CTF learning tree.

Walks content/<category>/*.md and validates the lessons exactly the way the Go
loader (internal/content/content.go) parses them:

  * file discovery skips dot/underscore prefixed files and directories and
    only accepts *.md / *.markdown
  * front-matter is delimited by '---' lines; the body is everything after the
    closing delimiter
  * front-matter is parsed by a "simple YAML" reader that understands
      - scalar values  (key: value)
      - inline lists   (key: [a, b, c])
      - block lists    (key:\\n  - a\\n  - b)
  * difficulty must be one of beginner|easy|medium|hard|expert
  * sections are split on lines beginning with '## '
  * a lesson carries an interactive quiz either as a fenced ```quiz block or as
    a classic '## Квиз' section

The auditor reports (human readable, or --json for machine consumption):
  * duplicate ids / duplicate + near-duplicate titles
  * dangling parents and orphan/unreachable nodes
  * categories with zero lessons (vs the canonical 12)
  * lessons missing '## Квиз' or '## Где пригодится'
  * lessons without a fenced ```quiz block (interactive format migration)
  * invalid difficulty / non-integer order / empty category / missing keys
  * per-category lesson counts and id lists

Exit status is non-zero when any duplicate id, dangling parent or missing
mandatory section is found (i.e. the tree is broken / incomplete).

Usage:
    python3 tools/audit-content.py [--content DIR] [--json] [--near-ratio R]
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
from collections import Counter, defaultdict

# Canonical top-level categories (must mirror internal/content/content.go).
CANONICAL_CATEGORIES = [
    "web", "crypto", "pwn", "reversing", "forensics", "osint",
    "stego", "network", "cloud", "mobile", "hardware", "misc",
]

VALID_DIFFICULTIES = {"beginner", "easy", "medium", "hard", "expert"}

# Front-matter keys the content format mandates.
REQUIRED_KEYS = [
    "id", "title", "category", "parent", "difficulty", "order",
    "tags", "prerequisites", "useful_for", "estimated_minutes", "summary",
]

# Keys whose *absence* is tolerated (roots legitimately omit/blank parent).
SOFT_KEYS = {"parent"}

SECTION_QUIZ_RE = re.compile(r"(?i)^\s*(?:квиз|quiz)\b")
SECTION_WHERE_RE = re.compile(r"(?i)где\s+пригодится")
QUIZ_FENCE_RE = re.compile(r"^\s*```quiz\b")
HEADING_RE = re.compile(r"^## ")


# --------------------------------------------------------------------------
# Go-loader-compatible parsing
# --------------------------------------------------------------------------
def split_frontmatter(raw: str):
    """Return (frontmatter_dict_or_None, body). Mirrors splitFrontmatter()."""
    raw = raw.replace("\r\n", "\n")
    lines = raw.split("\n")
    start = -1
    for i, line in enumerate(lines):
        if line.strip() == "---":
            start = i
            break
        if line.strip() != "":
            return None, raw
    if start == -1:
        return None, raw
    end = -1
    for i in range(start + 1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end == -1:
        return None, raw
    fm = parse_simple_yaml(lines[start + 1:end])
    return fm, "\n".join(lines[end + 1:])


def unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    return s


def parse_simple_yaml(lines):
    """Minimal YAML reader matching parseSimpleYAML() in content.go."""
    m = {}
    cur_key = ""
    for ln in lines:
        if ln.strip() == "" or ln.strip().startswith("#"):
            continue
        trimmed = ln.strip()
        if trimmed.startswith("- ") and cur_key != "":
            item = unquote(trimmed[2:])
            arr = m.get(cur_key)
            if not isinstance(arr, list):
                arr = []
            arr.append(item)
            m[cur_key] = arr
            continue
        idx = ln.find(":")
        if idx == -1:
            continue
        key = ln[:idx].strip()
        val = ln[idx + 1:].strip()
        cur_key = key
        if val == "":
            m[key] = []
            continue
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            arr = []
            if inner != "":
                arr = [unquote(p.strip()) for p in inner.split(",")]
            m[key] = arr
            continue
        m[key] = unquote(val)
    return m


def get_string(m, k):
    v = m.get(k)
    return v if isinstance(v, str) else ""


def get_list(m, k):
    v = m.get(k)
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v != "":
        return [v]
    return []


def split_sections(body: str):
    """Return list of (title, markdown) — mirrors splitSections()."""
    lines = body.split("\n")
    secs = []
    cur = []
    cur_title = ""
    first = True

    def flush():
        nonlocal cur, cur_title, first
        md = "\n".join(cur).strip()
        title = cur_title
        if title == "":
            title = "Введение" if first else "Раздел %d" % (len(secs) + 1)
        if md == "":
            cur = []
            cur_title = ""
            first = False
            return
        secs.append((title, md))
        cur = []
        cur_title = ""
        first = False

    for ln in lines:
        if ln.startswith("## "):
            flush()
            cur_title = ln[3:].strip()
            continue
        cur.append(ln)
    flush()
    if not secs:
        md = body.strip()
        if md:
            secs.append(("Введение", md))
    return secs


def raw_sections(body: str):
    """Split body on '## ' headings but KEEP empty sections.

    The Go loader drops empty sections, which is exactly why a present-but-empty
    '## Квиз' heading means the reader gets no quiz. We need to see the heading
    to report that distinctly from a wholly absent one.
    """
    lines = body.split("\n")
    heads = [i for i, l in enumerate(lines) if l.startswith("## ")]
    out = []
    for k, i in enumerate(heads):
        title = lines[i][3:].strip()
        end = heads[k + 1] if k + 1 < len(heads) else len(lines)
        out.append((title, "\n".join(lines[i + 1:end]).strip()))
    return out


def parse_quiz_block(body: str):
    """Parse a fenced ```quiz block the way parseQuizYAML() does.

    Returns (count_valid_questions, count_total_questions). Valid means a
    non-empty question text, >= 2 options and an in-range 0-based answer.
    """
    lines = body.split("\n")
    start = end = -1
    for i, ln in enumerate(lines):
        t = ln.strip()
        if start == -1 and t.startswith("```quiz"):
            start = i
            continue
        if start != -1 and t == "```":
            end = i
            break
    if start == -1 or end == -1:
        return 0, 0, False
    block = lines[start + 1:end]

    total = 0
    valid = 0
    cur_q = None
    cur_opts = []
    cur_ans = -1
    in_opts = False

    def close():
        nonlocal total, valid, cur_q, cur_opts, cur_ans
        if cur_q is not None and cur_opts:
            total += 1
            if cur_q != "" and len(cur_opts) >= 2 and 0 <= cur_ans < len(cur_opts):
                valid += 1
        cur_q, cur_opts, cur_ans = None, [], -1

    for raw in block:
        s = raw.strip()
        if s == "" or s.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if s.startswith("- ") and (s[2:].startswith("question:") or s[2:].startswith("q:")):
            close()
            cur_q = unquote(s[2:].split(":", 1)[1].strip())
            in_opts = False
            continue
        if cur_q is None:
            continue
        if s.startswith("options:"):
            in_opts = True
        elif s.startswith("answer:"):
            in_opts = False
            cur_ans = quiz_answer(s.split(":", 1)[1].strip())
        elif s.startswith("explanation:"):
            in_opts = False
        elif s.startswith("question:") or s.startswith("q:"):
            in_opts = False
            cur_q = unquote(s.split(":", 1)[1].strip())
        elif s.startswith("- ") and in_opts:
            cur_opts.append(unquote(s[2:].strip()))
        elif indent > 0 and in_opts and cur_opts:
            cur_opts[-1] += " " + unquote(s)
    close()
    return valid, total, True


def quiz_answer(v: str) -> int:
    v = v.strip()
    if v == "":
        return -1
    try:
        return int(v)
    except ValueError:
        pass
    r = v.upper()[0]
    if "A" <= r <= "Z":
        return ord(r) - ord("A")
    if "А" <= r <= "Я":
        return ord(r) - ord("А")
    return -1


def parse_file(path: str):
    """Parse one lesson file into an audit record."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    fm, body = split_frontmatter(raw)
    rec = {
        "path": path,
        "has_frontmatter": fm is not None,
        "fm": fm or {},
        "body": body,
        "present_keys": set(fm.keys()) if fm else set(),
        "sections": split_sections(body) if body else [],
    }
    rec["id"] = get_string(fm or {}, "id")
    rec["title"] = get_string(fm or {}, "title")
    rec["parent"] = get_string(fm or {}, "parent")
    rec["difficulty"] = get_string(fm or {}, "difficulty")
    rec["category"] = get_string(fm or {}, "category")
    rec["summary"] = get_string(fm or {}, "summary")
    return rec


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
def walk_content(content_dir: str):
    """Yield lesson file paths, skipping ./_ prefixed entries (like Go does)."""
    found = []
    for root, dirs, files in os.walk(content_dir):
        # Skip dot/underscore dirs (except the root itself).
        dirs[:] = [d for d in dirs
                   if not (d.startswith(".") or d.startswith("_"))]
        for name in files:
            if name.startswith(".") or name.startswith("_"):
                continue
            if not (name.endswith(".md") or name.endswith(".markdown")):
                continue
            found.append(os.path.join(root, name))
    return sorted(found)


def category_of(path: str, content_dir: str) -> str:
    rel = os.path.relpath(path, content_dir)
    parts = rel.split(os.sep)
    return parts[0] if len(parts) > 1 else "(root)"


def normalize_title(t: str) -> str:
    t = t.lower()
    t = re.sub(r"[^\w\s]", " ", t, flags=re.UNICODE)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def audit(content_dir: str, near_ratio: float):
    files = walk_content(content_dir)
    lessons = []
    parse_errors = []
    for p in files:
        try:
            rec = parse_file(p)
        except Exception as exc:  # noqa: BLE001 - report, never crash
            parse_errors.append({"path": p, "error": str(exc)})
            continue
        rec["category_dir"] = category_of(p, content_dir)
        lessons.append(rec)

    report = {
        "content_dir": os.path.abspath(content_dir),
        "total_files": len(files),
        "total_lessons": len(lessons),
        "parse_errors": parse_errors,
        "duplicate_ids": [],
        "duplicate_titles": [],
        "near_duplicate_titles": [],
        "dangling_parents": [],
        "orphans": [],
        "empty_categories": [],
        "missing_quiz_section": [],
        "empty_quiz_section": [],
        "missing_where_section": [],
        "missing_quiz_fence": [],
        "malformed_quiz_block": [],
        "no_parsable_quiz": [],
        "invalid_difficulty": [],
        "non_integer_order": [],
        "empty_category": [],
        "missing_keys": [],
        "no_frontmatter": [],
        "self_parent": [],
        "counts": {},
        "ids_by_category": {},
    }

    # --- per-lesson structural checks -------------------------------------
    by_id = defaultdict(list)
    for rec in lessons:
        if not rec["has_frontmatter"]:
            report["no_frontmatter"].append(rec["path"])

        eff_id = rec["id"] or os.path.splitext(os.path.basename(rec["path"]))[0]
        rec["eff_id"] = eff_id
        by_id[eff_id].append(rec)

        # missing required keys
        missing = [k for k in REQUIRED_KEYS
                   if k not in rec["present_keys"] and k not in SOFT_KEYS]
        if missing:
            report["missing_keys"].append({"path": rec["path"], "missing": missing})

        # empty category
        if not rec["category"].strip():
            report["empty_category"].append({"path": rec["path"], "id": eff_id})

        # invalid difficulty
        diff = rec["difficulty"].strip().lower()
        if diff not in VALID_DIFFICULTIES:
            report["invalid_difficulty"].append({
                "path": rec["path"], "id": eff_id,
                "value": rec["difficulty"],
                "effective": "medium",  # loader silently defaults
            })

        # non-integer order
        order_raw = rec["fm"].get("order")
        if isinstance(order_raw, list):  # blank value -> [] in our parser
            order_raw = ""
        # Only flag present-but-non-integer values; an absent 'order' key is
        # already reported by the missing-keys check.
        if order_raw not in (None, ""):
            s = str(order_raw).strip()
            if not re.fullmatch(r"-?\d+", s):
                report["non_integer_order"].append({
                    "path": rec["path"], "id": eff_id, "value": order_raw,
                })

        # --- quiz / mandatory section checks ------------------------------
        # Use raw (empty-section-preserving) headings so a present-but-empty
        # '## Квиз' is distinguished from a wholly absent one.
        rs = raw_sections(rec["body"])
        quiz_headings = [(t, b) for t, b in rs if SECTION_QUIZ_RE.match(t)]
        where_headings = [t for t, _ in rs if SECTION_WHERE_RE.search(t)]
        has_quiz_heading = bool(quiz_headings)
        quiz_body_nonempty = any(b for _, b in quiz_headings)
        has_where = bool(where_headings)

        qv, qt, has_fence = parse_quiz_block(rec["body"])
        has_quiz_fence = has_fence

        if not has_quiz_heading:
            report["missing_quiz_section"].append({"path": rec["path"], "id": eff_id})
        elif not quiz_body_nonempty and not has_fence:
            report["empty_quiz_section"].append({
                "path": rec["path"], "id": eff_id,
                "note": "'## Квиз' heading present but section body is empty "
                        "(loader drops it -> 0 questions)",
            })
        if not has_where:
            report["missing_where_section"].append({"path": rec["path"], "id": eff_id})
        if not has_quiz_fence:
            report["missing_quiz_fence"].append({"path": rec["path"], "id": eff_id})
        if has_fence and qv == 0:
            report["malformed_quiz_block"].append({
                "path": rec["path"], "id": eff_id,
                "note": "```quiz block present but 0 valid questions "
                        "(total parsed=%d)" % qt,
            })
        # Effectively no quiz reaches the loader at all.
        if not has_quiz_fence and not quiz_body_nonempty:
            report["no_parsable_quiz"].append({"path": rec["path"], "id": eff_id})

        # self parent
        if rec["parent"] and rec["parent"] == eff_id:
            report["self_parent"].append({"path": rec["path"], "id": eff_id})

    # --- duplicate ids -----------------------------------------------------
    for cid, recs in sorted(by_id.items()):
        if len(recs) > 1:
            report["duplicate_ids"].append({
                "id": cid,
                "paths": sorted(r["path"] for r in recs),
            })

    all_ids = set(by_id.keys())

    # --- duplicate / near-duplicate titles --------------------------------
    title_map = defaultdict(list)
    for rec in lessons:
        norm = normalize_title(rec["title"] or rec["eff_id"])
        title_map[norm].append(rec)
    for norm, recs in sorted(title_map.items()):
        if len(recs) > 1:
            report["duplicate_titles"].append({
                "normalized": norm,
                "titles": sorted({r["title"] for r in recs}),
                "paths": sorted(r["path"] for r in recs),
                "ids": sorted(r["eff_id"] for r in recs),
            })
    # near-duplicates across distinct normalized titles
    norms = sorted(title_map.keys())
    seen_pairs = set()
    for i in range(len(norms)):
        for j in range(i + 1, len(norms)):
            a, b = norms[i], norms[j]
            if not a or not b:
                continue
            ratio = difflib.SequenceMatcher(None, a, b).ratio()
            if ratio >= near_ratio:
                ra = title_map[a][0]
                rb = title_map[b][0]
                if ra["eff_id"] == rb["eff_id"]:
                    continue
                key = tuple(sorted([ra["path"], rb["path"]]))
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                report["near_duplicate_titles"].append({
                    "ratio": round(ratio, 3),
                    "a": {"id": ra["eff_id"], "title": ra["title"], "path": ra["path"]},
                    "b": {"id": rb["eff_id"], "title": rb["title"], "path": rb["path"]},
                })
    report["near_duplicate_titles"].sort(key=lambda x: -x["ratio"])

    # --- dangling parents / orphans ---------------------------------------
    children = defaultdict(list)
    roots = []
    for rec in lessons:
        pid = rec["parent"]
        if pid and pid in all_ids and pid != rec["eff_id"]:
            children[pid].append(rec["eff_id"])
        else:
            if pid and pid not in all_ids:
                report["dangling_parents"].append({
                    "path": rec["path"], "id": rec["eff_id"], "parent": pid,
                })
            roots.append(rec["eff_id"])

    visited = set()
    stack = list(roots)
    while stack:
        nid = stack.pop()
        if nid in visited:
            continue
        visited.add(nid)
        stack.extend(children.get(nid, []))
    for rec in lessons:
        if rec["eff_id"] not in visited:
            report["orphans"].append({
                "path": rec["path"], "id": rec["eff_id"], "parent": rec["parent"],
            })

    # --- categories --------------------------------------------------------
    counts = Counter()
    ids_by_cat = defaultdict(list)
    for rec in lessons:
        cat = rec["category"].strip() or rec["category_dir"]
        counts[cat] += 1
        ids_by_cat[cat].append(rec["eff_id"])
    report["counts"] = dict(sorted(counts.items()))
    report["ids_by_category"] = {k: sorted(v) for k, v in sorted(ids_by_cat.items())}

    for cat in CANONICAL_CATEGORIES:
        if counts.get(cat, 0) == 0:
            report["empty_categories"].append(cat)
    # categories present on disk but not canonical
    report["extra_categories"] = sorted(
        c for c in counts if c not in CANONICAL_CATEGORIES
    )

    # --- verdict -----------------------------------------------------------
    report["ok"] = not (
        report["duplicate_ids"]
        or report["dangling_parents"]
        or report["missing_quiz_section"]
        or report["empty_quiz_section"]
        or report["missing_where_section"]
        or report["no_parsable_quiz"]
        or report["malformed_quiz_block"]
        or report["parse_errors"]
        or report["orphans"]
    )
    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def render_human(r: dict) -> str:
    out = []
    w = out.append
    w("=" * 72)
    w("CONTENT AUDIT — %s" % r["content_dir"])
    w("=" * 72)
    w("files scanned : %d" % r["total_files"])
    w("lessons parsed: %d" % r["total_lessons"])
    w("status        : %s" % ("OK" if r["ok"] else "PROBLEMS FOUND"))
    w("")

    def block(title, items, fmt):
        w("-- %s (%d) %s" % (title, len(items), "-" * max(0, 40 - len(title))))
        if not items:
            w("   (none)")
        else:
            for it in items:
                w("   " + fmt(it))
        w("")

    block("DUPLICATE IDS", r["duplicate_ids"],
          lambda x: "id=%s\n      %s" % (x["id"], "\n      ".join(x["paths"])))
    block("DUPLICATE TITLES", r["duplicate_titles"],
          lambda x: "%r -> ids=%s\n      %s" % (
              x["titles"], x["ids"], "\n      ".join(x["paths"])))
    block("NEAR-DUPLICATE TITLES", r["near_duplicate_titles"],
          lambda x: "%.2f  %s (%s)\n           %s (%s)\n      [%s | %s]" % (
              x["ratio"], x["a"]["title"], x["a"]["id"], x["b"]["title"], x["b"]["id"],
              x["a"]["path"], x["b"]["path"]))
    block("DANGLING PARENTS", r["dangling_parents"],
          lambda x: "%s  parent=%r  (%s)" % (x["id"], x["parent"], x["path"]))
    block("ORPHAN / UNREACHABLE", r["orphans"],
          lambda x: "%s  parent=%r  (%s)" % (x["id"], x["parent"], x["path"]))
    block("SELF-PARENT", r["self_parent"], lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("MISSING '## Квиз' SECTION", r["missing_quiz_section"],
          lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("EMPTY '## Квиз' SECTION (heading but no body)", r["empty_quiz_section"],
          lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("NO PARSABLE QUIZ (no fence, no non-empty Квиз)", r["no_parsable_quiz"],
          lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("MALFORMED ```quiz BLOCK (0 valid questions)", r["malformed_quiz_block"],
          lambda x: "%s — %s (%s)" % (x["id"], x["note"], x["path"]))
    block("MISSING '## Где пригодится' SECTION", r["missing_where_section"],
          lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("MISSING ```quiz FENCE (needs conversion)", r["missing_quiz_fence"],
          lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("INVALID DIFFICULTY", r["invalid_difficulty"],
          lambda x: "%s value=%r -> %s (%s)" % (
              x["id"], x["value"], x["effective"], x["path"]))
    block("NON-INTEGER ORDER", r["non_integer_order"],
          lambda x: "%s order=%r (%s)" % (x["id"], x["value"], x["path"]))
    block("EMPTY CATEGORY (front-matter)", r["empty_category"],
          lambda x: "%s (%s)" % (x["id"], x["path"]))
    block("MISSING REQUIRED KEYS", r["missing_keys"],
          lambda x: "%s missing=%s (%s)" % (
              os.path.basename(x["path"]), x["missing"], x["path"]))
    block("NO FRONT-MATTER", r["no_frontmatter"], lambda x: x)
    block("PARSE ERRORS", r["parse_errors"],
          lambda x: "%s: %s" % (x["path"], x["error"]))
    block("CATEGORIES WITH ZERO LESSONS", r["empty_categories"], lambda x: x)
    if r.get("extra_categories"):
        block("NON-CANONICAL CATEGORIES", r["extra_categories"], lambda x: x)

    w("-- PER-CATEGORY COUNTS " + "-" * 40)
    for cat in CANONICAL_CATEGORIES:
        n = r["counts"].get(cat, 0)
        mark = "  <-- EMPTY" if n == 0 else ""
        w("   %-11s %3d%s" % (cat, n, mark))
    w("")
    w("-- IDS BY CATEGORY " + "-" * 44)
    for cat in sorted(r["ids_by_category"]):
        w("   %s (%d):" % (cat, len(r["ids_by_category"][cat])))
        w("      " + ", ".join(r["ids_by_category"][cat]))
    w("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit the CTF learning-tree content.")
    default_content = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "content")
    ap.add_argument("--content", default=default_content,
                    help="content directory (default: ../content)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--near-ratio", type=float, default=0.88,
                    help="difflib ratio for near-duplicate titles (default 0.88)")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.content):
        sys.stderr.write("content dir not found: %s\n" % args.content)
        return 2

    report = audit(args.content, args.near_ratio)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_human(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
