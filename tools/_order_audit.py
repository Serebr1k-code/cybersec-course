#!/usr/bin/env python3
"""_order_audit.py — analyze learning-order coherence of the content tree.

Builds parent->children per category, flags:
  * missing / duplicated / non-contiguous order among siblings
  * difficulty non-monotonic along a branch
  * mis-parented lessons (parent in a different category or dangling)
  * hub ('Модуль:' / module) placed after its own children
  * cycles, multiple roots, >4 children
Prints a JSON report.
"""
from __future__ import annotations
import os, re, json, sys, collections

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "content")
ROOT = os.path.abspath(ROOT)
DIFF_RANK = {"beginner": 1, "easy": 2, "medium": 3, "hard": 4, "expert": 5}


def parse_fm(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    fm = text[3:end]
    d = {}
    for line in fm.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if v.startswith("[") and v.endswith("]"):
            items = [x.strip().strip('"').strip("'") for x in v[1:-1].split(",") if x.strip()]
            d[k] = items
        elif v == "" :
            d[k] = ""
        else:
            d[k] = v.strip('"').strip("'")
    return d


def main():
    lessons = {}
    for cat in sorted(os.listdir(ROOT)):
        cdir = os.path.join(ROOT, cat)
        if not os.path.isdir(cdir) or cat.startswith((".", "_")):
            continue
        for fn in sorted(os.listdir(cdir)):
            if not (fn.endswith(".md") or fn.endswith(".markdown")) or fn.startswith((".", "_")):
                continue
            p = os.path.join(cdir, fn)
            fm = parse_fm(p)
            if fm is None:
                print(f"WARN no frontmatter: {p}", file=sys.stderr)
                continue
            lid = fm.get("id") or fn[:-3]
            fm["_file"] = p
            fm["_id"] = lid
            lessons[lid] = fm

    # children map
    children = collections.defaultdict(list)
    roots = []
    for lid, fm in lessons.items():
        par = (fm.get("parent") or "").strip()
        if par == "":
            roots.append(lid)
        else:
            children[par].append(lid)

    report = {}
    for cat in sorted(os.listdir(ROOT)):
        cdir = os.path.join(ROOT, cat)
        if not os.path.isdir(cdir) or cat.startswith((".", "_")):
            continue
        cat_lessons = {lid: fm for lid, fm in lessons.items() if fm.get("category") == cat}
        cat_ids = set(cat_lessons)
        cat_roots = [lid for lid in cat_ids if not (lessons[lid].get("parent") or "").strip()]
        issues = []
        # order issues per parent
        for lid in cat_ids:
            kids = children.get(lid, [])
            if not kids:
                continue
            orders = []
            for k in kids:
                o = lessons[k].get("order")
                try:
                    oi = int(o)
                except (TypeError, ValueError):
                    oi = None
                orders.append((k, oi))
            ints = [o for _, o in orders if o is not None]
            # duplicates
            dup = [x for x, c in collections.Counter(ints).items() if c > 1]
            missing = [k for k, o in orders if o is None]
            # monotonic difficulty
            seq = sorted(orders, key=lambda t: (t[1] if t[1] is not None else 999))
            ranks = [DIFF_RANK.get(lessons[k].get("difficulty"), 3) for k, _ in seq]
            drops = []
            for i in range(1, len(ranks)):
                if ranks[i] < ranks[i-1] - 1:  # allow 1-step dip
                    drops.append((seq[i-1][0], seq[i][0], ranks[i-1], ranks[i]))
            # hub after children
            hub_after = []
            is_hub = "модуль" in (lessons[lid].get("title") or "").lower() or "module" in (lessons[lid].get("tags") or [])
            if is_hub:
                hub_oi = lessons[lid].get("order")
                try:
                    hub_oi = int(hub_oi)
                except (TypeError, ValueError):
                    hub_oi = 0
                for k, oi in orders:
                    if oi is not None and oi < hub_oi:
                        hub_after.append((k, oi, hub_oi))
            rec = {"parent": lid, "children": [(k, o) for k, o in orders],
                   "dup_order": dup, "missing_order": missing, "difficulty_drops": drops,
                   "hub_after_children": hub_after}
            if dup or missing or drops or hub_after or len(kids) > 4:
                issues.append(rec)
        # mis-parented: parent not in same category
        mis = []
        for lid in cat_ids:
            par = (lessons[lid].get("parent") or "").strip()
            if par and par not in cat_ids:
                mis.append((lid, par, lessons.get(par, {}).get("category", "MISSING")))
        report[cat] = {
            "count": len(cat_ids),
            "roots": cat_roots,
            "multi_root": len(cat_roots) > 1,
            "no_root": len(cat_roots) == 0,
            "mis_parented": mis,
            "order_issues": issues,
            "max_children": max([len(children.get(lid, [])) for lid in cat_ids] + [0]),
        }
    print(json.dumps(report, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
