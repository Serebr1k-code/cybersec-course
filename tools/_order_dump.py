#!/usr/bin/env python3
"""_order_dump.py — dump per-parent child lists (order/difficulty/title) and real issues."""
from __future__ import annotations
import os, re, json, sys, collections

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "content"))
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
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        d[k] = v.strip('"').strip("'")
    return d


def load():
    lessons = {}
    for cat in sorted(os.listdir(ROOT)):
        cdir = os.path.join(ROOT, cat)
        if not os.path.isdir(cdir) or cat.startswith((".", "_")):
            continue
        for fn in sorted(os.listdir(cdir)):
            if not fn.endswith(".md") or fn.startswith((".", "_")):
                continue
            fm = parse_fm(os.path.join(cdir, fn))
            if fm is None:
                continue
            fm["_file"] = os.path.join(cdir, fn)
            lessons[fm.get("id") or fn[:-3]] = fm
    return lessons


def main():
    lessons = load()
    children = collections.defaultdict(list)
    for lid, fm in lessons.items():
        children[(fm.get("parent") or "").strip()].append(lid)
    cats = sys.argv[1:] or sorted(os.listdir(ROOT))
    for cat in cats:
        cdir = os.path.join(ROOT, cat)
        if not os.path.isdir(cdir) or cat.startswith((".", "_")):
            continue
        cat_ids = [lid for lid, fm in lessons.items() if fm.get("category") == cat]
        print(f"\n{'='*70}\n{cat}: {len(cat_ids)} lessons\n{'='*70}")
        roots = [l for l in cat_ids if not (lessons[l].get("parent") or "").strip()]
        print(f"ROOTS: {roots}")
        for lid in cat_ids:
            kids = children.get(lid, [])
            if not kids:
                continue
            rows = []
            for k in kids:
                fm = lessons[k]
                try:
                    o = int(fm.get("order") or 0)
                except ValueError:
                    o = -999
                rows.append((o, DIFF_RANK.get(fm.get("difficulty"), 3), k, fm.get("title", "")))
            rows.sort()
            orders = [r[0] for r in rows]
            dups = [x for x, c in collections.Counter(orders).items() if c > 1]
            seq_exp = list(range(len(rows)))
            contig = (sorted(orders) == seq_exp)
            flag = []
            if dups:
                flag.append(f"DUP{dups}")
            if not contig:
                flag.append(f"GAP{orders}")
            prev = None
            for o, d, k, t in rows:
                if prev is not None and d < prev:
                    flag.append(f"DROP[{k}:{d}<{prev}]")
                prev = d
            mark = ("  <<< " + " ".join(flag)) if flag else ""
            print(f"\n PARENT {lid}{mark}")
            for o, d, k, t in rows:
                print(f"   order={o:<3} diff={d} {k}")


if __name__ == "__main__":
    main()
