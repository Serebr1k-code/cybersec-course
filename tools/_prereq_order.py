#!/usr/bin/env python3
"""_prereq_order.py — validate that the content tree's reading order respects
the `prerequisites` graph (a lesson must appear AFTER all lessons it names).

Reading order = pre-order DFS from each category root, children sorted by
(order, difficulty, id). Each node gets a global sequential index.
For every edge prereq -> node, we require index(prereq) < index(node).

Also reports: cycles, multiple roots per category, >4 children,
non-unique/non-contiguous sibling order, and mis-parented lessons.

Usage:
  python3 tools/_prereq_order.py            # summary
  python3 tools/_prereq_order.py --json     # full JSON
  python3 tools/_prereq_order.py <cat>      # detail for one category
"""
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
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if v.startswith("[") and v.endswith("]"):
            d[k] = [x.strip().strip('"').strip("'") for x in v[1:-1].split(",") if x.strip()]
        else:
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


def int_order(fm):
    try:
        return int(fm.get("order"))
    except (TypeError, ValueError):
        return 10 ** 6


def analyze(lessons):
    children = collections.defaultdict(list)
    roots_by_cat = collections.defaultdict(list)
    for lid, fm in lessons.items():
        par = (fm.get("parent") or "").strip()
        if par == "":
            roots_by_cat[fm.get("category")].append(lid)
        else:
            children[par].append(lid)

    # global reading index via pre-order DFS per category root
    index = {}
    cycle_nodes = set()
    seen = set()

    def dfs(lid, path):
        if lid in path:
            cycle_nodes.update(path[path.index(lid):])
            return
        if lid in seen:
            return
        seen.add(lid)
        index[lid] = len(index)
        kids = sorted(children.get(lid, []),
                      key=lambda k: (int_order(lessons[k]), DIFF_RANK.get(lessons[k].get("difficulty"), 3), k))
        for k in kids:
            dfs(k, path + [lid])

    cats = sorted(set(fm.get("category") for fm in lessons.values()))
    cat_of = {lid: fm.get("category") for lid, fm in lessons.items()}
    for cat in cats:
        for r in sorted(roots_by_cat.get(cat, [])):
            dfs(r, [])
    # orphan/unreachable nodes (not visited) — assign after
    for lid in lessons:
        if lid not in index:
            index[lid] = len(index)

    report = {"categories": {}, "missing_prereq": [], "cross_cat_prereq": []}
    for cat in cats:
        cat_ids = [lid for lid, fm in lessons.items() if fm.get("category") == cat]
        cat_ids.sort(key=lambda l: index.get(l, 10 ** 9))
        roots = roots_by_cat.get(cat, [])
        viol = []
        for lid in cat_ids:
            for p in lessons[lid].get("prerequisites", []):
                if p not in lessons:
                    report["missing_prereq"].append([lid, p])
                    continue
                if lessons[p].get("category") != cat:
                    report["cross_cat_prereq"].append([lid, cat, p, lessons[p].get("category")])
                    continue
                if index.get(p, 10 ** 9) >= index.get(lid, -1):
                    viol.append({"node": lid, "node_idx": index.get(lid),
                                 "prereq": p, "prereq_idx": index.get(p)})
        # sibling order checks
        order_issues = []
        for lid in cat_ids:
            kids = children.get(lid, [])
            if not kids:
                continue
            orders = [int_order(lessons[k]) for k in kids]
            if len(set(orders)) != len(orders) or sorted(orders) != list(range(len(orders))):
                order_issues.append({"parent": lid,
                                     "children": [(k, int_order(lessons[k])) for k in kids]})
        over = [lid for lid in cat_ids if len(children.get(lid, [])) > 4]
        # mis-parented: parent in another category / missing
        mis = []
        for lid in cat_ids:
            par = (lessons[lid].get("parent") or "").strip()
            if par and (par not in lessons or lessons[par].get("category") != cat):
                mis.append([lid, par, cat_of.get(par, "MISSING")])
        report["categories"][cat] = {
            "count": len(cat_ids),
            "roots": roots,
            "multi_root": len(roots) > 1,
            "no_root": len(roots) == 0,
            "prereq_violations": viol,
            "sibling_order_issues": order_issues,
            "over4": over,
            "mis_parented": mis,
            "cycles": sorted(cycle_nodes & set(cat_ids)),
        }
    return report, index, children, lessons


def main():
    lessons = load()
    report, index, children, _ = analyze(lessons)
    if "--json" in sys.argv:
        print(json.dumps(report, ensure_ascii=False, indent=1))
        return
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        cat = args[0]
        r = report["categories"][cat]
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return
    tot_v = 0
    for cat, r in report["categories"].items():
        tot_v += len(r["prereq_violations"])
        print(f"{cat:10} n={r['count']:<4} roots={len(r['roots'])} "
              f"prereq_viol={len(r['prereq_violations']):<3} "
              f"sib_order={len(r['sibling_order_issues']):<3} "
              f"over4={len(r['over4'])} mis={len(r['mis_parented'])} "
              f"cyc={len(r['cycles'])}")
    print(f"TOTAL prereq_violations={tot_v} "
          f"missing_prereq={len(report['missing_prereq'])} "
          f"cross_cat={len(report['cross_cat_prereq'])}")


if __name__ == "__main__":
    main()
