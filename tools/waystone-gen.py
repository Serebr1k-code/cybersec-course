#!/usr/bin/env python3
"""waystone-gen — вейстоуны (гейты веток) дерева обучения.

Подкоманды:

  check   (по умолчанию) проверить все вейстоуны дерева:
            * waystone_tasks непустой (пустой = инертный гейт, предупреждение);
            * каждый id задачи существует;
            * ни одна задача не лежит ВНУТРИ запираемого поддерева
              (иначе она недостижима и ветка запирается навсегда);
            * нет дублирующихся id уроков.
  list    показать вейстоуны, их задачи и порядок.
  new     напечатать (или с --write — записать) скелет урока-вейстоуна.

Пример:

  python3 tools/waystone-gen.py check
  python3 tools/waystone-gen.py list
  python3 tools/waystone-gen.py new --id network-waystone-analysis \\
      --category network --parent network-pcap-analysis \\
      --title "Вейстоун: аналитик трафика" \\
      --tasks network-tcpdump,network-wireshark,network-zeek,network-pcap-analysis,network-traffic-analysis-ctf
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTENT = os.path.join(ROOT, "content")


def parse_frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}
    fm = {}
    for ln in lines[1:end]:
        # Only TOP-LEVEL keys: nested blocks (e.g. the `lab:` mapping) are
        # indented and must not shadow a top-level key like `title`.
        if ln[:1] in (" ", "\t"):
            continue
        s = ln.strip()
        if not s or s.startswith("#") or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        fm[k.strip()] = v.strip()
    return fm


def parse_bool(v):
    return str(v).strip().lower() in ("true", "yes", "on", "1")


def parse_list(v):
    v = str(v).strip()
    if v.startswith("[") and v.endswith("]"):
        v = v[1:-1]
    out = []
    for part in v.split(","):
        p = part.strip().strip('"').strip("'")
        if p:
            out.append(p)
    return out


def load_lessons():
    """Return {id: {path, category, parent, waystone, tasks, order, title}}."""
    lessons = {}
    dups = []
    for dirpath, dirnames, filenames in os.walk(CONTENT):
        if os.path.basename(dirpath) == "labs":
            continue
        dirnames[:] = [d for d in dirnames if not d.startswith((".", "_"))]
        for fn in filenames:
            if not fn.endswith(".md") or fn.startswith((".", "_")):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8") as fh:
                    fm = parse_frontmatter(fh.read())
            except OSError:
                continue
            lid = fm.get("id") or os.path.splitext(fn)[0]
            if lid in lessons:
                dups.append((lid, lessons[lid]["path"], path))
                continue
            lessons[lid] = {
                "id": lid,
                "path": path,
                "category": fm.get("category", ""),
                "parent": fm.get("parent", ""),
                "order": fm.get("order", ""),
                "title": fm.get("title", "").strip('"'),
                "waystone": parse_bool(fm.get("waystone", "")),
                "tasks": parse_list(fm.get("waystone_tasks", "")),
            }
    return lessons, dups


def children_map(lessons):
    kids = {}
    for lid, l in lessons.items():
        kids.setdefault(l["parent"] or "__root__", []).append(lid)
    return kids


def descendants(root, kids):
    out = set()
    stack = list(kids.get(root, []))
    guard = 0
    while stack and guard < 200000:
        guard += 1
        nid = stack.pop()
        if nid in out:
            continue
        out.add(nid)
        stack.extend(kids.get(nid, []))
    return out


def cmd_check(_args):
    lessons, dups = load_lessons()
    kids = children_map(lessons)
    errors, warns = [], []

    # Duplicate lesson ids are a content-wide concern (tools/audit-content.py
    # owns the full audit); here they are only a warning, so `check` stays
    # focused on waystone validity and does not go red on unrelated content.
    for lid, _, other in dups:
        warns.append(f"duplicate lesson id {lid!r}: {os.path.relpath(_, ROOT)} and {os.path.relpath(other, ROOT)}")

    gates = [l for l in lessons.values() if l["waystone"]]
    for g in gates:
        rel = os.path.relpath(g["path"], ROOT)
        if not g["tasks"]:
            warns.append(f"{rel}: waystone with empty waystone_tasks -> inert gate (never locks)")
            continue
        gated = descendants(g["id"], kids)
        for t in g["tasks"]:
            if t not in lessons:
                errors.append(f"{rel}: waystone task {t!r} does not exist")
            elif t in gated:
                errors.append(f"{rel}: waystone task {t!r} is INSIDE the gated subtree -> unreachable, branch locks forever")
            elif t == g["id"]:
                errors.append(f"{rel}: waystone task equals the gate itself")
        if len(set(g["tasks"])) != len(g["tasks"]):
            warns.append(f"{rel}: duplicate ids in waystone_tasks")

    print(f"waystones: {len(gates)}; lessons: {len(lessons)}")
    for w in warns:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  ERROR {e}")
    if errors:
        print(f"FAIL: {len(errors)} error(s), {len(warns)} warning(s)")
        return 1
    print(f"OK: {len(gates)} waystone(s), {len(warns)} warning(s)")
    return 0


def cmd_list(_args):
    lessons, _ = load_lessons()
    gates = sorted((l for l in lessons.values() if l["waystone"]), key=lambda l: (l["category"], l["id"]))
    if not gates:
        print("no waystones")
        return 0
    for g in gates:
        n = len(g["tasks"])
        print(f"[{g['category']}] {g['id']}  ({g['title'][:48]})  N={n}")
        for t in g["tasks"]:
            mark = "ok" if t in lessons else "MISSING"
            print(f"    - {t}  [{mark}]")
    return 0


SCAFFOLD = """---
id: {id}
title: "{title}"
category: {category}
parent: {parent}
difficulty: medium
order: {order}
waystone: true
waystone_tasks: [{tasks}]
tags: [{category}, waystone, gate]
estimated_minutes: 40
summary: "Вейстоун: ветка откроется после решения {n} задач — {tasks}"
---

## Зачем этот вейстоун

Ветка «{title}» открывается не сразу: сначала подтверди навыки практикой.
Пока не решены все {n} задач ниже, поддерево этого вейстоуна скрыто — это
жёсткий замок (туман войны его не обходит).

## Задачи ветки

Чтобы открыть ветку, отметь пройденными все задачи:

{tasks_md}

## Как проверить

`python3 tools/waystone-gen.py check` — убедись, что все задачи существуют и
достижимы (лежат ДО вейстоуна, а не внутри его поддерева).

## Квиз

```quiz
- question: "Что произойдёт, если задача вейстоуна лежит внутри его же поддерева?"
  options:
    - "Ветка откроется быстрее"
    - "Задача недостижима и ветка запирается навсегда"
    - "Ничего"
  answer: 1
  explanation: "Задача внутри запираемого поддерева скрыта самим гейтом — её нельзя решить."
- question: "Когда вейстоун открывает ветку?"
  options:
    - "Когда прочитан сам вейстоун"
    - "Когда решены ВСЕ задачи из waystone_tasks"
    - "Никогда"
  answer: 1
  explanation: "Гейт открыт, только если completed у всех перечисленных задач."
- question: "Сколько задач по умолчанию подразумевает вейстоун?"
  options:
    - "1"
    - "5"
    - "10"
  answer: 1
  explanation: "N = длина waystone_tasks; на практике берут ~5 капстоун-задач."
```

## Где пригодится

- Контроль качества прохождения ветки.
- Подтверждение навыка практикой, а не только чтением.
"""


def cmd_new(args):
    lessons, _ = load_lessons()
    tasks = [t.strip() for t in (args.tasks or "").split(",") if t.strip()]
    if not tasks:
        print("ERROR: --tasks is required (comma-separated lesson ids)", file=sys.stderr)
        return 2
    for t in tasks:
        if t not in lessons:
            print(f"WARN: task {t!r} does not exist yet", file=sys.stderr)
    kids = children_map(lessons)
    siblings = kids.get(args.parent or "__root__", [])
    orders = [int(lessons[s]["order"]) for s in siblings if str(lessons[s]["order"]).isdigit()]
    order = (max(orders) + 1) if orders else 1
    body = SCAFFOLD.format(
        id=args.id, title=args.title or args.id, category=args.category,
        parent=args.parent, order=order, tasks=", ".join(tasks),
        n=len(tasks), tasks_md="\n".join(f"- {t}" for t in tasks),
    )
    if args.write:
        out = os.path.join(CONTENT, args.category, args.id + ".md")
        if os.path.exists(out):
            print(f"ERROR: {out} already exists", file=sys.stderr)
            return 2
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"wrote {os.path.relpath(out, ROOT)}")
    else:
        sys.stdout.write(body)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="waystone gate helper")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("check")
    sub.add_parser("list")
    pnew = sub.add_parser("new")
    pnew.add_argument("--id", required=True)
    pnew.add_argument("--category", required=True)
    pnew.add_argument("--parent", default="")
    pnew.add_argument("--title", default="")
    pnew.add_argument("--tasks", default="")
    pnew.add_argument("--write", action="store_true", help="write the file (default: print to stdout)")
    args = ap.parse_args(argv)
    cmd = args.cmd or "check"
    if cmd == "check":
        return cmd_check(args)
    if cmd == "list":
        return cmd_list(args)
    if cmd == "new":
        return cmd_new(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
