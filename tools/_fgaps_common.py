#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared helpers for gB forensics gap generators (authoring convenience)."""
import os, json

C = "content/forensics"
L = "content/labs"


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")


def fm(d):
    lab = d.get("lab")
    out = [
        "---",
        f"id: {d['id']}",
        f"title: {d['title']!r}",
        f"category: {d.get('category', 'forensics')}",
        f"parent: {d['parent']}",
        f"difficulty: {d['diff']}",
        f"order: {d['order']}",
        f"tags: {d['tags']}",
        f"prerequisites: {d['prereq']}",
        "useful_for:",
    ]
    for u in d.get("useful", ["CTF Forensics категория", "DFIR / Incident Response", "Анализ образов и артефактов"]):
        out.append(f"  - {u!r}")
    out.append(f"estimated_minutes: {d['mins']}")
    out.append(f"summary: {d['summary']!r}")
    if lab:
        out.append("lab:")
        out.append("  kind: shell")
        out.append(f"  title: {lab['title']!r}")
        out.append(f"  toolset: [{', '.join(lab.get('toolset', ['core', 'grep', 'strings']))}]")
        out.append(f"  workdir: {lab.get('workdir', '/home/student/task')}")
        out.append(f"  files: [{', '.join(lab.get('files', ['task.md']))}]")
        out.append("  check: 'grep -q ''nto{'' answer.txt'")
        out.append("  hints:")
        for h in lab.get("hints", [
            "Прочитай файл-артефакт: `cat <файл>`.",
            "Ищи строку с меткой nto{.",
            "Сохрани: `grep nto <файл> > answer.txt`.",
        ]):
            out.append(f"    - {h!r}")
    out.append("---")
    return "\n".join(out) + "\n"


def default_bundle(lid, task=None, evidence=None, flag=None):
    flag = flag or ("nto{" + lid.replace("-", "_") + "_0k}")
    task = task or (
        "# Задача\n\nАртефакт `evidence.txt` — фрагмент журнала/дампа. Найди строку "
        "с меткой и сохрани её в `answer.txt`.\n\n1. `cat evidence.txt`.\n"
        "2. `grep nto evidence.txt > answer.txt`.\n")
    evidence = evidence or (
        f"# фрагмент артефакта {lid}\n"
        "warning: suspicious activity detected\n"
        f"marker: {flag}\n")
    return {
        "id": lid,
        "workdir": "/home/student/task",
        "hostname": "lab",
        "expect": {"file": "/home/student/task/answer.txt", "contains": flag},
        "fs": [
            {"path": "/home/student/task", "type": "dir"},
            {"path": "/home/student/task/task.md", "text": task, "mode": "644"},
            {"path": "/home/student/task/evidence.txt", "text": evidence, "mode": "644"},
        ],
    }


def emit(hubs, lessons):
    for hid, hub in hubs.items():
        w(f"{C}/{hid}.md", hub)
    for lid, d in lessons.items():
        d["id"] = lid
        d.setdefault("lab", {"title": f"Практика: {d['title'].split(':')[0]}"})
        w(f"{C}/{lid}.md", fm(d) + "\n" + d["body"].strip() + "\n")
        b = d.get("bundle") or default_bundle(lid)
        w(f"{L}/{lid}.json", json.dumps(b, ensure_ascii=False, indent=2))
        print("wrote", lid)
