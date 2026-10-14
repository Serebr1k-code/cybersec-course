#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared helper for stego gap batch B3 generators (idempotent, skip-if-exists).

Writes:
  content/stego/<id>.md      — the lesson (front-matter + body)
  content/labs/<id>.json     — the interactive lab fixture bundle
"""
import base64, json, os, sys

ROOT = "content"
FORCE = "--force" in sys.argv


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def write(path, text, force=None):
    if force is None:
        force = FORCE
    if os.path.exists(path) and not force:
        print("SKIP(exists)", path)
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("WROTE", path)
    return True


def build_lab(lid, flag, task, files, tool_cases=None, tools=None, hostname="lab"):
    """files: list of (name, ('text', str) | ('b64', bytes)).
    tool_cases: list of (toolname, case-dict) OR dict {toolname: [cases]}.
    If `tools` given it is used verbatim; else python3 is the only tool."""
    fs = [{"path": "/home/student/task", "type": "dir"},
          {"path": "/home/student/task/task.md", "text": task}]
    for name, (kind, val) in files:
        if kind == "b64":
            fs.append({"path": "/home/student/task/" + name, "b64": b64(val)})
        else:
            fs.append({"path": "/home/student/task/" + name, "text": val})
    if tools is None:
        tools = {}
    return {
        "id": lid,
        "workdir": "/home/student/task",
        "hostname": hostname,
        "expect": {"file": "/home/student/task/found.txt", "contains": flag},
        "fs": fs,
        "tools": tools,
    }


def emit(lid, md, lab):
    write(ROOT + "/stego/" + lid + ".md", md)
    write(ROOT + "/labs/" + lid + ".json",
          json.dumps(lab, ensure_ascii=False, indent=2) + "\n")
