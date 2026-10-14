#!/usr/bin/env python3
"""Authoring helper for NEW content lessons + their lab bundles.

Not part of the engine — a content-authoring convenience (like _labgen.py /
_rw.py). Builds the front-matter exactly the way internal/content parses it and
optionally writes content/labs/<id>.json.

Usage from a batch file:

    from _newlesson import write_lesson, hub_meta, LESSON_TEMPLATE_TAIL
    write_lesson(meta, body, lab=lab_bundle)
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTENT = os.path.join(ROOT, 'content')


def _yaml(s):
    # Single-quoted YAML scalar; escape embedded single quotes.
    return "'" + str(s).replace("'", "''") + "'"


def build_frontmatter(m):
    L = ['---']
    L.append('id: ' + m['id'])
    L.append('title: ' + _yaml(m['title']))
    L.append('category: ' + m['category'])
    L.append('parent: ' + m['parent'])
    L.append('difficulty: ' + m['difficulty'])
    L.append('order: ' + str(m['order']))
    L.append('tags: [' + ', '.join(m['tags']) + ']')
    L.append('prerequisites: [' + ', '.join(m.get('prerequisites', [])) + ']')
    L.append('useful_for:')
    for u in m['useful_for']:
        L.append('  - ' + _yaml(u))
    L.append('estimated_minutes: ' + str(m.get('estimated_minutes', 30)))
    L.append('summary: ' + _yaml(m['summary']))
    if m.get('lab'):
        lab = m['lab']
        L.append('lab:')
        L.append('  kind: shell')
        if lab.get('title'):
            L.append('  title: ' + _yaml(lab['title']))
        L.append('  toolset: [' + ', '.join(lab.get('toolset', ['core', 'python'])) + ']')
        L.append('  workdir: ' + lab['workdir'])
        L.append('  files: [' + ', '.join(lab['files']) + ']')
        L.append('  check: ' + _yaml(lab['check']))
        L.append('  hints:')
        for h in lab['hints']:
            L.append('    - ' + _yaml(h))
    L.append('---')
    return '\n'.join(L)


def write_lesson(m, body, lab=None):
    """Write content/<category>/<id>.md and (optionally) its lab bundle."""
    cat = m['category']
    path = os.path.join(CONTENT, cat, m['id'] + '.md')
    if os.path.exists(path):
        raise SystemExit('refusing to overwrite existing lesson: ' + path)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(build_frontmatter(m) + '\n\n' + body.strip() + '\n')
    if lab is not None:
        bundle = {
            'id': m['id'],
            'workdir': lab['workdir'],
            'hostname': lab.get('hostname', 'lab'),
        }
        if lab.get('vars'):
            bundle['vars'] = lab['vars']
        if lab.get('env'):
            bundle['env'] = lab['env']
        if lab.get('expect'):
            bundle['expect'] = lab['expect']
        bundle['fs'] = lab.get('fs', [])
        if lab.get('tools'):
            bundle['tools'] = lab['tools']
        lp = os.path.join(CONTENT, 'labs', m['id'] + '.json')
        with open(lp, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, ensure_ascii=False, indent=2)
            f.write('\n')
    return path


# --- tiny lab fixture helpers ------------------------------------------------
def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def pyver():
    return {'match': '--version|^-V$', 'example': 'python3 --version',
            'output': 'Python 3.12.4'}


def py_tool(cases, help_='python3 <скрипт.py> — интерпретатор Python (эмуляция, вывод реального запуска)'):
    return {'python3': {'help': help_, 'cases': cases}}
