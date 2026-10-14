#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_cloudgen.py — authoring helpers for the cloud gap batches.

Builds lesson bodies in the LESSON_TEMPLATE shape (sections -> Квиз -> Куда
дальше -> Где пригодится) and lab bundles, then delegates frontmatter/lab
emission to _newlesson.write_lesson. Not part of the engine.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def b64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _b(p, data, mode='644'):
    return {'path': p, 'b64': b64(data), 'mode': mode}


def _tool(name, cases, help_):
    return {name: {'help': help_, 'cases': cases}}


def quiz(qs):
    """qs: list of (question, [options], answer_index, explanation).
    Text must NOT contain double quotes (template rule)."""
    out = ['```quiz']
    for q, opts, a, ex in qs:
        assert '"' not in q, q
        out.append('- question: "%s"' % q)
        out.append('  options:')
        for o in opts:
            assert '"' not in o, o
            out.append('    - "%s"' % o)
        out.append('  answer: %d' % a)
        assert '"' not in ex, ex
        out.append('  explanation: "%s"' % ex)
    out.append('```')
    return '\n'.join(out)


def body(sections, quiz_qs, next_text, where_items):
    parts = []
    for h, t in sections:
        parts.append(h + '\n\n' + t.strip())
    parts.append('## Квиз\n\nПроверь себя.\n\n' + quiz(quiz_qs))
    parts.append('## Куда дальше\n\n' + next_text.strip())
    where = '\n'.join('- ' + w for w in where_items)
    parts.append('## Где пригодится\n\n' + where)
    return '\n\n'.join(parts)


def lab(files, hints, flag, fs, tools=None, title='Практика', toolset=None,
        workdir=WD, check=CHECK, expect_file=None, expect_contains=None,
        hostname='lab', env=None, vars_=None):
    return {
        'title': title, 'toolset': toolset or ['core', 'python'],
        'workdir': workdir, 'files': files, 'check': check, 'hints': hints,
        'expect': {'file': expect_file or (workdir + '/found.txt'),
                   'contains': expect_contains or flag},
        'fs': fs, 'tools': tools or {},
        'hostname': hostname,
        'env': env, 'vars': vars_,
    }


def hub_meta(hid, title, parent, order, tags, prereqs, useful, summary):
    return {
        'id': hid, 'category': 'cloud', 'title': title, 'parent': parent,
        'difficulty': 'hard', 'order': order, 'tags': tags,
        'prerequisites': prereqs, 'useful_for': useful,
        'estimated_minutes': 18, 'summary': summary,
    }


def write(meta, sections, quiz_qs, next_text, where_items, lab_spec=None):
    b = body(sections, quiz_qs, next_text, where_items)
    if lab_spec is not None:
        meta = dict(meta)
        meta['lab'] = {k: lab_spec[k] for k in
                       ('title', 'toolset', 'workdir', 'files', 'check', 'hints')}
        bundle = {
            'id': meta['id'], 'workdir': lab_spec['workdir'],
            'hostname': lab_spec.get('hostname', 'lab'),
        }
        if lab_spec.get('vars'):
            bundle['vars'] = lab_spec['vars']
        if lab_spec.get('env'):
            bundle['env'] = lab_spec['env']
        if lab_spec.get('expect'):
            bundle['expect'] = lab_spec['expect']
        bundle['fs'] = lab_spec.get('fs', [])
        if lab_spec.get('tools'):
            bundle['tools'] = lab_spec['tools']
        import json
        lp = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'content', 'labs', meta['id'] + '.json')
        with open(lp, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, ensure_ascii=False, indent=2)
            f.write('\n')
    path = write_lesson(meta, b)
    print('wrote', path)
    return path
