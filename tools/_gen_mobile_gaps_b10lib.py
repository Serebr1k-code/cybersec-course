#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MOB-GAP-10 shared helpers: radio / telecom / IoT-companion batch.

Content lessons live under three new module hubs:
  * mobile-radio-deep      — BLE / NFC / UWB (parent mobile-wearable-iot)
  * mobile-cellular-sim    — cellular protocols + SIM attacks (parent mobile-telecom)
  * mobile-sim-esim-deep   — SIM Toolkit + eSIM provisioning (parent mobile-telecom)
  * mobile-iot-companion   — IoT / wearable / car / drone companions (parent mobile-wearable-iot)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson, _dir, _f  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def lab(title, files, hints, flag, fs):
    """Lab bundle dict, mirroring the b8 batch conventions."""
    return {
        'title': title,
        'toolset': ['core', 'grep'],
        'workdir': WD,
        'files': files,
        'check': CHECK,
        'hints': hints,
        'expect': {'file': WD + '/found.txt', 'contains': flag},
        'fs': fs,
    }


def seed_dir():
    return _dir(WD)


def task_md(text):
    return _f(WD + '/task.md', text)


def seed(name, text):
    return _f(WD + '/' + name, text)


def quiz(qs):
    """Build a fenced ```quiz block from (question, options, answer, explanation)."""
    out = ['```quiz']
    for q, opts, a, exp in qs:
        out.append('- question: ' + q)
        out.append('  options:')
        for o in opts:
            out.append('    - ' + o)
        out.append('  answer: ' + str(a))
        out.append('  explanation: ' + exp)
    out.append('```')
    return '\n'.join(out)
