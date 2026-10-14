#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Labs for MIS-GAP-4d (chess-engine, anti-cheat)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _labgen  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def spec(lid, title, toolset, files, hints, flag, fs, tools=None):
    return {'id': lid, 'category': 'misc', 'title': title, 'toolset': toolset,
            'workdir': WD, 'files': files, 'check': CHECK, 'hints': hints,
            'expect': {'file': WD + '/found.txt', 'contains': flag},
            'fs': fs, 'tools': tools}


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


_labgen.apply(spec(
    'misc-chess-engine', 'Практика: анализ шахматного движка',
    ['core', 'strings', 'hex', 'file'],
    ['task.md', 'engine', 'source.c'],
    ['Движок общается по UCI: команды `uci`, `position fen ...`, `go`.',
     'В `source.c` разбор FEN использует `strcpy` без проверки длины.',
     'Флаг — строка в бинарнике: `strings engine | grep nto`.'],
    'nto{ch3ss_uc1_f3n_b0f}',
    [_dir(WD),
     _f(WD + '/task.md', '# Шахматный движок\n\nВ `engine` есть баг разбора FEN. Изучи `source.c` и найди флаг.\n'),
     _f(WD + '/engine', 'MiniChess 1.0\nuciok\nbestmove e2e4\nnto{ch3ss_uc1_f3n_b0f}\n'),
     _f(WD + '/source.c', "void set_fen(char *fen){ char board[64]; strcpy(board, fen); } // no length check\n")],
    tools={'strings': {'help': 'strings <файл>', 'cases': [
        {'match': 'engine', 'example': 'strings engine',
         'output': 'MiniChess 1.0\nuci\nbestmove\nnto{ch3ss_uc1_f3n_b0f}'}]}},
))

_labgen.apply(spec(
    'misc-anti-cheat', 'Практика: обход проверки анти-чита',
    ['core', 'strings', 'hex', 'file'],
    ['task.md', 'game', 'ac_report.txt'],
    ['`ac_report.txt` показывает, что анти-чит обнаружил.',
     'Найди в `game` проверку отладчика (BeingDebugged).',
     'Нейтрализуй проверку и найди флаг: `strings game | grep nto`.'],
    'nto{4nt1_ch34t_b3ingd3bugg3d_byp4ss}',
    [_dir(WD),
     _f(WD + '/task.md', '# Анти-чит\n\n`game` закрывается при обнаружении отладчика. Найди проверку и обойди её.\n'),
     _f(WD + '/game', '[AC] scan...\n[AC] BeingDebugged=1\nterminated\nnto{4nt1_ch34t_b3ingd3bugg3d_byp4ss}\n'),
     _f(WD + '/ac_report.txt', 'AC detected: PEB.BeingDebugged set. Bypass: zero the flag before the check.\n')],
    tools={'strings': {'help': 'strings <файл>', 'cases': [
        {'match': 'game', 'example': 'strings game',
         'output': 'BeingDebugged\nNtQueryInformationProcess\nnto{4nt1_ch34t_b3ingd3bugg3d_byp4ss}'}]}},
))

print('batch 4d labs done')
