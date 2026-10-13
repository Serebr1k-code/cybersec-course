# Batch 7: misc — esolangs (real interpreters), rbash, regex, algorithmic, misc.
import base64
import os

B7 = '/tmp/labgen/b7'
WD = '/home/student/task'


def _b64(path):
    with open(os.path.join(B7, path), 'rb') as f:
        return base64.b64encode(f.read()).decode()


def _b64s(s):
    return base64.b64encode(s.encode()).decode()


_BF = _b64('flag.bf')
_WS = _b64('flag.ws')


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _lab(id, title, files, hints, flag, fs, tools=None, toolset=None):
    spec = {
        'id': id, 'category': 'misc', 'title': title,
        'toolset': toolset or ['core', 'grep'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }
    if tools:
        spec['tools'] = tools
    return spec


def _alg(id, title, flag, script, hints, extra=None):
    fs = [_dir(WD),
          _f(f'{WD}/task.md', f'# Задача\n\nРеши задачу из `{script}` и запиши флаг в `found.txt`.\n'),
          _f(f'{WD}/{script}', open(os.path.join(B7, 'alg', script)).read())]
    if extra:
        fs += extra
    return _lab(id, title, ['task.md', script], hints, flag, fs,
                toolset=['core', 'python3'],
                tools={'python3': {'help': 'python3 <скрипт> — эмуляция (вывод захвачен из реального запуска)',
                                   'cases': [{'match': script.replace('.', r'\.'), 'output': flag + '\n'}],
                                   'fallback': f'python3: доступно `python3 {script}`\n'}})


SPECS = [
    # rbash
    _lab('misc-bash-jails-deep', 'Практика: побег из restricted shell (rbash)',
         ['task.md', 'notes.txt'],
         ['`rbash` отключил `cd`, запуск по абсолютному пути и смену `PATH`.',
          'Разрешены только `vi`, `awk`, `less` — каждый умеет запускать команды.',
          "Например, `awk`: `awk 'BEGIN{system(\"cat flag.txt\")}'`. Запиши флаг в `found.txt`."],
         'nto{rb4sh_4wk_3sc4p3}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: rbash\n\nТебя пустили в restricted shell. Разрешены только `vi`, `awk`, `less`.\n'
             'Вырвись из ограничений и прочитай флаг. Запиши его в `found.txt`.\n'),
          _f(f'{WD}/notes.txt',
             '$ echo $SHELL\n/bin/rbash\n$ ls /usr/local/rbash/bin\nvi  awk  less\n')],
         toolset=['core', 'rbash', 'awk'],
         tools={
             'rbash': {'help': 'rbash — restricted shell (эмуляция реальной сессии)',
                       'cases': [
                           {'match': r"echo\s+\$SHELL", 'output': '/bin/rbash\n'},
                           {'match': r"ls\s+/usr/local/rbash/bin", 'output': 'vi  awk  less\n'},
                           {'match': r"cd\s+/", 'output': 'rbash: cd: restricted\n', 'code': 1},
                       ],
                       'fallback': 'rbash: в этой лабе доступны только `vi`, `awk`, `less`\n'},
             'awk': {'help': "awk 'BEGIN{system(\"...\")}' — выполнить команду (вывод захвачен из реального awk)",
                     'cases': [{'match': r"system\(.*cat.*flag", 'output': 'nto{rb4sh_4wk_3sc4p3}\n'}],
                     'fallback': 'awk: доступно `awk \'BEGIN{system("cat flag.txt")}\'`\n'},
         }),
    # eval sandbox
    _lab('misc-sandbox', 'Практика: eval-песочница сервиса',
         ['task.md', 'sandbox.py'],
         ['Прочитай `sandbox.py`: чёрный список слов, затем `eval`.',
          'Запрещённые слова нельзя писать буквально — собери их через `chr()`.',
          "Собери цепочку `vars()` → `__builtins__` → `__import__` из символов и запусти `python3 sandbox.py '<payload>'`."],
         'nto{3v4l_s4ndb0x_byp4ss}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: eval-песочница\n\n`sandbox.py` блокирует слова `import os system open subprocess eval exec`,\n'
             'затем вызывает `eval`. Обойди фильтр и прочитай флаг. Запиши его в `found.txt`.\n'),
          _f(f'{WD}/sandbox.py',
             "blacklist = ['import', 'os', 'system', 'open', 'subprocess', 'eval', 'exec']\n"
             "expr = input('>>> ')\n"
             "if any(b in expr for b in blacklist):\n"
             "    print('blocked'); exit(1)\n"
             "print(eval(expr))\n")],
         toolset=['core', 'python3'],
         tools={'python3': {'help': 'python3 <скрипт> [аргумент] — эмуляция',
                            'cases': [
                                {'match': r"chr\(95\)", 'output': '>>> nto{3v4l_s4ndb0x_byp4ss}\n0\n'},
                                {'match': r"\b(import|os|system|open|subprocess|eval|exec)\b",
                                 'output': '>>> blocked\n', 'code': 1},
                            ],
                            'fallback': "python3: доступно `python3 sandbox.py '<payload>'`\n"}}),
    # regex dos
    _lab('misc-regex-dos', 'Практика: ReDoS',
         ['task.md', 'server.js', 'payload.txt'],
         ['`server.js` валидирует ввод «жадной» регуляркой с вложенными квантификаторами.',
          'Такая регулярка уходит в экспоненциальный бэктрекинг на почти-совпадающем вводе.',
          "Флаг лежит рядом с уязвимой регуляркой — найди `nto{` и запиши в `found.txt`."],
         'nto{r3d0s_c4t4str0ph1c_b4ckt4ck1ng}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: ReDoS\n\nРазбери `server.js`, найди уязвимую регулярку и флаг рядом с ней.\n'),
          _f(f'{WD}/server.js',
             "const re = /^(a+)+$/;  // catastrophic backtracking\n"
             "function validate(input){ return re.test(input); }\n"
             "// debug: nto{r3d0s_c4t4str0ph1c_b4ckt4ck1ng}\n"),
          _f(f'{WD}/payload.txt', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX\n')]),
    # regex golf
    _lab('misc-regex-golf', 'Практика: regex-гольф',
         ['task.md', 'challenge.txt'],
         ['`challenge.txt` содержит список строк и подсказки к паттерну.',
          'Цель — короткая регулярка, различающая две группы.',
          "В файле есть флаг — найди `nto{` и запиши в `found.txt`."],
         'nto{r3g3x_g0lf_short3st_p4tt3rn}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: regex-golf\n\nНайди короткую регулярку под условие из `challenge.txt` и флаг рядом.\n'),
          _f(f'{WD}/challenge.txt',
             'match:   foo foo bar\n'
             'nomatch: foo bar baz\n'
             'goal: match the first group only\n'
             'flag: nto{r3g3x_g0lf_short3st_p4tt3rn}\n')]),
    # js obfuscation
    _lab('misc-esolang-js-obfuscation', 'Практика: JS-обфускация',
         ['task.md', 'obf.js'],
         ['`obf.js` — обфусцированный JavaScript (строки закодированы `\\xNN`).',
          'Запусти его в Node: `node obf.js`.',
          "Скрипт печатает флаг — запиши его в `found.txt`."],
         'nto{jsfuck_1s_st1ll_js}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: JS-обфускация\n\nРазбери обфусцированный скрипт и получи флаг: `node obf.js`.\n'),
          _f(f'{WD}/obf.js',
             'var a="\\x6e\\x74\\x6f\\x7b\\x6a\\x73\\x66\\x75\\x63\\x6b\\x5f\\x31\\x73\\x5f\\x73\\x74\\x31\\x6c\\x6c\\x5f\\x6a\\x73\\x7d";\n'
             'process.stdout.write(a+"\\n");\n')],
         toolset=['core', 'node'],
         tools={'node': {'help': 'node <файл> — эмуляция (вывод захвачен из реального node)',
                         'cases': [{'match': r"obf\.js", 'output': 'nto{jsfuck_1s_st1ll_js}\n'}],
                         'fallback': 'node: доступно `node obf.js`\n'}}),
    # brainfuck
    _lab('misc-esolang', 'Практика: Brainfuck',
         ['task.md', 'program.txt'],
         ['`program.txt` — программа на экзотическом языке из символов `><+-.,[]`.',
          'Это Brainfuck. Интерпретатор — `bf <файл>`.',
          "Запусти: `bf program.txt` — он напечатает флаг. Запиши в `found.txt`."],
         'nto{br41nfuck_1nt3rpr3t3r}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: Brainfuck\n\nОпредели язык программы и запусти интерпретатор `bf program.txt`.\n'
             'Полученный флаг запиши в `found.txt`.\n'),
          {'path': f'{WD}/program.txt', 'b64': _BF}],
         toolset=['core', 'bf'],
         tools={'bf': {'help': 'bf <файл> — интерпретатор Brainfuck (вывод захвачен из реального запуска)',
                       'cases': [{'match': r"program\.txt", 'output': 'nto{br41nfuck_1nt3rpr3t3r}\n'}],
                       'fallback': 'bf: доступно `bf program.txt`\n'}}),
    # whitespace
    _lab('misc-esolang-whitespace', 'Практика: Whitespace',
         ['task.md', 'program.ws'],
         ['`program.ws` выглядит пустым — но в нём спрятана программа из пробелов, табов и переводов строк.',
          'Посмотри байты: `xxd program.ws`.',
          "Запусти интерпретатор: `ws program.ws` — он напечатает флаг. Запиши в `found.txt`."],
         'nto{wh1t3sp4c3_1s_1nv1s1bl3}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: Whitespace\n\nФайл кажется пустым. Разбери его байты и запусти `ws program.ws`.\n'
             'Флаг запиши в `found.txt`.\n'),
          {'path': f'{WD}/program.ws', 'b64': _WS}],
         toolset=['core', 'ws', 'xxd'],
         tools={'ws': {'help': 'ws <файл> — интерпретатор Whitespace (вывод захвачен из реального запуска)',
                       'cases': [{'match': r"program\.ws", 'output': 'nto{wh1t3sp4c3_1s_1nv1s1bl3}\n'}],
                       'fallback': 'ws: доступно `ws program.ws`\n'}}),
    # befunge
    _lab('misc-esolang-befunge', 'Практика: Befunge-93',
         ['task.md', 'program.bf93'],
         ['`program.bf93` — двумерная программа (Befunge): указатель ходит по сетке.',
          '`"..."` кладёт символы в стек, `,` печатает, `@` завершает.',
          "Запусти `befunge program.bf93` и запиши флаг в `found.txt`."],
         'nto{befunge_2d_3sc4p3}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: Befunge\n\nРазбери двумерную программу и запусти `befunge program.bf93`.\n'
             'Флаг запиши в `found.txt`.\n'),
          _f(f'{WD}/program.bf93', '"}3p4cs3_d2_egnufeb{otn",,,,,,,,,,,,,,,,,,,,,,@\n')],
         toolset=['core', 'befunge'],
         tools={'befunge': {'help': 'befunge <файл> — интерпретатор Befunge-93 (вывод захвачен из реального запуска)',
                            'cases': [{'match': r"program\.bf93", 'output': 'nto{befunge_2d_3sc4p3}\n'}],
                            'fallback': 'befunge: доступно `befunge program.bf93`\n'}}),
    # algorithmic / misc analysis
    _alg('misc-complexity', 'Практика: сложность алгоритма', 'nto{0_n_l0g_l0g_n_b34ts_0_n2}',
         'complexity.py', ['`complexity.py` — оптимизированное решение для больших входов.',
                           'Разбери, почему sieve быстрее перебора.',
                           'Запусти `python3 complexity.py` и запиши флаг в `found.txt`.']),
    _alg('misc-dynamic-programming', 'Практика: динамическое программирование', 'nto{dp_0pt1m4l_substuctur3}',
         'dp.py', ['`dp.py` решает задачу о размене монет через DP.',
                   'Посмотри, как заполняется массив `dp`.',
                   'Запусти `python3 dp.py` и запиши флаг в `found.txt`.']),
    _alg('misc-graph-theory', 'Практика: графы и BFS', 'nto{bfs_sh0rt3st_p4th_f0und}',
         'graph.py', ['`graph.py` обходит граф в ширину.',
                   'BFS даёт кратчайшие расстояния от старта.',
                   'Запусти `python3 graph.py` и запиши флаг в `found.txt`.']),
    _alg('misc-number-theory-misc', 'Практика: теория чисел', 'nto{m0dul4r_1nv3rs3_gcd}',
         'nt.py', ['`nt.py` — задача на модульную арифметику.',
                   'Расширенный алгоритм Евклида даёт обратный элемент.',
                   'Запусти `python3 nt.py` и запиши флаг в `found.txt`.']),
    _alg('misc-chess-puzzles', 'Практика: шахматные задачи', 'nto{8_qu33ns_b4ckt4ck1ng}',
         'chess.py', ['`chess.py` решает задачу о N ферзях бэктрекингом.',
                   'Посчитай число решений для N=8.',
                   'Запусти `python3 chess.py` и запиши флаг в `found.txt`.']),
    _alg('misc-data-science-misc', 'Практика: данные и статистика', 'nto{m34n_m3d14n_m0d3_st4ts}',
         'ds.py', ['`ds.py` считает статистики по набору данных.',
                   'Разберись с mean/median/mode.',
                   'Запусти `python3 ds.py` и запиши флаг в `found.txt`.']),
    _alg('misc-programming', 'Практика: алгоритмическая задача', 'nto{cl34n_c0d3_w1ns}',
         'prog.py', ['`prog.py` — решение programming-задачи.',
                   'Проверь граничные случаи.',
                   'Запусти `python3 prog.py` и запиши флаг в `found.txt`.']),
    _alg('misc-math-puzzles', 'Практика: математическая головоломка', 'nto{pr0j3ct_3ul3r_style}',
         'math.py', ['`math.py` — решение в стиле Project Euler.',
                   'Разбери формулу.',
                   'Запусти `python3 math.py` и запиши флаг в `found.txt`.']),
    # radio
    _lab('misc-radio-misc', 'Практика: SDR / IQ-данные',
         ['task.md', 'iq_notes.txt'],
         ['`iq_notes.txt` — описание захваченного IQ-сигнала (суб-GHz).',
          'Ищи модуляцию, частоту и демодулированные данные.',
          "В заметках есть флаг — найди `nto{` и запиши в `found.txt`."],
         'nto{subghz_00k_d3m0d}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: SDR\n\nРазбери описание IQ-захвата и найди флаг.\n'),
          _f(f'{WD}/iq_notes.txt',
             'center_freq=433.92 MHz\nsample_rate=2 Msps\nmodulation=OOK\n'
             'demodulated bits -> "nto{subghz_00k_d3m0d}"\n')]),
    # ctf meta tooling
    _lab('misc-ctf-meta-tooling', 'Практика: CTF-инструментарий',
         ['task.md', 'toolbox.txt'],
         ['`toolbox.txt` — список инструментов и их вывода.',
          'Сопоставь задачу с инструментом (forensics → binwalk, web → ffuf).',
          "Среди вывода есть флаг — найди `nto{` и запиши в `found.txt`."],
         'nto{ch00s3_th3_r1ght_t00l}',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: инструментарий\n\nРазбери список инструментов и найди флаг.\n'),
          _f(f'{WD}/toolbox.txt',
             '$ binwalk -e firmware.bin\n  extracted squashfs-root/\n'
             '$ ffuf -u http://t/FUZZ -w wl\n  /admin [200]\n'
             '# note: nto{ch00s3_th3_r1ght_t00l}\n')]),
]
