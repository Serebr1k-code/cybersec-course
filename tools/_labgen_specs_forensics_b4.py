# Batch FB-4: interactive labs for 4 memory-forensics gap lessons.
# Note: the lab engine's `strings` is ASCII-only, so flags in binary fixtures
# are seeded as printable ASCII runs (real byte-level extraction).
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _labgen import lab_block, write_bundle  # noqa: E402

WD = '/home/student/task'


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


def _lab(lid, title, files, hints, flag, fs, toolset=None):
    return {
        'id': lid, 'category': 'forensics', 'title': title,
        'toolset': toolset or ['core', 'grep', 'strings'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }


def _task(text, rest):
    return [_dir(WD), _f(f'{WD}/task.md', text)] + rest


# --- mem-acquisition: raw memory dump --------------------------------------
MEMDUMP = (b'\x00' * 64 + b'System\x00' + b'\x00' * 32 + b'nginx\x00' +
           b'\x00' * 48 + b'C:\\Users\\jdoe> type secret.txt\r\n' +
           b'nto{m3m_dump_r4w_4cqu1r3d}\r\n' + b'\x00' * 64)

# --- mem-linux: lime dump with pslist/psscan hint --------------------------
MEMLIME = (b'EMiL\x00\x00' + b'\x00' * 12 + b'Linux version 5.15.0-91-generic\x00' +
           b'\x00' * 32 + b'systemd\x00nginx\x00kworkerd\x00hidden\x00' +
           b'\x00' * 16 + b'/tmp/.x/hidden --daemon\x00' +
           b'nto{l1nux_m3m0ry_h1dd3n_pr0c}\x00' + b'\x00' * 32)

# --- mem-swap-pagefile: pagefile with an ASCII secret ----------------------
PAGEFILE = (b'\x00' * 48 + b'Windows\x00' + b'\x00' * 24 +
            b'user=jdoe password=nto{p4g3f1l3_l34k3d_s3cr3t}\r\n' +
            b'\x00' * 48 + b'https://mail.corp.local/login\x00' + b'\x00' * 32)
HIBERFIL = (b'hibr\x00' + b'\x00' * 12 + b'chrome.exe\x00' + b'\x00' * 24 +
            b'https://portal.corp.local/invoices\x00')

# --- mem-shellcode: injected region with API strings -----------------------
SHELLCODE = (b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50' +
             b'\x00' * 8 + b'LoadLibraryA\x00GetProcAddress\x00WinExec\x00' +
             b'cmd.exe /c whoami\x00' + b'http://10.10.20.9/p\x00' +
             b'nto{sh3llc0d3_m4lf1nd_rwx}\x00' + b'\x00' * 16)

SPECS = [
    _lab('mem-acquisition', 'Практика: разбор дампа памяти',
         ['task.md', 'memdump.raw', 'acquire.log'],
         ['`file memdump.raw` и `ls -l memdump.raw` — размер образа.',
          'Память — бинарный файл: `strings memdump.raw`.',
          'В дампе видны имена процессов и фрагменты вывода команд.',
          'Выдели флаг: `strings memdump.raw | grep nto > found.txt`.'],
         'nto{m3m_dump_r4w_4cqu1r3d}',
         _task('# Задача: снятый дамп памяти\n\n'
               '`memdump.raw` — дамп оперативной памяти, `acquire.log` — журнал снятия. '
               'Найди в памяти флаг.\n\n'
               '1. `file memdump.raw`.\n'
               '2. `strings memdump.raw` — имена процессов и фрагменты.\n'
               '3. `strings memdump.raw | grep nto > found.txt`.\n',
               [_b(f'{WD}/memdump.raw', MEMDUMP),
                _f(f'{WD}/acquire.log',
                   'winpmem 3.3\nstart=2026-03-14T02:00:00Z\ndump=memdump.raw\n'
                   'sha256=9f1a7c\n')]),
         ),
    _lab('mem-linux', 'Практика: анализ памяти Linux',
         ['task.md', 'mem.lime'],
         ['`file mem.lime` — образ памяти Linux.',
          'Плагины Volatility ищут процессы и строки: `strings mem.lime`.',
          'Найди имя скрытого процесса и флаг.',
          'Выдели флаг: `strings mem.lime | grep nto > found.txt`.'],
         'nto{l1nux_m3m0ry_h1dd3n_pr0c}',
         _task('# Задача: память Linux-сервера\n\n'
               '`mem.lime` — дамп памяти Linux. Найди следы скрытого процесса и флаг.\n\n'
               '1. `file mem.lime`.\n'
               '2. `strings mem.lime` — версия ядра, имена процессов (pslist/psscan).\n'
               '3. `strings mem.lime | grep nto > found.txt`.\n',
               [_b(f'{WD}/mem.lime', MEMLIME)]),
         ),
    _lab('mem-swap-pagefile', 'Практика: секрет в pagefile',
         ['task.md', 'pagefile.sys', 'hiberfil.sys'],
         ['`file pagefile.sys` — бинарный файл подкачки.',
          'Windows хранит текст, ищи строки: `strings pagefile.sys`.',
          'Есть и hiberfil.sys — полный образ памяти.',
          'Выдели флаг: `strings pagefile.sys | grep nto > found.txt`.'],
         'nto{p4g3f1l3_l34k3d_s3cr3t}',
         _task('# Задача: память на диске\n\n'
               'Даны `pagefile.sys` (файл подкачки) и `hiberfil.sys` (образ гибернации). '
               'Найди секрет, оставшийся в подкачке.\n\n'
               '1. `file pagefile.sys`.\n'
               '2. `strings pagefile.sys` — видно user= и password=.\n'
               '3. `strings pagefile.sys | grep nto > found.txt`.\n',
               [_b(f'{WD}/pagefile.sys', PAGEFILE),
                _b(f'{WD}/hiberfil.sys', HIBERFIL)]),
         ),
    _lab('mem-shellcode', 'Практика: шеллкод из памяти',
         ['task.md', 'shellcode.bin'],
         ['`file shellcode.bin` — сырой код без заголовка.',
          '`xxd -l 16 shellcode.bin` — проверь пролог (fc 48 83 e4 f0).',
          '`strings shellcode.bin` покажет имена API и команду.',
          'Выдели флаг: `strings shellcode.bin | grep nto > found.txt`.'],
         'nto{sh3llc0d3_m4lf1nd_rwx}',
         _task('# Задача: внедрённый шеллкод\n\n'
               '`shellcode.bin` — регион, выгруженный из памяти процесса (rwx). '
               'Разбери пролог и найди флаг среди строк.\n\n'
               '1. `xxd -l 16 shellcode.bin` — пролог.\n'
               '2. `strings shellcode.bin` — LoadLibraryA/WinExec/URL.\n'
               '3. `strings shellcode.bin | grep nto > found.txt`.\n',
               [_b(f'{WD}/shellcode.bin', SHELLCODE)]),
         ),
]
