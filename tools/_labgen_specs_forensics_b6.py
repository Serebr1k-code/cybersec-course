# Batch FB-6: interactive labs for 4 malware-analysis gap lessons.
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


# --- mal-static: PE with strings -------------------------------------------
INVOICE = (b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' +
           b'\x00' * 24 + b'This program cannot be run in DOS mode\x00' +
           b'\x00' * 16 + b'GetProcAddress\x00LoadLibraryA\x00WinExec\x00' +
           b'cmd.exe /c whoami\x00http://10.10.20.9/upd.bin\x00' +
           b'Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00' +
           b'nto{st4t1c_str1ngs_4n4lys1s}\x00')

# --- mal-unpacking: packed + unpacked --------------------------------------
PACKED = (b'MZ\x90\x00' + b'\x00' * 16 + b'UPX0\x00UPX1\x00' +
          b'\x00' * 32 + b'packed-blob-' + b'\x9c' * 64)
UNPACKED = (b'MZ\x90\x00' + b'\x00' * 16 + b'.text\x00.rdata\x00' +
            b'\x00' * 16 + b'kernel32.dll\x00WinExec\x00' +
            b'http://10.10.20.9/upd.bin\x00' +
            b'nto{upx_unp4ck3d_st4g3}\x00')

# --- mal-config-extraction: beacon config ----------------------------------
BEACON_CFG = (
    '--- Cobalt Strike Beacon Config ---\n'
    'BeaconType: HTTPS\n'
    'C2Server: cdn-update.example,/api\n'
    'Port: 443\n'
    'UserAgent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n'
    'Watermark: 1234567890\n'
    'SleepTime: 60000\n'
    'Jitter: 20\n'
    'nto{c2_c0nf1g_3xtr4ct3d}\n'
)

# --- mal-dotnet: .NET assembly ---------------------------------------------
DOTNET = (b'MZ\x90\x00' + b'\x00' * 16 + b'.text\x00.rsrc\x00' +
          b'\x00' * 16 + b'mscoree.dll\x00_CorExeMain\x00mscorlib\x00' +
          b'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAA' + b'\x00' * 8 +
          b'nto{d0tn3t_d3c0mp1l3d}\x00')

SPECS = [
    _lab('mal-static', 'Практика: статический анализ образца',
         ['task.md', 'invoice.exe'],
         ['`file invoice.exe` — определи формат.',
          '`strings invoice.exe` — самый быстрый источник подсказок.',
          'Ищи URL, команды и ключи реестра.',
          'Выдели флаг: `strings invoice.exe | grep nto > found.txt`.'],
         'nto{st4t1c_str1ngs_4n4lys1s}',
         _task('# Задача: статический разбор\n\n'
               '`invoice.exe` — подозрительный образец. НЕ запускай его. Найди флаг '
               'статически.\n\n'
               '1. `file invoice.exe`.\n'
               '2. `strings invoice.exe` — URL, команды, ключ Run.\n'
               '3. `strings invoice.exe | grep nto > found.txt`.\n',
               [_b(f'{WD}/invoice.exe', INVOICE, mode='755')]),
         ),
    _lab('mal-unpacking', 'Практика: распаковка образца',
         ['task.md', 'packed.exe', 'unpacked.bin'],
         ['`file packed.exe` и `strings packed.exe` — образец упакован.',
          'Секции UPX0/UPX1 указывают на упаковщик UPX.',
          'После распаковки код в `unpacked.bin` содержит строки.',
          'Выдели флаг: `strings unpacked.bin | grep nto > found.txt`.'],
         'nto{upx_unp4ck3d_st4g3}',
         _task('# Задача: распаковка\n\n'
               '`packed.exe` — упакованный образец, `unpacked.bin` — результат снятия '
               'упаковки. Найди флаг в распакованном коде.\n\n'
               '1. `strings packed.exe` — почти нет строк (упакован).\n'
               '2. `strings unpacked.bin` — появились импорты и URL.\n'
               '3. `strings unpacked.bin | grep nto > found.txt`.\n',
               [_b(f'{WD}/packed.exe', PACKED, mode='755'),
                _b(f'{WD}/unpacked.bin', UNPACKED)]),
         ),
    _lab('mal-config-extraction', 'Практика: конфигурация малвари',
         ['task.md', 'beacon.cfg'],
         ['`cat beacon.cfg` — конфигурация beacon.',
          'Смотри поля C2Server, Port, UserAgent, Watermark.',
          'Флаг спрятан среди полей конфигурации.',
          'Выдели флаг: `grep nto beacon.cfg > found.txt`.'],
         'nto{c2_c0nf1g_3xtr4ct3d}',
         _task('# Задача: извлечение конфигурации\n\n'
               '`beacon.cfg` — извлечённая конфигурация beacon. Определи адрес C2 и найди '
               'флаг.\n\n'
               '1. `cat beacon.cfg`.\n'
               '2. Смотри C2Server, Port, Watermark.\n'
               '3. `grep nto beacon.cfg > found.txt`.\n',
               [_f(f'{WD}/beacon.cfg', BEACON_CFG)]),
         ),
    _lab('mal-dotnet', 'Практика: разбор .NET-образца',
         ['task.md', 'update.exe'],
         ['`file update.exe` — определи .NET-признак.',
          '`strings update.exe` покажет mscoree.dll, mscorlib, base64-нагрузку.',
          'Base64-строка начинается с TVqQ (это MZ).',
          'Выдели флаг: `strings update.exe | grep nto > found.txt`.'],
         'nto{d0tn3t_d3c0mp1l3d}',
         _task('# Задача: .NET-загрузчик\n\n'
               '`update.exe` — .NET-сборка с загрузчиком. Найди признаки .NET и флаг.\n\n'
               '1. `file update.exe`.\n'
               '2. `strings update.exe` — mscoree.dll, mscorlib, base64.\n'
               '3. `strings update.exe | grep nto > found.txt`.\n',
               [_b(f'{WD}/update.exe', DOTNET, mode='755')]),
         ),
]
