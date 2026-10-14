# Batch FB-5: interactive labs for 4 network-forensics gap lessons.
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
        'toolset': toolset or ['core', 'grep', 'strings', 'base64'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }


def _task(text, rest):
    return [_dir(WD), _f(f'{WD}/task.md', text)] + rest


# --- net-kerberos: tshark field dump ---------------------------------------
KERB = (
    '10.10.20.55  10.10.20.10  10  jdoe\n'
    '10.10.20.55  10.10.20.10  11  jdoe  till=2026-03-14 12:11:33\n'
    '10.10.20.55  10.10.20.30  12  jdoe\n'
    '10.10.20.55  10.10.20.10  11  Administrator  till=2036-03-14 02:11:33\n'
    'nto{g0ld3n_t1ck3t_t1ll_2036}\n'
)

# --- net-dns: query log with TXT answer ------------------------------------
DNS_LOG = (
    'aGVsbG8tZXhmaWwtcGFydC0x.evil.example   A\n'
    'c2VjcmV0LWNo dW5r.evil.example         A\n'
    'cmd.evil.example                        TXT  d2hvYW1p (whoami)\n'
    'mail.corp.local                         A\n'
    'nto{dns_tunn3l_3xf1ltr4t10n}\n'
)

# --- net-c2-reversing: base64 payload + beacon log -------------------------
C2_PAYLOAD = '{"cmd":"download","url":"http://10.10.20.9/p","flag":"nto{c2_pr0t0c0l_r3v3rs3d}"}'
C2_B64 = b64(C2_PAYLOAD)
BEACON = ('1.000\n61.000\n121.000\n181.000\n241.000\n')

# --- net-tcp-reassembly: reassembled stream with MZ header -----------------
STREAM7 = (b'\x00' * 8 + b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' +
           b'\x00' * 32 + b'C:\\Users\\jdoe\\update.exe\x00' +
           b'nto{tcp_r34ss3mbly_obj3ct}\x00' + b'\x00' * 16)

SPECS = [
    _lab('net-kerberos', 'Практика: Golden Ticket в трафике',
         ['task.md', 'kerberos.txt'],
         ['`cat kerberos.txt` — вывод полей Kerberos.',
          'msg_type 10 — AS-REQ, 11 — AS-REP, 12 — TGS-REQ.',
          'Обрати внимание на TGT с till в 2036 году.',
          'Выдели флаг: `grep nto kerberos.txt > found.txt`.'],
         'nto{g0ld3n_t1ck3t_t1ll_2036}',
         _task('# Задача: поддельный Kerberos-тикет\n\n'
               '`kerberos.txt` — поля из PCAP (tshark). Найди признак Golden Ticket и флаг.\n\n'
               '1. `cat kerberos.txt`.\n'
               '2. Смотри `till` у TGT (msg_type 11).\n'
               '3. `grep nto kerberos.txt > found.txt`.\n',
               [_f(f'{WD}/kerberos.txt', KERB)]),
         ),
    _lab('net-dns', 'Практика: DNS-туннель',
         ['task.md', 'dns_log.txt'],
         ['`cat dns_log.txt` — запросы и ответы DNS.',
          'Длинные случайные поддомены указывают на туннель.',
          'TXT-ответ может содержать команду.',
          'Выдели флаг: `grep nto dns_log.txt > found.txt`.'],
         'nto{dns_tunn3l_3xf1ltr4t10n}',
         _task('# Задача: DNS-эксфильтрация\n\n'
               '`dns_log.txt` — лог DNS-трафика. Определи признак туннеля и найди флаг.\n\n'
               '1. `cat dns_log.txt`.\n'
               '2. Поддомены вида `aGVsbG8...` — это base64.\n'
               '3. `grep nto dns_log.txt > found.txt`.\n',
               [_f(f'{WD}/dns_log.txt', DNS_LOG)]),
         ),
    _lab('net-c2-reversing', 'Практика: реверс C2-нагрузки',
         ['task.md', 'c2_payload.b64', 'beacon.log'],
         ['`cat beacon.log` — интервалы beacon.',
          '`cat c2_payload.b64` — нагрузка в base64.',
          'Декодируй: `base64 -d c2_payload.b64`.',
          'Выдели флаг: `base64 -d c2_payload.b64 | grep nto > found.txt`.'],
         'nto{c2_pr0t0c0l_r3v3rs3d}',
         _task('# Задача: командный канал\n\n'
               '`beacon.log` — времена обращений к C2, `c2_payload.b64` — нагрузка в base64. '
               'Восстанови содержимое и найди флаг.\n\n'
               '1. `cat beacon.log` — интервал 60с.\n'
               '2. `base64 -d c2_payload.b64` — JSON с командой.\n'
               '3. `base64 -d c2_payload.b64 | grep nto > found.txt`.\n',
               [_f(f'{WD}/c2_payload.b64', C2_B64 + '\n'),
                _f(f'{WD}/beacon.log', BEACON)]),
         ),
    _lab('net-tcp-reassembly', 'Практика: извлечение файла из TCP',
         ['task.md', 'stream7.raw'],
         ['`file stream7.raw` — это собранный поток.',
          '`xxd -l 16 stream7.raw` — проверь сигнатуру (MZ).',
          '`strings stream7.raw` покажет путь и флаг.',
          'Выдели флаг: `strings stream7.raw | grep nto > found.txt`.'],
         'nto{tcp_r34ss3mbly_obj3ct}',
         _task('# Задача: файл из потока\n\n'
               '`stream7.raw` — данные TCP-потока, собранные по sequence-номерам. '
               'Определи тип файла и найди флаг.\n\n'
               '1. `xxd -l 16 stream7.raw` — сигнатура MZ (PE-файл).\n'
               '2. `strings stream7.raw`.\n'
               '3. `strings stream7.raw | grep nto > found.txt`.\n',
               [_b(f'{WD}/stream7.raw', STREAM7)]),
         ),
]
