#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab specs for the anti-forensics cluster (core-command labs)."""
import base64

def b64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')

WD = '/home/student/task'

# --- fixtures -------------------------------------------------------------
photo = (b'\xff\xd8\xff\xe1\x00\x10Exif\x00\x00'
         b'Make=Canon\x00Model=EOS\x00'
         b'GPS=55.7558N,37.6173E\x00'
         b'Comment=nto{ex1f_l34ks_s3cr3ts}\x00'
         b'\xff\xd9')

disk = b'\x00' * 220 + b'nto{d3l3t3d_n0t_w1p3d}\x00' + b'\x00' * 220

strings_out = (
    'MZ\x90\x00\n'
    'VBOX__GUEST\n'
    'vmware-tools\n'
    'qemu-ga\n'
    'nto{vmd3t3ct10n_c0d3}\n'
    'sandbox\n'
    'vmmouse.sys\n'
)

SPECS = [
    {
        'id': 'af-metadata-scrubbing', 'category': 'forensics',
        'title': 'Практика: метаданные файла',
        'toolset': ['core'], 'workdir': WD,
        'files': ['task.md', 'photo.jpg'], 'check': "grep -q 'nto{' answer.txt",
        'hints': [
            'Начни с `file photo.jpg` — убедись, что это изображение.',
            'Метаданные лежат в самом файле как текст: `strings photo.jpg`.',
            'Найди строку с флагом: `strings photo.jpg | grep nto > answer.txt`.',
        ],
        'expect': {'file': WD + '/answer.txt', 'contains': 'nto{ex1f_l34ks_s3cr3ts}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': '# Задача: метаданные\n\n`photo.jpg` — фото с метаданными. Найди скрытую в метаданных метку и запиши её в `answer.txt`.\n\n1. `file photo.jpg` — тип файла.\n2. `strings photo.jpg` — текстовые поля (EXIF и др.).\n3. `strings photo.jpg | grep nto > answer.txt`.\n'},
            {'path': WD + '/photo.jpg', 'b64': b64(photo), 'mode': '644'},
        ],
    },
    {
        'id': 'af-secure-delete', 'category': 'forensics',
        'title': 'Практика: удалено ≠ стёрто',
        'toolset': ['core'], 'workdir': WD,
        'files': ['task.md', 'disk.img'], 'check': "grep -q 'nto{' answer.txt",
        'hints': [
            'Содержимое удалённого файла ищи в образе: `strings disk.img`.',
            'Файл «удалили», но не перезаписали — данные на месте.',
            '`strings disk.img | grep nto > answer.txt`.',
        ],
        'expect': {'file': WD + '/answer.txt', 'contains': 'nto{d3l3t3d_n0t_w1p3d}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': '# Задача: удаление vs стирание\n\n`disk.img` — фрагмент образа диска. Файл был «удалён» обычным способом. Найди остаточные данные.\n\n1. `strings disk.img` — печатаемые строки.\n2. `strings disk.img | grep nto > answer.txt`.\n'},
            {'path': WD + '/disk.img', 'b64': b64(disk), 'mode': '644'},
        ],
    },
    {
        'id': 'af-vm-detection', 'category': 'forensics',
        'title': 'Практика: VM-detection код',
        'toolset': ['core'], 'workdir': WD,
        'files': ['task.md', 'strings_out.txt'], 'check': "grep -q 'nto{' answer.txt",
        'hints': [
            '`strings_out.txt` — строки из образца. Ищи маркеры гипервизоров.',
            '`grep -iE "vbox|vmware|qemu" strings_out.txt`.',
            'Метка лежит рядом с VM-маркерами: `grep nto strings_out.txt > answer.txt`.',
        ],
        'expect': {'file': WD + '/answer.txt', 'contains': 'nto{vmd3t3ct10n_c0d3}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': '# Задача: VM-detection\n\n`strings_out.txt` — строки, извлечённые из образца. Найди признаки проверки на виртуальную среду и метку рядом с ними.\n\n1. `grep -iE "vbox|vmware|qemu" strings_out.txt`.\n2. `grep nto strings_out.txt > answer.txt`.\n'},
            {'path': WD + '/strings_out.txt', 'text': strings_out, 'mode': '644'},
        ],
    },
]
