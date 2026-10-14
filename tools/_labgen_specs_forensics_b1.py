# Batch FB-1: interactive labs for 4 Windows-artifact gap lessons.
# Fixtures are real bytes (ESE-ish NTDS, DPAPI blob, bcache2, SECURITY hive)
# with a genuine flag embedded so `strings`/`base64 -d` find it for real.
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


def _lab(lid, title, files, hints, flag, fs, tools=None, toolset=None):
    spec = {
        'id': lid, 'category': 'forensics', 'title': title,
        'toolset': toolset or ['core', 'grep', 'base64'],
        'workdir': WD, 'files': files,
        'check': "grep -q 'nto{' found.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/found.txt', 'contains': flag},
        'fs': fs,
    }
    if tools:
        spec['tools'] = tools
    return spec


def _task(text, rest):
    return [_dir(WD), _f(f'{WD}/task.md', text)] + rest


# --- win-dpapi: DPAPI masterkey + base64 blob ------------------------------
DPAPI_SECRET = '{"user":"jdoe","password":"nto{dp4p1_m4st3rk3y_ch41n}"}'
MASTERKEY = (b'\x03\x00\x00\x00' + b'\x6e\x9a\xaa\xaa' + b'\x00' * 8 +
             b'5560fa6e-2b1c-4d3a-9f11-7c8e2a4b0d19' +
             b'\x00' * 16 + b'MASTERKEY-GUID 5560fa6e\r\n')

# --- win-ntds: fake ESE NTDS.dit with a secretsdump-shaped hash line --------
NTDS = (b'\xef\xcd\xab\x89' + b'\x00' * 12 + b'MSysObjects\x00' +
        b'\x00' * 64 + b'datatable\x00' * 3 + b'\x00' * 32 +
        b'Administrator:500:aad3b435b51404eeaad3b435b51404ee:'
        b'nto{ntds_d1t_p3k_unl0ck3d}::::\r\n' + b'\x00' * 64 +
        b'jdoe:1103:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99::::\r\n')
SYSTEM_HIVE = (b'regf' + b'\x00' * 12 + b'JD\x00\x00' + b'Skew1\x00' +
               b'GBG\x00' + b'Data\x00' + b'\x00' * 32 + b'bootKey-material\r\n')

# --- win-rdp-artifacts: bcache2 bitmap cache with visible tile text ---------
BCACHE = (b'bcache2\x00\x00' + b'\x00' * 8 +
          b'\x00' * 32 + b'cmd.exe - Remote Desktop\r\n'
          b'C:\\Users\\jdoe> type secret.txt\r\n'
          b'nto{rdp_b1tm4p_c4ch3_r3c0v3ry}\r\n' + b'\x00' * 48)
RDP_EVTX = (b'ElfFile\x00' + b'\x00' * 24 + b'TerminalServices-LocalSessionManager\r\n'
            b'<EventID>21</EventID>\r\n<Address>10.10.20.55</Address>\r\n'
            b'<User>CORP\\jdoe</User>\r\n')

# --- win-lsa-secrets: SECURITY hive with DefaultPassword secret -------------
SECURITY_HIVE = (b'regf' + b'\x00' * 12 + b'Policy\x00\x00' + b'Secrets\x00' +
                 b'\x00' * 24 + b'DefaultPassword\x00' + b'\x00' * 16 +
                 b'CORP\\svc_backup:nto{ls4_s3cr3ts_svc_p4ss}\r\n' + b'\x00' * 32 +
                 b'_SC_sqlsvc\x00' + b'CORP\\sqlsvc:Summer2024!\r\n')
SAM_HIVE = (b'regf' + b'\x00' * 12 + b'SAM\x00\x00' + b'Domains\x00' +
            b'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\r\n')

SPECS = [
    # ------------------------------------------------------------------ 1
    _lab('win-dpapi', 'Практика: расшифровка секрета DPAPI',
         ['task.md', 'masterkey.bin', 'secret.b64', 'protect.log'],
         ['Посмотри на файлы: `ls -la` и `file masterkey.bin`.',
          '`strings masterkey.bin` покажет GUID мастер-ключа.',
          'Секрет лежит в base64: `base64 -d secret.b64`.',
          'Найди флаг: `base64 -d secret.b64 | grep nto > found.txt`.'],
         'nto{dp4p1_m4st3rk3y_ch41n}',
         _task('# Задача: секрет DPAPI\n\n'
               'В профиле пользователя лежат мастер-ключ (`masterkey.bin`) и '
               'зашифрованный секрет (`secret.b64`, в base64). Расшифруй секрет и найди флаг.\n\n'
               '1. `ls -la` и `file masterkey.bin` — что за файлы.\n'
               '2. `strings masterkey.bin` — GUID мастер-ключа.\n'
               '3. `base64 -d secret.b64` — открытый секрет.\n'
               '4. `base64 -d secret.b64 | grep nto > found.txt`.\n',
               [_b(f'{WD}/masterkey.bin', MASTERKEY),
                _f(f'{WD}/secret.b64', b64(DPAPI_SECRET) + '\n'),
                _f(f'{WD}/protect.log',
                   'Protect/S-1-5-21-...-1001/5560fa6e-... (masterkey)\nCREDHIST present\n')]),
         ),
    # ------------------------------------------------------------------ 2
    _lab('win-ntds', 'Практика: разбор NTDS.dit',
         ['task.md', 'ntds.dit', 'SYSTEM'],
         ['`file ntds.dit` и `ls -l ntds.dit` — формат и размер.',
          'NTDS.dit нельзя прочитать без SYSTEM — но строки хешей читаются: `strings ntds.dit`.',
          'Флаг спрятан в строке вида имя:RID:LM:NT.',
          'Выдели флаг: `strings ntds.dit | grep nto > found.txt`.'],
         'nto{ntds_d1t_p3k_unl0ck3d}',
         _task('# Задача: база Active Directory\n\n'
               '`ntds.dit` — доменная база, `SYSTEM` — hive с boot key. В строке учётной '
               'записи спрятан флаг. Найди его.\n\n'
               '1. `file ntds.dit` и `ls -l ntds.dit`.\n'
               '2. `strings ntds.dit` — видно строки хешей (Administrator:500:...).\n'
               '3. `strings ntds.dit | grep nto > found.txt`.\n',
               [_b(f'{WD}/ntds.dit', NTDS),
                _b(f'{WD}/SYSTEM', SYSTEM_HIVE)]),
         ),
    # ------------------------------------------------------------------ 3
    _lab('win-rdp-artifacts', 'Практика: кэш битмапов RDP',
         ['task.md', 'Cache0000.bin', 'LocalSessionManager.evtx'],
         ['`xxd -l 16 Cache0000.bin` — проверь магию (bcache2).',
          '`strings Cache0000.bin` покажет текст из плиток экрана.',
          '`strings LocalSessionManager.evtx` даст адрес и учётку сессии.',
          'Флаг — в кэше битмапов: `strings Cache0000.bin | grep nto > found.txt`.'],
         'nto{rdp_b1tm4p_c4ch3_r3c0v3ry}',
         _task('# Задача: удалённая сессия RDP\n\n'
               '`Cache0000.bin` — кэш битмапов клиента RDP, `LocalSessionManager.evtx` — '
               'журнал сессий. Восстанови, что было на экране, и найди флаг.\n\n'
               '1. `xxd -l 16 Cache0000.bin` — магия `bcache2`.\n'
               '2. `strings Cache0000.bin` — текст плиток (виден вывод команд).\n'
               '3. `strings Cache0000.bin | grep nto > found.txt`.\n'
               '4. `strings LocalSessionManager.evtx` — адрес клиента и учётка.\n',
               [_b(f'{WD}/Cache0000.bin', BCACHE),
                _b(f'{WD}/LocalSessionManager.evtx', RDP_EVTX)]),
         ),
    # ------------------------------------------------------------------ 4
    _lab('win-lsa-secrets', 'Практика: LSA-секреты',
         ['task.md', 'SECURITY', 'SYSTEM', 'SAM'],
         ['`file SECURITY` — это реестровый hive (regf).',
          'Секреты лежат в ветвях Policy\\Secrets: `strings SECURITY`.',
          'Ищи строки с `nto{` среди секретов служб.',
          'Выдели флаг: `strings SECURITY | grep nto > found.txt`.'],
         'nto{ls4_s3cr3ts_svc_p4ss}',
         _task('# Задача: секреты LSA\n\n'
               'Три hive-файла: `SECURITY`, `SYSTEM`, `SAM`. В `SECURITY` лежат секреты LSA '
               '(пароли служб, автологин). Найди флаг среди них.\n\n'
               '1. `file SECURITY` — формат regf.\n'
               '2. `strings SECURITY` — видно DefaultPassword и _SC_sqlsvc.\n'
               '3. `strings SECURITY | grep nto > found.txt`.\n',
               [_b(f'{WD}/SECURITY', SECURITY_HIVE),
                _b(f'{WD}/SYSTEM', SYSTEM_HIVE),
                _b(f'{WD}/SAM', SAM_HIVE)]),
         ),
]
