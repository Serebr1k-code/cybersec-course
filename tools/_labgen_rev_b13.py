#!/usr/bin/env python3
"""Author lab batch reversing-b13: labs for the 9 hands-on lessons from the
gB-reversing gap batch that lack a `lab:` block."""
import base64, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS_DIR = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"

def b64(d):
    return base64.b64encode(d).decode()

def f_dir(p):
    return {'path': p, 'type': 'dir'}

def f_b64(p, d, mode='644'):
    return {'path': p, 'b64': b64(d), 'mode': mode}

def f_text(p, t, mode='644'):
    return {'path': p, 'text': t, 'mode': mode}

# ---------------------------------------------------------------- fixtures --
def pe(payload, wide=False):
    b = bytearray(b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00')
    b += b'PE\x00\x00' + b'L\x01\x04\x00' + b'\x00' * 200
    if isinstance(payload, str):
        payload = payload.encode('utf-16-le') if wide else payload.encode()
    b += payload
    return bytes(b)

def beacon_exe():
    b = bytearray(pe(''))
    b += b'\x2e' * 8  # XOR key byte
    # "encrypted" config region: key 0x2e XOR'd plaintext markers
    plain = b'MAGIC\x00\x00beef\x00C2\x0010.10.20.7:443\x00URI\x00/submit.php\x00SLEEP\x0060000\x00'
    b += bytes(c ^ 0x2e for c in plain)
    return bytes(b)

def inject_exe():
    imports = (b'KERNEL32.dll\x00OpenProcess\x00VirtualAllocEx\x00WriteProcessMemory\x00'
               b'CreateRemoteThread\x00NtUnmapViewOfSection\x00QueueUserAPC\x00'
               b'mutex_nto{cr34t3r3m0t3thr34d_1nj3ct10n}\x00')
    return pe(imports)

def shellcode_bin():
    stub = bytes([0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x83, 0xED, 0x06, 0x8D, 0x85, 0x00, 0x00, 0x00, 0x00])
    stub += bytes(range(0x90, 0x90 + 16))
    stub += b'\xfc\xe8\x82\x00\x00\x00'  # Metasploit-ish prologue bytes
    stub += b'http://10.10.20.7/stage\x00nto{d0nut_st4g3_r3fl3ct1v3}\x00'
    return stub

def metadata_dat():
    b = bytearray(b'\xaf\x1b\xb1\xfa' + b'\x00' * 24 + b'\x1d\x00\x00\x00')
    b += b'\x00' * 64
    b += b'Assembly-CSharp\x00UnityEngine.CoreModule\x00GameManager\x00'
    b += b'PlayerPrefs.GetString\x00System.String\x00'
    b += b'secretKey_nto{1l2cpp_m3t4d4t4_str1ngs}\x00'
    return bytes(b)

def packed_apk():
    b = bytearray(b'PK\x03\x04' + b'\x14\x00\x00\x00' + b'\x00' * 24)
    b += b'AndroidManifest.xml\x00classes.dex\x00resources.arsc\x00META-INF/CERT.RSA\x00'
    b += b'\x00' * 40
    b += b'com.bangcle.protect.StubApp\x00assets/libjiagu.so\x00'
    return bytes(b)

def classes_dex():
    b = bytearray(b'dex\n035\x00' + b'\x00' * 24)
    b += b'\x00' * 40
    b += b'Lcom/example/app/MainActivity;\x00checkLicense\x00'
    b += b'decrypted_payload_nto{unp4ck3d_d3x_b4ngcl3}\x00'
    return bytes(b)

def libsample_so():
    b = bytearray(b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8)
    b += bytes([3, 0, 0xB7, 0, 1, 0, 0, 0])  # AArch64
    b += b'\x00' * 152
    b += b'check_key\x00helper\x00'
    b += b'stp x29, x30, [sp, #-16]!\x00mov x29, sp\x00csel x0, x1, x2, eq\x00'
    b += b'flag_nto{4rm64_csel_k3y_ch3ck}\x00'
    return bytes(b)

def implant_exe():
    stub = b'\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3'  # mov r10,rcx; mov eax,18h; syscall; ret
    b = bytearray(pe(''))
    b += stub
    b += b'\x00' * 8
    b += b'HellGate\x00HaloGate\x00FreshyCalls\x00SysWhispers3\x00'
    b += b'ssn_table_nto{h3lls_g4t3_ssn_0x18}\x00'
    return bytes(b)

LABS = []

def add(**k):
    LABS.append(k)

# ================================================================ LABS ======
add(cat='reversing', id='reversing-c2-beacon-config',
    title='Практика: декодируем конфиг C2-бикона',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: конфиг C2-бикона\n\n"
        "`beacon.exe` — образец бикона. Строки внутри зашифрованы однобайтовым XOR\n"
        "(ключ — первый байт конфиг-блока), поэтому `strings beacon.exe` показывает мусор.\n\n"
        "1. `strings -n 6 beacon.exe` — убедись, что адреса C2 в открытом виде нет.\n"
        "2. `xxd -l 96 beacon.exe` — найди блок после PE-заголовка.\n"
        "3. В каталоге лежит разбор-скрипт `beacon_conf.py`; запусти его:\n"
        "   `python3 beacon_conf.py beacon.exe` — он снимет XOR и распечатает поля конфига.\n"
        "4. Найди строку с флагом и сохрани её.\n\n"
        "Флаг: `nto{...}` среди расшифрованных полей.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/beacon.exe', beacon_exe()),
        f_text(WD + '/beacon_conf.py',
               "#!/usr/bin/env python3\n"
               "# Декодер конфига бикона: первый байт блока - XOR-ключ.\n"
               "import sys\n"
               "data = open(sys.argv[1], 'rb').read()\n"
               "key = 0x2e\n"
               "dec = bytes(b ^ key for b in data)\n"
               "print(dec.decode('latin-1'))\n")],
    tools={'python3': {
        'help': 'python3 <скрипт.py> [аргументы] — интерпретатор (эмуляция разбора конфига)',
        'cases': [
            {'match': r'beacon_conf',
             'example': 'beacon_conf.py beacon.exe',
             'output': (
                 'MAGIC  0x0000beef\n'
                 'VERSION 4\n'
                 'C2     10.10.20.7:443\n'
                 'URI    /submit.php\n'
                 'UA     Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n'
                 'SLEEP  60000\n'
                 'JITTER 37\n'
                 'KEYS   pubkey=30819f300d06092a864886f70d010101\n'
                 'FLAG   nto{b33f_c4f3_x0r_k3y_2e}\n')},
        ],
        'fallback': 'python3: в этой лабе эмулируется только beacon_conf.py.\n',
    }},
    hints=[
        '`strings` не находит C2, потому что конфиг XOR-нут одним байтом.',
        'Блок конфига начинается сразу после PE-заголовка; первый байт — ключ `0x2e`.',
        'Запусти `python3 beacon_conf.py beacon.exe` — скрипт снимет XOR и распечатает поля.',
        "`python3 beacon_conf.py beacon.exe > conf.txt`, затем `grep nto conf.txt > found.txt` и `check`.",
    ],
    flag='nto{b33f_c4f3_x0r_k3y_2e}', batch='reversing-b13',
    solution=["python3 beacon_conf.py beacon.exe > conf.txt", "grep nto conf.txt > found.txt"])

add(cat='reversing', id='reversing-process-injection',
    title='Практика: подпись инъекции по импортам',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: распознаём инъекцию\n\n"
        "`inject.exe` — подозрительный образец. Задача — по таблице импортов понять,\n"
        "какую технику инъекции он использует, и найти артефакт образца.\n\n"
        "1. `strings -n 6 inject.exe > s.txt` — выгрузи строки.\n"
        "2. Найди цепочку вызовов: `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` →\n"
        "   `CreateRemoteThread` — это классическая remote-thread инъекция.\n"
        "3. В строках спрятан артефакт-мутекс; найди строку с `nto{`.\n"
        "4. Сохрани её в `found.txt`.\n\n"
        "Флаг: `nto{...}` внутри строк образца.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/inject.exe', inject_exe())],
    tools={},
    hints=[
        'Начни со `strings -n 6 inject.exe` — импорты Windows видны как обычные строки.',
        'Классика remote-thread: `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`.',
        'Наличие `QueueUserAPC` без `CreateRemoteThread` выдаёт APC-инъекцию.',
        "`strings -n 6 inject.exe > s.txt && grep nto s.txt > found.txt`, затем `check`.",
    ],
    flag='nto{cr34t3r3m0t3thr34d_1nj3ct10n}', batch='reversing-b13',
    solution=["strings -n 6 inject.exe > s.txt", "grep nto s.txt > found.txt"])

add(cat='reversing', id='reversing-shellcode-loaders',
    title='Практика: разбор сырого shellcode-стаба',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: shellcode-загрузчик\n\n"
        "`payload.bin` — «сырой» blob без заголовков (не PE, не начинается с `MZ`).\n"
        "Это shellcode, который загрузчик разворачивает в памяти.\n\n"
        "1. `file payload.bin` — увидишь `data` (нет заголовка).\n"
        "2. `xxd -l 32 payload.bin` — первая инструкция `e8 00 00 00 00` это `call $+5`\n"
        "   (позиционно-независимый код).\n"
        "3. Выгрузи строки и найди URL стейджера и артефакт с флагом.\n\n"
        "Флаг: `nto{...}` среди строк payload.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/payload.bin', shellcode_bin())],
    tools={},
    hints=[
        'Файл не начинается с `MZ` — значит, это не PE, а raw shellcode.',
        'Первые байты `e8 00 00 00 00` = `call $+5`: типичный позиционно-независимый пролог.',
        'В строках виден URL стейджера — рядом лежит и флаг.',
        "`strings -n 5 payload.bin | grep nto > found.txt`, затем `check`.",
    ],
    flag='nto{d0nut_st4g3_r3fl3ct1v3}', batch='reversing-b13',
    solution=["xxd -l 32 payload.bin", "strings -n 5 payload.bin | grep nto > found.txt"])

add(cat='reversing', id='reversing-unity-il2cpp',
    title='Практика: строки из global-metadata.dat',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: IL2CPP-метаданные\n\n"
        "Игра собрана на Unity с бэкендом IL2CPP: логика в нативном `libil2cpp.so`,\n"
        "а имена классов/методов/строк — в `global-metadata.dat`. Нужен артефакт игры.\n\n"
        "1. `xxd -l 32 global-metadata.dat` — проверь магию метаданных (`0xFAB11BAF`).\n"
        "2. `strings -n 5 global-metadata.dat` — метаданные содержат строковые литералы игры.\n"
        "3. Найди строку-ключ с флагом.\n\n"
        "Флаг: `nto{...}` среди строк метаданных.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/global-metadata.dat', metadata_dat())],
    tools={},
    hints=[
        'В IL2CPP-сборке метаданные C# лежат в `global-metadata.dat` (магия `0xFAB11BAF`).',
        'Строковые литералы игры хранятся в метаданных открытым текстом.',
        'Используй `strings` с порогом 5 символов.',
        "`strings -n 5 global-metadata.dat | grep nto > found.txt`, затем `check`.",
    ],
    flag='nto{1l2cpp_m3t4d4t4_str1ngs}', batch='reversing-b13',
    solution=["strings -n 5 global-metadata.dat | grep nto > found.txt"])

add(cat='reversing', id='reversing-android-packers',
    title='Практика: распаковка Android-упаковщика',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: Android-упаковщик\n\n"
        "`packed.apk` защищён упаковщиком (Bangcle/Legu-подобным): настоящий DEX\n"
        "зашифрован и разворачивается в памяти при запуске.\n\n"
        "1. `strings -n 5 packed.apk` — видны следы упаковщика (`libjiagu.so`, `StubApp`).\n"
        "2. Сдампи память запущенного приложения эмулятором `frida-dexdump`.\n"
        "3. Дамп сохранит `classes.dex` — в нём уже расшифрованный код.\n"
        "4. Найди в дампе артефакт с флагом.\n\n"
        "Флаг: `nto{...}` среди строк `classes.dex`.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/packed.apk', packed_apk()),
        f_b64(WD + '/classes.dex', classes_dex())],
    tools={'frida-dexdump': {
        'help': 'frida-dexdump [-U] [-f <package>] — дамп DEX из памяти (эмуляция)',
        'cases': [
            {'match': r'-f',
             'example': '-U -f com.example.app',
             'output': '[*] Searching memory for DEX magic (dex\\n035\\x00)...\n'
                       '[+] Found DEX @ 0x7f8a1c2000\n'
                       '[+] Dumped -> classes.dex\n'},
        ],
        'fallback': 'frida-dexdump: укажи `-f <package>`.\n',
    }},
    hints=[
        'Сначала посмотри, что за упаковщик: `strings -n 5 packed.apk` (ищи `jiagu`, `StubApp`).',
        'Настоящий код появляется в памяти только после расшифровки — нужен дамп.',
        'Дампни DEX: `frida-dexdump -U -f com.example.app` — получишь `classes.dex`.',
        "`strings -n 5 classes.dex | grep nto > found.txt`, затем `check`.",
    ],
    flag='nto{unp4ck3d_d3x_b4ngcl3}', batch='reversing-b13',
    solution=["frida-dexdump -U -f com.example.app", "strings -n 5 classes.dex | grep nto > found.txt"])

add(cat='reversing', id='reversing-fuzzing-aflpp',
    title='Практика: читаем краш фаззера',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: краш из AFL++\n\n"
        "Ты запустил `afl-fuzz` на парсере `parse`. В каталоге `out/default/crashes/`\n"
        "лежит вход, на котором программа упала. Нужно понять, что за магия его ломает.\n\n"
        "1. `ls -la out/default/crashes` — список крашей.\n"
        "2. `cat out/default/crashes/crash_0000` — вход, который привёл к падению.\n"
        "3. Найди магическую строку-константу, которую искал фаззер.\n\n"
        "Флаг: `nto{...}` внутри краш-входа.\n"
    ),
    fs=[f_dir(WD), f_dir(WD + '/out'), f_dir(WD + '/out/default'),
        f_dir(WD + '/out/default/crashes'),
        f_text(WD + '/parse.c',
               '#include <string.h>\n'
               'int main(int argc, char** argv){ char buf[64]; /* read file */\n'
               '  if (!memcmp(buf, "MAGIC\\x00", 6)) { /* parse fields */ }\n'
               '  return 0; }\n'),
        f_text(WD + '/out/default/fuzzer_stats',
               'start_time        : 1750000000\n'
               'execs_done        : 1248391\n'
               'saved_crashes     : 1\n'
               'edges_found       : 42\n'),
        f_b64(WD + '/out/default/crashes/crash_0000',
              b'MAGIC\x00' + b'\x00' * 4 + b'nto{aflpp_c0v3r4g3_m4g1c_0xdead}\x00\xff\xff')],
    tools={},
    hints=[
        'Фаззер складывает падающие входы в `out/default/crashes/`.',
        'Открой вход: `cat out/default/crashes/crash_0000`.',
        'Магия — первые байты входа; в хвосте лежит артефакт с флагом.',
        "`strings -n 5 out/default/crashes/crash_0000 | grep nto > found.txt`, затем `check`.",
    ],
    flag='nto{aflpp_c0v3r4g3_m4g1c_0xdead}', batch='reversing-b13',
    solution=["ls -la out/default/crashes",
              "strings -n 5 out/default/crashes/crash_0000 | grep nto > found.txt"])

add(cat='reversing', id='reversing-hybrid-fuzzing',
    title='Практика: вход, найденный concolic-движком',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: гибридный фаззинг\n\n"
        "Чистый coverage-фаззинг не прошёл проверку `if (a == 0xDEADBEEF)`. SymCC\n"
        "решил ограничение и записал найденный вход в `solution.b64` (base64).\n\n"
        "1. `cat solution.b64` — это base64-строка решённого входа.\n"
        "2. Декодируй её: `base64 -d solution.b64`.\n"
        "3. В декодированном входе лежит флаг.\n\n"
        "Флаг: `nto{...}` в декодированном входе.\n"
    ),
    fs=[f_dir(WD),
        f_text(WD + '/target.c',
               '#include <stdint.h>\n'
               'void check(uint8_t* p){ if (*(uint32_t*)p == 0xDEADBEEF) __builtin_trap(); }\n'),
        f_text(WD + '/symcc.log',
               '[symcc] solving branch #3: (concat ... ) -> SAT\n'
               '[symcc] new input written: solution.b64\n'),
        f_text(WD + '/solution.b64', b64(b'solved input: nto{c0ncol1c_s0lv3d_c0nst4nt}\n'))],
    tools={},
    hints=[
        'SymCC пишет решённый вход в base64, чтобы байты не потерялись при передаче.',
        'Декодируй файл: `base64 -d solution.b64`.',
        'В декодированном входе — строка с флагом.',
        "`base64 -d solution.b64 > found.txt`, затем `check`.",
    ],
    flag='nto{c0ncol1c_s0lv3d_c0nst4nt}', batch='reversing-b13',
    solution=["cat solution.b64", "base64 -d solution.b64 > found.txt"])

add(cat='reversing', id='reversing-asm-arm64',
    title='Практика: читаем ARM64-проверку ключа',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: ARM64-дизассемблер\n\n"
        "`libsample.so` — ARM64-библиотека из прошивки. Нужно разобрать функцию\n"
        "проверки ключа и найти артефакт.\n\n"
        "1. `xxd -l 20 libsample.so` — заголовок ELF; `e_machine = 0xB7` = AArch64.\n"
        "2. `objdump -d libsample.so` — дизассемблер покажет пролог (`stp x29,x30`),\n"
        "   вызов (`bl`) и условный выбор (`csel`).\n"
        "3. Выгрузи строки и найди строку с флагом.\n\n"
        "Флаг: `nto{...}` среди строк библиотеки.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/libsample.so', libsample_so())],
    tools={'objdump': {
        'help': 'objdump [-d] <файл> — дизассемблер (эмуляция ARM64)',
        'cases': [
            {'match': r'-d',
             'example': '-d libsample.so',
             'output': (
                 'libsample.so:     file format elf64-littleaarch64\n\n'
                 'Disassembly of section .text:\n\n'
                 '0000000000000740 <check_key>:\n'
                 ' 740:\ta9bf7bfd \tstp\tx29, x30, [sp, #-16]!\n'
                 ' 744:\t910003fd \tmov\tx29, sp\n'
                 ' 748:\t52800041 \tmov\tw1, #0x2\n'
                 ' 74c:\t97ffffb5 \tbl\t630 <helper>\n'
                 ' 750:\t9a9f1020 \tcsel\tx0, x1, x2, eq\n'
                 ' 754:\ta8c17bfd \tldp\tx29, x30, [sp], #16\n'
                 ' 758:\td65f03c0 \tret\n')},
        ],
        'fallback': 'objdump: используй `-d <файл>`.\n',
    }},
    hints=[
        '`e_machine` в ELF-заголовке `0xB7` — это AArch64 (ARM64).',
        'В ARM64 вызов — `bl` (адрес возврата в `x30`), пролог сохраняет пару `stp x29,x30`.',
        '`csel` выбирает значение по условию без ветвления — типично для проверки ключа.',
        "`strings -n 5 libsample.so | grep nto > found.txt`, затем `check`.",
    ],
    flag='nto{4rm64_csel_k3y_ch3ck}', batch='reversing-b13',
    solution=["xxd -l 20 libsample.so", "objdump -d libsample.so",
              "strings -n 5 libsample.so | grep nto > found.txt"])

add(cat='reversing', id='reversing-win-syscalls-ssn',
    title='Практика: прямой системный вызов и SSN',
    toolset=['core', 'hex', 'strings'],
    task_md=(
        "# Практика: direct syscall\n\n"
        "`implant.exe` вызывает ядро напрямую (`syscall`), минуя `ntdll`, чтобы обойти\n"
        "EDR-хуки. Нужно определить номер системного вызова (SSN) и найти артефакт.\n\n"
        "1. `xxd -l 32 implant.exe` — увидишь стаб `mov r10,rcx; mov eax,18h; syscall`.\n"
        "2. `0x18` — это SSN (номер операции в конкретной сборке Windows).\n"
        "3. Выгрузи строки — там имена техник (Hell's Gate и т.п.) и артефакт.\n\n"
        "Флаг: `nto{...}` среди строк образца.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/implant.exe', implant_exe())],
    tools={},
    hints=[
        'В стабе перед `syscall` в `eax` кладут номер операции — SSN.',
        '`mov eax, 18h` = SSN `0x18` (например, `NtAllocateVirtualMemory`).',
        'Имена `HellGate`/`FreshyCalls` указывают, как имплант берёт SSN.',
        "`strings -n 5 implant.exe | grep nto > found.txt`, затем `check`.",
    ],
    flag='nto{h3lls_g4t3_ssn_0x18}', batch='reversing-b13',
    solution=["xxd -l 32 implant.exe", "strings -n 5 implant.exe | grep nto > found.txt"])

# ---------------------------------------------------------------- emit ------
def yaml_dq(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

def js_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

def lab_block(lab):
    lines = ['lab:', '  kind: shell', '  title: ' + yaml_dq(lab['title']),
             '  toolset: [' + ', '.join(lab['toolset']) + ']',
             '  workdir: ' + WD, '  files: [task.md]',
             '  check: ' + yaml_dq(CHECK), '  hints:']
    for h in lab['hints']:
        lines.append('    - ' + yaml_dq(h.replace('"', "'")))
    return '\n'.join(lines)

def build_fs(lab):
    fs = [f_dir(WD), f_text(WD + '/task.md', lab['task_md'])]
    for f in lab['fs']:
        if f.get('path') == WD and f.get('type') == 'dir':
            continue
        fs.append(f)
    return fs

def write_bundle(lab):
    bundle = {'id': lab['id'], 'workdir': WD, 'hostname': 'lab',
              'expect': {'file': WD + '/found.txt', 'contains': lab['flag']},
              'fs': build_fs(lab)}
    if lab.get('tools'):
        bundle['tools'] = lab['tools']
    with open(os.path.join(LABS_DIR, lab['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write('\n')

def inject(lab):
    path = os.path.join(ROOT, 'content', lab['cat'], lab['id'] + '.md')
    with open(path, encoding='utf-8') as f:
        txt = f.read()
    m = re.match(r'^(---\n)(.*?\n)(---\n)', txt, re.S)
    assert m, 'no front-matter: ' + path
    if re.search(r'^lab:', m.group(2), re.M):
        print('SKIP (already has lab):', lab['id'])
        return
    new = '---\n' + m.group(2) + lab_block(lab) + '\n---\n' + txt[m.end():]
    with open(path, 'w', encoding='utf-8') as f:
        f.write(new)

def write_spec(batch, labs):
    out = ["import { describe, it, expect } from 'vitest'",
           "import fs from 'node:fs'",
           "import path from 'node:path'",
           "import { createSession } from './session'",
           '',
           '// End-to-end solvability check for lab batch ' + batch + '.',
           "const dir = path.resolve(process.cwd(), '../content/labs')",
           "const WD = '/home/student/task'",
           "const CHECK = \"grep -q 'nto{' found.txt\"",
           '',
           'function load(id) {',
           "  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))",
           '}',
           '',
           'const LABS = [']
    for lab in labs:
        sol = ', '.join(js_str(c) for c in lab['solution'])
        out.append('  {')
        out.append('    id: ' + js_str(lab['id']) + ', flag: ' + js_str(lab['flag']) + ', hints: ' + str(len(lab['hints'])) + ',')
        out.append('    solution: [' + sol + '],')
        out.append('  },')
    out.append(']')
    out.append('')
    out.append("describe.each(LABS)('lab batch " + batch + ": $id', ({ id, flag, hints, solution }) => {")
    out.append('  const bundle = load(id)')
    out.append("  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }")
    out.append('')
    out.append("  it('bundle + seed files are consistent with the lesson lab block', () => {")
    out.append('    expect(bundle.id).toBe(id)')
    out.append('    expect(bundle.workdir).toBe(WD)')
    out.append('    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)')
    out.append('    expect(bundle.expect.file).toBe(`${WD}/found.txt`)')
    out.append('    expect(bundle.expect.contains).toBe(flag)')
    out.append('  })')
    out.append('')
    out.append("  it('replays the intended solution and passes check', async () => {")
    out.append('    const s = createSession({ spec, bundle })')
    out.append("    expect((await s.run('check')).code).toBe(1)")
    out.append('    for (const cmd of solution) await s.run(cmd)')
    out.append("    expect((await s.run('check')).code).toBe(0)")
    out.append('  })')
    out.append('})')
    path = os.path.join(ROOT, 'frontend', 'src', 'lab', batch + '.spec.js')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')

def main():
    batches = {}
    for lab in LABS:
        write_bundle(lab)
        inject(lab)
        batches.setdefault(lab['batch'], []).append(lab)
    for batch, labs in batches.items():
        write_spec(batch, labs)
    print('Wrote %d bundles, %d specs:' % (len(LABS), len(batches)))
    for b, labs in batches.items():
        print('  %s: %s' % (b, ', '.join(l['id'] for l in labs)))

if __name__ == '__main__':
    main()
