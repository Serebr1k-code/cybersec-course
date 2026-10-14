#!/usr/bin/env python3
"""Author lab bundles + e2e spec for reversing b14 batch (15 lessons).

Each lesson already carries its `lab:` front-matter; this script writes the
matching content/labs/<id>.json bundle and a vitest spec proving solvability.
"""
import base64, json, os

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


def py_tool(match, example, output, fallback):
    return {'python3': {
        'help': 'python3 <скрипт.py> [аргументы] — интерпретатор (эмуляция разбора)',
        'cases': [{'match': match, 'example': example, 'output': output}],
        'fallback': fallback,
    }}


# ------------------------------------------------------------------ fixtures
def pe(payload=b''):
    b = bytearray(b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00')
    b += b'PE\x00\x00' + b'L\x01\x04\x00' + b'\x00' * 200
    b += payload
    return bytes(b)


PEB_BIN = bytes(range(256)) + b'PEB\x00' + b'LDR\x00InLoadOrderModuleList\x00'
HOOKS_BIN = (b'\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3' + b'\xcc' * 8 +
             b'\x4c\x8b\xd1\xb8\x08\x00\x00\x00\x0f\x05\xc3' + b'\xcc' * 8 +
             b'\xe9\x8a\x3c\x12\x00' + b'\x90' * 7 + b'edr_hook\x00')
CLASSES_BIN = (b'.?AVC2Channel@@\x00.?AVCryptoContext@@\x00.?AVLogger@@\x00' +
               b'\x00' * 64 + b'RTTI\x00vtable\x00' + b'\xaa' * 32)
LKM_BIN = (b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8 + bytes([1, 0, 62, 0]) +
           b'\x00' * 152 + b'vermagic=5.15.0-91-generic\x00' +
           b'register_kprobe\x00kallsyms_lookup_name\x00getdents64\x00' + b'\x00' * 64)
KEXT_PLIST = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              '<plist version="1.0"><dict>\n'
              '<key>CFBundleIdentifier</key><string>com.sample.driver</string>\n'
              '<key>CFBundleVersion</key><string>2.1.0</string>\n'
              '<key>IOKitPersonalities</key><dict><key>SampleUSB</key><dict>\n'
              '<key>IOProviderClass</key><string>IOUSBDevice</string>\n'
              '<key>IOClass</key><string>com_sample_driver</string>\n'
              '<key>IOUserClientClass</key><string>com_sample_userclient</string>\n'
              '</dict></dict></dict></plist>\n')
KEXT_BIN = (b'\xcf\xfa\xed\xfe' + b'\x07\x00\x00\x01' + b'\x03\x00\x00\x00' +
            b'\x00' * 40 + b'_IOService\x00_kprintf\x00externalMethod\x00' + b'\x00' * 32)
FIRMWARE_BIN = (b'_FVH' + b'\x00' * 12 + b'VZ\x90\x00' + b'\x00' * 20 +
                b'DxeCore\x00UsbBusDxe\x00NetworkStack\x00NtfsDxe\x00' + b'\x00' * 32)
APP_BIN = (b'\xcf\xfa\xed\xfe' + b'\x07\x00\x00\x01' + b'\x00' * 24 +
           b'__objc_classlist\x00__objc_methname\x00__objc_classname\x00' +
           b'LoginViewController\x00CryptoManager\x00viewDidLoad\x00encryptData:\x00' +
           b'\x00' * 32)
FUNC_BIN = bytes([0xD5, 0x03, 0x03, 0xFD]) + b'\xfd\x7b\xbf\xa9' + b'\x00' * 8 + \
    bytes([0xD5, 0x03, 0x03, 0xFD]) + bytes([0xFF, 0x0B, 0x00, 0xD5]) + b'\x00' * 8
TARGET_BIN = pe(b'check\x00MAGIC\x00strcmp\x00')
BLOB_BIN = (b'\xe9\x04\x00\x00\x00\xe8\x00\x00\x00\x00' + b'\x90' * 6 +
            b'\x31\xc0\x39\xc0\x75\x10' + b'\x00' * 12 + b'junk\x00' + b'\x00' * 8)
STRINGS_BIN = bytes(c ^ 0x5e for c in
                    b'http://10.10.20.7/gate.php\x00cmd.exe /c whoami\x00'
                    b'nto{x0r_str1ngs_d3crypt3d}\x00')
CRASH_BIN = b'MAGIC\x00\x00\x00\x00' + b'nto{l1bfuzz3r_4s4n_4rt1f4ct}\x00' + b'\xff\xff'
CRASHLOG = ('BUG: KASAN: slab-use-after-free in tcp_recvmsg\n'
            'Call Trace:\n  tcp_recvmsg+0x1a2/0x8c0\n  sock_recvmsg+0x1f0/0x210\n'
            'syz repro: 3 syscalls\nC repro: 12 lines\n'
            'crash type: KASAN: slab-use-after-free\nnote: nto{kcov_kasan_slab_uaf}\n')

LABS = []


def add(**k):
    LABS.append(k)


# ==================================================================== LABS ===
add(id='reversing-win-peb-teb',
    title='Практика: ручной обход загрузчика через PEB',
    task=("# Практика: PEB и список модулей\n\n"
          "`peb.bin` — дамп участка памяти процесса с PEB. Скрипт `walk_peb.py`\n"
          "обходит `InLoadOrderModuleList` и печатает модули.\n\n"
          "1. `xxd -l 48 peb.bin` — посмотри байты дампа.\n"
          "2. `python3 walk_peb.py peb.bin` — обход списка модулей.\n"
          "3. Найди модуль с флагом среди имён.\n\nФлаг: `nto{...}` среди имён модулей.\n"),
    fs=[f_b64(WD + '/peb.bin', PEB_BIN),
        f_text(WD + '/walk_peb.py',
               "# обход InLoadOrderModuleList\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('PEB @ 0x7ff7a1c00000')\n")],
    tool=py_tool(r'walk_peb', 'walk_peb.py peb.bin',
                 ('PEB @ 0x00007ff7a1c00000\nLdr @ 0x00007ffb8a2c4a80\n'
                  '--- InLoadOrderModuleList ---\n'
                  '[0] base=0x00007ff7a1b80000  ntdll.dll\n'
                  '[1] base=0x00007ffb87f00000  KERNEL32.DLL\n'
                  '[2] base=0x00007ffb87e00000  KERNELBASE.dll\n'
                  '[3] base=0x00007ff7a0c10000  nto{ntdll_unh00k_by_hand}\n'),
                 'python3: в этой лабе эмулируется только walk_peb.py.\n'),
    hints=['Дамп `peb.bin` — это память процесса; имена модулей в нём текстом.',
           'Список модулей — двусвязный InLoadOrderModuleList внутри PEB->Ldr.',
           'Запусти `python3 walk_peb.py peb.bin` — скрипт пройдёт список и напечатает модули.',
           "`python3 walk_peb.py peb.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{ntdll_unh00k_by_hand}',
    sol=['python3 walk_peb.py peb.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-win-api-hooking',
    title='Практика: находим inline-хук по прологу',
    task=("# Практика: детект inline-хука\n\n"
          "`hooks.bin` — дамп `ntdll` с несколькими функциями. Одна перехвачена\n"
          "(пролог заменён на `jmp`). Скрипт `find_hook.py` найдёт подмену.\n\n"
          "1. `xxd -l 32 hooks.bin` — каноничный пролог `4c 8b d1 b8 ... 0f 05 c3`.\n"
          "2. `python3 find_hook.py hooks.bin` — поиск подменённого пролога.\n"
          "3. Куда ведёт хук и что внутри?\n\nФлаг: `nto{...}` в цели хука.\n"),
    fs=[f_b64(WD + '/hooks.bin', HOOKS_BIN),
        f_text(WD + '/find_hook.py',
               "# сравнение прологов с эталоном\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('scanning', len(d), 'bytes')\n")],
    tool=py_tool(r'find_hook', 'find_hook.py hooks.bin',
                 ('[+] ntdll!NtCreateFile   prologue OK (4c 8b d1 b8 55 ...)\n'
                  '[+] ntdll!NtReadFile     prologue OK (4c 8b d1 b8 06 ...)\n'
                  '[!] ntdll!NtWriteFile    HOOKED: e9 8a 3c 12 00 -> 0x00007ffb3a118000\n'
                  '[+] 0x00007ffb3a118000   edr_hook_nto{1nline_h00k_d3t3ct3d}\n'),
                 'python3: в этой лабе эмулируется только find_hook.py.\n'),
    hints=['Сравни первые байты функции с каноничным прологом ntdll: `4c 8b d1 b8 ... 0f 05 c3`.',
           'Хук — это `jmp` в начало функции; опкод `e9` (relative) или `ff 25` (absolute).',
           'Запусти `python3 find_hook.py hooks.bin` — скрипт найдёт подменённый пролог.',
           "`python3 find_hook.py hooks.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{1nline_h00k_d3t3ct3d}',
    sol=['python3 find_hook.py hooks.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-win-seh-cpp',
    title='Практика: разбор vtable и RTTI',
    task=("# Практика: RTTI и vtable\n\n"
          "`classes.bin` — дамп секции данных C++-бинарника с RTTI и vtable.\n"
          "Скрипт `parse_rtti.py` восстановит классы и их методы.\n\n"
          "1. `strings -n 6 classes.bin | grep '?AV'` — имена классов MSVC.\n"
          "2. `python3 parse_rtti.py classes.bin` — классы, vtable и методы.\n"
          "3. Найди класс-маркер с флагом.\n\nФлаг: `nto{...}` среди классов.\n"),
    fs=[f_b64(WD + '/classes.bin', CLASSES_BIN),
        f_text(WD + '/parse_rtti.py',
               "# разбор RTTI-локаторов\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('scanning RTTI...')\n")],
    tool=py_tool(r'parse_rtti', 'parse_rtti.py classes.bin',
                 ('class C2Channel  @ 0x180012340  vtable=0x180020000\n'
                  '  [0] 0x180001010  ~C2Channel\n  [1] 0x1800010a0  Connect\n'
                  '  [2] 0x180001150  Send\n'
                  'class CryptoContext  vtable=0x180020080\n'
                  '  [1] 0x1800012c0  Encrypt  (AES-256-CBC)\n'
                  '  [2] 0x1800013a0  Decrypt\n'
                  'class nto{rtt1_vt4bl3_cl4ss_r3c0v3ry}\n'),
                 'python3: в этой лабе эмулируется только parse_rtti.py.\n'),
    hints=['RTTI-имя класса лежит рядом с типом-дескриптором: `.?AV<класс>@@`.',
           'vtable — массив указателей на методы; нулевой слот часто `dtor`.',
           'Запусти `python3 parse_rtti.py classes.bin` — скрипт напечатает классы и их методы.',
           "`python3 parse_rtti.py classes.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{rtt1_vt4bl3_cl4ss_r3c0v3ry}',
    sol=['python3 parse_rtti.py classes.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-linux-kernel-modules',
    title='Практика: разбор подозрительного LKM',
    task=("# Практика: анализ .ko\n\n"
          "`suspicious.ko` — модуль ядра Linux. Скрипт `scan_lkm.py` покажет\n"
          "секции и импортируемые символы ядра.\n\n"
          "1. `strings suspicious.ko | grep vermagic` — для какой версии ядра собран.\n"
          "2. `python3 scan_lkm.py suspicious.ko` — секции и импорты.\n"
          "3. Какую функцию ядра перехватывает модуль?\n\nФлаг: `nto{...}` в отчёте.\n"),
    fs=[f_b64(WD + '/suspicious.ko', LKM_BIN),
        f_text(WD + '/scan_lkm.py',
               "# разбор ELF-модуля ядра\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('ELF64 relocatable')\n")],
    tool=py_tool(r'scan_lkm', 'scan_lkm.py suspicious.ko',
                 ('ELF64 relocatable, arch=x86-64\n'
                  'sections: .text (size 0x1420)  .init.text  .data  .modinfo\n'
                  'undefined (imported) symbols:\n'
                  '  register_kprobe\n  kallsyms_lookup_name\n  getdents64  (patched?)\n'
                  '  nto{lkm_kpr0b3_g3td3nts_h00k}\n'),
                 'python3: в этой лабе эмулируется только scan_lkm.py.\n'),
    hints=['Заголовок модуля содержит поле vermagic и список symbol-версий.',
           'Ищи строки `kprobe`/`ftrace`/`register_kprobe` — ими перехватывают функции ядра.',
           'Запусти `python3 scan_lkm.py suspicious.ko` — скрипт покажет секции и импорты ядра.',
           "`python3 scan_lkm.py suspicious.ko > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{lkm_kpr0b3_g3td3nts_h00k}',
    sol=['python3 scan_lkm.py suspicious.ko > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-macos-kexts',
    title='Практика: разбор Info.plist kext',
    task=("# Практика: kext как бандл\n\n"
          "`Sample.kext` — бандл драйвера macOS: каталог с `Contents/Info.plist`\n"
          "и бинарником. Скрипт `kext_info.py` разберёт plist и метаданные.\n\n"
          "1. `find Sample.kext -type f` — структура бандла.\n"
          "2. `cat Sample.kext/Contents/Info.plist` — описание драйвера.\n"
          "3. `python3 kext_info.py Sample.kext` — идентификатор, IOKitPersonalities.\n\n"
          "Флаг: `nto{...}` в метаданных бандла.\n"),
    fs=[f_dir(WD + '/Sample.kext'), f_dir(WD + '/Sample.kext/Contents'),
        f_dir(WD + '/Sample.kext/Contents/MacOS'),
        f_text(WD + '/Sample.kext/Contents/Info.plist', KEXT_PLIST),
        f_b64(WD + '/Sample.kext/Contents/MacOS/Sample', KEXT_BIN),
        f_text(WD + '/kext_info.py',
               "# разбор бандла kext\nimport sys\nprint('bundle:', sys.argv[1])\n")],
    tool=py_tool(r'kext_info', 'kext_info.py Sample.kext',
                 ('Identifier: com.sample.driver\nVersion:    2.1.0\n'
                  'Mach-O:     x86_64 + arm64e (fat)\nSigned:     yes (Apple notarized)\n'
                  'IOKitPersonalities:\n  SampleUSB -> IOUSBDevice / com_sample_driver\n'
                  '  userclient: com_sample_userclient\n'
                  'note: bundle id nto{k3xt_10k1t_p3rs0n4l1t13s}\n'),
                 'python3: в этой лабе эмулируется только kext_info.py.\n'),
    hints=['kext — это бандл: каталог с Info.plist и бинарником в Contents/MacOS.',
           'В Info.plist ключ IOKitPersonalities описывает, какие устройства драйвер берёт.',
           'Запусти `python3 kext_info.py Sample.kext` — скрипт разберёт plist и метаданные.',
           "`python3 kext_info.py Sample.kext > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{k3xt_10k1t_p3rs0n4l1t13s}',
    sol=['python3 kext_info.py Sample.kext > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-smm-uefi',
    title='Практика: поиск DXE-драйвера в прошивке',
    task=("# Практика: разбор прошивки\n\n"
          "`firmware.bin` — дамп UEFI-прошивки. Скрипт `scan_uefi.py` ищет\n"
          "Firmware Volume и PE/TE-модули внутри.\n\n"
          "1. `xxd -l 16 firmware.bin` — сигнатура тома `_FVH`.\n"
          "2. `python3 scan_uefi.py firmware.bin` — список модулей.\n"
          "3. Найди модуль без вендорского GUID, ссылающийся на SMM.\n\n"
          "Флаг: `nto{...}` в отчёте.\n"),
    fs=[f_b64(WD + '/firmware.bin', FIRMWARE_BIN),
        f_text(WD + '/scan_uefi.py',
               "# поиск Firmware Volume и TE-образов\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('Firmware Volume @ 0x000000')\n")],
    tool=py_tool(r'scan_uefi', 'scan_uefi.py firmware.bin',
                 ('Firmware Volume @ 0x000000  size 0x800000\n'
                  '  [0x001200] TE image  module: DxeCore\n'
                  '  [0x04a800] TE image  module: UsbBusDxe\n'
                  '  [0x09c000] TE image  module: NetworkStack\n'
                  '  [0x0d4000] TE image  module: NtfsDxe_nto{uefi_dx3_dr1v3r_f0und}\n'
                  '  [!] module at 0x0d4000 has no known vendor GUID and references SmmInstallProtocolInterface\n'),
                 'python3: в этой лабе эмулируется только scan_uefi.py.\n'),
    hints=['Прошивка — контейнер с разделами; UEFI-модули имеют тип PE (TE-образы).',
           'DXE-драйверы ищут по сигнатуре `VZ`/`_ModuleEntryPoint` или GUID-протоколам.',
           'Запусти `python3 scan_uefi.py firmware.bin` — скрипт перечислит найденные модули.',
           "`python3 scan_uefi.py firmware.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{uefi_dx3_dr1v3r_f0und}',
    sol=['python3 scan_uefi.py firmware.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-objc-runtime',
    title='Практика: восстановление классов из метаданных',
    task=("# Практика: метаданные Objective-C\n\n"
          "`app.bin` — Mach-O arm64 приложения. Скрипт `objc_meta.py` идёт по\n"
          "`__objc_classlist` и печатает классы с методами.\n\n"
          "1. `strings -n 5 app.bin | grep -E 'ViewController|Manager'` — имена классов.\n"
          "2. `python3 objc_meta.py app.bin` — классы, селекторы и реализации.\n"
          "3. Найди класс-артефакт с флагом.\n\nФлаг: `nto{...}` среди классов.\n"),
    fs=[f_b64(WD + '/app.bin', APP_BIN),
        f_text(WD + '/objc_meta.py',
               "# обход __objc_classlist\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('scanning objc metadata...')\n")],
    tool=py_tool(r'objc_meta', 'objc_meta.py app.bin',
                 ('class LoginViewController : UIViewController\n'
                  '  - viewDidLoad              @ 0x100004a20\n'
                  '  - loginWithToken:          @ 0x100004c10\n'
                  'class CryptoManager\n'
                  '  - encryptData:             @ 0x100005120\n'
                  '  - secret_nto{0bjc_m3th0d_l1st_r3c0v3ry}\n'),
                 'python3: в этой лабе эмулируется только objc_meta.py.\n'),
    hints=['В Mach-O секция __objc_classlist содержит указатели на классы.',
           'Строки имён классов и селекторов лежат в __objc_methname / __objc_classname.',
           'Запусти `python3 objc_meta.py app.bin` — скрипт перечислит классы и методы.',
           "`python3 objc_meta.py app.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{0bjc_m3th0d_l1st_r3c0v3ry}',
    sol=['python3 objc_meta.py app.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-ios-arm64e-pac',
    title='Практика: разбор PAC-инструкций',
    task=("# Практика: Pointer Authentication\n\n"
          "`func.bin` — дамп функции arm64e. Скрипт `scan_pac.py` найдёт\n"
          "PAC-инструкции (подпись/проверка указателя).\n\n"
          "1. `xxd -l 32 func.bin` — байты с префиксом `d5` (PAC-пространство).\n"
          "2. `python3 scan_pac.py func.bin` — найденные PAC-инструкции.\n"
          "3. Какие инструкции защищают указатель возврата?\n\nФлаг: `nto{...}` в отчёте.\n"),
    fs=[f_b64(WD + '/func.bin', FUNC_BIN),
        f_text(WD + '/scan_pac.py',
               "# поиск PAC-инструкций\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('scanning arm64e...')\n")],
    tool=py_tool(r'scan_pac', 'scan_pac.py func.bin',
                 ('0x0000: pacibsp        (sign LR)\n'
                  '0x0004: stp x29, x30, [sp, #-16]!\n'
                  '0x0038: autibsp        (auth LR)\n'
                  '0x003c: retab\n'
                  '[+] signed pointer region found: nto{pac1bsp_aut1bsp_r3tab}\n'),
                 'python3: в этой лабе эмулируется только scan_pac.py.\n'),
    hints=['PAC-инструкции: pacia/pacib (подпись), autia/autib (проверка), retaa/retab.',
           'В дампе ищи опкоды с префиксом D5 (ARM64 PAC-пространство).',
           'Запусти `python3 scan_pac.py func.bin` — скрипт найдёт PAC-инструкции.',
           "`python3 scan_pac.py func.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{pac1bsp_aut1bsp_r3tab}',
    sol=['python3 scan_pac.py func.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-binary-ninja',
    title='Практика: автоматизация анализа через API',
    task=("# Практика: HLIL через API\n\n"
          "`target.bin` — небольшой бинарник. Скрипт `bn_script.py` открывает его\n"
          "через Binary Ninja API и печатает HLIL функции проверки.\n\n"
          "1. `strings -n 5 target.bin` — что ищет программа.\n"
          "2. `python3 bn_script.py target.bin` — HLIL функции.\n"
          "3. Найди артефакт в декомпилированном виде.\n\nФлаг: `nto{...}` в HLIL.\n"),
    fs=[f_b64(WD + '/target.bin', TARGET_BIN),
        f_text(WD + '/bn_script.py',
               "# Binary Ninja API\nimport sys\nprint('opening', sys.argv[1])\n")],
    tool=py_tool(r'bn_script', 'bn_script.py target.bin',
                 ('int32_t check(char* s)\n{\n    if (strcmp(s, "MAGIC") == 0)\n'
                  '        return 1;\n    // nto{bnil_hl1l_aut0m4t10n}\n    return 0;\n}\n'),
                 'python3: в этой лабе эмулируется только bn_script.py.\n'),
    hints=['Binary Ninja поднимает код через уровни: LLIL -> MLIL -> HLIL.',
           'HLIL ближе всего к C; в нём видны высокоуровневые конструкции.',
           'Запусти `python3 bn_script.py target.bin` — скрипт выведет HLIL функции.',
           "`python3 bn_script.py target.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{bnil_hl1l_aut0m4t10n}',
    sol=['python3 bn_script.py target.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-hexrays-microcode',
    title='Практика: проход по microcode',
    task=("# Практика: Hex-Rays microcode\n\n"
          "`target.bin` — функция с константными вычислениями. Скрипт `mc_dump.py`\n"
          "печатает microcode до и после оптимизаций.\n\n"
          "1. `strings -n 5 target.bin` — что за бинарник.\n"
          "2. `python3 mc_dump.py target.bin` — microcode функции.\n"
          "3. Как оптимизатор свернул выражение?\n\nФлаг: `nto{...}` в microcode.\n"),
    fs=[f_b64(WD + '/target.bin', TARGET_BIN),
        f_text(WD + '/mc_dump.py',
               "# дамп microcode\nimport sys\nprint('decompiling', sys.argv[1])\n")],
    tool=py_tool(r'mc_dump', 'mc_dump.py target.bin',
                 ('; block 0\n    mov  $v0.8, #5\n    mov  $v1.8, #3\n'
                  '    add  $v2.8, $v0.8, $v1.8\n    shl  $v3.8, $v2.8, #1\n'
                  '; after opt:\n    mov  $v3.8, #16   ; nto{m1cr0c0d3_c0nst_f0ld1ng}\n    ret  $v3.8\n'),
                 'python3: в этой лабе эмулируется только mc_dump.py.\n'),
    hints=['Microcode — это язык операций над регистрами и временными переменными.',
           'Оптимизации сворачивают константы и упрощают выражения.',
           'Запусти `python3 mc_dump.py target.bin` — скрипт выведет microcode функции.',
           "`python3 mc_dump.py target.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{m1cr0c0d3_c0nst_f0ld1ng}',
    sol=['python3 mc_dump.py target.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-ghidra-pcode-emulator',
    title='Практика: эмуляция P-Code функции',
    task=("# Практика: эмуляция P-Code\n\n"
          "`target.bin` — функция, вычисляющая строку. Скрипт `emulate_pcode.py`\n"
          "эмулирует её P-Code и печатает результат, не запуская бинарник.\n\n"
          "1. `strings -n 5 target.bin` — что за бинарник.\n"
          "2. `python3 emulate_pcode.py target.bin` — эмуляция функции.\n"
          "3. Что вернула функция?\n\nФлаг: `nto{...}` в результате эмуляции.\n"),
    fs=[f_b64(WD + '/target.bin', TARGET_BIN),
        f_text(WD + '/emulate_pcode.py',
               "# эмуляция P-Code\nimport sys\nprint('loading', sys.argv[1])\n")],
    tool=py_tool(r'emulate_pcode', 'emulate_pcode.py target.bin',
                 ('loaded function @ 0x00401000\nemulating 137 pcode ops...\n'
                  "result @ 0x00402000 = b'nto{pcode_3mul4t10n_d30bfusc4t10n}'\n"),
                 'python3: в этой лабе эмулируется только emulate_pcode.py.\n'),
    hints=['P-Code — это набор микроопераций, в которые Ghidra переводит каждую инструкцию.',
           'Эмулятор выполняет P-Code, не запуская реальный процесс.',
           'Запусти `python3 emulate_pcode.py target.bin` — скрипт эмулирует функцию.',
           "`python3 emulate_pcode.py target.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{pcode_3mul4t10n_d30bfusc4t10n}',
    sol=['python3 emulate_pcode.py target.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-anti-disassembly',
    title='Практика: распутываем наложение байтов',
    task=("# Практика: anti-disassembly\n\n"
          "`blob.bin` — участок кода с ловушкой: одна область байт читается\n"
          "по-разному. Скрипт `fix_disasm.py` покажет реальный поток.\n\n"
          "1. `xxd -l 32 blob.bin` — посмотри байты (есть `e9`, `e8`).\n"
          "2. `python3 fix_disasm.py blob.bin` — реальный поток и мусор.\n"
          "3. Найди артефакт, спрятанный за мусором.\n\nФлаг: `nto{...}` в отчёте.\n"),
    fs=[f_b64(WD + '/blob.bin', BLOB_BIN),
        f_text(WD + '/fix_disasm.py',
               "# анализ по потоку\nimport sys\nprint('fixing', sys.argv[1])\n")],
    tool=py_tool(r'fix_disasm', 'fix_disasm.py blob.bin',
                 ('0x0000: jmp 0x0006          ; реальный поток\n'
                  '0x0002: (junk) e8 ...       ; недостижимо\n'
                  '0x0006: mov eax, 1\n0x000b: cmp eax, eax\n'
                  '0x000d: jne 0x0020          ; opaque -> never taken\n'
                  '0x0013: lea rdi, [rip+...]\n0x001a: call puts\n0x0020: (junk) ...\n'
                  "0x0030: db 'nto{0v3rl4pp1ng_byt3s_d1s4sm}'\n"),
                 'python3: в этой лабе эмулируется только fix_disasm.py.\n'),
    hints=['Одна и та же последовательность байт читается по-разному с разных смещений.',
           'Хитрость — `jmp` внутрь другой инструкции (в середину операнда).',
           'Запусти `python3 fix_disasm.py blob.bin` — скрипт покажет реальный поток.',
           "`python3 fix_disasm.py blob.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{0v3rl4pp1ng_byt3s_d1s4sm}',
    sol=['python3 fix_disasm.py blob.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-string-obfuscation',
    title='Практика: расшифровка строк',
    task=("# Практика: XOR-строки\n\n"
          "`strings.bin` — блоб с зашифрованными строками (однобайтовый XOR).\n"
          "`strings` покажет мусор. Скрипт `decstrings.py` применит ключ.\n\n"
          "1. `strings -n 4 strings.bin` — убедись, что строки скрыты.\n"
          "2. `python3 decstrings.py strings.bin` — расшифровка.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}` среди расшифрованных строк.\n"),
    fs=[f_b64(WD + '/strings.bin', STRINGS_BIN),
        f_text(WD + '/decstrings.py',
               "# XOR-декодер\nimport sys\nd = open(sys.argv[1],'rb').read()\nprint('key = 0x5e')\n")],
    tool=py_tool(r'decstrings', 'decstrings.py strings.bin',
                 ('key = 0x5e (single-byte XOR)\n'
                  '[0] http://10.10.20.7/gate.php\n'
                  '[1] cmd.exe /c whoami\n'
                  '[2] nto{x0r_str1ngs_d3crypt3d}\n'),
                 'python3: в этой лабе эмулируется только decstrings.py.\n'),
    hints=['В `strings` ты увидишь мусор, а не URL — строки шифруются в рантайме.',
           'Найди ключ XOR в коде и примени его к блобу строк.',
           'Запусти `python3 decstrings.py strings.bin` — скрипт расшифрует строки.',
           "`python3 decstrings.py strings.bin > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{x0r_str1ngs_d3crypt3d}',
    sol=['python3 decstrings.py strings.bin > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-fuzzing-libfuzzer-honggfuzz',
    title='Практика: артефакт из libFuzzer',
    task=("# Практика: ASan-артефакт\n\n"
          "libFuzzer нашёл падение и сохранил вход `crash-xxxx`. Скрипт\n"
          "`read_artifact.py` разберёт артефакт и причину краха.\n\n"
          "1. `xxd crash-xxxx` — вход, приведший к падению.\n"
          "2. `python3 read_artifact.py crash-xxxx` — разбор артефакта.\n"
          "3. Что за строка спрятана в артефакте?\n\nФлаг: `nto{...}` в артефакте.\n"),
    fs=[f_b64(WD + '/crash-xxxx', CRASH_BIN),
        f_text(WD + '/read_artifact.py',
               "# разбор артефакта libFuzzer\nimport sys\n"
               "d = open(sys.argv[1],'rb').read()\nprint('artifact size', len(d))\n")],
    tool=py_tool(r'read_artifact', 'read_artifact.py crash-xxxx',
                 ('artifact: crash-xxxx (size 42)\n'
                  'reason: AddressSanitizer: heap-buffer-overflow READ of size 8\n'
                  'input hex: 4d41474943 00000000 6e746f7b ...\n'
                  "decoded: MAGIC\\x00\\x00\\x00\\x00nto{l1bfuzz3r_4s4n_4rt1f4ct}\n"),
                 'python3: в этой лабе эмулируется только read_artifact.py.\n'),
    hints=['libFuzzer сообщает о падении и печатает вход (artifact_prefix).',
           'Падение может быть не segfault, а срабатыванием санитайзера (например, ASan).',
           'Запусти `python3 read_artifact.py crash-xxxx` — скрипт разберёт вход.',
           "`python3 read_artifact.py crash-xxxx > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{l1bfuzz3r_4s4n_4rt1f4ct}',
    sol=['python3 read_artifact.py crash-xxxx > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-kernel-fuzzing',
    title='Практика: разбор syzkaller-репорта',
    task=("# Практика: KASAN-отчёт\n\n"
          "`crash.log` — лог краха ядра от syzkaller. Скрипт `parse_syz.py`\n"
          "разберёт отчёт: тип ошибки, стек и syz-репро.\n\n"
          "1. `cat crash.log` — исходный отчёт.\n"
          "2. `python3 parse_syz.py crash.log` — разбор.\n"
          "3. Какой класс уязвимости и в какой функции?\n\nФлаг: `nto{...}` в отчёте.\n"),
    fs=[f_text(WD + '/crash.log', CRASHLOG),
        f_text(WD + '/parse_syz.py',
               "# разбор syzkaller-отчёта\nimport sys\n"
               "d = open(sys.argv[1]).read()\nprint('parsing syzkaller report...')\n")],
    tool=py_tool(r'parse_syz', 'parse_syz.py crash.log',
                 ('BUG: KASAN: slab-use-after-free in tcp_recvmsg\nCall Trace:\n'
                  '  tcp_recvmsg+0x1a2/0x8c0\n  sock_recvmsg+0x1f0/0x210\n'
                  '  __sys_recvfrom+0x...\nsyz repro: 3 syscalls\nC repro: 12 lines\n'
                  'crash type: KASAN: slab-use-after-free\nnote: nto{kcov_kasan_slab_uaf}\n'),
                 'python3: в этой лабе эмулируется только parse_syz.py.\n'),
    hints=['syzkaller описывает баг на языке syscall-программ (syz-репро).',
           'KASAN-отчёт содержит стек вызовов и тип ошибки (use-after-free, OOB).',
           'Запусти `python3 parse_syz.py crash.log` — скрипт разберёт отчёт.',
           "`python3 parse_syz.py crash.log > out.txt`, затем `grep nto out.txt > found.txt` и `check`."],
    flag='nto{kcov_kasan_slab_uaf}',
    sol=['python3 parse_syz.py crash.log > out.txt', 'grep nto out.txt > found.txt'])


# -------------------------------------------------------------------- emit --
def write_bundle(lab):
    fs = [f_dir(WD), f_text(WD + '/task.md', lab['task'])] + lab['fs']
    bundle = {'id': lab['id'], 'workdir': WD, 'hostname': 'lab',
              'expect': {'file': WD + '/found.txt', 'contains': lab['flag']},
              'fs': fs, 'tools': lab['tool']}
    with open(os.path.join(LABS_DIR, lab['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write('\n')


def js_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def write_spec(labs):
    out = ["import { describe, it, expect } from 'vitest'",
           "import fs from 'node:fs'",
           "import path from 'node:path'",
           "import { createSession } from './session'",
           '',
           '// End-to-end solvability check for reversing gap batch b14.',
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
        sol = ', '.join(js_str(c) for c in lab['sol'])
        out.append('  {')
        out.append('    id: ' + js_str(lab['id']) + ', flag: ' + js_str(lab['flag']) + ', hints: ' + str(len(lab['hints'])) + ',')
        out.append('    solution: [' + sol + '],')
        out.append('  },')
    out.append(']')
    out.append('')
    out.append("describe.each(LABS)('reversing b14 lab: $id', ({ id, flag, hints, solution }) => {")
    out.append('  const bundle = load(id)')
    out.append("  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }")
    out.append('')
    out.append("  it('bundle + seed files are consistent', () => {")
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
    path = os.path.join(ROOT, 'frontend', 'src', 'lab', 'reversing-b14.spec.js')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    for lab in LABS:
        write_bundle(lab)
    write_spec(LABS)
    print('wrote %d bundles + 1 spec' % len(LABS))
    for lab in LABS:
        print(' ', lab['id'])
