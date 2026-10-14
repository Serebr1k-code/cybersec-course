#!/usr/bin/env python3
"""Author lab bundles + e2e spec for reversing gap batch b15 (15 lessons).

Lessons already carry their `lab:` front-matter; this script writes the
matching content/labs/<id>.json bundle and a vitest spec proving solvability.
Flags are embedded as plain bytes in fixtures so `strings | grep` works.
"""
import base64
import io
import json
import os
import struct
import zipfile

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


def elf64(machine, entry, tail=b''):
    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8
    hdr = ident + struct.pack('<HHIQQQIHHHHHH',
                              2, machine, 1, entry, 0, 0, 0, 64, 56, 1, 64, 0, 0)
    return hdr + tail


def elf32(machine, entry, tail=b''):
    ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + b'\x00' * 8
    hdr = ident + struct.pack('<HHIIIIIHHHHHH',
                              2, machine, 1, entry, 0, 0, 0, 52, 32, 1, 40, 0, 0)
    return hdr + tail


def apk_bytes(flag):
    """Minimal real ZIP (stored) so the flag lives literally in the file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        z.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00' + b'\x00' * 16)
        z.writestr('classes.dex', b'dex\n035\x00' + b'\x00' * 20)
        z.writestr('resources.arsc', b'\x02\x00\x0c\x00' + b'\x00' * 16)
        z.writestr('assets/notes.txt', flag + '\n')
    return buf.getvalue()


LABS = []


def add(**k):
    LABS.append(k)


def replay(tool, help_text, cases, fallback):
    return {tool: {'help': help_text, 'cases': cases, 'fallback': fallback}}


# ==================================================================== LABS ===

add(id='reversing-riscv-advanced',
    title='Практика: разбор RISC-V-прошивки',
    task=("# Практика: RISC-V\n\n`riscv.elf` — образ прошивки на RISC-V. Разберись со\n"
          "структурой и найди артефакт.\n\n"
          "1. `readelf -h riscv.elf` — заголовок (Machine, флаги RVC).\n"
          "2. `xxd -l 24 riscv.elf` — магические байты.\n"
          "3. Выгрузи строки и найди флаг.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/riscv.elf',
              elf64(0xF3, 0x80000000,
                    b'\x13\x05\x10\x00' + b'\xc5\x05' + b'\x82\x80' +
                    b'main\x00uart_init\x00csrr mcause\x00'
                    b'nto{r1scv_c0mpress3d_1nstr}\x00'))],
    tool=replay('readelf', 'readelf [-h] <файл> — заголовки ELF',
                [{'match': r'-h', 'example': '-h riscv.elf',
                  'output': ('ELF Header:\n  Class:                             ELF64\n'
                             '  Data:                              2\'s complement, little endian\n'
                             '  Machine:                           RISC-V\n'
                             '  Flags:                             0x5, RVC, double-float ABI\n'
                             '  Entry point address:               0x80000000\n')}],
                'readelf: используй `-h <файл>`.\n'),
    hints=['`e_machine` для RISC-V в ELF-заголовке равен `0xF3` (243).',
           'Компрессия C-инструкций видна как «короткие» двухбайтовые опкоды.',
           '`readelf -h riscv.elf` покажет класс и архитектуру; затем ищи строки.',
           "`strings -n 5 riscv.elf | grep nto > found.txt`, затем `check`."],
    flag='nto{r1scv_c0mpress3d_1nstr}',
    sol=['strings -n 5 riscv.elf > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-mips-delay-slots',
    title='Практика: MIPS с delay slot',
    task=("# Практика: MIPS\n\n`mips.elf` — фрагмент прошивки на MIPS (big-endian).\n"
          "1. `readelf -h mips.elf` — заголовок.\n"
          "2. `objdump -d mips.elf` — дизассемблер (обрати внимание на delay slot).\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/mips.elf',
              elf32(0x08, 0x400000,
                    b'\x0c\x10\x01\x48' + b'\x00\x00\x00\x00' +
                    b'\x27\xbd\xff\xe0' + b'check_key\x00'
                    b'nto{m1ps_d3l4y_sl0t_tr4p}\x00'))],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер',
                [{'match': r'-d', 'example': '-d mips.elf',
                  'output': ('mips.elf:     file format elf32-bigmips\n\n'
                             'Disassembly of section .text:\n\n'
                             '00400510 <check_key>:\n'
                             ' 400510:\t27bdffe0 \taddiu\tsp,sp,-32\n'
                             ' 400514:\t0c100148 \tjal\t400520 <helper>\n'
                             ' 400518:\t00000000 \tnop\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['`e_machine` для MIPS в ELF — `0x08` (8).',
           'Delay slot — инструкция сразу после перехода, которая исполняется ДО перехода.',
           '`objdump -d mips.elf` покажет `nop` после `jal` — это заполненный delay slot.',
           "`strings -n 5 mips.elf | grep nto > found.txt`, затем `check`."],
    flag='nto{m1ps_d3l4y_sl0t_tr4p}',
    sol=['strings -n 5 mips.elf > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-powerpc',
    title='Практика: PowerPC big-endian',
    task=("# Практика: PowerPC\n\n`ppc.elf` — модуль прошивки на PowerPC.\n"
          "1. `readelf -h ppc.elf` — заголовок (Machine, big endian).\n"
          "2. `objdump -d ppc.elf` — листинг (mflr/mtlr/blr).\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/ppc.elf',
              elf32(0x14, 0x10000000,
                    b'\x7c\x08\x02\xa6' + b'\x94\x21\xff\xc0' +
                    b'\x4b\xff\xff\xe5' + b'check_key\x00'
                    b'nto{ppc_b1g_3nd14n_l1nk_r3g}\x00'))],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер',
                [{'match': r'-d', 'example': '-d ppc.elf',
                  'output': ('ppc.elf:     file format elf32-powerpc\n\n'
                             'Disassembly of section .text:\n\n'
                             '10000400 <check_key>:\n'
                             '10000400:\t7c 08 02 a6 \tmflr\tr0\n'
                             '10000404:\t94 21 ff c0 \tstwu\tr1,-64(r1)\n'
                             '10000408:\t4b ff ff e5 \tbl\t100003ec <helper>\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['`e_machine` для PowerPC в ELF — `0x14` (20).',
           'PowerPC по умолчанию big-endian: `Data: 2\'s complement, big endian`.',
           'Вызов функции — `bl` (branch and link), адрес возврата сохраняется в регистр `LR`.',
           "`strings -n 5 ppc.elf | grep nto > found.txt`, затем `check`."],
    flag='nto{ppc_b1g_3nd14n_l1nk_r3g}',
    sol=['strings -n 5 ppc.elf > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-sparc',
    title='Практика: SPARC register windows',
    task=("# Практика: SPARC\n\n`sparc.elf` — демон под SPARC.\n"
          "1. `readelf -h sparc.elf` — заголовок.\n"
          "2. `objdump -d sparc.elf` — листинг (save/restore, delay slot).\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/sparc.elf',
              elf32(0x02, 0x10000,
                    b'\x9d\xe3\xbf\xa0' + b'\x81\xc7\xe0\x08' +
                    b'\x40\x00\x00\x02' + b'check_key\x00'
                    b'nto{sp4rc_w1nd0ws_d3l4y}\x00'))],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер',
                [{'match': r'-d', 'example': '-d sparc.elf',
                  'output': ('sparc.elf:     file format elf32-sparc\n\n'
                             'Disassembly of section .text:\n\n'
                             '00010400 <check_key>:\n'
                             ' 10400:\t9d e3 bf a0 \tsave  %sp, -96, %sp\n'
                             ' 10404:\t81 c7 e0 08 \tret\n'
                             ' 10408:\t81 e8 00 00 \trestore\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['`e_machine` для SPARC в ELF — `0x02` (2) для SPARC32.',
           'SPARC big-endian и имеет register windows — save/restore переключают окна.',
           '`save %sp, -96, %sp` — пролог функции; `restore` — эпилог.',
           "`strings -n 5 sparc.elf | grep nto > found.txt`, затем `check`."],
    flag='nto{sp4rc_w1nd0ws_d3l4y}',
    sol=['strings -n 5 sparc.elf > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-s390x',
    title='Практика: s390x CISC-код',
    task=("# Практика: s390x\n\n`s390x.elf` — утилита мейнфрейма.\n"
          "1. `readelf -h s390x.elf` — заголовок.\n"
          "2. `objdump -d s390x.elf` — листинг (stmg/lay/brasl).\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/s390x.elf',
              elf64(0x16, 0x10004a0,
                    b'\xc0\x40\x00\x00\x00\x00' + b'\xeb\xbf\xf0\x58\x00\x24' +
                    b'\x0d\xe4' + b'check_key\x00'
                    b'nto{s390x_c1sc_v4r1abl3_l3n}\x00'))],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер',
                [{'match': r'-d', 'example': '-d s390x.elf',
                  'output': ('s390x.elf:     file format elf64-s390\n\n'
                             'Disassembly of section .text:\n\n'
                             '00000000010004a0 <check_key>:\n'
                             ' 10004a0:\teb bf f0 58 00 24 \tstmg\t%r11,%r15,88(%r15)\n'
                             ' 10004a6:\t0d e4             \tbasr\t%r14,%r4\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['`e_machine` для s390x в ELF — `0x16` (22).',
           's390x big-endian и имеет инструкции переменной длины (2, 4, 6 байт).',
           '`lg`/`stg` — загрузка/запись 64-битного значения; `lgr` — копирование регистра.',
           "`strings -n 5 s390x.elf | grep nto > found.txt`, затем `check`."],
    flag='nto{s390x_c1sc_v4r1abl3_l3n}',
    sol=['strings -n 5 s390x.elf > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-superh',
    title='Практика: SuperH-прошивка',
    task=("# Практика: SuperH\n\n`sh4.elf` — образ прошивки на SuperH (SH-4).\n"
          "1. `readelf -h sh4.elf` — заголовок.\n"
          "2. `objdump -d sh4.elf` — листинг (sts pr, jsr, rts).\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/sh4.elf',
              elf32(0x2A, 0x8c010000,
                    b'\x2f\xe6' + b'\x4f\x22' + b'\x00\x0b' +
                    b'check_key\x00' + b'nto{superh_16b1t_f1x3d}\x00'))],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер',
                [{'match': r'-d', 'example': '-d sh4.elf',
                  'output': ('sh4.elf:     file format elf32-sh\n\n'
                             'Disassembly of section .text:\n\n'
                             '8c010000 <check_key>:\n'
                             '8c010000:\t2f e6       \tmov.l\tr14,@-r15\n'
                             '8c010002:\t4f 22       \tsts\tpr,@-r15\n'
                             '8c010004:\t00 0b       \trts\n'
                             '8c010006:\t09 00       \tnop\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['`e_machine` для SuperH в ELF — `0x2A` (42).',
           'SuperH использует 16-битные инструкции фиксированной длины.',
           'Вызов функции — `jsr`/`bsr`; адрес возврата сохраняется в `PR`.',
           "`strings -n 5 sh4.elf | grep nto > found.txt`, затем `check`."],
    flag='nto{superh_16b1t_f1x3d}',
    sol=['strings -n 5 sh4.elf > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-android-root-detect',
    title='Практика: находим root-проверку',
    task=("# Практика: root-детект\n\n`libdetect.so` — нативная библиотека детекта.\n"
          "1. `strings -n 5 libdetect.so` — посмотри индикаторы (пути su, frida).\n"
          "2. Найди сообщение детекта.\n\nФлаг: `nto{...}` среди строк.\n"),
    fs=[f_b64(WD + '/libdetect.so',
              elf64(0xB7, 0x1000,
                    b'/system/bin/su\x00/system/xbin/su\x00/sbin/su\x00'
                    b'frida-server\x00frida-agent\x00ro.debuggable=1\x00'
                    b'ro.build.tags=test-keys\x00'
                    b'nto{r00t_d3t3ct_byp4ss3d}\x00'))],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер ARM64',
                [{'match': r'-d', 'example': '-d libdetect.so',
                  'output': ('libdetect.so:     file format elf64-littleaarch64\n'
                             'Disassembly of section .text:\n'
                             ' 1000:\tadrp\tx0, 2000\n'
                             ' 1004:\tadd\tx0, x0, #0x10\n'
                             ' 1008:\tbl\taccess\n'
                             ' 100c:\tcbnz\tw0, 0x1020\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['Приложения ищут файлы вроде `/system/bin/su` и `/system/xbin/su`.',
           'Проверяй строки `.so` и `classes.dex`: имена путей и `frida` — явный признак.',
           '`strings -n 5 libdetect.so` покажет пути и сообщение о детекте.',
           "`strings -n 5 libdetect.so | grep nto > found.txt`, затем `check`."],
    flag='nto{r00t_d3t3ct_byp4ss3d}',
    sol=['strings -n 5 libdetect.so > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-android-smali-dex-edit',
    title='Практика: правим smali',
    task=("# Практика: smali/DEX\n\n`classes.dex` — байткод Dalvik.\n"
          "1. `xxd -l 16 classes.dex` — magic `dex\\n035`.\n"
          "2. `strings -n 6 classes.dex` — имена классов и методов.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/classes.dex',
              b'dex\n035\x00' + b'\x00' * 24 +
              b'Lcom/example/app/IntegrityCheck;\x00verifySignature\x00'
              b'isDebugBuild\x00getActual\x00'
              b'nto{sm4l1_p4tch_r3turn_tru3}\x00')],
    tool=replay('objdump', 'objdump [-d] <файл> — не применимо к DEX',
                [{'match': r'.', 'example': '-d classes.dex',
                  'output': 'objdump: classes.dex: file format not recognized\n'}],
                'objdump: classes.dex не ELF.\n'),
    hints=['`classes.dex` содержит байткод Dalvik; строки в нём лежат в пуле строк.',
           'smali — текстовое представление байткода; но в этой лабе доступен только `strings`.',
           'Флаг лежит строкой в DEX-пуле.',
           "`strings -n 5 classes.dex | grep nto > found.txt`, затем `check`."],
    flag='nto{sm4l1_p4tch_r3turn_tru3}',
    sol=['strings -n 5 classes.dex > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-android-dynamic-instrumentation',
    title='Практика: Frida-хук в действии',
    task=("# Практика: Frida\n\n`hook.js` — Frida-скрипт перехвата метода.\n"
          "1. `cat hook.js` — прочитай скрипт.\n"
          "2. Обрати внимание на комментарий с примером вывода.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_text(WD + '/hook.js',
               "// Frida: перехват Java-метода\n"
               "Java.perform(function () {\n"
               "  var Cipher = Java.use('com.example.app.Crypto');\n"
               "  Cipher.encrypt.implementation = function (data) {\n"
               "    console.log('encrypt called with:', data);\n"
               "    // пример вывода: encrypt -> nto{fr1d4_h00k_j4v4_n4t1v3}\n"
               "    return this.encrypt(data);\n"
               "  };\n"
               "});\n")],
    tool=replay('objdump', 'objdump [-d] <файл> — не применимо',
                [{'match': r'.', 'example': '-d hook.js',
                  'output': 'objdump: hook.js: file format not recognized\n'}],
                'objdump: hook.js — не ELF.\n'),
    hints=['Frida-скрипт — это JavaScript, перехватывающий функции через Java.use/Interceptor.',
           'Скрипт печатает аргументы перехваченной функции.',
           'Прочитай `hook.js` — в комментарии с примером вывода есть артефакт.',
           "`strings -n 5 hook.js | grep nto > found.txt`, затем `check`."],
    flag='nto{fr1d4_h00k_j4v4_n4t1v3}',
    sol=['strings -n 5 hook.js > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-android-native-symbols',
    title='Практика: восстановление символов .so',
    task=("# Практика: JNI-символы\n\n`libnative.so` — обрезанная библиотека.\n"
          "1. `strings -n 5 libnative.so` — найди имена JNI-функций.\n"
          "2. Ищи `Java_...` и `RegisterNatives`.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/libnative.so',
              elf64(0xB7, 0x2000,
                    b'Java_com_example_app_NativeBridge_checkLicense\x00'
                    b'Java_com_example_app_NativeBridge_getDeviceId\x00'
                    b'RegisterNatives\x00JNI_OnLoad\x00'
                    b'nto{jni_r3g1st3rn4t1v3s_symb0ls}\x00'))],
    tool=replay('nm', 'nm [-D] <файл> — таблица символов',
                [{'match': r'-D', 'example': '-D libnative.so',
                  'output': ('0000000000012340 T Java_com_example_app_NativeBridge_checkLicense\n'
                             '00000000000123a0 T Java_com_example_app_NativeBridge_getDeviceId\n')}],
                'nm: используй `-D <файл>`.\n'),
    hints=['Если `.dynsym` не обрезан, имена JNI-методов видны через `nm -D`.',
           'JNI-функции называют `Java_<пакет>_<класс>_<метод>`.',
           '`strings -n 5 libnative.so` покажет имена и артефакт.',
           "`strings -n 5 libnative.so | grep nto > found.txt`, затем `check`."],
    flag='nto{jni_r3g1st3rn4t1v3s_symb0ls}',
    sol=['strings -n 5 libnative.so > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-dex-internals',
    title='Практика: ручной разбор DEX',
    task=("# Практика: DEX изнутри\n\n`classes.dex` — контейнер байткода.\n"
          "1. `xxd -l 16 classes.dex` — magic `dex\\n035\\0`.\n"
          "2. `strings -n 5 classes.dex` — пул строк.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/classes.dex',
              b'dex\n035\x00' + struct.pack('<I', 0x1234abcd) + b'\x00' * 20 +
              struct.pack('<I', 0x021a) + b'\x00' * 12 +
              b'Ljava/lang/String;\x00Lcom/example/App;\x00'
              b'nto{d3x_h34d3r_p00ls_mult1d3x}\x00')],
    tool=replay('objdump', 'objdump [-d] <файл> — не применимо к DEX',
                [{'match': r'.', 'example': '-d classes.dex',
                  'output': 'objdump: classes.dex: file format not recognized\n'}],
                'objdump: classes.dex не ELF.\n'),
    hints=['DEX начинается с magic `dex\\n035\\0` (или `035`, `037`, `038`).',
           'В заголовке есть `string_ids_size` и `string_ids_off` — пул строк.',
           'Строки в DEX хранятся в формате ULEB128 + байты.',
           "`strings -n 5 classes.dex | grep nto > found.txt`, затем `check`."],
    flag='nto{d3x_h34d3r_p00ls_mult1d3x}',
    sol=['strings -n 5 classes.dex > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-oat-art',
    title='Практика: разбор OAT/vdex',
    task=("# Практика: OAT/vdex\n\n`base.vdex` — артефакт, снятый с устройства.\n"
          "1. `xxd -l 16 base.vdex` — magic `vdex021`.\n"
          "2. `strings -n 5 base.vdex` — строки встроенного DEX.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/base.vdex',
              b'vdex021\x00' + b'\x14\x00\x00\x00' + b'\x00' * 8 +
              b'dex\n035\x00' + b'\x00' * 12 +
              b'Lcom/example/app/MainActivity;\x00onCreate\x00'
              b'nto{oat_art_vd3x_qu1ck3n}\x00')],
    tool=replay('objdump', 'objdump [-d] <файл> — не применимо к vdex',
                [{'match': r'.', 'example': '-d base.vdex',
                  'output': 'objdump: base.vdex: file format not recognized\n'}],
                'objdump: base.vdex не ELF.\n'),
    hints=['vdex-файл начинается с magic `vdex` и содержит встроенный DEX.',
           'Даже если код скомпилирован, строки остаются в vdex.',
           '`strings -n 5 base.vdex` покажет строки приложения и артефакт.',
           "`strings -n 5 base.vdex | grep nto > found.txt`, затем `check`."],
    flag='nto{oat_art_vd3x_qu1ck3n}',
    sol=['strings -n 5 base.vdex > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-apk-structure',
    title='Практика: инвентаризация APK',
    task=("# Практика: анатомия APK\n\n`app.apk` — ZIP-контейнер приложения.\n"
          "1. `unzip -l app.apk` — список содержимого.\n"
          "2. Найди файл с заметками и извлеки его: `unzip -p app.apk assets/notes.txt`.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/app.apk', apk_bytes('nto{apk_4n4t0my_spl1t_s1gn3d}'))],
    tool=replay('unzip', 'unzip [-l | -p <файл>] <архив>',
                [{'match': r'-l', 'example': '-l app.apk',
                  'output': ('Archive:  app.apk\n'
                             '  Length      Name\n'
                             '     1024    AndroidManifest.xml\n'
                             '   842140    classes.dex\n'
                             '    12300    resources.arsc\n'
                             '       60    assets/notes.txt\n'
                             '     2048    META-INF/CERT.RSA\n')},
                 {'match': r'-p\s+app\.apk\s+assets/notes\.txt', 'example': '-p app.apk assets/notes.txt',
                  'output': 'nto{apk_4n4t0my_spl1t_s1gn3d}\n'}],
                'unzip: используй `-l app.apk` или `-p app.apk <файл>`.\n'),
    hints=['APK — это ZIP-архив; `unzip -l app.apk` покажет его содержимое.',
           'Ищи `AndroidManifest.xml`, `classes.dex`, `resources.arsc`, `META-INF/`.',
           'Флаг лежит в одном из файлов APK; посмотри список, затем содержимое.',
           "`unzip -p app.apk assets/notes.txt > out.txt`, затем `grep nto out.txt > found.txt`."],
    flag='nto{apk_4n4t0my_spl1t_s1gn3d}',
    sol=['unzip -p app.apk assets/notes.txt > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-win-com-rpc',
    title='Практика: разбор RPC-интерфейса',
    task=("# Практика: COM/RPC\n\n`rpcserver.exe` — служба с RPC-интерфейсом.\n"
          "1. `strings -n 6 rpcserver.exe` — найди UUID и имена методов.\n"
          "2. Ищи `RpcServerRegisterIf` и UUID.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/rpcserver.exe',
              b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00' +
              b'PE\x00\x00' + b'L\x01\x04\x00' + b'\x00' * 200 +
              b'RpcServerRegisterIf\x00NdrServerCallAll\x00'
              b'8a7c1d40-9e2b-4f3a-b1c5-7d6e8f9a0b12\x00'
              b'IComputeService\x00ComputeHash\x00GetStatus\x00'
              b'nto{rpc_m1dl_stub_1nt3rf4c3}\x00')],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер PE',
                [{'match': r'-d', 'example': '-d rpcserver.exe',
                  'output': ('rpcserver.exe:     file format pei-x86-64\n'
                             'Disassembly of section .text:\n'
                             '140001000 <main>:\n'
                             '140001000:\t48 8d 05 39 20 00 00 \tlea\trdx,[rip+0x2039]\n'
                             '140001007:\tff 15 f3 0f 00 00    \tcall\tQWORD PTR [rip+0xff3]\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['RPC-интерфейсы идентифицируются по UUID вида `xxxxxxxx-xxxx-...`.',
           'Функции RPC-сервера регистрируются через `RpcServerRegisterIf`.',
           '`strings -n 6 rpcserver.exe` покажет UUID и имена методов.',
           "`strings -n 6 rpcserver.exe | grep nto > found.txt`, затем `check`."],
    flag='nto{rpc_m1dl_stub_1nt3rf4c3}',
    sol=['strings -n 6 rpcserver.exe > out.txt', 'grep nto out.txt > found.txt'])

add(id='reversing-win-drivers-irp',
    title='Практика: разбор драйвера',
    task=("# Практика: драйвер Windows\n\n`vulndrv.sys` — сторонний драйвер.\n"
          "1. `strings -n 5 vulndrv.sys` — найди DeviceEntry/IOCTL.\n"
          "2. Ищи `IoCreateDevice`, `IRP_MJ_DEVICE_CONTROL`.\n"
          "3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n"),
    fs=[f_b64(WD + '/vulndrv.sys',
              b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00' +
              b'PE\x00\x00' + b'L\x01\x04\x00' + b'\x00' * 200 +
              b'DriverEntry\x00IoCreateDevice\x00IoCreateSymbolicLink\x00'
              b'\\Device\\VulnDrv\x00\\DosDevices\\VulnDrv\x00'
              b'IRP_MJ_DEVICE_CONTROL\x00'
              b'nto{10ctl_d1sp4tch_arb1tr4ry_wr1t3}\x00')],
    tool=replay('objdump', 'objdump [-d] <файл> — дизассемблер PE',
                [{'match': r'-d', 'example': '-d vulndrv.sys',
                  'output': ('vulndrv.sys:     file format pei-x86-64\n'
                             'Disassembly of section .text:\n'
                             '140001000 <DriverEntry>:\n'
                             '140001000:\t81 79 18 03 22 22 00 \tcmp\tDWORD PTR [rcx+0x18],0x222003\n'
                             '140001007:\t74 12                \tje\t14000101b <handler>\n')}],
                'objdump: используй `-d <файл>`.\n'),
    hints=['Драйвер — это PE-файл; `DriverEntry` и `IoCreateDevice` — признаки драйвера.',
           'IOCTL-коды задаются макросом CTL_CODE и видны как hex-константы.',
           '`strings -n 5 vulndrv.sys` покажет имена функций и артефакт.',
           "`strings -n 5 vulndrv.sys | grep nto > found.txt`, затем `check`."],
    flag='nto{10ctl_d1sp4tch_arb1tr4ry_wr1t3}',
    sol=['strings -n 5 vulndrv.sys > out.txt', 'grep nto out.txt > found.txt'])


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
           '// End-to-end solvability check for reversing gap batch b15.',
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
        out.append('    id: ' + js_str(lab['id']) + ', flag: ' + js_str(lab['flag']) +
                   ', hints: ' + str(len(lab['hints'])) + ',')
        out.append('    solution: [' + sol + '],')
        out.append('  },')
    out.append(']')
    out.append('')
    out.append("describe.each(LABS)('reversing b15 lab: $id', ({ id, flag, hints, solution }) => {")
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
    path = os.path.join(ROOT, 'frontend', 'src', 'lab', 'reversing-b15.spec.js')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    for lab in LABS:
        write_bundle(lab)
    write_spec(LABS)
    print('wrote %d bundles + 1 spec' % len(LABS))
    for lab in LABS:
        print(' ', lab['id'])
