#!/usr/bin/env python3
"""Generate lab bundles + e2e spec for reversing gap batch b16.

Lessons carry their own `lab:` front-matter (written directly as markdown);
this script writes the matching content/labs/<id>.json bundles and a vitest
spec proving solvability. Flags are embedded as plain bytes so `strings | grep`
works against the real fixture.
"""
import base64
import json
import os
import struct

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


def pe(dll=False, tail=b''):
    chars = 0x2000 | (0x2000 if dll else 0)
    return (b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00' + b'PE\x00\x00' +
            struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 0, chars) + tail)


def replay(tool, help_text, cases, fallback):
    return {tool: {'help': help_text, 'cases': cases, 'fallback': fallback}}


def write_bundle(lab):
    fs = [f_dir(WD), f_text(WD + '/task.md', lab['task'])] + lab['fs']
    bundle = {'id': lab['id'], 'workdir': WD, 'hostname': 'lab',
              'expect': {'file': WD + '/found.txt', 'contains': lab['flag']},
              'fs': fs, 'tools': lab['tools']}
    with open(os.path.join(LABS_DIR, lab['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write('\n')


LABS = []


def add(**k):
    LABS.append(k)


# ------------------------------------------------------------------ 6502 ----
add(id='reversing-6502-8bit', flag='nto{r0m_h4ck_6502_4sm}',
    task=('# Практика: ROM картриджа NES\n\n`game.nes` — дамп картриджа.\n'
          '1. `file game.nes` — определи формат по сигнатуре.\n'
          '2. `xxd -l 16 game.nes` — разбери заголовок iNES.\n'
          '3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/game.nes',
              b'NES\x1a\x02\x01\x01\x00' + b'\x00' * 8 +
              b'\xa9\x00\x8d\x00\x20\x20\x34\x80' + b'\x00' * 8 +
              b'(c) RETRO SOFT 1989\x00nto{r0m_h4ck_6502_4sm}\x00')],
    tools=replay('xxd', 'xxd [-l N] <файл> — hex-дамп',
                 [{'match': r'-l\s*16', 'example': '-l 16 game.nes',
                   'output': '00000000: 4e45 531a 0201 0100 0000 0000 0000 0000  NES.............\n'}],
                 'xxd: используй `xxd -l 16 <файл>`.\n'),
    sol=['strings -n 5 game.nes > out.txt', 'grep nto out.txt > found.txt'])

# ------------------------------------------------------------------- AVR ----
add(id='reversing-avr-8bit', flag='nto{avr_h4rv4rd_lpm_str1ng}',
    task=('# Практика: прошивка AVR\n\n`firmware.elf` — прошивка ATmega.\n'
          '1. `readelf -h firmware.elf` — определи Machine (AVR).\n'
          '2. `strings -n 5 firmware.elf` — найди версию и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/firmware.elf',
              elf32(83, 0x6c, b'ATmega328P\x00FW v1.2 build 2021\x00'
                              b'nto{avr_h4rv4rd_lpm_str1ng}\x00'))],
    tools=replay('readelf', 'readelf [-h] <файл> — заголовки ELF',
                 [{'match': r'-h', 'example': '-h firmware.elf',
                   'output': ('ELF Header:\n  Class:                             ELF32\n'
                              "  Data:                              2's complement, little endian\n"
                              '  Type:                              EXEC (Executable file)\n'
                              '  Machine:                           Atmel AVR 8-bit microcontroller\n')}],
                 'readelf: используй `readelf -h <файл>`.\n'),
    sol=['strings -n 5 firmware.elf > out.txt', 'grep nto out.txt > found.txt'])

# ------------------------------------------------------------------ BEAM ----
add(id='reversing-beam-erlang', flag='nto{beam_bytecode_4t0ms}',
    task=('# Практика: BEAM-модуль\n\n`module.beam` — скомпилированный модуль Erlang.\n'
          '1. `xxd -l 32 module.beam` — разбери контейнер FOR1/BEAM.\n'
          '2. `strings -n 5 module.beam` — найди имена и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/module.beam',
              b'FOR1' + struct.pack('>I', 0x0f2c) + b'BEAM' + struct.pack('>I', 0x0c) +
              b'AtU8' + struct.pack('>I', 40) +
              b'module_info\x00start\x00handle_call\x00nto{beam_bytecode_4t0ms}\x00')],
    tools=replay('xxd', 'xxd [-l N] <файл> — hex-дамп',
                 [{'match': r'-l\s*32', 'example': '-l 32 module.beam',
                   'output': '00000000: 464f 5231 0000 0f2c 4245 414d 0000 000c  FOR1...,BEAM....\n'}],
                 'xxd: используй `xxd -l 32 <файл>`.\n'),
    sol=['strings -n 5 module.beam > out.txt', 'grep nto out.txt > found.txt'])

# ------------------------------------------------------------- Ada/Fortran --
add(id='reversing-ada-fortran', flag='nto{f0rtr4n_c0lumn_m4j0r}',
    task=('# Практика: Fortran-бинарник\n\n`solver` — научный исполняемый файл.\n'
          '1. `file solver` — подтверди ELF.\n'
          '2. `strings -n 5 solver` — найди версию gfortran и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/solver',
              elf64(62, 0x1234, b'GNU Fortran 13.2.0\x00__gfortran_st_write\x00'
                                b'__math_MOD_solve\x00solve_\x00nto{f0rtr4n_c0lumn_m4j0r}\x00'))],
    tools=replay('nm', 'nm [-D] <файл> — таблица символов',
                 [{'match': r'-D', 'example': '-D solver',
                   'output': ('0000000000001234 T solve_\n'
                              '0000000000001280 T __math_MOD_gradient\n')}],
                 'nm: используй `nm -D <файл>`.\n'),
    sol=['strings -n 5 solver > out.txt', 'grep nto out.txt > found.txt'])

# ------------------------------------------------------------------ APT -----
add(id='reversing-apt-tooling', flag='nto{apt_1mpl4nt_c0mm4nds}',
    task=('# Практика: APT-имплант\n\n`implant.exe` — подозрительный PE.\n'
          '1. `file implant.exe` — подтверди PE.\n'
          '2. `strings -n 5 implant.exe` — выпиши команды импланта.\n'
          '3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/implant.exe',
              pe(tail=(b'shell\x00upload\x00download\x00sleep\x00whoami\x00'
                       b'VirtualAlloc\x00VirtualProtect\x00'
                       b'/api/v1/update\x00Mozilla/5.0\x00'
                       b'nto{apt_1mpl4nt_c0mm4nds}\x00')))],
    tools=replay('objdump', 'objdump [-d] <файл> — дизассемблер PE',
                 [{'match': r'-d', 'example': '-d implant.exe',
                   'output': ('implant.exe:     file format pei-x86-64\n'
                              'Disassembly of section .text:\n'
                              '140001000 <main>:\n'
                              '140001000:\tff 15 f3 0f 00 00 \tcall QWORD PTR [rip+0xff3]  ; VirtualAlloc\n'
                              '140001007:\tff e0            \tjmp rax\n')}],
                 'objdump: используй `objdump -d <файл>`.\n'),
    sol=['strings -n 5 implant.exe > out.txt', 'grep nto out.txt > found.txt'])

# --------------------------------------------------------------- banker -----
add(id='reversing-banker-infostealer', flag='nto{b4nk3r_w3b1nj3ct_h00k}',
    task=('# Практика: банкер\n\n`banker.dll` — подозрительная DLL.\n'
          '1. `file banker.dll` — подтверди PE DLL.\n'
          '2. `strings -n 5 banker.dll` — выпиши цели и канал C2.\n'
          '3. Найди строку-артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/banker.dll',
              pe(dll=True, tail=(b'login\x00password\x00cookie\x00wallet.dat\x00'
                                 b'VirtualProtect\x00HttpSendRequest\x00'
                                 b'gate.php\x00Content-Type\x00'
                                 b'nto{b4nk3r_w3b1nj3ct_h00k}\x00')))],
    tools=replay('objdump', 'objdump [-d] <файл> — дизассемблер PE',
                 [{'match': r'-d', 'example': '-d banker.dll',
                   'output': ('banker.dll:     file format pei-x86-64\n'
                              'Disassembly of section .text:\n'
                              '180001000 <DllMain>:\n'
                              '180001000:\tff 15 f3 0f 00 00 \tcall QWORD PTR [rip+0xff3]  ; VirtualProtect\n'
                              '180001007:\t48 89 03         \tmov QWORD PTR [rbx],rax\n')}],
                 'objdump: используй `objdump -d <файл>`.\n'),
    sol=['strings -n 5 banker.dll > out.txt', 'grep nto out.txt > found.txt'])

# --------------------------------------------------------------- botnet -----
add(id='reversing-botnet-loader', flag='nto{dga_s33d_r3c0v3r}',
    task=('# Практика: botnet-загрузчик\n\n`loader` — статический ELF.\n'
          '1. `file loader` — подтверди ELF.\n'
          '2. `strings -n 5 loader` — найди seed и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/loader',
              elf64(62, 0x1000, b'DGA v3\x00seed=2024-01-01\x00domain list\x00'
                                b'getaddrinfo\x00srand\x00rand\x00'
                                b'nto{dga_s33d_r3c0v3r}\x00'))],
    tools=replay('readelf', 'readelf [-h] <файл> — заголовки ELF',
                 [{'match': r'-h', 'example': '-h loader',
                   'output': ('ELF Header:\n  Class:                             ELF64\n'
                              '  Type:                              EXEC (Executable file)\n'
                              '  Machine:                           Advanced Micro Devices X86-64\n')}],
                 'readelf: используй `readelf -h <файл>`.\n'),
    sol=['strings -n 5 loader > out.txt', 'grep nto out.txt > found.txt'])

# -------------------------------------------------------------- bindiff -----
add(id='reversing-bindiff-diaphora-advanced', flag='nto{p4tch_d1ff_b0unds_ch3ck}',
    task=('# Практика: диффинг версий\n\nДаны `libfoo_v1.so` и `libfoo_v2.so`.\n'
          '1. `file libfoo_v1.so libfoo_v2.so` — подтверди ELF.\n'
          '2. `strings -n 5 libfoo_v2.so` — найди добавленную строку/артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/libfoo_v1.so', elf64(3, 0x2000, b'foo_parse_request\x00foo_free\x00')),
        f_b64(WD + '/libfoo_v2.so',
              elf64(3, 0x2000, b'foo_parse_request\x00foo_free\x00'
                                b'bounds_check\x00nto{p4tch_d1ff_b0unds_ch3ck}\x00'))],
    tools=replay('nm', 'nm [-D] <файл> — таблица символов',
                 [{'match': r'v2', 'example': '-D libfoo_v2.so',
                   'output': ('0000000000002000 T foo_parse_request\n'
                              '0000000000002100 T foo_free\n'
                              '0000000000002200 T bounds_check\n')}],
                 'nm: используй `nm -D <файл>`.\n'),
    sol=['strings -n 5 libfoo_v2.so > out.txt', 'grep nto out.txt > found.txt'])

# ----------------------------------------------------------------- CFG ------
add(id='reversing-cfg-recovery', flag='nto{cfg_r3c0v3ry_d1sp4tch3r}',
    task=('# Практика: CFG\n\n`obf.elf` — обфусцированный бинарник.\n'
          '1. `objdump -d obf.elf` — посмотри блоки и переходы.\n'
          '2. `strings -n 5 obf.elf` — найди строку-артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/obf.elf',
              elf64(62, 0x1000, b'dispatcher\x00jump table\x00'
                                b'nto{cfg_r3c0v3ry_d1sp4tch3r}\x00'))],
    tools=replay('objdump', 'objdump [-d] <файл> — дизассемблер',
                 [{'match': r'-d', 'example': '-d obf.elf',
                   'output': ('obf.elf:     file format elf64-x86-64\n'
                              'Disassembly of section .text:\n'
                              '0000000000001000 <dispatcher>:\n'
                              '    1000:\tff 24 c5 00 20 00 00 \tjmp QWORD PTR [rax*8+0x2000]\n'
                              '0000000000001100 <block1>:\n'
                              '    1100:\te9 fb fe ff ff       \tjmp 1000 <dispatcher>\n')}],
                 'objdump: используй `objdump -d <файл>`.\n'),
    sol=['strings -n 5 obf.elf > out.txt', 'grep nto out.txt > found.txt'])

# -------------------------------------------------------------- capstone ----
add(id='reversing-capstone-keystone', flag='nto{c4pst0n3_k3yst0n3_un1c0rn}',
    task=('# Практика: анализатор на Python\n\n`engine.elf` — целевой бинарник.\n'
          '1. `file engine.elf` — подтверди ELF.\n'
          '2. `strings -n 5 engine.elf` — найди версии библиотек и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/engine.elf',
              elf64(62, 0x1000, b'Capstone 5.0\x00Keystone 0.9\x00Unicorn 2.0\x00'
                                b'nto{c4pst0n3_k3yst0n3_un1c0rn}\x00'))],
    tools=replay('python3', 'python3 <скрипт.py> — интерпретатор Python',
                 [{'match': r'capstone|disasm', 'example': 'python3 disasm.py',
                   'output': ('0x1000: push rbp\n0x1001: mov rbp, rsp\n'
                              '0x1004: call 0x1100\n')}],
                 'python3: используй `python3 <скрипт.py>`.\n'),
    sol=['strings -n 5 engine.elf > out.txt', 'grep nto out.txt > found.txt'])

# -------------------------------------------------------------- cfg/cet -----
add(id='reversing-cfg-guard-cet', flag='nto{cf1_3ndbr64_sh4d0w_stack}',
    task=('# Практика: CFG/CET\n\n`hardened.exe` — защищённый PE.\n'
          '1. `file hardened.exe` — подтверди PE.\n'
          '2. `strings -n 5 hardened.exe` — найди метки CFG/CET и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/hardened.exe',
              pe(tail=(b'endbr64\x00GuardCFCheckFunctionPointer\x00'
                       b'__guard_check_icall_fptr\x00'
                       b'nto{cf1_3ndbr64_sh4d0w_stack}\x00')))],
    tools=replay('objdump', 'objdump [-d] <файл> — дизассемблер PE',
                 [{'match': r'-d', 'example': '-d hardened.exe',
                   'output': ('hardened.exe:     file format pei-x86-64\n'
                              'Disassembly of section .text:\n'
                              '140001000 <main>:\n'
                              '140001000:\tf3 0f 1e fa \tendbr64\n'
                              '140001004:\t55          \tpush rbp\n')}],
                 'objdump: используй `objdump -d <файл>`.\n'),
    sol=['strings -n 5 hardened.exe > out.txt', 'grep nto out.txt > found.txt'])

# --------------------------------------------------------------- uboot ------
add(id='reversing-bootloader-uboot', flag='nto{ub00t_env_b00targs_r3v}',
    task=('# Практика: загрузчик U-Boot\n\n`u-boot.bin` — образ загрузчика.\n'
          '1. `file u-boot.bin` — определи тип образа.\n'
          '2. `strings -n 5 u-boot.bin` — найди версию, env и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/u-boot.bin',
              b'\x27\x05\x19\x56' + b'\x00' * 12 +
              b'U-Boot 2023.07 (Aug 01 2023)\x00'
              b'bootargs=console=ttyS0 root=/dev/mtdblock2\x00'
              b'bootcmd=bootm 0x80000\x00'
              b'nto{ub00t_env_b00targs_r3v}\x00')],
    tools=replay('binwalk', 'binwalk <файл> — поиск встроенных образов',
                 [{'match': r'u-boot', 'example': 'u-boot.bin',
                   'output': ('DECIMAL       HEXADECIMAL     DESCRIPTION\n'
                              '0             0x0             uImage header, ...\n'
                              '64            0x40            U-Boot version string\n')}],
                 'binwalk: используй `binwalk <файл>`.\n'),
    sol=['strings -n 5 u-boot.bin > out.txt', 'grep nto out.txt > found.txt'])

# -------------------------------------------------------------- baseband ----
add(id='reversing-baseband-modem', flag='nto{b4s3b4nd_f1rmw4r3_c2}',
    task=('# Практика: прошивка модема\n\n`modem.mbn` — образ baseband-прошивки.\n'
          '1. `file modem.mbn` — определи тип.\n'
          '2. `strings -n 5 modem.mbn` — найди версию, AT-команды и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/modem.mbn',
              b'\x7fELF' + b'\x00' * 8 + b'QC_IMAGE_VERSION_STRING=MPSS.JO.3.0\x00'
              b'AT+CGSN\x00AT+CFUN=1\x00AT+COPS?\x00'
              b'nto{b4s3b4nd_f1rmw4r3_c2}\x00')],
    tools=replay('strings', 'strings [-n N] <файл> — печатаемые строки',
                 [{'match': r'modem', 'example': '-n 5 modem.mbn',
                   'output': ('QC_IMAGE_VERSION_STRING=MPSS.JO.3.0\n'
                              'AT+CGSN\nAT+CFUN=1\nAT+COPS?\n')}],
                 'strings: используй `strings -n 5 <файл>`.\n'),
    sol=['strings -n 5 modem.mbn > out.txt', 'grep nto out.txt > found.txt'])

# ------------------------------------------------------------------ BLE -----
add(id='reversing-bluetooth-l2cap', flag='nto{ble_l2c4p_g4tt_r3v}',
    task=('# Практика: BLE-трейс\n\n`ble_capture.pcap` — перехваченный обмен BLE.\n'
          '1. `file ble_capture.pcap` — определи формат.\n'
          '2. `strings -n 5 ble_capture.pcap` — найди GATT-сервисы и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/ble_capture.pcap',
              b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00' + b'\x00' * 16 +
              b'ATT_OP_READ_REQ\x00GATT_PRIMARY_SERVICE\x00'
              b'0000fff0-0000-1000-8000-00805f9b34fb\x00'
              b'nto{ble_l2c4p_g4tt_r3v}\x00')],
    tools=replay('tshark', 'tshark -r <файл> — анализ захвата',
                 [{'match': r'ble_capture', 'example': '-r ble_capture.pcap',
                   'output': ('    1 0.000000  aa:bb:cc:dd:ee:ff -> ff:ff:ff:ff:ff:ff  ATT  27 Read Request\n'
                              '    2 0.010000  ff:ff:ff:ff:ff:ff -> aa:bb:cc:dd:ee:ff  ATT  31 Read Response\n')}],
                 'tshark: используй `tshark -r <файл>`.\n'),
    sol=['strings -n 5 ble_capture.pcap > out.txt', 'grep nto out.txt > found.txt'])

# --------------------------------------------------------------- archive ----
add(id='reversing-archive-formats', flag='nto{arch1v3_z1p_crypt_r3v}',
    task=('# Практика: вложенный архив\n\n`sample.zip` — контейнер из малварь-дроппера.\n'
          '1. `file sample.zip` — определи формат.\n'
          '2. `strings -n 5 sample.zip` — найди имена вложений и артефакт.\n\nФлаг: `nto{...}`.\n'),
    fs=[f_b64(WD + '/sample.zip',
              b'PK\x03\x04' + b'\x00' * 22 + b'payload.bin\x00'
              b'config.json\x00stage2.bin\x00'
              b'nto{arch1v3_z1p_crypt_r3v}\x00' + b'PK\x05\x06' + b'\x00' * 18)],
    tools=replay('unzip', 'unzip [-l] <архив> — список содержимого',
                 [{'match': r'-l\s+sample', 'example': '-l sample.zip',
                   'output': ('Archive:  sample.zip\n'
                              '  Length      Name\n'
                              '     1024  payload.bin\n'
                              '      512  config.json\n'
                              '     2048  stage2.bin\n')}],
                 'unzip: используй `unzip -l <архив>`.\n'),
    sol=['strings -n 5 sample.zip > out.txt', 'grep nto out.txt > found.txt'])


def js_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def write_spec(labs):
    out = ["import { describe, it, expect } from 'vitest'",
           "import fs from 'node:fs'",
           "import path from 'node:path'",
           "import { createSession } from './session'",
           '',
           '// End-to-end solvability check for reversing gap batch b16.',
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
                   ', hints: 4,')
        out.append('    solution: [' + sol + '],')
        out.append('  },')
    out.append(']')
    out.append('')
    out.append("describe.each(LABS)('reversing b16 lab: $id', ({ id, flag, hints, solution }) => {")
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
    p = os.path.join(ROOT, 'frontend', 'src', 'lab', 'reversing-b16.spec.js')
    with open(p, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    for lab in LABS:
        write_bundle(lab)
    write_spec(LABS)
    print('wrote %d bundles + 1 spec' % len(LABS))
    for lab in LABS:
        print(' ', lab['id'])
