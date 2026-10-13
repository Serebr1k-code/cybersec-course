# Batch: remaining pwn kernel lessons (kernel pwn recon/heap/mitigations/ROP/pipe/eBPF/uffd/nft/io_uring/cross-cache).
# Real fixtures: a freestanding ELF "module" (vuln.ko), a freestanding kernel image (vmlinux) with real
# gadgets captured from ROPgadget, a real eBPF object (clang -target bpf), real /proc and /sys captures.
import base64
import os

KB = '/tmp/labgen/kb'
WD = '/home/student/task'


def _b64(path):
    with open(os.path.join(KB, path), 'rb') as f:
        return base64.b64encode(f.read()).decode()


def _txt(path):
    with open(os.path.join(KB, path), encoding='utf-8') as f:
        return f.read()


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _bin(p, path):
    return {'path': p, 'b64': _b64(path), 'mode': '755'}


def _lab(id, title, files, hints, answer, fs, tools=None, toolset=None):
    return {
        'id': id, 'category': 'pwn', 'title': title,
        'toolset': toolset or ['core', 'elf'],
        'workdir': WD, 'files': files,
        'check': "grep -q '" + answer + "' answer.txt",
        'hints': hints,
        'expect': {'file': f'{WD}/answer.txt', 'contains': answer},
        'fs': fs,
        'tools': tools or {},
    }


CPUINFO = (
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "cpu family\t: 6\n"
    "model\t\t: 158\n"
    "model name\t: Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz\n"
    "stepping\t: 10\n"
    "cpu MHz\t\t: 3192.000\n"
    "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
    "clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc "
    "art arch_perfmon pebs bts rep_good nopl xtopology cpuid pni pclmulqdq dtes64 monitor ds_cpl "
    "vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt "
    "tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb "
    "invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid fsgsbase "
    "tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt "
    "xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp "
    "md_clear flush_l1d arch_capabilities\n"
    "bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit\n"
    "bogomips\t: 6384.00\n"
)

CR4_TXT = (
    "$ gdb ./vmlinux -ex 'target remote :1234'\n"
    "Remote debugging using :1234\n"
    "0xffffffff81000000 in ?? ()\n"
    "(gdb) p/x $cr4\n"
    "$1 = 0x370ef0\n"
    "(gdb) x/2i $rip\n"
    "=> 0xffffffff81000000:  nop\n"
    "   0xffffffff81000002:  nop\n"
)

SLAB_LIST = _txt('slab-list.txt')

# ---------------------------------------------------------------- specs ----

SPECS = [
    # 1) kernel-intro — recon the vulnerable module
    _lab('pwn-kernel-intro', 'Практика: разведка уязвимого модуля ядра',
         ['task.md', 'vuln.ko', 'vuln.readelf.txt', 'vuln.objdump.txt', 'cpuinfo.txt'],
         ['Модуль — это ELF-объект: `file vuln.ko` покажет `ELF`, а `readelf -sW vuln.ko` перечислит символы.',
          'Символы обработчиков: `vuln_read`, `vuln_write`, `vuln_ioctl` — именно ioctl обычно несёт баг.',
          'В дизассемблере (`objdump -d vuln.ko`, файл `vuln.objdump.txt`) найди в `vuln_ioctl` сравнение с константой: `cmpq $0x1337`.',
          "Запиши `ioctl=0x1337` в `answer.txt` и набери `check`."],
         'ioctl=0x1337',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: разведка уязвимого модуля ядра\n\n'
             'В каталоге лежит объект ядерного модуля `vuln.ko` (устройство `/dev/vuln`).\n'
             'Твоя цель — найти **команду ioctl**, которая триггерит баг.\n\n'
             '1. `file vuln.ko` — убедись, что это ELF-объект.\n'
             '2. `readelf -sW vuln.ko` (или `cat vuln.readelf.txt`) — символы модуля.\n'
             '3. `objdump -d vuln.ko` (или `cat vuln.objdump.txt`) — дизассемблер; найди константу сравнения в `vuln_ioctl`.\n'
             '4. Запиши `ioctl=<команда>` в `answer.txt` и набери `check`.\n'),
          _bin(f'{WD}/vuln.ko', 'vuln.ko'),
          _f(f'{WD}/vuln.readelf.txt', _txt('vuln.readelf-s.txt')),
          _f(f'{WD}/vuln.objdump.txt', _txt('vuln.objdump.txt')),
          _f(f'{WD}/cpuinfo.txt', CPUINFO)],
         tools={
             'readelf': {'help': 'readelf [-sW | --file-header] <файл> — (replay)',
                         'cases': [{'match': r'vuln', 'example': '-sW vuln.ko', 'output': _txt('vuln.readelf-s.txt')}],
                         'fallback': 'readelf: доступно `readelf -sW vuln.ko`\n'},
             'objdump': {'help': 'objdump [-d | -s] <файл> — (replay)',
                         'cases': [{'match': r'vuln', 'example': '-d vuln.ko', 'output': _txt('vuln.objdump.txt')}],
                         'fallback': 'objdump: доступно `objdump -d vuln.ko`\n'},
             'nm': {'help': 'nm <файл> — (replay)',
                    'cases': [{'match': r'vuln', 'example': 'vuln.ko', 'output': _txt('vuln.nm.txt')}],
                    'fallback': 'nm: доступно `nm vuln.ko`\n'},
         }),

    # 2) kernel-heap — SLUB cache selection
    _lab('pwn-kernel-heap', 'Практика: выбор kmalloc-кэша (SLUB)',
         ['task.md', 'slab-list.txt', 'structs.txt'],
         ['SLUB округляет запрос до ближайшего кэша из списка `slab-list.txt`.',
          '`seq_operations` — это 4 указателя на функции (`start`, `stop`, `next`, `show`).',
          'На 64-бит один указатель = 8 байт, значит размер структуры = 4 × 8 = 0x20.',
          "Ближайший кэш ≥ 0x20 — `kmalloc-32`. Запиши `seq_ops_cache=kmalloc-32` и набери `check`."],
         'seq_ops_cache=kmalloc-32',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: выбор kmalloc-кэша\n\n'
             'Уязвимый объект — `struct seq_operations` (открытие `/proc/self/stat` его аллоцирует).\n'
             'Чтобы переиспользовать освобождённую память, объект-жертва должен попасть в **тот же** кэш.\n\n'
             '1. Посмотри список кэшей: `cat slab-list.txt` (реальный `ls /sys/kernel/slab/`).\n'
             '2. В `structs.txt` — размеры структур. Возьми размер `seq_operations`.\n'
             '3. Округли размер вверх до ближайшего `kmalloc-*` кэша.\n'
             '4. Запиши `seq_ops_cache=<кэш>` в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/slab-list.txt', SLAB_LIST),
          _f(f'{WD}/structs.txt',
             'struct seq_operations   size 0x20    (4 function pointers)\n'
             'struct pipe_buffer      size 0x28    (per-entry, array in kmalloc)\n'
             'struct tty_struct       size 0x2b8   (kernel 6.1, varies)\n'
             'struct msg_msg header   size 0x30    (+ payload, variable)\n')]),

    # 3) kernel-smep-smap — check flags and clear cr4 bits
    _lab('pwn-kernel-smep-smap', 'Практика: проверка SMEP/SMAP и очистка cr4',
         ['task.md', 'cpuinfo.txt', 'cr4.txt'],
         ['Проверь флаги CPU: `grep smep cpuinfo.txt` и `grep smap cpuinfo.txt` — обе защиты включены.',
          'SMEP — бит 20 регистра `cr4` (0x100000), SMAP — бит 21 (0x200000).',
          'Текущее значение `cr4` захвачено в `cr4.txt`: `0x370ef0`.',
          "Очисти оба бита: `cr4 & ~0x300000` → `0x70ef0`. Запиши `cr4_clean=0x70ef0` и набери `check`."],
         'cr4_clean=0x70ef0',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: обход SMEP/SMAP через cr4\n\n'
             'Прежде чем строить ROP, узнай защиты цели. `cpuinfo.txt` — захваченный `/proc/cpuinfo`.\n\n'
             '1. `grep smep cpuinfo.txt` и `grep smap cpuinfo.txt` — убедись, что биты есть.\n'
             '2. `cat cr4.txt` — значение `cr4` из отладчика (`p/x $cr4`).\n'
             '3. Сбрось биты SMEP (20) и SMAP (21), чтобы `ret2usr` стал возможен.\n'
             '4. Запиши `cr4_clean=<значение>` (в hex, с префиксом `0x`) в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/cpuinfo.txt', CPUINFO),
          _f(f'{WD}/cr4.txt', CR4_TXT)]),

    # 4) kernel-rop — find gadgets in vmlinux
    _lab('pwn-kernel-rop', 'Практика: поиск гаджетов в vmlinux',
         ['task.md', 'vmlinux', 'vmlinux.ropgadget.txt'],
         ['ROPgadget ищет гаджеты в ELF: `ROPgadget --binary ./vmlinux --only "pop|ret"`.',
          'Первый аргумент в x86-64 передаётся через `rdi`, поэтому нужен гаджет `pop rdi ; ret`.',
          'Готовый вывод захвачен в `vmlinux.ropgadget.txt` (файл `vmlinux` — тот же образ).',
          "Найди строку `pop rdi ; ret` и запиши её адрес: `pop_rdi=0x401036`. Затем `check`."],
         'pop_rdi=0x401036',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: гаджеты ядра\n\n'
             'Для ядерного ROP нужны гаджеты из кода ядра (`vmlinux`).\n\n'
             '1. `ROPgadget --binary ./vmlinux --only "pop|ret"` (или `cat vmlinux.ropgadget.txt`).\n'
             '2. Найди гаджет `pop rdi ; ret` — им задают первый аргумент функции ядра.\n'
             '3. Запиши `pop_rdi=<адрес>` (hex, с `0x`) в `answer.txt` и набери `check`.\n'
             'Подсказка: `swapgs ; ret` в этом же образе понадобится для возврата в userland.\n'),
          _bin(f'{WD}/vmlinux', 'vmlinux'),
          _f(f'{WD}/vmlinux.ropgadget.txt', _txt('vmlinux.ropgadget-pop.txt'))],
         tools={
             'ROPgadget': {'help': 'ROPgadget --binary <файл> [--only "pop|ret"] — (replay)',
                           'cases': [{'match': r'pop', 'example': '--binary ./vmlinux --only "pop|ret"',
                                      'output': _txt('vmlinux.ropgadget-pop.txt')},
                                     {'match': r'vmlinux', 'example': '--binary ./vmlinux',
                                      'output': _txt('vmlinux.ropgadget.txt')}],
                           'fallback': 'ROPgadget: доступно `ROPgadget --binary ./vmlinux`\n'},
             'readelf': {'help': 'readelf [-sW | --file-header] <файл> — (replay)',
                         'cases': [{'match': r'vmlinux', 'example': '-sW vmlinux', 'output': _txt('vmlinux.readelf-s.txt')}],
                         'fallback': 'readelf: доступно `readelf -sW vmlinux`\n'},
         }),

    # 5) kernel-pipe-buffer — cache selection + sysctls
    _lab('pwn-kernel-pipe-buffer', 'Практика: pipe_buffer — размеры и кэш',
         ['task.md', 'slab-list.txt', 'pipe-max-size.txt', 'pipe-user-pages-soft.txt'],
         ['Уязвимый объект занимает ~0x280 байт — его надо накрыть объектом из того же кэша.',
          '`slab-list.txt` — реальный список кэшей; найди ближайший кэш ≥ 0x280.',
          '0x280 = 640 байт: это больше `kmalloc-512`, но ≤ `kmalloc-1k`.',
          "Запиши `victim_cache=kmalloc-1k` в `answer.txt` и набери `check`."],
         'victim_cache=kmalloc-1k',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: pipe_buffer и кэш жертвы\n\n'
             'План: освободить уязвимый объект (~0x280 байт) и накрыть его `pipe_buffer`-массивом.\n'
             'Для этого нужен **тот же** kmalloc-кэш.\n\n'
             '1. `cat slab-list.txt` — реальный `ls /sys/kernel/slab/`.\n'
             '2. `cat pipe-max-size.txt`, `cat pipe-user-pages-soft.txt` — лимиты pipe (контекст).\n'
             '3. Определи кэш для объекта размером 0x280 (округление вверх).\n'
             '4. Запиши `victim_cache=<кэш>` в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/slab-list.txt', SLAB_LIST),
          _f(f'{WD}/pipe-max-size.txt', '1048576\n'),
          _f(f'{WD}/pipe-user-pages-soft.txt', '16384\n')]),

    # 6) kernel-ebpf — availability + program type
    _lab('pwn-kernel-ebpf', 'Практика: доступность eBPF на цели',
         ['task.md', 'bpfprog.o', 'bpf.readelf.txt', 'unprivileged_bpf_disabled.txt', 'bpf_jit_enable.txt'],
         ['Сначала проверь, разрешён ли unprivileged eBPF: `cat unprivileged_bpf_disabled.txt`.',
          'Значение `2` означает «полностью запрещён» (даже для CAP_BPF-пользователей он не включается).',
          'Для контекста: `bpf.readelf.txt` — реальный ELF-заголовок eBPF-объекта (`Machine: Linux BPF`).',
          "Запиши `unprivileged_bpf=2` в `answer.txt` и набери `check`."],
         'unprivileged_bpf=2',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: доступность eBPF\n\n'
             'В ядерных задачах часто эксплуатируют подсистему eBPF. Сначала узнай, доступна ли она.\n\n'
             '1. `cat unprivileged_bpf_disabled.txt` — захваченный `/proc/sys/kernel/unprivileged_bpf_disabled`.\n'
             '2. `cat bpf_jit_enable.txt` — включён ли JIT.\n'
             '3. `cat bpf.readelf.txt` — реальный ELF eBPF-программы (архитектура, секция `xdp`).\n'
             '4. Запиши `unprivileged_bpf=<значение>` в `answer.txt` и набери `check`.\n'),
          _bin(f'{WD}/bpfprog.o', 'bpfprog.o'),
          _f(f'{WD}/bpf.readelf.txt', _txt('bpf.readelf-h.txt') + '\n' + _txt('bpf.readelf-S.txt')),
          _f(f'{WD}/unprivileged_bpf_disabled.txt', '2\n'),
          _f(f'{WD}/bpf_jit_enable.txt', '1\n')],
         tools={
             'readelf': {'help': 'readelf [--file-header | -SW] <файл> — (replay)',
                         'cases': [{'match': r'file-header', 'example': '--file-header bpfprog.o',
                                    'output': _txt('bpf.readelf-h.txt')},
                                   {'match': r'-SW', 'example': '-SW bpfprog.o', 'output': _txt('bpf.readelf-S.txt')},
                                   {'match': r'bpfprog', 'example': '-sW bpfprog.o', 'output': _txt('bpf.readelf-s.txt')}],
                         'fallback': 'readelf: доступно `readelf --file-header bpfprog.o`\n'},
         }),

    # 7) kernel-userfaultfd — availability
    _lab('pwn-kernel-userfaultfd', 'Практика: доступность userfaultfd',
         ['task.md', 'unprivileged_userfaultfd.txt'],
         ['UFFD нужен для «заморозки» ядра в гонке (окно между check и use).',
          'Проверь `cat unprivileged_userfaultfd.txt` — захваченный `/proc/sys/vm/unprivileged_userfaultfd`.',
          'Значение `0` = unprivileged-доступ запрещён (нужен CAP_SYS_PTRACE); тогда гонку делают через FUSE.',
          "Запиши `unprivileged_userfaultfd=0` в `answer.txt` и набери `check`."],
         'unprivileged_userfaultfd=0',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: доступность userfaultfd\n\n'
             'Приём UFFD (заморозить ядро на user-странице) требует включённого unprivileged userfaultfd.\n\n'
             '1. `cat unprivileged_userfaultfd.txt`.\n'
             '2. Определи, доступен ли UFFD обычному пользователю (0 = нет, 1 = да).\n'
             '3. Запиши `unprivileged_userfaultfd=<значение>` в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/unprivileged_userfaultfd.txt', '0\n')]),

    # 8) kernel-nftables — userns + nft version
    _lab('pwn-kernel-nftables', 'Практика: условия для nf_tables-эксплойта',
         ['task.md', 'unprivileged_userns_clone.txt', 'nft-version.txt', 'version.txt'],
         ['nf_tables-эксплойты (CVE-2022-32250, CVE-2023-32233) требуют user namespace.',
          'Проверь `cat unprivileged_userns_clone.txt` — захваченный `/proc/sys/kernel/unprivileged_userns_clone`.',
          '`1` = непривилегированные userns разрешены → атака достижима.',
          "Запиши `userns_clone=1` в `answer.txt` и набери `check`."],
         'userns_clone=1',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: условия для nf_tables\n\n'
             'Чтобы эксплуатировать баг в `nf_tables` из userland, нужен unprivileged user namespace.\n\n'
             '1. `cat unprivileged_userns_clone.txt` — можно ли создавать userns без root.\n'
             '2. `cat version.txt` и `cat nft-version.txt` — версия ядра и nftables (контекст).\n'
             '3. Запиши `userns_clone=<значение>` в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/unprivileged_userns_clone.txt', '1\n'),
          _f(f'{WD}/nft-version.txt', 'nftables v1.0.9 (Old Doc Yak #3)\n'),
          _f(f'{WD}/version.txt', 'Linux version 6.1.0-lab (root@lab) #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n')]),

    # 9) kernel-io_uring — disabled flag
    _lab('pwn-kernel-io_uring', 'Практика: доступность io_uring',
         ['task.md', 'io_uring_disabled.txt', 'version.txt'],
         ['io_uring-эксплойты (CVE-2021-41073, CVE-2023-0461) требуют доступного интерфейса io_uring.',
          'Проверь `cat io_uring_disabled.txt` — захваченный `/proc/sys/kernel/io_uring_disabled`.',
          'Значение `2` = io_uring полностью отключён (syscall `io_uring_setup` не создаст ring).',
          "Запиши `io_uring_disabled=2` в `answer.txt` и набери `check`."],
         'io_uring_disabled=2',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: доступность io_uring\n\n'
             'Прежде чем строить эксплойт через io_uring, узнай, не выключен ли интерфейс на цели.\n\n'
             '1. `cat io_uring_disabled.txt` — захваченный `/proc/sys/kernel/io_uring_disabled`.\n'
             '2. `cat version.txt` — версия ядра.\n'
             '3. Запиши `io_uring_disabled=<значение>` в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/io_uring_disabled.txt', '2\n'),
          _f(f'{WD}/version.txt', 'Linux version 6.1.0-lab (root@lab) #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n')]),

    # 10) kernel-cross-cache — identify cache names
    _lab('pwn-kernel-cross-cache', 'Практика: cross-cache — имена кэшей',
         ['task.md', 'slab-list.txt', 'structs.txt'],
         ['Cross-cache атака переиспользует память между разными кэшами/слабами.',
          '`slab-list.txt` — реальный `ls /sys/kernel/slab/`; имена кэшей там точные.',
          'Найди отдельный (не kmalloc-) кэш для структуры `struct cred`.',
          "Он называется `cred`. Запиши `cred_cache=cred` в `answer.txt` и набери `check`."],
         'cred_cache=cred',
         [_dir(WD),
          _f(f'{WD}/task.md',
             '# Задача: имена кэшей для cross-cache\n\n'
             'Cross-cache эксплуатация требует точно знать имя кэша объекта-жертвы.\n\n'
             '1. `cat slab-list.txt` — реальный список кэшей ядра.\n'
             '2. `cat structs.txt` — краткие размеры.\n'
             '3. Найди кэш, в котором живёт `struct cred` (это не `kmalloc-*`).\n'
             '4. Запиши `cred_cache=<имя>` в `answer.txt` и набери `check`.\n'),
          _f(f'{WD}/slab-list.txt', SLAB_LIST),
          _f(f'{WD}/structs.txt',
             'struct cred          -> dedicated cache\n'
             'struct file          -> dedicated cache (filp)\n'
             'struct seq_operations-> kmalloc-32\n'
             'struct msg_msg       -> msg_msg-<size> or kmalloc\n')]),
]
