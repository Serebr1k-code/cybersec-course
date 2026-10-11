---
id: reversing-ebpf
title: "Реверс eBPF-программ"
category: reversing
parent: reversing-kernel-drivers
difficulty: expert
order: 1
tags: [reversing, ebpf, kernel, bpf, bytecode, rootkit, observability]
prerequisites: [reversing-kernel-drivers]
useful_for:
  - "CTF Reversing (expert)"
  - "Linux kernel security"
  - "Malware analysis (eBPF rootkits)"
estimated_minutes: 60
summary: "Анализ eBPF: байткод и BTF, загрузка программ, verifier, eBPF-руткиты и трассировка через bpftrace."
---
eBPF (extended Berkeley Packet Filter) — это программы, исполняемые **внутри ядра Linux**, используемые для observability, сетей, безопасности и (злонамеренно) для **rootkit**-техник. Реверс eBPF отличается от обычного: это байткод, проверяемый **verifier**'ом и исполняемый в ядре. Нужно уметь извлекать загруженные программы, дизассемблировать байткод, читать maps и трассировать поведение. Этот урок — практический разбор eBPF от архитектуры до анализа подозрительных программ.

## Что такое eBPF

- **BPF-байткод**: 64-битные RISC-подобные инструкции (`r0`–`r10`), загружаемые в ядро через `bpf()`.
- **Verifier**: статически проверяет безопасность — типы, границы доступа к памяти, завершаемость (нет бесконечных циклов без границы), отсутствие произвольных указателей.
- **JIT/интерпретатор**: исполняет байткод в ядре (JIT компилирует в машинный код).
- **Maps**: разделяемые структуры данных между программой, пользователем и ядром.
- **BTF**: типы/структуры ядра (для CO-RE — «compile once, run everywhere»).
- **Attach points**: `kprobe`, `fentry`, `tracepoint`, `xdp`, `tc`, `socket_filter`, `lsm`, `perf_event`.

## Типы программ и загрузка

| Тип | Точка привязки | Применение |
|-----|----------------|------------|
| kprobe/kretprobe | вход/выход функции ядра | observability, перехват |
| fentry/fexit | то же (BTF-based, быстрее) | современные хуки |
| tracepoint | статические точки ядра | стабильная трассировка |
| xdp | приём пакета (драйвер) | фильтрация, DDoS |
| tc (clsact) | трафик (qdisc) | маршрутизация, NAT |
| socket_filter | сокеты | фильтрация пакетов |
| lsm | LSM-хуки | безопасность |
| perf_event | события perf | профилирование |

Загрузка: `bpf(BPF_PROG_LOAD, ...)`; программы компилируют из C (clang `-target bpf`) или пишут на ассемблере. Прикрепление — через `BPF_LINK_CREATE`/libbpf.

## Verifier и безопасность

Verifier — ключевая особенность: он не даёт программе навредить ядру. Что проверяет:

- **Границы памяти**: каждое чтение/запись должно быть в допустимом диапазоне (проверка типов указателей).
- **Завершаемость**: циклы должны иметь известную границу (нет бесконечных циклов).
- **Инициализацию регистров**: нельзя читать неинициализированный регистр.
- **Типы хелперов**: вызовы разрешённых helper-функций с корректными аргументами.

Для реверса это значит: **что бы ни делала программа, она прошла verifier** — значит, она «безопасна» с точки зрения памяти, но может быть вредоносной логически (скрывать данные, фильтровать syscalls).

## BTF и CO-RE

BTF (BPF Type Format) описывает типы ядра, а CO-RE (Compile Once — Run Everywhere) позволяет программе работать на разных ядрах, используя BTF для релокаций:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux | head
# Дампить BTF конкретного объекта
bpftool btf dump file prog.o format c
```

BTF помогает восстановить имена полей структур и типов — незаменимо при анализе.

## Maps

Maps — где живут данные и состояние программы:

```bash
bpftool map list
bpftool map dump id <id>          # содержимое (ключи/значения)
bpftool map show id <id>          # тип, размеры
```

Скрытые данные rootkit'а (списки скрытых PID/файлов, ключи) часто лежат именно в maps.

## Внутреннее устройство: инструкции и хелперы

BPF-байткод — это простая RISC-подобная машина:

- **Регистры** `r0`–`r10` (64-бит). `r10` — read-only указатель на стек (frame pointer); `r0` — возврат; `r1`–`r5` — аргументы хелперов.
- **Стек** — фиксированный (512 байт) на программу.
- **Инструкции**: загрузка/сохранение (`ldx/stx`), арифметика/логика (`add/sub/and/or/xor`), сдвиги, ветвления (`jmp/jeq/jne/jgt`), вызовы (`call`).
- **Хелперы** — заранее разрешённые функции ядра (`bpf_map_lookup_elem`, `bpf_probe_read_kernel`, `bpf_get_current_pid_tgid`, `bpf_send_signal`, ...). Список зависит от типа программы.
- **Псевдо-вызовы (kfuncs)** — современный механизм вызова ядерных функций по BTF.

Чтение xlated-байткода: ищите `call <helper>` (что делает), обращения к map (что читает/пишет) и условные переходы (логика фильтрации). Это быстро раскрывает назначение программы.

## Как eBPF попадает в систему (загрузка и персистентность)

- **Загрузка** — пользовательский процесс вызывает `bpf(BPF_PROG_LOAD)`; требуются `CAP_BPF`/`CAP_SYS_ADMIN` (или root).
- **Прикрепление** — `BPF_LINK_CREATE`, `perf_event_open`, `setsockopt(SO_ATTACH_BPF)`, `bpf_trace_printk`; бывает «pinned» в bpffs (`/sys/fs/bpf/`) для персистентности между процессами.
- **Персистентность rootkit'а**: pinned-программа в bpffs + авто-прикрепление при старте (systemd/init) или через уже скомпрометированный процесс.
- **Сокрытие**: перехват `bpf_prog_get_next_id`/`bpf_map_get_next_id` скрывает программу от `bpftool` — тогда нужны прямые syscall'ы или анализ ядра/памяти.

## Извлечение и анализ

```bash
# Загруженные программы
bpftool prog list
bpftool prog dump xlated id <id>       # дизассемблированный байткод (человекочитаемый)
bpftool prog dump jited id <id>        # JIT-код (машинный)
bpftool map list
bpftool btf dump file /sys/kernel/btf/vmlinux
# Список с деталями (JSON)
bpftool -j prog show
# Дамп по имени
bpftool prog dump xlated name <name>
```

## Дизассемблирование

- **bpftool** выдаёт «xlated» (понятный байткод) и JIT-код — первый лучше для логики.
- **LLVM**: `llvm-objdump -d prog.o` (если есть ELF BPF-объект).
- **Ghidra**: плагины для eBPF (eBPF-процессор).
- **BTF** помогает восстановить типы структур.

```bash
# Если есть ELF BPF
llvm-objdump -S prog.o
```

## eBPF-руткиты

Злонамеренный eBPF (например, rootkit'ы вроде bpfdoor-подобных техник) может:

- **Перехватывать syscalls** (`kprobe`/`fentry` на `sys_*`) и скрывать процессы/файлы (фильтруя результаты `getdents`/`readdir`).
- **Манипулировать** данными в ядре через map (скрытые PID, подмена возвратов).
- **Прятать себя** от `bpftool`/`lsmod` (перехват `bpf`/`bpf_prog_get_next_id`).
- **Обходить LSM** (перехват LSM-хуков).

Анализ: сравнить состояние с эталоном (чистой системой), искать неожиданные BPF-программы/maps, трассировать их поведение.

## Трассировка через bpftrace

```bash
# Пример: трассировка открытий файлов
bpftrace -e 'kprobe:do_sys_open { printf("%s %s\n", comm, str(arg1)); }'
# Список доступных точек
bpftrace -l 'tracepoint:syscalls:*'
# Готовые скрипты
bpftrace /usr/share/bpftrace/tools/execsnoop.bt
```

bpftrace — высокоуровневый язык для написания/анализа BPF-логики; удобен, чтобы быстро понять, что делает программа.

## Разобранный пример: анализ подозрительной BPF-программы

```text
1) bpftool prog list -> неожиданная kprobe-программа (без известного имени).
2) bpftool prog dump xlated id N -> байткод.
3) Читаем: какие map использует, какие функции перехватывает.
4) bpftool map dump id M -> содержимое map (возможно, скрытые данные: PID/пути).
5) Сопоставляем с поведением (скрытые процессы/файлы).
```

```bash
bpftool prog list
bpftool -j prog show
bpftool prog dump xlated id <id>
bpftool prog dump jited id <id>
bpftool map list
bpftool map dump id <id>
bpftool btf dump file /sys/kernel/btf/vmlinux | head
```

## Практика: написание и загрузка своей eBPF-программы

Чтобы понять механику, полезно написать простую программу:

```c
// trace.c — kprobe на do_sys_open, логирует имя файла
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    char fmt[] = "open called\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
char _license[] SEC("license") = "GPL";
```

```bash
clang -O2 -target bpf -c trace.c -o trace.o
bpftool prog load trace.o /sys/fs/bpf/trace_open
bpftool net attach kprobe do_sys_open pinned /sys/fs/bpf/trace_open
cat /sys/kernel/debug/tracing/trace_pipe
```

Загрузка требует `CAP_BPF`/`CAP_SYS_ADMIN`. Так вы видите весь путь: компиляция → verifier → загрузка → прикрепление → исполнение. Анализ чужой программы — обратный процесс: от загруженного байткода к исходной логике.

## Частые ошибки

- **Игнорировать BTF.** Типы помогают понять структуры и поля.
- **Смотреть только JIT.** xlated-байткод понятнее для логики.
- **Забыть про maps.** Скрытые данные часто именно в map.
- **Нет эталона.** Сравнивайте с чистой системой — иначе не отличить легитимное.
- **Не учитывать verifier-ограничения.** Он ограничивает возможности программы (но не логику).
- **Привилегии.** Анализ eBPF требует root/CAP_BPF (в контейнерах часто отключено).
- **Пропуск attach-точек.** Программа «видна», но её эффект — в перехваченной функции.

## Что делать дальше / решение

1. Перечислите программы/maps (`bpftool prog list`, `map list`) и сравните с эталоном.
2. Для подозрительных — дампите байткод (`dump xlated`) и читайте логику.
3. Импортируйте BTF, восстановите типы; дампите maps (скрытые данные).
4. Определите attach-точку (какой syscall/функция перехвачена) и её эффект.
5. Трассируйте поведение (`bpftrace`) и подтвердите сокрытие/манипуляцию.
6. Оформите IOC (ID программ, содержимое maps, перехваченные функции).

## Квиз

```quiz
- question: "Что такое eBPF?"
  options:
    - "Программы, исполняемые в ядре Linux (байткод, проверяемый verifier)"
    - "Пакет Python"
    - "Формат ELF"
    - "Пакер"
  answer: 0
  explanation: "eBPF — расширенный BPF, исполняемый в ядре."
- question: "Как вывести байткод BPF-программы?"
  options:
    - "bpftool prog dump xlated id <id>"
    - "nm"
    - "ldd"
    - "objdump -h"
  answer: 0
  explanation: "bpftool дампит xlated/JIT код программы."
- question: "Что такое BTF?"
  options:
    - "Типы/структуры ядра для CO-RE"
    - "Формат картинок"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "BTF описывает типы для eBPF-программ."
- question: "Как eBPF-руткит может скрывать процессы?"
  options:
    - "Перехватом syscalls через kprobe/fentry"
    - "Шифрованием диска"
    - "Сканированием портов"
    - "Сжатием памяти"
  answer: 0
  explanation: "Перехват sys_* позволяет фильтровать результаты."
- question: "Какой инструмент удобен для трассировки eBPF?"
  options:
    - "bpftrace"
    - "nm"
    - "objdump"
    - "strace"
  answer: 0
  explanation: "bpftrace — высокоуровневый язык для eBPF-трассировки."
```

## Где пригодится

- **CTF:** Reversing (expert) — eBPF-задачи.
- **Linux kernel security:** анализ rootkit.
- **Malware analysis:** eBPF-малварь.
- **Работа:** observability, kernel security.
