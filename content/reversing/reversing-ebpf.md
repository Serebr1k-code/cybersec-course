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
## Вопрос, с которого всё начинается

На Linux-хосте появилась подозрительная активность, а в системе крутится программа, которой ты не
ставил. Она **не** обычный бинарник: она исполняется **внутри ядра** и называется **eBPF**
(extended Berkeley Packet Filter). Такие программы используют и для наблюдаемости, и для атак
(eBPF-**руткиты**). Как её найти, прочитать и понять, что она делает?

Реверс eBPF отличается от обычного: это не машинный код x86, а **байткод** для виртуальной машины
ядра, проверяемый **verifier**'ом. Нужно уметь извлекать загруженные программы, дизассемблировать
байткод, читать maps и трассировать поведение.

Опираемся на прошлые уроки: мы умеем читать дизассемблер (`objdump`) и анализировать бинарники.
Здесь применим те же навыки к байткоду ядра.

## Наш пример

Чтобы понять механику, соберём маленькую eBPF-программу и посмотрим на её байткод. Программа
привязывается к функции ядра `do_sys_open` (открытие файла) и печатает сообщение:

```c
#define SEC(NAME) __attribute__((section(NAME), used))
typedef unsigned int __u32;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

SEC("kprobe/do_sys_open")
int trace_open(void *ctx) {
    char fmt[] = "open called\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return 0;
}
char _license[] SEC("license") = "GPL";
```

Компилируем в объект BPF (clang умеет целевую архитектуру `bpf`):

```
$ clang -O2 -target bpf -c trace.c -o trace.o
$ file trace.o
trace.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

`SEC("kprobe/do_sys_open")` — это **attach point**: точка ядра, к которой прицепится программа
(kprobe — перехват входа в функцию ядра). Файл получился ELF с архитектурой **eBPF**.

## Шаг 1: что такое eBPF

- **BPF-байткод** — 64-битные RISC-подобные инструкции для виртуальной машины ядра, регистры
  `r0`–`r10`.
- **Verifier** — статически проверяет программу: типы указателей, границы памяти, завершаемость
  (нет бесконечных циклов), инициализацию регистров. Программа, прошедшая verifier, **безопасна
  для памяти** — но может быть вредоносной логически.
- **Maps** — разделяемые структуры данных между программой, ядром и пользователем.
- **BTF** (BPF Type Format) — описание типов ядра для механизма **CO-RE** («compile once, run
  everywhere»).
- **Attach points**: `kprobe`/`kretprobe`, `fentry`/`fexit`, `tracepoint`, `xdp`, `tc`, `lsm`,
  `perf_event`.

Тип attach point определяет, где именно работает программа. Наша — `kprobe` на `do_sys_open`.

## Шаг 2: читаем байткод

Дизассемблируем объект обычным `objdump` — он понимает eBPF:

```
$ objdump -d trace.o
trace.o:     file format elf64-bpfle

Disassembly of section kprobe/do_sys_open:

0000000000000000 <trace_open>:
   0:  b4 01 00 00 6c 65 64 0a  mov32 %r1,174351724
   8:  63 1a f8 ff 00 00 00 00  stxw [%r10-8],%r1
  10:  18 01 00 00 6f 70 65 6e  lddw %r1,7809632219779395695
  18:  00 00 00 00 20 63 61 6c
  20:  7b 1a f0 ff 00 00 00 00  stxdw [%r10-16],%r1
  28:  b4 01 00 00 00 00 00 00  mov32 %r1,0
  30:  73 1a fc 00 00 00 00 00  stxb [%r10-4],%r1
  38:  bf a1 00 00 00 00 00 00  mov %r1,%r10
  40:  07 01 00 00 f0 ff ff ff  add %r1,-16
  48:  b4 02 00 00 0d 00 00 00  mov32 %r2,13
  50:  85 00 00 00 06 00 00 00  call 6
  58:  b4 00 00 00 00 00 00 00  mov32 %r0,0
  60:  95 00 00 00 00 00 00 00  exit
```

Читается как ассемблер. `mov32 %r1,174351724` кладёт в регистр `r1` первые 4 байта строки
`"open called\n"` (это little-endian число). `lddw %r1,...` догружает остаток строки. Затем
`mov %r1,%r10; add %r1,-16` — `r10` это указатель на стек (frame pointer), поэтому так берут адрес
буфера на стеке. `mov32 %r2,13` — второй аргумент (длина 13 байт). И, наконец,
`call 6` — вызов **хелпера** номер 6, то есть `bpf_trace_printk`. `exit` завершает программу.

Вот и вся логика: подготовить строку на стеке и вызвать хелпер печати. Читая `call <helper>`
(что делает), обращения к map (что читает/пишет) и условные переходы (фильтрация), можно быстро
понять назначение любой eBPF-программы.

## Шаг 3: как программа попадает в ядро

Пользовательский процесс вызывает `bpf(BPF_PROG_LOAD, ...)` — загрузка требует прав
`CAP_BPF`/`CAP_SYS_ADMIN` (или root). Затем программа **прикрепляется**: `BPF_LINK_CREATE`,
`perf_event_open`, `setsockopt(SO_ATTACH_BPF)`. Полезные объекты часто **pinned** в bpffs
(`/sys/fs/bpf/`) — это делает их персистентными между процессами.

```
$ bpftool prog load trace.o /sys/fs/bpf/trace_open
$ bpftool net attach kprobe do_sys_open pinned /sys/fs/bpf/trace_open
$ cat /sys/kernel/debug/tracing/trace_pipe
```

Мы прошли весь путь: компиляция → verifier → загрузка → прикрепление → исполнение. Анализ чужой
программы — обратный процесс: от загруженного байткода к исходной логике.

## Шаг 4: анализ чужой программы

В живом ядре программы и их данные смотрят через `bpftool`:

```
$ bpftool prog list                    # загруженные программы
$ bpftool prog dump xlated id <id>     # человекочитаемый байткод
$ bpftool prog dump jited  id <id>     # JIT-код (машинный)
$ bpftool map list                     # maps
$ bpftool map dump id <id>             # содержимое map (ключи/значения)
$ bpftool btf dump file /sys/kernel/btf/vmlinux | head
```

`xlated`-байткод читается легче JIT-кода — начинай с него. **BTF** помогает восстановить имена
полей структур. А в **maps** часто лежат скрытые данные: списки скрытых PID, путей, ключи.

## Шаг 5: eBPF-руткиты

Злонамеренный eBPF может:

- **Перехватывать syscalls** (`kprobe`/`fentry` на `sys_*`) и скрывать процессы/файлы, фильтруя
  результаты `getdents`/`readdir`.
- **Манипулировать** данными в ядре через map (подмена возвратов, скрытые списки).
- **Прятать себя** от `bpftool` — перехватом `bpf_prog_get_next_id`/`bpf_map_get_next_id`.
- **Обходить LSM** — перехватом LSM-хуков.

Анализ строится на сравнении с **эталоном** (чистой системой): ищем неожиданные BPF-программы и
maps, дампим их байткод и содержимое map, трассируем поведение через **bpftrace**:

```
$ bpftrace -e 'kprobe:do_sys_open { printf("%s %s\n", comm, str(arg1)); }'
$ bpftrace -l 'tracepoint:syscalls:*'
```

## Что мы теперь знаем

- **eBPF** — программы, исполняемые в ядре Linux; это байткод для RISC-подобной VM (`r0`–`r10`).
- **Verifier** гарантирует безопасность памяти, но не безопасность логики.
- Байткод читается как ассемблер: `call <helper>` — вызов ядерной функции, `r10` — стек.
- Программы загружают (`bpf()`) и прикрепляют к attach point; могут быть pinned в bpffs.
- **`bpftool`** перечисляет программы/maps, дампит байткод; **BTF** восстанавливает типы.
- **Maps** хранят состояние и часто — скрытые данные руткита.

## На что смотреть дальше

- Начинай с `xlated`-байткода, а не с JIT — логика читается легче.
- Не забывай про maps: скрытые PID и пути чаще всего именно там.
- Без эталонной системы легитимную программу не отличить от вредоносной — веди сравнение.
- Анализ eBPF требует root/CAP_BPF; в контейнерах часто отключён.
- Помни: verifier ограничивает возможности, но не мешает вредоносной **логике** (сокрытию).
- Пропустить attach point легко: программа «видна», а её эффект — в перехваченной функции.

## Квиз

Проверь себя.

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

## Куда дальше

Мы разобрали байткод ядра — самую низкоуровневую поверхность реверса. Дальше возьмём
гипервизор — слой виртуализации, где работают свои механизмы и свои артефакты. А пока главное
запомни: **eBPF — это читаемый байткод**, и связка `bpftool` + BTF + maps раскрывает любую
программу в ядре.

## Где пригодится

- **CTF:** Reversing (expert) — eBPF-задачи.
- **Linux kernel security:** анализ rootkit и скрытых программ.
- **Malware analysis:** eBPF-малварь и подозрительные программы в ядре.
- **Работа:** observability, kernel security, DFIR.
