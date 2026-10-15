---
id: pwn-methodology-env
title: "Методология: окружение и отладка (qemu-user, отладка heap)"
category: pwn
parent: pwn-methodology
difficulty: easy
order: 1
tags: [pwn, methodology, qemu, debugging, heap]
prerequisites: [pwn-methodology]
useful_for:
  - "CTF Pwn: бинари других архитектур"
  - "Эмуляция встроенных устройств"
estimated_minutes: 10
summary: "Второй методологический этап: запуск бинарей чужой архитектуры через qemu-user и отладка heap-состояния под эмуляцией."
lab:
  kind: shell
  title: "Практика: архитектура чужого бинаря"
  toolset: [core, readelf]
  workdir: /home/student/task
  files: [task.md, arm.o]
  check: "grep -q 'arrch64' answer.txt"
  hints:
    - "`readelf --file-header` показывает поле `Machine` — целевую архитектуру."
    - "Сравни `Class` (ELF32/ELF64) и `Machine`."
    - "`arm.o` собран кросс-компилятором под AArch64."
    - "Ответ — `AArch64` (нижний регистр): `arrch64`."
---
Второй методологический модуль — про окружение. Реальные pwn-задачи и CVE требуют запускать чужую архитектуру и отлаживать её. Здесь вы учитесь поднимать эмуляцию и отлаживать heap в нестандартной среде.

## Что покрывает этап

**pwn-qemu-user** — запуск бинарей другой архитектуры через qemu-user и проброс отладчика.
**pwn-heap-qemu-debug** — отладка heap-состояния под эмуляцией: символы glibc, heap-команды, поиск нужного chunk.

## Почему такой порядок

Сначала нужно научиться вообще запустить и отладить «чужой» бинарь (qemu-user), и только затем — разбирать в нём сложное heap-состояние. Это ровно тот порядок, в котором вы будете действовать на задаче с ARM/MIPS-бинарём.

## Что вы сможете после этапа

- Запускать ARM/MIPS/PPC-бинари под qemu-user и подключать gdb-multiarch.
- Находить и инспектировать chunk'и в эмуляции с помощью heap-команд.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf --file-header arm.o
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          184 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         4
  Section header string table index: 1
```

Подсказка из лаборатории: `readelf [--file-header|-s] <файл>`.

## Эмуляция: qemu-user и qemu-system

Для работы с бинарями чужой архитектуры (ARM, MIPS) нужна эмуляция. **qemu-user** запускает один бинарник другой архитектуры поверх ядра хоста: `qemu-aarch64 ./prog`. Это быстро и удобно для CTF, но не эмулирует ядро — системные вызовы транслируются. **qemu-system** эмулирует целую машину (ядро + периферия): медленнее, но нужен для kernel-эксплуатации и прошивок.

```bash
# запуск ARM-бинаря с подменой ld и библиотек
qemu-aarch64 -L /usr/aarch64-linux-gnu ./prog
# отладка через gdbstub
qemu-aarch64 -g 1234 -L /usr/aarch64-linux-gnu ./prog
gdb-multiarch ./prog -ex "target remote :1234"
```

Важно: при эмуляции нужно указать sysroot (`-L`), иначе не найдутся библиотеки; и учитывать, что некоторые антиэмуляционные проверки (счётчики, инструкции) могут отличаться от реального железа.

## Отладка heap: gdb + pwndbg

Отладка heap требует инструментов, которые понимают структуру аллокатора. **pwndbg** (или GEF) добавляет к gdb команды `heap`, `bins`, `vis_heap_chunks`, `tcachebins`, `fastbins`, `unsortedbin`. Это позволяет видеть состояние free-list и chunk-метаданных без ручного разбора памяти.

```text
pwndbg> heap                 # карта heap
pwndbg> bins                 # состояние всех bin
pwndbg> tcachebins           # tcache по размерам
pwndbg> vis_heap_chunks      # визуализация чанков
```

Типичный рабочий цикл: ставишь breakpoint после `malloc`/`free`, смотришь bins, проверяешь, куда попал чанк, подставляешь адрес в следующий `malloc`. Без этих команд отладка heap превращается в ручной `x/` по адресам, что медленно и ошибкоопасно. Дополнительно полезны `pahole` для раскладки структур и `malloc_info` для статистики.

## Рабочий процесс heap-эксплуатации

Порядок работы. Первое — определить аллокатор (glibc, jemalloc, mimalloc, tcache) по символам и поведению. Второе — понять версию glibc (защиты зависят от неё: safe-linking с 2.32, tcache key с 2.29). Третье — найти уязвимость (UAF, overflow, double-free) и примитив. Четвёртое — построить примитив чтения/записи: утечка адреса → подмена free-list → arbitrary alloc. Пятое — превратить в control flow (перезапись GOT, `__free_hook`, `__malloc_hook` — если версия старая, или vtable/структуры).

```bash
# узнать версию glibc
./prog  # в выводе "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3)..."
ldd --version
```

Ключевой навык — читать состояние heap в отладчике и сопоставлять его с ожидаемой логикой аллокатора. Именно это отличает «я понял эксплойт» от «я скопировал PoC».

## Квиз

```quiz
- question: "Зачем нужен qemu-user в pwn?"
  options:
    - "Для запуска бинарей чужой архитектуры на хосте"
    - "Для компиляции"
    - "Для шифрования"
    - "Для сканирования сети"
  answer: 0
  explanation: "qemu-user транслирует системные вызовы чужой архитектуры."
- question: "Почему отладка heap идёт после освоения qemu-user?"
  options:
    - "Отладка heap невозможна без символов"
    - "Сначала нужно уметь запустить и подключиться к бинарю другой архитектуры"
    - "Отладка heap быстрее"
    - "Они не связаны"
  answer: 1
  explanation: "Нельзя отлаживать то, что не запускается."
- question: "Какой отладчик подходит для мультиархитектурного анализа?"
  options:
    - "ollydbg"
    - "gdb-multiarch"
    - "windbg"
    - "x64dbg"
  answer: 1
  explanation: "gdb-multiarch понимает разные целевые архитектуры."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
