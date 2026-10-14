---
id: pwn-mitigations-bypass
title: "Обход защит: ret2dlresolve, canary, PIE, CET/CFI"
category: pwn
parent: pwn-mitigations
difficulty: hard
order: 1
tags: [pwn, mitigations, ret2dlresolve, canary, pie, cet]
prerequisites: [pwn-mitigations]
useful_for:
  - "CTF Pwn: бинари с включёнными защитами"
  - "Обход современных митигаций"
estimated_minutes: 10
summary: "Модуль обхода защит: ret2dlresolve, обход canary, PIE и аппаратного CET/CFI."
lab:
  kind: shell
  title: "Практика: триаж защит (RELRO/PIE/canary)"
  toolset: [core, readelf]
  workdir: /home/student/task
  files: [task.md, a, b, c]
  check: "grep -q 'fullrelro=a' answer.txt"
  hints:
    - "FULL RELRO = сегмент GNU_RELRO + `BIND_NOW` в `FLAGS`."
    - "PIE = `Type: DYN` в ELF-заголовке."
    - "Сравни `readelf -d a`, `readelf -d b`, `readelf -d c`."
    - "`BIND_NOW` в `FLAGS` есть только у одного бинаря — это и есть FULL RELRO."
---
Этот модуль собирает техники обхода четырёх защит, которые чаще всего стоят на пути эксплуататора: отсутствия символов, стека-канарейки, рандомизации адресов и аппаратной защиты потока управления.

## Что покрывает этап

**pwn-ret2dlresolve** — разрешение символов в рантайме без известного адреса libc.
**pwn-canary-bypass** — обход stack canary: утечка, брутфорс, перезапись через другие примитивы.
**pwn-pie-bypass** — обход PIE/ASLR: утечки адресов и относительная адресация.
**pwn-cet-cfi** — обход CET/CFI: аппаратный контроль потока управления и его ограничения.

## Почему такой порядок

ret2dlresolve идёт первым: он решает задачу вызова функций без libc. Затем обход canary — самая частая защита стека. PIE/ASLR — следующий уровень, требующий утечки. CET/CFI замыкает модуль как новейшая аппаратная защита, ограничивающая сам ROP.

## Что вы сможете после этапа

- Вызывать функции через ret2dlresolve без известного адреса libc.
- Обходить stack canary разными способами.
- Обходить PIE/ASLR через утечки и относительные адреса.
- Понимать ограничения CET/CFI и приёмы их обхода.

## Инструмент: readelf — разбор ELF

`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и включённые защиты. С него начинается любой разбор нативного бинарника.

Ключи, которые пригодятся:
* `readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;
* `readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);
* `readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);
* `readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.

### Рабочий пример (как в лаборатории)

```
$ readelf -d a

Dynamic section at offset 0x2dc8 contains 27 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x1000
 0x000000000000000d (FINI)               0x1160
 0x0000000000000019 (INIT_ARRAY)         0x3db8
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x3dc0
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x390
 0x0000000000000005 (STRTAB)             0x458
 0x0000000000000006 (SYMTAB)             0x3b0
 0x000000000000000a (STRSZ)              141 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x3fb8
 0x0000000000000002 (PLTRELSZ)           24 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x5e8
 0x0000000000000007 (RELA)               0x528
 0x0000000000000008 (RELASZ)             192 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 0x000000006ffffffe (VERNEED)            0x4f8
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x4e6
 0x000000006ffffff9 (RELACOUNT)          3
 0x0000000000000000 (NULL)               0x0
```

Подсказка из лаборатории: `readelf [-d|-s|--file-header] <файл>`.

## Квиз

```quiz
- question: "Какую задачу решает ret2dlresolve?"
  options:
    - "Вызов функций без известного адреса libc"
    - "Шифрование стека"
    - "Ускорение программы"
    - "Отключение NX"
  answer: 0
  explanation: "ret2dlresolve заставляет динамический линкер разрешить символ."
- question: "Какой защите стека посвящён отдельный урок модуля?"
  options:
    - "NX"
    - "stack canary"
    - "ASLR"
    - "RELRO"
  answer: 1
  explanation: "Canary проверяется при возврате из функции."
- question: "Почему CET/CFI замыкает модуль?"
  options:
    - "Это новейшая аппаратная защита, ограничивающая ROP"
    - "Она проще canary"
    - "Она не связана с потоком управления"
    - "Она работает только в userspace"
  answer: 0
  explanation: "CET/CFI контролирует легитимность переходов."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
