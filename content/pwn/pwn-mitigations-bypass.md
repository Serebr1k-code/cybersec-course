---
id: pwn-mitigations-bypass
title: "Обход защит: ret2dlresolve, canary, PIE, CET/CFI"
category: pwn
parent: pwn-mitigations
difficulty: hard
order: 3
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
