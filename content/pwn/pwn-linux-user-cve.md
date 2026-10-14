---
id: pwn-linux-user-cve
title: "Модуль: Linux user-space CVE"
category: pwn
parent: pwn-cve-exploitation
difficulty: medium
order: 1
tags: [pwn, module, roadmap, cve]
prerequisites: [pwn-nday]
useful_for:
  - "Эксплуатация реальных CVE"
  - "Red team: повышение привилегий"
estimated_minutes: 10
summary: "Навигационный модуль: локальное повышение привилегий через ошибки в setuid-программах и загрузчике."
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Linux user-space CVE»: локальное повышение привилегий через ошибки в setuid-программах и загрузчике.

- `sudo` (Baron Samedit) — переполнение кучи в парсере аргументов.
- `pkexec` (PwnKit) — выход за границы массива `argv`.
- Ядро памяти (Dirty COW) — гонка в copy-on-write.
- `ld.so` (Looney Tunables) — переполнение в парсере `GLIBC_TUNABLES`.

## Почему такой порядок

User-space идёт первым: меньше переменных, воспроизводимость почти 100%, не нужен спрей кучи ядра.

## Что вы сможете после этапа

- Определять уязвимую версию по строке и патчу.
- Собирать минимальный PoC и читать результат обратно.

## Квиз

Проверь себя.

```quiz
- question: Что объединяет эти четыре CVE?
  options:
    - "Все требуют доступа к ядру"
    - "Все дают локальный root без эксплуатации памяти ядра"
    - "Все сетевые"
    - "Все в Windows"
  answer: 1
  explanation: Это user-space уязвимости локального повышения привилегий.
- question: Почему user-space разбирают раньше kernel?
  options:
    - "Он быстрее"
    - "Меньше переменных и выше воспроизводимость"
    - "Не нужен shell"
    - "Не нужен root"
  answer: 1
  explanation: User-space эксплойты проще отлаживать и стабилизировать.
- question: Что общего у Baron Samedit и Looney Tunables?
  options:
    - "Гонка"
    - "Загрузка подложенной библиотеки"
    - "Сетевой парсинг"
    - "SQL"
  answer: 1
  explanation: Оба в итоге заставляют привилегированный процесс загрузить нашу .so.
```

## Где пригодится

- Повышение привилегий на Linux-хостах.
- Разбор публичных PoC для setuid-программ.
- Аудит загрузчика и setuid-кода.
