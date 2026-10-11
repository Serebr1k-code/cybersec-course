---
id: pwn-io-file-internals
title: "Модуль: внутренности _IO_FILE (wfile, vtable check, утечки)"
category: pwn
parent: pwn-fsop
difficulty: hard
order: 1
tags: [fsop, io-file, wfile, vtable, leak, roadmap]
prerequisites: [pwn-fsop]
useful_for:
  - "CTF Pwn категория"
  - "Modern glibc exploitation"
  - "Vulnerability research"
estimated_minutes: 12
summary: "Отдельный этап: глубокий разбор _IO_FILE — атака _IO_wfile, обход проверки vtable и извлечение утечек через потоки."
---

FSOP (File-Stream-Oriented Programming) строится на структуре `_IO_FILE_plus` и её vtable. Базовые приёмы (`_IO_2_1_stdout_`, `_IO_str_overflow`) уже разобраны в ветке `pwn-fsop`, но modern glibc усилил проверки: vtable должен лежать в секции `__libc_IO_vtables`, а wide-ориентированные потоки (`_IO_wfile_jumps`) открывают новые цели. Этот модуль — про то, как FSOP выживает в glibc 2.24+ и как из потоков достать утечки.

## Что покрывает этот модуль

- **_IO_wfile** — атака на широкие (wide) потоки, `_IO_wfile_jumps`, `wide_data`.
- **vtable check** — проверка `IO_validate_vtable` и обход через валидные vtable-таблицы libc.
- **Утечки через IO** — `_IO_2_1_stdout_` как источник адресов libc и heap.
- **Связки** — комбинирование FSOP с tcache- и unsorted-bin-примитивами.

## Рекомендуемый порядок изучения

1. `pwn-io-wfile` — атака `_IO_wfile` и wide-потоки в glibc 2.24+.
2. `pwn-vtable-check-bypass` — проверка vtable и обход через `__libc_IO_vtables`.
3. `pwn-io-leak` — извлечение утечек libc/heap через стандартные потоки.

Материал продолжает `pwn-fsop` (`pwn-io-stdout`, `pwn-io-str-overflow`) и связан с `pwn-exit-handlers`; пригодится при отсутствии обычных утечек.

## Что вы будете уметь

- Объяснять layout `_IO_FILE_plus` и валидацию vtable в разных glibc.
- Строить FSOP-цепочку через `_IO_wfile_jumps`.
- Обходить `IO_validate_vtable`, используя валидные таблицы.
- Получать libc/heap-утечку через потоки без явного `printf`.

## Квиз

```quiz
- question: "Что проверяет IO_validate_vtable в glibc 2.24+?"
  options:
    - "Что vtable указывает в секцию __libc_IO_vtables"
    - "Что файл открыт"
    - "Что буфер пуст"
    - "Что поток закрыт"
  answer: 0
  explanation: "Проверка не даёт подсунуть vtable из контролируемой памяти."
- question: "Почему _IO_wfile_jumps интересен для FSOP?"
  options:
    - "Это валидная таблица в libc, которую можно использовать в цепочке"
    - "Он отключает проверки"
    - "Он хранит пароли"
    - "Он отвечает за сеть"
  answer: 0
  explanation: "Валидная vtable обходит проверку и даёт нужный вызов."
- question: "Как получить утечку libc через _IO_2_1_stdout_?"
  options:
    - "Прочитать поле, содержащее указатель на libc, через вывод потока"
    - "Перезагрузить систему"
    - "Вызвать fork"
    - "Отключить ASLR"
  answer: 0
  explanation: "Подменив указатели буфера, можно заставить поток вывести адрес libc."
```

## Где пригодится

- **CTF:** задачи на FSOP и утечки в modern glibc.
- **Bug bounty:** баги в потоках ввода-вывода.
- **Пентест:** обход hardening glibc в реальных сервисах.
- **Работа:** понимание внутренностей libc I/O.
