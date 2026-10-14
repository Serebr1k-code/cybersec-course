---
id: mem-macos
title: 'Память macOS: сбор и анализ'
category: forensics
parent: forensics-memory-extra
difficulty: hard
order: 1
tags: [forensics, memory, macos, volatility, unified-memory]
prerequisites: [forensics-memory-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Особенности памяти macOS: унифицированная память, сжатие, инструменты сбора и что искать в дампе.'
lab:
  kind: shell
  title: 'Практика: Память macOS'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Нужно проанализировать память Mac. Но macOS отличается: сжатие страниц, унифицированная
память на Apple Silicon, ограниченная поддержка Volatility. Разберём.

## Наш пример: дамп Mac

## Шаг 1: особенности

- **compressed memory** — неактивные страницы сжимаются, а не пишутся в swap;
- **UMA** (Apple Silicon) — общая память CPU/GPU;
- **шифрование swap** — выгруженные страницы зашифрованы.

Это меняет то, что вообще попадает в дамп.

## Шаг 2: сбор

```
$ sudo osxpmem -o mac.raw
```

Или специализированные средства (в т.ч. коммерческие). На Apple Silicon вариантов
меньше.

## Шаг 3: анализ

Volatility для macOS ограничена. Базовый подход:

- `strings` + `grep` по IOC;
- плагины профилей macOS (если есть);
- специализированные парсеры.

```
$ strings mac.raw | grep -iE 'http://|https://' | head
```

## Шаг 4: что искать

- **процессы** и командные строки;
- **открытые файлы/сокеты**;
- **пароли и ключи**;
- **расшифрованные данные**;
- **код в памяти** (fileless).

## Шаг 5: практика

- фиксируй версию ОС (влияет на структуры);
- снимай память до выключения;
- считай хеш;
- комбинируй с unified log.

## Что мы теперь знаем

- macOS сжимает память и шифрует swap.
- Apple Silicon использует унифицированную память.
- Сбор — osxpmem/спец. средства.
- Volatility ограничена — используй strings/парсеры.
- Ищем процессы, ключи, fileless-код.

## Если не сработало

- Apple Silicon? Используй живые средства.
- Нет профиля? Работай строками.
- Нужен порядок? Фиксируй версию ОС.

## Квиз

Проверь себя.

```quiz
- question: Чем macOS-память отличается от Windows?
  options:
    - 'ничем'
    - 'сжатие страниц и шифрование swap'
    - 'она меньше'
    - 'она в облаке'
  answer: 1
  explanation: 'macOS сжимает неактивные страницы и шифрует swap.'
- question: Какой инструмент снимает память macOS?
  options:
    - 'ls'
    - 'osxpmem'
    - 'grep'
    - 'nmap'
  answer: 1
  explanation: 'osxpmem — средство сбора дампа памяти macOS.'
- question: Что делать, если Volatility не поддерживает профиль?
  options:
    - 'сдаться'
    - 'использовать strings и спец. парсеры'
    - 'перезагрузиться'
    - 'удалить дамп'
  answer: 1
  explanation: 'Базовый анализ возможен по строкам и IOC.'
- question: Почему важно фиксировать версию ОС?
  options:
    - 'для отчёта'
    - 'структуры памяти зависят от версии'
    - 'для сети'
    - 'неважно'
  answer: 1
  explanation: 'Профили и структуры ядра привязаны к версии.'
```
