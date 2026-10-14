---
id: mem-registry-hives
title: 'Кусты реестра из памяти: восстановление из дампа'
category: forensics
parent: forensics-memory-extra
difficulty: hard
order: 3
tags: [forensics, memory, registry, hives, volatility]
prerequisites: [forensics-memory-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как извлечь кусты реестра прямо из дампа памяти, когда файлы hives недоступны или повреждены.'
lab:
  kind: shell
  title: "Практика: куст реестра из памяти"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, mem_hives.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Кусты реестра можно вырезать прямо из дампа памяти (volatility/редактор)."
    - "Ключ ...\\CurrentVersion\\Run — автозапуск."
    - "`grep nto mem_hives.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Файлы реестра на диске повреждены или зашифрованы. Но реестр был загружен в память —
и его можно оттуда достать. Разберём.

## Наш пример: дамп Windows

## Шаг 1: реестр в памяти

Ядро держит загруженные кусты в памяти. Volatility умеет их находить:

```
$ vol.py -f mem.raw windows.registry.hivelist
Offset      FileFullPath
0x...  \SystemRoot\System32\Config\SOFTWARE
0x...  \??\C:\Users\Ivan\NTUSER.DAT
```

`hivelist` перечисляет загруженные кусты и их адреса в памяти.

## Шаг 2: дампим куст

```
$ vol.py -f mem.raw windows.registry.hivedump --hive-offset 0x... -o SOFTWARE.hive
```

Получаем настоящий файл-куст, который можно открыть RegRipper/Registry Explorer.

## Шаг 3: зачем

- файлы на диске зашифрованы (BitLocker без ключа) — память даёт реестр;
- куст повреждён — память даёт целую версию;
- нужно **актуальное** состояние (на момент снятия).

## Шаг 4: что искать

- автозапуск (`Run`);
- недавние изменения;
- подключённые USB;
- пароли/секреты (иногда в открытом виде);
- конфигурацию.

## Шаг 5: практика

- дампи **все** кусты (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER);
- анализируй RegRipper-плагинами;
- сопоставляй с дисковыми копиями (расхождения = активность).

## Что мы теперь знаем

- Загруженные кусты живут в памяти.
- `hivelist` находит их, `hivedump` извлекает.
- Память спасает, когда диск зашифрован/повреждён.
- Из кустов достаём автозапуск, USB, секреты.
- Дампь все кусты и сопоставляй.

## Если не сработало

- Hive не найден? Проверь профиль/версию.
- Куст повреждён в дампе? Пробуй другие адреса.
- Нужен разбор? Используй RegRipper.

## Квиз

Проверь себя.

```quiz
- question: Что делает windows.registry.hivelist?
  options:
    - 'удаляет кусты'
    - 'перечисляет загруженные кусты реестра в памяти'
    - 'шифрует'
    - 'сканирует сеть'
  answer: 1
  explanation: 'Плагин находит адреса загруженных hive в дампе.'
- question: Чем полезна память для реестра?
  options:
    - 'ничем'
    - 'даёт кусты, когда диск зашифрован/повреждён'
    - 'ускоряет'
    - 'шифрует'
  answer: 1
  explanation: 'Загруженные кусты живут в памяти независимо от диска.'
- question: Как извлечь куст целиком?
  options:
    - 'grep'
    - 'windows.registry.hivedump'
    - 'cp'
    - 'ping'
  answer: 1
  explanation: 'hivedump сохраняет куст в файл для разбора.'
- question: Что искать в кустах?
  options:
    - 'обои'
    - 'автозапуск, USB, секреты, конфигурацию'
    - 'сеть'
    - 'музыку'
  answer: 1
  explanation: 'Реестр хранит ключевые следы активности.'
```
