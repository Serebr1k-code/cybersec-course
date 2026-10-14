---
id: tool-regripper
title: 'RegRipper: разбор реестра Windows'
category: forensics
parent: forensics-tools-utility
difficulty: medium
order: 4
tags: [forensics, tools, regripper, registry, windows]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как RegRipper извлекает артефакты из кустов реестра: плагины, автозапуск, историю и конфигурацию.'
lab:
  kind: shell
  title: "Практика: плагин RegRipper"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, regripper_report.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "RegRipper запускается как `rip.pl -r <hive> -p run`."
    - "Плагин `run` печатает значения ключа автозапуска Run."
    - "`grep nto regripper_report.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Реестр Windows — это база данных конфигурации и следов активности. Читать его вручную
(бинарный формат) невозможно. **RegRipper** применяет **плагины** и выдаёт готовые
артефакты. Разберём.

## Наш пример: куст NTUSER.DAT

## Шаг 1: кусты реестра

Реестр — это набор «кустов» (hives):

- `SYSTEM` — конфигурация системы;
- `SOFTWARE` — установленное ПО;
- `SAM` — пользователи;
- `SECURITY` — политики;
- `NTUSER.DAT` — настройки пользователя.

## Шаг 2: запуск плагина

```
$ rip.pl -r NTUSER.DAT -p userassist
```

`userassist` — один из плагинов. Он показывает, какие программы запускал пользователь,
сколько раз и когда.

## Шаг 3: полезные плагины

- `run` — ключи автозапуска (`Run`/`RunOnce`);
- `shellbags` — какие папки открывали;
- `usb` — подключённые USB-устройства;
- `recentdocs` — недавние документы;
- `typedurls` — введённые URL.

```
$ rip.pl -r SYSTEM -p usb
```

## Шаг 4: массовый прогон

RegRipper умеет прогонять **все** плагины:

```
$ rip.pl -r NTUSER.DAT -a > all.txt
```

Или использовать `rip.pl` с `-l` для списка плагинов.

## Шаг 5: что искать

- **автозапуск** (persistence);
- **запущенные программы** (UserAssist, Prefetch-связка);
- **USB-история**;
- **недавние файлы**;
- **конфигурация** (RDP, сеть).

## Что мы теперь знаем

- Реестр — набор кустов (SYSTEM, SOFTWARE, SAM, NTUSER.DAT).
- RegRipper применяет плагины к кустам.
- Плагины: run, shellbags, usb, userassist, recentdocs.
- Можно прогнать все плагины сразу.
- Даёт persistence, запуски, USB, недавние файлы.

## Если не сработало

- Куст повреждён? Используй восстановление (reg-recovery).
- Нужен плагин? Проверь список (`-l`).
- Нужен другой артефакт? Пиши свой плагин.

## Квиз

Проверь себя.

```quiz
- question: Что такое куст реестра?
  options:
    - 'файл журнала'
    - 'hive — набор ключей (SYSTEM, SAM, NTUSER.DAT)'
    - 'сеть'
    - 'образ'
  answer: 1
  explanation: 'Реестр хранится в нескольких hive-файлах.'
- question: Что показывает плагин userassist?
  options:
    - 'пароли'
    - 'запущенные программы, счётчик и время'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'UserAssist хранит запуски программ с GUI.'
- question: Какой плагин даёт автозапуск?
  options:
    - 'usb'
    - 'run'
    - 'shellbags'
    - 'recentdocs'
  answer: 1
  explanation: 'Плагин run читает ключи Run/RunOnce.'
- question: Как прогнать все плагины сразу?
  options:
    - 'rip.pl -a'
    - 'rip.pl -r hive -a'
    - 'rip.pl -l'
    - 'rip.pl -h'
  answer: 1
  explanation: 'Флаг -a запускает все плагины на кусте.'
```
