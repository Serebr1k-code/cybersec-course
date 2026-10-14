---
id: spec-smarttv
title: 'Smart TV в форензике: что хранит умный телевизор'
category: forensics
parent: forensics-embedded-devices
difficulty: medium
order: 4
tags: [forensics, smarttv, embedded, apps, logs]
prerequisites: [forensics-special-devices]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Какие данные хранит Smart TV: приложения, историю, аккаунты, микрофон и следы сети.'
lab:
  kind: shell
  title: "Практика: приложения Smart TV"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, smarttv_apps.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Приложения Smart TV обычно ставятся из магазина и подписаны."
    - "source=sideload + signed=no — установлено вручную."
    - "`grep nto smarttv_apps.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Телевизор в комнате — это компьютер на Linux/Android TV с приложениями, аккаунтами и
иногда микрофоном. Что он может хранить и как это извлечь? Разберём.

## Наш пример: Android TV

## Шаг 1: платформа

Большинство Smart TV — на **Android TV**, **Tizen**, **webOS** или **Roku OS**. Android
TV ближе всего к телефону: APK-приложения, SQLite, логи.

```
$ adb connect 10.10.50.20:5555
$ adb shell pm list packages | head
```

`adb` — мост отладки Android. Если включён — даёт доступ к файловой системе.

## Шаг 2: что хранится

- **история приложений** (что запускали);
- **аккаунты** (Google, Netflix, YouTube);
- **просмотры** (что смотрели);
- **голосовые запросы** (если есть микрофон);
- **сетевые настройки**.

## Шаг 3: где искать

```
$ adb shell find /data/data -name '*.db' | head
```

SQLite-базы приложений, логи, кэш. Плюс `/sdcard` для пользовательских данных.

## Шаг 4: сетевые следы

Телевизор постоянно общается с серверами производителя и приложений. Дамп трафика
показывает:

- какие домены (телеметрия, реклама);
- какие аккаунты;
- что передаётся (иногда — голос).

## Шаг 5: физический доступ

Если ADB выключен, снимают флеш-чип программатором или ищут UART-порт на плате
(отладочный консольный порт). Через UART часто доступен shell.

## Что мы теперь знаем

- Smart TV — Linux/Android-устройство.
- ADB даёт доступ к приложениям и базам.
- Хранятся история, аккаунты, просмотры, голос.
- Сеть показывает телеметрию и аккаунты.
- UART/программатор — путь при закрытом доступе.

## Если не сработало

- ADB закрыт? Ищи UART и снимай флеш.
- Шифрование? Нужен ключ устройства.
- Нужны аккаунты? Смотри облачные сервисы.

## Квиз

Проверь себя.

```quiz
- question: На какой ОС обычно Android TV?
  options:
    - 'Windows'
    - 'Android/Linux'
    - 'macOS'
    - 'iOS'
  answer: 1
  explanation: 'Android TV основан на Android (Linux).'
- question: Что даёт adb connect?
  options:
    - 'обновление ТВ'
    - 'доступ к файловой системе и приложениям'
    - 'шифрование'
    - 'сканирование сети'
  answer: 1
  explanation: 'ADB — мост отладки Android для доступа к устройству.'
- question: Что может хранить Smart TV с микрофоном?
  options:
    - 'только каналы'
    - 'голосовые запросы'
    - 'обои'
    - 'драйверы'
  answer: 1
  explanation: 'Голосовое управление сохраняет запросы локально/в облаке.'
- question: Что делать, если ADB выключен?
  options:
    - 'ничего'
    - 'искать UART/снимать флеш программатором'
    - 'перезагрузить'
    - 'отключить сеть'
  answer: 1
  explanation: 'Физический доступ (UART/чип) обходит закрытый ADB.'
```
