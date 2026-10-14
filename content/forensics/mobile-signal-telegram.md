---
id: mobile-signal-telegram
title: 'Signal и Telegram: защищённые мессенджеры'
category: forensics
parent: forensics-mobile-data
difficulty: hard
order: 2
tags: [forensics, mobile, signal, telegram, encryption]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Что можно извлечь из Signal и Telegram: локальные базы, шифрование, секретные чаты и ограничения.'
lab:
  kind: shell
  title: 'Практика: Signal и Telegram'
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

Signal и Telegram известны защитой. Что реально можно извлечь? Зависит от настроек и
платформы. Разберём.

## Наш пример: извлечение мессенджеров

## Шаг 1: Telegram

Telegram хранит данные:

- **облачные чаты** — на серверах Telegram (доступ через аккаунт);
- **локальный кэш** — на устройстве (`cache4.db`);
- **секретные чаты** — только на устройстве, с шифрованием.

```
$ find /data/data/org.telegram.messenger -name '*.db' | head
cache4.db
```

## Шаг 2: Signal

Signal хранит всё **локально** в зашифрованной базе:

```
$ ls /data/data/org.thoughtcrime.securesms/databases/
signal.db
```

База зашифрована; ключ привязан к устройству (в Android Keystore). Без разблокированного
устройства база не читается.

## Шаг 3: что доступно

- Telegram: облачные чаты (через аккаунт), локальный кэш;
- Signal: только на живом разблокированном устройстве;
- метаданные (с кем, когда) могут быть в уведомлениях/системных базах.

## Шаг 4: секретные чаты

- Telegram secret chats — E2E, только на устройстве;
- Signal всегда E2E;
- исчезающие сообщения могут быть уже удалены.

## Шаг 5: что искать

- локальные базы (если доступны);
- уведомления (текст);
- метаданные звонков;
- вложения;
- облачные данные Telegram.

## Что мы теперь знаем

- Telegram: облако + локальный кэш + секретные чаты.
- Signal: всё локально и зашифровано.
- Без разблокировки Signal не читается.
- Уведомления дают метаданные.
- Облако Telegram доступно через аккаунт.

## Если не сработало

- База зашифрована? Нужно живое устройство.
- Нужны чаты Telegram? Работай через аккаунт.
- Нужны метаданные? Смотри уведомления.

## Квиз

Проверь себя.

```quiz
- question: Где Signal хранит сообщения?
  options:
    - 'в облаке'
    - 'локально в зашифрованной базе'
    - 'в браузере'
    - 'в SIM'
  answer: 1
  explanation: 'Signal хранит всё локально с шифрованием.'
- question: Что доступно в Telegram через аккаунт?
  options:
    - 'ничего'
    - 'облачные чаты'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Облачные чаты Telegram синхронизируются с сервером.'
- question: Чем отличаются секретные чаты Telegram?
  options:
    - 'они быстрее'
    - 'они E2E и только на устройстве'
    - 'они публичные'
    - 'они в облаке'
  answer: 1
  explanation: 'Secret chats не синхронизируются с облаком.'
- question: Где искать метаданные при защите мессенджера?
  options:
    - 'в обои'
    - 'в уведомлениях и системных базах'
    - 'в шрифтах'
    - 'в музыке'
  answer: 1
  explanation: 'Уведомления фиксируют отправителя и текст.'
```
