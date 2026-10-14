---
id: mobile-android-notifications
title: 'Android-уведомления: журнал и тексты'
category: forensics
parent: forensics-mobile-android-deep
difficulty: medium
order: 2
tags: [forensics, mobile, android, notifications, logs]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как Android хранит уведомления и как извлечь их тексты, источники и время.'
lab:
  kind: shell
  title: "Практика: журнал уведомлений Android"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, android_notifications.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Android хранит уведомления в системной БД с пакетом-источником."
    - "Пакет com.unknown.* с OTP — кража кодов."
    - "`grep nto android_notifications.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Что приходило на телефон: сообщения, коды, оповещения? Android логирует уведомления.
Разберём, где и как их читать.

## Наш пример: извлечение Android

## Шаг 1: notification log

Современный Android хранит историю уведомлений:

```
$ find /data -iname 'notification*'
/data/system/users/0/notification_log.db
```

База `notification_log.db` — история отображённых уведомлений.

## Шаг 2: читаем

```
$ sqlite3 notification_log.db '.tables'
$ sqlite3 notification_log.db 'SELECT * FROM notification LIMIT 3;'
```

Текст уведомления может лежать в сжатом/бинарном виде — извлекается парсерами (ALEAPP).

## Шаг 3: источники

Каждое уведомление привязано к **пакету** (приложению):

```
pkg: com.whatsapp
```

Так понимаешь, откуда пришло.

## Шаг 4: что искать

- OTP-коды (двухфакторка);
- имена отправителей;
- тексты сообщений;
- банковские оповещения;
- ошибки приложений.

## Шаг 5: сопоставление

Уведомления дублируют данные приложений. Если база мессенджера удалена, уведомления
могут сохранить текст.

## Что мы теперь знаем

- Android хранит `notification_log.db`.
- Уведомления привязаны к пакету.
- Тексты извлекаются парсерами.
- Могут сохранить OTP и сообщения.
- Дублируют данные приложений.

## Если не сработало

- База пуста? Смотри кэши приложений.
- Текст закодирован? Используй ALEAPP.
- Нет доступа? Нужен root/извлечение.

## Квиз

Проверь себя.

```quiz
- question: Где Android хранит историю уведомлений?
  options:
    - 'в /etc'
    - 'в notification_log.db'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Системная база notification_log.db ведёт журнал.'
- question: К чему привязано уведомление?
  options:
    - 'к обои'
    - 'к пакету приложения'
    - 'к сети'
    - 'к шрифту'
  answer: 1
  explanation: 'Пакет указывает источник уведомления.'
- question: Чем полезны уведомления при удалённых сообщениях?
  options:
    - 'ничем'
    - 'могут сохранить текст/OTP'
    - 'шифруют'
    - 'сеть'
  answer: 1
  explanation: 'Журнал уведомлений хранит отображаемый текст.'
- question: Как разобрать уведомления?
  options:
    - 'grep'
    - 'парсерами (ALEAPP)'
    - 'ping'
    - 'ssh'
  answer: 1
  explanation: 'Тексты часто в спец-формате; нужен парсер.'
```
