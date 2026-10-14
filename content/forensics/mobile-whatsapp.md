---
id: mobile-whatsapp
title: 'WhatsApp-форензика: переписка и вложения'
category: forensics
parent: forensics-mobile-data
difficulty: medium
order: 1
tags: [forensics, mobile, whatsapp, msgstore, sqlite]
prerequisites: [forensics-mobile]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как разобрать данные WhatsApp: msgstore.db, вложения, ключи и ограничения шифрования.'
lab:
  kind: shell
  title: 'Практика: WhatsApp-форензика'
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

Нужна переписка WhatsApp. Она есть в извлечении — но структура специфична. Разберём.

## Наш пример: извлечение Android

## Шаг 1: где данные

```
$ find /data/data/com.whatsapp -name 'msgstore.db'
/data/data/com.whatsapp/databases/msgstore.db
```

`msgstore.db` — база сообщений. Рядом `wa.db` (контакты) и `media/` (вложения).

## Шаг 2: читаем сообщения

```
$ sqlite3 msgstore.db '.tables' | tr ' ' '\n' | grep -i message
message  message_add_on  ...
$ sqlite3 msgstore.db 'SELECT key_remote_jid, from_me, data, timestamp FROM message LIMIT 3;'
```

Поля: чат (`key_remote_jid`), направление, текст (`data`), время (unix-ms).

## Шаг 3: вложения

```
$ ls /data/data/com.whatsapp/files/Media/
```

Вложения названы хешами; связь с сообщением — через таблицы `message_media`.

## Шаг 4: шифрование

WhatsApp использует end-to-end шифрование в транспорте, но **на устройстве** база
расшифрована (иначе приложение не работало бы). Значит, при извлечении читается.

## Шаг 5: что искать

- текст переписки;
- медиа (фото/видео/документы);
- время и участников;
- удалённые сообщения (могут остаться);
- группы.

## Что мы теперь знаем

- WhatsApp хранит `msgstore.db` и `wa.db`.
- Сообщения в таблице message.
- Вложения в files/Media.
- На устройстве база расшифрована.
- Ищем текст, медиа, время, участников.

## Если не сработало

- База повреждена? Есть бэкапы `msgstore.db.crypt*`.
- Нужны удалённые? Смотри WAL и бэкапы.
- iOS? Путь другой (`ChatStorage.sqlite`).

## Квиз

Проверь себя.

```quiz
- question: Где WhatsApp хранит сообщения на Android?
  options:
    - 'в /etc'
    - 'в msgstore.db'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'msgstore.db — база сообщений WhatsApp.'
- question: Почему база на устройстве читается без ключа?
  options:
    - 'она не шифруется'
    - 'на устройстве она расшифрована для работы приложения'
    - 'её расшифровывает браузер'
    - 'она в облаке'
  answer: 1
  explanation: 'E2E шифрование защищает транспорт, а не локальную базу.'
- question: Где вложения WhatsApp?
  options:
    - 'в /etc'
    - 'в files/Media'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Медиа лежат в каталоге Media.'
- question: Что искать в базе?
  options:
    - 'обои'
    - 'текст, время, участников, медиа'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Таблица message содержит переписку и метаданные.'
```
