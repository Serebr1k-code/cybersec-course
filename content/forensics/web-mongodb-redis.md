---
id: web-mongodb-redis
title: 'MongoDB и Redis: NoSQL-хранилища в расследовании'
category: forensics
parent: forensics-web-apps
difficulty: medium
order: 4
tags: [forensics, web, mongodb, redis, nosql]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как расследовать компромисс MongoDB/Redis: открытый доступ, аудит, изменения данных и следы эксплуатации.'
lab:
  kind: shell
  title: 'Практика: MongoDB и Redis'
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

Приложение использует MongoDB/Redis, и что-то пошло не так. Оба часто выставляют
наружу без пароля. Разберём, где следы.

## Наш пример: Redis

## Шаг 1: открытый доступ

Redis без пароля:

```
$ redis-cli -h target INFO server | head
redis_version:6.2.0
```

Ответ без `AUTH` — открытый инстанс. MongoDB проверяется `mongosh --host target`.

## Шаг 2: Redis-эксплуатация

Redis известен записью файлов (RCE через SSH-ключ/cron):

```
$ redis-cli -h target CONFIG GET dir
dir /var/spool/cron
```

`dir` в `/var/spool/cron` + `SET`/`SAVE` = запись cron-файла → RCE. В логах Redis:

```
$ grep -i 'CONFIG\|SAVE\|BGSAVE' /var/log/redis/redis-server.log
```

## Шаг 3: MongoDB

MongoDB без авторизации даёт доступ к БД:

```
$ mongosh --host target
> show dbs
admin  appdb
> db.appdb.users.find()
```

Утечка пользователей/паролей — типичный итог.

## Шаг 4: следы изменений

- новые БД/коллекции (загруженные данные);
- удаление коллекций (anti-forensics);
- `oplog` (журнал операций) MongoDB — история изменений;
- RDB/AOF-файлы Redis — история данных.

## Шаг 5: что искать

- доступ с внешних IP;
- `CONFIG`/`SAVE` в Redis (запись файлов);
- новые пользователи/БД;
- удалённые коллекции;
- oplog/AOF как источник истории.

## Что мы теперь знаем

- Redis/Mongo часто без пароля.
- Redis CONFIG+SAVE = запись файлов (RCE).
- Mongo без авторизации даёт доступ к данным.
- oplog/AOF — история изменений.
- Ищем внешний доступ и изменения.

## Если не сработало

- Пароль есть? Ищи его в конфиге приложения.
- Логи выключены? Смотри сеть/аудит ОС.
- Данные удалены? Восстанавливай из RDB/oplog.

## Квиз

Проверь себя.

```quiz
- question: Как Redis позволяет выполнить код?
  options:
    - 'через CSS'
    - 'записью файла (CONFIG dir + SAVE) в cron/SSH'
    - 'через обои'
    - 'никак'
  answer: 1
  explanation: 'Redis умеет сохранять данные в файл по указанному пути.'
- question: Что даёт MongoDB без авторизации?
  options:
    - 'ничего'
    - 'полный доступ к базам данных'
    - 'шифрование'
    - 'ускорение'
  answer: 1
  explanation: 'Открытый Mongo отдаёт все БД без пароля.'
- question: Что такое oplog MongoDB?
  options:
    - 'обои'
    - 'журнал операций (история изменений)'
    - 'сеть'
    - 'шелл'
  answer: 1
  explanation: 'Oplog хранит операции репликации — историю изменений.'
- question: Где история данных Redis?
  options:
    - 'в RDB/AOF-файлах'
    - 'в реестре'
    - 'в браузере'
    - 'в шрифтах'
  answer: 0
  explanation: 'Redis персистит данные в RDB-снапшотах и AOF-журнале.'
```
