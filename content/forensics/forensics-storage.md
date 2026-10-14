---
id: forensics-storage
title: 'Объектные хранилища: версии, логи доступа и удалённые объекты'
category: forensics
parent: forensics-cloud-runtime
difficulty: medium
order: 4
tags: [cloud, s3, blob, gcs, versioning, access-logs, forensics]
prerequisites: [forensics-cloud-identity]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Cloud Security'
estimated_minutes: 45
summary: 'Как расследовать объектные хранилища (S3/Blob/GCS): версионирование, логи доступа, жизненный цикл, репликация и presigned-URL — и найти удалённые объекты.'
lab:
  kind: shell
  title: 'Практика: Объектные хранилища'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Файл удалили из облачного хранилища, а он был важен. Или наоборот: атакующий выкачал
данные из бакета. Диска нет — есть **объекты**. Как расследовать облачное хранилище?

## Наш пример: бакет с данными

Есть бакет `data-bucket` (S3). Смотрим его настройки:

```
$ aws s3api get-bucket-versioning --bucket data-bucket
{ "Status": "Enabled" }
```

**Версионирование включено** — это меняет всё: удалённый объект не исчезает, а получает
**delete-marker**, и старые версии остаются.

## Шаг 1: версии объекта

```
$ aws s3api list-object-versions --bucket data-bucket --prefix report/
{ "Versions": [ { "VersionId": "v2...", "IsLatest": true },
                { "VersionId": "v1...", "IsLatest": false } ] }
```

У объекта несколько версий. Даже после «удаления» можно скачать конкретную версию:

```
$ aws s3api get-object --bucket data-bucket --key report/secret.pdf \
    --version-id v1... out.pdf
```

Это спасает данные, которые «удалили».

## Шаг 2: логи доступа

У S3 есть **server access logs** и **data events** в CloudTrail. Они фиксируют, кто
обращался к объектам:

```
$ aws s3api get-bucket-logging --bucket data-bucket
{ "LoggingEnabled": { "TargetBucket": "logs-bucket" } }
```

В логах ищем аномалии: необычные IP, массовые `GetObject`, обращения извне организации.

## Шаг 3: жизненный цикл и репликация

Политики жизненного цикла могут **удалять** объекты через N дней, а репликация копирует
их в другой регион/аккаунт. Проверяем:

```
$ aws s3api get-bucket-lifecycle-configuration --bucket data-bucket
$ aws s3api get-bucket-replication --bucket data-bucket
```

Если данные реплицировались в чужой аккаунт — это может быть эксфильтрация под видом
«резервного копирования».

## Шаг 4: presigned-URL и публичный доступ

Объект можно отдать по **presigned URL** — временной ссылке с подписью. Утечка такой
ссылки даёт доступ без ключей. Проверяем политику бакета и блокировку публичного доступа:

```
$ aws s3api get-public-access-block --bucket data-bucket
$ aws s3api get-bucket-policy --bucket data-bucket
```

Публичный бакет — классическая причина утечки.

## Ловушки

- **Версионирование выключено**: удалённый объект не восстановить.
- **Логи не включены**: доступа к данным нет, только события управления.
- **Репликация**: объект может существовать в другом месте — проверяй и его.
- **Шифрование**: объект может быть зашифрован ключом KMS — без доступа к ключу не прочесть.

## Что мы теперь знаем

- Версионирование сохраняет удалённые объекты и старые версии.
- Логи доступа фиксируют, кто читал объекты.
- Жизненный цикл и репликация могут «удалять» и «копировать» данные.
- Presigned-URL и публичный доступ — каналы утечки.
- Шифрование и отсутствие логов ограничивают расследование.

## Квиз

Проверь себя.

```quiz
- question: Что даёт версионирование объекта?
  options:
    - 'сжатие'
    - 'сохранение удалённых объектов и старых версий'
    - 'шифрование'
    - 'ускорение'
  answer: 1
  explanation: 'Удаление добавляет delete-marker, но версии остаются.'
- question: Как восстановить удалённый объект в S3?
  options:
    - 'перезагрузить бакет'
    - 'get-object с конкретным version-id'
    - 'удалить бакет'
    - 'включить SMART'
  answer: 1
  explanation: 'list-object-versions + get-object --version-id возвращают версию.'
- question: Что фиксирует доступ к объектам?
  options:
    - 'SMART'
    - 'server access logs и CloudTrail data events'
    - 'BIOS'
    - 'консоль'
  answer: 1
  explanation: 'Эти логи показывают, кто читал объекты.'
- question: Что такое presigned URL?
  options:
    - 'постоянный публичный доступ'
    - 'временная подписанная ссылка на объект'
    - 'ключ шифрования'
    - 'резервная копия'
  answer: 1
  explanation: 'Утечка presigned URL даёт доступ без ключей на время действия.'
```

## Куда дальше

Мы закончили runtime-ветку облака. Дальше — **DevSecOps**: IaC, секреты и CI/CD. А пока
запомни: в объектном хранилище версии и логи доступа — твой главный источник улик.

## Где пригодится

- **Cloud Security** — расследование утечек из хранилищ.
- **DFIR / Incident Response** — восстановление удалённых объектов.
- **CTF Forensics** — задачи с S3/Blob/GCS.
