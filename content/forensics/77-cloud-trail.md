---
id: forensics-cloud-trail
title: "Аудит-логи облаков: CloudTrail, Azure, GCP"
category: forensics
parent: forensics-cloud
difficulty: hard
order: 1
tags: [cloudtrail, aws, azure, gcp, audit, forensics, iam]
prerequisites: [forensics-cloud]
useful_for:
  - "CTF Forensics категория"
  - "Cloud DFIR"
  - "Threat Hunting"
estimated_minutes: 55
summary: "Расследование инцидентов в облаке по аудит-логам: AWS CloudTrail, Azure Activity/Sign-in, GCP Audit Logs — атрибуция, персистентность, эксфильтрация."
---

## Вопрос, с которого всё начинается

Компания заметила странный счёт за облако и подозревает взлом аккаунта AWS. Но в облаке **нет диска**, который можно снять и разобрать: серверы — это чужие виртуальные машины, а следы живут только в журналах. Как понять, кто входил, что создавал и что выкачивал?

Ответ — в **аудит-логах**. Облако пишет **каждый** вызов своего API. Это и есть замена «диску». Разберём один инцидент по логу AWS CloudTrail.

## Наш пример: файл `trail.json`

**CloudTrail** — служба AWS, которая записывает все вызовы API. Логи складываются в S3 в виде сжатых JSON-файлов (по одному объекту на событие). Скачиваем и смотрим одну запись:

```bash
$ aws s3 cp s3://bucket/AWSLogs/.../CloudTrail/ . --recursive
$ gunzip -c trail.json.gz | jq '.Records[0]'
{
  "eventTime": "2025-10-06T14:20:11Z",
  "eventName": "ConsoleLogin",
  "userIdentity": { "arn": "arn:aws:iam::123:user/bob" },
  "sourceIPAddress": "203.0.113.7",
  "responseElements": { "ConsoleLogin": "Success" }
}
```

Разбираем поля. `eventName` — имя вызванного API-действия. `ConsoleLogin` означает **вход в веб-консоль** AWS. `userIdentity.arn` — кто вошёл (`bob`). `sourceIPAddress` — с какого адреса. `responseElements` показывает, что вход **удался**.

Обратите внимание: `jq` здесь — это утилита для выборки из JSON (формата, где данные хранятся как `ключ: значение`). Все дальнейшие шаги — это фильтры `jq` по нужным событиям.

## Шаг 1: находим подозрительный вход

Первый вопрос: вход был обычный или аномальный? Смотрим все входы и адреса:

```bash
$ gunzip -c trail.json.gz | jq -r '.Records[] | select(.eventName=="ConsoleLogin") | [.eventTime,.userIdentity.arn,.sourceIPAddress] | @tsv'
2025-10-06T14:20:11Z  arn:aws:iam::123:user/bob  203.0.113.7
```

Адрес `203.0.113.7` не похож на офисный диапазон компании. Это первая зацепка — **атрибуция**: атакующий вошёл извне.

## Шаг 2: ищем персистентность

Войдя, атакующий обычно создаёт себе долговременный доступ, чтобы не зависеть от пароля. В AWS для этого служит **access key** — постоянный программный ключ:

```bash
$ gunzip -c trail.json.gz | jq -r '.Records[] | select(.eventName=="CreateAccessKey") | [.eventTime,.userIdentity.arn,.responseElements.accessKey.accessKeyId] | @tsv'
2025-10-06T14:22:03Z  arn:aws:iam::123:user/bob  AKIAEXAMPLE123
```

Через две минуты после входа создан новый ключ `AKIAEXAMPLE123`. Это **персистентность**: даже если сменят пароль `bob`, ключ продолжит работать.

## Шаг 3: повышение прав

Дальше атакующий расширяет права. В AWS права задают **политики** — документы, описывающие, что разрешено. Прикрепление к пользователю широкой политики — эскалация:

```bash
$ gunzip -c trail.json.gz | jq -r '.Records[] | select(.eventName|test("AttachUserPolicy|PutUserPolicy")) | [.eventTime,.eventName,.requestParameters.policyArn] | @tsv'
2025-10-06T14:24:40Z  AttachUserPolicy  arn:aws:iam::aws:policy/AdministratorAccess
```

`AdministratorAccess` — политика полного администратора. Теперь у атакующего есть всё.

## Шаг 4: анти-форензика

Действие, которое часто выдаёт злоумышленника: попытка **отключить логирование**, чтобы скрыть следы. Само это событие — улика:

```bash
$ gunzip -c trail.json.gz | jq -r '.Records[] | select(.eventName|test("StopLogging|DeleteTrail")) | [.eventTime,.userIdentity.arn] | @tsv'
2025-10-06T14:26:11Z  arn:aws:iam::123:user/bob
```

`StopLogging` остановил бы запись новых событий. Это **анти-форензика** — попытка уничтожить доказательства. В расследовании такие события всегда проверяют в первую очередь.

## Шаг 5: эксфильтрация

Последний вопрос — что унесли. Данные в AWS лежат в **S3-бакетах** (облачное хранилище). Чтение объекта — `GetObject`, изменение политики бакета на публичную — `PutBucketPolicy`:

```bash
$ gunzip -c trail.json.gz | jq -r '.Records[] | select(.eventName|test("GetObject|PutBucketPolicy")) | [.eventTime,.eventName,.requestParameters.bucketName] | @tsv' | head
2025-10-06T14:30:02Z  PutBucketPolicy  corp-backups
2025-10-06T14:31:15Z  GetObject        corp-backups
```

Сначала бакет `corp-backups` сделали публичным, затем начали скачивать из него данные. Это **эксфильтрация** — вывод данных наружу.

## Шаг 6: собираем таймлайн

Отсортировав все подозрительные события по времени, получаем цельную картину:

```bash
$ gunzip -c trail.json.gz | jq -r '.Records[] | select(.eventName|test("ConsoleLogin|CreateAccessKey|AttachUserPolicy|StopLogging|PutBucketPolicy")) | [.eventTime,.eventName] | @tsv' | sort
2025-10-06T14:20:11Z  ConsoleLogin
2025-10-06T14:22:03Z  CreateAccessKey
2025-10-06T14:24:40Z  AttachUserPolicy
2025-10-06T14:26:11Z  StopLogging
2025-10-06T14:30:02Z  PutBucketPolicy
```

Цепочка: вход из необычного IP → создание ключа → повышение прав → попытка отключить логи → выгрузка данных. Такая последовательность — типовой сценарий компрометации облачного аккаунта.

## Если логи выглядят пустыми

Иногда цепочка обрывается. Три частые причины и что с ними делать:

- **Data access логи не включены.** CloudTrail по умолчанию пишет только события управления (создание, изменение). Чтение объектов S3 (`GetObject`) попадает в **data events**, которые надо включать заранее — задним числом их не появятся.
- **Retention истёк.** Логи хранятся ограниченное время; экспортировать их надо сразу, пока они есть.
- **`AssumeRole` скрывает источник.** Если атакующий действовал через смену роли, в `userIdentity` будет роль, а не исходный пользователь. Но в поле `sessionContext` виден, кто эту роль «взял», — по нему и восстанавливают цепочку.

И отдельно: **отсутствие записей — тоже улика**. Если `StopLogging` был выполнен, в логе просто зияет пропуск, и сам факт остановки фиксируется событием. В расследовании это первое, что проверяют.

## Полный разбор: от записи к цепочке атаки

Соберём расследование по `trail.json` в один сценарий.

| Время (UTC) | Событие | Трактовка |
|-------------|---------|-----------|
| 22:01 | `ConsoleLogin` (новый IP) | доступ |
| 22:05 | `CreateAccessKey` | персистентность |
| 22:07 | `AttachUserPolicy` (AdministratorAccess) | эскалация |
| 22:09 | `StopLogging` / `DeleteTrail` | антифорензика |
| 22:12 | `GetObject` (много, s3) | эксфильтрация |

1. **Находим вход.** `ConsoleLogin`/`AssumeRole` с аномального IP.
2. **Персистентность.** `CreateAccessKey`, `CreateLoginProfile`, новый пользователь/роль.
3. **Эскалация.** `AttachUserPolicy`, `PutRolePolicy`, изменение trust.
4. **Антифорензика.** `StopLogging`, `DeleteTrail`, `DeleteFlowLogs` — сами по себе тревожный сигнал.
5. **Эксфильтрация.** Массовые `GetObject`, снапшоты, `ModifySnapshotAttribute`.
6. **Таймлайн.** Сводим по `eventTime` и `sourceIPAddress`.

Ключ: даже когда ресурса уже нет, CloudTrail хранит «кто, что, когда».

## Шпаргалка по API-событиям

| Действие атакующего | API-события |
|---------------------|-------------|
| Персистентность | `CreateAccessKey`, `CreateLoginProfile` |
| Эскалация | `AttachUserPolicy`, `PutRolePolicy` |
| Антифорензика | `StopLogging`, `DeleteTrail` |
| Эксфильтрация | `GetObject`, `ModifySnapshotAttribute` |
| Криптомайнинг | `RunInstances` (крупные инстансы) |

## Частые вопросы

**Логи «пустые».** Возможно, trail выключен или пишет в другой регион/аккаунт — проверяйте все регионы и `CloudTrail` в каждом.

**Данные-события (S3 GetObject) не видны.** По умолчанию CloudTrail пишет только management events; data events нужно включать отдельно.

**Как найти атакующего по IP?** `sourceIPAddress` + user-agent; сопоставьте с историей входов.

**Логи удалены.** Если trail удалён, часть истории останется в S3-бакете с логами (если он с object-lock).

## Что мы теперь знаем

- CloudTrail пишет каждый вызов API: `eventName`, `userIdentity`, `sourceIPAddress`, `eventTime`.
- `ConsoleLogin` — вход; необычный IP даёт атрибуцию атакующего.
- `CreateAccessKey`/`CreateUser` — персистентность (постоянный доступ).
- `AttachUserPolicy`/`PutUserPolicy` — повышение прав.
- `StopLogging`/`DeleteTrail` — анти-форензика (и сама по себе улика).
- `GetObject`/`PutBucketPolicy` — эксфильтрация данных из S3.
- В Azure аналоги — Activity/Sign-in Logs, в GCP — Audit Logs.

## Квиз

Проверь себя.

```quiz
- question: "Какой лог AWS фиксирует все API-вызовы control plane?"
  options:
    - "VPC Flow Logs"
    - "CloudTrail"
    - "S3 access log"
    - "CloudWatch metrics"
  answer: 1
  explanation: "CloudTrail записывает каждый вызов API управления в JSON."
- question: "Какое событие CloudTrail указывает на персистентность?"
  options:
    - "ConsoleLogin"
    - "CreateAccessKey/CreateUser"
    - "GetObject"
    - "DescribeInstances"
  answer: 1
  explanation: "Создание ключа или пользователя даёт долговременный доступ."
- question: "Что означает событие StopLogging/DeleteTrail?"
  options:
    - "нормальная работа"
    - "отключение аудита — anti-forensics"
    - "эксфильтрация"
    - "вход в консоль"
  answer: 1
  explanation: "Попытка остановить логирование скрывает следы; само событие — улика."
- question: "Какой лог Azure фиксирует входы и MFA?"
  options:
    - "Activity Log"
    - "Sign-in Logs (Entra ID)"
    - "VNet Flow"
    - "Storage log"
  answer: 1
  explanation: "Azure AD (Entra ID) Sign-in Logs хранят входы, MFA и риск."
- question: "Что в GCP указывает на эскалацию прав?"
  options:
    - "SetIamPolicy с roles/owner"
    - "storage.objects.list"
    - "compute.instances.get"
    - "logging.read"
  answer: 0
  explanation: "Назначение роли owner через SetIamPolicy — повышение прав."
```

## Куда дальше

Мы восстановили облачный инцидент по логам. В следующем уроке (`forensics-chain-custody`) мы займёмся тем, что делает расследование юридически значимым — цепочкой хранения улик. А пока главное запомни: **в облаке вместо диска — аудит-логи API, и цепочка «вход → создание ключа → повышение прав → StopLogging → выгрузка» восстанавливается фильтрами `jq` по CloudTrail**.

## Где пригодится

- **CTF:** задачи с облачными аудит-логами.
- **Cloud DFIR:** расследование компрометации аккаунта.
- **Threat Hunting:** охота на создание ключей, эскалацию, эксфильтрацию.
- **SOC:** правила на события CloudTrail/Entra ID.
- **Судебная экспертиза:** атрибуция действий в облаке.
