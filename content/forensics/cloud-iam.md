---
id: cloud-iam
title: 'Cloud IAM: форензика идентичности в AWS/GCP/Azure'
category: forensics
parent: forensics-cloud-identity
difficulty: hard
order: 4
tags: [cloud, iam, cloudtrail, audit-log, assume-role, access-key, forensics]
prerequisites: [forensics-cloud-multi, forensics-cloud-trail]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Cloud security'
estimated_minutes: 55
summary: 'Как журналы идентичности AWS CloudTrail, GCP Audit Logs и Azure Activity Log показывают эскалацию прав, создание ключей, assume-role и доступ к секретам, и как строить из них картину компрометации облачного аккаунта.'
lab:
  kind: shell
  title: 'Практика: разбор CloudTrail'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, cloudtrail.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Начни с `ls -la cloudtrail.log` и `head cloudtrail.log`.'
    - 'Поля: eventName, userIdentity, sourceIPAddress, eventTime.'
    - 'Ищи CreateAccessKey, AttachUserPolicy, AssumeRole, GetSecretValue.'
    - 'Флаг лежит в записи журнала: `grep nto cloudtrail.log > found.txt`.'
---

## Вопрос, с которого всё начинается

В облачном аккаунте вырос счёт, а в логах — странные вызовы. Кто-то получил доступ и,
похоже, закрепился: создал ключ, выдал себе права, потянулся к секретам. Облако не имеет
диска — но у него есть **журнал идентичности**, где видно каждое такое действие.

## Что такое журналы идентичности облака

У каждого крупного провайдера есть журнал действий:

- **AWS CloudTrail** — все API-вызовы в аккаунте: кто (`userIdentity`), что (`eventName`),
  откуда (`sourceIPAddress`), когда (`eventTime`);
- **GCP Cloud Audit Logs** — admin activity, data access, system events;
- **Azure Activity Log / Entra audit logs** — операции управления и входы.

Именно эти журналы показывают **эскалацию прав и закрепление** в облаке.

## Наш пример: CloudTrail

```
$ ls -la
-rw-r--r-- 1 student student 8192 cloudtrail.log
$ head -n 2 cloudtrail.log
{"eventTime":"2026-03-11T02:14:09Z","eventName":"ConsoleLogin","userIdentity":{"type":"IAMUser","userName":"dev"},"sourceIPAddress":"203.0.113.9"}
{"eventTime":"2026-03-11T02:15:44Z","eventName":"CreateAccessKey","userIdentity":{"type":"IAMUser","userName":"dev"},"sourceIPAddress":"203.0.113.9"}
```

Второе событие — **создание access key**. Ключ — постоянный секрет, который переживает
смену пароля. Смотрим дальше:

```
$ grep -Ei 'CreateAccessKey|AttachUserPolicy|AssumeRole|GetSecret|nto' cloudtrail.log
{"eventName":"CreateAccessKey","userIdentity":{"userName":"dev"}}
{"eventName":"AttachUserPolicy","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}
{"eventName":"GetSecretValue","requestParameters":{"secretId":"prod/db"}}
{"EVIDENCE":"nto{cloud1am_cr3at3acc3ssk3y}"}
```

Нарратив атаки готов: вход → **создание ключа** → **выдача себе админ-политики** →
**чтение секрета** базы. Это классическая цепочка закрепления и эскалации.

## Шаг 1: события, за которыми следить

| eventName (AWS) | Что означает | Почему подозрительно |
|-----------------|--------------|----------------------|
| `CreateAccessKey` | создан ключ | постоянный доступ |
| `CreateUser` / `CreateLoginProfile` | новый пользователь | backdoor-учётка |
| `AttachUserPolicy` / `PutUserPolicy` | выдача прав | эскалация |
| `AssumeRole` | смена роли | переход к другой идентичности |
| `GetSecretValue` | чтение секрета | доступ к паролям |
| `StopLogging` | выключен CloudTrail | сокрытие следов |

Пара `CreateAccessKey` + `AttachUserPolicy` почти всегда означает компрометацию.

## Шаг 2: assume-role и цепочки ролей

**AssumeRole** — переход из одной идентичности в другую. Злоумышленники используют
**role chaining**: цепочку assume-role, чтобы добраться до привилегированной роли. В логах
это видно как последовательность `AssumeRole` с разными `roleArn`, часто с одного IP за
минуты. Смотри поле `userIdentity.sessionContext` — там указан источник роли.

## Шаг 3: GCP и Azure — то же, другие имена

- **GCP**: `SetIamPolicy`, `CreateServiceAccountKey`, `actAs`, `GetSecret` в Cloud Audit
  Logs; поле `protoPayload.authenticationInfo.principalEmail`.
- **Azure**: `Microsoft.Authorization/roleAssignments/write` в Activity Log; входы — в
  Entra ID sign-in logs; создание app registration/secret — в audit logs.

Общий принцип один: **ищи операции изменения прав и создания долговременных секретов**.

## Шаг 4: сокрытие следов

Атакующие пытаются отключить логи:

- **`StopLogging`** (CloudTrail) / удаление trail;
- **удаление потоков** в CloudWatch Logs;
- **изменение retention** журналов;
- **создание нового trail** с неполным набором событий.

Всё это — события в тех же журналах (если их успели выгрузить). Наличие `StopLogging`
рядом с подозрительной активностью — сильное доказательство.

## Шаг 5: выгрузка и анализ

CloudTrail можно читать через `aws cloudtrail lookup-events`, из S3-бакета (JSON-файлы),
или в Athena. Практика:

```
$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValues=CreateAccessKey \
    --start-time 2026-03-10 --end-time 2026-03-13
```

GCP — через `gcloud logging read`; Azure — через `az monitor activity-log list`. Хранение
тоже ограничено, но CloudTrail обычно пишется в S3, где может лежать долго (если не удалён).

## Мини-практика: восстановить цепочку

```
$ grep -E 'CreateAccessKey|AttachUserPolicy|GetSecretValue' cloudtrail.log
{"eventName":"CreateAccessKey","userIdentity":{"userName":"dev"}}
{"eventName":"AttachUserPolicy","requestParameters":{"policyArn":"...AdministratorAccess"}}
{"eventName":"GetSecretValue","requestParameters":{"secretId":"prod/db"}}
```

Три события — три шага атаки. Дальше: отозвать ключ, снять политику, ротировать секрет,
проверить, не созданы ли другие пользователи.

## Частые ошибки и подводные камни

- **Смотреть только ConsoleLogin.** Главное — действия после входа.
- **Пропустить AssumeRole-цепочку.** Роль может скрывать реального актора.
- **Не проверить StopLogging.** Сокрытие следов — само по себе улика.
- **Игнорировать регионы.** CloudTrail может писаться в один регион, а активность — в
  другом.
- **Забыть про data-access логи.** Чтение секретов и объектов S3 может логироваться
  отдельно (и часто выключено).

## Что мы теперь знаем

- CloudTrail/GCP Audit/Azure Activity — журналы идентичности облака.
- Ключевые события: CreateAccessKey, AttachUserPolicy, AssumeRole, GetSecretValue.
- AssumeRole-цепочки — способ добраться до привилегий.
- StopLogging — признак сокрытия следов.
- Выгрузка: `aws cloudtrail lookup-events`, S3/Athena, `gcloud logging read`.

## Что фиксировать в отчёте

| Что | Зачем |
|-----|-------|
| Цепочку событий эскалации | нарратив атаки |
| Созданные ключи/пользователи | закрепление |
| Прочитанные секреты | ущерб |
| StopLogging/изменения trail | сокрытие |
| Действия по устранению | реакция |

## Расширенный пример: полная цепочка эскалации

Соберём реальный сценарий компрометации облачного аккаунта. Всё начинается с утёкшего ключа
(из публичного репозитория или логов CI). Атакующий получает доступ с минимальными правами
и начинает эскалацию:

1. **Разведка.** `GetCallerIdentity`, `ListUsers`, `ListRoles` — понять, что доступно.
2. **Создание backdoor.** `CreateUser` + `CreateLoginProfile` или `CreateAccessKey`.
3. **Эскалация прав.** `AttachUserPolicy` с `AdministratorAccess` или `PutRolePolicy`.
4. **Доступ к секретам.** `GetSecretValue`, `GetParameter` — пароли баз, API-токены.
5. **Перемещение.** `AssumeRole` в другие роли и аккаунты.
6. **Сокрытие.** `StopLogging`, удаление trail, чистка ключей.

Каждый шаг — отдельное событие CloudTrail. Собирая их по `eventTime` и `sourceIPAddress`,
ты получаешь **полный нарратив**. Полезно смотреть `userIdentity.sessionContext`: если
действия идут из-под роли, там указано, кто её «взял» — это связывает цепочку.

Особенно важно не пропустить **`AssumeRole`**: часто атакующий не создаёт новую учётку, а
переходит в существующую привилегированную роль, и внешне «пользователь» меняется. Поле
`requestParameters.roleArn` покажет целевую роль.

## Практика: что делать с найденным

После того как цепочка восстановлена, следует **реагирование**, зависящее от найденных
событий:

- **отозвать** все созданные ключи и сессии (`DeleteAccessKey`, revoke STS);
- **удалить** backdoor-учётки и лишние роли;
- **снять** выданные политики (`DetachUserPolicy`);
- **ротировать** секреты, к которым был доступ (`GetSecretValue`);
- **восстановить** логирование, если его отключили (`StopLogging`);
- **проверить** все регионы и связанные аккаунты — атакующий мог уйти дальше.

Отдельная задача — **оценка ущерба**: по `GetObject`/`GetSecretValue` понять, что именно
прочитали. Если data-access логирование было выключено, это придётся признать ограничением.

В отчёте строй **таймлайн атаки** с точками: первый вход → создание ключа → эскалация →
доступ к данным → сокрытие. Это самый понятный формат для руководства и устранения причин.

## Чек-лист разбора облачного IAM

1. Определи **окно** и **идентичности** (`userIdentity`, `roleArn`).
2. Выгрузи события из **всех регионов** (CloudTrail может писаться в один регион).
3. Отфильтруй **изменения прав и секретов**: CreateAccessKey, AttachUserPolicy,
   AssumeRole, GetSecretValue.
4. Восстанови **цепочку** по `eventTime`.
5. Проверь **StopLogging** и изменения trail — сокрытие следов.
6. Оцени **ущерб**: какие объекты и секреты были прочитаны.

## Сравнение журналов трёх провайдеров

| Провайдер | Журнал | Ключевое поле |
|-----------|--------|---------------|
| AWS | CloudTrail | `userIdentity` + `eventName` |
| GCP | Cloud Audit Logs | `protoPayload.authenticationInfo` |
| Azure | Activity Log / Entra | `caller` + `operationName` |

Хотя названия разные, логика одна: **кто → что → откуда → когда**. Научившись читать один
журнал, ты быстро освоишь остальные. Разница — в деталях: у GCP события делятся на
`admin activity` и `data access` (последние часто выключены по умолчанию), у Azure часть
событий лежит в Entra ID logs, а не в Activity Log. Поэтому при расследовании важно
**знать, какой журнал где живёт**, и проверять оба.

## Что писать в отчёте

Отчёт по облачному IAM — это прежде всего **таймлайн атаки**: первый вход, создание ключа,
эскалация, доступ к данным, сокрытие. Для каждого шага укажи `eventName`, `userIdentity`,
`sourceIPAddress` и `eventTime`. Отдельно перечисли **созданные артефакты** (ключи, роли,
пользователи) и **прочитанные секреты**. Если логирование отключали, это тоже вывод —
«атакующий пытался скрыть следы». В конце — меры: отзыв ключей, ротация секретов,
восстановление логирования, проверка связанных аккаунтов.

## Квиз

Проверь себя.

```quiz
- question: "Какой сервис AWS ведёт журнал API-вызовов в аккаунте?"
  options:
    - "S3"
    - "CloudTrail"
    - "CloudFront"
    - "Route53"
  answer: 1
  explanation: "AWS CloudTrail фиксирует API-вызовы: userIdentity, eventName, sourceIPAddress."
- question: "Почему CreateAccessKey — важное событие?"
  options:
    - "Ускоряет работу"
    - "Создаёт долговременный секрет для доступа"
    - "Удаляет логи"
    - "Меняет пароль консоли"
  answer: 1
  explanation: "Access key — постоянный секрет, переживающий смену пароля; типичный backdoor."
- question: "Что означает цепочка AssumeRole?"
  options:
    - "Выход из системы"
    - "Переход между идентичностями/ролями"
    - "Создание бакета"
    - "Включение логирования"
  answer: 1
  explanation: "AssumeRole позволяет сменить идентичность; цепочки используются для эскалации."
- question: "Какое событие указывает на сокрытие следов?"
  options:
    - "ConsoleLogin"
    - "StopLogging"
    - "GetSecretValue"
    - "CreateBucket"
  answer: 1
  explanation: "StopLogging отключает CloudTrail — попытка скрыть активность."
```

## Куда дальше

Мы завершили блок облачных и SaaS-идентичностей. Дальше перейдём к **macOS** — Keychain,
TCC и unified logs: там свои форматы баз и журналов. А пока главное запомни: **в облаке
эскалация прав — это последовательность API-событий, и её надо собрать в цепочку**.

## Где пригодится

- **CTF Forensics:** выгрузки облачных журналов.
- **DFIR:** расследование компрометации облачного аккаунта.
- **Cloud security:** аудит IAM и секретов.
- **Threat hunting:** поиск создания ключей и смены политик.
