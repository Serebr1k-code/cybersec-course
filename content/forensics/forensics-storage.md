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

## Версионирование и delete-marker

Когда на бакете включено версионирование, `DeleteObject` **не удаляет** данные — он
ставит **delete-marker**. Это маркер «после этого объекта как бы нет», но предыдущие
версии остаются. Схема:

```
$ aws s3api list-object-versions --bucket data-bucket --prefix report/
{
  "Versions":      [ { "VersionId": "v2", "IsLatest": true,  "Size": 1024 } ],
  "DeleteMarkers": [ { "VersionId": "d3", "IsLatest": true } ]
}
```

Здесь `d3` — маркер удаления (самый свежий), `v2` — реальная последняя версия. Чтобы
достать данные, запрашивают конкретную версию:

```
$ aws s3api get-object --bucket data-bucket --key report/secret.pdf \
    --version-id v2 out.pdf
```

Снять маркер (восстановить объект) можно удалением версии-маркера:

```
$ aws s3api delete-object --bucket data-bucket --key report/secret.pdf --version-id d3
```

Именно так расследуют «атакующий удалил данные» и «данные удалили по ошибке».

## Логи доступа: server access logs против CloudTrail

Два разных источника, и путать их нельзя:

| Источник | Что пишет | Где |
|----------|-----------|-----|
| S3 server access logs | каждый GET/PUT к объекту (data plane) | бакет-назначение |
| CloudTrail data events | GetObject/PutObject с учёткой | CloudTrail |
| CloudTrail management events | изменение политик, версий (control plane) | CloudTrail |

```
$ aws s3api get-bucket-logging --bucket data-bucket
{ "LoggingEnabled": { "TargetBucket": "logs-bucket", "TargetPrefix": "data-bucket/" } }
```

Если data events **выключены**, обращения к объектам не видны — только изменения
конфигурации. Отсутствие логов доступа — отдельная находка. В логах ищем:

- массовые `GetObject` с одного IP — выкачка;
- `PutObject` в нерабочее время — загрузка полезной нагрузки;
- доступ извне организации;
- обращения к «чувствительным» префиксам.

## Жизненный цикл, репликация и presigned URL

- **Lifecycle** — политика удаляет объекты через N дней. Данные могли исчезнуть «штатно»,
  не из-за атакующего:

```
$ aws s3api get-bucket-lifecycle-configuration --bucket data-bucket
```

- **Replication** — объекты копируются в другой регион/аккаунт. Репликация в **чужой**
  аккаунт — потенциальная эксфильтрация под видом бэкапа:

```
$ aws s3api get-bucket-replication --bucket data-bucket
```

- **Presigned URL** — временная подписанная ссылка даёт доступ без ключей. Утечка такой
  ссылки = утечка объекта. Проверяем срок жизни и политику бакета.

## Публичный доступ и шифрование

```
$ aws s3api get-public-access-block --bucket data-bucket
$ aws s3api get-bucket-policy --bucket data-bucket
$ aws s3api get-bucket-encryption --bucket data-bucket
```

Публичный бакет — классическая причина утечки; блокировка публичного доступа её
предотвращает. Шифрование (SSE-S3/SSE-KMS) влияет на восстановление: с SSE-KMS без
доступа к ключу объект не прочесть даже при наличии версии.

## Ограничения

- **Версионирование выключено** — удалённый объект не восстановить.
- **Логи не включены** — доступа к данным не видно, только события управления.
- **Репликация** — объект может существовать в другом месте; проверяй и реплику.
- **Шифрование KMS** — без ключа данные не прочесть.
- **Lifecycle** — «пропажа» может быть штатным удалением, а не атакой.

## Практический чеклист

1. `get-bucket-versioning` — включено ли версионирование.
2. `list-object-versions` — версии и delete-marker'ы.
3. Скачать нужную версию по `VersionId`.
4. Проверить `get-bucket-logging` и CloudTrail data events.
5. `get-bucket-lifecycle-configuration` и `get-bucket-replication`.
6. `get-public-access-block`, `get-bucket-policy`, `get-bucket-encryption`.
7. Искать аномалии доступа (массовые GET, необычные IP, ночное время).

## Сценарий: «атакующий выкачал бакет»

Разберём типовое расследование по шагам.

**1. Аномалия в счёте.** Мониторинг видит рост исходящего трафика из бакета.

**2. Проверяем логи доступа.** Server access logs показывают массовые `REST.GET.OBJECT`
с одного адреса:

```
$ grep 'REST.GET.OBJECT' access.log | awk '{print $8}' | sort | uniq -c | sort -rn
   9843 203.0.113.9
```

**3. Кто это был.** В CloudTrail ищем `GetObject` с этим источником:

```
$ aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject
GetObject  user/ci-deploy  2026-03-10T03:14Z  data-bucket/report/secret.pdf
```

Учётка `ci-deploy` — CI-сервис, у которого не должно быть доступа к `report/`.

**4. Как получили доступ.** Проверяем политику бакета и ключи:

```
$ aws s3api get-bucket-policy --bucket data-bucket | jq '.Policy' -r
```

Возможно, политика разрешает `ci-deploy` читать весь бакет — слишком широкое право.

**5. Содержимое.** Скачиваем конкретные версии объектов, которые могли измениться, и
сверяем хеши. Если объекты уже удалены — поднимаем версии.

**6. Вывод.** Компрометация CI-ключа + избыточные права → эксфильтрация. Действия:
отозвать ключ, сузить политику, включить data events, ротировать содержимое.

## Различие data plane и control plane

Ключевое разделение, которое часто упускают:

- **Control plane** — управление (создание бакета, политики, версионирование). Пишется в
  CloudTrail **management events** всегда.
- **Data plane** — доступ к самим объектам. Пишется в **data events** (нужно включить) или
  в **server access logs** (настраиваются отдельно).

Отсюда типичная ошибка: «в CloudTrail чисто» — но data events выключены, и выкачка
объектов просто не залогирована. При расследовании первым делом проверяй, **какие**
события вообще собирались.

## Восстановление и целостность

- **Hash-проверка** — у объекта есть `ETag` (обычно MD5 для несоставных). Сверяй с
  локальной копией, чтобы доказать неизменность.
- **VersionId** — сохраняй его как часть улики; он привязан к конкретному состоянию.
- **Object Lock / WORM** — если включено, объект нельзя удалить до истечения срока; это
  защищает улику.
- **MFA Delete** — если включено, удаление версий требует MFA; проверь, не выключали ли.

## Ограничения

- **Данные могли быть перезаписаны** — версия восстановит, но не докажет, что видел
  атакующий, если он читал «между» версиями.
- **Логи асинхронны** — server access logs пишутся с задержкой (минуты-часы); события
  могут ещё не появиться.
- **Кросс-аккаунт** — доступ из другого аккаунта виден только если настроен траст и логи.
- **Шифрование** — SSE-KMS требует ключ для чтения версии.
- **Несколько бакетов** — эксфильтрация могла идти через бакет-«приёмник»; проверяй
  репликацию и назначения логов.

## Практический чеклист

1. `get-bucket-versioning`, `list-object-versions` — версии и маркеры.
2. Скачать версии по `VersionId`, сверить `ETag`.
3. Проверить `get-bucket-logging` и включённость CloudTrail data events.
4. Найти аномалии в access logs (массовые GET, необычные IP, ночное время).
5. `get-bucket-policy`, `get-public-access-block`, `get-bucket-encryption`.
6. `get-bucket-replication`, `get-bucket-lifecycle-configuration` — где ещё есть данные.
7. Составить вывод: кто, когда, что выкачал; отозвать доступ, ротировать.

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
