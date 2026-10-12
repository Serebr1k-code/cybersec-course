---
id: cloud-s3-deep
title: "S3 глубоко: ACL, bucket policies, presigned URL и обход блокировок"
category: cloud
parent: cloud-storage-s3
difficulty: medium
order: 1
tags: [cloud, aws, s3, acl, bucket-policy, presigned-url, misconfig]
prerequisites: [cloud-storage-s3, cloud-iam-basics]
useful_for:
  - "Поиск и эксплуатация мисконфигов S3"
  - "Bug bounty: публичные бакеты и presigned URL"
  - "Понимание, почему бакет открыт"
estimated_minutes: 40
summary: "Глубокий разбор контроля доступа S3: ACL vs bucket policy, public access block, presigned URL, Object Ownership, и как обходить типовые ограничения."
---
## Задача

S3 — самое частое место утечек в AWS. Мы уже видели базовые мисконфиги (`cloud-storage-s3`). Теперь — **глубоко**: как устроен контроль доступа (ACL vs bucket policy), что такое **presigned URL** и как обходить типовые ограничения. Разберём на конкретном бакете.

## Данные: бакет, который «закрыт»

Проверяем бакет `acme-backups`. Сначала смотрим публичный доступ:

```
$ aws s3api get-public-access-block --bucket acme-backups
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true, "IgnorePublicAcls": true,
    "BlockPublicPolicy": true, "RestrictPublicBuckets": true
  }
}
```

Все четыре флага **включены** — публичный доступ заблокирован. Листинг анонимно не работает:

```
$ aws s3 ls s3://acme-backups/ --no-sign-request
An error occurred (AccessDenied)
```

Кажется, бакет защищён. Но это не значит, что в него нельзя попасть.

## Два механизма доступа: ACL и bucket policy

Контроль доступа S3 держится на двух вещах:

- **ACL** (Access Control List) — старый механизм: права на уровне объекта/бакета, привязанные к **AWS-аккаунтам** (не к IAM-пользователям). Пример: `public-read` на объект.
- **Bucket policy** — JSON-политика на весь бакет: правила с `Principal`, `Action`, `Resource`, `Condition`. Современный и основной механизм.

Важно: `BlockPublicPolicy`/`IgnorePublicAcls` блокируют **публичные** правила. Но политика, разрешающая доступ **конкретному аккаунту или роли**, — не «публичная», и её блокировка не касается.

Смотрим bucket policy:

```
$ aws s3api get-bucket-policy --bucket acme-backups --query Policy --output text | jq '.Statement[]'
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::999999999999:root" },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::acme-backups/*"
}
```

Политика разрешает `GetObject` аккаунту `999999999999`. Если это **чужой** аккаунт, куда случайно выдали доступ (или наш), мы можем читать:

```
$ aws s3 cp s3://acme-backups/db-dump.sql .
```

## Приём: presigned URL

**Presigned URL** — временная ссылка на объект, подписанная ключом, у которого есть доступ. Такая ссылка работает **без** кредов: подпись уже внутри. Она часто утекает в логи, тикеты, мессенджеры, JS-код.

Формат:

```
https://acme-backups.s3.amazonaws.com/db-dump.sql?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Signature=...
```

Проверяем утёкшую ссылку:

```
$ curl -s -o db.sql -w "%{http_code}\n" "https://acme-backups.s3.amazonaws.com/db-dump.sql?X-Amz-..."
200
```

Ссылка работает, пока не истёк `X-Amz-Expires`. Даже с включённым Block Public Access presigned URL действует — он подписан ключом.

## Полный прогон: от «закрытого» бакета до данных

1. **Проверка флагов.** `get-public-access-block` → кажется, закрыто.
2. **Анонимный листинг.** `--no-sign-request` → AccessDenied.
3. **Bucket policy.** `get-bucket-policy` → видим доступ для аккаунта/роли.
4. **Чтение.** `s3 cp` с кредами, которым разрешено.
5. **Presigned.** Ищем ссылки в коде/логах/тикетах; пробуем `curl`.
6. **ACL-объекты.** Проверяем, нет ли отдельных объектов с `public-read`:

```
$ aws s3api get-object-acl --bucket acme-backups --key db-dump.sql --query 'Grants[].Grantee'
[ { "URI": "http://acs.amazonaws.com/groups/global/AllUsers" } ]
```

## Object Ownership и почему ACL путают

Раньше ACL был основным механизмом; сейчас AWS продвигает **Bucket owner enforced** (Object Ownership): ACL отключены, владелец бакета — владелец всех объектов. Если бакет в режиме `BucketOwnerEnforced`, ACL-и не действуют, и `IgnorePublicAcls` не нужен. Проверка:

```
$ aws s3api get-bucket-ownership-controls --bucket acme-backups
{ "OwnershipControls": { "Rules": [ { "ObjectOwnership": "BucketOwnerEnforced" } ] } }
```

`BucketOwnerEnforced` — ACL отключены. `ObjectWriter` — ACL работают, возможны сюрпризы.

## Защита и что ломает атаку

- **Block Public Access** на уровне аккаунта (не только бакета).
- **BucketOwnerEnforced** — отключить ACL целиком.
- **Минимум в bucket policy** — не выдавать чужим аккаунтам.
- **Короткий TTL presigned URL** и не логировать ссылки.
- **S3 Access Analyzer** — находит бакеты, доступные извне.

## Если не сработало

- **BucketOwnerEnforced + узкая policy + нет presigned** — доступа нет.
- **Presigned истёк** — нужен свежий.
- **Object Lock** — объект не изменить/удалить.
- **Шифрование SSE-KMS** без `kms:Decrypt` — прочитать нельзя.

## Мини-сценарий: утёкшая presigned-ссылка

1. **Находим бакет.** В JS-коде сайта видим URL вида `https://acme-assets.s3.amazonaws.com/report.pdf?X-Amz-Signature=...`.
2. **Проверяем бакет.** `get-public-access-block` → всё включено, публично не отдаётся.
3. **Пробуем ссылку.** `curl -o report.pdf "<url>"` → `200 OK`. Presigned URL работает несмотря на блокировку.
4. **Разбираем ссылку.** В параметрах видим `X-Amz-Credential` — это ARN роли, чьим ключом подписана ссылка.
5. **Ищем другие ссылки.** Грепаем сайт/логи на `X-Amz-Signature` — находим ссылку на `backups/db-dump.sql`.
6. **Скачиваем.** `curl` → дамп базы у нас. Кредов мы не использовали — сработала подпись.
7. **Оценка.** `X-Amz-Expires` показывает, сколько ещё живёт ссылка. Если долго — успеем выкачать всё.

Вывод: presigned URL — это «ключ в кармане»: пока он не истёк, Block Public Access не мешает. Ссылки утекают через фронтенд, логи и тикеты.

## Разбор: почему «всё включено» не значит «безопасно»

Block Public Access защищает от **публичных** правил, но доступ бывает и непубличным: bucket policy конкретному аккаунту, presigned URL с подписью, роль с `GetObject`. Все три обходят флаги, потому что формально не являются «публичным доступом». Отсюда урок: безопасность S3 нельзя оценивать по одному переключателю. Смотрите **всю** цепочку доступа: политику бакета, ownership-контролы, presigned-ссылки в коде и логах, права ролей. Инструмент S3 Access Analyzer как раз показывает бакеты, доступные **извне** аккаунта, — он закрывает именно этот разрыв.

И помните про версионирование: если объект перезаписали вредоносным, старая версия может остаться доступной; а если удалили — версия восстанавливается.

И проверяйте `GetBucketPolicyStatus` — он покажет, считается ли политика публичной по мнению AWS, что помогает быстро отсеять бакеты.

## Что мы теперь знаем

1. Доступ S3 — это ACL + bucket policy.
2. Block Public Access блокирует публичные правила, но не доступ конкретному аккаунту.
3. Presigned URL работает без кредов и часто утекает.
4. `BucketOwnerEnforced` отключает ACL.
5. Защита — account-level block, узкая policy, короткий TTL, Analyzer.

## Частые ошибки

- **Block Public Access только на бакете**, а не на уровне аккаунта — новый бакет может оказаться открытым.
- **Presigned URL с большим TTL** в коде, логах и тикетах.
- **ACL включены** (`ObjectWriter`) — неожиданный публичный доступ к объектам.
- **Политики, выданные «на время»** чужому аккаунту и забытые.
- **Отсутствие S3 Access Analyzer** — внешний доступ не находится.

## На что смотреть дальше

- `get-public-access-block` (бакет и аккаунт).
- `get-bucket-policy` — кому и что разрешено.
- Утёкшие presigned URL в коде/логах/тикетах.
- `get-bucket-ownership-controls` — включены ли ACL.
- Отдельные объекты с публичными ACL.

## Быстрая проверка

```bash
aws s3api get-public-access-block --bucket acme-backups
aws s3api get-bucket-policy --bucket acme-backups
aws s3api get-bucket-ownership-controls --bucket acme-backups
curl -s -o /dev/null -w '%{http_code}\n' "https://acme-backups.s3.amazonaws.com/db-dump.sql?X-Amz-Signature=..."
```

## Глазами защитника

Глубже: Object Ownership убирает ACL, bucket policies проверяют `Principal` и условия, Block Public Access перекрывает всё. Presigned URL подписывают коротким сроком и узкими правами. Версионирование и Object Lock защищают от удаления. Логирование (access logs, CloudTrail data events) показывает чтение. Аудит: политики, публичность, presigned-ссылки, старые версии.

## Частые вопросы

**Почему «закрытый» бакет бывает открыт?**

Из-за ACL на объектах, ошибки в bucket policy или presigned URL, утёкшего наружу. Проверяй все механизмы доступа.

**Что даёт Object Ownership?**

Отключает ACL и делает владельца бакета владельцем объектов. Убирает класс ошибок, когда объект загружен с чужим ACL.

**Как работает presigned URL?**

Подписывает запрос ключом; права и срок задаются при генерации. Долгий срок и широкие права делают ссылку ключом.

**Что видно в логах?**

Access logs показывают запросы к объектам, включая анонимные; CloudTrail data events — API-вызовы. Включай их для чувствительных бакетов.

**Что такое Object Lock?**

Запрет удаления и изменения объектов на срок (WORM). Защита от ransomware и от подмены бэкапов.

**Как найти presigned-ссылку?**

В JS, логах, документации, ошибках. Ищи параметры `X-Amz-Signature` и `X-Amz-Expires`.

**Как защититься?**

Object Ownership, узкие политики, Block Public Access, короткие presigned, логирование, Object Lock.

**Чем это отличается от базового урока про S3?**

Здесь фокус на том, как «закрытый» бакет всё равно открывается через другой механизм доступа.

## Разбор: «закрытый» бакет через presigned URL

Bucket policy запрещает анонимный доступ, но в JS-бандле остался presigned URL с длинным сроком и правом на весь префикс. Атакующий скачивает объекты до истечения ссылки, включая бэкапы с секретами. Политика бакета при этом выглядит закрытой. Защита — короткие presigned URL с узкими правами и запрет длинных сроков.

## Что чаще всего упускают

Множественность механизмов доступа: закрытая политика не означает закрытый бакет, если есть ACL или presigned-ссылка. Второе — логирование: без access logs и data events чтение не видно. Третье — Object Lock: без него бэкапы можно подменить. Вывод: проверяй каждый механизм доступа и включай логирование для чувствительных бакетов.

**Что если Block Public Access включён?**

Тогда публичный доступ закрыт даже при ошибке в политике; но presigned-ссылки всё ещё работают.

**Как проверить реальный статус бакета?**

`aws s3api get-public-access-block` и `get-bucket-policy` покажут фактические настройки, а не только намерения.

## Квиз

Проверь себя.

```quiz
- question: "Что блокирует Block Public Access?"
  options:
    - "Публичные ACL и публичные bucket policies"
    - "Доступ конкретному аккаунту"
    - "Шифрование"
    - "Версионирование"
  answer: 0
  explanation: "Он не мешает доступу, выданному конкретному аккаунту."
- question: "Чем bucket policy отличается от ACL?"
  options:
    - "Policy — JSON-правила бакета; ACL привязаны к аккаунтам"
    - "Policy шифрует данные"
    - "ACL современнее"
    - "Они одинаковы"
  answer: 0
  explanation: "Policy — основной современный механизм."
- question: "Почему presigned URL работает без кредов?"
  options:
    - "Подпись уже встроена в ссылку"
    - "Он публичный по умолчанию"
    - "Он шифрует данные"
    - "Он отключает policy"
  answer: 0
  explanation: "Подпись делает ссылку самодостаточной."
- question: "Что означает BucketOwnerEnforced?"
  options:
    - "ACL отключены, владелец бакета владеет всеми объектами"
    - "Бакет публичный"
    - "Объекты зашифрованы"
    - "Включён Object Lock"
  answer: 0
  explanation: "Это режим Object Ownership без ACL."
- question: "Что находит S3 Access Analyzer?"
  options:
    - "Бакеты, доступные извне аккаунта"
    - "Пароли пользователей"
    - "Тип шифрования"
    - "Размер объектов"
  answer: 0
  explanation: "Analyzer выявляет внешний доступ."
```

## Куда дальше

В следующем уроке (`cloud-database-exposure`) мы перейдём к управляемым базам и разберём, как они оказываются публично доступными. А пока главное: «закрытый» бакет — это ещё не безопасный бакет: смотрите policy, presigned URL и ACL.

## Где пригодится

- **Bug bounty:** утёкшие presigned URL и широкие policy.
- **Red team:** обход Block Public Access.
- **Пентест:** аудит S3.
- **Работа/DevSecOps:** account-level block, BucketOwnerEnforced, Analyzer.
- **Дальше по дереву:** `cloud-storage-s3`, `cloud-database-exposure`.
