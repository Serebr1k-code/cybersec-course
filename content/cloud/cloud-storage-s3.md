---
id: cloud-storage-s3
title: "Объектные хранилища: S3, GCS, Azure Blob и их мисконфиги"
category: cloud
parent: cloud-foundations-services
difficulty: easy
order: 1
tags: [cloud, s3, gcs, blob, bucket, misconfig, exfiltration]
prerequisites: [cloud-fundamentals]
useful_for:
  - "Поиск и эксплуатация публичных бакетов"
  - "Bug bounty: утечки данных через хранилища"
  - "CTF: 'найди флаг в бакете'"
estimated_minutes: 28
summary: "Объектные хранилища — самый частый источник облачных утечек. Разбираем права ListBucket/GetObject/PutObject, ACL и bucket policy, presigned URL, а также инструменты для массового поиска открытых бакетов."
---
## Что такое объектное хранилище

Object storage (AWS S3, Google Cloud Storage, Azure Blob Storage) хранит неограниченные объёмы данных как плоские объекты в контейнерах (bucket/container). Ключевые свойства: глобально уникальные имена, HTTP-доступ по URL, права на уровне bucket и объекта, а также presigned URL для временного доступа. Именно эти свойства делают его частой целью: утечка бакета — это часто дампы БД, бэкапы, конфиги, ключи, PII. В отличие от файловой системы, здесь нет иерархии директорий — «путь» это просто часть ключа объекта, и префиксы (`/backups/2024/`) служат для организации.

## Модель прав

- **Bucket policy** — JSON-политика на весь бакет (resource-based).
- **ACL** — устаревшая модель на уровне объекта/bucket (READ, WRITE, FULL_CONTROL).
- **IAM policy** — права сущности на `s3:GetObject` и т.д.
- **Block Public Access** — «рубильник», перекрывающий публичные политики.
- **Presigned URL** — подписанная ссылка с ограниченным TTL.

Порядок вычисления доступа: explicit Deny → SCP → permission boundary → identity policy → bucket policy → ACL. Block Public Access может переопределить даже разрешающую политику.

## Публичные бакеты: как найти

```bash
curl -s https://mybucket.s3.amazonaws.com/ | head
aws s3 ls s3://mybucket --no-sign-request
curl -sI https://mybucket.s3.amazonaws.com/backup.sql
```

`--no-sign-request` — ключевой флаг: запрос без учёта, то есть как аноним. Если `ListBucket` разрешён, вернётся XML с ключами. Ответ `403 AccessDenied` на `/` при доступном объекте тоже информативен — значит листинг закрыт, но объекты могут читаться по прямому ключу.

## Права через AWS CLI

```bash
aws s3 ls s3://mybucket --no-sign-request
aws s3 cp s3://mybucket/dump.sql . --no-sign-request
aws s3 sync s3://mybucket ./loot --no-sign-request --exclude "*.jpg"
aws s3api get-bucket-acl --bucket mybucket
aws s3api get-bucket-policy --bucket mybucket
aws s3api get-public-access-block --bucket mybucket
aws s3api list-objects-v2 --bucket mybucket --max-items 50
```

Для записи: `aws s3 cp poc.txt s3://mybucket/ --no-sign-request` — если проходит, бакет writable.

## ACL и bucket policy

Пример публичной политики:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
 "Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}
```

`Principal: *` без условия — классическая утечка. Опасны также `s3:ListBucket` (дамп списка), `s3:PutObject` (загрузка вредоносного контента → hosting/XSS), `s3:DeleteObject` (разрушение). Отдельно опасно сочетание `s3:PutObject` с website-конфигом — атакующий хостит фишинг на доверенном домене.

## Presigned URL

Presigned URL содержит `X-Amz-Signature`, `X-Amz-Expires`. Анализ:

- Длинный `Expires` (дни/годы) — риск при утечке ссылки.
- `X-Amz-Credential` раскрывает Access Key ID и регион.
- Предсказуемые ключи объектов позволяют перебор.

```bash
echo "https://bucket.s3.amazonaws.com/f?X-Amz-Expires=604800&X-Amz-Credential=AKIA..." \
  | tr '&' '\n' | grep -E 'Expires|Credential|Signature'
```

## Инструменты массового поиска

```bash
cloud_enum -k mycompany -k mycompany-backup --quickscan
s3scanner scan --bucket mybucket
trufflehog s3 --bucket mybucket
# Google dorks
# site:s3.amazonaws.com "index of" mycompany
# site:blob.core.windows.net mycompany
# site:storage.googleapis.com mycompany
```

`cloud_enum` флаги: `-k` ключевое слово, `--quickscan` быстрый режим, `-l` список слов. `s3scanner scan` проверяет права (list/read/write). `trufflehog` сканирует содержимое на секреты.

## Типовые находки и их последствия

| Находка | Влияние |
|---------|---------|
| ListBucket анонимно | полный дамп содержимого |
| GetObject на .env/.sql | утечка креденшелов/PII |
| PutObject анонимно | дефейс, хостинг малвари, XSS |
| ACL public-read-write | компрометация контента |
| Presigned без TTL | долговременный доступ |
| Website-конфиг + takeover | захват домена |

## Практика

1. Найти бакеты по имени компании (вариации: `company`, `company-dev`, `company-backup`, `company-assets`).
2. Проверить анонимный доступ: `aws s3 ls --no-sign-request`.
3. Скачать интересное, зафиксировать хэши (`sha256sum`).
4. Проверить содержимое на ключи → расширить доступ.
5. Проверить запись (PutObject) без разрушения данных — только маркер.
6. Оценить влияние и оформить.

## Защита

Block Public Access, отключение ACL (Object Ownership = BucketOwnerEnforced), шифрование (SSE-S3/SSE-KMS), логирование доступа (server access logs, CloudTrail data events), мониторинг через IAM Access Analyzer, запрет публичных presigned без TTL, версионирование.

## Частые ошибки

- Считать, что «bucket policy private» = безопасно: проверяйте ACL и Block Public Access.
- Путать регион: `s3.amazonaws.com` работает, но website-endpoint регион-специфичен.
- Игнорировать версионирование: удалённые объекты могут быть восстановлены.
- Скачивать всё подряд (объём, шум, OPSEC).
- Не проверять Azure/GCP-аналоги.
- Забывать, что `HeadObject` даёт метаданные без чтения тела.

## Что дальше / решение

Найдя открытый бакет, определите чувствительность (скан на ключи, PII, бэкапы), зафиксируйте доказательства и переходите к извлечению креденшелов → расширению прав. Для защиты — автоматический аудит (Access Analyzer, Prowler, ScoutSuite) и запрет публичных политик на уровне Organization SCP.

## Версионирование и восстановление объектов

Если на бакете включено версионирование, удалённый объект не исчезает: создаётся delete-marker, а старая версия доступна. Для атакующего это означает, что «удалённые» секреты могут читаться через `list-object-versions`:

```bash
aws s3api list-object-versions --bucket mybucket --no-sign-request \
  --query 'Versions[].{Key:Key,VersionId:VersionId,Size:Size}' --output table
aws s3api get-object --bucket mybucket --key .env --version-id 3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY --no-sign-request env.old
```

Для защитника версионирование — плюс (защита от ransomware), но и риск долгого хранения утечек.

## Шифрование и KMS

- **SSE-S3** — управляемые провайдером ключи, прозрачно.
- **SSE-KMS** — ключи в KMS; доступ к объекту требует `kms:Decrypt`. Проверьте, не даёт ли ключ политика широкий доступ.
- **SSE-C** — ключ передаёт клиент.

```bash
aws s3api get-bucket-encryption --bucket mybucket
aws kms describe-key --key-id <id>
aws kms get-key-policy --key-id <id> --policy-name default
```

Ошибка `AccessDenied` на KMS при разрешённом `s3:GetObject` — частая причина «странных» отказов; проверяйте key policy.

## Статический хостинг и его риски

Website-конфиг (`aws s3 website`) отдаёт объекты по HTTP без аутентификации, даже если сам бакет закрыт через Block Public Access — нет, не так: Block Public Access блокирует и website. Но при корректной конфигурации любой загруженный объект становится публичным. Загрузка HTML/JS через `s3:PutObject` на такой бакет = XSS/hosting на доверенном домене. Проверьте `index`/`error` документы и не загружайте исполняемый контент без нужды.

## Сравнение провайдеров

| Возможность | AWS S3 | GCS | Azure Blob |
|-------------|--------|-----|------------|
| Публичный доступ | bucket policy + Block Public Access | IAM allUsers + public access prevention | container access level + Allow Blob public |
| Листинг анонимно | ListBucket | storage.objects.list для allUsers | container public + list |
| Подписанные ссылки | presigned URL | signed URL | SAS-токен |
| Аудит | CloudTrail data events | Data Access logs | Storage analytics |
| Захват имени | глобально уникально | глобально уникально | уникально в аккаунте |

## Разобранный пример: от бакета до ключей

```bash
aws s3 ls s3://acme-backups --no-sign-request
# PRE db/  PRE configs/
aws s3 cp s3://acme-backups/configs/app.env . --no-sign-request
cat app.env
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...
aws sts get-caller-identity   # с найденными ключами
```

Ключи из бакета часто дают прямой доступ к аккаунту — это мост из «утечки» в «компрометацию».

## OPSEC, стоимость и шум

Массовое скачивание генерирует CloudTrail data events и может стоить денег владельцу (egress). Действуйте выборочно: сначала `list-objects` (метаданные), затем точечно скачивайте важное. Отмечайте размер бакета и не качайте образы/дампы целиком.

## Чек-лист

1. Имя и регион бакета.
2. Анонимный list → содержимое.
3. Анонимный get конкретных ключей.
4. Запись (маркер).
5. Поиск секретов в содержимом.
6. Версии удалённых объектов.
7. Шифрование/KMS-политика.
8. Оценка влияния и отчёт.

## Работа с большими бакетами и пагинацией

`list-objects-v2` возвращает не более 1000 ключей за раз. Для полного обхода используйте `--page-size` и `--max-items` либо `aws s3 sync --dryrun` для инвентаризации:

```bash
aws s3api list-objects-v2 --bucket big --no-sign-request --page-size 1000 \
  --query 'Contents[].Key' --output text | tr '\t' '\n' | wc -l
aws s3 ls --recursive s3://big --no-sign-request | awk '{print $3, $4}' | sort -k2 -h | tail -20
```

Сортировка по размеру помогает быстро найти дампы и архивы. Ищите расширения `.sql`, `.bak`, `.env`, `.pem`, `.zip`, `.tar.gz`, `.kdbx`, `.ovpn`.

## Тонкости префиксов и регионов

Публичный доступ к объекту можно проверить как по path-style (`https://s3.amazonaws.com/bucket/key`), так и по virtual-hosted (`https://bucket.s3.amazonaws.com/key`). Для некоторых регионов нужен endpoint `bucket.s3.<region>.amazonaws.com`. Ошибка `PermanentRedirect` указывает на неверный регион — это подсказка, где искать ресурс.

## Что ещё проверять

- **CORS**: `aws s3api get-bucket-cors --bucket mybucket` — широкий `AllowedOrigin: *` позволяет читать содержимое из браузера жертвы.
- **Политика lifecycle**: могут быть правила автоудаления — влияет на планирование.
- **Replication**: бакет может реплицироваться в другой аккаунт/регион.
- **Object Lock**: WORM, блокирует удаление.

Эти настройки определяют, насколько «живуча» находка и как долго данные доступны.

## Квиз

```quiz
- question: "Чем `PutObject` опаснее `GetObject`?"
  options:
    - "Ничем, это синонимы"
    - "Позволяет записывать объекты: подмена артефактов, XSS через CDN, дефейс"
    - "Даёт доступ к IAM"
    - "Открывает порт 22"
  answer: 1
  explanation: "Запись в публичный бакет — критично: содержимое можно подменить."
- question: "Что означает `"Principal": "*"` в bucket policy без Condition?"
  options:
    - "Бакет доступен только владельцу"
    - "Бакет публичный — доступен любому"
    - "Ошибка в политике"
    - "Только анонимное чтение"
  answer: 1
  explanation: "Звёздочка в Principal = все, политика делает бакет публичным."
- question: "Как убедиться, что бакет реально пуст, а не закрыт?"
  options:
    - "Просто посмотреть в браузере"
    - "Сравнить ответы с `--no-sign-request` и с валидными кредами, проверить HTTP-код"
    - "Пингануть бакет"
    - "Запустить nmap"
  answer: 1
  explanation: "Пустой ответ ≠ отсутствие прав; сравнивайте авторизованный и анонимный доступ."
- question: "Что искать в утёкшем `terraform.tfstate` в первую очередь?"
  options:
    - "Имена виртуалок"
    - "Ключи, пароли и секреты (access_key, secret_key, tokens)"
    - "Версию Terraform"
    - "Цвет интерфейса"
  answer: 1
  explanation: "State-файл часто содержит секреты в открытом виде."
```

## Где пригодится

- **Bug bounty** — публичные бакеты с PII/бэкапами стабильно приносят награды.
- **Пентест** — стартовый вектор получения креденшелов из `.env`/state.
- **CTF** — «флаг в бакете» — классика категории Cloud.
- **IR** — определение объёма утечки при инциденте (какие объекты были доступны).
- **Дальше** — найденные в бакете ключи ведут в `cloud-credential-hunting` и `cloud-privesc-iam`.
