---
id: osint-cloud-recon
title: "Разведка облачных ресурсов: S3, Azure Blob, GCS"
category: osint
parent: osint-infra-network
difficulty: medium
order: 3
tags: [cloud, s3, azure, gcs, buckets, misconfig]
prerequisites: [osint-infrastructure]
useful_for:
  - "Bug bounty: misconfigured buckets"
  - "Cloud security audit"
  - "CTF категория OSINT"
estimated_minutes: 55
summary: "Как находить публичные бакеты и облачные ресурсы по именам, сертификатам и JS; проверка прав доступа и этические границы."
---

Облачные хранилища (S3, Azure Blob, GCS) часто остаются открытыми. Их имена **предсказуемы**, а содержимое иногда попадает в публичный доступ. Этот урок — про то, как найти облачные активы по открытым данным и корректно проверить их доступность.

## Почему облако — отдельный источник

- **Имена бакетов детерминированы**: `company-backup`, `company-assets`, `company-dev`.
- **Регион в URL**: `bucket.s3.amazonaws.com`, `bucket.s3.eu-west-1.amazonaws.com`.
- **Ссылки в коде**: JS, конфиги, мобильные приложения часто содержат URL бакетов.
- **Сертификаты**: `*.s3.amazonaws.com` в CT-логах.
- **CNAME на бакет**: поддомен `static.example.com` может указывать на `example-static.s3.amazonaws.com`.

Именно предсказуемость имён делает облако «дешёвым» источником: не нужно сканировать порты — достаточно перебрать словарь имён.

## Признаки в открытых данных

Ищите в исходниках сайта и приложений:

```bash
# Ссылки на бакеты в JS/HTML
curl -s https://example.com/app.js | grep -Eo 'https?://[a-z0-9.-]+\.(s3[.-][a-z0-9-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com)[^"'\'' ]*'
```

Дорки:

```
site:s3.amazonaws.com "example"
site:blob.core.windows.net "example"
site:storage.googleapis.com "example"
inurl:amazonaws.com example.com
```

Дополнительно: `gau example.com | grep -Eo 'https?://[^ ]*(s3|blob\.core|googleapis)[^ ]*'` вытаскивает бакеты из архивов URL.

## Перечисление по имени

Зная шаблон компании, генерируйте кандидатов:

```bash
for suffix in assets backup static dev prod media uploads logs data; do
  echo "example-$suffix"
  echo "example.$suffix"
done
```

Проверка существования и прав S3:

```bash
# GET списка объектов (публичное чтение)
curl -s "https://example-assets.s3.amazonaws.com/?list-type=2" | head

# Проверка конкретного объекта
curl -sI "https://example-assets.s3.amazonaws.com/config.json"
```

Коды ответов:

- `200` + XML `<ListBucketResult>` → публичный листинг.
- `403 AccessDenied` → бакет есть, но закрыт.
- `404 NoSuchBucket` → не существует.

## Azure Blob и GCS

Azure:

```bash
curl -s "https://example.blob.core.windows.net/\$web?restype=container&comp=list"
curl -s "https://example.blob.core.windows.net/?comp=list"   # список контейнеров
```

GCS:

```bash
curl -s "https://storage.googleapis.com/example-assets"
curl -s "https://storage.googleapis.com/storage/v1/b/example-assets/o"  # JSON API
```

Инструменты: **cloud_enum**, **S3Scanner**, **GCPBucketBrute**, **MicroBurst** (Azure). Они автоматизируют генерацию имён и проверку.

## Что искать внутри

Если бакет открыт на чтение, смотрите:

- `backup*.zip`, `*.sql`, `*.env`, `credentials.*`;
- выгрузки БД, дампы, логи;
- статические ассеты с исходниками (`*.map`, `*.js`);
- `terraform.tfstate` — часто содержит секреты и внутреннюю топологию.

Имена файлов часто раскрывают структуру внутренних систем.

## Проверка записи (осторожно!)

Проверять **право на запись** допустимо только в рамках авторизованного пентеста и **минимальным** пробным объектом, который вы сразу удаляете. Для bug bounty это отдельно регламентируется правилами программы.

```bash
# ТОЛЬКО при наличии разрешения: пробный PUT и немедленный DELETE
curl -X PUT -d "poc" "https://example-assets.s3.amazonaws.com/poc_test.txt"
curl -X DELETE "https://example-assets.s3.amazonaws.com/poc_test.txt"
```

Не заливайте реальные файлы и не удаляйте чужие данные — это уже вред.

## Обогащение: связь с другими находками

- Бакет из JS → связать с доменом/компанией.
- Имя бакета содержит окружение (`dev`, `staging`) → это отдельная поверхность.
- Содержимое ссылается на внутренние хосты → новые цели.
- `terraform.tfstate` → имена VPC, ролей, БД — карта облачной инфраструктуры.

## Автоматизация перебора имён

Ручная проверка сотен имён не масштабируется. Инструменты:

- **cloud_enum** — перебор S3/Azure/GCS по словарю и шаблонам компании.
- **S3Scanner** — находит открытые на чтение/запись бакеты.
- **GCPBucketBrute** — GCS-бакеты.
- **MicroBurst** — Azure (blob, ключи, подписки).

```bash
# cloud_enum по ключевому слову компании
cloud_enum -k example -k examplecorp --disable-azure
# S3Scanner с проверкой прав
s3scanner -bucket-file names.txt -enumerate
```

Словарь формируйте из бренда + суффиксов (`-backup`, `-dev`, `-assets`, `-logs`, `-media`, `-prod`, `-static`, `-uploads`, `-data`).

## Различия провайдеров и коды ответов

| Провайдер | URL-форма | Признак публичности |
|---|---|---|
| AWS S3 | `bucket.s3.amazonaws.com` | 200 + `<ListBucketResult>` |
| Azure Blob | `acct.blob.core.windows.net` | 200 + `EnumerationResults` |
| GCS | `storage.googleapis.com/bucket` | 200 + XML/JSON listing |

Коды: `200` (доступ), `403` (есть, закрыт), `404` (нет). Azure-контейнеры перечисляются по `?restype=container&comp=list`. GCS иногда отдаёт JSON при `?list-type=2`.

## Разобранный пример

1. На `example.com` нашли `app.js` со ссылкой `https://example-static.s3.amazonaws.com/`.
2. Проверили: `curl -sI https://example-static.s3.amazonaws.com/` → `403`.
3. Сгенерировали кандидатов, нашли `example-static-dev` → `200` и XML-листинг.
4. В листинге — `backup/2023-11.zip` и `terraform.tfstate`.
5. Зафиксировали находку: имя бакета, права (read), список ключей, источник ссылки.

## Что делать с находкой (без вреда)

Открытый бакет — это находка, а не «поле для грабежа»:

1. **Зафиксируйте** имя, права (read/write), список ключей (первые N), источник.
2. **Не скачивайте** весь объём — только доказательство (листинг, пару файлов-образцов).
3. **Не удаляйте и не изменяйте** ничего.
4. **Сообщите** владельцу через программу/контакт (часто есть `abuse`/security.txt).
5. Для **записи** — только пробный PUT с немедленным DELETE и явным разрешением.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| curl | `curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2"` | ручная проверка S3 |
| cloud_enum | `cloud_enum -k <brand>` | перебор S3/Azure/GCS |
| S3Scanner | `s3scanner -bucket-file names.txt -enumerate` | права бакетов |
| GCPBucketBrute | `gcpbucketbrute -k <brand>` | GCS-бакеты |
| MicroBurst | PowerShell-модуль | Azure blob |
| gau | `gau example.com \| grep s3` | бакеты из архивов |

## Частые ошибки

- **Проверять запись без разрешения** → вред и юридические последствия.
- **Скачивать чужой приватный контент** «на всякий случай».
- **Считать `403` отсутствием бакета** (он есть, просто закрыт).
- **Не проверять регион** (`s3.<region>.amazonaws.com`) — даёт другой результат.
- **Забывать про CDN-домены**, указывающие на бакет.
- **Игнорировать GCS/Azure** — не только S3 бывает открыт.

## Что делать дальше / решение

- **Нужны имена бакетов** → JS/конфиги + дорки + `gau` → сгенерировать кандидатов.
- **Нужна проверка прав** → `curl`/S3Scanner; запись — только с разрешения.
- **Нужен масштаб** → `cloud_enum -k <brand>` по всем провайдерам.
- **Нужна карта облака** → `terraform.tfstate` и конфиги внутри открытых бакетов.

## CloudFront, Firebase и другие хранилища

S3/Azure/GCS — не единственные цели. Та же логика применима к другим облачным хранилищам. **AWS CloudFront** отдаёт контент через распределение, но origin-бакет остаётся в S3, и его имя часто вычисляется из домена. **Firebase Storage** хранит файлы в бакетах вида `project-id.appspot.com`, а Realtime Database — в `project-id.firebaseio.com`; и то и другое легко проверяется на публичный доступ (`curl -s "https://<id>.firebaseio.com/.json"`). **DigitalOcean Spaces** и **Backblaze B2** имеют собственные форматы URL (`<space>.<region>.digitaloceanspaces.com`, `<bucket>.s3.<region>.backblazeb2.com`), и `cloud_enum` умеет их проверять. **GitHub Pages / Netlify / Vercel** тоже могут содержать артефакты сборки с исходниками и картами (`*.map`). Правило одно: если сервис даёт предсказуемое имя из бренда — он входит в словарь перебора.

## IAM-ключи и секреты внутри бакетов

Открытый на чтение бакет — это ещё не доступ, но часто внутри лежат **ключи доступа**, и вот они уже опасны. Что искать: AWS Access Key ID (начинается с `AKIA`/`ASIA`) вместе с `aws_secret_access_key`; Google service-account JSON (`"type": "service_account"`, поле `private_key`); Azure connection string (`DefaultEndpointsProtocol=...;AccountKey=...`); файлы `.env`, `terraform.tfstate`, `credentials`, `id_rsa`. Найдя такой ключ, **не используйте** его для доступа к чужим ресурсам — это выход за рамки находки и часто прямое нарушение закона. Правильное действие: зафиксировать факт утечки (путь к файлу, префикс ключа, время) и передать владельцу через программу. Ключи, найденные в публичном бакете, — критическая находка независимо от того, активны ли они: их наличие уже говорит о гигиене секретов.

## Практика: полный сценарий разведки облака

Соберём всё в один проход для цели `example.com`. Сначала пассивно ищем имена: `gau example.com | grep -Eo 'https?://[^ ]*(s3|blob\.core|googleapis|cloudfront|firebaseio)[^ ]*' | sort -u`, затем дорки `site:s3.amazonaws.com "example"`. Из найденных URL выписываем бренд-токены (`example-static`, `example-backup`) и генерируем словарь с суффиксами (`-dev`, `-prod`, `-logs`, `-media`, `-uploads`, `-assets`). Запускаем `cloud_enum -k example -k examplecorp` и `s3scanner -bucket-file names.txt -enumerate`. Для каждого найденного бакета фиксируем код ответа, права и первые ключи листинга. Отдельно проверяем Firebase (`curl -s https://example.firebaseio.com/.json`) и Azure (`?restype=container&comp=list`). Результат — таблица `bucket, provider, read, write, sample_keys, source`. Всё, что вне авторизованного scope, не проверяем на запись и не скачиваем целиком.

## Быстрая шпаргалка по облакам

| Задача | Команда |
|---|---|
| S3 листинг | `curl -s "https://<b>.s3.amazonaws.com/?list-type=2"` |
| S3 объект | `curl -sI "https://<b>.s3.amazonaws.com/<key>"` |
| Azure контейнеры | `curl -s "https://<acct>.blob.core.windows.net/?comp=list"` |
| GCS | `curl -s "https://storage.googleapis.com/<b>"` |
| Firebase RTDB | `curl -s "https://<id>.firebaseio.com/.json"` |
| Перебор | `cloud_enum -k <brand>` |
| Права | `s3scanner -bucket-file names.txt -enumerate` |
| Бакеты из архивов | `gau example.com \| grep -Ei 's3\|blob\|googleapis'` |

Коды: `200` — доступ, `403` — есть/закрыт, `404` — нет. Проверку записи делайте только с разрешения.

## Квиз

```quiz
- question: "Как отличить существующий закрытый S3-бакет от несуществующего?"
  options:
    - "`403 AccessDenied` — бакет есть, `404 NoSuchBucket` — нет"
    - "Оба возвращают 200"
    - "По размеру ответа нельзя"
    - "Никак"
  answer: 0
- question: "Что такое `cloud_enum`?"
  options:
    - "Инструмент перечисления облачных ресурсов (S3/Azure/GCS) по имени"
    - "Сканер портов"
    - "Поисковик изображений"
    - "Генератор паролей"
  answer: 0
- question: "Откуда чаще всего узнают имя бакета?"
  options:
    - "Из JS/конфигов сайта, дорков и TLS-сертификатов"
    - "Из DNS MX-записей"
    - "Из WHOIS"
    - "Из robots.txt"
  answer: 0
- question: "Что правильно при проверке права записи?"
  options:
    - "Делать это только с разрешения, минимальным пробным объектом и сразу его удалять"
    - "Заливать реальные данные"
    - "Удалять чужие файлы"
    - "Проверять всегда, это безопасно"
  answer: 0
- question: "Какой код ответа указывает на публичный листинг S3?"
  options:
    - "`200` с XML `<ListBucketResult>`"
    - "`301`"
    - "`401`"
    - "`500`"
  answer: 0
```

## Где пригодится

- **Bug bounty:** поиск открытых бакетов с данными — частый класс находок.
- **Cloud audit:** инвентаризация облачных активов организации.
- **CTF (OSINT):** найти публичный бакет с подсказкой/флагом.
- **Пентест:** расширение поверхности через облачные ресурсы.
