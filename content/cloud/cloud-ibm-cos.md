---
id: cloud-ibm-cos
title: 'IBM Cloud Object Storage: HMAC-ключи и публичный доступ'
category: cloud
parent: cloud-alt-clouds
difficulty: hard
order: 3
tags: [cloud, ibm, cos, object-storage, hmac, s3, bucket]
prerequisites: [cloud-ibm-cloud]
useful_for:
  - 'Пентест IBM Cloud'
  - 'Разбор утёкших HMAC-ключей'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'IBM Cloud Object Storage: сервисные креденшелы, HMAC-ключи для S3-совместимого API, bucket policy и публичный доступ. Сквозной пример — утёкший HMAC-ключ и чтение бакета через aws-cli.'
lab:
  kind: shell
  title: 'Практика: HMAC-ключ IBM COS'
  toolset: [core]
  workdir: /home/student/ibm-cos
  files: [task.md, cos-credentials.json, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Изучи креды: `cat cos-credentials.json`. Найди hmac и endpoint.'
    - 'Определи, к какому бакету даёт доступ этот ключ.'
    - 'Флаг — в notes.md: найди строку `nto` и запиши её в found.txt.'
---

## Вопрос, с которого всё начинается

В конфигурации приложения на IBM Cloud ты находишь пару ключей, похожих на S3: `cos_hmac_keys`. Рядом — endpoint вида `s3.eu-de.cloud-object-storage.appdomain.cloud`. Вопрос: как этим пользоваться и что можно сделать без консоли IBM? Ответ прост и приятен для атакующего: IBM COS совместим с S3-API, а значит обычный `aws-cli` (или `s3cmd`) работает с ним напрямую.

## Что такое IBM Cloud Object Storage

COS — объектное хранилище IBM Cloud. Оно построено на S3-совместимом API: те же бакеты и объекты, те же операции `GET`/`PUT`/`DELETE`. Аутентификация бывает двух видов: **IAM-токен** (Bearer, от сервисного ID или пользователя) и **HMAC-ключи** (Access Key ID + Secret Access Key), которые работают как в AWS S3. Именно HMAC-ключи чаще всего утекают — они выглядят как обычные S3-креды и их копируют в конфиги.

## Сквозной пример: утёкшие креды

Смотрим файл:
```
$ cat cos-credentials.json
{
  "apikey": "EXAMPLEnotarealapikey",
  "cos_hmac_keys": {
    "access_key_id": "EXAMPLEACCESSKEY",
    "secret_access_key": "EXAMPLEnotarealsecret"
  },
  "endpoints": "https://s3.eu-de.cloud-object-storage.appdomain.cloud"
}
```
Здесь есть и API-key (для IAM), и HMAC-пара. Для атаки проще HMAC: настраиваем `aws-cli` с этим endpoint и ключами — и работаем с COS как с S3.

## Использование HMAC-ключей

Настройка профиля:
```
$ aws configure --profile cos
AWS Access Key ID: EXAMPLEACCESSKEY
AWS Secret Access Key: EXAMPLEnotarealsecret
Default region name: eu-de
```
Далее — обычные S3-команды, но с флагом endpoint:
```
$ aws --profile cos --endpoint-url https://s3.eu-de.cloud-object-storage.appdomain.cloud s3 ls
$ aws --profile cos --endpoint-url https://s3.eu-de.cloud-object-storage.appdomain.cloud s3 ls s3://acme-backups
```
Если ключ валиден, `s3 ls` перечислит бакеты, доступные этому сервисному ID. Дальше — чтение объектов.

## Права сервисного ID

HMAC-ключ принадлежит **сервисному ID** (service ID) — это «учётка для приложения», аналог service account. Права сервисного ID определяет его политика IAM: какие роли на какие сервисы. Частая ошибка — выдать сервисному ID роль `Manager` на весь COS, чтобы «не возиться». Тогда утёкший HMAC-ключ читает и пишет все бакеты аккаунта. При аудите всегда уточняй: какой сервисный ID, какие у него роли, и есть ли среди них Writer/Manager.

## Bucket policy и публичный доступ

У бакета COS есть **bucket policy** (JSON, как в S3) и **public access**. Публичный бакет отдаёт объекты по обычному HTTPS-URL без ключей. Bucket policy может разрешить анонимные `GetObject`/`ListBucket` — это тот же мисконфиг, что мы видели в OSS и S3. Проверяй оба: и креды (доступ с ключом), и policy (доступ без ключа).

## Шифрование и версии

COS поддерживает управляемое и собственное шифрование (SSE-C, Key Protect), а также версионирование. Для атакующего версионирование важно тем же, чем везде: «удалённый» объект может сохраниться в старой версии. Собственное шифрование (SSE-C) означает, что для чтения объекта нужен ещё и ключ шифрования — тогда утёкших HMAC недостаточно. Проверяй, какое шифрование включено, прежде чем считать данные доступными.

## Как проверить руками

Помимо `aws-cli`, удобен `s3cmd` или `rclone`. Минимальная проверка валидности ключа — `s3 ls` на корне endpoint. Если команда возвращает список бакетов, ключ жив и несёт хотя бы `ListBuckets`. Дальше — по бакетам, которые видны.

## Что мы теперь знаем

- IBM COS — S3-совместимое хранилище; работает с `aws-cli` через `--endpoint-url`.
- HMAC-ключи ведут себя как S3-креды и часто утекают.
- Права определяет сервисный ID и его роли IAM (Writer/Manager опасны).
- Публичный доступ даёт bucket policy и public access.
- Версионирование и SSE-C меняют картину доступа.

## Квиз

Проверь себя.

```quiz
- question: "Почему с IBM COS работает обычный aws-cli?"
  options:
    - "COS совместим с S3-API"
    - "COS использует только IAM-токены"
    - "COS — это база данных"
    - "COS требует SSH"
  answer: 0
  explanation: "IBM COS реализует S3-совместимый API, поэтому aws-cli/s3cmd/rclone работают через --endpoint-url."
- question: "Что такое HMAC-ключ в IBM COS?"
  options:
    - "Пара Access Key ID + Secret Access Key для S3-совместимого доступа"
    - "Тип бакета"
    - "Сетевой шлюз"
    - "Формат сертификата"
  answer: 0
  explanation: "HMAC-ключи — аналог S3-креденшелов, привязаны к сервисному ID."
- question: "Чем опасна роль Manager у сервисного ID?"
  options:
    - "Даёт полный контроль над всеми бакетами COS"
    - "Разрешает только чтение"
    - "Ничего не разрешает"
    - "Только логирует"
  answer: 0
  explanation: "Manager на уровне COS позволяет читать, писать и менять настройки всех бакетов."
- question: "Что даёт публичный bucket policy?"
  options:
    - "Анонимное чтение (и иногда листинг) объектов без ключей"
    - "Только ускорение"
    - "Отключение шифрования"
    - "Ротацию ключей"
  answer: 0
  explanation: "Policy с Principal * и GetObject/ListBucket открывает бакет анонимно."
- question: "Как SSE-C меняет оценку доступа при утёкшем HMAC-ключе?"
  options:
    - "Для чтения объекта нужен ещё и ключ шифрования клиента"
    - "Ключ становится публичным"
    - "Данные расшифровываются автоматически"
    - "Никак"
  answer: 0
  explanation: "При собственной схеме шифрования (SSE-C) одного HMAC-ключа недостаточно — нужен ключ шифрования."
```

## Куда дальше

В следующем уроке — Hetzner/OVH/Scaleway: bare-metal API и захват аккаунта, где вся защита сводится к одному токену. А пока главное: если хранилище S3-совместимо, работай с ним как с S3 — и проверяй и ключи, и policy.

## Где пригодится

- Пентест сред на IBM Cloud.
- Разбор утёкших S3-подобных ключей из конфигов.
- CTF-задачи категории cloud.
