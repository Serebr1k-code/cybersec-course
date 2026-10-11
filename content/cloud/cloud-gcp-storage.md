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

## Зачем этот урок

Cloud Storage (GCS) — объектное хранилище GCP и крупнейший источник утечек. Бакеты делают публичными «на минуту» для теста и забывают; ACL оставляют открытыми; signed URL живут месяцами. Атакующего интересуют: публичные бакеты, слабые IAM-политики, утёкшие signed URLs, версии объектов (включая удалённые) и то, что бакеты иногда имеют предсказуемые имена (`company-backups`, `company-prod-assets`).

## Модель GCS

- **Bucket** — контейнер с глобально уникальным именем.
- **Object** — файл; у него есть поколения (generations) и метаданные.
- **IAM** — роли на бакет/объект (`roles/storage.objectViewer` и т.п.), наследуются от проекта.
- **ACL** — per-object/per-bucket гранты (legacy). При **uniform bucket-level access** (UBLA) ACL отключены, и всё решает IAM.
- **Signed URL** — временная ссылка с подписью, дающая доступ без аутентификации.
- **Object versioning** — хранит старые поколения; soft-delete хранит удалённые объекты.
- **Public access prevention** — организация может запретить публичность на уровне org policy.

Ключевые права: `storage.buckets.list`, `storage.objects.get`, `storage.objects.list`, `storage.buckets.getIamPolicy`, `storage.objects.getIamPolicy`.

## Инструменты и команды

```bash
# Список бакетов проекта
gcloud storage buckets list --project PROJECT_ID
gsutil ls -p PROJECT_ID

# IAM бакета
gcloud storage buckets get-iam-policy gs://my-bucket
# allUsers с roles/storage.objectViewer = публичный бакет

# Публичный доступ
gsutil iam get gs://my-bucket | grep -A2 allUsers

# Содержимое и объекты
gcloud storage ls -r gs://my-bucket/**
gsutil ls -l gs://my-bucket/ | head

# Версии объектов (включая старые)
gsutil ls -a gs://my-bucket/secret.txt
gsutil cp gs://my-bucket/secret.txt#1699999999999999 /tmp/old-secret.txt

# Публичное чтение без аутентификации
curl -s "https://storage.googleapis.com/my-bucket/config.json" | head

# Перебор имён бакетов
for n in backups prod-assets company-data; do curl -s -o /dev/null -w "%{http_code} $n\n" "https://storage.googleapis.com/$n"; done
```

## Разобранный пример: публичный бакет → секреты

Сценарий: бакет `company-ci-artifacts` публичен.

```bash
gsutil iam get gs://company-ci-artifacts | jq '.bindings[] | select(.members[]? == "allUsers")'
# {"role":"roles/storage.objectViewer","members":["allUsers"]}

gcloud storage ls -r gs://company-ci-artifacts/**
# gs://company-ci-artifacts/builds/app-v1.2.3.tar.gz
# gs://company-ci-artifacts/secrets/prod.env
# gs://company-ci-artifacts/kube/config

gsutil cp gs://company-ci-artifacts/secrets/prod.env /tmp/
cat /tmp/prod.env
# DB_PASSWORD=...
# GCP_SA_KEY={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----..."}
```

Найденный service-account JSON-ключ даёт полноценный доступ к проекту. Даже если бакет потом закрыли, ключ продолжает работать до ротации.

## Signed URLs и versioning

- **Signed URL** — подписанная ссылка (`X-Goog-Signature`). Если она утекла в лог/репозиторий, доступ есть до истечения срока (может быть до 7 дней, иногда дольше через impersonation). Ищите в JS, мобильных приложениях, логах прокси.
- **Versioning** — включённый versioning хранит старые версии; даже если секрет «удалили», старое поколение может быть доступно. `gsutil cp 'gs://bucket/obj#GENERATION'`.
- **Soft delete** — удалённые объекты хранятся 7 дней; `storage.objects.restore` возвращает их.
- **Retention policy / Bucket Lock** — если включены, объекты нельзя удалить до срока (защита, но и источник данных).

```bash
# Восстановление удалённого объекта
gcloud storage restore gs://my-bucket/secret.txt

# Список с поколениями
gsutil ls -a gs://my-bucket/secret.txt
```

## Чек-лист атаки

1. `gcloud storage buckets list` — инвентаризация.
2. Проверить `allUsers`/`allAuthenticatedUsers` в IAM бакетов.
3. Перебрать предсказуемые имена бакетов.
4. Искать signed URLs в клиентах и логах.
5. Проверить versioning/soft-delete на чувствительных объектах.
6. Проверить `storage.buckets.getIamPolicy` и `setIamPolicy` — право менять IAM бакета.
7. Проверить наследование: право на проект (`roles/storage.admin`) даёт всё.

## Обход защит и edge cases

- **UBLA.** При uniform bucket-level access ACL отключены; смотрите только IAM. При fine-grained — ACL могут открывать объекты в обход IAM.
- **Public access prevention.** Org policy `storage.publicAccessPrevention` блокирует `allUsers`. Проверяйте, включена ли она: если нет, бакет можно сделать публичным.
- **VPC Service Controls.** Может блокировать доступ к GCS извне периметра — тогда нужен пивот внутри VPC.
- **CMEK.** Шифрование собственным ключом KMS: чтение требует `cloudkms.cryptoKeyVersions.useToDecrypt`.
- **Retention.** Bucket Lock не даёт удалить объекты — учитывайте в эксфильтрации (но чтение доступно).

## Частые ошибки и подводные камни

- Считать, что «бакет приватный», не проверив IAM и ACL.
- Игнорировать versioning: старые версии часто содержат то, что «уже удалили».
- Забыть про soft-delete (7 дней).
- Не проверить signed URLs — они не требуют аутентификации.
- Путать права проекта и бакета: `roles/storage.admin` на проекте = доступ ко всем бакетам.

## Защита и детект

- Включить uniform bucket-level access и public access prevention.
- Не хранить секреты в бакетах; использовать Secret Manager.
- Ограничить `storage.buckets.setIamPolicy` и `storage.objects.get` минимальным scope.
- Включить Cloud Audit Logs (data access) для чувствительных бакетов; алертить на аномальные чтения.
- Настроить retention/Bucket Lock для критичных данных и ротацию ключей.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `allUsers` в IAM бакета. Второй — ACL, открывающий объект. Третий — секреты в бакете (SA-ключи, `.env`). Четвёртый — versioning без контроля доступа. Пятый — signed URL с длинным сроком в публичном клиенте. Все ведут к утечке данных или ключей.

## Практическое задание

1. Создайте бакет, включите versioning, загрузите объект и перезапишите его.
2. Откройте бакет через `allUsers` и прочитайте объект без аутентификации.
3. Сгенерируйте signed URL и откройте его из другого окружения.
4. Включите public access prevention и проверьте, что публичность блокируется.

## Что дальше / решение

Из GCS достаём данные и ключи. Дальше — использовать найденные SA-ключи для доступа к проекту. Зафиксируйте путь «публичный бакет/версия → секреты» в графе. При VPC-SC или CMEK без прав — `blocked` с условием.

## Разобранный пример 2: signed URL из клиента

Signed URL — распространённая утечка: разработчик генерирует ссылку для загрузки/скачивания и она попадает в JS-бандл, мобильное приложение или лог прокси.

```bash
# Ищем подписанные ссылки в бандле
curl -s https://app.example.com/main.js | grep -oE 'https://storage.googleapis.com/[^"]*X-Goog-Signature[^"]*' | head
# https://storage.googleapis.com/company-exports/report.csv?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Expires=604800&X-Goog-Signature=...

# Используем как есть (без аутентификации)
curl -s "https://storage.googleapis.com/company-exports/report.csv?X-Goog-Algorithm=..." -o report.csv
head -3 report.csv
# id,email,plan,revenue
# 1,user@example.com,pro,1200

# Проверяем срок действия
echo "X-Goog-Expires: 604800 секунд = 7 дней"
```

Срок действия signed URL может быть до 7 дней (для SA с ключом) или до 12 часов (для impersonation). Если ссылка выдана на запись (`PUT`), можно загрузить свой объект — потенциальная подмена данных или, если объект используется как конфиг, влияние на приложение. Также проверяйте параметр `X-Goog-SignedHeaders`: иногда подпись покрывает только `host`, что позволяет менять другие заголовки.

## Практическое задание (продолжение)

1. Сгенерируйте signed URL на чтение объекта и откройте его из окружения без аутентификации.
2. Сгенерируйте signed URL на запись и загрузите объект, изменив его содержимое.
3. Включите versioning и убедитесь, что старая версия осталась доступной.
4. Включите public access prevention и проверьте, что `allUsers` больше не добавляется.

## Квиз

```quiz
- question: "Что означает член allUsers в IAM бакета?"
  options:
    - "Бакет публичен для всех, включая анонимов"
    - "Бакет только для сотрудников"
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
    - "Старые версии объектов могут содержать «удалённые» секреты"
    - "Он замедляет чтение"
    - "Он публикует бакет"
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
```

## Где пригодится

- **Пентест GCP:** аудит бакетов и поиск публичных данных.
- **Bug bounty:** облачные программы с GCS в scope.
- **Red team:** получение SA-ключей из бакетов.
- **Cloud security review:** настройка UBLA и prevention.
