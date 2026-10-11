---
id: cloud-azure-blob-deep
title: "Azure Blob Storage глубоко: доступ, SAS, версии и soft-delete"
category: cloud
parent: cloud-azure-data-deep
difficulty: hard
order: 1
tags: [cloud, azure, blob, storage, sas, versioning, soft-delete, immutability]
prerequisites: [cloud-azure-data-deep, cloud-azure-storage-sas]
useful_for:
  - "Пентест Azure Storage"
  - "Использование SAS и восстановление данных"
  - "Обход сетевых ограничений Storage"
estimated_minutes: 50
summary: "Azure Blob: уровни доступа (private/blob/container), account vs service SAS, stored access policies, версии, soft-delete и immutable. Как читать и восстанавливать данные."
---

## Зачем этот урок

Azure Blob Storage — крупнейшее объектное хранилище Azure. В отличие от простого «бакета», у него богатая модель доступа: уровни публичного доступа, несколько типов SAS, stored access policies, сетевые ограничения, версионирование и soft-delete. Именно из-за гибкости здесь чаще всего встречаются мисконфиги: контейнер `Blob`-уровня с чувствительными файлами, account-level SAS с широкими правами, открытые stored access policies. Для атакующего важно уметь и читать данные, и восстанавливать «удалённое», и обходить сетевые ограничения.

## Модель доступа Blob

- **Public access level**: `Private` (по умолчанию), `Blob` (анонимное чтение отдельных blob'ов), `Container` (анонимный listing + чтение).
- **SAS (Shared Access Signature)**: user delegation (Entra ID), service (на сервис), account (на весь аккаунт). Параметры: ресурсы (`s`ervice/`c`ontainer/`o`bject), права (`r`/`w`/`d`/`l`/`a`/`c`), срок, IP.
- **Stored access policy**: именованная политика на контейнер, на которую ссылается SAS; позволяет отзывать доступ.
- **Networking**: `publicNetworkAccess`, firewall (selected networks), private endpoints.
- **Versioning / soft-delete / immutable (WORM)**: хранение версий и удалённых blob'ов.

Ключевые права RBAC: `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read`, `.../write`, `listKeys`, `listServiceSas`.

## Инструменты и команды

```bash
# Инвентаризация аккаунтов и контейнеров
az storage account list --query '[].{Name:name,RG:resourceGroup,Public:allowBlobPublicAccess}' --output table
az storage container list --account-name mystorage --auth-mode login -o table

# Уровень доступа контейнера
az storage container show-permission --name public --account-name mystorage --auth-mode login
# "publicAccess": "container"

# Анонимное чтение (без кредов)
curl -s "https://mystorage.blob.core.windows.net/public/config.json" | head
curl -s "https://mystorage.blob.core.windows.net/public?restype=container&comp=list" | head -c 300

# SAS: получить/сгенерировать
az storage container generate-sas --name data --account-name mystorage \
  --permissions racwdl --expiry 2030-01-01 --auth-mode login

# Список ключей аккаунта (если есть права)
az storage account keys list --account-name mystorage --query '[].value'
```

## Разобранный пример: контейнер Container-уровня → данные и SAS

Сценарий: контейнер `backups` имеет публичный доступ `container`.

```bash
# 1. Листинг без аутентификации
curl -s "https://mystorage.blob.core.windows.net/backups?restype=container&comp=list" \
  | grep -oE '<Name>[^<]+</Name>' | sed 's/<[^>]*>//g'
# db-backup-2024-03-01.sql
# secrets.env
# app-config.json

# 2. Скачиваем секреты
curl -s "https://mystorage.blob.core.windows.net/backups/secrets.env" -o secrets.env
cat secrets.env
# DB_CONNECTION=...
# STORAGE_KEY=...

# 3. Если включено версионирование — смотрим версии
curl -s "https://mystorage.blob.core.windows.net/backups/secrets.env?comp=versions" | head

# 4. Восстанавливаем удалённый blob (soft-delete)
curl -s -X PUT "https://mystorage.blob.core.windows.net/backups/secrets.env?comp=undelete&timeout=30"
```

Даже если blob «удалён», soft-delete (по умолчанию включён, 7 дней) позволяет его вернуть. Версии дают доступ к прошлым значениям секретов, которые ротировали. Проверяйте оба механизма.

## Типы SAS и их злоупотребление

| Тип SAS | Область | Особенность |
|---|---|---|
| User delegation | Entra ID, до 7 дней | Без ключа аккаунта; отзывается |
| Service | Сервис (blob/file/queue/table) | Подписан ключом аккаунта |
| Account | Весь аккаунт | Самый широкий; может включать все сервисы |
| Stored access policy | Контейнер | Позволяет отзывать через политику |

Account SAS с правами `rwdlacup` на все сервисы — фактически ключ ко всему аккаунту. Если такой SAS утёк (в логах, JS, мобильном приложении) — атакующий читает и пишет всё. Проверяйте `signedServices`, `signedResourceTypes`, `signedPermission` в утёкшей ссылке.

## Обход сетевых ограничений

- **Public network access disabled + private endpoint.** Из интернета доступа нет; нужен пивот в VNet. SAS тоже не поможет, если firewall блокирует ваш IP.
- **Firewall (selected networks).** Разрешённые сети/IP; иногда в списке есть `0.0.0.0/0` или админский диапазон.
- **Trusted Azure services.** Некоторые сервисы (Azure Backup, Logic Apps) ходят в Storage в обход firewall — это confused deputy.
- **Private endpoint.** Доступ только из VNet; проверяйте DNS-резолв (`*.privatelink.blob.core.windows.net`).

```bash
az storage account show --name mystorage --query '{net:networkRuleSet,public:publicNetworkAccess}'
```

## Чек-лист атаки

1. `allowBlobPublicAccess` и уровни контейнеров.
2. Анонимный listing/чтение.
3. Утёкшие SAS (account/service/user delegation).
4. Stored access policies (можно ли использовать/отозвать).
5. Версии и soft-delete.
6. Сетевые ограничения и private endpoints.
7. Ключи аккаунта (`listKeys`) — если есть права, генерируйте SAS сами.

## Частые ошибки и подводные камни

- Считать `Blob`-уровень «безопасным»: отдельные blob'ы читаются анонимно, если имя известно.
- Не проверить soft-delete/versioning: «удалённое» часто доступно.
- Путать account SAS и service SAS по объёму прав.
- Игнорировать stored access policies: они позволяют отзывать доступ, но и злоупотреблять.
- Забыть про firewall: SAS без доступа к сети бесполезен.

## Защита и детект

- Запретить публичный доступ (`allowBlobPublicAccess=false`) и включить `publicAccessPrevention`.
- Использовать user delegation SAS с коротким сроком и stored access policies.
- Ограничить сеть (private endpoints, firewall), включить `defaultAction=Deny`.
- Включить versioning, soft-delete и immutable для критичных данных.
- Ограничить `listKeys`/`listServiceSas`; включить Storage analytics/diagnostic logs и алертить.

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — контейнер `Container`-уровня с данными. Второй — account SAS на 5 лет в клиенте. Третий — секреты в blob'ах. Четвёртый — `0.0.0.0/0` в firewall. Пятый — soft-delete без контроля. Все они ведут к утечке данных и ключей.

## Практическое задание

1. Создайте аккаунт, контейнер `Container`-уровня и прочитайте blob анонимно.
2. Сгенерируйте service SAS на чтение и используйте его.
3. Включите versioning, перезапишите blob и прочитайте старую версию.
4. Включите firewall и убедитесь, что анонимный доступ блокируется.

## Что дальше / решение

Из Blob достаём данные и ключи. Дальше — использовать найденные SAS/ключи. Зафиксируйте путь «публичный контейнер/версия → данные» в графе. При private endpoint без пивота — `blocked`.

## Разобранный пример 2: stored access policy и отзыв

Stored access policy — именованная политика на контейнере, на которую ссылается SAS. Она позволяет отзывать доступ, меняя политику. Но если политика разрешает широкие права, ей можно злоупотребить.

```bash
# Список stored access policies контейнера
az storage container policy list --container-name data --account-name mystorage --auth-mode login
# {"read-policy":{"permissions":"r","expiry":"2030-01-01"},"full-policy":{"permissions":"racwdl","expiry":"2030-01-01"}}

# Генерируем SAS на основе политики
az storage container generate-sas --name data --account-name mystorage \
  --policy-name full-policy --auth-mode login
# se=2030-01-01&sp=racwdl&sv=...&sig=...

# Используем SAS
curl "https://mystorage.blob.core.windows.net/data/config.json?se=2030-01-01&sp=racwdl&sv=...&sig=..." | head
```

Если политика `full-policy` имеет права `racwdl` (read/add/create/write/delete/list) и срок до 2030 — по сути это ключ ко всему контейнеру на годы. Отзыв возможен только изменением/удалением политики, что требует прав на контейнер. Проверяйте, нет ли политик с длинным сроком и широкими правами, и есть ли у вас право их менять.

## Иммутабельность, retention и восстановление

Immutable storage (WORM) и retention policies защищают данные от удаления, но их тоже нужно понимать.

```bash
# Проверяем immutable policy и retention
az storage container immutability-policy show --container-name data --account-name mystorage 2>/dev/null
az storage container legal-hold show --container-name data --account-name mystorage 2>/dev/null

# Восстановление удалённого контейнера (soft-delete на уровне контейнера)
az storage container restore --name data --deleted-version 01DA... --account-name mystorage

# Список удалённых контейнеров
az storage container list --include-deleted --account-name mystorage
```

Retention policy может запрещать удаление объектов до определённого срока — это защита целостности, но также означает, что ваши изменения останутся в истории. Legal hold блокирует удаление до снятия. Для атакующего важно: если включён versioning, ваши перезаписи создают новые версии, а старые сохраняются — следы остаются. Учитывайте это в OPSEC.

## Квиз

```quiz
- question: "Чем уровень доступа Container отличается от Blob?"
  options:
    - "Container разрешает анонимный listing и чтение, Blob — только чтение известных blob'ов"
    - "Они идентичны"
    - "Blob разрешает запись"
    - "Container приватный"
  answer: 0
  explanation: "Container даёт listing, Blob — нет."
- question: "Почему versioning опасен для владельца?"
  options:
    - "Старые версии могут содержать прежние секреты"
    - "Он удаляет данные"
    - "Он публикует контейнер"
    - "Он меняет регион"
  answer: 0
  explanation: "Версии хранят прошлые значения объектов."
- question: "Что восстанавливает soft-delete?"
  options:
    - "Удалённые blob'ы в течение срока хранения"
    - "Ключи аккаунта"
    - "IAM-роли"
    - "VNet"
  answer: 0
  explanation: "Soft-delete хранит удалённые объекты заданное число дней."
- question: "Почему SAS может не сработать при private endpoint?"
  options:
    - "Сетевые ограничения блокируют доступ вне VNet"
    - "SAS истёк"
    - "SAS только для чтения"
    - "SAS требует MFA"
  answer: 0
  explanation: "Firewall/private endpoint ограничивают сеть независимо от SAS."
```

## Где пригодится

- **Пентест Azure:** аудит Storage.
- **Red team:** чтение и запись данных через SAS.
- **Cloud IR:** восстановление удалённых данных.
- **Сертификация:** AZ-500.
