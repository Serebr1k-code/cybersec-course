---
id: cloud-azure-storage-sas
title: "Azure Storage: SAS-токены, Blob и контейнеры"
category: cloud
parent: cloud-azure-deep
difficulty: medium
order: 1
tags: [cloud, azure, storage, blob, sas, containers, data]
prerequisites: [cloud-azure-deep, cloud-storage-s3]
useful_for:
  - "Пентест Azure Storage"
  - "Использование утёкших SAS-токенов"
  - "Поиск публичных контейнеров"
estimated_minutes: 45
summary: "Как устроены Azure Storage и SAS-токены, чем service/account/user-delegation SAS отличаются, как находить публичные контейнеры и использовать утёкшие токены для чтения, записи и удаления данных."
---

## Зачем этот урок

Azure Storage — это Blob (объекты), File (SMB-шары), Queue и Table. Доступ к данным регулируется четырьмя механизмами: account key (полный доступ), **SAS-токен** (делегированный, подписанный доступ), Azure RBAC (роли на данные) и анонимный доступ (публичный контейнер). SAS-токены — самая частая находка в пентесте: они утекают в URL, логах, мобильных приложениях, Git-репозиториях и сообщениях. Утёкший SAS даёт доступ **в обход учётных данных Azure** — без входа в Entra ID. Этот урок — про типы SAS, поиск публичных контейнеров, использование утёкших токенов и переход от Storage к другим ресурсам.

## Как устроен Azure Storage и SAS

Структура:

- **Storage account** — контейнер верхнего уровня (`mystorageacct`), имеет уникальное имя в глобальном namespace.
- **Blob container** — папка для блобов. Может быть `private`, `blob` (публичное чтение блобов) или `container` (публичное чтение/список).
- **Blob** — объект; есть версии, snapshots, soft delete, immutable policy.
- **File share / Queue / Table** — остальные сервисы аккаунта.

Типы SAS:

| Тип | Подписывается | Кем создаётся |
|-----|---------------|---------------|
| Service SAS | account key | для одного сервиса (blob/file/queue/table) |
| Account SAS | account key | для нескольких сервисов аккаунта |
| User delegation SAS | Entra ID (user delegation key) | без account key, ограничен правами пользователя |

Параметры SAS-токена (query string):

- `sv` — версия сервиса, `ss` — сервисы (b/f/q/t), `srt` — типы ресурсов (s/c/o).
- `sp` — разрешения (`r` read, `a` add, `c` create, `w` write, `d` delete, `l` list).
- `se` — expiry, `st` — start, `spr` — протокол (https/http).
- `sig` — подпись.

Ключевые слабости: `sp=racwdl` (все права), `se` далеко в будущем, `spr=https,http` (разрешает plaintext), account SAS на все сервисы. Плюс публичные контейнеры с `container`-доступом, где можно листить содержимое.

## Инструменты и команды

Разведка (с валидными кредами или SAS):

```bash
# Аккаунты
az storage account list --query '[].{Name:name,RG:resourceGroup,Kind:kind}'

# Контейнеры (через account key или SAS)
az storage container list --account-name mystorageacct \
  --query '[].{Name:name,PublicAccess:properties.publicAccess}'

# Публичный доступ без кредов (если контейнер container/blob)
curl -s "https://mystorageacct.blob.core.windows.net/?comp=list" | head -40

# Список блобов в контейнере
az storage blob list --account-name mystorageacct --container-name data \
  --query '[].name' --output tsv
```

Работа с SAS:

```bash
SAS="?sv=2021-08-06&ss=b&srt=sco&sp=rl&se=2030-01-01T00:00:00Z&sig=..."

# Список контейнеров
az storage container list --account-name mystorageacct --sas-token "$SAS"

# Скачать блоб
az storage blob download --account-name mystorageacct --container-name data \
  --name config.json --file ./config.json --sas-token "$SAS"

# Или напрямую curl
curl -s "https://mystorageacct.blob.core.windows.net/data/config.json$SAS" -o config.json
```

Поиск SAS в артефактах:

```bash
grep -rEo 'sig=[A-Za-z0-9%]+' . | head
grep -rEo 'https://[a-z0-9]+\.blob\.core\.windows\.net[^" ]+' . | sort -u
```

## Разобранный пример: от утёкшего SAS к данным и дальше

Сценарий: в мобильном приложении найден URL с SAS на контейнер `backups`.

Шаг 1 — разбираем параметры SAS, чтобы понять права и срок:

```
sv=2021-08-06&ss=b&srt=sco&sp=racwdl&se=2031-12-31&spr=https,http&sig=...
```

`sp=racwdl` — чтение, добавление, создание, запись, удаление, список. `se` в 2031 — долгий. `spr=https,http` — допускает plaintext. Это полноценный доступ к контейнеру.

Шаг 2 — листим контейнер и качаем бэкапы:

```bash
az storage blob list --account-name corpstore --container-name backups \
  --sas-token "$SAS" --query '[].{Name:name,Size:properties.contentLength}' --output table
az storage blob download-batch --account-name corpstore --destination ./loot \
  --source backups --sas-token "$SAS"
```

Шаг 3 — ищем секреты в бэкапах: `.env`, `terraform.tfstate`, дампы БД, `appsettings.json`, приватные ключи. Именно здесь чаще всего лежат креды для следующего шага.

Шаг 4 — если `sp` включает `w`/`d`, можно изменить или удалить данные — это уже destructive-возможность (согласуйте с заказчиком до применения). Более полезно для атаки — **запись** конфига, который читает приложение (например, `appsettings.json` в контейнере, откуда App Service грузит настройки), или **подмена** блоба, используемого Function как триггер.

Шаг 5 — если в аккаунте есть File share, монтируем его и ищем другие данные:

```bash
# Смонтировать SMB-шар (нужен account key или SAS с ss=f)
# Windows: net use Z: \\corpstore.file.core.windows.net\share /u:AZURE\corpstore <key>
```

Шаг 6 — переход к Azure-ресурсам. Storage account часто содержит ключи к Function App (триггер по блобу), логи приложений с токенами, выгрузки Key Vault. Найденные креды проверяем через `az login` и идём дальше.

## Варианты атак и обходы

- **Публичные контейнеры.** `publicAccess: container` позволяет листить и читать всё; `blob` — только читать по имени. Часто в таких контейнерах статика с чувствительными артефактами.
- **Account SAS на всё.** `ss=bfqt&srt=sco&sp=racwdl` — полный контроль аккаунта, включая очереди и таблицы.
- **SAS в логах и Referer.** Токены из URL попадают в access-логи, Referer-заголовки, APM. Ищите в Application Insights, CloudTrail-аналогах, SIEM.
- **Stored access policies.** Если SAS построен на stored access policy, его можно отозвать; но если policy слишком широкая — она опасна сама по себе.
- **User delegation SAS.** Подписан ключом делегирования пользователя; утечка даёт доступ в пределах прав пользователя, иногда на всё, что он видит.
- **Azurite/эмулятор.** Аккаунты с эмулятором и известным ключом (`devstoreaccount1`) — открытая дверь в dev-среду.
- **Table/Queue.** Account SAS даёт доступ к таблицам (данные приложений) и очередям (возможность подсунуть сообщение — инъекция в worker).
- **Immutable/soft-delete обход.** Soft-deleted блобы можно восстановить; immutable policy, наоборот, мешает удалить — но не читать.

## Частые ошибки и подводные камни

- **Путать RBAC и SAS.** SAS действует независимо от RBAC; даже если у вас нет роли на аккаунт, SAS откроет данные.
- **Не проверять `spr`.** Разрешение `http` означает, что токен может утечь в plaintext.
- **Считать `se` в будущем безопасным.** Долгий срок — это постоянный доступ; ротация невозможна без смены ключа.
- **Забывать про версии и snapshots.** Старые версии блоба могут содержать секреты, удалённые из текущей.
- **Игнорировать Firewalls.** Аккаунт может быть ограничен по сети (`networkAcls`), и ваш IP не пройдёт — проверяйте `az storage account show`.
- **Ошибка с user delegation.** Для него нужен `--auth-mode login`, а не account key.

## Защита и детект

- **Отключите анонимный доступ.** `allowBlobPublicAccess: false` на аккаунте.
- **Короткоживущие SAS с узкими правами.** `sp=r`, срок — минуты/часы, `spr=https`. Предпочитайте user delegation SAS.
- **Stored access policies** с возможностью отзыва.
- **Private endpoints и network rules** для ограничения сети.
- **Детект.** Azure Monitor/Activity Log: `ListKeys`, создание SAS через `GetServiceSas`, аномальные `GetBlob` с новых IP. Defender for Storage (advanced threat protection) флагует аномальный доступ и подозрительную активность. Алерты на скачивание большого объёма и на доступ к «backup»-контейнерам.
- **Управление ключами.** Ротация account keys, предпочтение Entra ID-аутентификации.

## Azure Storage vs AWS S3: различия для атакующего

Хотя и S3, и Azure Blob — объектные хранилища, модели доступа различаются, и это меняет подход:

| Аспект | AWS S3 | Azure Blob |
|--------|--------|------------|
| Делегированный доступ | Presigned URL (SigV4) | SAS (service/account/user-delegation) |
| Публичный доступ | Bucket policy / ACL | Container access level (`blob`/`container`) |
| Полный доступ | IAM-роль/ключ | Account key или RBAC |
| Аутентификация | SigV4 в заголовке/query | `sig` в query или Bearer-токен |
| Список | `s3:ListBucket` | `sp=l` в SAS или RBAC |
| Шифрование | SSE-S3/KMS | SSE (Microsoft-managed/CMK) |

Практический вывод: в Azure утёкший SAS — это полноценный «presigned URL» с явно прописанными правами (`sp`) и сроком (`se`); в отличие от S3 presigned URL, SAS может быть **account-level** и покрывать все сервисы. Это делает утечку account SAS особенно опасной. Зато в Azure нет понятия «bucket policy», а публичность задаётся на уровне контейнера — искать `publicAccess` проще.

## OPSEC и заметность

Azure Storage оставляет следы в диагностических логах (Storage analytics / diagnostic settings) и в Activity Log для control-plane операций. Чтение блобов по SAS может не писаться в Activity Log (data-plane), но пишется в Storage logs, если включена диагностика. Практические соображения: массивное скачивание (`download-batch`) генерирует трафик и может сработать на Defender for Storage; перечисление контейнеров заметно по аномальному `list`. Использование `http` (если разрешён `spr=https,http`) может быть перехвачено в сети. Если вы пишете в контейнер, изменение данных — самая громкая операция; для доказательства лучше ограничиться чтением. Помните, что отзыв SAS требует ротации ключа или удаления stored access policy — то есть ваша активность может побудить защиту сменить ключи и закрыть канал.

## Что дальше / решение

SAS — это делегированный доступ, и утёкший токен почти всегда стоит проверить. Алгоритм: разберите параметры (`sp`, `se`, `spr`, `srt`), листите контейнеры, скачайте и проанализируйте содержимое на секреты, проверьте права на запись. Найденные в бэкапах/конфигах креды открывают следующий ресурс — App Service, Key Vault, БД. Если SAS даёт запись, рассмотрите подмену конфигов, читаемых приложением, но согласуйте destructive-шаги. Записывайте цепочку и все найденные секреты.

## Квиз

```quiz
- question: "Что даёт SAS-токен атакующему?"
  options:
    - "Делегированный доступ к Storage в обход учётных данных Azure"
    - "Root-доступ к подписке"
    - "Доступ к Entra ID"
    - "Смену биллинга"
  answer: 0
  explanation: "SAS — подписанный URL-токен, действующий независимо от RBAC."
- question: "Какой параметр SAS задаёт права?"
  options:
    - "sp"
    - "sv"
    - "sig"
    - "se"
  answer: 0
  explanation: "sp перечисляет разрешения (r, a, c, w, d, l)."
- question: "Что означает publicAccess: container у контейнера?"
  options:
    - "Анонимное чтение и листинг содержимого"
    - "Только запись"
    - "Доступ только из Azure"
    - "Шифрование"
  answer: 0
  explanation: "container-level доступ разрешает анонимно листить и читать блобы."
- question: "Какой SAS тип не требует account key?"
  options:
    - "User delegation SAS"
    - "Account SAS"
    - "Service SAS"
    - "Blob SAS с ключом"
  answer: 0
  explanation: "User delegation SAS подписывается ключом делегирования пользователя из Entra ID."
```

## Где пригодится

- **Пентест Azure:** Storage и утёкшие SAS.
- **Bug bounty:** публичные контейнеры и SAS в клиентском коде.
- **Red team:** от Storage к Key Vault и App Service.
- **Blue team:** аудит публичного доступа и ротации SAS.
