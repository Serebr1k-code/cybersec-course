---
id: cloud-azure-blob-deep
title: "Azure Blob Storage глубоко: доступ, SAS, версии и soft-delete"
category: cloud
parent: cloud-azure-storage-sas
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

## Задача

Ты нашёл в Azure аккаунт хранилища **Blob Storage** — объектное хранилище, аналог «бакета». Как понять, что из него можно прочитать, и как достать данные, даже если часть из них «удалена»? В отличие от простого бакета, у Blob богатая модель доступа: уровни публичности, несколько типов **SAS**, версии и soft-delete. Именно из-за гибкости здесь чаще всего встречаются мисконфиги. Задача урока — научиться читать, восстанавливать и обходить сетевые ограничения.

## Что такое Blob и его модель доступа

**Blob** — один объект (файл) в контейнере. **Контейнер** — группа blob'ов. Аккаунт хранилища содержит контейнеры.

Уровни публичного доступа контейнера:

- `Private` (по умолчанию) — нужна авторизация.
- `Blob` — анонимно читаются отдельные blob'ы, если знаешь имя.
- `Container` — анонимно доступен и **листинг** всех blob'ов, и чтение.

**SAS (Shared Access Signature)** — подписанная ссылка, дающая ограниченный доступ. Бывает:

- **User delegation** — подписана Entra ID, до 7 дней, отзывается.
- **Service** — подписана ключом аккаунта, на один сервис.
- **Account** — самый широкий, на весь аккаунт и все сервисы.
- **Stored access policy** — именованная политика на контейнер, на которую ссылается SAS; её можно отозвать.

Плюс **версионирование** (хранит старые версии объектов), **soft-delete** (хранит удалённые) и **immutable/WORM** (запрещает изменение). Ключевые права RBAC: `.../blobs/read`, `.../write`, `listKeys`, `listServiceSas`.

## Данные, с которыми работаем

Инвентаризация аккаунтов и проверка публичности:

```bash
$ az storage account list --query '[].{Name:name,Public:allowBlobPublicAccess}' -o table
Name        Public
----------  --------
mystorage   True
```

`allowBlobPublicAccess=True` — публичный доступ разрешён. Смотрим контейнеры:

```bash
$ az storage container list --account-name mystorage --auth-mode login -o table
Name      PublicAccess
--------  --------------
backups   container
```

Контейнер `backups` имеет уровень `container` — анонимный листинг. Это цель.

## Шаг 1: анонимный листинг

```bash
$ curl -s "https://mystorage.blob.core.windows.net/backups?restype=container&comp=list" \
    | grep -oE '<Name>[^<]+</Name>' | sed 's/<[^>]*>//g'
db-backup-2024-03-01.sql
secrets.env
app-config.json
```

Три файла. Имена говорящие: дамп базы и файл с секретами.

## Шаг 2: скачиваем секреты

```bash
$ curl -s "https://mystorage.blob.core.windows.net/backups/secrets.env" -o secrets.env
$ cat secrets.env
DB_CONNECTION=Server=prod-sql.database.windows.net;User=sqladmin;Password=Pr0d_P@ss!
STORAGE_KEY=7f3a9...==
```

Мы получили строку подключения к БД и ключ другого хранилища. Ключ `STORAGE_KEY` позволяет подписывать свои SAS — то есть двигаться дальше.

## Шаг 3: версии и soft-delete

Допустим, секрет уже «ротировали» и перезаписали. Но если включено версионирование, старые значения остались:

```bash
$ curl -s "https://mystorage.blob.core.windows.net/backups/secrets.env?comp=versions" | grep -oE '<VersionId>[^<]+' | head
<VersionId>2024-02-01T10:00:00.0000000Z
```

Читаем старую версию (в URL добавляется `versionid`). А если blob **удалили**, при включённом soft-delete (по умолчанию 7 дней) его можно вернуть:

```bash
$ curl -s -X PUT "https://mystorage.blob.core.windows.net/backups/secrets.env?comp=undelete&timeout=30"
```

Проверяй оба механизма: версии дают прошлые секреты, soft-delete — удалённые.

## Шаг 4: stored access policy

Иногда доступа «в лоб» нет, но есть **stored access policy** с широкими правами и длинным сроком — по сути ключ к контейнеру на годы:

```bash
$ az storage container policy list --container-name data --account-name mystorage --auth-mode login
{"full-policy":{"permissions":"racwdl","expiry":"2030-01-01"}}
$ az storage container generate-sas --name data --account-name mystorage \
    --policy-name full-policy --auth-mode login
se=2030-01-01&sp=racwdl&sv=...&sig=...
```

`racwdl` — read/add/create/write/delete/list. Отозвать такой доступ можно только изменением политики, что требует прав на контейнер.

## Полный прогон от начала до конца

1. `az storage account list` → `allowBlobPublicAccess=True`.
2. `az storage container list` → `backups` уровня `container`.
3. Анонимный листинг → `secrets.env`, дамп БД.
4. Скачали `secrets.env` → строка подключения к БД и `STORAGE_KEY`.
5. `comp=versions` / `comp=undelete` → прошлые и удалённые секреты.
6. Ключом `STORAGE_KEY` подписали SAS → доступ к другим контейнерам.

## Если не сработало

- **Public access выключен.** `allowBlobPublicAccess=False` — анонимного чтения нет, нужен SAS или ключ.
- **Private endpoint / firewall.** Даже валидный SAS вернёт ошибку, если ваш IP не разрешён — нужен пивот в VNet.
- **Trusted Azure services.** Некоторые сервисы (Azure Backup, Logic Apps) ходят в Storage в обход firewall — это confused deputy, ищи доступ через них.
- **Уровень `Blob`.** Листинга нет, но отдельный blob читается, если знаешь точное имя — перебирай типовые имена.
- **Account SAS утёк.** Проверь в ссылке `signedServices`, `signedResourceTypes`, `signedPermission` — account SAS с `rwdlacup` на всё это ключ ко всему аккаунту.
- **Иммутабельность.** Retention/legal hold мешают удалить, но не читать; помни, что твои перезаписи оставляют версии — след в логах.

## Обход сетевых ограничений

Если `publicNetworkAccess` выключен и стоит private endpoint, из интернета доступа нет — нужен пивот в VNet, и SAS тут не поможет. Проверяй правило firewall:

```bash
$ az storage account show --name mystorage --query '{net:networkRuleSet,public:publicNetworkAccess}'
{"net":{"defaultAction":"Deny","ipRules":[...]},"public":null}
```

Иногда в `ipRules` встречается широкий диапазон или `0.0.0.0/0`. Отдельный приём — **trusted Azure services**: сервисы вроде Azure Backup или Logic Apps ходят в Storage в обход firewall. Если ты можешь заставить такой сервис прочитать blob (confused deputy), сеть тебя не остановит.

## Сравнение с AWS S3

У S3 и Blob похожая логика, но разные механизмы: в S3 делегированный доступ — это presigned URL, а публичность задаётся bucket policy/ACL; в Azure — SAS с явными правами и уровни контейнера. У S3 нет «account-level» presigned URL, а в Azure **account SAS** покрывает все сервисы сразу — это делает его утечку особенно опасной. Зато в Azure нет аналога bucket policy, и публичность видна проще: достаточно посмотреть `publicAccess` контейнера.

## Что мы теперь знаем

- `Container`-уровень = анонимный листинг и чтение; `Blob` — только чтение известных имён.
- Типы SAS различаются по охвату: account шире service; user delegation отзывается.
- Stored access policy с `racwdl` и сроком до 2030 — фактически ключ.
- Версии и soft-delete возвращают «старые» и «удалённые» секреты.
- Firewall/private endpoint блокируют доступ независимо от SAS.

## На что смотреть дальше

- **cloud-azure-storage-sas**: устройство SAS и генерация ссылок.
- **cloud-terraform-state**: state-файлы часто лежат в Blob и содержат креды.
- **cloud-exfiltration**: как вывозить найденные данные.

## Глазами защитника

Blob Storage защищают запретом публичного доступа на уровне аккаунта (`allowBlobPublicAccess: false`), private endpoints, узкими SAS, stored access policies, soft-delete и versioning. Ключи аккаунта ротируют, SAS делают короткими. Диагностические логи показывают доступ. Аудит: какие контейнеры публичны, где лежат SAS, включены ли soft-delete и versioning.

## Частые вопросы

**Чем Blob отличается от S3 по модели доступа?**

Уровнями доступа (private, blob, container) и SAS вместо presigned URL. Контейнер может быть публичным на чтение.

**Что такое уровни доступа?**

Private (только по авторизации), Blob (анонимное чтение объектов по URL), Container (анонимный листинг и чтение). Ошибка — выставить Blob или Container.

**Что даёт SAS на запись?**

Подмену содержимого: конфиг, образ, статику. Если приложение загружает это, путь ведёт к RCE.

**Как работают версии и soft-delete?**

Версии хранят прошлые состояния объекта; soft-delete сохраняет удалённое. Оба могут раскрыть «удалённые» секреты.

**Что такое stored access policy?**

Политика на контейнере, на которую ссылается SAS; позволяет отозвать доступ, не меняя саму ссылку.

**Как листить контейнер анонимно?**

REST-запрос `GET https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list` вернёт список при публичном доступе.

**Как защититься?**

Отключить публичный доступ на аккаунте, private endpoints, короткие SAS, stored policies, soft-delete и версии.

**Чем это отличается от базового урока?**

Здесь фокус на версиях, soft-delete и stored access policies — механизмах, которые переживают удаление и отзыв.

## Разбор: публичный контейнер и soft-delete

Контейнер выставлен на уровень Container, поэтому атакующий анонимно листит его и скачивает конфиги. Найдя в них SAS с правом записи, он подменяет статический файл приложения. Даже после того как защитник удаляет файл, soft-delete и версии позволяют прочитать его снова — и атакующий возвращается к данным. Защита — запрет публичного доступа, короткие SAS и контроль версий.

## Что чаще всего упускают

Уровни доступа контейнера: Blob и Container открывают анонимный доступ, и это легко не заметить при работе через портал. Второе — версии и soft-delete: «удалённые» данные остаются читаемыми, если есть доступ к контейнеру. Третье — account SAS: он покрывает несколько сервисов и опаснее service SAS. Вывод: проверяй уровень доступа, SAS-токены и настройки версий.

**Опасна ли immutability policy?**

Нет, наоборот: она запрещает изменение и удаление объектов на срок, защищая от подмены и ransomware. Если её нет, бэкапы уязвимы к подмене.

**Что если аккаунт запрещает публичный доступ, но есть SAS?**

SAS работает независимо от уровня доступа: ссылка даёт доступ даже к private-контейнеру. Поэтому утечка SAS опасна всегда.

## Квиз

Проверь себя.

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
- question: "Какой SAS самый широкий по охвату?"
  options:
    - "Account SAS — на весь аккаунт и все сервисы"
    - "Service SAS"
    - "User delegation SAS"
    - "Stored access policy"
  answer: 0
  explanation: "Account SAS может включать все сервисы и типы ресурсов — это ключ ко всему аккаунту."
```

## Куда дальше

В следующем уроке мы разберём **SAS-токены** подробнее — как они подписываются, где утекают и как их проверять. А пока главное запомни: **в Blob «удалённое» часто доступно через версии и soft-delete, а один утёкший account SAS равен ключу ко всему аккаунту.**

## Где пригодится

- **Пентест Azure:** аудит Storage.
- **Red team:** чтение и запись данных через SAS.
- **Cloud IR:** восстановление удалённых данных.
- **Сертификация:** AZ-500.
