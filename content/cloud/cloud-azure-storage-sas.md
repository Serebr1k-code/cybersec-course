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
lab:
  kind: shell
  title: "Практика: разбор SAS-токенов Azure"
  toolset: [core]
  workdir: /home/student/azure
  files: [task.md, sas-urls.txt, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Открой список ссылок: `cat sas-urls.txt`."
    - "Разбери параметры SAS: `sp=` — разрешения (r/w/d/l/a/c/u/p), `srt=` — тип ресурса."
    - "Найди токен с избыточными правами (`sp=rwdlacup`) — это и есть находка."
    - "Скачанное содержимое объекта с флагом лежит в `downloaded-flag.txt`. Итог: `grep nto downloaded-flag.txt > found.txt`."
---

## Задача

В клиентском коде мобильного приложения ты нашёл URL с длинным набором параметров после знака `?`. Это похоже на **SAS-токен** (Shared Access Signature) — подписанную ссылку, дающую доступ к Azure Storage. Как понять, что она открывает, и как этим воспользоваться? Задача урока — разобрать параметры SAS, прочитать данные и дойти до секретов, которые ведут к следующему ресурсу.

## Что такое Azure Storage и SAS

**Azure Storage** — четыре сервиса: **Blob** (объекты, аналогия — бакет), **File** (SMB-шары), **Queue** (очереди) и **Table** (таблицы). Доступ регулируют четыре механизма: **account key** (полный доступ), **SAS-токен** (делегированный подписанный доступ), **RBAC** (роли на данные) и анонимный доступ (публичный контейнер).

**SAS** — это подписанная строка в URL. Она действует **независимо от RBAC**: даже если у тебя нет никакой роли в Entra ID, валидный SAS откроет данные. Три типа:

| Тип | Подписан | Особенность |
|-----|----------|-------------|
| Service SAS | account key | на один сервис (blob/file/queue/table) |
| Account SAS | account key | на весь аккаунт, все сервисы |
| User delegation SAS | Entra ID | без account key, ограничен правами пользователя |

Параметры SAS (в query string):

- `sv` — версия сервиса, `ss` — сервисы (`b`/`f`/`q`/`t`), `srt` — типы ресурсов (`s`/`c`/`o`).
- `sp` — **права**: `r` read, `a` add, `c` create, `w` write, `d` delete, `l` list.
- `se` — expiry (истечение), `spr` — протокол (`https`/`http`).
- `sig` — подпись.

Слабые места, которые мы ищем: `sp=racwdl` (все права), `se` далеко в будущем, `spr=https,http` (допускает plaintext), account SAS на все сервисы.

## Данные, с которыми работаем

В мобильном приложении найден такой URL:

```
https://corpstore.blob.core.windows.net/backups?sv=2021-08-06&ss=b&srt=sco&sp=racwdl&se=2031-12-31&spr=https,http&sig=...
```

Разбираем: `sp=racwdl` — чтение, добавление, создание, запись, удаление, список. `se` в 2031 — долгий срок. `spr=https,http` — разрешён plaintext. Это полноценный доступ к контейнеру `backups`.

## Шаг 1: листим контейнер

```bash
$ SAS="?sv=2021-08-06&ss=b&srt=sco&sp=racwdl&se=2031-12-31&spr=https,http&sig=..."
$ az storage blob list --account-name corpstore --container-name backups \
    --sas-token "$SAS" --query '[].{Name:name,Size:properties.contentLength}' -o table
Name                 Size
-------------------  --------
terraform.tfstate    8192
appsettings.json     1024
prod-db-backup.sql   1048576
```

`terraform.tfstate` — state-файл Terraform, в котором часто лежат креды; `appsettings.json` — настройки приложения.

## Шаг 2: скачиваем и ищем секреты

```bash
$ az storage blob download-batch --account-name corpstore --destination ./loot \
    --source backups --sas-token "$SAS"
$ grep -rEo '(password|client_secret|access_key)"?\s*[:=]\s*"?[^",]+' ./loot | head
./loot/appsettings.json: "password": "Pr0d_P@ss!"
```

В `appsettings.json` — пароль БД, в `terraform.tfstate` — обычно service principal. Это креды для следующего шага.

## Шаг 3: права на запись — подмена конфига

Если `sp` включает `w`, можно **записать** файл. Это полезнее, чем удаление: например, `appsettings.json` в контейнере, откуда App Service подгружает настройки, или blob, который служит триггером Function. Подмена содержимого запускает чужой код от имени MI функции.

```bash
$ az storage blob upload --account-name corpstore --container-name backups \
    --name appsettings.json --file ./evil.json --sas-token "$SAS" --overwrite
```

Деструктивные действия (`d`) и подмена данных заметны и меняют состояние — согласуй перед применением.

## Шаг 4: account SAS и другие сервисы

Если SAS — account-level (`ss=bfqt&srt=sco`), он покрывает и очереди. Запись в очередь — это **инъекция в worker**: сообщение обработается воркером с его правами.

```bash
$ az storage message put --account-name corpstore --queue-name jobs \
    --content '{"cmd":"id"}' --sas-token "$SAS"
```

## Полный прогон от начала до конца

1. Нашли URL с SAS в мобильном приложении.
2. Разобрали `sp=racwdl`, `se=2031`, `spr=https,http` → широкий долгий доступ.
3. Листинг `backups` → `terraform.tfstate`, `appsettings.json`.
4. Скачали → пароль БД и service principal.
5. Если есть `w` → подмена конфига/триггера.
6. Account SAS → очередь → инъекция в воркер.

## Если не сработало

- **Firewall/private endpoint.** Аккаунт ограничен по сети — проверь `az storage account show --query networkRuleSet`; SAS не поможет, если твой IP не разрешён.
- **SAS истёк.** `se` в прошлом — ссылка мертва.
- **Только `r`.** Запись/удаление недоступны — работай на чтение.
- **User delegation SAS.** Требует `--auth-mode login`, а не account key.
- **Публичный контейнер вместо SAS.** Если контейнер уровня `container`, читай без токена: `curl "https://acct.blob.core.windows.net/backups?restype=container&comp=list"`.
- **Версии и snapshots.** Старые версии могут хранить секреты, удалённые из текущей.

## Azure Storage против AWS S3

Модели доступа у S3 и Azure Blob различаются, и это меняет подход. В AWS делегированный доступ — это **presigned URL** (подпись SigV4), а публичность задаётся bucket policy или ACL. В Azure делегирование — **SAS** с явными правами (`sp`) и сроком (`se`), а публичность — на уровне контейнера (`blob`/`container`). Практический вывод: в Azure нет «bucket policy», зато есть **account SAS**, который покрывает все сервисы сразу, — поэтому его утечка особенно опасна. Искать публичность в Azure проще: достаточно посмотреть `publicAccess` контейнера.

## OPSEC и заметность

Data-plane чтение по SAS может не писаться в Activity Log, но попадает в Storage diagnostic logs, если они включены. Массивное скачивание (`download-batch`) генерирует трафик и может сработать на Defender for Storage; аномальный `list` заметен. Запись в контейнер — самая громкая операция, поэтому для доказательства лучше ограничиться чтением. Помни: отзыв SAS требует ротации ключа или удаления stored access policy, то есть твоя активность может побудить защиту закрыть канал.

## Что мы теперь знаем

- SAS действует в обход RBAC — это подписанная ссылка с явными правами и сроком.
- `sp` задаёт права, `se` — срок, `spr` — протокол, `sig` — подпись.
- Account SAS шире service SAS и покрывает все сервисы, включая очереди.
- Утёкший SAS ищут в URL, логах, Referer, мобильном коде, Git.
- Права на запись позволяют подменить конфиг/триггер — это путь к RCE.

## На что смотреть дальше

- **cloud-azure-blob-deep**: версии, soft-delete и обход сетевых ограничений.
- **cloud-terraform-state**: что делать с найденным `terraform.tfstate`.
- **cloud-exfiltration**: как аккуратно вывозить найденное.

## Глазами защитника

SAS-токены дают ограниченный доступ к Azure Storage. Ошибки: долгий срок, широкие права (`rwdl`), account SAS на все сервисы, отсутствие привязки к IP. Stored access policies позволяют отозвать SAS, но ими часто не пользуются. Защита: короткие сроки, минимальные права, привязка к IP, использование stored policies, запрет публичного доступа к контейнерам, аудит. Утечка SAS в логах или JS равносильна утечке ключа на время его жизни.

## Частые вопросы

**Чем SAS отличается от ключа аккаунта?**

SAS — ограниченный по правам и сроку токен; ключ аккаунта даёт полный контроль. Но широкий SAS по факту равен ключу на время действия.

**Что такое account SAS и service SAS?**

Account SAS покрывает несколько сервисов аккаунта; service SAS — один сервис или ресурс. Account SAS опаснее из-за широты.

**Как найти SAS-токен?**

В URL, в JS, в логах, в конфигах. Ищи параметры `sig=`, `se=`, `sp=`.

**Что дают права на запись?**

Подмену содержимого: например, конфиг или образ, который потом загрузит приложение. Это путь к RCE.

**Что такое stored access policy?**

Политика на контейнере, на которую ссылается SAS. Позволяет отозвать или изменить права, не меняя ссылку.

**Как листить контейнер?**

Через SAS: `az storage blob list --container-name X --sas-token ...`. Или напрямую REST-запросом.

**Как защититься?**

Короткие SAS, минимальные права, привязка к IP, stored policies, запрет публичного доступа, аудит.

**Чем Azure Storage отличается от S3?**

Другим механизмом подписи (SAS против presigned URL) и моделью контейнеров. Логика атаки та же: утечка ссылки.

## Разбор: SAS из фронтенда

В JS-бандле приложения найден SAS-токен для контейнера с логами. Права включают `read` и `list`, срок — год. Атакующий листит контейнер и скачивает файлы, среди которых есть дампы с токенами и конфигами. Затем проверяет права: SAS позволяет и запись. Он подменяет файл конфигурации, который приложение загружает при старте, и при следующем деплое получает исполнение кода. Защита — короткий SAS с минимальными правами и stored access policy.

## Что чаще всего упускают

То, что SAS — это временный ключ, и его утечка в JS или логах равносильна утечке пароля. Проверяй срок (`se`), права (`sp`) и привязку к IP (`sip`). Второе — account SAS: он покрывает несколько сервисов и опаснее service SAS. Третье — отсутствие stored access policy: без неё SAS нельзя отозвать досрочно. Для атакующего порядок: найти SAS, определить его права, затем искать чувствительные объекты и возможность записи.

## Квиз

Проверь себя.

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
- question: "Почему account SAS опаснее service SAS?"
  options:
    - "Он покрывает все сервисы аккаунта, включая очереди и таблицы"
    - "Он не истекает"
    - "Он не требует подписи"
    - "Он работает только по http"
  answer: 0
  explanation: "Account SAS выдаётся на весь аккаунт, поэтому даёт больше поверхности."
```

## Куда дальше

В следующем уроке мы разберём **Blob Storage глубоко** — версии, soft-delete и stored access policies. А пока главное запомни: **утёкший SAS — это подписанный ключ с явными правами; читай `sp` и `se`, и не забывай, что account SAS покрывает весь аккаунт.**

## Где пригодится

- **Пентест Azure:** Storage и утёкшие SAS.
- **Bug bounty:** публичные контейнеры и SAS в клиентском коде.
- **Red team:** от Storage к Key Vault и App Service.
- **Blue team:** аудит публичного доступа и ротации SAS.
