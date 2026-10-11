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

## Зачем этот урок

Azure Key Vault хранит то, ради чего атакующий идёт в облако: пароли БД, строки подключения, API-ключи, сертификаты и криптоключи. Это центральная цель цепочек «SSRF → managed identity → Key Vault → БД». Но у Key Vault есть особенность, на которой спотыкаются: **две плоскости** — management plane (ARM, `Microsoft.KeyVault/vaults`) и data plane (`.vault.azure.net`). Право видеть хранилище в ARM (роль `Reader`) **не даёт** доступа к секретам. Плюс две несовместимые модели авторизации: **access policies** (legacy) и **Azure RBAC**. Этот урок — про то, как читать обе модели, как из MI-токена добраться до секретов и как использовать soft-delete/purge.

## Как устроен Key Vault

- **Vault** — хранилище с уникальным именем (`https://myvault.vault.azure.net/`). Содержит секреты, ключи, сертификаты.
- **Secret** — именованное значение с версиями. Секреты могут быть помечены `contentType`, `enabled`, `expires`.
- **Key** — криптоключ (RSA/EC) для шифрования/подписи, может быть неэкспортируемым.
- **Certificate** — сертификат с приватным ключом, часто связан с Key.
- **Access policy (legacy)** — список разрешений на principals (`get`, `list`, `set`, `delete` для secrets/keys/certs).
- **Azure RBAC (новый)** — роли:
  - `Key Vault Reader` — видеть metadata, не значения.
  - `Key Vault Secrets User` — читать секреты.
  - `Key Vault Secrets Officer` — читать/создавать/удалять секреты.
  - `Key Vault Crypto User` — использовать ключи.
  - `Key Vault Administrator` — полный контроль data plane.
- **Soft delete** — удалённые объекты хранятся (обычно 90 дней) и могут быть восстановлены.
- **Purge protection** — запрещает окончательное удаление до истечения срока; если выключено, `purge` удаляет навсегда (destructive).
- **Network ACLs / private endpoint** — ограничение доступа по сети.
- **Managed HSM** — отдельный сервис для ключей с FIPS 140-2 Level 3; более строгий.

Важно: **authorization model задаётся на vault** (`enableRbacAuthorization`). Если он `false` — работают access policies; если `true` — RBAC. Смешения нет: включение RBAC отключает access policies.

## Инструменты и команды

Разведка vault:

```bash
az keyvault list --query '[].{Name:name,RG:resourceGroup,Rbac:properties.enableRbacAuthorization}'

# Модель доступа и политики
az keyvault show -n myvault --query 'properties.{Rbac:enableRbacAuthorization,Policies:accessPolicies}'

# Роли RBAC на vault
az role assignment list --scope $(az keyvault show -n myvault --query id -o tsv) -o table
```

Чтение секретов:

```bash
az keyvault secret list --vault-name myvault --query '[].{Name:name,Enabled:attributes.enabled}'
az keyvault secret show --vault-name myvault --name db-password --query value -o tsv
az keyvault key list --vault-name myvault
az keyvault certificate list --vault-name myvault
```

Через REST (с MI-токеном):

```bash
TOKEN=$(...)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://myvault.vault.azure.net/secrets?api-version=7.4"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://myvault.vault.azure.net/secrets/db-password?api-version=7.4"
```

Восстановление и удаление (осторожно):

```bash
az keyvault secret list-deleted --vault-name myvault
az keyvault secret recover --vault-name myvault --name old-secret
# destructive — только с согласия:
# az keyvault secret purge --vault-name myvault --name old-secret
```

## Разобранный пример: от MI-токена к БД

Сценарий: через SSRF в App Service получен MI-токен. Проверяем, что он может.

Шаг 1 — определяем identity и её права:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq '.value[].displayName'
# Может вернуть пусто, если MI не имеет прав на ARM — это нормально.
```

Шаг 2 — перечисляем vault'ы. Даже если ARM-доступ есть только на чтение, список хранилищ виден; но секреты — нет.

```bash
az keyvault list --query '[].name'
```

Шаг 3 — пробуем data plane. Токен для Key Vault должен иметь resource `https://vault.azure.net` (аудитория). Если токен получен с другим resource, нужен новый:

```bash
curl -s "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

Шаг 4 — читаем секреты:

```bash
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://prod-vault.vault.azure.net/secrets?api-version=7.4" | jq '.value[].id'
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://prod-vault.vault.azure.net/secrets/sql-conn?api-version=7.4" | jq -r '.value'
```

Шаг 5 — используем найденную строку подключения к SQL/Cosmos/Storage. Часто там же лежат ключи других сервисов. Проверяем их и двигаемся по цепочке.

Шаг 6 — если доступ только на чтение metadata (`Key Vault Reader`), но не значений, — ищите другой путь: другой vault, где MI имеет `Secrets User`, или другой principal (user-assigned MI).

## Варианты атак и обходы

- **Слишком широкие access policies.** Политика, дающая `get/list` всем secrets всем principals (включая гостей), — типовая находка.
- **Access policy на уровне vault для группы.** Если ваша группа (или гость) попала в политику, вы читаете всё.
- **RBAC-роли на высоком уровне.** `Key Vault Secrets User` на подписке/management group даёт доступ ко всем vault'ам в scope.
- **`list` без `get`.** `list` показывает имена секретов — это уже разведка; часто имена раскрывают структуру (`prod-sql-admin`, `stripe-live-key`).
- **Версии секретов.** Старые версии могут содержать действующие ключи, которые «забыли» ротировать.
- **Certificates с приватным ключом.** `Key Vault Certificates Officer`/`Secrets User` может выгрузить сертификат с ключом.
- **Managed HSM.** Отдельные роли (`Managed HSM Crypto User`); если есть доступ — ключи нельзя экспортировать, но можно использовать для операций.
- **Soft-delete recovery.** Если секрет удалили в рамках ротации, а soft-delete включён, вы можете восстановить старую версию и прочитать её.
- **ARM Reader ≠ data plane.** Не путайте: `Reader` на vault не даёт секретов, но даёт видеть access policies — а это подсказка, кто имеет доступ.

## Частые ошибки и подводные камни

- **Пробовать data plane с токеном не для `vault.azure.net`.** Нужна правильная аудитория.
- **Считать RBAC и access policies взаимозаменяемыми.** Если RBAC включён, access policies игнорируются.
- **Забывать про network ACL.** Если vault за private endpoint, публичный data-plane вернёт ошибку — нужен доступ из сети.
- **Путать management и data plane.** ARM-права не читают секреты.
- **Пробовать purge без согласования.** Это destructive; и при purge protection не сработает.
- **Игнорировать версии.** `az keyvault secret show` без `--version` даёт текущую; перебирайте версии.

## Защита и детект

- **RBAC вместо access policies.** Узкие роли (`Secrets User` только там, где нужно).
- **Purge protection включён.** Чтобы случайное/вредоносное удаление было восстановимо.
- **Private endpoint и firewall.** Ограничение доступа по сети.
- **Разделение vault'ов** по среде и назначению; секреты не «в одном большом».
- **Детект.** Azure Monitor/Activity Log: `Microsoft.KeyVault/vaults/secrets/read`, аномальные `SecretGet`, чтение многих секретов подряд. Defender for Key Vault флагует подозрительный доступ. Алерты на доступ к vault с новых IP/principal, на массовый list, на изменения access policies.
- **Ротация и срок действия.** `expires` на секретах; автоматическая ротация.

## Key Vault в цепочках и в мульти-облаке

Key Vault почти всегда — звено, а не финал. Типовые цепочки:

1. **App Service SSRF → MI → Key Vault → SQL.** Самая частая: MI имеет `Secrets User`, читаем строку подключения, идём в базу.
2. **Contributor → runCommand на VM → MI → Key Vault.** Если у VM-идентичности есть доступ к хранилищу.
3. **Key Vault → Storage → бэкапы → другие креды.** Секрет может быть ключом Storage account.
4. **Key Vault → сертификат → аутентификация приложения.** Сертификат с приватным ключом позволяет выдать себя за приложение (client credential flow).
5. **Key Vault → Key (Crypto User) → расшифровка данных.** Если у вас есть `Crypto User`, можно использовать ключ для операций (расшифровка/подпись) без экспорта.

Сравнение с AWS/GCP: AWS Secrets Manager хранит секреты с rotation и resource policies; GCP Secret Manager — с IAM на уровне секрета и версий. Azure Key Vault отличается двумя моделями авторизации (policies/RBAC) и тем, что management plane отделён от data plane. Поэтому «Reader на vault» в Azure — ложная уверенность: секреты он не отдаёт. В AWS `secretsmanager:GetSecretValue` и в GCP `secretmanager.versions.access` — это именно data-plane права, и их нужно искать отдельно.

## Практический чек-лист проверки Key Vault

1. Определите модель: `enableRbacAuthorization` true/false.
2. При RBAC — выпишите все role assignments на scope vault/подписка/MG.
3. При policies — прочитайте `accessPolicies` и найдите свои/групповые/гостевые привязки.
4. Проверьте network ACL и private endpoint — доступны ли вы по сети.
5. Получите токен с аудиторией `https://vault.azure.net`.
6. Перечислите секреты/ключи/сертификаты; обратите внимание на версии и `enabled`.
7. Проверьте soft-deleted объекты (`list-deleted`) — там могут быть старые, но действующие креды.
8. Для сертификатов — можно ли выгрузить приватный ключ.
9. Для ключей — можно ли использовать их для операций (если не экспортируемые).

Этот чек-лист отделяет «вижу хранилище» от «читаю секреты» — самая частая ошибка новичков в Azure.

## Что дальше / решение

Key Vault — цель, но не финал: найденные секреты ведут к БД, Storage, другим API. Алгоритм: определите модель доступа (RBAC или policies), проверьте data-plane с правильной аудиторией токена, прочитайте список и значения, обратите внимание на версии и сертификаты. Если есть только `list` — используйте имена для разведки. Если доступ к metadata есть, но значений нет — ищите другой vault/MI. Найденные креды проверяйте и записывайте цепочку. Помните про soft-delete: он может вернуть секрет, который защита считала удалённым.

## Квиз

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
```

## Где пригодится

- **Пентест Azure:** кража секретов и эскалация.
- **Red team:** MI → Key Vault → БД.
- **Bug bounty:** Azure-приложения и их хранилища.
- **Blue team:** аудит политик доступа и детект чтения секретов.
