---
id: cloud-azure-iam
title: "Entra ID и Azure RBAC: злоупотребление ролями и назначениями"
category: cloud
parent: cloud-iam-identity
difficulty: hard
order: 2
tags: [cloud, azure, entra-id, aad, rbac, privesc, service-principal, graph]
prerequisites: [cloud-azure-basics, cloud-iam-basics]
useful_for:
  - "Эскалация привилегий в Azure/Entra ID"
  - "Анализ app registrations и Microsoft Graph permissions"
  - "Атаки на гибридные AD + Entra ID среды"
estimated_minutes: 45
summary: "Как читать и злоупотреблять правами в Entra ID и Azure RBAC: роли, app permissions, административные unit'ы, гибридные связи с on-prem AD и типовые пути эскалации."
lab:
  kind: shell
  title: "Практика: Entra ID и Azure RBAC"
  toolset: [core]
  workdir: /home/student/aziam
  files: [task.md, notes.md, role-assignments.json, sp-list.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`role-assignments.json` — назначения ролей; `sp-list.json` — service principals."
    - "Ищи service principal с ролью Owner на подписку."
    - "Найди флаг: `grep nto role-assignments.json > found.txt`."

---

## Вопрос, с которого всё начинается

В Azure права устроены хитрее, чем в AWS: есть **две** системы — Entra ID (каталог пользователей) и Azure RBAC (права на ресурсы). Одна и та же учётка может быть никем в каталоге, но администратором подписки. Как это читать и где искать эскалацию? Разберём на одном сервис-принципале.

## Наш пример: сервис-принципал webapp-sp

Объект урока — сервис-принципал (service principal) `webapp-sp`, у которого есть секрет приложения. Через него мы и будем разбираться с правами.

## Шаг 1: две системы прав

**Entra ID** (бывший Azure AD) — это каталог: пользователи, группы, приложения. Здесь права дают доступ к «директории» (например, читать всех пользователей через Graph).

**Azure RBAC** — права на ресурсы: подписки, resource groups, отдельные сервисы. Здесь роли вроде `Contributor` назначаются на определённый **scope**.

Итог: чтобы понять возможности учётки, нужно проверить **обе** системы. Часто бывает так, что в RBAC — `Reader`, а в Entra ID — `Global Reader`, и второе даёт куда больше.

## Шаг 2: смотрим назначения Azure RBAC

Входим под сервис-принципалом и смотрим роли на подписке:

```
$ az login --service-principal -u c3f1d2e4-... -p 'SECRET' --tenant 72f988bf-...
$ az role assignment list --assignee c3f1d2e4-... --all --query "[].{role:roleDefinitionName, scope:scope}" -o table
Role         Scope
-----------  -------------------------------------------
Contributor  /subscriptions/11111111-...
```

`Contributor` на подписке — это права управлять почти всеми ресурсами (создавать, менять, удалять), кроме назначения ролей. Значит, из `webapp-sp` можно трогать ресурсы продакшена.

## Шаг 3: смотрим права в Entra ID (Graph)

Отдельно проверяем права приложения в каталоге. Они выдаются как **API permissions** (разрешения на Microsoft Graph):

```
$ az ad app permission list --id c3f1d2e4-...
[
  { "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [ { "id": "df021288-...", "type": "Role" } ] }
]
```

Идентификатор `00000003-...` — это Microsoft Graph. Тип `Role` означает **application permission** — право работать без пользователя. Расшифровать конкретное разрешение можно так:

```
$ az ad sp show --id 00000003-0000-0000-c000-000000000000 \
    --query "appRoles[?id=='df021288-...'].{name:displayName,value:value}"
[ { "name": "User.ReadWrite.All", "value": "User.ReadWrite.All" } ]
```

`User.ReadWrite.All` — право читать и менять всех пользователей каталога. Это очень серьёзно: можно сбросить пароль админу и войти под ним.

## Шаг 4: получаем токен по client secret

Секрет приложения позволяет получить токен на любой ресурс, где у приложения есть права:

```
$ az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
eyJ0eXAiOiJKV1Qi...
```

С этим токеном обращаемся к Graph и перечисляем пользователей:

```
$ curl -s -H "Authorization: Bearer eyJ0eXAi..." \
    "https://graph.microsoft.com/v1.0/users?\$select=displayName,userPrincipalName" | head
{"value":[{"displayName":"Global Admin","userPrincipalName":"admin@acme.onmicrosoft.com"}, ...]}
```

Мы прочитали весь каталог. Из одного секрета приложения — доступ ко всем пользователям компании.

## Шаг 5: эскалация до полного контроля

С `User.ReadWrite.All` путь прост: сбросить пароль привилегированному пользователю и войти под ним, либо добавить себя в админ-группу. Дальше — назначение роли `Owner` на подписку и полный контроль. Другие типовые пути эскалации в Entra ID:

| Право | Что даёт |
|-------|----------|
| `User.ReadWrite.All` | сброс паролей, смена данных пользователей |
| `AppRoleAssignment.ReadWrite.All` | выдавать приложениям любые права |
| `Directory.ReadWrite.All` | менять каталог, группы |
| `RoleManagement.ReadWrite.Directory` | назначать админ-роли |

## Шаг 6: гибридные связи с on-prem AD

Если компания синхронизирует Entra ID с локальным Active Directory (через Entra Connect), появляется мощный вектор. Право `Directory.ReadWrite.All` позволяет изменить атрибуты синхронизируемой учётки — и изменения «утекут» в локальный AD. Так облачный доступ превращается в контроль над доменом. Это одна из самых серьёзных связок в гибридных средах.

## Шаг 7: как искать пути

Порядок такой: войти → посмотреть RBAC-назначения (`az role assignment list`) → посмотреть app permissions в Graph → сверить с таблицей путей. Для автоматизации есть инструменты вроде `AzureHound` и `ROADtools`, которые строят граф прав, как BloodHound для AD.

## Шаг 8: как защищаться

- принцип наименьших привилегий для сервис-принципалов;
- ограничивать `application` permissions (в отличие от delegated, они работают без пользователя);
- регулярно проверять секреты приложений и их срок;
- не давать `User.ReadWrite.All` никому, кроме явно необходимого.

## Шаг 9: административные unit'ы и PIM

Два механизма Azure стоит знать отдельно. **Administrative units** позволяют ограничить админа частью каталога: например, администратор может управлять только пользователями филиала. Если тебе выдали роль в таком unit'е, ты видишь не всех — это ограничивает разведку. **PIM** (Privileged Identity Management) делает роли **активируемыми по требованию**: админ-роль есть, но её нужно «включить» на время, иногда с MFA и обоснованием. Для атакующего PIM означает, что право может быть, но не активно прямо сейчас; иногда роль можно активировать самостоятельно. Для защитника — что даже украденная учётка не даёт мгновенных админ-прав. Оба механизма нужно проверять при оценке Azure-среды.

## Шаг 10: как быстро оценить масштаб

Собери три факта: (1) роли в Azure RBAC на подписке, (2) application permissions в Graph, (3) наличие гибридной синхронизации. Эти три пункта почти полностью определяют, что можно сделать с данной учёткой. Дальше — по таблице путей эскалации. Так за несколько команд ты понимаешь и доступ к ресурсам, и доступ к каталогу.

## Практический совет

Проверяй обе системы прав сразу: пропустишь Graph — не увидишь половину возможностей учётки. Начни с `az role assignment list` и `az ad app permission list`.

## Частые вопросы

**«Чем Entra ID отличается от Azure RBAC?»** Entra ID — каталог (пользователи, приложения), RBAC — права на ресурсы. Это две разные системы.

**«Почему роль Contributor на подписке так много даёт?»** Она позволяет управлять почти всеми ресурсами: создавать, менять и удалять их.

**«Что опаснее — роль на ресурс или право в Graph?»** Часто право в Graph: `User.ReadWrite.All` позволяет сбросить пароль админу и войти под ним.

**«Как читать application permissions?»** По идентификатору ресурса и роли: `00000003-...` — это Graph, а `Role` — работа без пользователя.

## Что мы теперь знаем

По-простому:

1. В Azure две системы прав: Entra ID и Azure RBAC.
2. RBAC назначает роли на scope ресурсов.
3. API permissions в Graph дают доступ к каталогу.
4. `User.ReadWrite.All` позволяет сбросить пароль админа.
5. Гибридная синхронизация связывает облако с локальным AD.

## На что смотреть дальше

- **Проверяй обе системы.** Каталог и ресурсы — разные права.
- **Ищи application permissions.** Они не требуют пользователя.
- **Смотри секреты приложений.** Долгоживущий секрет — риск.
- **Помни про гибрид.** Облачный доступ может дотянуться до домена.

## Что внутри токена: читаем access_token

Прежде чем что-то делать, полезно понять, **за кого** вы действуете и с какими
правами. Access-токен — это JWT, и его payload читается без секрета:

```bash
$ TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
$ echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
{
  "aud": "https://graph.microsoft.com",
  "tid": "72f988bf-...",
  "roles": ["User.ReadWrite.All", "Directory.Read.All"],
  "appid": "c3f1d2e4-...",
  "exp": 1730000000
}
```

Ключевые поля: `aud` — для какого ресурса токен (Graph или ARM),
`roles` — **application** permissions (права без пользователя), `scp` — delegated
(права в контексте пользователя), `tid` — tenant. Если в `roles` лежит
`User.ReadWrite.All` — это уже готовый путь к сбросу пароля. Если токен получен на
`https://management.azure.com` (ARM), в `roles` будут роли RBAC, а не Graph.

Обратите внимание: один секрет даёт **разные** токены на разные `aud`. Поэтому
проверяйте права отдельно для ARM и для Graph — это ровно те «две системы» из Шага 1.

## Секрет приложения против managed identity

Не всякая «личность» в Azure хранит секрет, который можно украсть. Сравните:

| Тип | Чем аутентифицируется | Риск |
|---|---|---|
| Service principal (secret) | client secret / сертификат | секрет утекает в конфиг, CI, git |
| Managed identity | платформой, секрета нет | украсть нечего, но даёт доступ из VM/функции |
| User (delegated) | пароль/MFA пользователя | фишинг, но MFA мешает |

Отсюда практическое правило: если сервис-принципал можно заменить managed
identity — секрет исчезает из кода. Для атакующего это означает, что «найти
app secret в репозитории» и «найти SSRF на VM с managed identity» — два разных
пути к одним и тем же правам.

## Практика: собрать граф прав

Вручную сверять десятки назначений тяжело. Инструменты вроде **AzureHound**
(для Azure) и **ROADtools** (для Entra ID) собирают назначения и строят граф
«кто → что может». Это аналог BloodHound: узлы — пользователи, группы, приложения,
роли; рёбра — «может назначить», «владеет», «участник». По графу ищут кратчайший
путь от вашей учётки до `Global Administrator` или до роли на подписке.

Минимальная последовательность:

```bash
$ az login --service-principal -u <APPID> -p <SECRET> --tenant <TENANT>
$ az role assignment list --all --query "[].{p:principalName, r:roleDefinitionName, s:scope}" -o table
$ az ad app permission list --id <APPID>
$ az ad group member list --group "Global Administrators" 2>/dev/null
```

Первая команда показывает, на что вы можете влиять на ресурсах; вторая — что можно
в каталоге; третья — кто уже сидит в самой сильной роли (потенциальная цель для
сброса пароля).

## Квиз

Проверь себя.

```quiz
- question: "Какие две системы прав есть в Azure?"
  options:
    - "Entra ID (каталог) и Azure RBAC (ресурсы)"
    - "IAM и KMS"
    - "S3 и EC2"
    - "DNS и CDN"
  answer: 0
  explanation: "Каталог и ресурсы управляются по-разному."
- question: "На что назначается роль в Azure RBAC?"
  options:
    - "На scope: подписку, resource group или ресурс"
    - "На пользователя ОС"
    - "На бакет"
    - "На регион DNS"
  answer: 0
  explanation: "Scope определяет область действия роли."
- question: "Что означает тип Role (application permission) в Graph?"
  options:
    - "Приложение работает без пользователя, со своими правами"
    - "Право только для чтения"
    - "Требуется MFA"
    - "Право истекает за час"
  answer: 0
  explanation: "Application permissions не зависят от пользователя."
- question: "Какое право позволяет сбросить пароль любому пользователю?"
  options:
    - "User.ReadWrite.All"
    - "s3:GetObject"
    - "Contributor"
    - "Reader"
  answer: 0
  explanation: "Оно даёт менять данные всех пользователей каталога."
- question: "Чем опасна гибридная синхронизация с AD?"
  options:
    - "Изменения в облаке могут утечь в локальный домен"
    - "Она ускоряет вход"
    - "Она шифрует пароли"
    - "Она отключает RBAC"
  answer: 0
  explanation: "Через синхронизацию облачный доступ дотягивается до домена."
```

## Куда дальше

Мы разобрали Azure. Дальше — **GCP**: сервисные аккаунты и имперсонация, где права «примерить» другую личность выражаются явным permission. А пока запомни главное: в Azure смотри обе системы прав, а права приложения в Graph часто опаснее ролей на ресурсы.

## Где пригодится

- **CTF (Cloud):** Azure-задачи с сервис-принципалами.
- **Bug bounty:** over-permissive app registrations.
- **Пентест:** аудит RBAC и Graph permissions.
- **Blue team:** минимизация application permissions и ротация секретов.
