---
id: cloud-azure-logic-apps
title: "Logic Apps: connector'ы, managed identity и инъекции"
category: cloud
parent: cloud-azure-platform-deep
difficulty: hard
order: 2
tags: [cloud, azure, logic-apps, workflows, connectors, managed-identity, ssrf]
prerequisites: [cloud-azure-platform-deep, cloud-azure-managed-identity]
useful_for:
  - "Пентест Azure Logic Apps"
  - "Эксплуатация connector'ов и managed identity"
  - "Поиск workflow-инъекций"
estimated_minutes: 45
summary: "Logic Apps: триггеры, действия, connector'ы и managed identity. Как low-code workflow держит креды и права, и как через инъекции в параметры получить доступ к данным и сервисам."
lab:
  kind: shell
  title: "Практика: Logic Apps, connectors и managed identity"
  toolset: [core]
  workdir: /home/student/logicapps
  files: [task.md, notes.md, workflow-definition.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`workflow-definition.json` — определение Logic App."
    - "Ищи действие с connector, использующим managed identity (доступ к ресурсам)."
    - "Найди флаг: `grep nto workflow-definition.json > found.txt`."

---

## Вопрос, с которого всё начинается

В Azure есть сервис, где бизнес-процессы собирают мышкой, без кода — **Logic Apps**. Он ходит в другие сервисы от твоего имени, держит подключения и managed identity. Казалось бы, «low-code, что там ломать». Но именно потому, что он ходит куда угодно и хранит доступы, он и интересен атакующему. Разберём один workflow.

**Logic App** — это рабочий процесс (workflow) из триггера и действий. Триггер запускает процесс, действия выполняют шаги (отправить письмо, записать в базу, вызвать API).

## Наш пример: workflow sync-users

Объект урока — Logic App `sync-users`, который по расписанию синхронизирует пользователей из системы в каталог. Допустим, у нас есть ограниченный доступ к Azure.

## Шаг 1: находим Logic App

Перечислим Logic Apps в подписке через ARM:

```
$ az logic workflow list --query "[].{name:name, state:state}" -o table
Name         State
sync-users   Enabled
alert-hook   Enabled
```

Берём `sync-users`. Посмотреть её определение (триггеры и действия) можно так:

```
$ az logic workflow show --name sync-users --resource-group rg-prod --query "definition" -o json
{
  "triggers": { "Recurrence": { "type": "Recurrence", "recurrence": { "frequency": "Hour", "interval": 1 } } },
  "actions": {
    "GetUsers": { "type": "Http", "inputs": { "method": "GET", "uri": "https://api.internal.acme/users" } },
    "WriteGraph": { "type": "ApiConnection", "inputs": { "host": { "connection": "graph-conn" } } }
  }
}
```

Читаем: workflow каждый час ходит во внутренний API и пишет в Graph через **connector** `graph-conn`.

## Шаг 2: что такое connector'ы

**Connector** — это готовое «подключение» к сервису (Graph, SharePoint, SQL, Key Vault). Внутри него хранятся креды или используется managed identity. Для атакующего connector ценен тем, что:

- действует **от имени** сервиса или пользователя;
- имеет доступ к данным (почта, файлы, каталог);
- его параметры часто приходят извне и могут быть подделаны.

Посмотрим, какие подключения у Logic App:

```
$ az resource list --resource-type Microsoft.Web/connections --query "[].{name:name, api:properties.api.name}" -o table
Name        Api
graph-conn  microsoftgraph
kv-conn     keyvault
```

Есть подключение к Graph и к Key Vault. Если workflow использует их, значит, за ним стоят реальные права на почту, каталог и секреты.

## Шаг 3: HTTP-триггер без авторизации

Многие Logic Apps запускаются HTTP-запросом. Если триггер не защищён, вызвать workflow может кто угодно:

```
$ az logic workflow show --name alert-hook --resource-group rg-prod --query "definition.triggers"
{
  "manual": {
    "type": "Request",
    "kind": "Http",
    "inputs": { "schema": { "properties": { "user": {"type": "string"} } } }
  }
}
```

Проверим, есть ли у триггера ключ или авторизация. Если нет — мы можем отправить свой запрос и запустить процесс с нашими данными.

## Шаг 4: инъекция в параметры

Самое интересное — если workflow подставляет параметры в команду, запрос или путь без проверки. Например, действие вызывает внешний API по URL, собранному из входных данных. Тогда можно подсунуть свой адрес и получить **SSRF** внутри Logic App:

```
POST https://prod-01.westeurope.logic.azure.com/workflows/.../triggers/manual/paths/invoke
{"user": "x", "callback": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"}
```

Если workflow сходит по нашему `callback` с managed identity, мы получим токен — как в уроке про managed identity, но через low-code-сервис.

## Шаг 5: managed identity Logic App

У самой Logic App может быть managed identity с правами на Key Vault, Storage, Graph. Получив возможность выполнять в ней действия (через инъекцию или правку определения), мы работаем **от её имени**. Права проверяются так же, как для любой identity: смотрим назначенные роли.

## Шаг 6: почему это недооценивают

Logic Apps воспринимают как «интеграцию», а не как поверхность атаки. Но она держит доступы к десяткам сервисов и часто запускается извне. С точки зрения безопасности это полноценное приложение: у него есть вход, логика и привилегии. Ошибка в параметрах или открытый триггер — такой же баг, как в обычном вебе.

## Шаг 7: как защищаться

- требовать авторизацию на HTTP-триггерах;
- не строить URL/команды из входных данных;
- давать managed identity минимальные права;
- ограничивать доступ к определениям workflow через RBAC.

## Шаг 8: как найти уязвимые Logic Apps

Порядок такой: перечислить все Logic Apps в подписке; для каждой посмотреть триггеры; выделить HTTP-триггеры без авторизации; проверить, какие connector'ы используются и какие права за ними; поискать действия, которые строят URL или команду из входных данных. Именно последнее даёт инъекцию. Если Logic App запускается по расписанию и ходит во внутренние API — тоже интересно: там можно найти незащищённые внутренние сервисы.

## Шаг 9: пример реального сценария

Представь Logic App, который отправляет уведомления: HTTP-триггер принимает событие от внешнего вебхука, а действие через connector к Outlook рассылает письма. Если триггер не защищён, любой может отправить своё событие — и workflow разошлёт письма **от имени компании**. Добавь сюда подстановку параметра в URL, и получишь SSRF с managed identity. Так «безобидная интеграция» превращается в рассылку фишинга на бланке компании и доступ к её облачным ресурсам.

## Шаг 10: шпаргалка по Logic Apps

Три вещи решают всё: защищён ли HTTP-триггер, какие connector'ы подключены (какие права за ними), строит ли workflow URL или команду из входных данных. Если триггер открыт и есть инъекция — ты работаешь с правами managed identity Logic App.

## Частые вопросы

**«Почему low-code — это поверхность атаки?»** Потому что workflow держит подключения к десяткам сервисов и часто запускается извне.

**«Что такое connector?»** Готовое подключение к сервису (Graph, Key Vault, SQL) с хранимыми кредами или managed identity.

**«Где искать инъекцию?»** Там, где workflow строит URL или команду из входных данных: тогда можно подсунуть свой адрес.

**«Как защититься?»** Требовать авторизацию на HTTP-триггерах, валидировать вход и давать identity минимальные права.

## Что мы теперь знаем

По-простому:

1. Logic App — workflow из триггера и действий.
2. Connector'ы держат доступы к Graph, Key Vault и другим сервисам.
3. HTTP-триггер без авторизации можно вызвать извне.
4. Инъекция в параметры даёт SSRF и доступ к managed identity.
5. Low-code — это полноценная поверхность атаки.

## На что смотреть дальше

- **Проверяй триггеры.** Открытый HTTP-триггер — вход.
- **Смотри connector'ы.** Они определяют, к чему есть доступ.
- **Ищи инъекции в параметры.** URL и команды из входа — цель.
- **Помни про identity.** Она задаёт масштаб.

## Разбор определения workflow: где искать инъекцию

Ключевое — читать определение построчно и отмечать, какие входы попадают в опасные места. Признаки инъекции:

- URL или путь собирается конкатенацией: `"uri": "https://@{triggerBody()?['host']}/api"`;
- команда формируется из входных данных (SSH/Run command через connector);
- SQL-запрос или OData-фильтр склеивается строкой;
- вызов `HTTP` с `method`/`uri`, взятыми из тела запроса.

Если хотя бы одно поле контролируется извне и не валидируется — это SSRF или инъекция. Проверяется отправкой своего значения и наблюдением, куда реально ушёл запрос (по логам run history).

## Таблица: типовые мисконфиги Logic Apps

| Мисконфиг | Последствие | Проверка |
|---|---|---|
| HTTP-триггер без авторизации | вызов извне с любыми данными | `definition.triggers.*.inputs` + отсутствие `auth` |
| URL из входных данных | SSRF, доступ к metadata | поиск конкатенаций в `uri` |
| Managed identity с ролью Contributor | эскалация ко всей подписке | `az role assignment list` |
| Секреты в параметрах workflow | утечка кред | чтение `parameters`/`actions` |
| Connector с избыточными scopes | доступ к почте/файлам | `properties.api` подключения |

## Run history как источник утечек

История запусков Logic App (`runs`) хранит входы и выходы каждого шага, включая тела запросов и ответов. Если у вас есть доступ к ней (или она экспортируется в хранилище с широкими правами), вы можете вытащить токены, URL внутренних API и персональные данные, которые проходили через workflow. Проверяется через ARM:

```
$ az rest --method get --url "https://management.azure.com/subscriptions/<id>/resourceGroups/rg-prod/providers/Microsoft.Logic/workflows/sync-users/runs?api-version=2016-06-01"
```

Часто run history включена по умолчанию и не ограничена RBAC — это отдельная, недооценённая поверхность утечки.

## Частые вопросы по детекту

**Как быстро найти опасные Logic Apps?** Выгрузите все определения и грепните по `"type": "Request"` (HTTP-триггеры) и по конкатенациям в `uri` — это два главных признака. **Что проверять у connector'ов?** Их API и scopes: connector к Graph с `Mail.Read` даёт чтение почты, к Key Vault — доступ к секретам. **Где хранятся секреты?** Часто в `parameters` определения или в подключениях; и то, и другое читается при наличии RBAC. **Что делать при отсутствии доступа к определениям?** Смотреть run history и логи — они могут раскрыть больше, чем само определение.

## Квиз

Проверь себя.

```quiz
- question: "Что такое Logic App?"
  options:
    - "Рабочий процесс из триггера и действий"
    - "База данных"
    - "Виртуальная машина"
    - "Тип бакета"
  answer: 0
  explanation: "Low-code workflow в Azure."
- question: "Что хранит connector?"
  options:
    - "Подключение и доступ к сервису"
    - "Пароль root"
    - "Ключ SSH"
    - "Правило firewall"
  answer: 0
  explanation: "Connector — готовое подключение к сервису."
- question: "Чем опасен HTTP-триггер без авторизации?"
  options:
    - "Его может вызвать кто угодно с любыми данными"
    - "Он удаляет данные"
    - "Он отключает логи"
    - "Он меняет DNS"
  answer: 0
  explanation: "Открытый вход позволяет запустить процесс извне."
- question: "Что даёт инъекция в параметры workflow?"
  options:
    - "SSRF и доступ к managed identity"
    - "Только косметику"
    - "Рост биллинга"
    - "Смену региона"
  answer: 0
  explanation: "Workflow ходит по нашему адресу с правами identity."
- question: "Как защищают Logic Apps?"
  options:
    - "Авторизация триггеров, минимальные права identity, валидация входа"
    - "Отключением HTTPS"
    - "Сменой пароля"
    - "Удалением логов"
  answer: 0
  explanation: "Это обычные меры безопасности приложения."
```

## Куда дальше

Мы разобрали Logic Apps. Дальше — **app registrations**: как приложения в Entra ID получают права через API permissions и как украденный секрет даёт постоянный доступ к Graph. А пока запомни главное: low-code-сервисы держат доступы к десяткам систем и потому заслуживают полноценного тестирования.

## Где пригодится

- **Пентест:** аудит Logic Apps и connector'ов.
- **Bug bounty:** открытые триггеры и инъекции в workflow.
- **Red team:** доступ к сервисам через low-code.
- **Blue team:** авторизация триггеров и минимизация прав identity.
