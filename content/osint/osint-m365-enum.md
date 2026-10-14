---
id: osint-m365-enum
title: 'Microsoft 365: тенант и перечисление пользователей'
category: osint
parent: osint-mod-saas-identity
difficulty: medium
order: 1
tags: [osint, m365, azure, tenant, user-enum]
prerequisites: [osint-dns-recon]
useful_for:
  - 'CTF OSINT'
  - 'Bug bounty'
  - 'Пентест: recon'
  - 'Red team'
estimated_minutes: 50
summary: 'Как по домену найти тенант Microsoft 365, узнать федерацию и получить список пользователей через открытые эндпоинты входа.'
lab:
  kind: shell
  title: 'Практика: тенант и пользователи M365'
  toolset: [core, curl, jq]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Спроси realm домена: `curl -s ''https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&json=1''`.'
    - 'Поле `NameSpaceType` покажет `Managed` или `Federated`.'
    - 'Тенант-идентификатор и маркер лежат в ответе OpenID-конфигурации.'
    - 'Запиши строку `nto{...}` в `answer.txt` и набери `check`.'
---

## Вопрос, с которого всё начинается

У тебя есть домен `example.com`. Ты почти уверен, что почта компании живёт в Microsoft 365. Но как это доказать и как узнать, какие учётные записи в тенанте существуют — не отправляя ни одного письма и не подбирая паролей?

Оказывается, сервис входа Microsoft сам отвечает на эти вопросы любому, кто спросит его правильно. Разберём, как это устроено.

## Наш пример: домен и вопрос о тенанте

Держим объект — домен `example.com`. Первый вопрос: **это управляемый тенант Microsoft или федерация с внешним IdP?** От этого зависит вся дальнейшая тактика.

Microsoft отдаёт это через эндпоинт **getuserrealm**. Он предназначен для клиентов Outlook, чтобы те знали, куда отправлять пользователя при входе, — и поэтому доступен без аутентификации.

```bash
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&json=1'
```

```json
{"State":1,"UserState":2,"Login":"user@example.com","NameSpaceType":"Managed",
 "DomainName":"example.com","FederationBrandName":"Example Corp",
 "CloudInstanceName":"microsoftonline.com"}
```

Читаем ответ: `NameSpaceType: Managed` — значит, тенант «управляемый», учётные записи живут прямо в Microsoft, а не в чужом IdP. Поле `FederationBrandName` — бренд организации. Уже отсюда мы знаем: тенант существует и домен к нему привязан.

## Шаг 1: получаем идентификатор тенанта

У тенанта есть неизменяемый **tenant ID** — GUID вида `72f988bf-...`. Он не меняется, даже если переименовать организацию, и по нему строятся все дальнейшие ссылки.

Есть два простых пути. Первый — OpenID-конфигурация:

```bash
curl -s 'https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration'
```

```json
{"token_endpoint":"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
 "issuer":"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
 "tenant_region_scope":"EU"}
```

В URL `token_endpoint` спрятан тот самый GUID. Второй путь — попросить токен для `example.com` и посмотреть поле `iss` в ответе. Оба пути дают одно и то же значение.

**tenant ID** — ключ: с ним можно обращаться к публичным метаданным тенанта, строить ссылки на вход и понимать, к какому облаку привязана организация (`tenant_region_scope: EU` — данные в Европе).

## Шаг 2: подтверждаем существование пользователей

Как проверить, существует ли конкретный пользователь, не отправляя письмо? У Microsoft есть открытые проверки, которые для существующего и несуществующего пользователя отвечают по-разному.

Исторически работал трюк с **GetCredentialType**: сервис отвечает, существует ли учётная запись, и какие методы входа ей доступны — пароль, MFA, Windows Hello. Это не аутентификация, а подсказка клиенту, как показать форму входа.

```text
POST https://login.microsoftonline.com/common/GetCredentialType
{"Username":"ceo@example.com"}

→ {"IfExistsResult":0,"ThrottleStatus":0,"Credentials":{"HasPassword":true}}
```

`IfExistsResult: 0` означает, что пользователь найден; `1` — что учётной записи нет. Аккуратно: сервис троттлит частые запросы, поэтому массовый перебор быстро приведёт к `ThrottleStatus`, и это уже заметно защите.

## Шаг 3: проверяем федерацию и внешние IdP

Если в первом шаге `NameSpaceType` был `Federated`, значит домен доверяет внешнему IdP — например, ADFS или Okta. Тогда полезно узнать адрес этого IdP: он виден в полях `AuthURL` и в CNAME-записях вида `_sipfederationtls._tcp`, `enterpriseregistration`, `enterpriseenrollment`.

```bash
dig +short CNAME enterpriseregistration.example.com
dig +short TXT _sipfederationtls._tcp.example.com
```

```text
enterpriseregistration.windows.net.
```
```text
"v=spf1 include:spf.protection.outlook.com -all"
```

Первая запись подтверждает привязку к Azure AD; SPF-запись с `outlook.com` — ещё одно независимое подтверждение, что почта в Microsoft.

## Шаг 4: что даёт этот срез

Мы получили: тенант существует, его GUID, регион данных, бренд, наличие федерации, подтверждение по DNS и признак существования пользователя. Из этого строится карта: домены организации, SSO-эндпоинт, список потенциальных учёток для авторизованного теста.

Важно: **мы не подбираем пароли**. GetCredentialType говорит лишь «есть/нет». Дальше — отдельная, отдельно авторизуемая фаза.

## Полный прогон

```bash
# 1. realm — управляемый или федерация?
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&json=1' | jq .NameSpaceType
# → "Managed"

# 2. tenant id
curl -s 'https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration' | jq -r .token_endpoint
# → .../72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token

# 3. подтверждение почты через DNS
dig +short MX example.com
# → example-com.mail.protection.outlook.com.
```

Непрерывная история: домен → realm → tenant id → подтверждение по MX → готовый профиль облака организации.

## Если не сработало

**Домен не в Microsoft.** `NameSpaceType` вернёт ошибку или пусто — проверь Google Workspace и Okta.
**Троттлинг.** GetCredentialType начал отвечать `ThrottleStatus` — остановись, не перебирай.
**Федерация.** Дальше смотри внешний IdP: ADFS, Okta, Ping — там своя разведка.

## Что мы теперь знаем

1. `getuserrealm` показывает тип тенанта без аутентификации.
2. Tenant ID добывается из OpenID-конфигурации или токена.
3. GetCredentialType подтверждает существование пользователя.
4. DNS (MX, enterpriseregistration) независимо подтверждает облако.
5. Перечисление ≠ подбор паролей; это чтение публичных метаданных.

## Справочная таблица: эндпоинты и что они дают

Все запросы ниже — без аутентификации, это публичные метаданные сервиса входа.

| Эндпоинт | Что возвращает | Зачем |
|----------|----------------|-------|
| `/getuserrealm.srf?login=` | `NameSpaceType`, бренд, `AuthURL` | тип тенанта, федерация |
| `/<domain>/v2.0/.well-known/openid-configuration` | `token_endpoint`, `issuer`, регион | tenant ID, регион данных |
| `/common/GetCredentialType` | `IfExistsResult`, методы входа | существование пользователя |
| `/common/discovery/instance` | метаданные эндпоинтов | список сервисов тенанта |
| `/<domain>/oauth2/v2.0/token` | `iss` в ответе | tenant ID из токена |

Таблица — шпаргалка: при разведке иди сверху вниз, каждый ответ подтверждай вторым источником (DNS, токен), чтобы не строить вывод на одном ответе сервиса.

## Частые ошибки и подводные камни

**Ошибка 1: считать `FederationBrandName` официальным названием компании.** Это бренд, который администратор ввёл при настройке; он может отличаться от юридического имени. Для юридической привязки используй реестры.

**Ошибка 2: перебирать GetCredentialType тысячами запросов.** Сервис троттлит, и защита видит аномалию. Достаточно нескольких подтверждающих запросов.

**Ошибка 3: путать `Managed` и `Federated`.** При `Federated` пароль проверяет внешний IdP, и логика атаки (и разведки) совсем другая — сначала изучают IdP.

**Ошибка 4: игнорировать регион.** `tenant_region_scope` говорит, где хранятся данные; это важно для понимания юрисдикции и для отчёта.

**Ошибка 5: верить одному ответу.** OpenID может кэшироваться CDN; MX может указывать на шлюз, а не на тенант. Подтверждай вторым независимым источником.

## Вопросы и ответы

**Что такое «тенант» простыми словами?** Изолированное пространство организации в облаке Microsoft: пользователи, почта, файлы, приложения. У него есть неизменяемый идентификатор — GUID.

**Почему сервис вообще отдаёт эту информацию без входа?** Клиентам (Outlook, браузеру) нужно заранее знать, куда вести пользователя при входе: в Microsoft или в его собственный IdP. Поэтому сервис отвечает на «куда идти» до аутентификации.

**Это законно?** Сами запросы — публичные. Массовый сбор данных о людях и использование его для атак — нет. В авторизованном тесте ограничься подтверждением тенанта и нескольких учёток.

**Как отличить Microsoft 365 от Google Workspace по DNS?** MX-запись: у Microsoft — `*.mail.protection.outlook.com`, у Google — `*.google.com` (или `googlemail.com`), плюс TXT-записи `MS=` и `google-site-verification`.

**Что делать, если тенант федеративен?** Найти адрес IdP: поля `AuthURL` в getuserrealm и DNS-записи `_sipfederationtls._tcp`, `enterpriseregistration`. Дальше разведка идёт по внешнему IdP.

## Разбор кейса: три домена — один тенант

Представь, что у компании три домена: `example.com`, `example-corp.com` и бренд `example.net`. Задача — понять, живут ли они в одном тенанте Microsoft.

Первый шаг — спросить realm по каждому домену:

```bash
for d in example.com example-corp.com example.net; do
  echo -n "$d: "
  curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@$d&json=1" | jq -r .NameSpaceType
done
```

```text
example.com: Managed
example-corp.com: Managed
example.net: Managed
```

Все три управляемые — уже хороший знак, но это не доказывает один тенант. Второй шаг — достать tenant ID из OpenID каждого домена и сравнить GUID:

```bash
for d in example.com example-corp.com example.net; do
  curl -s "https://login.microsoftonline.com/$d/v2.0/.well-known/openid-configuration" \
    | jq -r .token_endpoint | grep -oE '[0-9a-f-]{36}'
done
```

```text
72f988bf-86f1-41af-91ab-2d7cd011db47
72f988bf-86f1-41af-91ab-2d7cd011db47
72f988bf-86f1-41af-91ab-2d7cd011db47
```

Одинаковый GUID трижды — значит, три домена принадлежат **одному тенанту**. Это вывод, ради которого стоило работать: разведчик получил полную карту доменов организации, а не один домен.

## На что смотреть дальше

- **Подтверждай второй раз.** Один ответ сервиса — гипотеза; GUID из двух источников — факт.
- **Следи за троттлингом.** Частые запросы GetCredentialType приводят к `ThrottleStatus` и заметны защите.
- **Разделяй разведку и атаку.** Перечисление пользователей — это карта, а не вход; подбор паролей — отдельный авторизуемый шаг.
- **Фиксируй источник и время.** Метаданные тенанта меняются; отмечай, когда получен факт.

## Словарь терминов урока

**Тенант** — изолированное пространство организации в облаке: пользователи, почта, файлы, приложения. Простыми словами — «дом» компании в облаке.

**Tenant ID** — неизменяемый GUID тенанта. По нему связывают домены и однозначно опознают организацию.

**Realm** — «царство» домена в терминах сервиса входа: отвечает, где живёт учётная запись — в Microsoft или во внешнем IdP.

**Managed / Federated** — два типа тенанта. Managed: пароль проверяет Microsoft. Federated: пароль проверяет внешний поставщик входа (ADFS, Okta).

**SPF** — DNS-запись со списком серверов, которым разрешено отправлять почту от имени домена. У Microsoft она содержит `spf.protection.outlook.com`.

**Троттлинг** — ограничение частоты запросов. Сервис входа начинает отвечать отказом, если спрашивать слишком часто; это ещё и сигнал защиты.

Запомнив эти слова, ты сможешь читать ответы сервисов входа без «магии»: каждое поле — это ответ на понятный вопрос о тенанте.

## Квиз

Проверь себя.

```quiz
- question: "Что показывает поле NameSpaceType в ответе getuserrealm?"
  options:
    - "Пароль администратора"
    - "Тип тенанта: Managed или Federated"
    - "Число лицензий"
    - "IP почтового сервера"
  answer: 1
  explanation: "Managed — учётки в Microsoft; Federated — доверие внешнему IdP."
- question: "Где взять неизменяемый tenant ID?"
  options:
    - "В OpenID-конфигурации или в поле iss токена"
    - "В MX-записи"
    - "В robots.txt"
    - "В favicon"
  answer: 0
  explanation: "GUID тенанта виден в token_endpoint и issuer."
- question: "Что означает IfExistsResult: 0 в GetCredentialType?"
  options:
    - "Пароль верный"
    - "Учётная запись существует"
    - "MFA отключена"
    - "Тенант удалён"
  answer: 1
  explanation: "0 — пользователь найден; 1 — нет."
- question: "Какая DNS-запись независимо подтверждает привязку к Azure AD?"
  options:
    - "enterpriseregistration CNAME"
    - "NS"
    - "AAAA"
    - "CAA"
  answer: 0
  explanation: "CNAME enterpriseregistration → *.windows.net указывает на Azure AD."
```

## Куда дальше

Мы научились находить тенант и подтверждать пользователей. В следующем уроке модуля возьмём **Azure AD tenant ID** и разберём ещё больше способов его добыть — включая те, что работают без домена. А пока запомни: сервис входа Microsoft сам рассказывает про тенант любому, кто спросит правильно.

## Где пригодится

- **Пентест:** карта облачной поверхности Microsoft-организации.
- **Bug bounty:** подтверждение тенантов в scope.
- **CTF (OSINT):** поиск tenant ID и пользователей по домену.
- **Blue team:** проверка, что ваш тенант не светит лишнего.
