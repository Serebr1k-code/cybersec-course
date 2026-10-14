---
id: osint-azure-tenant
title: 'Azure AD tenant ID: способы добычи и применение'
category: osint
parent: osint-mod-saas-identity
difficulty: medium
order: 2
tags: [osint, azure, aad, tenant-id, aadinternals]
prerequisites: [osint-m365-enum]
useful_for:
  - 'CTF OSINT'
  - 'Bug bounty'
  - 'Пентест: recon'
  - 'Red team'
estimated_minutes: 45
summary: 'Как найти tenant ID Azure AD из домена, из IP, из сертификата и из публичных API — и зачем этот GUID нужен разведчику.'
lab:
  kind: shell
  title: 'Практика: tenant ID из нескольких источников'
  toolset: [core, curl, jq, dig]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'OpenID-конфигурация: `curl -s ''https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration''`.'
    - 'Домен авторизации AAD можно получить через DNS-запись `login.windows.net`.'
    - 'GUID вида `72f988bf-...` — это tenant ID.'
    - 'Запиши строку `nto{...}` в `answer.txt` и набери `check`.'
---

## Вопрос, с которого всё начинается

В прошлом уроке мы нашли tenant ID из OpenID-конфигурации. Но что если домен не отвечает на OpenID, а ты знаешь только IP или имя сервера? И почему этот GUID вообще важен — это же просто строка из цифр и букв?

Разберём, что такое tenant ID, зачем он нужен и **четырьмя независимыми способами** добыть его для организации `example.com`.

## Наш пример: GUID, который не меняется

**Azure AD tenant ID** — это GUID (например, `72f988bf-86f1-41af-91ab-2d7cd011db47`), который однозначно идентифицирует тенант организации в Microsoft Entra (бывш. Azure AD). Его нельзя «переименовать»: меняется имя домена — GUID остаётся. Поэтому он — надёжный якорь для дедупликации и отслеживания организации.

Держим объект: домен `example.com` и вопрос — **как получить его tenant ID разными путями?**

## Способ 1: OpenID-конфигурация

Самый прямой путь. Сервис входа публикует документ с эндпоинтами, а в URL спрятан GUID.

```bash
curl -s 'https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration' | jq -r .token_endpoint
```

```text
https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token
```

GUID в середине URL и есть tenant ID. Этот путь требует лишь домен.

## Способ 2: поле iss в токене

Если запросить токен для домена, в ответе есть поле `iss` (issuer) — оно тоже содержит GUID. Метод хорош, когда OpenID-документ по какой-то причине не отдаётся, но эндпоинт токена работает.

```text
POST https://login.microsoftonline.com/example.com/oauth2/v2.0/token
→ {"token_type":"Bearer", ...}
iss → https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/
```

Форма `sts.windows.net/<GUID>/` — ещё один стабильный «отпечаток» тенанта.

## Способ 3: из DNS и федерации

Когда домен федеративен, Azure AD оставляет следы в DNS. Записи `enterpriseregistration`, `enterpriseenrollment` и `_sipfederationtls._tcp` указывают на инфраструктуру Microsoft и на адрес IdP.

```bash
dig +short CNAME enterpriseenrollment.example.com
dig +short TXT _sipfederationtls._tcp.example.com
```

```text
enterpriseenrollment.manage.microsoft.com.
```

Эти записи не дают GUID напрямую, но подтверждают привязку к Azure AD и часто выдают адрес внешнего IdP — важный следующий шаг.

## Способ 4: по сертификату и по IP

Иногда GUID утекает в TLS-сертификате (в SAN или CN) или в публичных реестрах Azure. Инструменты вроде AADInternals автоматизируют перебор: по домену они собирают и GUID, и домен авторизации, и регион.

```bash
# концептуально (AADInternals)
Get-AADIntTenantID -Domain example.com
Get-AADIntLoginInformation -Domain example.com
```

`Get-AADIntLoginInformation` возвращает JSON с полями `TenantID`, `Region`, `FederationBrandName`, `AuthURL` — фактически готовый профиль тенанта.

## Зачем это разведчику

Tenant ID нужен, чтобы: строить ссылки на вход (`login.microsoftonline.com/<GUID>`), однозначно привязывать домены к одной организации, находить другие домены того же тенанта, обращаться к публичным метаданным приложений. Для CTF это часто «ключ» к следующему шагу; для пентеста — якорь карты.

## Полный прогон

```bash
# 1. GUID из OpenID
curl -s 'https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration' | jq -r .token_endpoint
# 2. подтверждение через DNS
dig +short CNAME enterpriseregistration.example.com
# 3. профиль тенанта
# Get-AADIntLoginInformation -Domain example.com
```

Непрерывно: домен → GUID → регион → подтверждение по DNS → профиль.

## Если не сработало

**Домен не привязан к AAD.** OpenID вернёт ошибку — проверь M365-реalm.
**Федерация.** OpenID может редиректить на внешний IdP — GUID ищи в `iss` токена.
**GUID утёк в сертификат.** Проверь SAN сертификатов на поддоменах.

## Что мы теперь знаем

1. Tenant ID — неизменяемый GUID тенанта.
2. Добывается из OpenID-конфигурации, из `iss` токена, из DNS и из сертификатов.
3. Форма `sts.windows.net/<GUID>/` — стабильный отпечаток.
4. GUID связывает домены в одну организацию.

## Справочная таблица: источники tenant ID

| Источник | Как получить | Требует |
|----------|--------------|---------|
| OpenID-конфигурация | `curl .../<domain>/v2.0/.well-known/openid-configuration` | домен |
| `iss` токена | запрос токена, разбор `iss` | домен |
| `sts.windows.net/<GUID>/` | поле issuer в старых токенах | домен |
| DNS (federation) | `dig CNAME enterpriseregistration` | домен |
| TLS-сертификат | SAN сертификата поддомена | доступ к сервису |
| AADInternals | `Get-AADIntLoginInformation` | домен |

Шпаргалка: начинай с OpenID, подтверждай через токен или DNS, автоматизируй AADInternals, когда источников много.

## Частые ошибки и подводные камни

**Ошибка 1: считать tenant ID секретом.** Он публичен и неизменяем; это не «пароль», а идентификатор. Ценность его — в дедупликации и в построении ссылок.

**Ошибка 2: путать tenant ID и Object ID.** Object ID — идентификатор конкретного объекта (пользователя, приложения); tenant ID — идентификатор всего тенанта. Формат похож (GUID), но роли разные.

**Ошибка 3: брать GUID из кэша CDN.** OpenID-документ может кэшироваться; убедись, что ответ свежий, иначе рискуешь записать устаревшее значение.

**Ошибка 4: игнорировать регион.** `tenant_region_scope` указывает, в каком дата-центре живут данные; это часть профиля тенанта.

**Ошибка 5: не проверять второй источник.** Один запрос может вернуть ошибку федерации; GUID, подтверждённый двумя путями, надёжнее.

## Вопросы и ответы

**Зачем вообще нужен GUID, если есть домен?** Домены можно добавить и убрать, они не уникальны между организациями. GUID неизменяем и однозначен, поэтому по нему связывают все домены одной организации.

**Что такое «федеративный» тенант?** Тенант, который доверяет внешнему поставщику входа (ADFS, Okta, Ping). Пароли проверяет IdP, а Microsoft лишь доверяет его токенам.

**Можно ли найти tenant ID, зная только IP?** Иногда — через обратный DNS, TLS-сертификат или публичные реестры Azure. Но надёжнее всего работать от домена.

**Чем опасна утечка tenant ID?** Сам по себе он не даёт доступа. Но он — каркас для фишинга, подбора и поиска связанных доменов, поэтому организации не любят его «светить» лишний раз.

**Как связать tenant ID с другими доменами?** Собери домены организации (сертификаты, SPF, реестры), проверь каждый тем же OpenID-запросом: одинаковый GUID = один тенант.

## Полный прогон: один домен, четыре пути к GUID

Соберём всё в один маршрут на домене `example.com`.

```bash
# Путь 1: OpenID-конфигурация
curl -s 'https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration' \
  | jq -r .token_endpoint
# → https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token

# Путь 2: realm (тип тенанта)
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=a@example.com&json=1' \
  | jq -r .NameSpaceType
# → Managed

# Путь 3: DNS-подтверждение
dig +short CNAME enterpriseregistration.example.com
# → enterpriseregistration.windows.net.

# Путь 4: почта
dig +short MX example.com
# → example-com.mail.protection.outlook.com.
```

Четыре запроса — один профиль: GUID `72f988bf-...`, регион EU, управляемый тенант, подтверждение по DNS и почте. Если хотя бы два пути дают согласованный результат, вывод устойчив.

## Как это выглядит в отчёте

Разведчик фиксирует не «сырые» запросы, а сжатый вывод с источником и уверенностью:

```text
Организация: Example Corp
Облако: Microsoft 365 / Azure AD
Tenant ID: 72f988bf-86f1-41af-91ab-2d7cd011db47   [OpenID + iss, подтверждено]
Регион данных: EU
Тип тенанта: Managed (без федерации)
Домены: example.com, example-corp.com   [один GUID]
Источник: login.microsoftonline.com (публичные метаданные)
Ограничение: список пользователей не собирался
```

Такой блок сразу отвечает на вопросы: где организация, насколько она «облачная», какие домены связаны, что уже проверено. Дальше по этому профилю планируют авторизованную фазу.

## Мини-практика

Возьми любой домен из открытого списка компаний и определи: привязан ли он к Azure AD, каков его tenant ID и регион данных. Запиши результат в формате блока выше. Сравни два-три домена одной отрасли — увидишь, как GUID группирует организации.

## На что смотреть дальше

- **Кэш.** OpenID-документ может отдаваться из кэша; проверяй свежесть ответа.
- **Федерация.** При внешнем IdP GUID всё равно есть — ищи его в `iss` токена.
- **Связанные домены.** Собрав GUID, проверь по нему другие домены организации.
- **Юрисдикция.** `tenant_region_scope` — часть профиля, не игнорируй его.

## Словарь терминов урока

**Azure AD / Microsoft Entra** — облачная служба каталога Microsoft: пользователи, группы, приложения, вход в сервисы. Прежнее имя — Azure AD.

**Tenant ID** — GUID, однозначно идентифицирующий каталог организации. Не меняется при переименовании домена.

**Object ID** — GUID конкретного объекта внутри тенанта: пользователя, группы, приложения. Формат тот же, роль другая.

**Issuer (`iss`)** — поле токена, указывающее, кто его выдал. Для Azure содержит GUID тенанта в форме `sts.windows.net/<GUID>/`.

**OpenID Connect** — надстройка над OAuth 2.0; публикует документ с эндпоинтами. Именно из него мы достаём GUID.

**Federation** — доверие внешнему IdP. Тенант доверяет токенам другого поставщика входа.

Эти термины описывают всю цепочку: каталог (тенант) → его GUID → эндпоинты входа → доверие (федерация). Понимая их, ты читаешь ответы Azure AD как открытую книгу.

## Почему один домен даёт несколько GUID-ов на вид

Иногда новичок путается: в одном ответе мелькает один GUID, в другом — другой. Причина в том, что в метаданных Azure AD рядом живут идентификаторы разных сущностей: сам тенант, приложение, политика. Tenant ID — это GUID в URL эндпоинтов токена и авторизации; Object ID приложения — в его манифесте. Сравнивая, всегда уточняй, к чему относится GUID: если он стоит сразу после `login.microsoftonline.com/`, это тенант. Так ты не перепутаешь каталог организации с конкретным приложением внутри него.

## Квиз

Проверь себя.

```quiz
- question: "Почему tenant ID считают надёжным якорем?"
  options:
    - "Он меняется каждый день"
    - "Он неизменяем и не зависит от переименования домена"
    - "Его легко подделать"
    - "Он не связан с организацией"
  answer: 1
  explanation: "GUID тенанта постоянен — по нему дедуплицируют домены."
- question: "Где в OpenID-конфигурации виден tenant ID?"
  options:
    - "В поле summary"
    - "В URL token_endpoint и в issuer"
    - "В MX"
    - "В favicon"
  answer: 1
  explanation: "GUID встроен в token_endpoint и issuer."
- question: "Какую форму имеет отпечаток тенанта в issuer?"
  options:
    - "sts.windows.net/<GUID>/"
    - "example.com/tenant"
    - "MX: tenant"
    - "tenant@example.com"
  answer: 0
  explanation: "Issuer формата sts.windows.net/<GUID>/ — стабильный признак."
- question: "Какой инструмент автоматизирует сбор информации о тенанте?"
  options:
    - "AADInternals"
    - "nmap"
    - "hashcat"
    - "wireshark"
  answer: 0
  explanation: "AADInternals умеет TenantID и LoginInformation."
```

## Куда дальше

Теперь у нас есть GUID. В следующем уроке модуля возьмём **Okta** — другого крупного провайдера SSO — и научимся находить организацию и её эндпоинты. А пока запомни: tenant ID — неизменяемый якорь организации в Azure.

## Где пригодится

- **Пентест:** однозначная привязка доменов к тенанту.
- **Bug bounty:** поиск связанных доменов одного тенанта.
- **CTF (OSINT):** добыча GUID из открытых источников.
- **Blue team:** инвентаризация доменов, привязанных к вашему тенанту.
