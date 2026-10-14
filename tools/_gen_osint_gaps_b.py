#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch B: osint SaaS/identity lessons — Okta, Google Workspace, Slack, Jira/Confluence."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson as _wl
def write_lesson(meta, body, lab=None):
    try:
        return _wl(meta, body, lab=lab)
    except SystemExit:
        print('skip:', meta.get('id')); return None

U = ["CTF OSINT", "Bug bounty", "Пентест: recon", "Red team"]

# ---------------- osint-okta-enum
okta = dict(
    id="osint-okta-enum", title="Okta: поиск организации и её SSO-эндпоинтов",
    category="osint", parent="osint-mod-saas-identity", difficulty="medium", order=3,
    tags=["osint", "okta", "sso", "idp", "tenant"], prerequisites=["osint-azure-tenant"],
    useful_for=U, estimated_minutes=45,
    summary="Как найти организацию Okta по домену, прочитать метаданные орг и её OAuth/OIDC-конфигурацию — без аутентификации.",
    lab=dict(title="Практика: организация Okta", toolset=["core", "curl", "jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["Org-эндпоинт: `curl -s https://example.okta.com/api/v1/org`.",
               "Поле `subdomain` — имя организации, `id` — её идентификатор.",
               "OIDC-конфигурация: `curl -s https://example.okta.com/oauth2/default/.well-known/openid-configuration`.",
               "Маркер `nto{...}` — в поле ответа; запиши в `answer.txt` и набери `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{okt4_0rg_ss0_d1sc0v3ry}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: Okta org recon\n\n1. `curl -s https://example.okta.com/api/v1/org`\n2. Найди `subdomain`, `id`, `companyName`.\n3. `curl -s https://example.okta.com/oauth2/default/.well-known/openid-configuration`\n4. Маркер `nto{...}` — в одном из ответов. Запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов Okta","cases":[
            {"match":"api/v1/org","example":"curl -s https://example.okta.com/api/v1/org",
             "output":"{\"id\":\"00o1abcdefGHIJKLmn\",\"subdomain\":\"example\",\"companyName\":\"Example Corp\",\"status\":\"ACTIVE\",\"created\":\"2019-04-02T10:11:12.000Z\",\"address1\":null,\"city\":null,\"country\":\"US\",\"x_flag\":\"nto{okt4_0rg_ss0_d1sc0v3ry}\"}\n"},
            {"match":"openid-configuration","example":"curl -s https://example.okta.com/oauth2/default/.well-known/openid-configuration",
             "output":"{\"issuer\":\"https://example.okta.com/oauth2/default\",\"authorization_endpoint\":\"https://example.okta.com/oauth2/default/v1/authorize\",\"token_endpoint\":\"https://example.okta.com/oauth2/default/v1/token\",\"jwks_uri\":\"https://example.okta.com/oauth2/default/v1/keys\"}\n"}],
            "fallback":"curl: в этой лабе доступен только example.okta.com.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"subdomain|companyName|\\.","example":"jq -r .subdomain org.json","output":"example\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
okta_body = r"""## Вопрос, с которого всё начинается

Ты нашёл поддомен `example.okta.com`. Что это даёт? Okta — один из крупнейших провайдеров единого входа (SSO). Если организация держит вход в свои приложения через Okta, то этот поддомен — её «парадная дверь»: через неё входят в десятки сервисов.

Задача: понять, что за организация стоит за этим адресом, и собрать её публичные метаданные — без единого логина.

## Наш пример: организация в Okta

Okta у каждой организации выдаёт свой поддомен вида `<company>.okta.com`. Иногда — `<company>-admin.okta.com` для админки, иногда региональные: `.okta-emea.com`, `.oktapreview.com`.

Держим объект `example.okta.com`. Первый вопрос: **отдаёт ли он публичные метаданные организации?** Да — через API-эндпоинт `/api/v1/org`.

```bash
curl -s https://example.okta.com/api/v1/org | jq .
```

```json
{"id":"00o1abcdefGHIJKLmn","subdomain":"example","companyName":"Example Corp",
 "status":"ACTIVE","created":"2019-04-02T10:11:12.000Z","country":"US"}
```

Читаем: `subdomain: example` подтверждает имя орг, `companyName` — юридический бренд, `status: ACTIVE` — орг жива, `created` — когда заведена. Это уже полноценный профиль: мы знаем, что компания Example Corp использует Okta с 2019 года.

## Шаг 1: находим организацию по домену

Организацию находят по DNS и сертификатам. Ищи поддомены с ключевыми словами `okta`, `sso`, `login`, `idp`:

```bash
curl -s 'https://crt.sh/?q=%25.okta.com&output=json' | jq -r '.[].name_value' | grep example
# в реальности: сертификаты <org>.okta.com видны в CT-логах
```

Часто в CNAME видно привязку: `sso.example.com → example.okta.com`. Это надёжное подтверждение, что вход компании идёт через Okta.

## Шаг 2: читаем OIDC-конфигурацию

Как и у Azure AD, Okta публикует документ OpenID Connect с эндпоинтами:

```bash
curl -s https://example.okta.com/oauth2/default/.well-known/openid-configuration | jq -r .issuer
```

```text
https://example.okta.com/oauth2/default
```

Здесь виден `authorization_endpoint`, `token_endpoint`, `jwks_uri`. `jwks_uri` — адрес публичных ключей подписи токенов; он подтверждает, что орг реально выдаёт токены. Наличие этой конфигурации — сильный признак живого SSO-провайдера.

## Шаг 3: изучаем страницу входа

Страница входа Okta живёт по адресу `/login/login.htm`. Она рассказывает, какие методы включены: пароль, MFA, вход через внешний IdP (Okta умеет федерацию с ADFS, Azure AD и др.).

```bash
curl -s https://example.okta.com/login/login.htm | grep -iE 'sign in|factor|mfa' | head
```

```text
<title>Sign In</title>
```

Если на странице виден брендинг организации — это ещё одно подтверждение. Если появляется редирект на сторонний IdP — значит, Okta сама делегирует вход дальше, и разведку надо продолжать там.

## Шаг 4: перечисление и его границы

У Okta есть эндпоинт аутентификации `/api/v1/authn`, который по имени пользователя отвечает, существует ли он и какие факторы ему доступны. Ответы различаются для существующего и несуществующего пользователя — это и есть основа перечисления.

```text
POST https://example.okta.com/api/v1/authn
{"username":"ceo@example.com","password":""}

→ 401 {"errorCode":"E0000004","errorSummary":"Authentication failed"}
```

Осторожно: Okta агрессивно троттлит и логирует такие запросы. Перечисление — это карта, а не вход: один-два запроса для подтверждения, дальше стоп. Массовый перебор — это уже не разведка, а атака, и она заметна.

## Полный прогон

```bash
# 1. орг-метаданные
curl -s https://example.okta.com/api/v1/org | jq -r '.subdomain, .companyName, .status'
# → example / Example Corp / ACTIVE
# 2. OIDC-конфигурация
curl -s https://example.okta.com/oauth2/default/.well-known/openid-configuration | jq -r .issuer
# → https://example.okta.com/oauth2/default
# 3. страница входа
curl -s -o /dev/null -w '%{http_code}\n' https://example.okta.com/login/login.htm
# → 200
```

Непрерывная история: поддомен → орг-метаданные → OIDC → страница входа → профиль SSO организации.

## Если не сработало

**`/api/v1/org` закрыт.** Некоторые орг отключают публичный доступ — тогда опирайся на OIDC и страницу входа.
**Нет поддомена okta.** Организация может использовать кастомный домен (`sso.example.com`) — проверь CNAME.
**Регион.** Орг может жить в `okta-emea.com` или `oktapreview.com` — проверь и их.

## Частые ошибки

**Ошибка: считать `subdomain` секретом.** Он публичен и нужен клиентам для входа.
**Ошибка: перебирать `/api/v1/authn`.** Быстрый троттлинг и алерты; подтверждай единичными запросами.
**Ошибка: игнорировать федерацию.** Если Okta делегирует вход внешнему IdP, реальный провайдер — там.

## Что мы теперь знаем

1. Организация Okta живёт на `<company>.okta.com`.
2. `/api/v1/org` отдаёт публичный профиль орг.
3. OIDC-конфигурация раскрывает эндпоинты и JWKS.
4. Страница входа показывает методы и федерацию.
5. Перечисление — карта, не вход; троттлинг реален.

## Квиз

Проверь себя.

```quiz
- question: "Какой эндпоинт Okta отдаёт метаданные организации?"
  options:
    - "/api/v1/org"
    - "/robots.txt"
    - "/favicon.ico"
    - "/wp-login.php"
  answer: 0
  explanation: "/api/v1/org возвращает id, subdomain, companyName и статус."
- question: "Что содержит OIDC-конфигурация Okta?"
  options:
    - "Пароли пользователей"
    - "Эндпоинты авторизации/токена и адрес JWKS"
    - "Список сотрудников"
    - "Резервные коды"
  answer: 1
  explanation: "Это стандартный OIDC-документ с эндпоинтами и jwks_uri."
- question: "Чем опасно массовое перечисление в Okta?"
  options:
    - "Ничем"
    - "Троттлингом и алертами защиты"
    - "Замедлением интернета"
    - "Сменой пароля"
  answer: 1
  explanation: "Okta лимитирует и логирует частые запросы аутентификации."
- question: "Как подтвердить привязку домена к Okta?"
  options:
    - "По CNAME sso.example.com → example.okta.com"
    - "По MX"
    - "По favicon"
    - "По TTL"
  answer: 0
  explanation: "CNAME на *.okta.com — надёжный признак SSO через Okta."
```

## Куда дальше

Следующий урок модуля — **Google Workspace**: научимся по MX понять, что почта в Google, и проверим пользователей. А пока запомни: Okta-поддомен — это публичная парадная дверь организации в её приложения.

## Где пригодится

- **Пентест:** карта SSO-провайдера организации.
- **Bug bounty:** подтверждение Okta-орг в scope.
- **CTF (OSINT):** поиск org id и эндпоинтов.
- **Blue team:** контроль публичной экспозиции Okta.
"""
write_lesson(okta, okta_body, lab=okta["lab"])

# ---------------- osint-google-workspace
gws = dict(
    id="osint-google-workspace", title="Google Workspace: MX-признаки и перечисление пользователей",
    category="osint", parent="osint-mod-saas-identity", difficulty="medium", order=4,
    tags=["osint", "google", "workspace", "gmail", "mx"], prerequisites=["osint-okta-enum"],
    useful_for=U, estimated_minutes=45,
    summary="Как по MX/TXT понять, что домен в Google Workspace, найти SSO-следы и проверить существование учётных записей.",
    lab=dict(title="Практика: Google Workspace recon", toolset=["core","curl","jq","dig"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["Проверь MX: `dig +short MX example.com`.",
               "TXT: `dig +short TXT example.com` — ищи google-site-verification.",
               "Спроси провайдера входа: `curl -s https://accounts.google.com/.well-known/openid-configuration`.",
               "Маркер `nto{...}` — в одном из ответов; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{g00gl3_w0rksp4c3_mx_r3c0n}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: Google Workspace\n\n1. `dig +short MX example.com`\n2. `dig +short TXT example.com`\n3. `curl -s https://accounts.google.com/.well-known/openid-configuration`\n4. Найди маркер `nto{...}` и запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов Google","cases":[
            {"match":"openid-configuration","example":"curl -s https://accounts.google.com/.well-known/openid-configuration",
             "output":"{\"issuer\":\"https://accounts.google.com\",\"authorization_endpoint\":\"https://accounts.google.com/o/oauth2/v2/auth\",\"token_endpoint\":\"https://oauth2.googleapis.com/token\",\"jwks_uri\":\"https://www.googleapis.com/oauth2/v3/certs\",\"x_note\":\"nto{g00gl3_w0rksp4c3_mx_r3c0n}\"}\n"}],
            "fallback":"curl: в этой лабе доступен только accounts.google.com.\n"},
        "dig":{"help":"dig [+short] <запись> — эмуляция DNS","cases":[
            {"match":"MX","example":"dig +short MX example.com","output":"1 aspmx.l.google.com.\n5 alt1.aspmx.l.google.com.\n5 alt2.aspmx.l.google.com.\n"},
            {"match":"TXT","example":"dig +short TXT example.com","output":"\"google-site-verification=abcd1234EFGH5678\"\n\"v=spf1 include:_spf.google.com ~all\"\n"}],
            "fallback":"dig: в этой лабе доступны MX и TXT.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"issuer|\\.","example":"jq -r .issuer conf.json","output":"https://accounts.google.com\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
gws_body = r"""## Вопрос, с которого всё начинается

Домен `example.com`, и ты хочешь понять, где живёт его почта и учётные записи. Если это Google Workspace, то у разведки появляется свой набор «дверей»: MX-записи Google, SSO-следы, страницы входа Google.

Задача: подтвердить Google Workspace по DNS и собрать публичные метаданные входа.

## Наш пример: домен и его почта

Первый и самый надёжный признак — **MX-запись** (mail exchanger): она говорит, какой сервер принимает почту домена.

```bash
dig +short MX example.com
```

```text
1 aspmx.l.google.com.
5 alt1.aspmx.l.google.com.
5 alt2.aspmx.l.google.com.
```

`aspmx.l.google.com` и `alt*.aspmx.l.google.com` — это инфраструктура Google. Значит, почта домена обрабатывается Google. Для Microsoft было бы `*.mail.protection.outlook.com`, для Яндекса — `mx.yandex.net`.

## Шаг 1: подтверждаем владение через TXT

Второй независимый признак — TXT-записи. Google просит подтвердить владение доменом записью `google-site-verification`, а SPF-запись содержит `include:_spf.google.com`.

```bash
dig +short TXT example.com
```

```text
"google-site-verification=abcd1234EFGH5678"
"v=spf1 include:_spf.google.com ~all"
```

Две независимые записи, указывающие на Google, — надёжное подтверждение. Мы не строим вывод на одном источнике.

## Шаг 2: читаем OIDC-конфигурацию Google

Сервис входа Google публикует стандартный OIDC-документ:

```bash
curl -s https://accounts.google.com/.well-known/openid-configuration | jq -r .issuer, .jwks_uri
```

```text
https://accounts.google.com
https://www.googleapis.com/oauth2/v3/certs
```

`issuer: accounts.google.com` и адрес публичных ключей подтверждают, что вход идёт через Google. Для организаций Workspace дополнительно доступны SAML-настройки на кастомном домене (`accounts.google.com/o/saml2/...`).

## Шаг 3: ищем следы Workspace

Признаки корпоративного Google, а не просто личного Gmail:

- `google-site-verification` с параметрами организации;
- CNAME `calendar.google.com`, `mail.google.com` на поддоменах;
- SAML-редиректы на страницах приложений;
- `_dmarc` с отчётами на почтовый шлюз организации.

```bash
dig +short CNAME mail.example.com
dig +short TXT _dmarc.example.com
```

```text
ghs.googlehosted.com.
"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

`ghs.googlehosted.com` — хостинг сервисов Google, а DMARC с `rua` на свой домен показывает, что организацией управляют всерьёз.

## Шаг 4: проверка пользователей и границы

Google исторически позволял проверять существование адреса Gmail через разные механики (регистрация, восстановление). Для Workspace-домена косвенный признак даёт страница входа: для существующего адреса она ведёт на страницу пароля Workspace, для несуществующего — на «создать аккаунт».

```text
https://accounts.google.com/v3/signin/identifier?identifier=ceo@example.com
→ существующий: страница ввода пароля Workspace
→ несуществующий: «Не удалось найти аккаунт Google»
```

Здесь та же дисциплина: **пара проверок, не перебор**. Google троттлит и требует капчу, а массовый перебор — уже не разведка.

## Полный прогон

```bash
dig +short MX example.com                 # → aspmx.l.google.com (Google)
dig +short TXT example.com                # → google-site-verification, _spf.google.com
curl -s https://accounts.google.com/.well-known/openid-configuration | jq -r .issuer
# → https://accounts.google.com
```

Домен → MX → TXT → OIDC → профиль: почта и вход в Google Workspace.

## Если не сработало

**MX не Google.** Проверь Microsoft (outlook.com) и Яндекс (yandex.net) — у них свои следы.
**Нет TXT-подтверждения.** Домен мог подтверждаться через CNAME — проверь и его.
**Личный Gmail, не Workspace.** Тогда SSO-следов не будет, только страница входа Google.

## Частые ошибки

**Ошибка: путать личный Gmail и Workspace.** Признак Workspace — корпоративный домен в MX/TXT, а не `gmail.com`.
**Ошибка: перебирать signin-эндпоинт.** Капча и троттлинг приходят быстро.
**Ошибка: игнорировать DMARC.** Запись показывает почтовую гигиену организации.

## Что мы теперь знаем

1. MX-запись Google подтверждает почту в Workspace.
2. TXT (verification, SPF) — второй независимый признак.
3. OIDC-конфигурация Google раскрывает issuer и JWKS.
4. Признаки корпоративного аккаунта — SAML, ghs, DMARC.
5. Перечисление — пара запросов, не перебор.

## Квиз

Проверь себя.

```quiz
- question: "Какая DNS-запись подтверждает почту в Google Workspace?"
  options:
    - "MX → *.google.com / aspmx.l.google.com"
    - "AAAA"
    - "NS"
    - "CAA"
  answer: 0
  explanation: "MX-запись указывает на почтовые серверы Google."
- question: "Какой TXT-признак подтверждает владение доменом в Google?"
  options:
    - "google-site-verification"
    - "v=spf1 include:_spf.google.com"
    - "Оба варианта"
    - "Ни один"
  answer: 2
  explanation: "И verification, и SPF-запись — независимые признаки Google."
- question: "Где взять issuer Google для входа?"
  options:
    - "В OpenID-конфигурации accounts.google.com"
    - "В MX"
    - "В favicon"
    - "В robots.txt"
  answer: 0
  explanation: "Стандартный OIDC-документ отдаёт issuer и jwks_uri."
- question: "Что показывает CNAME ghs.googlehosted.com?"
  options:
    - "Хостинг сервисов Google"
    - "Пароль администратора"
    - "Номер телефона"
    - "VIN"
  answer: 0
  explanation: "ghs.googlehosted.com — хостинг сервисов Google для домена."
```

## Куда дальше

Мы закрыли четырёх крупных провайдеров идентичности. Дальше модуль перейдёт к **DevOps-поверхности** — Slack, Jira, CI/CD и реестры контейнеров. А пока запомни: MX и TXT надёжно выдают, что домен живёт в Google Workspace.

## Где пригодится

- **Пентест:** определение облака и почтового провайдера.
- **Bug bounty:** подтверждение Workspace-доменов в scope.
- **CTF (OSINT):** поиск SSO-следов по DNS.
- **Blue team:** проверка почтовой гигиены (SPF/DMARC).
"""
write_lesson(gws, gws_body, lab=gws["lab"])

print("Batch B part 1 done: okta, gws")
