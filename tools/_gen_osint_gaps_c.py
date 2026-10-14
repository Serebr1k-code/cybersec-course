#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch C: osint Slack + Jira/Confluence lessons."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson as _wl
def write_lesson(meta, body, lab=None):
    try: return _wl(meta, body, lab=lab)
    except SystemExit: print('skip:', meta.get('id')); return None
U = ["CTF OSINT", "Bug bounty", "Пентест: recon", "Red team"]

slack = dict(
    id="osint-slack-enum", title="Slack: поиск workspace и его публичных метаданных",
    category="osint", parent="osint-mod-saas-devops", difficulty="medium", order=1,
    tags=["osint","slack","workspace","saas","recon"], prerequisites=["osint-google-workspace"],
    useful_for=U, estimated_minutes=45,
    summary="Как по имени компании найти workspace Slack, подтвердить его существование и снять публичные метаданные команды.",
    lab=dict(title="Практика: workspace Slack", toolset=["core","curl","jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["Проверь существование: `curl -s -o /dev/null -w '%{http_code}' https://example.slack.com`.",
               "Legacy API: `curl -s 'https://slack.com/api/team.info?team=example'`.",
               "Смотри поле `team` с `id`, `name`, `domain`.",
               "Маркер `nto{...}` — в ответе; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{sl4ck_w0rksp4c3_f0und}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: Slack workspace\n\n1. `curl -s -o /dev/null -w '%{http_code}\\n' https://example.slack.com`\n2. `curl -s 'https://slack.com/api/team.info?team=example'`\n3. Найди `team.id`, `team.name`, `team.domain`.\n4. Маркер `nto{...}` — запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов Slack","cases":[
            {"match":"example\\.slack\\.com","example":"curl -s https://example.slack.com","output":"<html><head><title>Sign in to Example Corp | Slack</title></head><body>Sign in to Example Corp</body></html>\n"},
            {"match":"team\\.info","example":"curl -s 'https://slack.com/api/team.info?team=example'",
             "output":"{\"ok\":true,\"team\":{\"id\":\"T0123ABCDEF\",\"name\":\"Example Corp\",\"domain\":\"example\",\"email_domain\":\"example.com\",\"icon\":{\"image_132\":\"https://a.slack-edge.com/...\"},\"x_flag\":\"nto{sl4ck_w0rksp4c3_f0und}\"}}\n"}],
            "fallback":"curl: в этой лабе доступны example.slack.com и slack.com/api/team.info.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"team|\\.","example":"jq -r .team.domain resp.json","output":"example\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
slack_body = r"""## Вопрос, с которого всё начинается

Компания `Example Corp` явно общается внутри команды. Скорее всего, у неё есть workspace в Slack. Как найти его адрес, подтвердить, что он существует, и снять публичные метаданные — не вступая в него?

Slack — это ещё одна публичная «дверь» организации: страница входа, домен, иногда открытые пригласительные ссылки. Разберём, что именно видно снаружи и как это читать.

## Наш пример: компания и её workspace

У каждого workspace Slack есть адрес вида `<company>.slack.com`. Держим объект `example.slack.com` и первый вопрос: **существует ли он и на кого зарегистрирован?**

Проверяем существование простым запросом:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://example.slack.com
```

```text
200
```

Если адрес существует, откроется страница входа с названием организации. Если нет — Slack вернёт страницу «workspace not found». Уже по коду ответа и заголовку мы понимаем, жив ли workspace.

## Шаг 1: как вообще находят workspace

Есть несколько путей. Первый — по имени компании: пробуют варианты `company`, `company-org`, `companyteam`. Второй — по DNS и CT-логам: иногда на поддомене компании виден CNAME или редирект на `*.slack.com`. Третий — по открытым приглашениям: ссылки вида `join.slack.com/t/example/shared_invite/...` часто утекают в документации, на лендингах вакансий и в публичных репозиториях.

```bash
# поиск утёкших инвайтов и упоминаний workspace
# в реальности — через поисковые дорки и GitHub-поиск
```

Четвёртый путь — по job-описаниям: работодатели часто пишут «мы в Slack» и указывают домен.

## Шаг 2: снимаем метаданные команды

У Slack есть legacy-эндпоинт `team.info`, который для известного workspace отдаёт базовые данные команды:

```bash
curl -s 'https://slack.com/api/team.info?team=example' | jq .
```

```json
{"ok":true,"team":{"id":"T0123ABCDEF","name":"Example Corp",
 "domain":"example","email_domain":"example.com"}}
```

Читаем: `id` — внутренний идентификатор команды (неизменяем), `name` — бренд, `domain` — короткое имя, `email_domain` — домен, по которому регистрируются сотрудники. Это подтверждает связь workspace с организацией: если `email_domain` совпадает с доменом компании, сомнений не остаётся.

Важно: сам эндпоинт со временем менял требования к токену. Если он отвечает `not_authed`, значит публичный доступ закрыт, и ты опираешься на страницу входа и приглашения.

## Шаг 3: читаем страницу входа

Страница `https://example.slack.com` показывает брендинг и подсказки: «Sign in to Example Corp». Иногда там указан домен, разрешённый для регистрации, и способ входа — пароль, Google, SAML. Это ценно: если включён SAML, значит организация использует корпоративный SSO, и его провайдера можно определить по редиректу.

```bash
curl -s https://example.slack.com | grep -iE 'sign in|saml|google' | head
```

```text
<title>Sign in to Example Corp | Slack</title>
```

Так мы связываем Slack с провайдером идентичности компании — Google Workspace, Okta или Azure AD.

## Шаг 4: публичные каналы и границы

Некоторые каналы Slack доступны для чтения без входа по прямой ссылке `<company>.slack.com/archives/<channel>`. Если администратор сделал канал публичным для внешнего доступа, его содержимое видно. Здесь и появляется главный риск: в переписке утекают токены, ссылки на внутренние системы, имена и адреса.

Но граница проста: **мы не вступаем в workspace и не читаем то, что требует приглашения**. Разведка фиксирует факт существования, домен, бренд и связь с SSO. Всё, что дальше, — уже доступ, а не разведка.

## Полный прогон

```bash
# 1. существует ли workspace
curl -s -o /dev/null -w '%{http_code}\n' https://example.slack.com      # → 200
# 2. метаданные команды
curl -s 'https://slack.com/api/team.info?team=example' | jq -r '.team.domain, .team.email_domain'
# → example / example.com
# 3. страница входа
curl -s https://example.slack.com | grep -o '<title>[^<]*</title>'
# → <title>Sign in to Example Corp | Slack</title>
```

Непрерывная история: имя компании → адрес workspace → метаданные → страница входа → связь с SSO.

## Если не сработало

**Workspace не найден.** Попробуй варианты имени: с дефисом, `-org`, `-team`, аббревиатуру.
**`team.info` отвечает `not_authed`.** Публичный доступ закрыт — опирайся на страницу входа и приглашения.
**Домен не тот.** Компания могла сменить имя или использовать суббренд.

## Частые ошибки

**Ошибка: считать workspace закрытым, если страница входа требует логин.** Существование подтверждается и без входа — по коду ответа и заголовку.
**Ошибка: вступать в workspace.** Это уже доступ, а не разведка.
**Ошибка: игнорировать `email_domain`.** Именно он связывает workspace с организацией надёжнее всего.
**Ошибка: путать Slack и Slack Connect.** Shared-каналы между организациями видны иначе — не путай их с внутренними.

## Справочная таблица: что видно снаружи Slack

| Артефакт | Где | Что даёт |
|----------|-----|----------|
| `<company>.slack.com` | DNS, догадка | существование workspace |
| `/api/team.info?team=` | Slack API | id, name, domain, email_domain |
| `join.slack.com/t/.../shared_invite/...` | утечки | открытое приглашение |
| страница входа | `<company>.slack.com` | бренд, методы входа, SSO |
| `/archives/<channel>` | прямая ссылка | публичный канал, если открыт |

## Разбор кейса: от вакансии до SSO

Дано: на странице вакансии компании `Example Corp` указано «общаемся в Slack». Шаг первый — пробуем `example.slack.com`, получаем `200` и заголовок с брендом. Шаг второй — `team.info?team=example` отдаёт `email_domain: example.com`; связь с компанией подтверждена. Шаг третий — на странице входа видим кнопку входа через Google, а DNS домена показывает MX Google. Вывод: компания использует Google Workspace и Slack с SSO через Google. Это готовый профиль: облако, SSO, рабочее пространство. Дальше разведчик переходит к следующему инструменту DevOps-контура.

## Частые вопросы

**Slack — это публичный или приватный сервис?** Сам сервис приватный, но факт существования workspace и его базовые метаданные видны снаружи. Внутренняя переписка закрыта.

**Что такое Slack Connect?** Возможность делиться каналами между организациями. Такие каналы видны иначе и могут раскрывать партнёров компании.

**Зачем разведчику `team.id`?** Он неизменяем и позволяет дедуплицировать упоминания одной команды, даже если имя поменяли.

**Можно ли перечислить сотрудников?** Прямого открытого списка нет. Косвенно — из публичных каналов, приглашений и упоминаний в других источниках.

**Это законно?** Чтение публичных метаданных — да. Вступление в workspace, обход приглашений и сбор переписки — нет, без авторизации.

## Термины

**Workspace** — изолированное пространство команды в Slack с адресом и идентификатором.

**Team ID** — неизменяемый идентификатор команды (`T...`).

**Shared invite** — публичная пригласительная ссылка в workspace.

**SAML** — корпоративный протокол входа; его включение в Slack указывает на SSO организации.

**email_domain** — домен, по которому сотрудники могут регистрироваться; связывает workspace с организацией.

## Что мы теперь знаем

1. Workspace Slack живёт на `<company>.slack.com`.
2. Существование подтверждается без входа — по коду и заголовку.
3. `team.info` отдаёт id, имя, домен и email_domain.
4. Страница входа раскрывает SSO-провайдера.
5. Мы фиксируем факт, не вступая в workspace.

## Квиз

Проверь себя.

```quiz
- question: "Как выглядит адрес workspace Slack?"
  options:
    - "slack.com/company"
    - "<company>.slack.com"
    - "company.slack.io"
    - "slack.company.com"
  answer: 1
  explanation: "Workspace живёт на поддомене <company>.slack.com."
- question: "Какое поле связывает workspace с организацией?"
  options:
    - "email_domain"
    - "icon"
    - "created"
    - "tz"
  answer: 0
  explanation: "email_domain — домен регистрации сотрудников."
- question: "Что означает ответ not_authed от team.info?"
  options:
    - "Workspace удалён"
    - "Публичный доступ к метаданным закрыт"
    - "Пароль верный"
    - "Команда пустая"
  answer: 1
  explanation: "Эндпоинт требует токен — публичные данные недоступны."
- question: "Что категорически нельзя делать в рамках разведки Slack?"
  options:
    - "Смотреть заголовок страницы входа"
    - "Вступать в workspace и читать переписку"
    - "Проверять код ответа"
    - "Читать email_domain"
  answer: 1
  explanation: "Вступление и чтение переписки — это доступ, а не разведка."
```

## Куда дальше

Дальше в модуле — **Jira и Confluence**: научимся находить инстанс Atlassian и читать его метаданные сервера. А пока запомни: workspace Slack выдаёт себя заголовком и доменом, а его метаданные связывают команду с организацией.

## Где пригодится

- **Пентест:** карта рабочих инструментов и SSO организации.
- **Bug bounty:** поиск workspace в scope.
- **CTF (OSINT):** определение компании по Slack-домену.
- **Blue team:** контроль публичной экспозиции workspace.
"""
write_lesson(slack, slack_body, lab=slack["lab"])

jira = dict(
    id="osint-jira-confluence", title="Jira и Confluence: поиск инстанса и метаданные",
    category="osint", parent="osint-mod-saas-devops", difficulty="medium", order=2,
    tags=["osint","jira","confluence","atlassian","recon"], prerequisites=["osint-slack-enum"],
    useful_for=U, estimated_minutes=50,
    summary="Как найти Jira/Confluence организации, определить версию и прочитать публичные метаданные сервера через REST API.",
    lab=dict(title="Практика: инстанс Jira", toolset=["core","curl","jq"], workdir="/home/student/task",
        files=["task.md"], check="grep -q 'nto{' answer.txt",
        hints=["Метаданные сервера: `curl -s https://jira.example.com/rest/api/2/serverInfo`.",
               "Поле `version` — версия Jira, `serverTitle` — название.",
               "Проверь `/rest/api/2/dashboard` на публичные дашборды.",
               "Маркер `nto{...}` — в ответе; запиши в `answer.txt`, затем `check`."],
        expect={"file":"/home/student/task/answer.txt","contains":"nto{j1r4_s3rv3r1nf0_l34k}"},
        fs=[{"path":"/home/student/task","type":"dir"},
            {"path":"/home/student/task/task.md","text":"# Практика: Jira recon\n\n1. `curl -s https://jira.example.com/rest/api/2/serverInfo`\n2. Найди `version`, `serverTitle`, `buildNumber`.\n3. `curl -s https://jira.example.com/rest/api/2/dashboard`\n4. Маркер `nto{...}` — запиши в `answer.txt`, затем `check`.\n"}],
        tools={"curl":{"help":"curl [-s] <URL> — эмуляция ответов Jira","cases":[
            {"match":"serverInfo","example":"curl -s https://jira.example.com/rest/api/2/serverInfo",
             "output":"{\"baseUrl\":\"https://jira.example.com\",\"version\":\"9.4.0\",\"versionNumbers\":[9,4,0],\"deploymentType\":\"Server\",\"buildNumber\":940000,\"buildDate\":\"2023-02-01T00:00:00.000+0000\",\"serverTitle\":\"Example Corp Jira\",\"x_flag\":\"nto{j1r4_s3rv3r1nf0_l34k}\"}\n"},
            {"match":"dashboard","example":"curl -s https://jira.example.com/rest/api/2/dashboard",
             "output":"{\"dashboards\":[{\"id\":\"10000\",\"name\":\"Example Corp - Engineering\",\"self\":\"https://jira.example.com/rest/api/2/dashboard/10000\"}],\"total\":1}\n"}],
            "fallback":"curl: в этой лабе доступен только jira.example.com.\n"},
        "jq":{"help":"jq [опции] <фильтр> <файл> — разбор JSON (эмуляция)","cases":[
            {"match":"version|serverTitle|\\.","example":"jq -r .version info.json","output":"9.4.0\n"}],
            "fallback":"jq: в этой лабе поддерживается разбор полей.\n"}},
    ),
)
jira_body = r"""## Вопрос, с которого всё начинается

Организация ведёт разработку — значит, где-то живут её задачи и документация. Чаще всего это Jira и Confluence от Atlassian. Их инстансы торчат в интернет, и у каждого есть публичные страницы: страница входа, REST API, иногда открытые дашборды.

Задача: найти инстанс Jira или Confluence компании, определить его версию и прочитать публичные метаданные сервера — не входя в систему.

## Наш пример: инстанс Jira

Держим объект `https://jira.example.com`. Первый вопрос: **какой это Jira и насколько он свежий?** Atlassian отдаёт это через REST-эндпоинт `serverInfo`.

```bash
curl -s https://jira.example.com/rest/api/2/serverInfo | jq .
```

```json
{"baseUrl":"https://jira.example.com","version":"9.4.0","versionNumbers":[9,4,0],
 "deploymentType":"Server","buildNumber":940000,
 "serverTitle":"Example Corp Jira"}
```

Читаем: `version: 9.4.0` — конкретная версия, `deploymentType: Server` — это self-hosted, а не Cloud, `serverTitle` — название, часто с именем организации. Уже отсюда видно: инстанс корпоративный и, возможно, требует обновления.

## Шаг 1: как находят инстанс

Инстансы ищут по трём каналам. Первый — DNS: поддомены `jira`, `confluence`, `wiki`, `issues`, `tickets`. Второй — поисковые дорки: `inurl:/secure/Dashboard.jspa`, `inurl:/rest/api/2/serverInfo`, `intitle:"Log in - Confluence"`. Третий — CT-логи и favicon-хэши: у Jira и Confluence узнаваемая иконка, и по её хэшу находят все инстансы в Shodan.

```text
# дорки (иллюстративно)
inurl:/secure/Dashboard.jspa "Example"
inurl:/rest/api/2/serverInfo
intitle:"Log in - Confluence"
```

Комбинация трёх каналов почти всегда выводит на живой инстанс.

## Шаг 2: читаем метаданные сервера

`serverInfo` — золотая жила разведчика. Он даёт версию, тип развёртывания, дату сборки и заголовок. По версии определяют, уязвим ли инстанс к известным CVE.

```bash
curl -s https://jira.example.com/rest/api/2/serverInfo | jq -r '.version, .deploymentType, .serverTitle'
```

```text
9.4.0
Server
Example Corp Jira
```

Важно: сам по себе факт версии — не уязвимость. Это вход в разведку: зная версию, ты сверяешь её с публичными базами уязвимостей и понимаешь, актуален ли патч. Дальше — только в рамках авторизованного теста.

## Шаг 3: публичные дашборды и проекты

Часто инстанс отдаёт без входа список дашбордов и проектов — они не всегда закрыты правильно.

```bash
curl -s https://jira.example.com/rest/api/2/dashboard | jq -r '.dashboards[].name'
```

```text
Example Corp - Engineering
```

Названия дашбордов выдают структуру команд: направления, проекты, отделы. Иногда виден user picker `/rest/api/2/user/picker?query=`, который по подстроке подсказывает существующие учётные записи.

## Шаг 4: Confluence и границы

Confluence устроен похоже. Метаданные видны через `/rest/api/`, версия — через страницу входа или заголовки. Публичные пространства (spaces) иногда читаются без входа — там могут быть технические регламенты, схемы сетей, инструкции.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://wiki.example.com/login.action
```

```text
200
```

Границы те же: **мы фиксируем версию и публичные метаданные, но не пытаемся эксплуатировать найденные CVE и не читаем закрытые пространства**. Уязвимость в отчёте — это строка с версией и ссылкой на CVE, а не попытка входа.

## Полный прогон

```bash
# 1. версия Jira
curl -s https://jira.example.com/rest/api/2/serverInfo | jq -r '.version, .serverTitle'
# → 9.4.0 / Example Corp Jira
# 2. публичные дашборды
curl -s https://jira.example.com/rest/api/2/dashboard | jq -r '.dashboards[].name'
# → Example Corp - Engineering
# 3. Confluence жив?
curl -s -o /dev/null -w '%{http_code}\n' https://wiki.example.com/login.action
# → 200
```

Непрерывно: поддомен → serverInfo → версия → дашборды → Confluence → профиль документации компании.

## Если не сработало

**serverInfo закрыт.** Некоторые админы прячут эндпоинт — тогда версию ищут по странице входа и заголовкам.
**Инстанс в Atlassian Cloud.** Тогда домен `*.atlassian.net` — другой набор путей и метаданных.
**Confluence без Jira.** Проверь отдельно: `confluence`, `wiki`, `docs`.

## Частые ошибки

**Ошибка: считать версию доказательством уязвимости.** Версия — гипотеза; уязвимость подтверждается отдельно и в авторизованном тесте.
**Ошибка: пытаться эксплуатировать CVE в разведке.** Разведка фиксирует, эксплуатация — отдельная фаза.
**Ошибка: путать Server и Cloud.** У Cloud (`*.atlassian.net`) другой контур и другие метаданные.
**Ошибка: игнорировать favicon.** Хэш иконки — мощный идентификатор для поиска инстансов.

## Справочная таблица: эндпоинты Jira/Confluence

| Эндпоинт | Что даёт |
|----------|----------|
| `/rest/api/2/serverInfo` | версия, тип, заголовок сервера |
| `/rest/api/2/dashboard` | публичные дашборды |
| `/rest/api/2/user/picker?query=` | подсказка существующих пользователей |
| `/secure/Dashboard.jspa` | страница входа Jira |
| `/login.action` (Confluence) | страница входа Confluence |
| `/rest/api/` (Confluence) | метаданные API |

## Разбор кейса: от дорка до карты команд

Дано: домен `example.com`. Шаг первый — дорк `inurl:/secure/Dashboard.jspa "Example"` выводит на `jira.example.com`. Шаг второй — `serverInfo` отдаёт `version 9.4.0`, `deploymentType Server`. Шаг третий — `/rest/api/2/dashboard` показывает дашборд «Engineering»; значит, у компании есть инженерный отдел, работающий в Jira. Шаг четвёртый — `wiki.example.com` отвечает `200`; это Confluence с документацией. Вывод: организация ведёт разработку на self-hosted Atlassian, версия известна, документация на отдельном поддомене. Разведчик получил карту внутренних процессов — и повод проверить актуальность патчей в авторизованной фазе.

## Частые вопросы

**Чем Jira отличается от Confluence?** Jira — трекинг задач и проектов, Confluence — вики и документация. Часто стоят рядом и связаны SSO.

**Почему версия так важна?** Потому что по ней определяют соответствие патчам. Но версия — это вход в разведку, а не готовый эксплойт.

**Что видно без входа?** Метаданные сервера, иногда дашборды и публичные пространства. Задачи и закрытые пространства — нет.

**Как искать инстансы массово?** По favicon-хэшу и доркам в Shodan/Censys. Один хэш даёт сотни инстансов.

**Это законно?** Чтение публичных метаданных — да. Эксплуатация и вход — нет, без авторизации.

## Термины

**serverInfo** — REST-эндпоинт Jira с метаданными сервера.

**Deployment type** — Server (self-hosted) или Cloud (`*.atlassian.net`).

**Dashboard** — панель задач в Jira, иногда публичная.

**Space** — пространство документации в Confluence.

**User picker** — эндпоинт подсказки имён пользователей.

## Что мы теперь знаем

1. Инстансы Jira/Confluence находят по DNS, доркам и favicon.
2. `serverInfo` отдаёт версию, тип и заголовок сервера.
3. Дашборды и публичные пространства выдают структуру команд.
4. Версия — гипотеза об уязвимости, а не доказательство.
5. Разведка фиксирует метаданные, не эксплуатируя.

## Квиз

Проверь себя.

```quiz
- question: "Какой эндпоинт Jira отдаёт версию сервера?"
  options:
    - "/rest/api/2/serverInfo"
    - "/robots.txt"
    - "/favicon.ico"
    - "/wp-login.php"
  answer: 0
  explanation: "serverInfo возвращает version, deploymentType, serverTitle."
- question: "Что означает deploymentType: Server?"
  options:
    - "Облачный Atlassian"
    - "Self-hosted инстанс"
    - "Прокси"
    - "CDN"
  answer: 1
  explanation: "Server — самостоятельно размещённый инстанс."
- question: "Что даёт favicon-хэш при поиске инстансов?"
  options:
    - "Пароль"
    - "Массовый поиск инстансов по иконке в Shodan/Censys"
    - "Список сотрудников"
    - "Резервные коды"
  answer: 1
  explanation: "Узнаваемая иконка идентифицирует все инстансы Jira/Confluence."
- question: "Что допустимо в разведке Jira?"
  options:
    - "Эксплуатировать CVE"
    - "Читать публичные метаданные сервера"
    - "Входить в закрытые проекты"
    - "Менять задачи"
  answer: 1
  explanation: "Разведка читает публичное; эксплуатация — отдельная фаза."
```

## Куда дальше

Дальше в модуле — **CI/CD**: разведка Jenkins, GitLab и GitHub Actions. А пока запомни: инстанс Atlassian выдаёт себя версией и дашбордами, а favicon-хэш находит их массово.

## Где пригодится

- **Пентест:** поиск инстансов Atlassian и их версий.
- **Bug bounty:** инстансы Jira/Confluence в scope.
- **CTF (OSINT):** метаданные сервера и структура команд.
- **Blue team:** контроль версий и публичной экспозиции.
"""
write_lesson(jira, jira_body, lab=jira["lab"])
print("Batch C done: slack, jira")
