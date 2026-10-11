---
id: web-tool-httpx-katana
title: "httpx и katana: полный практический справочник"
category: web
parent: web-tools-recon
difficulty: medium
order: 1
tags: [httpx, katana, recon, probing, crawling, tech-detect, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Все флаги httpx (проба хостов, технологии, матчеры, JSON) и katana (краулинг, JS-crawl, формы, фильтры) с пайплайнами."
---

`httpx` (ProjectDiscovery) и `katana` — два инструмента разведки, которые работают в паре: **httpx** берёт огромный список целей и быстро «пробует» их — что живо, какой код ответа, title, сервер, технологии, редиректы. **katana** берёт живые хосты и обходит их как паук — собирает URL, эндпоинты, параметры, а при необходимости и то, что генерируется в JavaScript.

Этот урок — **рабочий справочник**: полные таблицы флагов, разбор режимов и пайплайны, которые связывают оба инструмента с nuclei/ffuf.

## Шпаргалка: флаги, которые нужны в 90% задач

| Команда/флаг | Что делает | Пример |
|------|-----------|--------|
| `httpx -l LIST -sc -title -td` | проба: код, title, технологии | `httpx -l subs.txt -silent -sc -title -td` |
| `httpx -mc` / `-fc` | матчер / фильтр по коду | `-mc 200,302 -fc 404` |
| `httpx -json -o FILE` | JSON-вывод | `-json -o httpx.jsonl` |
| `httpx -p` | порты для http/https-пробы | `-p 80,443,8080` |
| `httpx -path` | проверка конкретных путей | `-path /admin,/api` |
| `httpx -td` | определение технологий | `-td` |
| `httpx -favicon` | хэш favicon (mmh3) | `-favicon` |
| `katana -u URL -jc` | краулинг с разбором JS | `katana -u https://t -jc -silent` |
| `katana -d` | глубина краулинга | `-d 3` |
| `katana -kf all` | известные файлы (robots/sitemap) | `-kf all` |
| `katana -fx` | извлечь формы | `-fx -jsonl` |
| `katana -jsonl -o FILE` | JSONL-вывод | `-j -o crawl.jsonl` |

## Когда httpx и katana, а когда другой инструмент

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Понять, что живо из списка | **httpx** | Массовая HTTP-проба + метаданные |
| Определить технологии/стек | **httpx** | `-tech-detect`, `-title`, `-server` |
| Быстрый скан портов по http/https | **httpx** | `-ports`/`-p` |
| Собрать все URL и параметры | **katana** | Краулинг + JS-парсинг |
| Найти эндпоинты внутри JS | **katana** | `-js-crawl`, `-jsluice` |
| Перебрать пути | ffuf/feroxbuster | Перебор, а не краулинг |
| Найти известные баги | nuclei | Сигнатуры |

Правило: **httpx — «кто дома и что это», katana — «что внутри», ffuf — «что спрятано», nuclei — «что сломано»**.

## httpx: базовый синтаксис и цели

```bash
httpx [флаги] -u URL
httpx [флаги] -l targets.txt
```

| Флаг | Что делает |
|------|-----------|
| `-u, -target` | Цель |
| `-l, -list` | Файл со списком целей |
| `-request` | Сырой запрос как шаблон |
| `-resume` | Продолжить с прогресс-файла |
| `-silent` | Только результаты |
| `-v, -verbose` | Подробнее |
| `-nc, -no-color` | Без ANSI |
| `-json` | JSON-вывод (по строке) |
| `-csv` | CSV-вывод |

Часто httpx читает цели из stdin (пайплайн):

```bash
subfinder -d target.com -silent | httpx -silent -sc -title -td
```

## httpx: флаги проб

По умолчанию httpx не печатает много — включайте нужные «пробы» явно.

| Флаг | Что показывает |
|------|---------------|
| `-sc, -status-code` | HTTP-код |
| `-cl, -content-length` | Длина тела |
| `-ct, -content-type` | Content-Type |
| `-location` | Location (редирект) |
| `-title` | `<title>` страницы |
| `-server, -web-server` | Заголовок Server |
| `-td, -tech-detect` | Технологии (wappalyzer) |
| `-rt, -response-time` | Время ответа |
| `-lc, -line-count` | Число строк |
| `-wc, -word-count` | Число слов |
| `-ip` | IP хоста |
| `-cname` | CNAME |
| `-cdn` | CDN-имя |
| `-favicon` | Хэш favicon |
| `-hash` | Хэши (`md5,mmh3,sha256,sha1`) |
| `-jarm` | JARM-отпечаток TLS |
| `-tls-grab` | Данные TLS |
| `-asn` | ASN |
| `-websocket` | Проверка WebSocket |
| `-method` | HTTP-метод |
| `-probe` | Статус пробы |
| `-bp, -body-preview` | Превью тела |
| `-frd, -follow-redirects` | Следовать редиректам |
| `-fhr, -follow-host-redirects` | Только внутри хоста |
| `-maxr, -max-redirects` | Макс. редиректов |

```bash
cat subs.txt | httpx -silent -sc -title -td -server -cl
```

## httpx: матчеры, фильтры, вывод

**Матчеры** (что оставить):

| Флаг | Что матчит |
|------|-----------|
| `-mc, -match-code` | Коды |
| `-ml, -match-length` | Длина |
| `-mlc, -match-line-count` | Строки |
| `-mwc, -match-word-count` | Слова |
| `-mr, -match-regex` | Regexp |
| `-ms, -match-string` | Строка |
| `-mdc, -match-condition` | DSL-условие |
| `-mfc, -match-favicon` | Favicon-хэш |

**Фильтры** (что убрать):

| Флаг | Что фильтрует |
|------|--------------|
| `-fc, -filter-code` | Коды |
| `-fl, -filter-length` | Длину |
| `-flc, -filter-line-count` | Строки |
| `-fwc, -filter-word-count` | Слова |
| `-fr, -filter-regex` | Regexp |
| `-fs, -filter-string` | Строку |
| `-fdc, -filter-condition` | DSL-условие |
| `-ffc, -filter-favicon` | Favicon |

**Вывод и производительность:**

| Флаг | Что делает |
|------|-----------|
| `-o, -output` | Файл |
| `-oa, -output-all` | Все форматы |
| `-od, -output-dir` | Каталог |
| `-sr, -store-response` | Сохранить ответы |
| `-srd, -store-response-dir` | Каталог ответов |
| `-rl, -rate-limit` | Запросов/сек |
| `-t, -threads` | Потоки (по умолчанию 50) |
| `-timeout` | Таймаут |
| `-retries` | Повторы |
| `-stats` | Показывать статистику |

```bash
httpx -l alive.txt -mc 200,302 -title -td -json -o httpx.jsonl
```

## httpx: порты, пути, JSON и пайплайны

**Скан http/https по портам:**

```bash
httpx -l ips.txt -p 80,443,8080,8443,8000,8888 -sc -title
httpx -l ips.txt -ports http:80,https:443,http:8080
```

**Проверка путей:**

```bash
httpx -l hosts.txt -path /admin,/api,/swagger -sc -cl
```

**JSON + jq:**

```bash
httpx -l subs.txt -json -silent -sc -title -td \
  | jq -r 'select(.status_code==200) | "\(.host) \(.title) \(.tech)"'
```

**Пайплайн в nuclei/katana:**

```bash
cat subs.txt | httpx -silent -mc 200,302 | katana -silent -jc | nuclei -silent
```

## katana: базовый синтаксис и глубина

```bash
katana -u https://target.com
katana -list urls.txt
```

| Флаг | Что делает |
|------|-----------|
| `-u, -list` | Цель / файл со списком |
| `-d, -depth` | Глубина краулинга (по умолчанию 3) |
| `-ct, -crawl-duration` | Лимит времени (`30s`, `5m`) |
| `-s, -strategy` | Стратегия: `depth-first`, `breadth-first` |
| `-pc, -path-climb` | Авто-подъём по родительским путям |
| `-resume` | Продолжить |
| `-e, -exclude` | Исключить хосты (`cdn`, `private-ips`, cidr, regex) |
| `-proxy` | Прокси |
| `-H, -headers` | Заголовки/cookie |
| `-timeout` | Таймаут запроса |
| `-retry` | Повторы |
| `-iqp, -ignore-query-params` | Игнорировать разные значения query |
| `-fsu, -filter-similar` | Фильтровать похожие URL (`/users/1`, `/users/2`) |
| `-dr, -disable-redirects` | Отключить редиректы |
| `-td, -tech-detect` | Определение технологий |
| `-kb, -knowledge-base` | Классификация через базу знаний |

```bash
katana -u https://target.com -d 3 -s breadth-first -silent
```

## katana: JS-crawl, известные файлы, форм-филлинг

Современные SPA строят ссылки в JavaScript — без `-jc` katana их не увидит.

| Флаг | Что делает |
|------|-----------|
| `-jc, -js-crawl` | Парсить/краулить JS-файлы |
| `-jsl, -jsluice` | Глубокий парсинг JS (jsluice, память-интенсивный) |
| `-kf, -known-files` | Краулить `all`, `robotstxt`, `sitemapxml` |
| `-aff, -automatic-form-fill` | Авто-заполнение форм (эксперим.) |
| `-fx, -form-extraction` | Извлекать формы/input/textarea/select в JSONL |
| `-fc, -form-config` | Свой конфиг форм |
| `-flc, -field-config` | Свой конфиг полей |
| `-hl, -headless` | Headless-краулинг |
| `-hh, -hybrid` | Гибрид (обычный + headless) |
| `-xhr, -xhr-extraction` | Извлекать XHR-запросы в JSONL |
| `-sc, -system-chrome` | Использовать локальный Chrome |
| `-nos, -no-sandbox` | Chrome `--no-sandbox` |

```bash
katana -u https://target.com -jc -kf all -fx -jsonl -o crawl.jsonl
katana -u https://target.com -hl -jc -xhr -silent
```

## katana: фильтры, scope, вывод

**Scope (что краулить):**

| Флаг | Что делает |
|------|-----------|
| `-cs, -crawl-scope` | Regex URL в scope |
| `-cos, -crawl-out-scope` | Regex URL вне scope |
| `-fs, -field-scope` | Предустановленный scope (`dn`, `rdn`, `fqdn`) или regex |
| `-ns, -no-scope` | Отключить host-based scope |
| `-do, -display-out-scope` | Показать внешние эндпоинты |

**Фильтры вывода:**

| Флаг | Что делает |
|------|-----------|
| `-mr, -match-regex` | Оставить URL по regex |
| `-fr, -filter-regex` | Убрать URL по regex |
| `-em, -extension-match` | Оставить по расширению |
| `-ef, -extension-filter` | Убрать по расширению |
| `-fpt, -filter-page-type` | Убрать `error,captcha,parked` |
| `-mdc, -match-condition` | DSL-условие (оставить) |
| `-fdc, -filter-condition` | DSL-условие (убрать) |
| `-duf, -disable-unique-filter` | Отключить фильтр дубликатов |

**Rate-limit и вывод:**

| Флаг | Что делает |
|------|-----------|
| `-c, -concurrency` | Параллельных фетчеров (по умолчанию 10) |
| `-p, -parallelism` | Параллельных входов (по умолчанию 10) |
| `-rl, -rate-limit` | Запросов/сек |
| `-rd, -delay` | Задержка между запросами |
| `-o, -output` | Файл |
| `-j, -jsonl` | JSONL-вывод |
| `-sr, -store-response` | Сохранить запрос/ответ |
| `-or, -omit-raw` | Убрать сырые данные из JSONL |
| `-ob, -omit-body` | Убрать тело |
| `-lof, -list-output-fields` | Список полей JSONL |
| `-ot, -output-template` | Свой шаблон вывода |
| `-silent` | Только вывод |

```bash
katana -u https://t -jc -ef png,css,woff -fr 'logout' -jsonl -o urls.jsonl
jq -r 'select(.url) | .url' urls.jsonl | sort -u > endpoints.txt
```

## Дополнительные флаги httpx и katana (полный охват)

**httpx:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-p` / `-ports` | порты для http/https-пробы | `httpx -l ips.txt -p 80,443,8080` |
| `-path` | пути для проверки | `httpx -l hosts.txt -path /admin,/api` |
| `-screenshot` | сделать скриншот (headless) | `httpx -l alive.txt -screenshot` |
| `-st` / `-screenshot-timeout` | таймаут скриншота | `httpx -l alive.txt -screenshot -st 20` |
| `-http2` | использовать HTTP/2 | `httpx -l alive.txt -http2` |
| `-pipeline` | HTTP/1.1 pipelining | `httpx -l alive.txt -pipeline` |
| `-proxy` | прокси | `httpx -l alive.txt -proxy http://127.0.0.1:8080` |
| `-random-agent` | случайный User-Agent | `httpx -l alive.txt -random-agent` |
| `-H` / `-header` | свой заголовок | `httpx -l alive.txt -H 'X-Foo: bar'` |
| `-body` | тело для POST-пробы | `httpx -l alive.txt -method POST -body 'a=1'` |
| `-config FILE` | файл конфигурации | `httpx -l alive.txt -config httpx.yaml` |
| `-auth` | Basic-аутентификация `user:pass` | `httpx -l alive.txt -auth admin:pass` |
| `-unsafe` | разрешить небезопасные запросы | `httpx -l alive.txt -unsafe` |
| `-sni` | свой TLS SNI | `httpx -l ips.txt -sni t.local` |
| `-tls-impersonate` | имитация TLS-отпечатка браузера | `httpx -l alive.txt -tls-impersonate` |
| `-ztls` | ztls-стек (устаревший TLS) | `httpx -l alive.txt -ztls` |
| `-r` / `-resolvers` | свои DNS-резолверы | `httpx -l alive.txt -r 1.1.1.1` |
| `-eh` / `-exclude-hosts` | исключить хосты | `httpx -l alive.txt -eh 10.0.0.1` |
| `-exclude` | исключить по regex | `httpx -l alive.txt -exclude 'staging'` |
| `-allow` / `-deny` | allow/deny по regex | `httpx -l alive.txt -allow 'prod'` |
| `-fe` / `-filter-error-page` | фильтровать страницы-ошибки | `httpx -l alive.txt -fe` |
| `-fd` / `-filter-duplicates` | фильтровать дубликаты | `httpx -l alive.txt -fd` |
| `-oB` / `-omit-body` | не выводить тело | `httpx -l alive.txt -oB` |
| `-j` / `-jsonl` | JSONL-вывод | `httpx -l alive.txt -j` |
| `-si` / `-stats-interval` | интервал статистики | `httpx -l alive.txt -stats -si 10` |
| `-rlm` / `-rate-limit-minute` | лимит запросов в минуту | `httpx -l alive.txt -rlm 600` |
| `-max-host-error` | ошибок на хост до пропуска | `httpx -l alive.txt -max-host-error 20` |
| `-sa` / `-scan-all-ips` | сканировать все IP домена | `httpx -l hosts.txt -sa` |
| `-iv` / `-ip-version` | версия IP (4/6) | `httpx -l hosts.txt -iv 4` |
| `-im` / `-input-mode` | формат входа (burp/jsonl/openapi) | `httpx -l burp.xml -im burp` |
| `-host-ip` | показывать `host:ip` | `httpx -l alive.txt -host-ip` |
| `-include-chain` | показать цепочку редиректов | `httpx -l alive.txt -include-chain` |

**katana:**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-ps` / `-passive` | пассивный краулинг (без новых запросов) | `katana -u https://t -ps -silent` |
| `-ho` / `-headless-options` | опции Chrome (`--no-sandbox` и др.) | `katana -u https://t -hl -ho '--disable-gpu'` |
| `-cdd` / `-chrome-data-dir` | каталог данных Chrome | `katana -u https://t -hl -cdd /tmp/chrome` |
| `-cwu` / `-chrome-ws-url` | подключиться к уже запущенному Chrome | `katana -u https://t -hl -cwu ws://127.0.0.1:9222/devtools/browser/ID` |
| `-elog` / `-error-log` | лог ошибок в файл | `katana -u https://t -elog err.log` |

> Опущены чисто отладочные флаги httpx (`-debug`, `-debug-req`, `-debug-resp`, `-health-check`, `-no-stdin`) и katana (`-version`, дополнительные `-v`-уровни) — они не влияют на результат разведки.

## Пайплайн httpx → katana → ffuf/nuclei

Классический поток «от поддоменов до находок»:

```bash
# 1. живые хосты с метаданными
subfinder -d target.com -silent | httpx -silent -sc -title -td -o alive.txt

# 2. обход живых (JS включён)
katana -list alive.txt -jc -d 3 -silent -o urls.txt

# 3. известные баги по живым хостам
nuclei -l alive.txt -severity medium,high,critical -silent -o nuc.txt

# 4. скрытые пути на интересном хосте
ffuf -u https://interesting.target.com/FUZZ -w raft-medium-directories.txt -ac -o dirs.json -of json
```

Только URL с параметрами (кандидаты на инъекции/IDOR):

```bash
katana -list alive.txt -jc -silent | grep '?' | sort -u > with_params.txt
```

## Рецепты

**1. Проба списка с ключевыми метаданными:**

```bash
httpx -l subs.txt -silent -sc -title -td -server -cl -o alive.txt
```

**2. Только «интересные» ответы (200/302/403):**

```bash
httpx -l subs.txt -mc 200,302,403 -title -td -silent
```

**3. Быстрый http-скан портов:**

```bash
httpx -l ips.txt -p 80,443,8080,8443,8000 -sc -title -silent
```

**4. Поиск по конкретным путям:**

```bash
httpx -l hosts.txt -path /admin,/login,/api,/swagger -mc 200,401,403 -silent
```

**5. Глубокий обход SPA:**

```bash
katana -u https://t -jc -jsl -hl -d 5 -c 20 -silent -o crawl.txt
```

**6. Извлечение форм и XHR:**

```bash
katana -u https://t -fx -xhr -jsonl -o forms.jsonl
jq -r 'select(.xhr) | .xhr' forms.jsonl | sort -u
```

**7. Обход с авторизацией:**

```bash
katana -u https://t -H 'Authorization: Bearer eyJ...' -jc -silent -o auth_urls.txt
```

**8. JSON-пайплайн с jq:**

```bash
httpx -l subs.txt -json -silent -sc -td \
  | jq -r 'select(.status_code==200 and (.tech|length>0)) | "\(.host) \(.tech|join(","))"'
```

## Что выбрать и когда

- **«Что живо» из большого списка:** httpx `-sc -title`.
- **Понять стек:** httpx `-td -server -title`.
- **Собрать URL:** katana `-jc -d 3`.
- **SPA на JS:** katana `-jc -jsl` (при необходимости `-hl`).
- **Формы/поля:** katana `-fx -aff`.
- **Только внешние/внутренние ссылки:** katana `-do` / scope-флаги.
- **Скрытые пути:** ffuf/feroxbuster (не httpx/katana).
- **Известные баги:** nuclei по списку httpx.
- **Пайплайн:** subfinder → httpx → katana → nuclei/ffuf.

## Частые ошибки

- **Забыть `-silent` в пайплайне.** Баннеры ломают разбор stdout.
- **Краулить без `-jc`.** SPA-ссылки в JS не найдутся.
- **`-jsl` на большом сайте.** jsluice память-интенсивен; начинайте с `-jc`.
- **Игнорировать scope.** katana по умолчанию ограничен доменом; для внешних ссылок — `-do`/`-cs`.
- **Слишком высокая параллельность.** `-c 100` на слабом сервере = бан; начинайте с 10–20.
- **Путать `-fs` в katana.** Это `-field-scope`, а не filter-similar (это `-fsu`).
- **Не включать пробы httpx.** Без `-sc -title -td` вывод почти пустой — флаги включают поля явно.
- **Долгий краулинг убит таймаутом.** Ставьте `-ct 5m` и/или запускайте в фоне.

## Квиз

```quiz
- question: "Что делает httpx по умолчанию, если не указать флаги проб?"
  options:
    - "Показывает title и технологии"
    - "Показывает только статус ответа (жив/не жив)"
    - "Краулит сайт"
    - "Пишет SARIF"
  answer: 1
  explanation: "httpx только «пробует» цель; метаданные включаются флагами -sc/-title/-td."
- question: "Какой флаг katana включает разбор ссылок внутри JavaScript?"
  options:
    - "-d"
    - "-jc"
    - "-kf"
    - "-dr"
  answer: 1
  explanation: "-js-crawl парсит JS-файлы и извлекает эндпоинты."
- question: "Как подать список целей в httpx?"
  options:
    - "-l targets.txt"
    - "-w targets.txt"
    - "-m targets.txt"
    - "-t targets.txt"
  answer: 0
  explanation: "-l/-list читает список целей (по строке); -t — это threads."
- question: "Что такое -fs в katana?"
  options:
    - "Фильтр по размеру"
    - "Field-scope (область краулинга)"
    - "Следование редиректам"
    - "Формат вывода"
  answer: 1
  explanation: "В katana -fs/-field-scope задаёт область краулинга; filter-similar — это -fsu."
- question: "Зачем в пайплайне после subfinder ставят httpx?"
  options:
    - "Чтобы краулить сайт"
    - "Чтобы оставить только живые хосты и добавить метаданные"
    - "Чтобы найти SQLi"
    - "Чтобы скачать файлы"
  answer: 1
  explanation: "httpx отсеивает мёртвое и обогащает список перед katana/nuclei."
```

## Где пригодится

- **CTF (Web):** быстро понять, что за приложение, и собрать эндпоинты до ручного анализа.
- **Bug bounty:** пайплайн subfinder → httpx → katana → nuclei — стандарт разведки программы.
- **Пентест:** карта живых хостов и URL с параметрами — основа для фаззинга и инъекций.
- **Работа (AppSec):** инвентаризация поверхности атаки, отслеживание изменений в технологиях.
