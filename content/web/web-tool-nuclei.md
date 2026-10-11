---
id: web-tool-nuclei
title: "nuclei: полный практический справочник"
category: web
parent: web-tools-recon
difficulty: medium
order: 2
tags: [nuclei, templates, scanner, cve, dast, fuzzing, oob, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 50
summary: "Все флаги nuclei: цели, фильтрация шаблонов, rate-limit, вывод, свой YAML-шаблон, DAST-режим и Interactsh OOB."
---

`nuclei` — шаблонный сканер уязвимостей: вы даёте ему цель, он прогоняет тысячи YAML-шаблонов сообщества (CVE, мисконфиги, exposed-панели, takeover, дефолтные креды) и оставляет совпадения. Его сила — **скорость + огромная база шаблонов + расширяемость**: если шаблона нет, вы пишете свой.

Этот урок — **рабочий справочник**: как ставить и обновлять, как фильтровать шаблоны, как не устроить DoS, как писать свои шаблоны, как гонять DAST-режим и как парсить вывод. Версия в примерах — nuclei 3.x.

## Шпаргалка: флаги, которые нужны в 90% задач

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u` / `-l` | цель / файл со списком целей | `nuclei -u https://t` |
| `-ut` | обновить базу шаблонов | `nuclei -update-templates` |
| `-tags` | фильтр по тегам | `-tags cve,rce` |
| `-severity` | фильтр по severity | `-severity high,critical` |
| `-id` | конкретная CVE/шаблон | `-id CVE-2024-12345` |
| `-rl` / `-c` | rate-limit / параллельных шаблонов | `-rl 50 -c 25` |
| `-H` | заголовок/cookie во все запросы | `-H 'Authorization: Bearer X'` |
| `-dast` | DAST/fuzz-режим | `-dast -fa low` |
| `-silent` | только находки (для пайплайна) | `-silent` |
| `-j` / `-o` | JSONL и файл вывода | `-j -o nuc.jsonl` |
| `-me DIR` | markdown-экспорт для отчёта | `-me report/` |
| `-as` | авто-подбор тегов по технологиям | `-as` |

## Когда nuclei, а когда другой инструмент

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Быстро найти известные баги | **nuclei** | База шаблонов CVE/мисконфигов |
| Найти скрытые пути | ffuf/feroxbuster | Перебор, а не сигнатуры |
| Подтвердить конкретную CVE | nuclei `-id` | Точечный шаблон + ручная верификация |
| Обойти приложение | katana | Краулинг |
| Проверить инъекцию в параметре | sqlmap/nuclei DAST | Специализированный/фаззинг-режим |
| Массовая проба живых | httpx | Проба, а не скан |

Правило: **nuclei — для известных классов и сигнатур**. Он не заменяет ручной анализ: находка = кандидат, который надо верифицировать.

## Установка, обновление шаблонов, проверка

```bash
# установка (если нет)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# обновление самих шаблонов (не инструмента!)
nuclei -update-templates        # или: nuclei -ut

# проверка версии
nuclei -version

# список доступных тегов
nuclei -tgl

# список шаблонов, подходящих под текущие фильтры
nuclei -tl -tags cve -severity critical
```

Важно: обновляйте **шаблоны** (`-ut`) перед сканом — новые CVE добавляются постоянно.

## Базовый запуск и цели (-u/-l)

| Флаг | Что делает |
|------|-----------|
| `-u, -target` | Одна или несколько целей |
| `-l, -list` | Файл со списком целей (по строке) |
| `-eh, -exclude-hosts` | Исключить хосты (ip/cidr/hostname) |
| `-resume` | Продолжить и сохранять прогресс |
| `-sa, -scan-all-ips` | Сканировать все IP домена |
| `-iv, -ip-version` | Версия IP (4/6) |
| `-im, -input-mode` | Формат входа: `list, burp, jsonl, yaml, openapi, swagger` |

```bash
nuclei -u https://target.com
nuclei -l alive.txt -silent
nuclei -l urls.txt -im burp          # вход — выгрузка Burp XML
nuclei -im openapi -l api.json       # вход — OpenAPI/Swagger
```

**Только важные severity:**

```bash
nuclei -l alive.txt -severity low,medium,high,critical -silent -o nuc.txt
```

## Фильтрация шаблонов

| Флаг | Что фильтрует |
|------|--------------|
| `-t, -templates` | Конкретный шаблон/каталог |
| `-tags` | По тегам (`cve,rce,wordpress`) |
| `-etags, -exclude-tags` | Исключить теги |
| `-itags, -include-tags` | Вернуть даже исключённые |
| `-id, -template-id` | По id шаблона (поддерживает wildcard) |
| `-eid, -exclude-id` | Исключить id |
| `-s, -severity` | По severity |
| `-es, -exclude-severity` | Исключить severity |
| `-a, -author` | По автору |
| `-pt, -type` | По протоколу: `http, dns, tcp, ssl, file, headless, websocket, whois, code, javascript` |
| `-ept, -exclude-type` | Исключить протокол |
| `-tc, -template-condition` | По выражению |
| `-nt, -new-templates` | Только новые шаблоны |
| `-as, -automatic-scan` | Авто-выбор тегов по технологиям (wappalyzer) |
| `-et, -exclude-templates` | Каталог/файл исключить |
| `-em, -exclude-matchers` | Исключить матчеры |

```bash
# только CVE, только high/critical
nuclei -u https://t -tags cve -severity high,critical -silent

# конкретная CVE
nuclei -u https://t -id CVE-2024-12345 -silent

# WordPress-специфика
nuclei -u https://t -tags wordpress -silent

# всё, кроме info и dns-шаблонов
nuclei -l alive.txt -es info -ept dns -silent
```

**Автоматический скан по технологиям** (сам подберёт теги):

```bash
nuclei -u https://t -as -silent
```

## Rate-limit, concurrency, таймауты

По умолчанию nuclei шлёт **150 запросов/сек** — на слабом сервере это DoS. Снижайте.

| Флаг | Что делает | По умолчанию |
|------|-----------|--------------|
| `-rl, -rate-limit` | Запросов в секунду | 150 |
| `-rld, -rate-limit-duration` | Окно rate-limit | 1s |
| `-c, -concurrency` | Параллельных шаблонов | 25 |
| `-bs, -bulk-size` | Хостов на шаблон параллельно | 25 |
| `-pc, -payload-concurrency` | Параллельных payload | 25 |
| `-hbs, -headless-bulk-size` | Хостов для headless | 10 |
| `-timeout` (в шаблоне) | Таймаут запроса | — |
| `-retries` (в шаблоне) | Повторы | — |

```bash
# вежливый скан
nuclei -l alive.txt -rl 30 -c 10 -bs 10 -silent
```

## Заголовки, авторизация, переменные (-H/-V)

| Флаг | Что делает |
|------|-----------|
| `-H, -header` | Свой заголовок/cookie во все запросы |
| `-V, -var` | Пользовательская переменная `key=value` |
| `-ev, -env-vars` | Использовать переменные окружения в шаблонах |
| `-fr, -follow-redirects` | Следовать редиректам |
| `-fhr, -follow-host-redirects` | Редиректы только внутри хоста |
| `-mr, -max-redirects` | Максимум редиректов |
| `-dr, -disable-redirects` | Отключить редиректы |
| `-x` (шаблон) | Прокси в шаблоне |
| `-passive` | Только пассивный анализ ответов |

Скан с авторизацией:

```bash
nuclei -l alive.txt -H 'Authorization: Bearer eyJ...' -H 'Cookie: session=abc' -silent
```

Свои переменные (используются шаблоном как `{{apikey}}`):

```bash
nuclei -u https://t -V apikey=SECRET -t custom-template.yaml
```

## Дополнительные флаги (полный охват)

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-p` / `-proxy` | прокси для запросов | `nuclei -u https://t -p http://127.0.0.1:8080` |
| `-sni` | свой TLS SNI | `nuclei -u https://t -sni t.local` |
| `-r` / `-resolvers` | свои DNS-резолверы | `nuclei -l alive.txt -r 1.1.1.1` |
| `-system-resolvers` | использовать системные резолверы | `nuclei -l alive.txt -system-resolvers` |
| `-timeout N` | таймаут запроса, сек (по умолчанию 10) | `nuclei -u https://t -timeout 15` |
| `-retries N` | число повторов запроса | `nuclei -u https://t -retries 2` |
| `-max-host-error N` | ошибок на хост до пропуска | `nuclei -l alive.txt -max-host-error 30` |
| `-page-timeout N` | таймаут на страницу headless, сек | `nuclei -u https://t -page-timeout 20` |
| `-headc` / `-headless-concurrency` | параллельных headless-браузеров | `nuclei -u https://t -headc 5` |
| `-stream` | потоковый режим (для больших целей) | `nuclei -l big.txt -stream -silent` |
| `-nc` / `-no-color` | без ANSI-цвета | `nuclei -u https://t -nc` |
| `-v` / `-verbose` | подробный вывод | `nuclei -u https://t -v` |
| `-stats` / `-si N` | статистика и её интервал | `nuclei -l alive.txt -stats -si 10` |
| `-metrics` / `-mp PORT` | Prometheus-метрики и порт | `nuclei -l alive.txt -metrics -mp 9092` |
| `-duc` / `-disable-update-check` | не проверять обновления при запуске | `nuclei -u https://t -duc` |
| `-up` / `-update` | обновить сам nuclei | `nuclei -up` |
| `-ud` / `-update-directory` | каталог шаблонов | `nuclei -u https://t -ud /opt/nuclei-templates` |
| `-tl` / `-tgl` | список шаблонов / тегов | `nuclei -tl -tags cve` |
| `-lfa` / `-allow-local-file-access` | разрешить file:// в шаблонах | `nuclei -u https://t -lfa` |
| `-lna` / `-restrict-local-network-access` | запретить SSRF в локальную сеть | `nuclei -u https://t -lna` |
| `-tls-impersonate` | имитация TLS-отпечатка браузера | `nuclei -u https://t -tls-impersonate` |
| `-ztls` | ztls-стек (устаревший TLS) | `nuclei -u https://t -ztls` |
| `-dut` / `-disable-unsigned-templates` | не запускать неподписанные шаблоны | `nuclei -u https://t -dut` |

> Опущены: подкоманды (`nuclei -validate`, `nuclei -wizard`), узкоспециальные серверные/облачные опции (`-scloud-*`, `-sgm`), а также редкие флаги отладки шаблонов (`-dut`-семейство описано выше).

## Форматы вывода

| Флаг | Формат |
|------|--------|
| `-o, -output` | Обычный текстовый файл |
| `-j, -jsonl` | JSONL (по строке на находку) |
| `-je, -json-export` | JSON-файл |
| `-jle, -jsonl-export` | JSONL-файл |
| `-me, -markdown-export` | Каталог с markdown-отчётами |
| `-se, -sarif-export` | SARIF (для CI/дескбордов) |
| `-pe, -pdf-export` | PDF-отчёт |
| `-sresp, -store-resp` | Сохранить запросы/ответы |
| `-srd, -store-resp-dir` | Каталог для них |
| `-rdb, -report-db` | Локальная БД отчётов |
| `-silent` | Только находки |
| `-nm, -no-meta` | Без метаданных в CLI |
| `-ms, -matcher-status` | Показать статус матчеров |
| `-or, -omit-raw` | Убрать пары запрос/ответ |
| `-ot, -omit-template` | Убрать шаблон из JSON |

Парсинг JSONL через jq:

```bash
nuclei -l alive.txt -j -o nuc.jsonl -silent
jq -r '"\(.info.severity)\t\(.template-id)\t\(.host)\t\(.matched-at)"' nuc.jsonl | sort
```

Только critical/high в удобном виде:

```bash
jq -r 'select(.info.severity=="critical" or .info.severity=="high")
       | "\(.info.severity) \(.template-id) \(.matched-at)"' nuc.jsonl
```

Markdown-экспорт для отчёта:

```bash
nuclei -l alive.txt -me report/ -silent
```

## Анатомия своего шаблона (YAML)

Структура минимального HTTP-шаблона:

```yaml
id: my-custom-check

info:
  name: My Custom Check
  author: me
  severity: medium
  description: Detects an exposed debug endpoint
  reference:
    - https://example.com/advisory
  tags: exposure,debug
  classification:
    cwe-id: CWE-200

http:
  - method: GET
    path:
      - "{{BaseURL}}/debug/status"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "debug_enabled"
          - "build_id"
        condition: and
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "build_id\":\"([0-9a-f]+)\""
```

Разбор блоков:

- `id` — уникальный идентификатор шаблона (CVE-шаблоны называют по id CVE!).
- `info` — метаданные: `name`, `author`, `severity`, `description`, `reference`, `tags`, `classification`.
- `http` — список запросов: `method`, `path` (`{{BaseURL}}` — цель), `headers`, `body`, `redirects`, `attack` (для fuzz).
- `matchers` — условия совпадения: `type` (`status, word, regex, dsl, binary, size`), `part` (`body, header, all`), `words`, `regex`, `status`, `dsl`, `condition` (`and`/`or`).
- `extractors` — что вытащить: `type` (`regex, kval, json, xpath, dsl`), `group`, `regex`.

Проверка и запуск своего шаблона:

```bash
nuclei -validate -t my-custom-check.yaml
nuclei -u https://t -t my-custom-check.yaml -silent
```

**Важно:** CVE-шаблоны в библиотеке названы по id CVE (`CVE-2025-XXXX.yaml`), а не по продукту. Поэтому грепать библиотеку по имени продукта бессмысленно — используйте `-tags`, `-id` или `-tl`.

## DAST/fuzzing-режим

DAST-шаблоны не просто шлют фиксированный запрос, а **фаззят параметры** (подставляют payload в найденные точки).

| Флаг | Что делает |
|------|-----------|
| `-dast` | Включить/запустить DAST (fuzz) шаблоны |
| `-ft, -fuzzing-type` | Тип: `replace, prefix, postfix, infix` |
| `-fm, -fuzzing-mode` | `multiple, single` |
| `-dfp, -display-fuzz-points` | Показать точки фаззинга (отладка) |
| `-fa, -fuzz-aggression` | Агрессивность: `low, medium, high` |
| `-cs, -fuzz-scope` | Regex URL в scope фаззера |
| `-cos, -fuzz-out-scope` | Regex URL вне scope |
| `-dts, -dast-server` | Режим live-фаззинга (сервер) |
| `-dtr, -dast-report` | Отчёт DAST |

```bash
nuclei -u 'https://t/api?q=test' -dast -fa low -silent
nuclei -u https://t -dast -dfp -fa low      # сначала посмотреть точки фаззинга
```

## Interactsh и OOB-проверки

Шаблоны для слепых уязвимостей (SSRF, blind RCE, Log4Shell, XXE) используют **Interactsh** — внешний OOB-сервер, который ловит обратные соединения.

| Флаг | Что делает |
|------|-----------|
| `-iserver, -interactsh-server` | Свой Interactsh-сервер |
| `-itoken, -interactsh-token` | Токен для self-hosted |
| `-ni, -no-interactsh` | Отключить OOB (и исключить OOB-шаблоны) |
| `-interactions-poll-duration` | Интервал опроса |
| `-interactions-cooldown-period` | Доп. время ожидания перед выходом |

```bash
# свой сервер (когда нет egress или нужен контроль)
nuclei -u https://t -iserver oast.mycorp.local -itoken SECRET -tags ssrf -silent
```

В шаблоне OOB-точка задаётся как `{{interactsh-url}}`; в матчере проверяется, что было взаимодействие.

## Рецепты

**1. Быстрый CVE-свип по списку живых:**

```bash
nuclei -l alive.txt -tags cve -severity medium,high,critical -rl 50 -silent -o cve.txt
```

**2. Полный скан с JSON для отчёта:**

```bash
nuclei -l alive.txt -severity low,medium,high,critical -j -o nuc.jsonl -me report/ -silent
```

**3. Скан с авторизацией:**

```bash
nuclei -l alive.txt -H 'Authorization: Bearer eyJ...' -tags cve,exposure -silent
```

**4. Конкретная CVE:**

```bash
nuclei -u https://t -id CVE-2024-12345 -silent
```

**5. Только новые шаблоны (после `-ut`):**

```bash
nuclei -update-templates && nuclei -l alive.txt -nt -silent
```

**6. Авто-подбор по технологиям:**

```bash
nuclei -u https://t -as -silent
```

**7. OOB-проверка SSRF/слепых инъекций:**

```bash
nuclei -u https://t -tags ssrf,blind -silent
```

**8. Экспорт в SARIF для CI:**

```bash
nuclei -l alive.txt -se results.sarif -silent
```

## Что выбрать и когда

- **Быстрый «урожай» известного:** `-tags cve -severity high,critical`.
- **Конкретный продукт:** `-tags wordpress,jenkins,...` (не грепать библиотеку по имени!).
- **Конкретная CVE:** `-id CVE-...`.
- **Неизвестный стек:** `-as` (auto-scan по технологиям).
- **Слепые уязвимости:** шаблоны с Interactsh (по умолчанию включён).
- **Параметры/инъекции:** `-dast` (осторожно с агрессивностью).
- **Слабый/защищённый сервер:** `-rl 20 -c 10 -bs 10`.
- **CI-отчёт:** `-j` + jq или `-se` (SARIF).
- **Своя проверка:** написать YAML-шаблон + `-validate`.

## Частые ошибки

- **Слишком высокий rate-limit.** По умолчанию 150 rps — риск DoS и бана; снижайте `-rl`.
- **Грепать шаблоны по имени продукта.** Файлы названы по CVE-id; используйте `-tags`/`-id`.
- **Не обновлять шаблоны.** Без `-ut` вы не увидите свежие CVE.
- **Слепо доверять находкам.** nuclei даёт кандидатов; подтверждайте вручную (curl/Burp).
- **Забыть `-silent` в пайплайне.** Баннер и прогресс ломают stdout следующей утилиты.
- **`-dast` с высокой агрессией на проде.** Это реальный фаззинг — начните с `-fa low` и `-dfp`.
- **Игнорировать OOB.** Слепые баги не находятся без Interactsh; проверьте egress или поднимите свой `-iserver`.
- **Путать `-es` и `-s`.** `-s` — включаемые severity, `-es` — исключаемые.

## Квиз

```quiz
- question: "Как обновить именно шаблоны nuclei, а не сам инструмент?"
  options:
    - "nuclei -version"
    - "nuclei -update-templates"
    - "nuclei -tl"
    - "go install ..."
  answer: 1
  explanation: "-update-templates (или -ut) тянет свежую базу шаблонов."
- question: "Как запустить только high и critical CVE-шаблоны?"
  options:
    - "-severity high,critical -tags cve"
    - "-es high,critical"
    - "-id high,critical"
    - "-pt high,critical"
  answer: 0
  explanation: "-severity выбирает уровни, -tags cve ограничивает классом CVE."
- question: "Что делает -as (automatic-scan)?"
  options:
    - "Отключает шаблоны"
    - "Автоматически подбирает теги по технологиям цели"
    - "Ставит прокси"
    - "Пишет SARIF"
  answer: 1
  explanation: "wappalyzer-детект технологий → авто-выбор релевантных тегов."
- question: "Зачем шаблонам nuclei Interactsh?"
  options:
    - "Для ускорения скана"
    - "Для обнаружения слепых уязвимостей через OOB-взаимодействия"
    - "Для записи cookie"
    - "Для обхода TLS"
  answer: 1
  explanation: "Interactsh ловит обратные соединения — SSRF, blind RCE, Log4Shell, XXE."
- question: "Какой флаг включает DAST/fuzz-режим?"
  options:
    - "-dast"
    - "-silent"
    - "-jsonl"
    - "-tgl"
  answer: 0
  explanation: "-dast включает шаблоны, которые фаззят параметры."
```

## Где пригодится

- **CTF (Web):** быстрый прогон известных багов и CVE по цели; свой шаблон под нестандартную проверку.
- **Bug bounty:** nuclei-first скан по программам; теги, auto-scan и OOB-проверки в пайплайне.
- **Пентест:** покрытие известных классов, воспроизводимый JSON/SARIF для отчёта.
- **Работа (AppSec/DevSecOps):** регулярные сканы в CI, SARIF в дешборды, свои шаблоны под внутренние проверки.
