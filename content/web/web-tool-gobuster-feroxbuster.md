---
id: web-tool-gobuster-feroxbuster
title: "gobuster и feroxbuster: полный практический справочник"
category: web
parent: web-tools-fuzz
difficulty: medium
order: 2
tags: [gobuster, feroxbuster, fuzzing, discovery, dns, vhost, recursion, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 42
summary: "Все режимы и флаги gobuster (dir/dns/vhost/fuzz) и feroxbuster (рекурсия, авто-фильтры, extract-links) с рецептами."
---

`gobuster` и `feroxbuster` — два классических инструмента обнаружения контента, которые дополняют ffuf. **gobuster** силён своими специализированными режимами: `dir` (пути), `dns` (поддомены), `vhost` (виртуальные хосты), `fuzz` (произвольное место в запросе). **feroxbuster** — «умный» рекурсивный сканер: сам углубляется в найденные директории, автоматически фильтрует wildcard-ответы и умеет вытаскивать ссылки из ответов.

Этот урок — **рабочий справочник**: полные таблицы флагов обоих инструментов, разбор режимов и рецепты, копируемые как есть.

## Шпаргалка: флаги, которые нужны в 90% задач

| Команда/флаг | Что делает | Пример |
|------|-----------|--------|
| `gobuster dir -u URL -w LIST` | перебор путей | `gobuster dir -u https://t -w common.txt -x php,html` |
| `gobuster dir -x` | расширения | `-x php,html,bak` |
| `gobuster dir -s` / `-b` | показать / исключить коды | `-s 200,301,302,403` |
| `gobuster dir -t` | потоки | `-t 30` |
| `gobuster dir -k` | без проверки TLS | `-k` |
| `gobuster dir -q -o FILE` | тихо + вывод в файл | `-q -o dirs.txt` |
| `gobuster dns -d DOMAIN -w LIST` | перебор поддоменов | `gobuster dns -d t.com -w subs.txt --check-cname` |
| `gobuster vhost -u URL -w LIST` | виртуальные хосты | `gobuster vhost -u https://t -w v.txt --append-domain` |
| `feroxbuster -u URL -w LIST` | рекурсивный обход | `feroxbuster -u https://t -w raft.txt -x php` |
| `feroxbuster -d` / `--smart` | глубина / авто-режим | `-d 3 --smart` |
| `feroxbuster -C` / `-S` | фильтр кодов / размеров | `-C 404 -S 1234` |
| `feroxbuster --json -o FILE` | JSON-вывод | `--json -o ferox.json` |
| `feroxbuster --burp` | прокси Burp + insecure | `--burp` |

## Когда gobuster/feroxbuster, а когда другой инструмент

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Поддомены через DNS | **gobuster dns** | Резолвер, CNAME, wildcard-детект |
| Виртуальные хосты | **gobuster vhost** | Спец-режим с `--append-domain` |
| Рекурсивный обход дерева | **feroxbuster** | Из коробки рекурсия + авто-фильтр |
| Простой надёжный dir-scan | gobuster dir | Стабильно, понятный вывод |
| Тонкие фильтры + JSON | ffuf | Больше матчеров/фильтров |
| Один эндпоинт, много значений | wfuzz | Гибкие payloads |

Правило: **gobuster — когда нужен конкретный режим (dns/vhost) или простая надёжность; feroxbuster — когда важен рекурсивный обход и умная фильтрация**.

## gobuster: режимы и общий синтаксис

```bash
gobuster <режим> [опции]
```

Режимы: `dir`, `dns`, `vhost`, `fuzz`, `tftp`, `s3`, `gcs`. Общие (global) опции есть почти у всех: `-w`, `-t`, `-d` (задержка), `-o`, `-q`, `--no-progress`, `--no-error`, `--no-color`, `--debug`, `-p` (pattern).

```bash
gobuster dir  -u https://target.com -w common.txt -x php,html
gobuster dns  -d target.com -w subdomains.txt
gobuster vhost -u https://target.com -w vhosts.txt --append-domain
gobuster fuzz -u 'https://target.com/?p=FUZZ' -w values.txt
```

## gobuster dir: флаги

| Флаг | Что делает |
|------|-----------|
| `-u, --url` | Целевой URL |
| `-w, --wordlist` | Словарь (`-` = stdin) |
| `-x, --extensions` | Расширения: `-x php,html,txt` |
| `-X, --extensions-file` | Расширения из файла |
| `-s, --status-codes` | «Положительные» коды (например `200,301,302,401,403`) |
| `-b, --status-codes-blacklist` | Исключаемые коды (по умолчанию `404`) |
| `-t, --threads` | Потоки (по умолчанию 10) |
| `-r, --follow-redirect` | Следовать редиректам |
| `-k, --no-tls-validation` | Не проверять TLS-серт |
| `-c, --cookies` | Cookie |
| `-H, --headers` | Заголовок (можно много) |
| `-U`/`-P` | Basic auth логин/пароль |
| `-a, --useragent` | User-Agent |
| `--random-agent` | Случайный UA |
| `--proxy` | Прокси (http/socks5) |
| `--timeout, --to` | Таймаут (по умолчанию 10s) |
| `-d, --delay` | Пауза между запросами (например `1500ms`) |
| `-e, --expanded` | Печатать полные URL |
| `-n, --no-status` | Не печатать коды |
| `--hl, --hide-length` | Скрыть длину тела |
| `-f, --add-slash` | Добавлять `/` к каждому запросу |
| `--xl, --exclude-length` | Исключить длины (диапазоны: `203-206`) |
| `--db, --discover-backup` | Искать бэкапы найденных файлов |
| `-q, --quiet` | Без баннера и шума |
| `-o, --output` | Файл вывода |
| `--force` | Продолжать, даже если precheck не прошёл |

```bash
gobuster dir -u https://target.com -w raft-medium-directories.txt \
  -x php,html,js,bak -s 200,204,301,302,307,401,403 -t 30 -k -q -o dirs.txt
```

Важно: `-s` (status-codes) и `-b` (blacklist) конфликтуют — если задан `-b`, он переопределяет `-s`.

## gobuster dns / vhost / fuzz

**dns** — перебор поддоменов через резолвер:

| Флаг | Что делает |
|------|-----------|
| `-d, --domain` | Домен |
| `-w, --wordlist` | Словарь субдоменов |
| `-c, --check-cname` | Показывать CNAME |
| `-r, --resolver` | Свой DNS (`8.8.8.8`) |
| `--wildcard, --wc` | Продолжать при wildcard-DNS |
| `--no-fqdn, --nf` | Не добавлять точку |
| `--protocol` | udp/tcp для кастомного резолвера |
| `-i` (неявно) | — |

```bash
gobuster dns -d target.com -w subdomains.txt -t 50 -r 1.1.1.1 --check-cname -q
```

**vhost** — виртуальные хосты:

| Флаг | Что делает |
|------|-----------|
| `-u, --url` | URL (лучше по IP) |
| `-w, --wordlist` | Словарь имён хостов |
| `--append-domain` | Дописывать домен из URL к словам |
| `--domain` | Домен для подстановки при IP-URL |
| `--xl, --exclude-length` | Исключить длины (главный фильтр) |
| `--xs, --exclude-status` | Исключить коды |
| `--xh, --exclude-hostname-length` | Авто-корректировка длины по hostname |

```bash
gobuster vhost -u https://10.0.0.5 -w vhosts.txt --append-domain \
  --exclude-length 1234 -k -q
```

**fuzz** — подстановка `FUZZ` в URL, заголовки и тело:

| Флаг | Что делает |
|------|-----------|
| `-u, --url` | URL с `FUZZ` |
| `-w, --wordlist` | Словарь |
| `-H, --headers` | Заголовок с `FUZZ` |
| `-B, --body` | Тело запроса с `FUZZ` |
| `-m, --method` | Метод |
| `-b, --exclude-statuscodes` | Исключаемые коды |
| `--xl, --exclude-length` | Исключаемые длины |

```bash
gobuster fuzz -u 'https://target.com/api?key=FUZZ' -w keys.txt \
  -b 404 -q
```

## feroxbuster: синтаксис и ключевые отличия

```bash
feroxbuster -u https://target.com -w wordlist.txt [опции]
```

Отличия от gobuster/ffuf:

- **Рекурсия по умолчанию** (глубина 4) — сам заходит в найденные каталоги.
- **Авто-фильтр wildcard** — по умолчанию (`-D/--dont-filter` отключает).
- **Extract links** — вытаскивает ссылки из HTML/JS ответов (`--dont-extract-links` отключает).
- **Collect words / extensions / backups** — динамически расширяет словарь (`-g`, `-E`, `-B`).
- **Replay proxy** — отправляет найденное в Burp только по нужным кодам.

```bash
feroxbuster -u https://target.com -w raft-medium-directories.txt -x php,html,js -d 3 --smart
```

## feroxbuster: флаги

| Флаг | Что делает |
|------|-----------|
| `-u, --url` | Целевой URL |
| `-w, --wordlist` | Словарь (или URL) |
| `-x, --extensions` | Расширения (`-x php -x js,html`) |
| `-m, --methods` | Методы (по умолчанию GET) |
| `-H, --headers` | Заголовки |
| `-b, --cookies` | Cookie |
| `-Q, --query` | Query-параметры (`-Q token=abc`) |
| `-f, --add-slash` | Добавлять `/` |
| `--data` | Тело запроса (`@file` поддерживается) |
| `--data-json` | JSON-тело + POST + Content-Type |
| `--data-urlencoded` | Form-тело + POST |
| `-t, --threads` | Потоки (по умолчанию 50) |
| `-d, --depth` | Глубина рекурсии (по умолчанию 4; 0 = ∞) |
| `-n, --no-recursion` | Отключить рекурсию |
| `--force-recursion` | Рекурсия на все найденные эндпоинты |
| `-L, --scan-limit` | Лимит одновременных сканов |
| `--parallel` | Параллельные инстансы (по URL из stdin) |
| `--rate-limit` | Лимит rps на директорию |
| `--time-limit` | Общий лимит времени (`10m`) |
| `-T, --timeout` | Таймаут клиента (по умолчанию 7с) |
| `-r, --redirects` | Следовать редиректам |
| `-k, --insecure` | Не проверять TLS |
| `-p, --proxy` | Прокси |
| `-P, --replay-proxy` | Replay-прокси (только найденное) |
| `-R, --replay-codes` | Коды для replay |
| `-s, --status-codes` | Разрешённые коды |
| `-C, --filter-status` | Исключить коды |
| `-S, --filter-size` | Исключить размеры |
| `-W, --filter-words` | Исключить по словам |
| `-N, --filter-lines` | Исключить по строкам |
| `-X, --filter-regex` | Исключить по regexp |
| `--filter-similar-to` | Исключить страницы, похожие на данную |
| `--unique` | Только уникальные ответы |
| `--smart` | `--auto-tune` + `--collect-words` + `--collect-backups` |
| `--thorough` | `--smart` + `--collect-extensions` + `--scan-dir-listings` |
| `--auto-tune` | Снижать скорость при ошибках |
| `--auto-bail` | Останавливаться при ошибках |
| `-E, --collect-extensions` | Авто-обнаружение расширений |
| `-B, --collect-backups` | Запрашивать бэкапы (`~`, `.bak`, `.old`) |
| `-g, --collect-words` | Пополнять словарь словами из ответов |
| `-I, --dont-collect` | Игнорировать расширения при сборе |
| `-v, --verbosity` | Больше деталей (`-vv`) |
| `--silent` | Только URL |
| `-q, --quiet` | Скрыть баннер/прогресс |
| `--json` | JSON-лог в `-o` |
| `-o, --output` | Файл вывода |
| `--no-state` | Не писать `.state` |
| `--resume-from` | Продолжить с state-файла |
| `--request-file` | Сырой запрос как шаблон |
| `--stdin` | Читать URL из stdin |
| `--burp` | `--proxy 127.0.0.1:8080` + `--insecure` |

## Дополнительные флаги gobuster (полный охват)

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-m` / `--method` | HTTP-метод | `gobuster dir -u https://t -w w.txt -m POST` |
| `--retry` / `--retry-attempts N` | повтор при таймауте (по умолчанию 3) | `gobuster dir -u https://t -w w.txt --retry --retry-attempts 3` |
| `--no-error` | не показывать ошибки | `gobuster dir -u https://t -w w.txt --no-error` |
| `--no-color` | без ANSI-цвета | `gobuster dir -u https://t -w w.txt --no-color` |
| `-z` / `--no-progress` | без прогресс-бара | `gobuster dir -u https://t -w w.txt -z` |
| `-v` / `--verbose` | подробный вывод (ошибки) | `gobuster dir -u https://t -w w.txt -v` |
| `-p` / `--pattern` | файл с шаблонами подстановки | `gobuster dir -u https://t -w w.txt -p patterns.txt` |
| `--wordlist-offline` | fallback на локальный словарь | `gobuster dir -u https://t -w w.txt --wordlist-offline` |
| `--client-cert-pem` / `--client-cert-pem-key` | клиентский серт/ключ (mTLS) | `gobuster dir -u https://t -w w.txt --client-cert-pem c.pem --client-cert-pem-key k.pem` |
| `--client-cert-p12` / `--client-cert-p12-password` | клиентский P12 (mTLS) | `gobuster dir -u https://t -w w.txt --client-cert-p12 c.p12 --client-cert-p12-password x` |
| `--timeout` / `--to` | HTTP-таймаут | `gobuster dir -u https://t -w w.txt --timeout 20s` |
| `--version` / `-h` | версия / справка | `gobuster version` |

## Дополнительные флаги feroxbuster (полный охват)

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-a` / `--user-agent UA` | свой User-Agent | `feroxbuster -u https://t -w w.txt -a 'Mozilla/5.0'` |
| `-A` / `--random-agent` | случайный User-Agent | `feroxbuster -u https://t -w w.txt -A` |
| `--protocol P` | протокол для domain-only / `--request-file` | `feroxbuster -u t.local --protocol https -w w.txt` |
| `--dont-scan URL` | исключить URL/regex из рекурсии | `feroxbuster -u https://t -w w.txt --dont-scan '/logout'` |
| `--scope URL` | дополнительные in-scope домены | `feroxbuster -u https://t -w w.txt --scope https://api.t` |
| `--server-certs PEM` | дополнительные корневые серты | `feroxbuster -u https://t -w w.txt --server-certs ca.pem` |
| `--client-cert` / `--client-key` | mTLS-серт/ключ | `feroxbuster -u https://t -w w.txt --client-cert c.pem --client-key k.pem` |
| `--response-size-limit BYTES` | лимит размера читаемого тела | `feroxbuster -u https://t -w w.txt --response-size-limit 2MB` |
| `-D` / `--dont-filter` | не авто-фильтровать wildcard | `feroxbuster -u https://t -w w.txt -D` |
| `--dont-extract-links` | не извлекать ссылки из ответов | `feroxbuster -u https://t -w w.txt --dont-extract-links` |
| `--scan-dir-listings` | рекурсить в directory listing | `feroxbuster -u https://t -w w.txt --scan-dir-listings` |
| `--burp-replay` | replay-прокси на Burp + insecure | `feroxbuster -u https://t -w w.txt --burp-replay` |
| `--limit-bars N` | сколько прогресс-баров показывать | `feroxbuster -u https://t -w w.txt --limit-bars 2` |
| `--debug-log FILE` | лог отладки в файл | `feroxbuster -u https://t -w w.txt --debug-log dbg.log` |
| `-U` / `--update` | обновить feroxbuster | `feroxbuster -U` |
| `-h` / `-V` | справка / версия | `feroxbuster --version` |

> Опущены: редкие в веб-тестах режимы gobuster `tftp`/`s3`/`gcs` и служебные `--debug`/`--help` (выводятся `gobuster <режим> -h`).

## Рекурсия, фильтры и автоматический tuning

**Рекурсия.** feroxbuster сам углубляется в найденные каталоги; ограничивайте глубиной и лимитом сканов, чтобы не улететь:

```bash
feroxbuster -u https://t -w words.txt -d 3 --scan-limit 2 --rate-limit 100
```

**Фильтры.** Комбинируйте по коду, размеру, словам, строкам:

```bash
feroxbuster -u https://t -w words.txt -C 404 -S 1234 -W 42 --unique
```

**Авто-фильтр wildcard.** По умолчанию включён; если сервер отдаёт «мусор» на всё — feroxbuster сам его отсеет. Отключается `-D`.

**Auto-tune / auto-bail.** При всплеске ошибок (бан, таймауты) инструмент снижает скорость или останавливается:

```bash
feroxbuster -u https://t -w words.txt --auto-tune --auto-bail
```

## Extract links, collect words, collect backups

- **Extract links:** по умолчанию feroxbuster парсит ответы и находит новые ссылки → глубже покрытие SPA. Отключить: `--dont-extract-links`.
- **Collect words (`-g`):** добавляет «важные» слова из ответов в словарь.
- **Collect extensions (`-E`):** находит используемые расширения и добавляет их в `-x`.
- **Collect backups (`-B`):** запрашивает `file~`, `file.bak`, `file.old` для найденных файлов.

```bash
feroxbuster -u https://t -w words.txt --thorough -x php,html
```

`--thorough` = smart + collect-extensions + scan-dir-listings — самый «жадный» режим.

## Рецепты

**1. Классический dir-scan (gobuster):**

```bash
gobuster dir -u https://t -w raft-medium-directories.txt -x php,html,js \
  -s 200,204,301,302,307,401,403 -t 30 -q -o gobuster.txt
```

**2. Рекурсивный обход (feroxbuster):**

```bash
feroxbuster -u https://t -w raft-medium-directories.txt -x php,html -d 3 \
  --smart --json -o ferox.json
```

**3. Поддомены (gobuster dns):**

```bash
gobuster dns -d target.com -w subdomains-top1million-5000.txt -t 50 -r 1.1.1.1 --check-cname -q
```

**4. Виртуальные хосты (gobuster vhost):**

```bash
# узнайте размер дефолтной страницы
curl -s -o /dev/null -w '%{size_download}\n' -H 'Host: nosuch.target.com' https://target.com/
gobuster vhost -u https://target.com -w vhosts.txt --append-domain --exclude-length <РАЗМЕР> -q
```

**5. Произвольный фаззинг (gobuster fuzz):**

```bash
gobuster fuzz -u 'https://t/?id=FUZZ' -w <(seq 1 2000) --exclude-length 1234 -q
```

**6. С авто-расширением словаря (feroxbuster --thorough):**

```bash
feroxbuster -u https://t -w small.txt --thorough -C 404
```

**7. Через Burp для ручного анализа (feroxbuster):**

```bash
feroxbuster -u https://t -w words.txt --burp --smart
```

## gobuster vs feroxbuster vs ffuf

| Критерий | gobuster | feroxbuster | ffuf |
|----------|----------|-------------|------|
| Рекурсия | нет (только dir) | **да, по умолчанию** | опционально |
| DNS-режим | **да** | нет | нет (Host-фаззинг) |
| vhost-режим | **да** | нет | да (`-H Host: FUZZ`) |
| Авто-фильтр wildcard | нет | **да** | `-ac` |
| Extract links | нет | **да** | нет |
| Тонкие матчеры/фильтры | базовые | расширенные | **самые гибкие** |
| JSON-вывод | нет | `--json` | **`-of json`** |
| Скорость | средняя | высокая | **высокая** |

## Что выбрать и когда

- **DNS-поддомены:** gobuster dns.
- **Vhost:** gobuster vhost (или ffuf).
- **Рекурсивный обход:** feroxbuster.
- **Простой надёжный dir-scan:** gobuster dir.
- **Тонкая фильтрация + JSON + vhost + params:** ffuf.
- **SPA/JS-приложение:** feroxbuster с extract-links + katana.
- **Пайплайн/скрипт:** ffuf (`-json`) или feroxbuster (`--json --silent`).

## Частые ошибки

- **Путать `-s` и `-b` в gobuster.** `-s` — «показывать эти коды», `-b` — «исключать эти»; `-b` переопределяет `-s`.
- **Забыть `--append-domain` в vhost.** Без него в словаре нужны полные FQDN, иначе запросы уйдут не туда.
- **Не задать `--exclude-length` для vhost.** Сервер отдаёт одну заглушку на все Host — получите тысячи ложных.
- **Оставить рекурсию без лимитов.** feroxbuster уйдёт вглубь и растянет скан; ставьте `-d`, `--scan-limit`, `--time-limit`.
- **`--thorough` на большом словаре.** Очень шумно и долго; для больших списков используйте `--smart`.
- **Игнорировать wildcard-DNS.** В gobuster dns добавьте `--wildcard`, иначе результат будет мусорным.
- **Забыть `-k` на самоподписанных сертах.** Все запросы упадут по TLS.

## Квиз

```quiz
- question: "Какой режим gobuster перебирает поддомены через DNS?"
  options:
    - "dir"
    - "vhost"
    - "dns"
    - "fuzz"
  answer: 2
  explanation: "gobuster dns — резолвинг поддоменов с поддержкой CNAME и кастомного резолвера."
- question: "Что делает флаг feroxbuster --smart?"
  options:
    - "Включает auto-tune, collect-words и collect-backups"
    - "Отключает рекурсию"
    - "Ставит прокси Burp"
    - "Выводит только JSON"
  answer: 0
  explanation: "--smart = --auto-tune + --collect-words + --collect-backups."
- question: "Какая особенность feroxbuster отличает его от gobuster dir?"
  options:
    - "Он не умеет работать с HTTPS"
    - "Он рекурсивный по умолчанию и авто-фильтрует wildcard"
    - "Он перебирает только DNS"
    - "Он требует Burp"
  answer: 1
  explanation: "feroxbuster изначально рекурсивный и сам отсеивает soft-404."
- question: "Зачем в gobuster vhost флаг --append-domain?"
  options:
    - "Добавляет / к URL"
    - "Дописывает домен из URL к словам словаря"
    - "Включает TLS"
    - "Ставит cookie"
  answer: 1
  explanation: "Без него в словаре должны быть полные FQDN, а не короткие имена."
- question: "Что исключает флаг gobuster dir -b 404?"
  options:
    - "Показывает только 404"
    - "Исключает коды из blacklist (по умолчанию 404)"
    - "Добавляет расширение .404"
    - "Ставит Basic auth"
  answer: 1
  explanation: "-b (status-codes-blacklist) — «негативные» коды; по умолчанию 404."
```

## Где пригодится

- **CTF (Web):** быстрый перебор поддоменов/vhost и рекурсивный поиск скрытых путей.
- **Bug bounty:** расширение поверхности атаки; feroxbuster `--smart` экономит часы ручной работы.
- **Пентест:** стандартный content discovery и DNS-разведка с воспроизводимым выводом.
- **Работа (AppSec):** регулярные проверки новых каталогов и поддоменов после релизов.
