---
id: web-tools-fuzz
title: "Фаззинг и перебор: ffuf, gobuster, feroxbuster, wfuzz"
category: web
parent: web-tools-discovery
difficulty: medium
order: 2
tags: [fuzzing, ffuf, gobuster, feroxbuster, wfuzz, bruteforce, discovery, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Модуль-навигатор по инструментам фаззинга: что перебирать ffuf/gobuster/feroxbuster/wfuzz и когда какой брать."
---

Фаззинг — это систематический перебор вариантов (путей, параметров, значений, хостов) с целью найти то, что разработчик не intended показывать. Это не «угадывание», а **инженерный перебор с фильтрацией шума**: вы подаёте словарь, инструмент шлёт тысячи запросов и оставляет только отклонения от «нормального» ответа. В этом модуле — четыре инструмента, которые закрывают весь класс задач: **ffuf** (быстрый и универсальный), **gobuster** (надёжный, режимы dir/dns/vhost/fuzz), **feroxbuster** (рекурсивный, с умной авто-фильтрацией) и **wfuzz** (гибкие payload/encoders/filters + Burp Intruder как альтернатива из GUI).

Этот урок — навигатор: что делает каждый инструмент, как не утонуть в ложных срабатываниях и **какой взять под конкретную задачу**.

## Что покрывает этот этап

| Задача | Вопрос | Инструмент |
|--------|--------|-----------|
| Скрытые пути и файлы | «Есть ли `/admin`, `/backup.zip`, `/.git/`?» | ffuf, gobuster dir, feroxbuster |
| Поддомены | «Есть ли `dev.target.com`?» | gobuster dns, ffuf (Host) |
| Виртуальные хосты | «Отдаёт ли сервер другой сайт для чужого Host?» | ffuf, gobuster vhost |
| Параметры | «Есть ли скрытые `?debug=`, `?id=`?» | ffuf, wfuzz, Arjun |
| Значения параметров | «Что при `?id=1..N`, разных ролях?» | ffuf, wfuzz |
| Логины/пароли | «Есть ли слабый кред?» | ffuf, wfuzz, Intruder |
| API-эндпоинты | «Какие маршруты у API?» | ffuf, feroxbuster |

Ключевая идея: **сначала карта и фильтрация, потом интерпретация**. Инструмент лишь генерирует кандидатов; решение «это баг» принимаете вы.

## Карта модуля

Три практических справочника внутри модуля:

- **[web-tool-ffuf](web-tool-ffuf)** — универсальный фаззер: FUZZ-подстановка, матчеры/фильтры, режимы vhost/params/values/login, JSON-вывод и jq.
- **[web-tool-gobuster-feroxbuster](web-tool-gobuster-feroxbuster)** — gobuster (dir/dns/vhost/fuzz) и feroxbuster (рекурсия, авто-фильтры, extract-links).
- **[web-tool-wfuzz-burp-intruder](web-tool-wfuzz-burp-intruder)** — wfuzz (payloads/encoders/iterators/filters) и типы атак Burp Intruder.

Смежные уроки:

- **[web-recon-fuzzing](web-recon-fuzzing)** — методология: что искать и как не утонуть в шуме.
- **[web-tools-recon](web-tools-recon)** — предыдущий шаг: проба живых и краулинг (httpx/katana/nuclei).

## Оси фаззинга: что именно перебираем

Фаззинг — это всегда два решения: **где** подставлять (позиция) и **чем** (словарь). Позиций ровно столько, сколько «дырок» в запросе:

- **Путь/файл:** `https://t/FUZZ` → словарь имён директорий и файлов.
- **Расширение:** `https://t/index.FUZZ` → `php, bak, old, txt, json`.
- **Параметр:** `https://t/?FUZZ=1` → словарь имён параметров.
- **Значение:** `https://t/?id=FUZZ` → `1..1000`, `admin`, `true`, payload-строки.
- **Заголовок:** `-H 'Host: FUZZ'`, `-H 'X-Forwarded-For: FUZZ'`.
- **Тело:** `-d 'user=FUZZ&pass=x'` → логин/пароль.
- **Cookie:** `-b 'role=FUZZ'`.

Словари берутся из `seclists` (`Discovery/Web-Content/`, `Usernames/`, `Passwords/`). Правило: **один словарь на одну позицию, не смешивать**.

## Как выбирать инструмент

| Ситуация | Инструмент | Почему |
|----------|-----------|--------|
| Быстрый перебор путей, нужны тонкие фильтры | **ffuf** | Скорость, `-mc/-fs/-fw/-fl`, JSON, vhost-режим |
| Простой надёжный dir-scan без сюрпризов | **gobuster dir** | Стабильный, понятный вывод, `-x` расширения |
| Поддомены через DNS | **gobuster dns** | Резолвер, CNAME, wildcard-детект |
| Рекурсивный обход дерева директорий | **feroxbuster** | Авто-рекурсия, авто-фильтр wildcard, extract-links |
| Сложные payload-комбинации, encoders, iterators | **wfuzz** | Мощный движок payloads, замена `FUZZ` на `FUZZ{}` |
| Логин-форма, нужен GUI и обработка payload | **Burp Intruder** | Типы атак, payload processing, grep-match |
| Скрипт/пайплайн, нужен JSON | **ffuf** | `-of json` + jq |

Правило выбора по умолчанию: **ffuf для скорости и автоматизации, feroxbuster для рекурсии, gobuster для надёжного DNS/vhost, wfuzz/Intruder для хитрых payload-сценариев**.

## Мини-пайплайн

От живого хоста к скрытым путям:

```bash
# 1. базовый перебор путей с расширениями
ffuf -u https://target.com/FUZZ -w seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -e .php,.bak,.old -mc 200,301,302,401,403 -t 40 -o dirs.json -of json

# 2. рекурсивный обход найденного (feroxbuster сам углубится)
feroxbuster -u https://target.com -w raft-medium-directories.txt -x php,html,js -d 3 --smart

# 3. параметры найденного эндпоинта
ffuf -u 'https://target.com/api/user?FUZZ=1' -w seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0 -mc all
```

Затем — интерпретация: коды 200/301/403/500, размеры, редиректы; кандидатов проверяем вручную.

## Частые ошибки

- **Не фильтровать шум.** SPA отдаёт 200 на всё; без `-fs`/`-ac` ffuf завалит вас false positives.
- **Один поток на слабый сервер.** `-t 200` уронит хост и вас забанят. Начинайте с `-t 20–40`.
- **Забыть про wildcard.** Если `https://t/random123` тоже отдаёт 200 — включите авто-калибровку (`-ac`) или фильтр по размеру.
- **Повторять один и тот же словарь.** Ведите учёт, какой список уже применён к `host:port` — иначе дублируете работу.
- **Молча игнорировать `-mc all`.** Он нужен только вместе с фильтром, иначе выводит всё.
- **Забывать про таймауты.** Большой словарь по сети убивается таймаутом shell: `-maxtime` (ffuf), `--time-limit` (feroxbuster) или запуск в фоне.

## ffuf: полный справочник флагов

ffuf — основной фаззер. Ключевые флаги:

```bash
ffuf -u https://target.com/FUZZ \
     -w wordlist.txt \
     -e .php,.bak,.old \        # расширения (создаёт FUZZ.php и т.д.)
     -X GET \                   # метод
     -d 'user=FUZZ&pass=x' \    # тело (для POST)
     -H 'Host: FUZZ' \          # свой заголовок с подстановкой
     -b 'role=admin' \          # cookie
     -mc 200,301,302,401,403 \  # match-codes (что считать попаданием)
     -fc 404 \                  # filter-codes (исключить)
     -fs 0 \                    # filter-size (исключить размер)
     -fw 12 \                   # filter-words
     -fl 30 \                   # filter-lines
     -ac \                      # авто-калибровка против soft-404/wildcard
     -t 40 \                    # потоков
     -rate 100 \                # лимит запросов/сек
     -p 0.1 \                   # пауза между запросами
     -timeout 5 \
     -maxtime 300 \             # общий лимит времени (сек)
     -o out.json -of json \     # вывод
     -recursion -recursion-depth 2 \
     -ic                        # игнорировать комментарии в словаре
```

Несколько позиций сразу: ffuf подставляет каждое ключевое слово (`FUZZ`, `W1`, `W2`) из своего словаря `-w W1:list1 -w W2:list2`.

```bash
# пользователь+пароль в одном запросе
ffuf -u https://target.com/login -X POST -d 'user=W1&pass=W2' \
     -w users.txt:W1 -w pass.txt:W2 -mc 200 -fs 1234
```

Режим vhost (виртуальные хосты) — подстановка в `Host`, а не в путь:

```bash
ffuf -u https://target.com/ -H 'Host: FUZZ.target.com' \
     -w subdomains.txt -fs 4242 -mc all
```

Фильтрация результата через jq:

```bash
ffuf -u https://target.com/FUZZ -w raft.txt -of json -o o.json -s
jq -r '.results[] | "\(.status) \(.length) \(.url)"' o.json | sort -k2 -n
```

## gobuster и feroxbuster: режимы и флаги

gobuster — режимы задаются подкомандой:

```bash
gobuster dir  -u https://t -w raft.txt -x php,html,txt -t 40 -q --status-codes 200,204,301,302,307,401,403
gobuster dns  -d target.com -w subdomains.txt -r 8.8.8.8 --show-cname -q
gobuster vhost -u https://t -w subdomains.txt --append-domain -q
gobuster fuzz -u 'https://t?p=FUZZ' -w params.txt -q
```

feroxbuster — рекурсивный, умеет авто-фильтр wildcard и сбор ссылок из ответов:

```bash
feroxbuster -u https://t -w raft.txt \
  -x php,html,js \      # расширения
  -d 3 \                # глубина рекурсии
  -t 40 \               # потоков
  --smart \             # авто-калибровка
  --auto-tune \         # адаптивный лимит
  -C 404 \              # фильтр кодов
  -S 0 \                # фильтр размеров
  --extract-links \     # тянуть ссылки из HTML/JS
  --time-limit 5m \
  -o out.json
```

Ключевое отличие: gobuster не рекурсирует (нужно запускать руками), feroxbuster — рекурсирует сам, что экономит запросы на перебор вложенных директорий.

## wfuzz: payloads, encoders, iterators, filters

wfuzz мощнее по комбинациям payload. Позиция обозначается `FUZZ`, `FUZ2Z`, `FUZ3Z` или `FUZZ{}`:

```bash
wfuzz -c -z file,users.txt -z file,pass.txt \
      --hc 404 -d 'u=FUZZ&p=FUZ2Z' https://t/login
```

- **encoders:** `-z file,list,md5` — применяет функцию к payload (`md5`, `base64`, `urlencode`, `hexlify`, `sha1`).
- **iterators:** `-z list,a-b-c` или диапазон `-z range,1-1000`; `--zP` для параметров.
- **filters:** `--hc/--hl/--hw/--hs` (hide codes/lines/words/chars), `--sc/--sl/--sw/--ss` (show).
- **рекрусия:** `-R 2` — добавляет найденные пути в очередь.

```bash
# перебор значений id от 1 до 2000, показываем только не-404
wfuzz -c -z range,1-2000 --hc 404 https://t/user?id=FUZZ
# base64-кодируем payload (обход фильтров)
wfuzz -c -z file,payloads.txt,base64 --hc 400 https://t/?q=FUZZ
```

## Полный worked-пример: от живого хоста до скрытого API (с выводом)

```bash
# 1. Проверяем, что хост живой и не soft-404
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://target.com/random123
# 200 5321   -> soft-404: всё отдаёт 200 -> нужен фильтр/калибровка

# 2. Перебор директорий с авто-калибровкой
ffuf -u https://target.com/FUZZ -w seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -ac -mc all -t 40 -o dirs.json -of json -s
jq -r '.results[] | "\(.status) \(.length) \(.url)"' dirs.json | sort -k2 -n | head
# 301 0     https://target.com/admin
# 200 1024  https://target.com/api
# 403 512   https://target.com/backup

# 3. Расширения у найденных файлов
ffuf -u https://target.com/api/FUZZ -w seclists/Discovery/Web-Content/raft-medium-files.txt \
     -e .json,.bak,.old -mc 200 -fs 0 -s
# 200 2048  https://target.com/api/users.json
# 200 512   https://target.com/api/config.bak

# 4. Параметры у эндпоинта
ffuf -u 'https://target.com/api/users?FUZZ=1' \
     -w seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0 -mc all -s
# 200 4096  https://target.com/api/users?debug=1

# 5. Значения параметра
ffuf -u 'https://target.com/api/users?id=FUZZ' -w <(seq 1 500) -mc 200 -fs 0 -s
# 200 8192  https://target.com/api/users?id=42
```

Итог: нашли `/api/users.json` (утечка), `debug=1` (debug-режим) и объект `id=42`. Дальше — ручная проверка каждого кандидата (IDOR, утечки, скрытые функции).

## Что делать дальше / решение

1. **Оценить цель:** пути → ffuf/feroxbuster, DNS → gobuster dns, vhost → ffuf `-H Host`.
2. **Настроить фильтрацию:** сначала один запрос на случайный путь, посмотреть код/размер, затем `-ac` или `-fs/-fc`.
3. **Выбрать поток:** старт `-t 20–40`, следить за 429/таймаутами, при бане снизить `-rate`.
4. **Держать лимит времени:** `-maxtime`/`--time-limit` ниже таймаута shell, иначе JSON не сольётся.
5. **Учитывать словари:** не повторять один и тот же список на `host:port`; разные словари для путей, параметров, значений.
6. **Интерпретировать:** коды 200/301/403/500 + размеры → ручная проверка кандидатов; не считать автоматический «200» баг.

## Квиз

```quiz
- question: "Какой флаг ffuf оставляет только ответы с определёнными кодами?"
  options:
    - "-fc"
    - "-mc"
    - "-fs"
    - "-t"
  answer: 1
  explanation: "-mc (match codes) — «попадание»; -fc (filter codes) — наоборот, исключение."
- question: "Почему перебор на SPA часто даёт ложные срабатывания?"
  options:
    - "Потому что SPA не отвечает"
    - "Потому что SPA отдаёт 200 на любой путь (soft-404)"
    - "Потому что словарь пустой"
    - "Потому что нет cookie"
  answer: 1
  explanation: "Soft-404: любой путь отдаёт страницу-заглушку; лечится фильтром по размеру/авто-калибровкой."
- question: "Какое ключевое слово ffuf подставляет значение словаря в URL?"
  options:
    - "WORD"
    - "FUZZ"
    - "PAYLOAD"
    - "INJECT"
  answer: 1
  explanation: "FUZZ — маркер подстановки; ffuf может использовать несколько ключевых слов."
- question: "Какой инструмент лучше подходит для рекурсивного обхода дерева директорий?"
  options:
    - "gobuster dns"
    - "feroxbuster"
    - "wfuzz --hc"
    - "nuclei"
  answer: 1
  explanation: "feroxbuster изначально рекурсивный и умеет авто-фильтровать wildcard."
- question: "Зачем нужен режим vhost (например, ffuf с -H 'Host: FUZZ')?"
  options:
    - "Чтобы перебирать пароли"
    - "Чтобы найти сайты, отдаваемые сервером для чужого Host-заголовка"
    - "Чтобы включить HTTPS"
    - "Чтобы скачать файл"
  answer: 1
  explanation: "Виртуальные хосты: один IP отдаёт разные сайты в зависимости от Host."
```

## Где пригодится

- **CTF (Web):** быстрый поиск скрытых путей/параметров, флаг часто лежит в `/backup` или скрытом API.
- **Bug bounty:** массовое обнаружение контента и параметров — основа расширения поверхности атаки.
- **Пентест:** стандартный этап content discovery; доказательства (коды, размеры) идут в отчёт.
- **Работа (AppSec/DevSecOps):** регулярный перебор в CI, поиск забытых бэкапов и админок после релизов.
