---
id: web-tool-wfuzz-burp-intruder
title: "wfuzz и Burp Intruder: полный практический справочник"
category: web
parent: web-tools-fuzz
difficulty: medium
order: 3
tags: [wfuzz, burp, intruder, fuzzing, payloads, brute, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "wfuzz (payloads, encoders, iterators, фильтры) и Burp Intruder (sniper/battering ram/pitchfork/cluster bomb) с рецептами."
---

`wfuzz` и **Burp Intruder** закрывают класс задач, где нужны **сложные комбинации payload**, кодирование и точный контроль над фильтрацией. `wfuzz` — консольный инструмент с мощным движком payload/encoders/iterators и выразительными фильтрами. Burp Intruder — GUI-инструмент того же назначения: вы размечаете позиции в запросе и гоняете один из четырёх типов атак.

Этот урок — **рабочий справочник**: полные таблицы флагов wfuzz, разбор payload-синтаксиса и всех четырёх типов атак Intruder, плюс рецепты.

## Шпаргалка: флаги, которые нужны в 90% задач

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-w LIST -u URL/FUZZ` | простой перебор | `wfuzz -w common.txt -u https://t/FUZZ --hc 404` |
| `--hc` | скрыть по HTTP-коду | `--hc 404` |
| `--hh` | скрыть по размеру | `--hh 1234` |
| `--ss` | показать строки по regex | `--ss admin` |
| `-z file,LIST` | payload из файла | `-z file,users.txt` |
| `-z list,a-b-c` | payload из списка | `-z list,admin-guest` |
| `-z range,1-100` | числовой диапазон | `-z range,1-100` |
| `-z file,LIST,ENCODER` | payload + encoder | `-z file,p.txt,base64` |
| `-t` | число потоков | `-t 30` |
| `-d` | тело POST | `-d 'user=FUZZ&pass=x'` |
| `-o json -f out.json` | JSON-вывод | `-o json -f out.json` |
| `--filter` | выражение фильтрации | `--filter 'c=200,l<8'` |

## Когда wfuzz/Intruder, а когда другой инструмент

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Простой быстрый перебор путей | ffuf | Скорость, JSON |
| Сложные payload + encoders + iterators | **wfuzz** | Гибкий движок payloads |
| Комбинации из нескольких словарей | wfuzz `zip/product` / Intruder pitchfork/cluster bomb | Многословарные режимы |
| Разные payload для разных позиций | **Intruder pitchfork** | Один payload-set на позицию |
| Ручная разметка позиций в GUI | **Burp Intruder** | Визуально, с payload processing |
| Один параметр, много значений | ffuf/wfuzz | Любой подойдёт |

Правило: **ffuf — по умолчанию; wfuzz — когда нужны хитрые payload/encoders; Intruder — когда удобнее GUI и payload processing**.

## wfuzz: синтаксис и плейсхолдер FUZZ

```bash
wfuzz [опции] -z payload,params -u URL_С_FUZZ
```

- `FUZZ` — место подстановки; можно несколько: `FUZ2Z`, `FUZ3Z`, …
- `FUZZ{baseline}` — первый запрос с `baseline` как опорный для фильтрации.
- `-w wordlist` — быстрый алиас для `-z file,wordlist`.
- `-z` задаёт payload-источник: тип, параметры, encoder.

Минимальный запуск:

```bash
wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.com/FUZZ --hc 404
```

## wfuzz: словари, payloads, encoders, iterators

**Payload-источники (`-z`):**

| Тип | Что даёт | Пример |
|-----|---------|--------|
| `file` | строки из файла | `-z file,/path/words.txt` |
| `list` | список через `-` | `-z list,admin-guest-user` |
| `range` | диапазон чисел | `-z range,1-1000` |
| `hexrange` | hex-диапазон | `-z hexrange,00-ff` |
| `names` | словарь имён | `-z names` |
| `dirwalk` | обход каталога | `-z dirwalk,/tmp/list` |
| `burplist` | из Burp-выгрузки | `-z burplist,burp.xml` |

**Несколько словарей.** Каждый `-z` получает своё ключевое слово:

```bash
wfuzz -z file,users.txt:FUZZ -z file,pass.txt:FUZ2Z \
      -d 'user=FUZZ&pass=FUZ2Z' -u https://t/login --hc 200
```

**Encoders** (третий параметр `-z`): `urlencode`, `double urlencode`, `base64`, `md5`, `sha1`, `hexlify`, `html_escape`, `uri_hex`, `uri_double_hex`, `none`.

```bash
wfuzz -z file,payloads.txt,urlencode -u 'https://t/?q=FUZZ' --hc 404
wfuzz -z file,ids.txt,base64      -u 'https://t/?id=FUZZ' --hc 400
```

**Iterators** (как комбинировать несколько payloads):

| Iterator | Что делает |
|----------|-----------|
| `product` | Декартово произведение (по умолчанию) |
| `zip` | Параллельно, по одной строке из каждого |
| `chain` | Последовательно один за другим |
| `cartesian` | Явное декартово произведение |

```bash
wfuzz -z file,users.txt:FUZZ -z file,pass.txt:FUZ2Z,zip -d 'u=FUZZ&p=FUZ2Z' -u https://t/login
```

Посмотреть доступное: `wfuzz -e payloads`, `wfuzz -e encoders`, `wfuzz -e iterators`, `wfuzz -e printers`.

## wfuzz: фильтры

Фильтры wfuzz — самая выразительная часть: можно скрывать/показывать по коду, строкам, словам, размеру и regexp.

| Флаг | Что делает |
|------|-----------|
| `--hc N(,N)` | Скрыть по HTTP-коду |
| `--hl N(,N)` | Скрыть по числу строк |
| `--hw N(,N)` | Скрыть по числу слов |
| `--hh N(,N)` | Скрыть по числу символов (размер) |
| `--sc N(,N)` | Показать только эти коды |
| `--sl N(,N)` | Показать только эти строки |
| `--sw N(,N)` | Показать только эти слова |
| `--sh N(,N)` | Показать только этот размер |
| `--ss REGEX` | Показать строки, содержащие regex |
| `--hs REGEX` | Скрыть строки, содержащие regex |
| `--filter EXPR` | Выражение фильтрации (`c=200,l<8,w>100`) |
| `--prefilter EXPR` | Фильтр по элементам до фаззинга |

```bash
# скрыть 404 и показать только ответы, где есть слово admin
wfuzz -w words.txt -u https://t/FUZZ --hc 404 --ss admin

# выразительный фильтр: код 200, меньше 8 строк, больше 100 слов
wfuzz -w words.txt -u https://t/FUZZ --filter 'c=200,l<8,w>100'
```

## wfuzz: флаги

| Флаг | Что делает |
|------|-----------|
| `-u URL` | Цель с `FUZZ` |
| `-z payload` | Payload-источник (тип,параметры,encoder) |
| `-w file` | Алиас `-z file,file` |
| `-X method` | HTTP-метод |
| `-d postdata` | Тело запроса |
| `-H header` | Заголовок |
| `-b cookie` | Cookie |
| `-p addr` | HTTP-прокси |
| `--socks5 ip:port` | SOCKS5-прокси |
| `-A/--basic user:pass` | Basic auth |
| `--digest/--ntlm/--negotiate user:pass` | Другие схемы аутентификации |
| `-t N` | Число потоков (по умолчанию 10) |
| `-s N` | Задержка между запросами |
| `-L, --follow` | Следовать редиректам |
| `-R depth` | Рекурсивный обход на глубину |
| `--req-delay N` | Таймаут запроса |
| `--conn-delay N` | Таймаут соединения |
| `-V alltype` | Брутить все параметры без `FUZZ` |
| `-c` | Цветной вывод |
| `-v` | Подробно |
| `-f filename,printer` | Сохранить результаты в файл |
| `-o printer` | Формат вывода (`raw, json, html, magictree`) |
| `--recipe file` | Читать опции из рецепта |
| `--dump-recipe file` | Сохранить опции как рецепт |
| `--dry-run` | Показать запросы без отправки |
| `--oF file` | Сохранить сессию фаззинга |
| `--efield/--field expr` | Показать поле ответа |
| `--slice filter` | Python-slice по результатам |
| `-e type` | Список encoders/payloads/iterators/printers |

```bash
wfuzz -w raft-medium-directories.txt -u https://t/FUZZ -t 20 -L --hc 404 -o json -f out.json
```

## Дополнительные флаги wfuzz (полный охват)

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-Z` / `--scan-mode` | режим для нескольких FUZZ (`zip`/`chain`) | `wfuzz -Z zip -z file,u.txt -z file,p.txt -u https://t/login` |
| `--no-cache` | отключить кэш запросов | `wfuzz -w w.txt -u https://t/FUZZ --no-cache` |
| `--script NAME` | выполнить плагин-скрипт | `wfuzz -w w.txt -u https://t/FUZZ --script=links` |
| `--script-help NAME` | справка по скрипту | `wfuzz --script-help=links` |
| `--script-args ARGS` | аргументы скрипта | `wfuzz -w w.txt -u https://t/FUZZ --script=links --script-args=alpha` |
| `--interact` | интерактивный режим | `wfuzz --interact -u https://t/FUZZ` |
| `--seed N` | seed генератора случайных значений | `wfuzz -w w.txt -u https://t/FUZZ --seed 42` |
| `--zP PARAMS` | параметры payload по умолчанию | `wfuzz -z file,words.txt --zP 'default=' -u https://t/FUZZ` |
| `--zD DEFAULT` | значение payload по умолчанию | `wfuzz -z list,a-b --zD a -u https://t/FUZZ` |
| `--zE ENCODER` | encoder для всех payload | `wfuzz -z file,w.txt --zE urlencode -u https://t/FUZZ` |
| `--json` | JSON-вывод | `wfuzz -w w.txt -u https://t/FUZZ --json` |
| `--grep REGEX` | показывать только строки по regex (алиас `--ss`) | `wfuzz -w w.txt -u https://t/FUZZ --grep admin` |
| `--save FILE` | сохранить профиль опций | `wfuzz -w w.txt -u https://t/FUZZ --save prof.json` |
| `-h` / `--version` | справка / версия | `wfuzz --version` |

> Опущены длинные алиасы (`--url`, `--method`, `--postdata`, `--headers`, `--cookie`, `--concurrent`, `--delay`, `--recursion`, `--proxy`, `--follow`, `--auth`) — они дублируют короткие флаги, уже описанные выше. Для Burp Intruder таблицы «типов атак» и «типов payload-set» ниже покрывают все значимые параметры (это GUI, флагов командной строки у него нет).

## Burp Intruder: типы атак

Intruder работает так: вы **размечаете позиции** (`§payload§`) в запросе, выбираете **тип атаки** и **наборы payload**.

| Тип атаки | Как работает | Когда применять |
|-----------|--------------|-----------------|
| **Sniper** | Один payload-set; подставляет значение по одной позиции за раз | Перебор одного параметра; тест каждого поля отдельно |
| **Battering ram** | Один payload-set; одно значение во **все** позиции одновременно | Когда одно и то же значение нужно во всех местах |
| **Pitchfork** | Несколько payload-sets; идут **параллельно** (1-й с 1-м, 2-й со 2-м) | Пары логин:пароль, соответствия id:role |
| **Cluster bomb** | Несколько payload-sets; **все комбинации** | Перебор всех пар логин×пароль, все комбинации значений |

Примеры разметки:

- Sniper: `username=§admin§&password=§x§` — перебирает каждую позицию по очереди.
- Battering ram: `username=§admin§&password=§admin§` — `admin` в обе.
- Pitchfork: `username=§user§&password=§pass§` с двумя наборами — идут в паре.
- Cluster bomb: `username=§user§&password=§pass§` — все пары.

## Burp Intruder: payloads, processing, options

**Типы payload-set (Payloads → Payload type):**

| Тип | Что делает |
|-----|-----------|
| Simple list | Список строк (ручной, из файла, paste) |
| Runtime file | Читает файл «на лету» (большие списки) |
| Custom iterator | Комбинирует несколько наборов с разделителями |
| Character blocks | Генерирует блоки символов |
| Numbers | Числовой диапазон |
| Dates | Даты |
| Brute forcer | Все комбинации символов заданной длины |
| Null payloads | Пустые payloads (повторить запрос N раз) |
| Username generator | Генерация вариантов username |
| Copy other payload | Копирует значение из другого набора |

**Payload processing** (обработка перед отправкой): Add prefix/suffix, Match/replace, Substring, Reverse, Encode (URL, base64, HTML, MD5/SHA), Hash, Skip if matches.

**Options:**

- **Grep - Match:** подсветить ответы, содержащие строки (например `error`, `admin`).
- **Grep - Extract:** вытащить данные из ответа (например CSRF-токен).
- **Grep - Payloads:** отметить, какой payload дал совпадение.
- **Request Engine:** потоки, задержки, повторы.
- **Redirections:** следовать редиректам (`Follow`/`Process cookies`).

## Рецепты

**1. wfuzz: dir-перебор с фильтром 404:**

```bash
wfuzz -w raft-medium-directories.txt -u https://t/FUZZ --hc 404 -t 30 -c
```

**2. wfuzz: параметры (скрытые имена):**

```bash
wfuzz -w burp-parameter-names.txt -u 'https://t/?FUZZ=1' --hh 0
```

**3. wfuzz: перебор ID с urlencode:**

```bash
wfuzz -z range,1-5000 -u 'https://t/api/order?id=FUZZ' --hc 404 -t 40
```

**4. wfuzz: логин, два словаря параллельно (zip):**

```bash
wfuzz -z file,users.txt:FUZZ -z file,pass.txt:FUZ2Z,zip \
      -d 'user=FUZZ&pass=FUZ2Z' -u https://t/login --hc 200
```

**5. wfuzz: payloads через base64:**

```bash
wfuzz -z file,payloads.txt,base64 -u 'https://t/?data=FUZZ' --hc 400
```

**6. wfuzz: только ответы со словом `admin`:**

```bash
wfuzz -w words.txt -u https://t/FUZZ --hc 404 --ss admin
```

**7. Intruder Sniper: тест одного параметра.** Размечаем `§value§` в `?id=§1§`, payload-set = числа 1–1000, Grep-Match = `"email"`. Запуск → смотрим, какие id возвращают чужие данные.

**8. Intruder Cluster bomb: логин×пароль.** Размечаем `user=§a§&pass=§b§`, два набора (users, passwords), тип Cluster bomb, Grep-Match = `Welcome`. Запуск → находим валидную пару.

**9. Intruder Pitchfork: id:token.** Размечаем `id=§1§&token=§x§`, два набора одинаковой длины, тип Pitchfork, чтобы пары шли синхронно.

## wfuzz vs Intruder vs ffuf

| Критерий | wfuzz | Burp Intruder | ffuf |
|----------|-------|---------------|------|
| Интерфейс | CLI | GUI | CLI |
| Encoders | **встроенные** | payload processing | `-enc` |
| Iterators (zip/product) | **да** | pitchfork/cluster bomb | pitchfork/clusterbomb |
| Фильтры | очень гибкие (`--filter`) | Grep-Match/Extract | `-mc/-fs/-fw/-fl` |
| JSON-вывод | да (`-o json`) | через расширения | **да** (`-of json`) |
| Скорость | средняя | средняя | **высокая** |
| Автоматизация | да | нет (GUI) | **да** |

## Что выбрать и когда

- **Быстрый перебор путей:** ffuf (или wfuzz `--hc 404`).
- **Сложные payload + encoders:** wfuzz (`-z ...,base64`).
- **Параллельные пары из двух словарей:** wfuzz `zip` / Intruder pitchfork.
- **Все комбинации:** wfuzz `product` / Intruder cluster bomb.
- **Один параметр по очереди:** Intruder sniper / ffuf.
- **Нужен GUI и grep-extract:** Burp Intruder.
- **Скрипт/пайплайн:** ffuf или wfuzz `-o json`.
- **Точное воспроизведение запроса:** сначала curl, потом инструмент.

## Частые ошибки

- **Забыть `--hc 404` в wfuzz.** Без фильтра вывод утонет в «не найдено».
- **Один поток в wfuzz на слабый сервер.** `-t 100` = бан; начинайте с 10–20 и `-s`.
- **Спутать `zip` и `product`.** `zip` — параллельно (пары), `product` — все комбинации.
- **Не задать второй `FUZ2Z`.** Если два словаря, второе ключевое слово должно отличаться.
- **Intruder без Grep-Match.** В море ответов не видно успеха; всегда добавляйте маркер.
- **Pitchfork с наборами разной длины.** Итерация идёт до конца меньшего — данные теряются.
- **Забыть про CSRF-токен в Intruder.** Токен нужно извлекать (Grep-Extract) и подставлять, иначе запросы отклонятся.
- **Не проверить `--dry-run`.** В wfuzz полезно увидеть, какие запросы уйдут, до массовой отправки.

## Квиз

```quiz
- question: "Какой тип атаки Burp Intruder использует все комбинации нескольких payload-sets?"
  options:
    - "Sniper"
    - "Battering ram"
    - "Pitchfork"
    - "Cluster bomb"
  answer: 3
  explanation: "Cluster bomb — декартово произведение наборов (все пары логин×пароль)."
- question: "Что делает iterator zip в wfuzz?"
  options:
    - "Все комбинации"
    - "Идёт параллельно, по одной строке из каждого словаря"
    - "Сжимает payload"
    - "Отключает фильтры"
  answer: 1
  explanation: "zip — параллельная итерация: удобно для пар логин:пароль."
- question: "Какой флаг wfuzz скрывает ответы с кодом 404?"
  options:
    - "--sc 404"
    - "--hc 404"
    - "--hh 404"
    - "--filter 404"
  answer: 1
  explanation: "--hc (hide code) скрывает по коду; --sc наоборот, показывает только их."
- question: "Какой тип атаки Intruder подставляет одно значение сразу во все размеченные позиции?"
  options:
    - "Sniper"
    - "Battering ram"
    - "Pitchfork"
    - "Cluster bomb"
  answer: 1
  explanation: "Battering ram использует один набор и одно значение во всех позициях."
- question: "Как в wfuzz закодировать каждый payload в base64?"
  options:
    - "-z file,payloads.txt,base64"
    - "--b64"
    - "-H 'encoding: base64'"
    - "--filter base64"
  answer: 0
  explanation: "Третий параметр -z — encoder; base64 кодирует каждый payload."
```

## Где пригодится

- **CTF (Web):** хитрые payload с кодированием, перебор ID и паролей, фильтрация шума.
- **Bug bounty:** разведка параметров и значений, перебор логинов, тесты IDOR с точными фильтрами.
- **Пентест:** массовые проверки с воспроизводимым выводом; GUI-атаки для ручного анализа.
- **Работа (AppSec):** понимание payload-комбинаций при code review и настройке WAF-правил.
