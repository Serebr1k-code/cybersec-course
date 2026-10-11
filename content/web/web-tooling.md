---
id: web-tooling
title: "Инструменты веб-тестировщика: Burp, ffuf, nuclei, sqlmap"
category: web
parent: web-recon-surface
difficulty: easy
order: 1
tags: [burp, ffuf, nuclei, sqlmap, tooling, workflow, recon]
prerequisites: [web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Рабочий арсенал: как связать Burp, ffuf, nuclei и sqlmap в единый пайплайн тестирования веб-приложения."
---

Инструменты не заменяют мышление, но экономят часы. В этом уроке — минимальный, но полный набор веб-тестировщика и, главное, как связать их в **пайплайн**: разведка → фаззинг → сканирование → проверка инъекций → эксплуатация. Мы разберём Burp (перехват), ffuf (фаззинг), nuclei (шаблонные проверки), sqlmap (SQLi) и вспомогательные утилиты.

## Теория: роль каждого инструмента

| Инструмент | Роль | Когда применять |
|-----------|------|-----------------|
| **Burp Suite** | прокси, перехват/повтор/фаззинг, расширения | всегда, ядро ручного теста |
| **ffuf** | быстрый фаззинг путей/параметров/vhost | после составления карты |
| **nuclei** | шаблонные проверки (CVE, мисконфиги, takeover) | ранний скан по известным шаблонам |
| **sqlmap** | подтверждение и эксплуатация SQLi | когда есть подозрение на SQLi |
| **curl** | точное воспроизведение/доказательство | везде, для PoC |
| **gf/qsreplace** | генерация payload из параметров | генерация словарей для ffuf |
| **subfinder/httpx** | сбор поддоменов и живых хостов | внешняя разведка |

Правильный порядок (nuclei-first): **разведка (subfinder/httpx) → nuclei (известные баги) → ffuf (скрытые пути) → ручной анализ в Burp → sqlmap (SQLi) → эксплуатация**.

## Инструменты: команды

**ffuf — фаззинг директорий/файлов:**

```bash
ffuf -u https://target.local/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -mc 200,301,302,401,403 -t 40 -maxtime 120 -o ffuf.json -of json
```

**ffuf — параметры GET (с сохранением базовых параметров):**

```bash
ffuf -u 'https://target.local/api?FUZZ=1' -w params.txt -fs 0 -mc all
```

**ffuf — vhost (Host header):**

```bash
ffuf -u https://target.local/ -H 'Host: FUZZ.target.local' -w subs.txt -fs <размер-дефолта>
```

**nuclei — быстрый скан по шаблонам:**

```bash
nuclei -u https://target.local -severity low,medium,high,critical -silent -j -o nuclei.json
```

**sqlmap — проверка параметра (из сохранённого запроса):**

```bash
sqlmap -r request.txt -p id --batch --level 3 --risk 2 --dbms=mysql
```

**curl — воспроизведение:**

```bash
curl -s -i 'https://target.local/api?id=1%27' -H 'Cookie: session=...'
```

## Пайплайн: от разведки до эксплуатации

Шаг 1. Живые хосты (внешняя разведка):

```bash
subfinder -d target.com -silent | httpx -silent -o alive.txt
```

Шаг 2. nuclei по живым хостам (ранний «урожай» известных уязвимостей):

```bash
nuclei -l alive.txt -severity medium,high,critical -silent -o nuc.txt
```

Шаг 3. Контент-фаззинг (после nuclei, чтобы не дублировать):

```bash
ffuf -u https://target.local/FUZZ -w raft-medium-directories.txt -mc 200,204,301,302,307,401,403 \
     -t 40 -maxtime 180 -o dirs.json -of json
```

Шаг 4. Анализ находок в **Burp**: перехват, повтор, поиск параметров.

Шаг 5. Генерация payload для найденных параметров:

```bash
cat urls.txt | gf sqli | qsreplace "'" > sqli_targets.txt
sqlmap -m sqli_targets.txt --batch --level 2 --risk 1
```

Шаг 6. Ручное подтверждение каждого бага через curl и отчёт с PoC.

## Разобранный пример: связка Burp → ffuf → sqlmap

Шаг 1. В Burp находим эндпоинт `GET /product?id=5`. Копируем запрос в файл `request.txt` (правый клик → *Copy to file*).

Шаг 2. Пробуем параметр на аномалии через ffuf (быстрый чек разных значений):

```bash
ffuf -u 'https://target.local/product?id=FUZZ' -w nums.txt -mc all -fs 0
```

Шаг 3. Запускаем sqlmap по сохранённому запросу (сохраняет cookie/заголовки):

```bash
sqlmap -r request.txt -p id --batch --level 3 --risk 2
```

sqlmap сообщит `Parameter 'id' is vulnerable` и тип техники. Шаг 4. Эксплуатация — дамп таблицы:

```bash
sqlmap -r request.txt -p id --batch -D appdb -T users --dump
```

Шаг 5. Фиксируем результат (в CTF — флаг; в отчёте — строки из дампа) как доказательство.

## Разобранный пример: nuclei-first на новом хосте

Шаг 1. Прогоняем шаблоны:

```bash
nuclei -u https://target.local -severity low,medium,high,critical -j -o out.json
```

Шаг 2. Смотрим находки:

```bash
jq -r '.info.severity + " " + .templateID + " " + .matchedAt' out.json | sort
```

Шаг 3. Для каждой находки — **ручная верификация** через curl (nuclei может давать false positives). Шаг 4. Если есть CVE — ищем публичный PoC (exploit-db, GitHub), читаем его и адаптируем, а не переписываем с нуля.

## Частые ошибки

- **Гнаться за тулзами вместо методологии.** Инструмент лишь ускоряет ручную работу; без понимания — шум.
- **Забывать про таймауты.** Длинный фаззинг убивается таймаутом shell; используйте `-maxtime`, background или больший timeout.
- **Грепать вывод вместо парсера.** Результаты nuclei/ffuf/sqlmap лучше сохранять в JSON и разбирать структурированно.
- **Слепо доверять сканеру.** nuclei/ffuf дают кандидатов; подтверждайте вручную.
- **Игнорировать `-mc`/`-fs`.** Без фильтров ffuf утонет в false positives (например, SPA всегда отдаёт 200).
- **Повторять один и тот же wordlist.** Отслеживайте, какой список уже применён к host:port, чтобы не дублировать работу.

## Reference-таблица: флаги ключевых инструментов

**ffuf:**

| Флаг | Значение |
|------|----------|
| `-u` | URL с маркером `FUZZ` |
| `-w` | словарь (можно `list:FUZZ`) |
| `-X` | HTTP-метод |
| `-d` | тело запроса |
| `-H` | заголовок |
| `-b` | cookie |
| `-mc`/`-fc` | match/filter по коду |
| `-fs`/`-fw`/`-fl` | filter по размеру/словам/строкам |
| `-ac` | авто-калибровка (soft-404) |
| `-t`/`-rate` | потоки / лимит запросов |
| `-o`/`-of` | вывод и формат (json) |
| `-maxtime` | общий лимит времени |

**nuclei:**

| Флаг | Значение |
|------|----------|
| `-u`/`-l` | цель / список целей |
| `-t`/`-tags` | шаблоны/теги (не грепать по имени продукта) |
| `-severity` | фильтр по критичности |
| `-j`/`-o` | JSON-вывод / файл |
| `-silent` | только находки |
| `-H` | заголовок (auth) |
| `-rl` | rate limit |

**sqlmap:**

| Флаг | Значение |
|------|----------|
| `-r` | файл с запросом (cookie/заголовки) |
| `-p` | конкретный параметр |
| `--batch` | без вопросов |
| `--level`/`--risk` | глубина/агрессивность |
| `--dbms` | явно указать СУБД |
| `--technique` | `B/E/U/S/T/Q` (boolean/error/union/stacked/time) |
| `-D`/`-T`/`-C`/`--dump` | выбор БД/таблицы/колонки и дамп |
| `--os-shell` | попытка RCE (осторожно) |

## Полный пайплайн с выводом (nuclei → ffuf → sqlmap)

```bash
# 1. живые хосты
subfinder -d target.com -silent | httpx -silent -o alive.txt
wc -l alive.txt
# 42 alive.txt

# 2. nuclei по известным багам
nuclei -l alive.txt -severity medium,high,critical -j -o nuc.json -silent
jq -r '[.info.severity,.templateID,.host]|@tsv' nuc.json | sort | head
# high    CVE-2021-44228   https://app.target.com
# medium  exposed-panels  https://admin.target.com

# 3. ffuf по главному хосту
ffuf -u https://app.target.com/FUZZ -w raft-medium-directories.txt \
     -mc 200,301,302,401,403 -ac -t 40 -maxtime 180 -o dirs.json -of json -s
jq -r '.results[]|"\(.status) \(.length) \(.url)"' dirs.json | sort -k2 -n | head
# 200 1024  https://app.target.com/api
# 301 0     https://app.target.com/admin

# 4. sqlmap по подозрительному параметру (сохранённый запрос)
sqlmap -r req.txt -p id --batch --level 3 --risk 2
# [INFO] Parameter 'id' is vulnerable
# [INFO] the back-end DBMS is MySQL
```

Итог: подтверждённая SQLi + список скрытых путей. Дальше — дамп нужной таблицы и ручное подтверждение каждого бага.

## Автоматизация: обёртка и разбор JSON

Небольшой скрипт-обёртка ускоряет повторяющиеся прогоны:

```bash
#!/usr/bin/env bash
set -euo pipefail
HOST="$1"
nuclei -u "$HOST" -severity medium,high,critical -j -o /tmp/nuc.json -silent
ffuf -u "$HOST/FUZZ" -w raft-medium-directories.txt -mc 200,301,302,401,403 \
     -ac -t 40 -maxtime 120 -o /tmp/dir.json -of json -s
echo "=== nuclei ==="; jq -r '[.info.severity,.templateID]|@tsv' /tmp/nuc.json | sort
echo "=== dirs ===";   jq -r '.results[]|"\(.status) \(.url)"' /tmp/dir.json | sort -u
```

Ключевое: сохраняйте вывод в JSON и разбирайте его `jq`/парсером, а не глазами — это масштабируется и не засоряет контекст. Для nuclei всегда проверяйте находки вручную (curl), для ffuf — фильтруйте soft-404.

## Что делать дальше / решение

1. **Начинайте с разведки** (subfinder/httpx), затем **nuclei-first** по живым хостам.
2. **Контент-фаззинг** ffuf/feroxbuster с фильтрацией (`-ac`/`-fs`).
3. **Ручной анализ** в Burp: параметры, скрытые функции, авторизация.
4. **Инъекции** — sqlmap по сохранённому запросу (`-r`), только после подозрения.
5. **CVE** — искать публичный PoC, читать, адаптировать, репойнтить колбэки.
6. **Подтверждать** каждую находку вручную и сохранять доказательство (request/response).
7. **Вести учёт** применённых словарей, чтобы не дублировать работу на `host:port`.

## Частые ошибки автоматизации

Автоматизация ускоряет работу, но при неверной настройке даёт ложную уверенность:

- **Слишком высокий `-t`/`-rl`.** Хост упадёт или забанит IP; начинайте с `-t 20–40`.
- **Отсутствие `-ac`/фильтров.** SPA отдаёт 200 на всё — результат превратится в шум.
- **Скан без сохранения вывода.** `nuclei`/`ffuf` без `-o` теряют находки; всегда пишите JSON.
- **Греп по имени продукта вместо тегов.** CVE-шаблоны названы по CVE-id — грепайте по `-tags`/`-severity`.
- **Доверие сканеру без верификации.** nuclei/ffuf/sqlmap дают кандидатов, не приговор.
- **Один и тот же словарь повторно.** Ведите учёт `host:port:tool:wordlist`.
- **Забыть про таймаут.** `-maxtime`/`--time-limit` ниже таймаута shell, иначе JSON не сольётся.
- **Не читать публичный PoC перед запуском.** Скачанный эксплойт — недоверенный код: читайте, репойнтите колбэки, оценивайте разрушительность.

Здоровая привычка: каждый прогон — в файл, разбор — парсером, подтверждение — руками, запись результата — сразу в трекер.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какой инструмент — ядро ручного перехвата и модификации запросов?"
  options:
    - "sqlmap"
    - "Burp Suite"
    - "binwalk"
    - "hashcat"
  answer: 1
  explanation: "Burp — прокси/повтор/фаззинг и расширения."
- question: "Что делает `ffuf -mc 200,301,403`?"
  options:
    - "Показывает только ответы с этими кодами"
    - "Отправляет только эти методы"
    - "Игнорирует эти коды"
    - "Меняет cookie"
  answer: 0
  explanation: "`-mc` — match codes: какие коды считать «попаданием»."
- question: "В каком порядке по методологии идёт тестирование?"
  options:
    - "sqlmap → nuclei → разведка"
    - "разведка → nuclei → ffuf → ручной анализ → sqlmap"
    - "ffuf → разведка → sqlmap"
    - "nuclei → sqlmap → разведка"
  answer: 1
  explanation: "Сначала карта, затем известные баги, потом фаззинг и инъекции."
- question: "Зачем `sqlmap -r request.txt`?"
  options:
    - "Чтобы запустить без параметров"
    - "Чтобы использовать сохранённый запрос с cookie/заголовками"
    - "Чтобы отключить SQLi"
    - "Чтобы сканировать порты"
  answer: 1
  explanation: "`-r` берёт полный запрос из файла."
- question: "Что нужно сделать с находками сканера перед отчётом?"
  options:
    - "Отправить как есть"
    - "Вручную верифицировать через curl"
    - "Удалить"
    - "Запустить ещё раз"
  answer: 1
  explanation: "Сканеры дают false positives; подтверждение обязательно."
```

## Где пригодится

- **CTF (Web):** быстрый перебор путей/параметров и подтверждение инъекций экономят время.
- **Bug bounty:** nuclei-first + ручной анализ — стандартный рабочий процесс; PoC через curl требуется платформами.
- **Пентест:** связка инструментов даёт покрытие и доказательства для отчёта.
- **Работа (AppSec):** автоматизация сканов в CI и структурированный разбор результатов — часть DevSecOps.
