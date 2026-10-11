---
id: web-recon-fuzzing
title: "Разведка и фаззинг веб-приложения: контент, параметры, vhost"
category: web
parent: web-architecture-basics
difficulty: easy
order: 1
tags: [recon, fuzzing, ffuf, gobuster, directory-bruteforce, subdomain, vhost]
prerequisites: [web-architecture]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как системно искать скрытые пути, параметры, поддомены и виртуальные хосты до начала эксплуатации."
---

Разведка — это этап, который отличает методичного тестировщика от новичка, который «тыкает наугад». Цель фаззинга — превратить чёрный ящик в карту: найти все пути, параметры, поддомены и виртуальные хосты, которые приложение обслуживает, но не афиширует. Большинство багов находят именно там, куда UI не ведёт.

## Теория: виды фаззинга

**Directory/Content fuzzing.** Перебор путей: `/admin`, `/backup.zip`, `/.git/config`, `/api/v1/...`. Ищем существующие ресурсы, бэкапы, скрытые ручки.

**Parameter fuzzing.** Перебор имён параметров (`?debug=`, `?id=`, `?admin=`) и их значений. Часто именно недокументированный параметр включает «режим отладки» или меняет права.

**Subdomain enumeration.** Поиск поддоменов (`admin.target.com`, `internal.target.com`). Каждый поддомен — отдельное приложение со своей поверхностью.

**VHost fuzzing.** Один IP обслуживает разные сайты в зависимости от заголовка `Host`. Скрытый vhost может отдавать админку.

**Parameter value fuzzing.** Отправка payload-словаря (`'`, `"`, `{{7*7}}`, `../../`) в уже найденные параметры — это уже этап тестирования инъекций, но инструмент тот же.

Ключевая идея: **фаззинг ищет «дельта-ответы»**. Важно не «сколько путей нашлось», а какие ответы отличаются от базового (обычно `404`). Фильтруйте по коду, размеру, количеству слов.

## Инструменты: ffuf, gobuster, feroxbuster

**ffuf** — самый гибкий. Пример перебора директорий:

```bash
ffuf -u https://target.example/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,204,301,302,401,403 \
  -t 40 -rate 100
```

- `FUZZ` — точка подстановки;
- `-w` — словарь (seclists — стандарт);
- `-mc` — какие коды считать «находками» (match codes);
- `-t` — потоки; `-rate` — запросов/сек (чтобы не забанили).

Добавить расширения (искать `index.php`, `config.bak`):

```bash
ffuf -u https://target.example/FUZZ -w common.txt -e .php,.bak,.zip,.txt,.json
```

**Перебор параметров** (`-X POST`, тело через `-d`):

```bash
ffuf -u https://target.example/api/search?FUZZ=test \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 1256   # отфильтровать ответы размером 1256 байт (шум)
```

`-fs` (filter size) — отбрасывает стандартный ответ; `-fc` — по коду; `-fw` — по словам.

**gobuster** — проще и быстрее для директорий:

```bash
gobuster dir -u https://target.example \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,js -q -t 40
```

**feroxbuster** — рекурсивный обход (сам заходит в найденные каталоги):

```bash
feroxbuster -u https://target.example -w common.txt -x php -d 3 -q
```

**Subdomain enumeration** (пассивно + активно):

```bash
# пассивно — из публичных источников, без запросов к цели
subfinder -d target.example -silent

# активная проверка списка кандидатов
ffuf -u https://FUZZ.target.example -w subs.txt -mc 200,301,302,401,403
```

**VHost fuzzing** (заголовок Host, домен — заведомо несуществующий):

```bash
ffuf -u https://target.example/ -H 'Host: FUZZ.target.example' \
  -w subs.txt -fs 0
```

Важно: перед фаззингом всегда проверяйте, не отдаёт ли сервер **wildcard**-ответ (любой случайный путь возвращает 200). Тогда `ffuf` нужно фильтровать по размеру (`-fs`) или коду. Проверка:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://target.example/zzzq-random-123
```

## Разобранный пример: полный рекон веб-цели

Цель — `https://shop.example` (магазин). Работаем по шагам.

Шаг 1. Базовая разведка и wildcard-проверка:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' https://shop.example/random-9x8y7z
# 404 512  -> wildcard нет, можно фаззить
```

Шаг 2. Перебор директорий:

```bash
ffuf -u https://shop.example/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,401,403 -t 40 -rate 80 -o dirs.json -of json
```

Находим: `/api`, `/admin`, `/backup`, `/static`, `/.git`.

Шаг 3. Углубляемся в `/api`:

```bash
ffuf -u https://shop.example/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -mc all -fc 404 -t 40
```

Находим `/api/users`, `/api/orders`, `/api/internal/health`.

Шаг 4. Проверяем `/.git` (частая утечка исходников):

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://shop.example/.git/HEAD
# 200 -> репозиторий доступен! Дамп через git-dumper:
git-dumper https://shop.example/.git/ ./shop-src
```

Шаг 5. Фаззим параметры на `/api/users`:

```bash
ffuf -u 'https://shop.example/api/users?FUZZ=1' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 44 -t 30
```

Находим параметр `role` — и вот уже вектор для privilege escalation.

Шаг 6. Перебор поддоменов:

```bash
subfinder -d example -silent | tee subs.txt
ffuf -u https://FUZZ.example -w subs.txt -mc 200,301,302,401,403 -fs 0
```

Находим `internal.example` → отдельное приложение.

Итог: за ~15 минут получена полная карта поверхности. Дальше — переходим к тестированию найденного (SQLi, IDOR и т.д.).

## Типичные ошибки новичков

- **Не проверять wildcard.** Если сервер отвечает `200` на всё, вы получите тысячи «находок». Всегда сначала отправьте случайный путь и посмотрите базовый ответ.
- **Слишком высокая скорость.** `-t 200 -rate 0` → вас забанит WAF/Cloudflare через минуту. Начинайте с `-rate 50–100`.
- **Один словарь на всё.** Для директорий — `raft-medium-directories`, для файлов — `common.txt`, для параметров — `burp-parameter-names`. Разные словари дают разный результат.
- **Игнорировать коды `403`/`401`.** «Запрещено» — это тоже существующий ресурс, который можно попробовать обойти (path traversal, метод, заголовки).
- **Не сохранять результаты.** Всегда `-o out.json`; иначе после перезапуска вы потеряете карту. Также полезно `-of all`.
- **Фаззить без авторизации, когда приложение требует логин.** Многие ручки отдают `302` на login; добавьте cookie (`-b 'session=...'`) и повторите — под авторизацией откроются новые пути.
- **Забыть про рекурсию.** Найденный `/api/` надо фаззить внутри, найденный `/api/v2/` — ещё глубже. Ограничьте глубину `-d 3`, чтобы не уйти в бесконечность.

## Словари: где брать и как выбирать

Качество фаззинга определяется словарём не меньше, чем инструментом. Плохой выбор — запустить `rockyou` по каталогам или `common.txt` по API. Правильный — подобрать список под задачу и стек. Основные источники: **SecLists** (`Discovery/Web-Content/` — от `common.txt` до `raft-*-directories.txt`), **Assetnote Wordlists** (собраны из реального краулинга, часто богаче SecLists), собственные списки из `katana`/`gau` (URL конкретной цели — самый точный источник), списки под технологии (`/api/`, `/graphql`, `/_next/`, `.php`, `.jsp`).

Практическое правило: начинайте с `raft-medium-directories.txt` для каталогов, `raft-medium-words.txt` для файлов, отдельный список для параметров (`burp-parameter-names.txt`, `arjun`), отдельный для vhost. Перед запуском проверяйте, не применялся ли уже этот словарь к данному `host:port:tool_type` — повторный прогон не даёт новой информации, только шум и риск бана.

```bash
ls /usr/share/seclists/Discovery/Web-Content/ | grep -iE 'raft|common|directories'
# собственный список из краулинга
katana -u https://t -jc -silent | sed 's#https\?://[^/]*##' | sort -u > target-dirs.txt
```

## vhost, параметры и скрытые поверхности

Каталоги — не единственная поверхность. **Vhost-фаззинг** находит сайты, отдаваемые тем же IP, но по другому `Host`. **Параметр-фаззинг** находит скрытые параметры, которые меняют поведение. **Заголовки** могут открывать скрытые функции (`X-Forwarded-Host`, `X-Original-URL`).

```bash
# vhost
ffuf -w subs.txt -u https://t/ -H 'Host: FUZZ.t' -fs 1234
# параметры
arjun -u https://t/api/item --get -m GET,POST
ffuf -w params.txt -u 'https://t/api?FUZZ=1' -fs 0
# скрытый роутинг
curl -s https://t/ -H 'X-Original-URL: /admin'
```

## Что делать дальше / решение

Стройте фаззинг итеративно: сначала каталоги (дешёво), затем параметры и vhost, затем скрытые поверхности из JS. Каждый найденный путь/параметр сразу триажируйте (код, размер, содержимое). Записывайте словарь и результат в журнал. Доводите интересные находки до артефакта (данные, функция). И не забывайте про rate-limit: снижайте `-t`, добавляйте паузы, иначе получите бан и ложное «ничего не найдено».

## Полный разобранный пример: от домена до находки

Пройдём типовой рекон целиком, с реальными выводами на каждом шаге. Цель — `app.target.local`. Начинаем с живых хостов и стека.

```bash
$ subfinder -d target.local -silent | httpx -silent -sc -title -td
https://app.target.local   [200] [App]   [nginx/1.20, PHP/8.1]
https://api.target.local   [401] [API]   [Express]
https://static.target.local [200] [Static] [AmazonS3]
```

Далее — контент. Берём `raft-medium-directories.txt` и фильтруем по коду.

```bash
$ ffuf -w raft-medium-directories.txt -u https://app.target.local/FUZZ -mc 200,301,302,401,403 -fs 0 -t 40
admin                   [Status: 302, Size: 0]
backup                  [Status: 301, Size: 169]
api                     [Status: 401, Size: 12]
uploads                 [Status: 200, Size: 1004]
```

`backup` редиректит в каталог — заходим и перебираем расширения.

```bash
$ ffuf -w raft-medium-words.txt -u https://app.target.local/backup/FUZZ -e .zip,.tar.gz,.sql,.bak -mc 200 -fs 0
db.sql                  [Status: 200, Size: 20480]
```

Артефакт: дамп `db.sql`. Дальше — параметры и vhost.

```bash
$ arjun -u https://app.target.local/api/item --get -m GET
[+] Valid parameter: id
$ ffuf -w subs.txt -u https://app.target.local/ -H 'Host: FUZZ.target.local' -fs 1004
dev                     [Status: 200, Size: 812]
```

Нашли скрытый параметр `id` и vhost `dev`. Каждый — новая поверхность. Маршрут закрыт до триажа инъекций и авторизации.

## Инструменты: расширенные флаги

| Задача | Команда |
|--------|---------|
| живые хосты + стек | `httpx -l hosts.txt -sc -title -td -server` |
| каталоги | `ffuf -w dirs.txt -u https://t/FUZZ -mc 200,301,302 -fs 0` |
| файлы с расширениями | `ffuf -w words.txt -u https://t/FUZZ -e .php,.bak,.zip` |
| vhost | `ffuf -w subs.txt -u https://t/ -H 'Host: FUZZ.t' -fs 0` |
| параметры | `arjun -u https://t/endpoint --get` |
| рекурсия | `feroxbuster -u https://t -w dirs.txt -d 3 --auto-tune` |
| краул JS | `katana -u https://t -jc -silent` |
| CVE | `nuclei -l live.txt -tags cve -silent` |

## Что делать дальше / решение

Рекон — итеративный процесс: нашли путь → триажируйте его (код, содержимое, параметры), нашли параметр → проверьте на инъекцию/IDOR, нашли vhost → повторите рекон на нём. Каждую находку доводите до артефакта, каждый отрицательный результат записывайте. Заканчивайте рекон не когда «кончились идеи», а когда закрыты все дешёвые ветки и найденные поверхности отработаны.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что означает `FUZZ` в команде `ffuf -u https://x/FUZZ`?"
  options:
    - "Спецсимвол для случайных данных"
    - "Точка подстановки слова из словаря"
    - "Фильтр по размеру"
    - "Код состояния"
  answer: 1
  explanation: "`FUZZ` — место, куда подставляется каждое слово."
- question: "Зачем перед фаззингом отправлять случайный путь?"
  options:
    - "Чтобы прогреть сервер"
    - "Чтобы выявить wildcard-ответ и настроить фильтр"
    - "Чтобы получить TLS-сертификат"
    - "Это не нужно"
  answer: 1
  explanation: "Иначе базовый ответ сольётся с «находками»."
- question: "Какой флаг ffuf фильтрует ответы по размеру?"
  options:
    - "`-mc`"
    - "`-fc`"
    - "`-fs`"
    - "`-ft`"
  answer: 2
  explanation: "`-fs` = filter size (по байтам)."
- question: "Что ищет vhost-фаззинг через заголовок `Host`?"
  options:
    - "Открытые порты"
    - "Другие сайты, обслуживаемые тем же IP"
    - "Уязвимости TLS"
    - "Записи DNS"
  answer: 1
  explanation: "Разные `Host` могут отдавать разные приложения."
- question: "Почему найденный код `403` — тоже «находка»?"
  options:
    - "Он означает успех"
    - "Ресурс существует, но закрыт — его можно попробовать обойти"
    - "Это признак SQLi"
    - "Он ничего не значит"
  answer: 1
  explanation: "Существующий, но защищённый ресурс — потенциальная цель."
```

## Где пригодится

- **CTF (Web):** скрытые пути (`.git`, `/admin`, бэкапы) — классический источник флагов; фаззинг часто и есть решение задачи.
- **Bug bounty:** расширение поверхности — прямой путь к уникальным багам; скрытые API и поддомены дают отчёты с высокой выплатой.
- **Пентест:** инвентаризация эндпоинтов — обязательный этап, без неё оценка покрытия неполна.
- **Работа (AppSec):** те же словари и техники используются в CI для проверки, что в прод не попали бэкапы и `.git`.
