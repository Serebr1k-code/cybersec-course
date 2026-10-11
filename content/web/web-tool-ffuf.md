---
id: web-tool-ffuf
title: "ffuf: полный практический справочник"
category: web
parent: web-tools-fuzz
difficulty: medium
order: 1
tags: [ffuf, fuzzing, discovery, vhost, parameters, brute, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Все флаги ffuf по группам, режимы подстановки, матчеры/фильтры, рецепты для путей, vhost, параметров, значений и логинов."
---

`ffuf` (Fuzz Faster U Fool) — самый универсальный HTTP-фаззер: он подставляет значение словаря в любое место запроса (URL, заголовок, cookie, тело) и оставляет только «отклонения» от нормы. Скорость, гибкие фильтры и JSON-вывод делают его инструментом по умолчанию для content discovery, vhost-фаззинга, перебора параметров и логинов.

Этот урок — **рабочий справочник**, а не введение. Здесь сгруппированы по задачам все ходовые флаги, показаны копируемые команды и разобрано, **что выбрать в конкретной ситуации**. Версия в примерах — ffuf 2.x.

## Шпаргалка: флаги, которые нужны в 90% задач

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-u` | цель (обязательно с `FUZZ`) | `ffuf -u https://t/FUZZ -w w.txt` |
| `-w` | словарь (можно `-w list:KEY`) | `ffuf -u https://t/FUZZ -w common.txt` |
| `-mc` / `-fc` | какие коды оставить / исключить | `-mc 200,301,302,403 -fc 404` |
| `-fs` / `-fw` / `-fl` | фильтр по размеру / словам / строкам | `-fs 1234` |
| `-ac` | авто-калибровка против wildcard/soft-404 | `-ac` |
| `-e` | добавить расширения к FUZZ | `-e .php,.bak` |
| `-H` | заголовок (в т.ч. `Host: FUZZ`) | `-H 'Authorization: Bearer X'` |
| `-X` / `-d` | метод / тело запроса | `-X POST -d 'a=FUZZ'` |
| `-b` | cookie | `-b 'session=abc'` |
| `-t` / `-rate` | потоки / запросов в секунду | `-t 40 -rate 80` |
| `-recursion` | рекурсивный обход | `-recursion -recursion-depth 3` |
| `-o` / `-of json` | файл вывода / формат | `-o out.json -of json` |

## Когда ffuf, а когда другой инструмент

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Перебор путей с тонкими фильтрами | **ffuf** | `-mc/-fs/-fw/-fl`, авто-калибровка, JSON |
| Рекурсивный обход дерева директорий | feroxbuster | Из коробки рекурсия + авто-фильтр wildcard |
| DNS-поддомены | gobuster dns | Специализированный резолвер |
| Сложные комбинации payload + encoders | wfuzz | Мощнее движок payloads |
| Интерактивная работа с формой | Burp Intruder | GUI, payload processing |
| Одноразовая проверка параметра | curl | Быстрее на один запрос |

Правило: **ffuf — когда нужна скорость, фильтры и автоматизация**. Если задача — «пройтись рекурсивно и забыть», берите feroxbuster; если «перебрать DNS», gobuster.

## Анатомия команды и ключевое слово FUZZ

Общая форма:

```bash
ffuf -u URL_С_FUZZ -w СЛОВАРЬ [опции]
```

- `-u` — цель; **обязательно** содержит ключевое слово (по умолчанию `FUZZ`).
- `-w` — словарь; можно указать своё ключевое слово: `-w list.txt:KEY`.
- Ключевое слово можно подставлять в `-H`, `-b`, `-d` — ffuf заменит его везде.
- Ключевых слов может быть несколько (см. многословарный режим).

Минимальный запуск:

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

По умолчанию ffuf «попаданием» считает коды `200-299,301,302,307,401,403,405,500` и фильтрует `404`.

## Словари и подстановка

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-w PATH` | Словарь | `-w common.txt` |
| `-w PATH:KEY` | Словарь с именем ключевого слова | `-w users.txt:USER -w pass.txt:PASS` |
| `-w -` | Читать словарь из stdin | `cat words.txt \| ffuf -w - ...` |
| `-e .php,.bak` | Расширения (добавляются к FUZZ) | `-e .php,.html,.bak` |
| `-D` | DirSearch-совместимость (с `-e`) | `-D -e .php` |
| `-enc FUZZ:urlencode` | Кодировать значение | `-enc FUZZ:urlencode b64encode` |
| `-ic` | Игнорировать комментарии (`#`) в словаре | `-ic` |
| `-mode` | Режим для нескольких словарей | `-mode clusterbomb` |
| `-input-cmd` | Генерировать вход командой | `-input-cmd 'seq 1 100' -input-num 100` |

**Многословарный режим.** Несколько `-w` с разными ключевыми словами:

```bash
ffuf -w users.txt:USER -w pass.txt:PASS -u https://t/login -X POST \
     -d 'user=USER&pass=PASS' -mode clusterbomb
```

- `clusterbomb` (по умолчанию) — все комбинации (медленно, но полно).
- `pitchfork` — идут параллельно (по одной строке из каждого), для пар логин:пароль.
- `sniper` — одно слово за раз, остальные — из «базового» запроса.

**Кодирование значений.** Если сервер ждёт URL-encoded или base64:

```bash
ffuf -u 'https://t/search?q=FUZZ' -w payloads.txt -enc FUZZ:urlencode
ffuf -u 'https://t/api?id=FUZZ' -w ids.txt -enc FUZZ:b64encode
```

## Матчеры и фильтры

Это сердце ffuf: **матчеры** говорят «что считать попаданием», **фильтры** — «что выбросить».

Матчеры:

| Флаг | Что матчит |
|------|-----------|
| `-mc` | HTTP-коды (`all` для всех) |
| `-ms` | Размер ответа (байты) |
| `-ml` | Число строк |
| `-mw` | Число слов |
| `-mr` | Regexp по телу |
| `-mt` | Время до первого байта (`>100`, `<100`) |
| `-mmode` | Логика между матчерами (`and`/`or`) |

Фильтры:

| Флаг | Что фильтрует |
|------|--------------|
| `-fc` | HTTP-коды (по умолчанию `404`) |
| `-fs` | Размер ответа |
| `-fl` | Число строк |
| `-fw` | Число слов |
| `-fr` | Regexp по телу |
| `-ft` | Время до первого байта |
| `-fmode` | Логика между фильтрами (`and`/`or`) |

Пример: показать всё, кроме размера 1234 и слов 42:

```bash
ffuf -u https://t/FUZZ -w words.txt -mc all -fs 1234 -fw 42
```

Пример: оставить только ответы, где тело содержит `admin`:

```bash
ffuf -u https://t/FUZZ -w words.txt -mr 'admin' -mc all
```

**Авто-калибровка** (против wildcard/soft-404):

| Флаг | Что делает |
|------|-----------|
| `-ac` | Автоматически подобрать фильтры |
| `-acc STRING` | Свой калибровочный вход (несколько раз) |
| `-ach` | Калибровка по каждому хосту |
| `-ack KEY` | Ключевое слово для калибровки (по умолчанию FUZZ) |

```bash
ffuf -u https://t/FUZZ -w words.txt -ac
```

## Методы, заголовки, cookie, тело запроса

| Флаг | Назначение | Пример |
|------|-----------|--------|
| `-X` | HTTP-метод | `-X POST` |
| `-H` | Заголовок (можно много) | `-H 'Authorization: Bearer X'` |
| `-b` | Cookie | `-b 'session=abc'` |
| `-d` | Тело POST | `-d 'a=1&b=FUZZ'` |
| `-r` | Следовать редиректам | `-r` |
| `-raw` | Не кодировать URI | `-raw` |
| `-http2` | Использовать HTTP/2 | `-http2` |
| `-timeout` | Таймаут запроса, сек | `-timeout 15` |
| `-ignore-body` | Не читать тело (только код/заголовки) | `-ignore-body` |
| `-replay-proxy` | Переиграть найденное через прокси | `-replay-proxy http://127.0.0.1:8080` |
| `-x` | Прокси (HTTP/SOCKS5) | `-x http://127.0.0.1:8080` |
| `-cc`/`-ck` | Клиентский серт/ключ (mTLS) | `-cc cert.pem -ck key.pem` |
| `-sni` | Свой TLS SNI | `-sni host.local` |

Пример: фаззинг JSON-API с авторизацией:

```bash
ffuf -u https://api.target.com/v1/FUZZ \
     -X POST \
     -H 'Content-Type: application/json' \
     -H 'Authorization: Bearer eyJ...' \
     -d '{"id":1}' \
     -mc 200,201,204,400,401,403,500 -ac
```

## Рекурсия, расширения, потоки, rate-limit

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-recursion` | Рекурсивный обход (URL должен кончаться на FUZZ) | `-recursion` |
| `-recursion-depth` | Максимальная глубина | `-recursion-depth 3` |
| `-recursion-strategy` | `default` (по редиректу) или `greedy` (по всем совпадениям) | `-recursion-strategy greedy` |
| `-t` | Потоки (по умолчанию 40) | `-t 20` |
| `-rate` | Запросов в секунду | `-rate 50` |
| `-p` | Задержка между запросами (число или диапазон) | `-p 0.1-1.0` |
| `-maxtime` | Общий лимит времени, сек | `-maxtime 120` |
| `-maxtime-job` | Лимит на один job | `-maxtime-job 30` |
| `-se` | Остановиться на ошибках | `-se` |
| `-sf` | Остановиться, если >95% ответов 403 | `-sf` |
| `-sa` | Стоп на любых ошибках | `-sa` |

```bash
ffuf -u https://t/FUZZ -w raft-medium-directories.txt -recursion -recursion-depth 3 \
     -e .php,.html -t 30 -rate 80 -maxtime 180 -o out.json -of json
```

## Режимы фаззинга: пути, vhost, параметры, значения, логин

**Пути/файлы (dir brute):**

```bash
ffuf -u https://target.com/FUZZ -w common.txt -mc 200,204,301,302,307,401,403,405,500 -e .php,.bak
```

**Vhost (Host header):** сначала найдите размер «дефолтной» страницы, потом фильтруйте его.

```bash
# 1) калибровка: размер ответа для случайного Host
curl -s -o /dev/null -w '%{size_download}\n' -H 'Host: nosuchhost.target.com' https://target.com/
# 2) фаззинг
ffuf -u https://target.com/ -H 'Host: FUZZ.target.com' -w subdomains.txt -fs <РАЗМЕР>
```

**Параметры (имена GET/POST):**

```bash
ffuf -u 'https://target.com/api/item?FUZZ=1' -w burp-parameter-names.txt -fs 0 -mc all
ffuf -u https://target.com/api/item -X POST -H 'Content-Type: application/json' \
     -d '{"FUZZ":"test"}' -w param-names.txt -mc all -fs <дефолт>
```

**Значения параметра:**

```bash
ffuf -u 'https://target.com/user?id=FUZZ' -w <(seq 1 500) -mc all -fs <дефолт>
ffuf -u 'https://target.com/?debug=FUZZ' -w <(printf '0\n1\ntrue\nfalse\n') -mc all
```

**Логин (перебор пароля к одному пользователю):**

```bash
ffuf -u https://target.com/login -X POST \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'username=admin&password=FUZZ' \
     -w rockyou-top1000.txt \
     -fc 200 -fs <размер-страницы-ошибки>
```

Здесь важно: коды/размер успеха и ошибки отличаются — задайте `-mc`/`-fs` по «странице ошибки».

**Заголовки:**

```bash
ffuf -u https://target.com/ -H 'X-Forwarded-For: FUZZ' -w ips.txt -mc all -fs <дефолт>
ffuf -u https://target.com/ -H 'FUZZ: 1' -w headers.txt -mc all -fs <дефолт>
```

## Чтение сырого запроса из файла (-request)

Самый точный способ — сохранить запрос из Burp и подать его ffuf:

```bash
ffuf -request request.txt -request-proto https -w values.txt -mc all -fs <дефолт>
```

Внутри `request.txt` — сырой HTTP-запрос; ffuf сам найдёт место подстановки (нужно вставить `FUZZ` в нужное поле). `-request-proto` задаёт схему (`https` по умолчанию).

## Вывод и автоматизация

| Флаг | Что делает |
|------|-----------|
| `-o FILE` | Файл вывода |
| `-of FORMAT` | `json, ejson, html, md, csv, ecsv, all` |
| `-od DIR` | Каталог для результатов |
| `-json` | NDJSON в stdout (для пайплайна) |
| `-or` | Не создавать файл, если результатов нет |
| `-s` | Silent |
| `-c` | Цвет |
| `-v` | Verbose (полный URL + Location) |
| `-audit-log FILE` | Лог всех запросов/ответов |
| `-debug-log FILE` | Внутренний лог |

**Дополнительные флаги (с примерами):**

| Флаг | Что делает | Пример |
|------|-----------|--------|
| `-k` | не проверять TLS-сертификат (self-signed) | `ffuf -u https://t/FUZZ -w w.txt -k` |
| `-noninteractive` | отключить интерактивную консоль | `ffuf -u https://t/FUZZ -w w.txt -noninteractive` |
| `-search STR` | найти строку в словаре и выйти | `ffuf -w raft.txt -search admin` |
| `-input-shell CMD` | шелл для генерации входа `-input-cmd` | `ffuf -u https://t/FUZZ -input-cmd 'seq 1 5' -input-num 5 -input-shell bash` |
| `-V` / `-h` | версия / справка | `ffuf -V` |

Разбор JSON через jq:

```bash
ffuf -u https://t/FUZZ -w w.txt -o out.json -of json -s
jq -r '.results[] | "\(.status) \(.length) \(.url)"' out.json | sort -n
```

Пайплайн в другие инструменты (NDJSON):

```bash
ffuf -u https://t/FUZZ -w w.txt -json -s | jq -r 'select(.status==200) | .url' > live.txt
```

## Рецепты

**1. Быстрый дискавери директорий с расширениями:**

```bash
ffuf -u https://t/FUZZ -w raft-medium-directories.txt -e .php,.html,.js,.bak \
     -mc 200,204,301,302,307,401,403 -ac -t 40 -o dirs.json -of json
```

**2. Перебор API-эндпоинтов (после краулинга katana):**

```bash
ffuf -u https://t/api/FUZZ -w api-endpoints.txt -H 'Accept: application/json' \
     -mc 200,201,400,401,403,405,422 -ac
```

**3. Subdomain-фаззинг через Host-заголовок:**

```bash
ffuf -u https://t/ -H 'Host: FUZZ.t.com' -w subdomains.txt -fs <дефолт> -t 50
```

**4. Перебор ID (IDOR-разведка):**

```bash
ffuf -u 'https://t/api/orders/FUZZ' -w <(seq 1 5000) -mc all -fs <дефолт> -rate 100
```

**5. Логин с pitchfork (пары логин:пароль):**

```bash
ffuf -w combos.txt:CRED -u https://t/login -X POST -d 'cred=CRED' \
     -fc 200 -fs <размер-ошибки> -mode pitchfork
```

**6. Разные методы на одном эндпоинте:**

```bash
ffuf -u https://t/api/user -X FUZZ -w <(printf 'GET\nPOST\nPUT\nDELETE\nPATCH\nOPTIONS\n') -mc all -fs <дефолт>
```

**7. Воспроизведение из сырого запроса (с cookie/заголовками):**

```bash
ffuf -request req.txt -w ids.txt -mc all -fs <дефолт>
```

## Что выбрать и когда

- **Пути/файлы:** ffuf + `raft-*` словарь + `-e` + `-ac`.
- **Рекурсия важнее скорости:** feroxbuster (не ffuf).
- **DNS-поддомены:** gobuster dns (не ffuf).
- **Vhost:** ffuf `-H 'Host: FUZZ'` + фильтр по размеру дефолта.
- **Параметры:** ffuf `?FUZZ=1` + `-fs 0 -mc all` (или Arjun).
- **Логины:** ffuf с `-d` + `-fs` размера страницы ошибки; малый словарь.
- **Хитрые payload/encoders:** wfuzz.
- **GUI и payload processing:** Burp Intruder.
- **Автоматизация/пайплайн:** ffuf `-json` + jq.

## Частые ошибки

- **Не фильтровать wildcard.** Если любой путь даёт 200 — включите `-ac` или `-fs <размер дефолта>`.
- **Слишком много потоков.** `-t 200` роняет сервис и провоцирует бан. Начинайте с 20–40, добавляйте `-rate`.
- **`-mc all` без фильтра.** Выведет вообще всё; всегда сочетайте с `-fs`/`-fw`/`-fl`.
- **Неверный размер страницы ошибки при переборе логинов.** Успех и провал отличаются — измерьте оба заранее.
- **Забыть `-request-proto`.** Сырой запрос без схемы может уйти по http вместо https.
- **Длинный скан убит таймаутом.** Используйте `-maxtime`, фон или больший timeout.
- **Игнорировать комментарии словаря.** Добавьте `-ic`, иначе ffuf шлёт запросы на строки `# ...`.

## Квиз

```quiz
- question: "Какой флаг ffuf задаёт словарь?"
  options:
    - "-u"
    - "-w"
    - "-d"
    - "-mc"
  answer: 1
  explanation: "-w — путь к словарю (можно с именем ключевого слова через двоеточие)."
- question: "Что делает -ac в ffuf?"
  options:
    - "Добавляет cookie"
    - "Автоматически калибрует фильтры против wildcard/soft-404"
    - "Меняет метод на POST"
    - "Включает HTTP/2"
  answer: 1
  explanation: "Авто-калибровка подбирает фильтры по «мусорным» ответам."
- question: "Какой флаг оставляет только ответы, содержащие regexp 'admin'?"
  options:
    - "-fr admin"
    - "-mr admin"
    - "-fs admin"
    - "-mc admin"
  answer: 1
  explanation: "-mr — match regexp; -fr — filter regexp (исключить)."
- question: "Зачем ffuf режим -mode pitchfork?"
  options:
    - "Все комбинации словарей"
    - "По одной строке из каждого словаря параллельно"
    - "Отключает фильтры"
    - "Читает запрос из файла"
  answer: 1
  explanation: "pitchfork идёт параллельно по словарям — удобно для пар логин:пароль."
- question: "Что нужно сделать перед vhost-фаззингом, чтобы не получить тысячи ложных попаданий?"
  options:
    - "Задать -X POST"
    - "Измерить размер дефолтного ответа и фильтровать его через -fs"
    - "Включить -recursion"
    - "Использовать -http2"
  answer: 1
  explanation: "Сервер обычно отдаёт одну и ту же заглушку для любого Host; её размер фильтруют."
```

## Где пригодится

- **CTF (Web):** быстрый перебор путей/параметров, поиск флагов в скрытых эндпоинтах и бэкапах.
- **Bug bounty:** content discovery, vhost- и parameter-фаззинг, разведка IDOR — основа расширения поверхности.
- **Пентест:** стандартный этап discovery с воспроизводимым JSON-выводом для отчёта.
- **Работа (AppSec/DevSecOps):** автоматизированные проверки новых релизов на забытые админки и файлы.
