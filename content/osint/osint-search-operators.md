---
id: osint-search-operators
title: "Поисковые операторы и Google Dorks"
category: osint
parent: osint-collection
difficulty: beginner
order: 1
tags: [google, dorks, search, operators, shodan]
prerequisites: [osint-intro]
useful_for:
  - "Поиск утёкших документов, панелей, файлов"
  - "CTF-задачи с поиском скрытых страниц"
estimated_minutes: 45
summary: "Операторы Google/Bing/Yandex, построение дорков, поиск утечек и панелей, OPSEC и ограничения."
---
Поисковые операторы — это язык, на котором вы «программируете» поисковик. Вместо перебора результатов вы точно описываете, что ищете: домен, тип файла, слово в URL или заголовке. Dorking — базовый навык OSINT и первый шаг почти любой веб-разведки. Умение строить запрос важнее умения пользоваться конкретным инструментом: тот же оператор работает в Google, Bing, Yandex и DuckDuckGo, лишь с небольшими отличиями синтаксиса.

## Базовые операторы Google

| Оператор | Что делает | Пример |
|---|---|---|
| `site:` | ограничить домен | `site:example.com` |
| `filetype:` | тип файла (alias `ext:`) | `filetype:pdf` |
| `inurl:` | слово в URL | `inurl:admin` |
| `allinurl:` | все слова в URL | `allinurl:admin login` |
| `intitle:` | слово в `<title>` | `intitle:"index of"` |
| `allintitle:` | все слова в title | `allintitle:index of` |
| `intext:` | слово в тексте | `intext:"пароль"` |
| `inbody:` | тело документа | `inbody:"confidential"` |
| `-` | исключить | `site:example.com -www` |
| `"..."` | точная фраза | `"internal use only"` |
| `OR` / `\|` | альтернатива | `filetype:xls OR filetype:xlsx` |
| `*` | wildcard | `"user * password"` |
| `..` | диапазон чисел | `filetype:pdf 2019..2024` |
| `AROUND(n)` | близость слов | `admin AROUND(3) password` |
| `cache:` | кэш страницы | `cache:example.com` |
| `related:` | похожие сайты | `related:example.com` |
| `source:` | источник Google News | `source:reuters` |

Комбинируйте: `site:example.com (filetype:pdf OR filetype:docx) intext:"confidential"`. Помните о приоритете: `-` действует на следующий термин, поэтому исключения группируйте осознанно.

## Классические Google Dorks

**Открытые листинги директорий** — самый частый источник утечек:

```
intitle:"index of" "parent directory"
intitle:"index of" passwd
intitle:"index of" "*.sql"
intitle:"index of" ".git"
```

**Конфиги и секреты:**

```
filetype:env "DB_PASSWORD"
filetype:yml "aws_secret_access_key"
filetype:log "password"
filetype:pem "PRIVATE KEY"
filetype:json "private_key_id"
```

**Панели и админки:**

```
inurl:admin intitle:login
inurl:phpMyAdmin
intitle:"Dashboard [Jenkins]"
intitle:"Grafana"
inurl:swagger OR inurl:api-docs
```

**Утёкшие документы:**

```
site:example.com filetype:pdf "internal"
filetype:xlsx "смета"
filetype:csv "email,password"
```

**Камеры и устройства (IoT):**

```
inurl:"/view/view.shtml"
intitle:"Network Camera"
inurl:":8080" intitle:"Hikvision"
```

> Важно: индексирование и доступ — разные вещи. Dork показывает, что страница **проиндексирована**; проверяйте, открыта ли она реально.

## Yandex, Bing и другие

- **Yandex** индексирует Рунет лучше Google. Операторы: `site:`, `mime:`, `title:`, `url:`, `host:`, `rhost:`, `date:`. Плюс сильный поиск по картинкам.
- **Bing** поддерживает `site:`, `filetype:`, `ip:` (поиск по IP), `feed:`, `language:`, `contains:`.
- **DuckDuckGo** (Bing-бэкенд) хорош для приватного поиска без пузыря фильтров, но не поддерживает часть операторов.
- **Google Hacking Database (GHDB)** на exploit-db — библиотека готовых дорков по категориям (footholds, sensitive dirs, error messages).

## Поиск по коду и утечкам

- **GitHub / GitLab поиск**: `org:company`, `filename:.env`, `path:config`, `"AKIA"` (AWS-ключи), `"BEGIN RSA PRIVATE KEY"`. Утёкшие ключи — золото для пентеста.
- **grep.app**, **Sourcegraph**, **searchcode** — поиск по открытому коду.
- **Wayback Machine** (`web.archive.org`) — исторические версии страниц; часто хранит то, что уже удалили.
- **haveibeenpwned.com** — проверка email/домена на утечки (только поиск, без скачивания баз).
- **IntelX / DeHashed** — поиск по утечкам (осторожно с легальностью).

Пример проверки доступности найденного файла (только заголовки, без скачивания тела):

```bash
curl -sI "https://example.com/backup/db.sql" | head -5
# HTTP/1.1 200 OK
# Content-Type: application/sql
```

## Техника: как строить dork

1. **Определите цель**: что ищем — файл, панель, упоминание, учётные данные?
2. **Выберите оператор-«якорь»**: `site:` для домена, `filetype:` для файла.
3. **Добавьте уточнители**: `intext:`, `intitle:`, исключения через `-`.
4. **Сужайте постепенно**: от широкого запроса к точному, чтобы не потерять результаты.
5. **Проверяйте каждую находку** и фиксируйте источник.

## Разобранный пример

Задача: найти открытые бэкапы и конфиги на домене `example.com`.

```
site:example.com (filetype:sql OR filetype:bak OR filetype:zip OR filetype:tar)
site:example.com intitle:"index of" backup
site:example.com filetype:env "DB_"
```

Затем проверяем кандидатов:

```bash
for u in "https://example.com/backup/db.sql" "https://example.com/.env"; do
  echo "== $u"; curl -sI "$u" | head -3
done
```

Код `200` и `Content-Type` подтверждают доступность. Если `403`/`302` на логин — файл есть, но закрыт (тоже информация).

## Автоматизация доркинга

Ручной ввод запросов не масштабируется. Инструменты:

- **pagodo** — гоняет дорки из GHDB через Google, поддерживает задержки против капчи.
- **googler** / **ddgr** — CLI-обёртки над Google/DuckDuckGo.
- **`ddgr`** пример:

```bash
ddgr --json -n 10 'site:example.com filetype:pdf' | jq -r '.[].url'
```

Учитывайте лимиты: Google банит автоматические запросы быстро, поэтому между запросами делайте паузы в десятки секунд и используйте ротацию.

## OPSEC при доркинге

- **Не логиньтесь** в поисковик — иначе персонализация и след.
- **Используйте `&pws=0`** (отключить персонализацию) и чистый профиль.
- **Не открывайте файлы** на рабочей машине — только в изолированной VM.
- **Проверяйте «проиндексировано» ≠ «доступно»** — делайте `curl -I`.
- **Осторожно с `cache:`/архивами** — они могут содержать актуальные данные, которые уже скрыли.
- **Rate-limit**: автоматические запросы быстро приводят к капче; уважайте `robots.txt` и ToS.

## Типичные ошибки

- **Слишком широкий запрос** — тысячи нерелевантных результатов.
- **Забыть кавычки** — фраза распадается на слова и теряет точность.
- **Игнорировать регион** — `site:` без страны даёт лишние языки.
- **Верить сниппету** — Google может показывать устаревший текст; сверяйтесь с живой страницей.
- **Открывать найденный файл локально** — макросы/эксплойты; только песочница.

## Справочные таблицы

| Что ищем | Dork |
|---|---|
| Открытые директории | `intitle:"index of" "parent directory"` |
| Конфиги с паролями | `filetype:env OR filetype:ini "password"` |
| Панели администратора | `inurl:admin intitle:login` |
| Утёкшие документы | `site:example.com filetype:pdf "confidential"` |
| Секреты AWS | `"AKIA" filetype:env` |
| Базы данных | `filetype:sql "INSERT INTO"` |
| Резервные копии | `filetype:bak OR filetype:zip site:example.com` |
| Листинги логов | `filetype:log "error" site:example.com` |
| Файлы SSH | `filename:id_rsa` |
| Swagger/API | `inurl:swagger OR inurl:api-docs` |
| Git-репозитории | `intitle:"index of" ".git"` |

| Поисковик | Сильная сторона | Ключевые операторы |
|---|---|---|
| Google | индексирование кода/файлов | `filetype`, `inurl`, `intitle`, `AROUND` |
| Yandex | Рунет, картинки | `mime`, `title`, `url`, `rhost` |
| Bing | по IP, фиды | `ip:`, `feed:`, `language:` |
| DuckDuckGo | приватность | базовые |

## Операторы под конкретные платформы

Разные площадки дают свои «доморощенные» операторы поверх обычного поиска:

- **LinkedIn**: `site:linkedin.com/in "Company Name"`, поиск сотрудников по должности. В самом LinkedIn — фильтры по company/school/title.
- **Pastebin**: `site:pastebin.com "example.com"` — ищут утёкшие конфиги и ключи.
- **Trello**: `site:trello.com "example.com"` — публичные доски с внутренней инфой.
- **GitHub**: `org:`, `user:`, `repo:`, `path:`, `language:`, `filename:`.
- **Shodan/Censys** — не операторы текста, а фильтры по сервисам: `org:"Example"`, `ssl:"example.com"`, `http.title:"Dashboard"`.
- **Google Groups / форумы**: `site:groups.google.com "example.com"`.

Пример связки для поиска внутренней документации:

```
site:docs.google.com OR site:drive.google.com "example.com" confidential
site:*.example.com -www filetype:xlsx
```

## Продвинутые комбинации и вложенные запросы

Освоив базовые операторы, комбинируйте их в «формулы» под конкретную задачу:

1. **Поверхность домена**: `site:example.com -www -mail` — отсечь служебные поддомены и увидеть необычные.
2. **Утечки данных**: `site:example.com (filetype:csv OR filetype:xlsx) ("password" OR "email")`.
3. **Инфраструктура**: `site:example.com inurl:api OR inurl:internal OR inurl:staging`.
4. **Документы с метаданными**: `site:example.com filetype:docx` → скачать → `exiftool` (в документах часто остаются имена авторов).
5. **Исторические страницы**: `cache:`/Wayback для уже удалённых путей.
6. **Чужие домены той же компании**: `related:example.com` и поиск по вендору из вывески.

Важно про порядок: сначала широкий якорь (`site:`), затем уточнение (`filetype:`, `inurl:`), затем исключения (`-`). Так вы не «пересузите» запрос до нуля результатов.

## Ограничения поисковиков

Даже идеальный dork не всесилен:

- **Не всё проиндексировано** — страницы за логином, `noindex`, свежие URL и динамический контент Google не видит.
- **Операторы урезают** — Google ограничивает число поддерживаемых `OR` и глубину вложенности; часть операторов (`cache:`, `link:`) устарела.
- **Персонализация искажает выдачу** — используйте `&pws=0` и чистый профиль.
- **Локализация** — регион поисковика меняет выдачу; для другой страны задайте `gl=` и `hl=`.
- **Rate-limit и капча** — массовые скриптовые запросы банятся; нужны паузы и ротация.
- **Сниппеты устаревают** — заголовок может быть актуален, а содержимое уже изменено.

Поэтому dork — это разведка *первого* шага: он подсказывает, куда смотреть, а подтверждение всегда делается отдельным запросом к живому ресурсу.

## Что дальше / решение

Dorking — это вход, а не финал. Дальше: **поиск по утечкам** (HIBP, IntelX), **GitHub-recon** (секреты в коде), **архивы Wayback**, **Shodan/Censys** (для сетевых сервисов, а не документов) и **автоматизация** через pagodo/googler. Итог: сначала находите *что* существует, потом проверяете *доступно ли оно*, и только затем переходите к активной фазе.

## Квиз

```quiz
- question: "Что делает оператор `filetype:sql`?"
  options:
    - "Ищет сайты с SQL-инъекциями"
    - "Ограничивает результаты файлами с расширением .sql"
    - "Ищет базы данных на сервере"
    - "Скачивает SQL-файлы"
  answer: 1
- question: "Как исключить поддомен www из выдачи?"
  options:
    - "`site:example.com +www`"
    - "`site:example.com -www`"
    - "`not www example.com`"
    - "`site:!www.example.com`"
  answer: 1
- question: "Какой dork ищет открытые листинги директорий?"
  options:
    - "`inurl:login`"
    - "`intitle:'index of' 'parent directory'`"
    - "`filetype:pdf`"
    - "`site:example.com admin`"
  answer: 1
- question: "Где искать утёкшие API-ключи в открытом коде?"
  options:
    - "В WHOIS"
    - "В GitHub-поиске (`org:company 'AKIA'`)"
    - "В crt.sh"
    - "В DNS-записях"
  answer: 1
- question: "Что показывает Wayback Machine?"
  options:
    - "Будущие версии сайта"
    - "Исторические снимки страниц, включая удалённые"
    - "Пароли сайта"
    - "Только главную страницу"
  answer: 1
```

## Где пригодится

- **CTF:** найти скрытую страницу/файл по подсказке-домену.
- **Bug bounty:** обнаружение открытых конфигов, бэкапов, панелей до сканирования.
- **Пентест:** сбор информации о технологиях и утечках до активной фазы.
- **Журналистика:** поиск документов и первоисточников.
