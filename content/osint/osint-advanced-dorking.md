---
id: osint-advanced-dorking
title: "Продвинутый доркинг: операторы, автоматизация и GHDB"
category: osint
parent: osint-search-dorking
difficulty: medium
order: 3
tags: [dorks, google, bing, yandex, ghdb, automation]
prerequisites: [osint-search-operators]
useful_for:
  - "Поиск утечек и уязвимых страниц"
  - "CTF категория OSINT"
  - "Bug bounty recon"
estimated_minutes: 45
summary: "Редкие операторы, различия Google/Bing/Yandex, Google Hacking Database, автоматизация доркинга и защита от ложных срабатываний."
---

Базовые `site:`/`filetype:` — только начало. Продвинутый доркинг — это умение **комбинировать редкие операторы**, знать различия движков и автоматизировать перебор. Здесь вы превращаете поисковик в сканер поверхности атаки, не отправляя ни одного запроса на цель.

## Полный набор операторов Google

| Оператор | Назначение | Пример |
|---|---|---|
| `site:` | домен/поддомен | `site:api.example.com` |
| `inurl:` / `allinurl:` | в URL (одно / все слова) | `inurl:reset allinurl:admin panel` |
| `intitle:` / `allintitle:` | в `<title>` | `intitle:"index of"` |
| `intext:` / `allintext:` | в тексте | `intext:"BEGIN RSA PRIVATE KEY"` |
| `filetype:` / `ext:` | расширение | `filetype:sql` |
| `inanchor:` | в тексте ссылок | `inanchor:"login"` |
| `link:` | страницы, ссылающиеся на URL (устарел) | `link:example.com` |
| `related:` | похожие сайты | `related:example.com` |
| `cache:` | кэш страницы | `cache:example.com` |
| `define:` | определение | `define:osint` |
| `AROUND(n)` | слова в пределах n слов | `password AROUND(3) file` |
| `before:` / `after:` | по дате | `after:2024-01-01` |
| `source:` | по новостному источнику | `source:reuters` |
| `-` | исключение | `site:example.com -inurl:www` |
| `|` / `OR` | альтернатива | `filetype:env | filetype:ini` |
| `*` | wildcard | `"password is *"` |
| `..` | диапазон чисел | `inurl:id=1..999` |

Комбинация `AROUND`, `..` и `-` даёт очень точные запросы: `inurl:id=1..999 -inurl:404 "user"`.

## Различия движков

**Google** — самый полный индекс, но персонализирует выдачу. Отключайте пузырь: `&pws=0`, режим инкогнито, отдельный профиль, `&num=100` для больших страниц.

**Bing** — поддерживает `ip:` (поиск по IP-адресу), `feed:`, `language:`, `loc:`. Полезен для страниц, которые Google выкинул из индекса.

```
ip:203.0.113.10
language:ru site:example.com filetype:pdf
```

**Yandex** — лучший индекс Рунета. Операторы: `site:`, `url:`, `title:`, `mime:` (аналог filetype), `host:`, `rhost:` (обратные ссылки).

```
site:example.com mime:docx "конфиденциально"
```

**DuckDuckGo / Startpage / Searx** — приватные фронтенды к Bing/Google; удобны, когда нельзя светить профиль. **Searx** можно поднять локально и получить мета-поиск без трекинга.

## Google Hacking Database (GHDB)

GHDB — каталог готовых дорков (Exploit-DB → Google Hacking Database). Категории: файлы с паролями, уязвимые серверы, ошибки, панели, чувствительные каталоги. Используйте как источник вдохновения, но **всегда адаптируйте под цель**.

Классические категории:

```
# Пароли и ключи
filetype:pem "PRIVATE KEY"
filetype:env DB_PASSWORD
filetype:json "api_key"

# Открытые логи
filetype:log inurl:error
intitle:"index of" access.log

# DevOps и панели
intitle:"Grafana"
intitle:"Kibana" inurl:app/kibana
intitle:"Jenkins" "Dashboard"

# Резервные копии и дампы
filetype:sql "INSERT INTO"
filetype:bak inurl:backup
```

## Дорки по сервисам и платформам

Кроме Google, дорки есть у каждой платформы со своим синтаксисом:

- **GitHub** — `filename:.env DB_PASSWORD`, `org:example`, `"AKIA" path:*.py`.
- **Shodan/Censys** — по баннерам (см. `osint-shodan-dorks`).
- **Pastebin/Google** — `site:pastebin.com "example.com"`.
- **FTP-индексы** — `intitle:"index of" "parent directory" ftp`.

## Автоматизация

Ручной перебор дорков не масштабируется. Инструменты:

- **Pagodo** — автоматизирует прогон GHDB-дорков через Google.
- **Dorkbot** — проверка дорков против домена с фильтрацией.
- **googler** (CLI) — скриптуемый поиск из терминала.
- **Собственный скрипт**: список дорков → API поисковика (SerpAPI, Bing API) → дедупликация результатов.

Пример ручного цикла на Bash (осторожно, лимиты!):

```bash
while read -r dork; do
  echo "== $dork"
  googler --json -n 20 "$dork" | jq -r '.[].url'
  sleep 5
done < dorks.txt
```

> Не долбите поисковик: бан за автоматизацию приходит быстро. Используйте API или паузы, ротацию User-Agent и прокси.

## Работа с ложными срабатываниями

Дорк находит **проиндексированное**, а не обязательно доступное. Отсеивайте:

1. Проверяйте код ответа: `curl -sI https://target/path` (200 vs 403/404).
2. Сравнивайте `Content-Type` и `Content-Length` — заглушки отличаются.
3. Исключайте чужие домены оператором `site:`.
4. Убирайте «мусор» через `-inurl:` (например, `-inurl:login`).

```bash
# быстрая проверка доступности найденных URL
cat urls.txt | httpx -silent -mc 200 -title
```

## Разобранный пример

Задача: найти конфиги и ключи на `example.com`.

```
site:example.com (filetype:env OR filetype:ini OR filetype:yml)
site:example.com inurl:.git
site:example.com intitle:"index of" ".ssh"
site:example.com "AKIA" intext:"aws"
```

Далее — только `curl -sI` по каждому URL. Что вернуло `200` и непустой `Content-Length`, попадает в отчёт с указанием источника и времени проверки.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| googler | `googler -n 50 "dork"` | скриптуемый поиск Google |
| pagodo | `pagodo.py -g dorks.txt -d example.com` | прогон GHDB |
| httpx | `httpx -mc 200 -title` | валидация URL |
| jq | `jq -r '.[].url'` | разбор JSON-вывода |
| SerpAPI/Bing API | REST | массовый поиск без бана |

## Частые ошибки

- Перебор одного и того же дорка после бана — бессмысленно, меняйте движок/API.
- Игнорирование персонализации → разные результаты у вас и у коллеги.
- Доверие результату без проверки доступности.
- Открытие скачанного файла на рабочей машине.
- Забыть про robots.txt/лимиты — вы просто получите 429.
- Копировать GHDB-дорки без адаптации: чужой дорк под вашу цель почти всегда даёт мусор.

## Что делать дальше / решение

- **Нужны утечки и конфиги** → `site:` + `filetype:` + `intext:` по бренду, затем `httpx` для валидации.
- **Нужны панели** → `intitle:` по списку продуктов из `osint-shodan-dorks`.
- **Нужен масштаб** → Pagodo/SerpAPI + дедупликация в CSV.
- **Нужна приватность** → Searx/Startpage или прокси-ротация.

## Дорки для поиска утечек и учётных данных

Отдельная категория — поиск утёкших секретов, которые поисковик успел проиндексировать:

```
site:example.com filetype:env "DB_"
site:example.com filetype:json "private_key"
site:example.com intext:"Authorization: Bearer"
site:example.com filetype:sql "INSERT INTO users"
site:pastebin.com "example.com" password
```

Правило гигиены: найденный файл **не открывайте** на рабочей машине и не скачивайте без нужды — достаточно `curl -sI` и чтения первых строк через `curl -s ... | head`. Если программа bug bounty запрещает выгрузку ПДн, ограничьтесь доказательством существования (URL + код ответа + размер).

## Обход блокировок выдачи и анти-бот

Поисковики режут автоматизацию. Приёмы, которые продлевают жизнь дорку:

- **Разные движки**: Google → Bing → Yandex → DuckDuckGo (разные индексы, разные лимиты).
- **Паузы и джиттер**: `sleep $((RANDOM%10+5))` между запросами.
- **Ротация User-Agent и прокси** — но не для целевого сайта, а для поисковика.
- **Официальные API** (SerpAPI, Bing Web Search, Yandex XML) вместо скрейпинга.
- **Приватные фронтенды** (Searx) — меньше CAPTCHA при малых объёмах.

## Нормализация и дедупликация результатов

Сырой вывод дорков — это сотни URL с мусором. Приводите к таблице:

```bash
googler --json -n 50 "$dork" | jq -r '.[] | [.url,.title] | @tsv' >> raw.tsv
sort -u raw.tsv | cut -f1 | sed -E 's#(https?://[^/]+).*#\1#' | sort | uniq -c | sort -rn
```

Так вы видите, какие хосты дали больше всего результатов (часто это «хаб» — форум, CDN или база утечек), и приоритизируете проверку.

## Чек-лист доркинга по цели

Последовательность, которая стабильно даёт результат:

1. **Соберите входные данные**: бренд, основной домен, известные поддомены, имена сотрудников.
2. **Базовые операторы**: `site:` + `filetype:` + `intitle:` по каждому поддомену.
3. **GHDB-категории**: пароли/ключи, открытые каталоги, логи, панели.
4. **Платформенные дорки**: GitHub, Pastebin, Shodan (по баннерам).
5. **Валидация**: `httpx -mc 200 -title` по всем URL, отсеять заглушки.
6. **Фиксация**: URL, источник, дата, статус доступности.

Одна строка «всё сразу» для быстрого старта:

```bash
for d in \
 'site:example.com filetype:env' \
 'site:example.com intitle:"index of"' \
 'site:example.com inurl:.git' ; do
  googler --json -n 30 "$d" | jq -r '.[].url'
  sleep 7
done | sort -u | httpx -silent -mc 200 -title
```

## Специфика Yandex и Рунета

Для русскоязычных целей Yandex часто богаче Google:

- `mime:` вместо `filetype:` — `site:example.com mime:xlsx`.
- `title:` / `url:` — прямые аналоги `intitle:`/`inurl:`.
- `rhost:` — обратные ссылки на домен (аналог устаревшего `link:`).
- `date:` и региональные фильтры дают точную сортировку по свежести.
- Индекс Yandex лучше покрывает VK, объявления, локальные форумы.

```text
site:example.com mime:doc "приказ"
site:example.com title:admin
rhost:example.com -site:example.com
```

Держите оба движка: Google найдёт англоязычные утечки и GitHub, Yandex — локальные документы и объявления.

## Форматы утечек и что в них искать

Разные типы файлов несут разные секреты — знайте, что искать внутри:

| Формат | Что внутри | Дорк-намёк |
|---|---|---|
| `.env` | пароли БД, API-ключи | `filetype:env DB_PASSWORD` |
| `.json` | конфиги сервисов, токены | `filetype:json "token"` |
| `.yml` | CI/CD, секреты деплоя | `filetype:yml "password"` |
| `.sql` | дампы БД с хэшами | `filetype:sql "INSERT INTO"` |
| `.pem`/`.key` | приватные ключи | `filetype:pem "PRIVATE KEY"` |
| `.log` | пути, учётки, ошибки | `filetype:log inurl:error` |

Найдя файл, извлеките только доказательство (ключ/строка), не выгружая весь дамп.

## Квиз

```quiz
- question: "Что делает оператор `AROUND(3)`?"
  options:
    - "Ищет два слова в пределах трёх слов друг от друга"
    - "Ищет три страницы с этим словом"
    - "Ограничивает глубину поиска тремя уровнями"
    - "Повторяет запрос три раза"
  answer: 0
- question: "Какой оператор Bing ищет страницы по IP-адресу?"
  options:
    - "`ip:`"
    - "`addr:`"
    - "`site:`"
    - "`host:`"
  answer: 0
- question: "Что такое GHDB?"
  options:
    - "Google Hacking Database — каталог готовых дорков по категориям"
    - "Протокол обмена данными Google"
    - "База уязвимостей CVE"
    - "Инструмент сканирования портов"
  answer: 0
- question: "Почему результат дорка нужно проверять через `curl -I`?"
  options:
    - "Индексирование и доступность — разные вещи; страница может уже быть закрыта"
    - "Чтобы узнать пароль"
    - "Чтобы получить HTML"
    - "Это не нужно, дорк всегда точен"
  answer: 0
- question: "Что правильно при автоматизации доркинга?"
  options:
    - "Использовать API или паузы, чтобы не получить бан"
    - "Слать запросы максимально быстро"
    - "Игнорировать лимиты"
    - "Всегда использовать один User-Agent"
  answer: 0
```

## Где пригодится

- **Bug bounty**: массовый поиск утечек, панелей и открытых конфигов по домену.
- **CTF (OSINT)**: точный поиск скрытой страницы по подсказке.
- **Пентест**: быстрый снимок публичной поверхности до сканирования.
- **Threat intel**: поиск упоминаний бренда и утёкших данных в открытом вебе.
