---
id: osint-email-enum
title: "Email-разведка: holehe, GHunt и поиск аккаунтов по почте"
category: osint
parent: osint-email-osint
difficulty: medium
order: 1
tags: [osint, email, holehe, ghunt, accounts, enumeration]
prerequisites: [osint-people-search]
useful_for:
  - "CTF категория OSINT"
  - "Расследования и деанон"
  - "Bug bounty"
estimated_minutes: 30
summary: "Email как ключ к аккаунтам: поиск регистраций через holehe, извлечение данных Google-аккаунта через GHunt, проверка утечек и построение профиля."
---
Email-адрес — самый распространённый идентификатор в интернете. Он привязан к десяткам сервисов, и многие сервисы при регистрации или восстановлении пароля **раскрывают сам факт существования аккаунта** с этим адресом. Инструменты email-разведки автоматизируют эту проверку: по одному адресу вы получаете список сервисов, где человек зарегистрирован, а иногда — и его публичный профиль. Это законно (проверяются публичные ответы), но требует этической аккуратности.

## Теория: почему email так ценен

Email — «якорь» цифровой личности. Причины:
- **Уникальность.** В отличие от ника, email обычно один на человека.
- **Повторное использование.** Люди регистрируются одним адресом везде.
- **Привязка к восстановлению.** Многие аккаунты привязаны к почте как к «корню».
- **Формат сам по себе информативен.** `ivan.petrov@corp.com` раскрывает имя и компанию.

Типы проверок:
1. **«Забыли пароль»** — сервис отвечает «письмо отправлено» или «нет аккаунта» (уязвимость — user enumeration).
2. **Проверка регистрации при вводе** — форма регистрации говорит «email занят».
3. **Публичный профиль** — Google, Gravatar, некоторые соцсети отдают данные по email.
4. **Утечки** — адрес встречается в базах (см. `osint-breach-data`).

## holehe: регистрация в сотнях сервисов

`holehe` проверяет, зарегистрирован ли email в 100+ сервисах, используя их публичные эндпоинты восстановления пароля и регистрации.

Установка:

```bash
pipx install holehe
# или
pip install holehe
```

Базовый прогон:

```bash
holehe target@example.com
```

Вывод (сокращённо):

```
[+] github.com
[+] instagram.com
[+] twitter.com
[-] facebook.com
[-] snapchat.com
[+] spotify.com
[+] pinterest.com
[+] tumblr.com
[+] adobe.com
[!] 34/121 services checked
```

`[+]` — зарегистрирован, `[-]` — нет, `[!]` — ошибка проверки. Полезные флаги:

```bash
holehe --only-used target@example.com     # показать только найденные
holehe -NP target@example.com             # без проверки паролей (быстрее/тише)
holehe --no-color target@example.com
```

Важно: `holehe` отправляет запросы к сервисам от вашего имени — это **активная** разведка (сервисы видят запросы с вашего IP). Для OPSEC используйте прокси (`--proxy`).

## GHunt: данные Google-аккаунта

`GHunt` извлекает из Google-аккаунта: имя, фото, ID, дату создания, отзывы на картах, публичные YouTube-каналы, иногда сервисные данные. Это один из самых мощных email-инструментов.

Установка и авторизация (нужен `cookies` от Google-аккаунта-наблюдателя):

```bash
pipx install ghunt
ghunt login       # интерактивно: указать cookies или использовать base64
```

Использование:

```bash
ghunt email target@gmail.com
```

Вывод:

```
Name: Ivan Petrov
Profile picture: https://lh3.googleusercontent.com/...
Gaia ID: 123456789012345678901
Account creation date: 2015-03-12
Maps reviews: 12
  - Café Pushkin (5 stars)
YouTube channel: @ivanpetrov (UC...)
```

Из этого — Gaia ID (стабильный идентификатор Google), дата создания (коррелируется с возрастом/активностью), отзывы на картах (геолокация!). Модули GHunt:

```bash
ghunt email target@gmail.com      # профиль
ghunt gaia 123456789012345678901  # по Gaia ID
ghunt drive <file-url>            # метаданные публичного файла Drive
```

`ghunt drive` по публичной ссылке Google Drive вытаскивает email владельца и время создания — ценнейший pivot.

## Другие инструменты email-разведки

| Инструмент | Что делает |
|-----------|-----------|
| `holehe` | регистрации в 100+ сервисах |
| `GHunt` | данные Google-аккаунта |
| `h8mail` | email + утечки + проверка |
| `emailrep.io` | репутация адреса (API) |
| `theHarvester` | email из поисковиков и доменов |
| `Epieos` | веб-сервис (Google/Outlook-аккаунты) |
| `Mailcat` | регистрации через SMTP-проверку |

`theHarvester` для сбора адресов компании:

```bash
theHarvester -d example.com -b google,bing,linkedin -l 500 -f out.html
```

## Разобранный пример: от одного email к профилю

Дано: `i.petrov@example.com`.

Шаг 1 — регистрации:

```bash
holehe --only-used i.petrov@example.com
# [+] github.com
# [+] twitter.com
# [+] spotify.com
# [+] adobe.com
```

Шаг 2 — формат адреса даёт имя (`i.petrov` → Иван Петров) и домен (`example.com`).

Шаг 3 — GitHub-профиль по найденному адресу:

```bash
curl -s "https://api.github.com/search/users?q=i.petrov+in:email" | python3 -m json.tool | grep login
# "login": "ipetrov-dev"
```

Шаг 4 — репозитории и коммиты:

```bash
curl -s "https://api.github.com/users/ipetrov-dev" | python3 -m json.tool | grep -E 'name|company|blog|location'
```

Вывод: имя, компания `example.com`, блог, локация. Теперь у нас связаны: email → GitHub → имя → компания → соцсети. Это и есть цепочка email-разведки.

## Утечки: h8mail и проверка

Проверка адреса в известных утечках:

```bash
h8mail -t i.petrov@example.com
# [>] HIBP: FOUND in 3 breaches (LinkedIn 2021, Adobe 2013, ...)
```

Для массовой проверки домена:

```bash
h8mail -t "@example.com" -c config.ini
```

Пароли из утечек — сильный pivot: их повторное использование проверяется (только в рамках авторизации!) через `cred_spray`-логику. Но помните: проверять чужие пароли на чужих сервисах без разрешения — нелегально.

## Таблица: что можно извлечь из email

| Проверка | Инструмент | Результат |
|----------|-----------|-----------|
| Регистрации | holehe | список сервисов |
| Google-профиль | GHunt | имя, ID, дата, отзывы |
| Утечки | h8mail/HIBP | бреши, пароли |
| Email компании | theHarvester | список адресов |
| Репутация | emailrep.io | возраст, риск |
| Формат | (вручную) | имя, домен, паттерн |

## Ошибки и подводные камни

- **Путать активную и пассивную проверку.** holehe/Epieos шлют запросы сервисам — это активная разведка с вашего IP.
- **Слепо доверять `[+]`.** Ложные срабатывания бывают (сервис всегда отвечает «занято»).
- **Забывать про OPSEC.** GHunt требует аккаунта-наблюдателя; не используйте личный.
- **Игнорировать корпоративные адреса.** `@corp.com` может быть catch-all: любой адрес «существует».
- **Считать email доказательством личности.** Один адрес может использоваться несколькими людьми.
- **Проверять пароли из утечек без разрешения.** Это переход к активной атаке — только в рамках engagement.

## Что дальше / решение

Email-разведка даёт входной идентификатор и первые аккаунты. Дальше: **people-агрегаторы** (`osint-people-aggregators`) для публичных данных (адрес, телефон), **разрешение идентичностей** (`osint-identity-resolution`) для связывания всего в граф, и **breach-data** (`osint-breach-data`) для проверки утечек. Итог: из одной почты вы строите профиль с аккаунтами, именем, компанией и, возможно, геолокацией — и всё это до активной атаки.

## Gravatar и avatar-хаши

Gravatar привязывает аватар к md5(email). Это мгновенный pivot:

```bash
EMAIL="target@example.com"
HASH=$(printf '%s' "$EMAIL" | tr 'A-Z' 'a-z' | md5sum | cut -d' ' -f1)
echo "https://www.gravatar.com/avatar/$HASH"
curl -s "https://gravatar.com/$HASH.json" | python3 -m json.tool
```

Ответ JSON содержит профиль: имя, сайт, аккаунты, иногда другие email. Профиль Gravatar — частый источник флага в CTF и реальных pivot.

## Массовый сбор адресов компании

Для домена компании собираем адреса из нескольких источников:

```bash
theHarvester -d example.com -b google,bing,linkedin,duckduckgo -l 1000 -f out
cat out.json | jq -r '.emails[]' | sort -u > emails.txt
```

Дополняем паттернами: если известен формат (`i.petrov@`, `ivan.petrov@`), генерируем кандидатов по списку имён из LinkedIn:

```bash
# пример генерации по шаблону first.last
while read -r fn ln; do echo "${fn}.${ln}@example.com"; done < names.txt > guesses.txt
# проверка catch-all
for e in $(head -5 guesses.txt); do echo -n "$e "; dig +short MX example.com | head -1; done
```

## Проверка catch-all и MX

Прежде чем проверять существование адресов, определите, не catch-all ли домен:

```bash
dig +short MX example.com
# SMTP-хендшейк и проверка случайного адреса
swaks --to randomnonexist1234@example.com --server mx.example.com --quit-after RCPT
```

Если случайный адрес «принимается» — домен catch-all, и проверка отдельных адресов бессмысленна.

## Безопасность и rate limit

- Инструменты шлют много запросов — сервисы могут блокировать ваш IP.
- Используйте прокси и задержки (`--proxy`, `-t`).
- Не проверяйте пароли из утечек вне авторизации.
- Логируйте свои запросы — для отчётности и OPSEC.

## Сервисы проверки аккаунтов

Помимо CLI, есть веб-сервисы для быстрой проверки:
- **Epieos** (`epieos.com`) — Google/Outlook-аккаунты по email.
- **Holehe-web** — фронтенд к holehe.
- **Have I Been Pwned** — утечки.
- **Hunter.io** — корпоративные адреса по домену.

Hunter.io особенно полезен для домена компании:

```bash
curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=$KEY" \
  | python3 -m json.tool | grep -E 'value|first_name|last_name|position'
```

Возвращает формат адресов (`{first}.{last}@`) и должности — основа для построения списка сотрудников.

## Сводный чек-лист email-разведки

| Шаг | Инструмент | Результат |
|-----|-----------|-----------|
| Регистрации | holehe | список сервисов |
| Google | GHunt | имя, ID, отзывы |
| Gravatar | md5 + gravatar | профиль, аватар |
| Домен | theHarvester/Hunter | адреса компании |
| Утечки | h8mail/HIBP | бреши |
| Формат | вручную | паттерн имён |

Пройдя этот чек-лист, вы получаете максимум из одного адреса.

## Квиз

```quiz
- question: "На чём основан механизм проверки регистраций в holehe?"
  options:
    - "На взломе сервисов"
    - "На публичных эндпоинтах регистрации/восстановления пароля"
    - "На DNS-запросах"
    - "На Shodan"
  answer: 1
- question: "Что даёт GHunt по email?"
  options:
    - "Только пароль"
    - "Имя, Gaia ID, дату создания, отзывы, YouTube-канал"
    - "Список портов"
    - "DNS-зону"
  answer: 1
- question: "Какой из инструментов шлёт запросы к сервисам от вашего IP (активная разведка)?"
  options:
    - "crt.sh"
    - "holehe"
    - "Wayback Machine"
    - "dig"
  answer: 1
- question: "Что даёт команда `ghunt drive <url>`?"
  options:
    - "Скачивает файл"
    - "Извлекает email владельца публичного файла Drive"
    - "Меняет права доступа"
    - "Удаляет файл"
  answer: 1
- question: "Почему корпоративный адрес `@corp.com` может вводить в заблуждение?"
  options:
    - "Он всегда неверный"
    - "Домен может быть catch-all — любой адрес «существует»"
    - "Он не имеет MX"
    - "Он зашифрован"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** по email найти аккаунт, а в нём — флаг/подсказку.
- **Расследования:** связать адрес с реальным человеком и компанией.
- **Bug bounty:** найти корпоративные адреса сотрудников для оценки фишингоустойчивости.
- **Пентест:** собрать список адресов для последующей (авторизованной) проверки.
- **Threat intelligence:** атрибуция аккаунтов по email-паттернам.
