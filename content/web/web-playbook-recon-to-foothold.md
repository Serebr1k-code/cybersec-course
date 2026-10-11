---
id: web-playbook-recon-to-foothold
title: "Плейбук: от URL до первого foothold"
category: web
parent: web-playbooks-recon
difficulty: medium
order: 1
tags: [playbook, recon, discovery, triage, foothold, decision-tree, web]
prerequisites: [web-tooling, web-recon-surface, web-tool-curl]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 34
summary: "Decision-tree от «у меня есть URL» до первого подтверждённого вектора: фингерпринт → контент → параметры → триаж → выбор эксплойта, с командами на каждом узле."
---

У вас есть только URL цели (или её IP). Дальше — самый неопределённый этап: непонятно, за что взяться. Этот плейбук превращает «непонятно» в **последовательность проверок с условиями**: на каждом шаге вы получаете факт, который либо ведёт вниз по дереву, либо закрывает ветку. Цель — довести дело до **первого подтверждённого вектора**, а не до «я посмотрел сайт и ушёл».

## Дерево решения (общая карта)

```
[URL цели]
   │
   ├─(0) ПОДГОТОВКА: scope, прокси, куки, словари
   │
   ├─(1) ФИНГЕРПРИНТ ──► стек, версия, заголовки, cookies
   │      │
   │      ├─ узнал CMS/фреймворк/версию ──► ищи известные CVE (nuclei)
   │      └─ кастомное приложение ──► иди в (2)
   │
   ├─(2) CONTENT DISCOVERY ──► скрытые пути, бэкапы, .git, API-доки
   │      │
   │      ├─ нашёл /admin, /api, /backup, .git ──► триаж ветки (5)
   │      └─ пусто ──► смотри JS, robots.txt, sitemap, иди в (3)
   │
   ├─(3) PARAMETER DISCOVERY ──► какие входы вообще есть
   │      │
   │      └─ собрал список параметров ──► иди в (4)
   │
   ├─(4) VULN TRIAGE ──► что реагирует: ошибка/эхо/задержка/ID
   │      │
   │      └─ есть подозрение на класс ──► CONFIRM одной командой
   │
   └─(5) EXPLOIT SELECTION ──► выбрать класс и инструмент
          │
          └─► подтверждённый вектор ──► [FOOTHOLD]
```

## Шаг 0. Подготовка: scope, прокси, словари

Прежде чем слать запросы — зафиксируйте рамки и настройте канал.

```bash
# Кто отвечает, куда редиректит, что за сертификат
curl -sS -k -D- -o /dev/null https://target.tld | head -30

# Через прокси (Burp) — чтобы всё шло в историю и можно было повторять
curl -sS -k -x http://127.0.0.1:8080 https://target.tld -o /dev/null -w '%{http_code}\n'

# Единый словарь путей (seclists) — не изобретайте свой на каждый хост
ls /usr/share/seclists/Discovery/Web-Content/ | head
```

**Условие ветвления:** если хост отдаёт `403` на всё — попробуйте `--path-as-is`, `-H 'X-Forwarded-For: 127.0.0.1'`, разные методы; если редиректит на SSO — зафиксируйте этот факт, авторизацию добавите позже.

**Тупик:** не начинайте с полного `-p-` портскана, если у вас один веб-хост. Это шумно и редко даёт foothold раньше, чем контент-разведка.

## Шаг 1. Фингерпринт: что это за приложение

Нужно понять стек и версию — от этого зависит, искать CVE или копать логику.

```bash
# Паспорт хоста: статус, заголовки, титул, технологии, TLS
httpx -u https://target.tld -title -status-code -tech-detect -server -td -sc -json -o httpx.json

# Заголовки и cookie вручную
curl -sSI https://target.tld

# Что за веб-сервер и язык (по ошибкам, расширениям, кукам)
whatweb -a 3 https://target.tld

# Быстрый шаблонный скан известных CVE/мисконфигов
nuclei -u https://target.tld -severity critical,high,medium -silent -j -o nuclei.json
```

На что смотреть в ответе:

| Признак | Что значит | Куда идти |
|---------|-----------|-----------|
| `X-Powered-By: PHP/8.1` | PHP-стек | LFI/RCE-ветки, `web-playbook-file-to-rce` |
| `Server: nginx` + `Set-Cookie: ...` | кастомное приложение | контент-разведка (шаг 2) |
| `wp-content`, `drupal`, `_next` | известная CMS/фреймворк | CVE по версии, `nuclei -tags <product>` |
| `graphql`, `/api/v1` | API | `web-playbook-injection-triage`, API-ветка |
| `WWW-Authenticate: Basic` | базовая аутентификация | `web-playbook-auth-bypass` |

**Условие ветвления:** узнали точную версию продукта → ищите её CVE (не grep'ом по именам шаблонов, а по `-tags`/CVE-id). Не узнали — идите в контент.

## Шаг 2. Content discovery: что спрятано

Перебираем пути и файлы. Только после быстрого фингерпринта — иначе будете фаззить вслепую.

```bash
# Директории и файлы (ffuf)
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -c

# Расширения
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u https://target.tld/FUZZ -e .php,.bak,.old,.zip,.tar.gz,.env,.sql -ac

# Специфично для веба: доки, бэкапы, VCS, конфиги
for p in .git/config .env backup.zip swagger.json openapi.json api-docs \
         robots.txt sitemap.xml .well-known/security.txt; do
  curl -s -o /dev/null -w "%{http_code} $p\n" https://target.tld/$p
done
```

**Условие ветвления:**
- `/.git/` открыт → дампните репозиторий (`git-dumper`) → исходники = точные баги.
- `/swagger.json`, `/openapi.json`, `/api-docs` → у вас полная карта API → шаг 3.
- `/backup.zip`, `*.bak`, `*.old` → скачивайте и читайте исходники/конфиги.
- `/admin`, `/manager`, `/console` → `web-playbook-auth-bypass`.

**Тупик:** 404 на всё и нет редиректов — не перебирайте ещё пять словарей. Переходите к разбору JS: там реальные эндпоинты приложения.

## Шаг 3. Parameter discovery: какие входы есть

Приложение может иметь десятки скрытых параметров. Их находят в JS, в HTML и фаззингом.

```bash
# Вытащить все URL и параметры из фронтенд-JS
cat $(curl -s https://target.tld | grep -oE '/static/[^"]+\.js') 2>/dev/null \
  | grep -oE '(/api/[a-zA-Z0-9_/]+|\?[a-zA-Z0-9_]+=)' | sort -u

# Скроить параметры на известном эндпоинте
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u 'https://target.tld/search?FUZZ=test' -fs 0 -ac -c

# Проверить методы и заголовки
for m in GET POST PUT PATCH DELETE OPTIONS; do
  curl -s -o /dev/null -w "$m %{http_code}\n" -X $m https://target.tld/api/user
done
```

**Условие ветвления:** если в JS нашлись пути вида `/api/v1/...` — это API, идите в ветку BOLA/IDOR и инъекций. Если параметр числовой (`id=123`) — сразу триаж на IDOR и SQLi.

## Шаг 4. Vuln triage: что реагирует

Теперь на каждый параметр — быстрая проверка класса. Не пишите payload'ы руками по одному — прогоните набор и смотрите на **отклонения** (ошибка, эхо, задержка, другой размер ответа).

```bash
# Базовый ответ — точка отсчёта
curl -s -o /dev/null -w 'size=%{size_download} time=%{time_total}\n' 'https://target.tld/search?q=test'

# Ошибки БД/шаблонов/фреймворка — одиночная кавычка и фигурные скобки
for p in "'" '"' '{{7*7}}' '${7*7}' '%00' '..%2f'; do
  curl -s -o /dev/null -w "payload=$p code=%{http_code} size=%{size_download}\n" \
    --get --data-urlencode "q=$p" https://target.tld/search
done

# Время: если ответ «завис» — возможен time-based
time curl -s -o /dev/null 'https://target.tld/search?q=test%27%20AND%20SLEEP(5)--%20-'
```

Матрица триажа:

| Реакция на payload | Вероятный класс | Следующий шаг |
|--------------------|-----------------|---------------|
| Ошибка SQL (`You have an error in your SQL syntax`) | SQLi | `web-playbook-injection-triage` |
| `49` в ответе на `{{7*7}}` | SSTI | `web-ssti`, tplmap |
| Содержимое `/etc/passwd` | LFI | `web-playbook-file-to-rce` |
| Ответ задержался ровно на N сек | time-based SQLi | `web-playbook-injection-triage` |
| Данные другого пользователя по смене `id` | IDOR | `web-playbook-auth-bypass` |
| Заголовок `Location:` на ваш хост | open redirect / SSRF | `web-playbook-ssrf-to-internal` |
| Ошибка «template not found», «no such file» | path traversal | `web-playbook-file-to-rce` |

**Условие ветвления:** реакция есть → CONFIRM одной командой (шаг 5). Реакции нет ни на что → вернитесь к шагу 2/3, вы не нашли нужный вход.

## Шаг 5. Exploit selection: выбрать класс и подтвердить

Доведите подозрение до воспроизводимого PoC. Дальше — профильный плейбук.

```bash
# Пример: подтверждение SQLi (руками, до sqlmap)
curl -s 'https://target.tld/item?id=1%20AND%201=1' | wc -c
curl -s 'https://target.tld/item?id=1%20AND%201=2' | wc -c   # разный размер = boolean SQLi

# Пример: подтверждение IDOR
curl -s -b "session=$TOKEN" 'https://target.tld/api/orders/1001' | jq .user_id
curl -s -b "session=$TOKEN" 'https://target.tld/api/orders/1002' | jq .user_id  # чужой?

# Пример: подтверждение SSTI
curl -s --get --data-urlencode 'name={{7*7}}' 'https://target.tld/greet' | grep -o '49'
```

Дальше по классу:

- SQLi / NoSQLi / LDAP / XPath → `web-playbook-injection-triage`
- логин, токены, IDOR, админка → `web-playbook-auth-bypass`
- upload / LFI / traversal → `web-playbook-file-to-rce`
- сервер ходит по вашему URL → `web-playbook-ssrf-to-internal`

## Если не сработало — пробуй это

- **Ничего не находится.** Возьмите JS-бандлы и `robots.txt`/`sitemap.xml` — реальные пути там. Прогоните `katana` для краулинга и сравните с ffuf.
- **Всё за 401/403.** Ищите обход: `--path-as-is`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, смена метода, `?debug=1`, case-варианты (`/ADMIN`).
- **Есть WAF, блокирует payload'ы.** Кодируйте: двойное URL-encoding, `%27` vs `'`, Unicode-нормализация, смена Content-Type.
- **Параметр игнорируется.** Проверьте, что он вообще доходит: `X-Forwarded-Host`, HPP (`?q=a&q=b`), JSON-вложенность, multipart.
- **Фреймворк без версии.** Определите по ошибкам/кукам/структуре (`_next`, `X-Runtime`, `django`, `PHPSESSID`) и ищите CVE для рантайма, а не приложения.

## Тупики (dead ends)

- Полный портскан одного веб-хоста «на всякий случай» — редко окупается против контент-разведки.
- Перебор пяти словарей подряд, когда 404 у всех — сначала JS/robots/sitemap.
- Ручной перебор payload'ов в браузере без сохранения запроса — вы не сможете воспроизвести PoC.
- Запуск тяжёлого `sqlmap -r` на каждый параметр «на удачу» — сначала дешёвый триаж, потом автоматика.
- Вывод «сайт безопасен» после одного скана без ручной проверки — отсутствие находки ≠ отсутствие уязвимости.

## Квиз

```quiz
- question: "Что делать СРАЗУ после того, как фингерпринт показал точную версию CMS?"
  options:
    - "Запускать полный брутфорс путей"
    - "Искать CVE именно для этой версии (nuclei -tags/CVE-id)"
    - "Пробовать SSRF"
    - "Менять User-Agent"
  answer: 1
  explanation: "Точная версия — самый дешёвый путь к известной уязвимости; ищите её CVE."
- question: "Открылся /.git/. Что это даёт?"
  options:
    - "Ничего, это просто служебная папка"
    - "Исходный код и историю — то есть точные баги, а не догадки"
    - "Только README"
    - "Только версию сервера"
  answer: 1
  explanation: "Дамп .git возвращает исходники — по ним видны реальные уязвимости."
- question: "Ответ на ' завис на 5 секунд, а на обычный ввод — мгновенный. Что это?"
  options:
    - "Сетевой лаг"
    - "Признак time-based SQL-инъекции"
    - "SSTI"
    - "XSS"
  answer: 1
  explanation: "Контролируемая задержка от payload — классический признак time-based SQLi."
- question: "Что превращает подозрение сканера в подтверждённую находку?"
  options:
    - "Скриншот сканера"
    - "Воспроизведение вручную (curl/PoC) с доказательством"
    - "Ещё один сканер"
    - "Пометка 'возможно'"
  answer: 1
  explanation: "Находка подтверждается только воспроизведением с конкретным доказательством."
- question: "Параметр, похоже, игнорируется. Что проверить в первую очередь?"
  options:
    - "Ничего, значит его нет"
    - "Доходит ли он вообще (метод, кодировка, HPP, Content-Type)"
    - "Сменить браузер"
    - "Перезагрузить сервер"
  answer: 1
  explanation: "Сначала убедитесь, что значение реально доходит до обработчика (метод/кодировка/дублирование)."
```

## Где пригодится

- **CTF (Web):** быстрый и дисциплинированный путь от URL к первому вектору под таймером.
- **Bug bounty:** порядок «дешёвое → дорогое» окупается на широком scope.
- **Пентест:** каждый шаг даёт артефакт (команда + ответ), из которого собирается отчёт.
- **Работа (AppSec):** понимание типичных входов помогает строить чек-листы и защиту.
