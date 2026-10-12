---
id: web-tool-burp-zap
title: "Burp Suite и OWASP ZAP: полный практический справочник"
category: web
parent: web-tools-exploit
difficulty: medium
order: 1
tags: [burp, zap, proxy, repeater, intruder, scanner, extensions]
prerequisites: [web-tooling]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Прокси, Repeater, Intruder, Decoder, Scanner, расширения, макросы и session handling — с точными настройками и рецептами."
---

## Задача

Мы нашли эндпоинт `https://shop.acme-lab.test/api/users?id=1` и форму логина с CSRF-токеном. Автоматические сканеры тут бесполезны: чтобы проверить IDOR, надо менять `id` и **сравнивать** ответы, а чтобы перебрать форму — обновлять одноразовый токен. Для этого нужен перехватывающий прокси: **Burp Suite** или **OWASP ZAP**.

Этот урок — практический справочник: настроить прокси, воспроизвести запрос, проверить авторизацию и автоматизировать обход CSRF.

## Данные, с которыми работаем

- Браузер и цель `https://shop.acme-lab.test`.
- Запрос `GET /api/users?id=1` (проверка IDOR).
- Форма `POST /login` с полем `csrf_token`.

## Шаг 1: прокси, сертификат, scope

1. **Proxy → Options:** listener `127.0.0.1:8080` (по умолчанию). Bind на `0.0.0.0` — только в изолированной лаборатории.
2. **Scope:** Target → Scope → добавь `shop.acme-lab.test` и поддомены. Intruder и Scanner уважают scope — не выйдешь за пределы цели.
3. **CA-сертификат:** с браузером через прокси открой `http://burp` → *CA Certificate* → скачай `cacert.der`. Импортируй в браузер. Для `curl` переведи в PEM:

```bash
$ openssl x509 -inform DER -in cacert.der -out cacert.pem
$ curl --proxy http://127.0.0.1:8080 --cacert cacert.pem https://shop.acme-lab.test/
```

Теперь весь трафик идёт через прокси и попадает в **HTTP history**.

## Шаг 2: Proxy и HTTP history → `Copy as cURL`

В **Proxy → HTTP history** видны все запросы. Правый клик по нужному → *Copy as curl command* — получаем воспроизводимый PoC:

```bash
$ curl -i -s -k -X POST 'https://shop.acme-lab.test/api/login' \
  -H 'Content-Type: application/json' \
  --data-binary '{"user":"admin","pass":"x"}'
```

Это самый быстрый способ перенести точный запрос в терминал. Здесь же — **Match and Replace** (Proxy → Options): автоподмена `User-Agent` или добавление `X-Forwarded-For: 127.0.0.1` во все запросы (обход IP-фильтров).

## Шаг 3: Repeater — проверить IDOR

Repeater — вкладка для итеративной правки одного запроса. Цикл: отправить запрос сюда, изменить **один** параметр, нажать *Send*, сравнить ответ.

Проверяем IDOR: меняем `id=1` на `id=2` и смотрим тело:

```http
GET /api/users?id=2 HTTP/2
Host: shop.acme-lab.test
Cookie: session=<наша сессия>

HTTP/2 200
{"id":2,"email":"bob@acme-lab.test","role":"user"}
```

Если в ответе чужие данные (`bob`) под нашей сессией — это IDOR. Так же проверяют SSTI: `name={{7*7}}` → появилось ли `49`.

## Шаг 4: Intruder — четыре типа атак

Intruder подставляет payload в помеченные позиции (`§param§`):

| Тип | Что делает | Когда |
|-----|-----------|-------|
| **Sniper** | по одной позиции за раз | один параметр, перебор значений |
| **Battering ram** | одно значение во все позиции | логин/пароль одинаковы |
| **Pitchfork** | параллельно по своему списку на позицию | user из A, pass из B попарно |
| **Cluster bomb** | декартово произведение | полный перебор user×pass |

Настройки, которые нужны: **Payloads → Payload type** (Simple list, Runtime file, Numbers, Brute forcer, Null payloads), **Payload processing** (add prefix/suffix, hash, URL-encode), **Grep — Match/Extract** (пометить ответы со строкой `Welcome`). **Resource pool** ограничивает потоки, чтобы не уронить цель.

> Community-Intruder искусственно замедлен. Для скорости — расширение **Turbo Intruder** или `ffuf` из CLI.

## Шаг 5: Decoder, Comparer, Sequencer

- **Decoder** — многослойное кодирование/декодирование (base64, URL, HTML, hex, gzip). Кнопка *Smart decode* определяет кодировку сама.
- **Comparer** — побайтовое/пословное сравнение двух ответов. Незаменим, когда «успех» и «провал» отличаются одним байтом.
- **Sequencer** — оценка энтропии токенов. Собери 100+ сэмплов session id → *Analyze now*. Низкая энтропия = предсказуемый токен.

## Шаг 6: Macros и session handling — обход CSRF

Проблема: в форме одноразовый `csrf_token`; при повторе он протухает. Решение — **macro**, который перед каждым запросом ходит за свежим токеном:

1. Settings → Sessions → Session Handling Rules → Add.
2. Rule Actions → Add → *Run a macro*.
3. Macro = `GET /login`, в нём через *Custom parameter locations* указан `csrf_token`.
4. Scope: правило применяется ко всем запросам в scope.
5. В целевом запросе токен подставляется автоматически.

Так же настраивается авто-логин: макрос `POST /login` обновляет cookie сессии перед запросами.

## Шаг 7: ключевые расширения (BApp Store)

| Расширение | Зачем |
|------------|-------|
| **Autorize** | автоповтор каждого запроса без cookie/с чужой сессией → IDOR/BOLA |
| **JWT Editor** | разбор и подделка JWT прямо в Burp |
| **Param Miner** | поиск скрытых параметров, заголовков, cache-ключей |
| **Turbo Intruder** | быстрый фаззинг и single-packet race |
| **Collaborator Everywhere** | инъекция OOB-payload в заголовки (SSRF/XXE вслепую) |
| **Logger++** | расширенный лог с фильтрами |
| **InQL** | GraphQL introspection и скрытые поля |
| **HTTP Request Smuggler** | детект request smuggling |

Установка: Extender → BApp Store → Install.

## ZAP: бесплатный активный сканер

ZAP — альтернатива, полностью бесплатная, с активным сканером и автоматизацией из CLI:

```bash
$ zap-baseline.py -t https://shop.acme-lab.test -r base.html     # пассивный
$ zap-full-scan.py -t https://shop.acme-lab.test -r full.html    # активный
$ zap.sh -cmd -quickurl https://shop.acme-lab.test -quickout out.xml
```

В GUI: Breakpoints (Ctrl+B) для перехвата, Fuzzer для фаззинга, **Ajax Spider** для JS-приложений.

## Полный прогон от начала до конца

1. Прокси + CA-сертификат → трафик в HTTP history.
2. Правый клик → *Copy as curl* → точный PoC в терминале.
3. Repeater: `id=1` → `id=2` → чужой объект (IDOR).
4. Autorize: повтор без cookie → видно, где нет проверки авторизации.
5. Macro: обход `csrf_token` для Intruder.
6. ZAP full-scan как стартовый фильтр.

## Если не сработало

- **Браузер ругается на сертификат.** Не импортирован CA Burp; скачай `cacert.der` и импортируй.
- **Запросы вне scope.** Проверь Target → Scope; Intruder игнорирует то, что вне scope.
- **Intruder слишком медленный.** Community throttled — бери Turbo Intruder или `ffuf`.
- **CSRF-токен протухает.** Настрой macro; без него все повторы отклоняются.
- **Сканер молчит.** Он не знает бизнес-логику и плохо ловит IDOR — проверяй руками (Autorize).

## Что мы теперь знаем

- Прокси перехватывает и повторяет любой запрос; *Copy as curl* делает PoC.
- Repeater — итеративная правка одного запроса; так проверяют IDOR и SSTI.
- Intruder — четыре типа атак (Sniper/Battering ram/Pitchfork/Cluster bomb).
- Macros + session handling обходят CSRF и делают авто-логин.
- Расширения (Autorize, Param Miner, Turbo Intruder) закрывают то, что Burp не умеет из коробки.
- ZAP — бесплатный активный сканер и автоматизация из CLI.

## На что смотреть дальше

- **Сканер — стартовый фильтр, не оракул.** Авторизационные баги (IDOR/BOLA) он почти не видит.
- **Match/Replace для заголовков.** `X-Forwarded-For`, `Client-IP` — классика обхода IP-ограничений.
- **Comparer для blind.** Разница true/false — часто единственный сигнал.
- **Collaborator для OOB.** Внешний DNS/HTTP-канал ловит blind SSRF/XXE/RCE.
- **DOM Invader.** Отдельный инструмент для DOM-XSS и prototype pollution.

## Квиз

Проверь себя.

```quiz
- question: "Какая вкладка Burp нужна для итеративной правки одного запроса и сравнения ответов?"
  options:
    - "Proxy"
    - "Repeater"
    - "Intruder"
    - "Decoder"
  answer: 1
  explanation: "Repeater — повтор одного запроса с правками; основной инструмент ручного PoC."
- question: "Какой тип атаки Intruder перебирает декартово произведение нескольких списков?"
  options:
    - "Sniper"
    - "Battering ram"
    - "Pitchfork"
    - "Cluster bomb"
  answer: 3
  explanation: "Cluster bomb — все комбинации; Pitchfork идёт параллельно попарно."
- question: "Для чего нужен macro в session handling?"
  options:
    - "Чтобы ускорить Intruder"
    - "Чтобы обновлять одноразовый CSRF-токен или сессию перед запросом"
    - "Чтобы кодировать payload"
    - "Чтобы сменить User-Agent"
  answer: 1
  explanation: "Макрос ходит за свежим токеном и подставляет его в целевой запрос."
- question: "Какое расширение автоматически повторяет запросы с чужой сессией для поиска IDOR?"
  options:
    - "Decoder"
    - "Autorize"
    - "Sequencer"
    - "Comparer"
  answer: 1
  explanation: "Autorize повторяет каждый запрос без cookie или с чужой сессией."
- question: "Чем ZAP отличается от Burp Community по активному сканированию?"
  options:
    - "У ZAP активный сканер бесплатный, у Burp Community — нет"
    - "У ZAP нет сканера"
    - "У Burp Community сканер быстрее"
    - "Разницы нет"
  answer: 0
  explanation: "ZAP даёт Active Scan бесплатно; Burp Community — только ручной тест."
```

## Куда дальше

Дальше (`web-tool-jwt-tools`) мы разберём инструменты для JWT — `jwt_tool` и JWT Editor в Burp. А пока главное запомни: прокси — это твоя «лаборатория на проводе»; без него проверка IDOR и обход CSRF превращаются в ручную возню с `curl`.

## Где пригодится

- **CTF (Web):** быстрый перехват и повтор запросов, проверка IDOR/SSTI.
- **Bug bounty:** воспроизводимый PoC через *Copy as curl* и точная фильтрация шума.
- **Пентест:** стандартный инструмент ручного теста; доказательства на каждом шаге.
- **Работа (AppSec):** настройка proxy в CI (ZAP) и автопроверки авторизации.
