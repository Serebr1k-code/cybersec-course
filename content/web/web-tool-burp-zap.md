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

Burp Suite и OWASP ZAP — два перехватывающих прокси, без которых ручной тест веб-приложения почти невозможен. Этот урок — практический справочник: как настроить, чем отличаются вкладки, какие расширения действительно нужны и как автоматизировать обход CSRF-токенов и авто-логин. Теории минимум — команды и настройки максимум.

## Шпаргалка: 10 самых частых действий

| Действие | Burp Suite | OWASP ZAP |
|----------|-----------|-----------|
| Включить/выключить перехват | `Proxy → Intercept → Intercept is on` | `Breakpoints → Set/Unset` (Ctrl+B) |
| Отправить запрос в Repeater | `Ctrl+R` (или правый клик → Send to Repeater) | `Ctrl+W` (Manual Request) |
| Отправить в Intruder/фаззер | `Ctrl+I` | выделить текст → правый клик → Fuzz |
| Задать scope | `Target → Scope → Add` | `Context → Include in Context` |
| Скачать CA-сертификат | открыть `http://burp` → CA Certificate | `Tools → Options → Dynamic SSL Certificates → Save` |
| Копировать запрос как curl | правый клик → Copy as curl command | правый клик → Copy as curl |
| Проверить авторизацию (IDOR) | расширение **Autorize** | скрипт/ручное сравнение сессий |
| Найти скрытые параметры | расширение **Param Miner** | фаззер со словарём |
| Разобрать/подделать JWT | расширение **JWT Editor** | вручную + jwt_tool |
| Активный скан | Pro: `Scanner`; Community — нет | `Attack → Active Scan` (бесплатно) |

## Чем Burp отличается от ZAP

| Возможность | Burp Suite (Community/Pro) | OWASP ZAP |
|-------------|----------------------------|-----------|
| Перехват и правка запросов | Intercept / Proxy | Breakpoints |
| Повтор запроса вручную | Repeater | Request Editor + Resend |
| Фаззинг параметров | Intruder (Community — медленный) | Fuzzer |
| Автоскан | Pro: Scanner; Community — только ручной | Active/Passive Scan (бесплатно) |
| Расширения | BApp Store (Java) | Add-ons (Marketplace, Java/Python/JS) |
| Автоматизация | Burp Extender API (Java/Python) | ZAP API + скрипты (Zest, JS, Python) |
| Цена | Community бесплатна, Pro платная | полностью бесплатный |
| Запуск из CLI/CI | headless через расширения | `zap.sh -cmd -quickurl ...` из коробки |

Практический вывод: **Burp** — стандарт ручного теста и расширений; **ZAP** — когда нужен бесплатный активный сканер и автоматизация в CI.

## Настройка Burp: proxy, сертификат, scope

1. **Proxy → Options:** listener `127.0.0.1:8080` (по умолчанию). Если нужен внешний доступ — bind на `0.0.0.0`, но только в изолированной лаборатории.
2. **Перехват только нужного:** Proxy → Intercept → *Intercept is on*; включите `Proxy → Options → Intercept Client Requests` и добавьте правило «не перехватывать вне scope».
3. **Scope:** Target → Scope → *Use advanced scope control* — добавьте `target.local` и его поддомены. Все инструменты (Intruder, Scanner) уважают scope.
4. **CA-сертификат:** с браузером через прокси откройте `http://burp` → *CA Certificate* → скачайте `cacert.der`. Для Firefox: Settings → Privacy → Certificates → View Certificates → Import. Для `curl`: `--cacert cacert.pem`.
5. **Экспорт сертификата в PEM:**

```bash
openssl x509 -inform DER -in cacert.der -out cacert.pem
curl --proxy http://127.0.0.1:8080 --cacert cacert.pem https://target.local/
```

6. **Hotkeys:** `Ctrl+R` — в Repeater, `Ctrl+I` — в Intruder, `Ctrl+Shift+B` — в Scanner (Pro).

## Proxy и HTTP history: перехват и фильтрация

- **Proxy → HTTP history** — все запросы; фильтруйте по scope, MIME, коду ответа, наличию параметров.
- Правый клик по запросу → *Send to Repeater* / *Send to Intruder* / *Do an active scan* (Pro) / *Copy as curl command*.
- **Copy as curl** — самый быстрый способ сделать воспроизводимый PoC:

```bash
curl -i -s -k -X POST 'https://target.local/api/login' \
  -H 'Content-Type: application/json' \
  --data-binary '{"user":"admin","pass":"x"}'
```

- **Match and Replace** (Proxy → Options): авто-подмена заголовков, например `User-Agent`, или добавление `X-Forwarded-For: 127.0.0.1` во все запросы — удобно для обхода IP-фильтров.

## Repeater: ручное воспроизведение

Repeater — вкладка для итеративной правки одного запроса. Типовой цикл:

1. Отправить запрос из history в Repeater.
2. Изменить один параметр → *Send* → сравнить ответ.
3. Нажать `Ctrl+Space` для вставки payload из списка, или использовать **Repeater tabs** для параллельных гипотез.
4. **Rendering** — вкладка для просмотра HTML без исполнения JS.

Рецепт: проверка IDOR — меняем `user_id=1` на `user_id=2` и сравниваем тела ответов. Рецепт: проверка SSTI — `name={{7*7}}`, смотрим, появилось ли `49`.

## Intruder: типы атак

Intruder подставляет payload в помеченные позиции (`§param§`). Четыре типа атаки:

| Тип | Что делает | Когда |
|-----|-----------|-------|
| **Sniper** | по одной позиции за раз, все payload | один параметр, перебор значений |
| **Battering ram** | один payload во все позиции одновременно | логин/пароль одинаковы |
| **Pitchfork** | параллельно по своему списку на позицию | user из A, pass из B, попарно |
| **Cluster bomb** | декартово произведение всех списков | полный перебор user×pass |

Настройки:

- **Payloads → Payload type:** Simple list (свой файл), Runtime file, Numbers, Brute forcer, Null payloads, Character blocks.
- **Payload processing:** правила (add prefix/suffix, hash, URL-encode, skip if matches regex).
- **Grep — Match / Extract:** отмечать ответы, содержащие строку (например `Welcome`), или извлекать regex.
- **Resource pool:** ограничивает число потоков — важно, чтобы не уронить цель и не словить бан.
- Community-версия Intruder **искусственно замедлена** (throttled). Для скорости — Turbo Intruder (см. ниже) или ffuf.

Пример: перебор ID через Sniper — позиция `id=§1§`, payload type Numbers от 1 до 1000, Grep-Match по строке `"email"`.

## Decoder, Comparer, Sequencer

- **Decoder** — многослойное кодирование/декодирование: base64, URL, HTML, hex, gzip, ASCII hex. Кнопка *Smart decode* определяет кодировку автоматически. Используйте для разбора токенов и payload.
- **Comparer** — побайтовое/пословное сравнение двух ответов; незаменим для поиска того самого байта, который меняется между «успех» и «провал».
- **Sequencer** — оценка энтропии токенов (session id, CSRF, reset-токен). Отправьте запрос с токеном, укажите позицию токена, соберите 100+ сэмплов → *Analyze now*. Низкая энтропия = предсказуемый токен.

## Scanner и его ограничения

- **Pro:** правый клик → *Scan* / *Do an active scan*; настраиваются scan configuration (audit checks), resource pool и scope.
- **Community:** активный сканер недоступен — только ручной тест и расширения.
- **ZAP:** активный сканер бесплатен — *Attack → Active Scan*, *Spider*, *Ajax Spider* (для JS-приложений).
- Ограничения обоих: сканер не знает бизнес-логику, плохо ловит авторизационные баги (IDOR, BOLA) и требует ручной верификации. Используйте сканер как **стартовый фильтр**, не как оракул.

## Extender и ключевые расширения (BApp Store)

| Расширение | Зачем |
|------------|-------|
| **Autorize** | автоповтор каждого запроса без cookie / с чужой сессией → детект авторизационных багов (IDOR/BOLA) |
| **JWT Editor** | разбор, правка, подпись/подделка JWT прямо в Burp |
| **Param Miner** | поиск скрытых параметров, заголовков, кэш-кэш-ключей |
| **Turbo Intruder** | сверхбыстрый фаззинг на Python-скриптах; single-packet race |
| **Logger++** | расширенный лог с фильтрами и grep |
| **Active Scan++** | дополнительные проверки к штатному сканеру |
| **Collaborator Everywhere** | инъекция Collaborator-пейлоадов в заголовки для поиска SSRF/XXE вслепую |
| **Backslash Powered Scanner** | эвристический поиск инъекций без готовых сигнатур |
| **Hackvertor** | тэги-преобразования (`<@base64>`, `<@urlencode>`, `<@unicode>`) прямо в запросе — обход фильтров |
| **Reflected Parameters** | подсветка параметров, отражённых в ответе (быстрый поиск XSS/redirect) |
| **Flow** | визуализация цепочек запросов и связей между эндпоинтами |
| **Bypass WAF** | автоматическая обфускация payload для обхода WAF |
| **JSON Web Tokens** | альтернатива JWT Editor для разбора/правки токенов |
| **InQL** | GraphQL introspection, генерация запросов и поиск скрытых полей |
| **Content Type Converter** | конвертация тела запроса между form/JSON/XML |
| **HTTP Request Smuggler** | детект request smuggling (CL.TE, TE.CL, TE.TE) |
| **AWS Signer** | переподпись запросов AWS SigV4 после правки |
| **CORS Raider / CORS Audit** | анализ и эксплуатация CORS-мисконфигураций |
| **Upload Scanner** | проверка загрузки файлов (типы, обход фильтров, RCE) |
| **Java Deserialization Scanner** | детект и эксплуатация Java-десериализации (ysoserial) |
| **GadgetProbe** | определение классов на classpath цели для подбора gadget-цепочки |

Установка: Extender → BApp Store → Install. Расширения на Python требуют Jython (Extender → Options → Python environment).

## Вкладки Burp: что делает каждая

| Вкладка | Назначение | Пример использования |
|---------|-----------|----------------------|
| **Target** | карта сайта, scope, история | задать scope, посмотреть дерево эндпоинтов |
| **Proxy** | перехват, HTTP history, match/replace | включить Intercept, отправить запрос в Repeater |
| **Intruder** | фаззинг/перебор по позициям | перебор `id=§1§`, brute force логина |
| **Repeater** | ручная правка и повтор одного запроса | проверить IDOR/SSTI итеративно |
| **Sequencer** | анализ энтропии токенов | оценить предсказуемость session id |
| **Decoder** | многослойное кодирование/декодирование | разобрать base64/hex/gzip payload |
| **Comparer** | сравнение двух ответов/запросов | найти отличающийся байт |
| **Extender** | установка расширений (BApp Store) | поставить Autorize, Turbo Intruder |
| **Scanner** (Pro) | активный/пассивный скан | Do an active scan по запросу |
| **Collaborator** (Pro) | OOB-детект (DNS/HTTP) | подтвердить blind SSRF/XXE |
| **Organizer** | хранение запросов/заметок | сохранить удачные payload'ы |
| **DOM Invader** | поиск DOM-XSS/prototype pollution | каналы postMessage, sinks |
| **Logger / Logger++** | расширенный лог всех запросов | grep по всему трафику |
| **Learn** | авто-сбор кандидатов на параметры | обучить Burp параметрам цели |

## Intruder: позиции, payload-типы, обработка

**Типы атак** — см. таблицу ниже (Sniper/Battering ram/Pitchfork/Cluster bomb).

**Payload type (Payloads → Payload type):**

| Payload type | Что делает | Пример |
|--------------|-----------|-------|
| Simple list | фиксированный список | список логинов |
| Runtime file | читать файл построчно во время атаки | большой словарь без загрузки в память |
| Numbers | диапазон чисел (from/to/step/base) | `id` от 1 до 1000 |
| Brute forcer | все комбинации набора символов заданной длины | перебор короткого PIN |
| Null payloads | N раз без изменения payload | повторить запрос N раз (race) |
| Character blocks | блоки одинаковых символов растущей длины | тесты переполнения |
| Bit flipper | инверсия битов исходного значения | поиск скрытых параметров |
| Username generator | генерация вариантов username | email-паттерны |
| Dates / Random | даты / случайные значения | тесты логики по времени |
| Copy other payload | копировать значение другой позиции | связывание полей |
| Custom iterator | несколько вложенных наборов | комбинирование (a:b) |

**Payload processing rules (Payloads → Payload processing):**

| Правило | Что делает |
|---------|-----------|
| Add prefix / Add suffix | обернуть payload (`"` + payload + `"`) |
| Match / Replace | заменить подстроку в payload |
| Substring | взять подстроку |
| Reverse substring | перевернуть подстроку |
| Modify case | смена регистра |
| Encode / Decode | URL, HTML, base64, hex, MD5/SHA |
| Hash | хешировать payload |
| Skip if matches regex | пропустить payload по шаблону |
| Invoke Burp extension | вызвать обработчик из расширения |
| Character substitution | замена символов (обход WAF) |

**Grep — Match / Extract (Options → Grep):**

| Опция | Что делает |
|-------|-----------|
| Grep — Match | пометить ответы, содержащие строку/regex (например `Welcome`) |
| Grep — Extract | извлечь regex-группу в колонку таблицы |
| Grep — Payloads | пометить, где в ответе отразился payload |
| Grep — Errors | пометить ответы с ошибками (SQL/stack trace) |

## Macros и session handling (обход CSRF-токенов)

Проблема: форма содержит одноразовый `csrf_token`; при повторе запроса токен протухает. Решение — **macro**:

1. Settings → Sessions → Session Handling Rules → Add.
2. Rule Actions → Add → *Run a macro*.
3. Macro = запрос `GET /form`, в котором через *Configure item → Custom parameter locations* указан `csrf_token`.
4. Scope: правило применяется ко всем запросам в scope.
5. В самом целевом запросе токен заменяется на извлечённый макросом.

Так же настраивается авто-логин: макрос `POST /login` → cookie сессии обновляется перед запросами.

**Опции Session Handling Rule / Macro (опция | что делает | пример):**

| Опция | Что делает | Пример |
|-------|-----------|-------|
| Rule Actions → Run a macro | выполнить макрос перед запросом | обновить `csrf_token` |
| Rule Actions → Add cookies | добавить cookie из ответа | подставить session id |
| Rule Actions → Set a specific cookie/header | принудительно задать cookie/заголовок | `X-Admin: 1` |
| Rule Actions → Check session is valid | проверить валидность сессии и перелогиниться | по строке `Logout` |
| Rule Actions → Invoke a Burp extension | вызвать обработчик расширения | кастомная авторизация |
| Scope → Tools scope | к каким инструментам применять | Intruder, Repeater, Scanner |
| Scope → URL scope | к каким URL применять | `target.local/*` |
| Scope → Parameter scope | только при наличии параметра | `csrf` |
| Macro → Configure item → Custom parameter locations | из какого места макроса брать значение | `csrf_token` из тела |
| Macro → Configure item → Cookies / Headers | извлекать из cookie/заголовка | `Set-Cookie: session` |
| Macro → Add item | добавить несколько запросов в цепочку | login → 2FA → redirect |
| Macro → Update/Re-record | перезаписать макрос | после смены формы |

## Match/Replace и upstream proxy

- **Proxy → Options → Match and Replace:** `Request header` → заменить `User-Agent` на мобильный, добавить `X-Forwarded-For: 127.0.0.1`, `Client-IP`, `X-Originating-IP` — классика обхода IP-ограничений.
- **Upstream proxy** (Proxy → Options → Upstream Proxy Servers): цепочка через второй прокси, например через SOCKS для pivoting:

```
Destination host: *.internal.local
Proxy host: 127.0.0.1   Proxy port: 9050   Type: SOCKS5
```

**Полная таблица Match and Replace (тип правила | что делает | пример):**

| Тип правила | Что делает | Пример |
|-------------|-----------|-------|
| Request header | добавить/заменить заголовок запроса | `User-Agent` → `Mozilla/5.0 (iPhone...)` |
| Request body | заменить строку в теле запроса | подменить JSON-поле |
| Request first line | изменить метод/путь | `GET /a` → `POST /b` |
| Request param name / value | переименовать/подменить параметр | `isAdmin=false` → `true` |
| Response header | добавить заголовок ответа | `Access-Control-Allow-Origin: *` |
| Response body | заменить строку в теле ответа | вставить `<script>` для self-XSS-теста |
| Add header | добавить без замены | `X-Forwarded-For: 127.0.0.1` |
| Regex match | сработать только при совпадении regex | только для `/api/*` |

Типовые «наборы» для обхода:
`X-Forwarded-For`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`, `X-Forwarded-Host` → `127.0.0.1`.

## ZAP: запуск из CLI и add-ons

ZAP CLI (`zap.sh` / `zap.bat`):

| Флаг | Что делает | Пример |
|------|-----------|-------|
| `-cmd` | режим без GUI (headless) | `zap.sh -cmd -quickurl https://t -quickout r.html` |
| `-quickurl URL` | быстрый скан одной цели | `-quickurl https://target.local` |
| `-quickout FILE` | файл отчёта | `-quickout report.html` |
| `-quickprogress` | прогресс в stdout | `-quickprogress` |
| `-quickprogress` + `-cmd` | CI-скан | в pipeline |
| `-port N` | порт ZAP-прокси | `-port 8090` |
| `-daemon` | запустить как демон | `zap.sh -daemon -port 8090` |
| `-config KEY=VAL` | задать параметр конфигурации | `-config api.key=12345` |
| `-session FILE` | открыть/создать сессию | `-session my.session` |
| `-newsession FILE` | новая сессия | `-newsession s1` |
| `-dir DIR` | домашняя директория | `-dir /tmp/zap` |

Управление через REST API (когда ZAP запущен как daemon):

```bash
# активный скан
curl "http://127.0.0.1:8090/JSON/ascan/action/scan/?url=https://target.local&apikey=12345"
# статус скана
curl "http://127.0.0.1:8090/JSON/ascan/view/status/?scanId=0&apikey=12345"
# spider
curl "http://127.0.0.1:8090/JSON/spider/action/scan/?url=https://target.local&apikey=12345"
```

**Ключевые ZAP add-ons (Marketplace):**

| Add-on | Зачем |
|--------|-------|
| **Fuzzer** | аналог Intruder (позиции — выделить → Add) |
| **Ajax Spider** | обход JS-приложений (headless browser) |
| **Access Control** | авто-тест авторизации по ролям (аналог Autorize) |
| **DOM XSS** | поиск DOM-XSS |
| **WebSocket** | перехват/фаззинг WebSocket |
| **Advanced SQLInjection / SQLi** | расширенный SQLi-сканер |
| **Retire.js** | детект уязвимых JS-библиотек |
| **Active Scan Rules / Passive Scan Rules** | наборы проверок |
| **GraphQL** | поддержка GraphQL |
| **OpenAPI / SOAP** | импорт спецификаций для скана API |
| **HUD** | in-browser интерфейс ZAP |

Соответствие инструментов ZAP ↔ Burp:

| Функция | ZAP |
|---------|-----|
| Repeater | Request Editor / Manual Request |
| Intruder | Fuzzer |
| Decoder | Encode/Decode/Hash |
| Comparer | Compare |
| Sequencer | Token Generation & Analysis |
| Scanner | Active/Passive Scan |
| Extender | Marketplace add-ons |
| Autorize | Access Control add-on |
| Collaborator | OAST/Callback (Collaborator-like) |

## ZAP: соответствие функциям Burp

| Burp | ZAP |
|------|-----|
| Proxy → Intercept | Breakpoints (Set / Unset) |
| Repeater | Request Editor (Manual Request) + Resend |
| Intruder | Fuzzer (позиции — выделить текст → Add) |
| Decoder | Encode/Decode/Hash tool |
| Comparer | Compare tool |
| Sequencer | Token Generation & Analysis |
| Scanner | Active Scan / Passive Scan |
| Extender/BApp | Marketplace add-ons |
| Repeater tabs | Sites tree + Manual Request |

Запуск ZAP из CLI (автоматизация в CI):

```bash
zap.sh -cmd -quickurl https://target.local -quickprogress -quickout report.html
```

## Типичные сценарии: что выбрать и когда

| Задача | Инструмент |
|--------|-----------|
| Перехватить и поправить один запрос | Burp Repeater / ZAP Manual Request |
| Перебрать значения параметра | Burp Intruder (Sniper) / ffuf / ZAP Fuzzer |
| Перебрать user×pass | Burp Intruder (Cluster bomb) / hydra |
| Найти скрытые параметры | Param Miner |
| Проверить авторизацию на всех запросах | Autorize |
| Бесплатный активный скан | ZAP Active Scan |
| Быстрый рейс-кондишн | Turbo Intruder |
| Разбор/подделка JWT | JWT Editor + jwt_tool |

## Частые ошибки

- **Забыть про scope.** Без scope Intruder/Scanner бьёт по чужим доменам — риск и шум.
- **Не установить CA-сертификат.** Браузер рвёт HTTPS, и вы видите ошибку вместо трафика.
- **Гонять Intruder в Community на больших списках.** Он throttled — используйте ffuf или Turbo Intruder.
- **Игнорировать Comparer.** Глазами «одинаковые» ответы часто различаются одним байтом.
- **Не настраивать session handling.** Повтор запроса с одноразовым токеном даёт ложные «403».
- **Доверять Scanner.** Авторизационные и логические баги он не находит — это ручная работа.

## Квиз

```quiz
- question: "Какой тип Intruder-атаки подставляет один и тот же payload во все позиции одновременно?"
  options:
    - "Sniper"
    - "Cluster bomb"
    - "Battering ram"
    - "Pitchfork"
  answer: 2
  explanation: "Battering ram — один payload во все позиции; Pitchfork — свои списки попарно."
- question: "Как расширение Autorize помогает искать авторизационные баги?"
  options:
    - "Сканирует порты"
    - "Повторяет каждый запрос без cookie или с чужой сессией"
    - "Взламывает пароли"
    - "Кодирует payload"
  answer: 1
  explanation: "Autorize авто-повторяет запросы с иной/пустой сессией и сравнивает доступ."
- question: "Зачем нужен macro в Session Handling Rules?"
  options:
    - "Чтобы ускорить сканер"
    - "Чтобы обновлять одноразовый CSRF-токен или сессию перед запросами"
    - "Чтобы менять тему оформления"
    - "Чтобы отключить прокси"
  answer: 1
  explanation: "Макрос выполняет запрос и извлекает свежий токен/cookie."
- question: "Какой инструмент оценивает предсказуемость session-токена?"
  options:
    - "Decoder"
    - "Comparer"
    - "Sequencer"
    - "Repeater"
  answer: 2
  explanation: "Sequencer собирает сэмплы токена и считает энтропию."
- question: "Что даёт Copy as curl command?"
  options:
    - "Готовую команду для воспроизведения запроса в терминале"
    - "Экспорт всего проекта"
    - "Новый payload для Intruder"
    - "Установку сертификата"
  answer: 0
  explanation: "Это удобный способ сделать воспроизводимый PoC."
```

## Где пригодится

- **CTF (Web):** Repeater/Intruder для перебора и правки запросов — базовый навык почти любой задачи.
- **Bug bounty:** Autorize, Param Miner и JWT Editor напрямую находят баги, которые платят.
- **Пентест:** единый прокси для ручного теста, доказательств и настройки цепочек.
- **Работа (AppSec):** ZAP в CI для автоскан-гейта, Burp — для ручного глубокого анализа.
