---
id: web-spring-boot-actuator
title: "Spring Boot Actuator: env, heapdump, jolokia и gateway SpEL RCE"
category: web
parent: web-frameworks
difficulty: hard
order: 4
tags: [spring, spring-boot, actuator, spel, jolokia, heapdump, rce, cve]
prerequisites: [web-frameworks]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 50
summary: "Spring Boot как цель: открытые Actuator-эндпоинты (env/heapdump/jolokia), утечка секретов и RCE через SpEL (CVE-2022-22947/22963)."
---

## Вопрос, с которого всё начинается

Spring Boot — стандарт для Java-микросервисов. У него есть **Actuator** — набор служебных эндпоинтов для мониторинга и управления (`/actuator/*`). Если Actuator оставлен открытым в проде (а так бывает часто), он отдаёт конфигурацию, переменные окружения и heap-дамп — то есть все секреты. Плюс SpEL-инъекции в Spring Cloud дают RCE. Разберём.

## Наш пример: Spring Boot-сервис

Цель — `https://api.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://api.target.example
https://api.target.example [200 OK] Spring Boot, Java, X-Application-Context[application:8080]
```

Заголовок `X-Application-Context` — признак Spring Boot. Проверяем Actuator:

```
$ curl -s https://api.target.example/actuator | head -c 300
{"_links":{"self":...,"env":...,"heapdump":...,"jolokia":...,"beans":...}}
```

Actuator открыт. В нём есть `env`, `heapdump`, `jolokia` — это критично.

## Шаг 1: /actuator/env — утечка конфигурации

Эндпоинт `/actuator/env` отдаёт все переменные окружения и свойства, включая **секреты** (пароли БД, API-ключи, токены). Часто они замаскированы (`******`), но маскировку можно обойти:

```
$ curl -s 'https://api.target.example/actuator/env'
$ curl -s 'https://api.target.example/actuator/env/spring.datasource.password'
```

Иногда через `POST /actuator/env` можно **изменить** свойство (например, `spring.cloud.gateway.routes`) — и это уже шаг к RCE.

## Шаг 2: /actuator/heapdump — дамп памяти

`/actuator/heapdump` отдаёт весь heap JVM. Через `MAT`/`jvisualvm` в нём находят пароли, ключи, токены, даже активные сессии. Это самый ценный Actuator-эндпоинт после env.

```
$ curl -s https://api.target.example/actuator/heapdump -o heap.hprof
$ strings heap.hprof | grep -iE 'password|secret|token' | head
```

## Шаг 3: /actuator/jolokia — RCE через JMX

**Jolokia** — мост к JMX (управление Java-приложением). Через него можно вызывать MBean-операции, включая загрузку и выполнение кода. Если `jolokia` открыт и `POST` разрешён — это **RCE**:

```
POST /actuator/jolokia/exec/...
```

Публичные PoC используют MBean для создания файла/запуска команды.

## Шаг 4: SpEL-инъекция (Spring Cloud)

Spring Cloud Gateway/Function исторически уязвимы к **SpEL-инъекции** (CVE-2022-22947 — Gateway Actuator; CVE-2022-22963 — Cloud Function). Через Actuator добавляется route с SpEL-выражением, которое вычисляется на сервере → RCE.

```
POST /actuator/gateway/routes/evil
{"predicates":[...],"filters":[{"name":"AddResponseHeader","args":{"name":"r","value":"#{new String(T(java.lang.Runtime).getRuntime().exec('id').getInputStream().readAllBytes())}"}}]}
```

## Шаг 5: план атаки на Spring Boot

1. Фингерпринт (`X-Application-Context`).
2. Проверка `/actuator` и его эндпоинтов.
3. Дамп `env`/`heapdump` (секреты).
4. Проверка `jolokia` (RCE).
5. Проверка SpEL (CVE-2022-22947/22963).
6. Пост-эксплуатация — креды, RCE.

## Шаг 6: как не навредить

Микросервис может быть частью прода. Изменение env/gateway-route меняет поведение; heapdump — тяжёлая операция. Поэтому: сначала чтение (env/heapdump), затем проверка SpEL без изменения боевых route'ов, RCE — при разрешении.

## Шаг 7: чек-лист по Spring Boot

1. Заголовок `X-Application-Context`.
2. `/actuator` и список эндпоинтов.
3. `env`/`heapdump` (секреты).
4. `jolokia` (RCE).
5. SpEL (Gateway/Function).
6. Сопоставление с CVE.

## heapdump: извлечение секретов из дампа

`/actuator/heapdump` отдаёт весь heap процесса. Это самый ценный артефакт: в нём лежат пароли БД, токены, ключи, содержимое сессий. Быстрый разбор — строками:

```bash
curl -s http://T:8080/actuator/heapdump -o heap.hprof
strings heap.hprof | grep -Ei 'password|secret|token|jdbc:|Authorization' | head
```

Глубже — через Eclipse MAT или `jhat`: ищутся объекты класса `java.lang.String` с паттернами, объекты `DataSource`, `SecurityContext`, поля `spring.datasource.*`. Часто находят учётки, которые не видны в `/actuator/env` (там они маскируются звёздочками). Дамп памяти — самый надёжный способ обойти маскирование секретов Actuator.

## Jolokia и SpEL: безопасная проверка

`/actuator/jolokia` даёт доступ к JMX. Через него читают MBean-атрибуты и, при неосторожной конфигурации, создают MBean или вызывают операции — вплоть до выполнения кода (`reloadByURL` в Logback MBean подтягивает удалённый конфиг). SpEL-инъекция (Spring Cloud Gateway) позволяет выполнить выражение через заголовок/параметр. Безопасная проверка — **time-based, без разрушения**: подставь выражение, которое лишь вычислит `7*7` и вернёт результат, или вызовет `sleep` фиксированной длительности. Никогда не запускай `rm`, не создавай пользователей, не пиши файлы на продакшне. Цель проверки — доказать выполнение, а не навредить.

## Полный сценарий атаки на Spring Boot-сервис

Разберём связный сценарий. Разведка: `curl -s http://T:8080/actuator` отдаёт список включённых эндпоинтов (`env`, `heapdump`, `jolokia`, `mappings`, `beans`). Если список пуст, но `/actuator/env` отвечает — эндпоинты включены точечно. Шаг второй — утечка конфигурации: `curl -s http://T:8080/actuator/env | jq ".propertySources"` показывает источники свойств, а в `configprops` часто видны незамаскированные параметры. Шаг третий — дамп памяти, если `heapdump` доступен. Шаг четвёртый — `jolokia` или SpEL, если первые два не дали кредов.

```bash
curl -s http://T:8080/actuator | jq -r "._links|keys[]"
curl -s http://T:8080/actuator/env | jq ".propertySources[].properties|keys[]" | head
```

Смысл сценария — идти от самого дешёвого к самому дорогому. `env` и `heapdump` безопаснее для цели (только чтение), а `jolokia`/SpEL — уже активное воздействие, которое может уронить сервис. Поэтому активные шаги применяют только когда пассивные не дали результата.

## Что делать, если Actuator закрыт

Если `/actuator` возвращает 404, это не значит «безопасно» — эндпоинты могли вынести на другой порт (`management.server.port`) или на отдельный контекст (`management.endpoints.web.base-path`). Проверь частые варианты: `/manage`, `/management`, `/actuator/health` (часто открыт намеренно), а также порт 8081 или 9090. Иногда Actuator доступен только из внутренней сети — тогда нужен SSRF или позиция в сети.

```bash
for p in /actuator /manage /management /actuator/health; do echo "== $p"; curl -s -o /dev/null -w "%{http_code}\n" http://T:8080$p; done
```

Помни: даже один открытый `/actuator/health` с `details` раскрывает статус БД и внешних зависимостей. Это низкорисковая, но полезная разведка.

## Типовые ошибки и как их избежать

Первая ошибка — считать `/actuator` единым флагом. В Spring Boot эндпоинты включаются по отдельности (`management.endpoints.web.exposure.include`), поэтому `env` может быть закрыт, а `heapdump` — открыт. Проверяй каждый. Вторая — игнорировать `/actuator/configprops`: там часто видны параметры подключения, которые не попали в `env`. Третья — сразу бить в `jolokia`/SpEL: это активное воздействие, и при неосторожности сервис падает, а вместе с ним уходит доступ. Четвёртая — забывать, что Actuator может жить на другом порту. Пятая — не проверять маскирование: значение в `env` со звёздочками всё равно утекает через `heapdump`.

## Мини-шпаргалка по Actuator

`/actuator` (список) → `/actuator/env` (конфиг) → `/actuator/configprops` → `/actuator/heapdump` (секреты) → `/actuator/jolokia` (JMX) → SpEL (Spring Cloud). Проверяй также другой порт (`management.server.port`) и базовый путь (`management.endpoints.web.base-path`). Активные шаги — в последнюю очередь.

## Итог и приоритеты

Порядок работы с Spring Boot Actuator продиктован соотношением риск/польза. Сначала дешёвое и пассивное: список эндпоинтов, `/actuator/env`, `/actuator/configprops`. Затем `/actuator/heapdump` — самый ценный артефакт, потому что обходит маскирование секретов и отдаёт пароли БД, токены и ключи. И только если пассивное не дало результата — активные `jolokia` и SpEL, потому что они могут уронить сервис.

В отчёте указывай конкретные утечки (что именно нашёл), а не «Actuator открыт». Рекомендации: отключить ненужные эндпоинты (`management.endpoints.web.exposure.include`), вынести management-порт в отдельную сеть, включить аутентификацию на management-эндпоинтах, убрать секреты из переменных окружения в внешний секрет-стор. Помни про другой порт и базовый путь: закрытие `/actuator` на основном порту не означает, что Actuator недоступен вовсе.

## Что мы теперь знаем

- Spring Boot узнаётся по `X-Application-Context`.
- Actuator отдаёт env/heapdump/jolokia.
- `env`/`heapdump` — утечка секретов.
- `jolokia` — RCE через JMX.
- SpEL в Gateway/Function — RCE (CVE-2022-22947/22963).

## Шаг 8: как искать Actuator-эндпоинты

Actuator может быть на `/actuator` или на собственном порту (management port). Проверь оба и перечисли ссылки:

```
$ curl -s https://api.target.example/actuator | grep -oE '"[a-z]+"' | head -30
$ curl -s https://api.target.example/actuator/info
$ curl -s https://api.target.example/actuator/mappings
```

Приоритет: `env`, `heapdump`, `jolokia`, `gateway/routes`. Если `/actuator` закрыт, пробуй `/actuator/health` (часто открыт) и обходы (регистр, точка на конце: `/actuator/env.`).

## Шаг 9: типовые ошибки при работе с Spring Boot

Ошибка первая — считать Actuator закрытым, не проверив `/health` и обходы. Вторая — запускать SpEL-RCE сразу (изменяет route). Третья — тянуть гигабайтный heapdump без нужды (нагрузка). Четвёртая — игнорировать `jolokia` (это прямой RCE).

## Шаг 10: как защититься от Spring Boot-атак

Защита: `management.endpoints.web.exposure.include=health,info` (только нужное); закрыть management-порт; отключить `jolokia`; обновить Spring Cloud (CVE-2022-22947/22963); аутентификация на Actuator. Для атакующего: защищённый Actuator закрывает утечки и RCE, и остаются прикладные баги.

## Шаг 11: как связать Spring Boot с инфраструктурой

`actuator/env` и `heapdump` содержат креды БД, Redis, очередей (Kafka/RabbitMQ), облака и сторонних API. С ними можно подключиться к брокерам сообщений, читать очереди, обращаться к БД напрямую. Плюс `jolokia` даёт RCE на самом сервисе. Поэтому Spring Boot-цель — это узел в микросервисной сети: компрометация одного сервиса открывает соседние.

## Шаг 12: как безопасно проверить SpEL

Не добавляй route в боевой Gateway сразу. Сначала проверь, доступен ли `POST /actuator/gateway/routes` (не 403/404). Затем — если разрешено — добавь **временный** route с безобидным SpEL (`7*7`) и удали его. Полноценный RCE — только при явном разрешении и на стенде.

## Шаг 13: как искать Spring Boot-цели и оценивать их

Spring Boot-сервисы выдают заголовок `X-Application-Context` и эндпоинт `/actuator`. Оценивай: какие Actuator-эндпоинты открыты (env/heapdump/jolokia), какая версия Spring Cloud, есть ли `POST` на gateway. Если открыт `jolokia` или `POST /actuator/gateway/routes` — цель критическая (RCE).

## Шаг 14: как оформить находку по Spring Boot

В отчёте: версия Spring Boot/Cloud; список открытых Actuator-эндпоинтов; утёкшие секреты (маскированно); подтверждение SpEL/Jolokia (если применимо); импакт (сервис + соседние микросервисы). Рекомендации: закрыть Actuator, отключить jolokia, обновить Spring Cloud, аутентификация.

## Шаг 15: почему Spring Boot — узел микросервисной сети

Микросервисы связаны: один сервис ходит в другой, все используют общие креды (БД, брокеры, секрет-менеджеры). Поэтому компрометация одного Spring Boot-сервиса через Actuator открывает соседние — а их десятки. Это делает такие цели приоритетными в облачных пентестах.

## Квиз

Проверь себя.

```quiz
- question: "По какому заголовку узнаётся Spring Boot?"
  options:
    - "X-Application-Context"
    - "X-Powered-By"
    - "Server"
    - "X-Jenkins"
  answer: 0
  explanation: "Характерный заголовок Spring Boot."
- question: "Что отдаёт /actuator/heapdump?"
  options:
    - "Только метрики"
    - "Дамп памяти JVM с паролями и токенами"
    - "Только логи"
    - "Ничего"
  answer: 1
  explanation: "В heap — секреты в открытом виде."
- question: "Через что Jolokia даёт RCE?"
  options:
    - "Через JMX MBean"
    - "Через SQLi"
    - "Через XSS"
    - "Через CSRF"
  answer: 0
  explanation: "Jolokia — мост к JMX."
- question: "Что такое SpEL-инъекция в Spring Cloud?"
  options:
    - "XSS"
    - "RCE через вычисление Spring Expression в Gateway/Function"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "CVE-2022-22947/22963."
- question: "С чего начинать атаку на Spring Boot?"
  options:
    - "С дампа heap"
    - "С проверки /actuator и его эндпоинтов"
    - "С перезагрузки"
    - "С SQLi"
  answer: 1
  explanation: "Actuator — карта возможностей."
```

## Куда дальше

Дальше — Spring Cloud Gateway/Function и другие Java-фреймворки. А пока запомни: **в Spring Boot открытый Actuator = секреты и RCE.**

## Где пригодится

- Пентест Java-микросервисов.
- Bug bounty: API на Spring Boot.
- CTF: задания с Actuator/SpEL.
