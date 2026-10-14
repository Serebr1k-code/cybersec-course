#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: web forensics (3 hubs + 11 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

HUBS["forensics-web-apps"] = r'''---
id: forensics-web-apps
title: "Модуль: веб-приложения — CMS, Java, БД и поиск"
category: forensics
parent: forensics-web-forensics
difficulty: hard
order: 3
tags: [forensics, web, cms, java, elasticsearch, mongodb, roadmap]
prerequisites: [forensics-web-forensics]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ веб-серверов"
estimated_minutes: 13
summary: "Этап ветки «веб»: как расследовать серверные приложения — CMS, Java-серверы, Elasticsearch и NoSQL-БД."
---

Веб-инцидент почти всегда оставляет следы в серверных приложениях: логи, базы, кэши,
сессии. Этот модуль — про типовые компоненты, которые встречаются почти везде.

## Что покрывает этот модуль

- **CMS** — WordPress/Joomla/Drupal и их логи.
- **Java-серверы** — Tomcat/JBoss/WildFly.
- **Elasticsearch** — поисковый движок и его логи.
- **MongoDB/Redis** — NoSQL-хранилища.

## Рекомендуемый порядок изучения

1. `web-cms` — самый частый случай.
2. `web-java-appserver` — корпоративные приложения.
3. `web-elasticsearch` — утечки и логи.
4. `web-mongodb-redis` — NoSQL.

## Что вы будете уметь

- Читать логи CMS и находить веб-шеллы.
- Анализировать Java-приложения.
- Расследовать компромисс Elasticsearch.
- Работать с NoSQL-данными.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| access.log CMS | что запрашивали | `grep`, `awk` |
| Tomcat-логи | что выполнялось | `catalina.out` |
| Elasticsearch-лог | кто читал индексы | консоль |
| Mongo/Redis | что в хранилище | `mongosh`, `redis-cli` |

## Куда дальше

Открывай урок **«CMS-форензика»** — начнём с самого частого.
'''

HUBS["forensics-web-infra"] = r'''---
id: forensics-web-infra
title: "Модуль: веб-инфраструктура — API-шлюзы, WAF/CDN, git и CI"
category: forensics
parent: forensics-web-forensics
difficulty: hard
order: 4
tags: [forensics, web, api-gateway, waf, cdn, git, jenkins, roadmap]
prerequisites: [forensics-web-forensics]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ веб-инфраструктуры"
estimated_minutes: 13
summary: "Этап ветки «веб»: как расследовать инфраструктуру вокруг приложения — API-шлюзы, WAF/CDN, git-репозитории и CI-серверы."
---

Приложение — только часть картины. Перед ним стоят шлюзы, WAF и CDN, а рядом — git и
CI. У каждого свои логи и своя роль в инциденте. Разберём.

## Что покрывает этот модуль

- **API-шлюзы** — маршрутизация и логи запросов.
- **WAF/CDN** — фильтрация и кэш.
- **Git-репозитории** — история и секреты.
- **Jenkins/CI** — сборки и доступ.

## Рекомендуемый порядок изучения

1. `web-api-gateway` — точка входа API.
2. `web-waf-cdn` — защита и кэш.
3. `web-git-repo` — код и секреты.
4. `web-jenkins-cicd` — сборки.

## Что вы будете уметь

- Читать логи шлюза и WAF.
- Восстанавливать запросы из кэша/CDN.
- Искать секреты в git-истории.
- Расследовать компромисс CI.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| gateway-лог | какие API вызывали | `grep`, `jq` |
| WAF-лог | что блокировали | консоль |
| git-история | что меняли | `git log` |
| Jenkins-лог | что собирали | консоль |

## Куда дальше

Открывай урок **«API-шлюзы»** — начнём с точки входа.
'''

HUBS["forensics-web-attack"] = r'''---
id: forensics-web-attack
title: "Модуль: атаки и логи — веб-шеллы, логи сервера, СУБД"
category: forensics
parent: forensics-web-forensics
difficulty: hard
order: 5
tags: [forensics, web, webshell, logs, oracle, roadmap]
prerequisites: [forensics-web-forensics]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ веб-атак"
estimated_minutes: 13
summary: "Этап ветки «веб»: как находить веб-шеллы, читать логи веб-сервера и расследовать компромисс корпоративной СУБД."
---

Финальный слой веб-форензики — сами атаки и их следы: загруженные шеллы, журналы
доступа и серверные базы данных. Разберём, как их найти.

## Что покрывает этот модуль

- **Веб-шеллы** — загруженный вредоносный код.
- **Логи сервера** — журналы доступа и ошибок.
- **Oracle/СУБД** — корпоративные базы и их аудит.

## Рекомендуемый порядок изучения

1. `web-server-logs` — журналы доступа.
2. `web-webshell` — поиск шеллов.
3. `web-oracle-db` — аудит СУБД.

## Что вы будете уметь

- Читать access/error-логи.
- Находить веб-шеллы по файлам и запросам.
- Расследовать компромисс СУБД.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| access.log | что запрашивали | `grep`, `awk` |
| .php в uploads | есть ли шелл | `grep`, `find` |
| Oracle audit | кто что делал | `audit` |

## Куда дальше

Открывай урок **«Логи веб-сервера»** — начнём с журналов.
'''

LESSONS["web-cms"] = dict(
parent="forensics-web-apps", order=1, diff="medium", mins=45,
title="CMS-форензика: WordPress, Joomla и следы компромисса",
tags="[forensics, web, cms, wordpress, joomla]",
prereq="[forensics-web-forensics]",
summary="Как расследовать компромисс CMS: логи доступа, изменённые файлы, веб-шеллы, плагины и пользователи.",
body=r'''
## Вопрос, с которого всё начинается

Сайт на WordPress «сломался» или рассылает спам. Скорее всего, загружен шелл или
изменён плагин. Разберём, где искать следы.

## Наш пример: WordPress

## Шаг 1: версия и компоненты

Уязвимости ищут по версиям ядра и плагинов:

```
$ curl -s http://target/wp-includes/version.php | grep wp_version
$ ls /var/www/html/wp-content/plugins/
```

Устаревший плагин — частый вход.

## Шаг 2: изменённые файлы

Злоумышленник меняет файлы. Сравни с эталоном:

```
$ diff -rq /var/www/html /opt/wordpress-clean/ | grep differ
Files /var/www/html/wp-content/themes/x/functions.php differ
```

`functions.php` с лишним кодом — классика.

## Шаг 3: веб-шеллы

Ищем исполняемые файлы в неожиданных местах:

```
$ find /var/www/html -name '*.php' -newermt '2026-01-14 03:00' | head
```

И подозрительный код:

```
$ grep -rE 'eval\(|base64_decode\(|system\(' /var/www/html/wp-content/uploads/
```

## Шаг 4: пользователи и логины

```
$ wp user list --role=administrator
```

Новый админ-аккаунт — признак компромисса. Сопоставь с логом входов:

```
$ grep 'wp-login' /var/log/apache2/access.log | grep POST | tail
```

## Шаг 5: что искать

- изменённые/новые PHP-файлы;
- шелл-паттерны (`eval`, `base64_decode`);
- новые админы;
- подозрительные запросы (POST на `wp-login`, доступ к `uploads/*.php`);
- устаревшие плагины.

## Что мы теперь знаем

- Версии ядра/плагинов — вектор.
- Изменённые файлы ловятся сравнением с эталоном.
- Шеллы ищут по времени и паттернам.
- Новый админ — признак компромисса.
- Логи показывают входы и запросы.

## Если не сработало

- Нет эталона? Скачай чистую версию CMS.
- Шелл обфусцирован? Ищи кодировки и eval.
- Нужен доступ? Проверь cron и wp-config.php.

## Квиз

Проверь себя.

```quiz
- question: Где чаще всего прячут веб-шелл в WordPress?
  options:
    - 'в /etc'
    - 'в uploads или изменённых файлах темы/плагина'
    - 'в /boot'
    - 'в шрифтах'
  answer: 1
  explanation: 'Uploads и файлы тем/плагинов — типичные места шеллов.'
- question: Как найти изменённые файлы?
  options:
    - 'по цвету'
    - 'сравнением с эталонной копией (diff -rq)'
    - 'по размеру'
    - 'никак'
  answer: 1
  explanation: 'Diff с чистой версией показывает отличия.'
- question: Признак компромисса в пользователях?
  options:
    - 'старый админ'
    - 'новый админ-аккаунт'
    - 'много редакторов'
    - 'смена пароля'
  answer: 1
  explanation: 'Неожиданный администратор — признак взлома.'
- question: Что искать в логах?
  options:
    - 'GET на главную'
    - 'POST на wp-login и доступ к uploads/*.php'
    - 'GET на favicon'
    - 'ничего'
  answer: 1
  explanation: 'Брутфорс логина и запуск PHP из uploads — подозрительны.'
```
''')

LESSONS["web-java-appserver"] = dict(
parent="forensics-web-apps", order=2, diff="hard", mins=50,
title="Java-серверы: Tomcat, JBoss и следы эксплуатации",
tags="[forensics, web, tomcat, jboss, java, logs]",
prereq="[forensics-web-forensics]",
summary="Как расследовать компромисс Java-серверов: логи, деплои WAR, десериализация и веб-шеллы.",
body=r'''
## Вопрос, с которого всё начинается

Корпоративное Java-приложение (Tomcat/JBoss) скомпрометировано. Такие серверы известны
уязвимостями (десериализация, менеджер). Где следы? Разберём.

## Наш пример: Tomcat

## Шаг 1: логи

```
$ ls /var/log/tomcat*/
catalina.out  localhost_access_log.2026-01-14.txt
```

`catalina.out` — общий лог, `localhost_access_log` — запросы.

```
$ grep -iE 'exception|deserial' catalina.out | tail
```

Исключения десериализации — признак эксплуатации.

## Шаг 2: менеджер

Tomcat Manager (`/manager/html`) позволяет деплоить WAR:

```
$ grep '/manager/html' localhost_access_log.2026-01-14.txt | tail
203.0.113.5 - - "POST /manager/html/upload HTTP/1.1" 200
```

Загрузка WAR с внешнего IP — почти наверняка атака.

## Шаг 3: деплои

Смотрим, что развёрнуто и когда:

```
$ ls -la /var/lib/tomcat/webapps/
shell.war   (Jan 14 03:30)
```

Новый WAR-файл = внедрённый веб-шелл.

## Шаг 4: десериализация

Уязвимости Java-десериализации (ysoserial) выполняют команды. Признаки:

- большие бинарные тела в логах;
- вызовы `Runtime.exec`;
- аномальные процессы Java (сеть, файлы).

```
$ ps aux | grep java
```

## Шаг 5: что искать

- новые/изменённые WAR/class-файлы;
- обращения к `/manager`, `/jmx-console`, `/wls-wsat`;
- исключения десериализации;
- исходящие соединения от Java.

## Что мы теперь знаем

- Tomcat логи: catalina.out + access-log.
- Manager позволяет деплоить WAR (вектор).
- Новый WAR = шелл.
- Десериализация даёт RCE.
- Ищем аномалии в логах и файлах.

## Если не сработало

- Логи усечены? Смотри access-log по датам.
- WAR зашифрован? Распакуй и смотри class-файлы.
- Нужен процесс? Анализируй память Java.

## Квиз

Проверь себя.

```quiz
- question: Что такое catalina.out?
  options:
    - 'база данных'
    - 'основной лог Tomcat'
    - 'шелл'
    - 'сеть'
  answer: 1
  explanation: 'catalina.out — общий лог контейнера Tomcat.'
- question: Чем опасен Tomcat Manager?
  options:
    - 'ничем'
    - 'позволяет деплоить WAR (RCE)'
    - 'шифрует'
    - 'ускоряет'
  answer: 1
  explanation: 'Через manager можно загрузить вредоносный WAR.'
- question: Признак эксплуатации десериализации?
  options:
    - 'GET на главную'
    - 'исключения десериализации и большие бинарные тела'
    - 'много картинок'
    - 'ничего'
  answer: 1
  explanation: 'Гаджет-цепи оставляют исключения в логах.'
- question: Что искать в webapps?
  options:
    - 'обои'
    - 'новые/изменённые WAR'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Лишний WAR — внедрённое приложение/шелл.'
```
''')

LESSONS["web-elasticsearch"] = dict(
parent="forensics-web-apps", order=3, diff="medium", mins=45,
title="Elasticsearch-форензика: индексы, логи и утечки",
tags="[forensics, web, elasticsearch, logs, data-leak]",
prereq="[forensics-web-forensics]",
summary="Как расследовать компромисс Elasticsearch: открытые индексы, аудит-логи, изменения данных и утечки.",
body=r'''
## Вопрос, с которого всё начинается

Elasticsearch часто выставляют наружу без аутентификации — и из него утекают данные
или его используют для RCE. Разберём, где следы.

## Наш пример: Elasticsearch

## Шаг 1: открытый доступ

```
$ curl -s http://target:9200/_cat/indices?v
green open logs-2026.01.14 ...
```

Если ответ приходит без авторизации — кластер открыт. Это уже находка.

## Шаг 2: аудит-логи

Elasticsearch умеет логировать запросы (audit):

```
$ grep -i 'rest.request' /var/log/elasticsearch/audit.log | tail
```

Видно, кто и что запрашивал (в т.ч. удаление индексов).

## Шаг 3: удаление данных

Атакующий может удалить индексы (anti-forensics):

```
$ grep -i 'DELETE.*_index' audit.log | tail
```

Или перезаписать документы. Проверь целостность и бэкапы (snapshots).

## Шаг 4: RCE через скрипты

Elasticsearch позволял RCE через `script` (Groovy) и плагины:

```
$ grep -i 'script' audit.log | tail
```

Аномальные скрипт-запросы — признак эксплуатации.

## Шаг 5: что искать

- несанкционированный доступ (внешние IP);
- удаление/изменение индексов;
- скрипт-запросы;
- утечку чувствительных индексов;
- новые пользователи/роли (X-Pack).

## Что мы теперь знаем

- Открытый ES проверяется запросом без авторизации.
- Audit-лог фиксирует запросы.
- Удаление индексов — anti-forensics.
- Скрипты/плагины давали RCE.
- Смотрим доступ, изменения, скрипты.

## Если не сработало

- Аудит выключен? Смотри логи балансировщика/сети.
- Нужны данные? Восстанавливай из snapshot.
- Нужны права? Читай роли X-Pack.

## Квиз

Проверь себя.

```quiz
- question: Как проверить открытость Elasticsearch?
  options:
    - 'ping'
    - 'запрос к _cat/indices без авторизации'
    - 'grep'
    - 'ssh'
  answer: 1
  explanation: 'Ответ без аутентификации означает открытый кластер.'
- question: Что фиксирует audit-лог ES?
  options:
    - 'погоду'
    - 'запросы REST и доступ'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Audit-лог хранит rest.request события.'
- question: Что такое удаление индексов с точки зрения форензики?
  options:
    - 'норма'
    - 'anti-forensics (уничтожение данных)'
    - 'обновление'
    - 'шифрование'
  answer: 1
  explanation: 'Удаление индексов стирает данные и следы.'
- question: Как ES мог давать RCE?
  options:
    - 'через CSS'
    - 'через скрипты (Groovy) и плагины'
    - 'через обои'
    - 'никак'
  answer: 1
  explanation: 'Динамические скрипты и плагины позволяли выполнение кода.'
```
''')

LESSONS["web-mongodb-redis"] = dict(
parent="forensics-web-apps", order=4, diff="medium", mins=45,
title="MongoDB и Redis: NoSQL-хранилища в расследовании",
tags="[forensics, web, mongodb, redis, nosql]",
prereq="[forensics-web-forensics]",
summary="Как расследовать компромисс MongoDB/Redis: открытый доступ, аудит, изменения данных и следы эксплуатации.",
body=r'''
## Вопрос, с которого всё начинается

Приложение использует MongoDB/Redis, и что-то пошло не так. Оба часто выставляют
наружу без пароля. Разберём, где следы.

## Наш пример: Redis

## Шаг 1: открытый доступ

Redis без пароля:

```
$ redis-cli -h target INFO server | head
redis_version:6.2.0
```

Ответ без `AUTH` — открытый инстанс. MongoDB проверяется `mongosh --host target`.

## Шаг 2: Redis-эксплуатация

Redis известен записью файлов (RCE через SSH-ключ/cron):

```
$ redis-cli -h target CONFIG GET dir
dir /var/spool/cron
```

`dir` в `/var/spool/cron` + `SET`/`SAVE` = запись cron-файла → RCE. В логах Redis:

```
$ grep -i 'CONFIG\|SAVE\|BGSAVE' /var/log/redis/redis-server.log
```

## Шаг 3: MongoDB

MongoDB без авторизации даёт доступ к БД:

```
$ mongosh --host target
> show dbs
admin  appdb
> db.appdb.users.find()
```

Утечка пользователей/паролей — типичный итог.

## Шаг 4: следы изменений

- новые БД/коллекции (загруженные данные);
- удаление коллекций (anti-forensics);
- `oplog` (журнал операций) MongoDB — история изменений;
- RDB/AOF-файлы Redis — история данных.

## Шаг 5: что искать

- доступ с внешних IP;
- `CONFIG`/`SAVE` в Redis (запись файлов);
- новые пользователи/БД;
- удалённые коллекции;
- oplog/AOF как источник истории.

## Что мы теперь знаем

- Redis/Mongo часто без пароля.
- Redis CONFIG+SAVE = запись файлов (RCE).
- Mongo без авторизации даёт доступ к данным.
- oplog/AOF — история изменений.
- Ищем внешний доступ и изменения.

## Если не сработало

- Пароль есть? Ищи его в конфиге приложения.
- Логи выключены? Смотри сеть/аудит ОС.
- Данные удалены? Восстанавливай из RDB/oplog.

## Квиз

Проверь себя.

```quiz
- question: Как Redis позволяет выполнить код?
  options:
    - 'через CSS'
    - 'записью файла (CONFIG dir + SAVE) в cron/SSH'
    - 'через обои'
    - 'никак'
  answer: 1
  explanation: 'Redis умеет сохранять данные в файл по указанному пути.'
- question: Что даёт MongoDB без авторизации?
  options:
    - 'ничего'
    - 'полный доступ к базам данных'
    - 'шифрование'
    - 'ускорение'
  answer: 1
  explanation: 'Открытый Mongo отдаёт все БД без пароля.'
- question: Что такое oplog MongoDB?
  options:
    - 'обои'
    - 'журнал операций (история изменений)'
    - 'сеть'
    - 'шелл'
  answer: 1
  explanation: 'Oplog хранит операции репликации — историю изменений.'
- question: Где история данных Redis?
  options:
    - 'в RDB/AOF-файлах'
    - 'в реестре'
    - 'в браузере'
    - 'в шрифтах'
  answer: 0
  explanation: 'Redis персистит данные в RDB-снапшотах и AOF-журнале.'
```
''')

LESSONS["web-api-gateway"] = dict(
parent="forensics-web-infra", order=1, diff="medium", mins=45,
title="API-шлюзы: логи запросов и следы атак",
tags="[forensics, web, api-gateway, logs, kong, nginx]",
prereq="[forensics-web-forensics]",
summary="Как читать логи API-шлюзов (Kong/nginx/APIM), восстанавливать запросы и находить аномалии.",
body=r'''
## Вопрос, с которого всё начинается

Вся API-активность идёт через **шлюз** (Kong, nginx, AWS API Gateway). Его логи —
полная карта запросов. Разберём, как их читать.

## Наш пример: API-шлюз

## Шаг 1: что логируется

Шлюз пишет: время, клиент, метод, путь, статус, латентность, upstream.

```
$ tail -3 /var/log/kong/access.log
... "GET /api/v1/users" 200 ...
... "POST /api/v1/admin" 403 ...
```

## Шаг 2: агрегация

```
$ awk '{print $6, $7}' access.log | sort | uniq -c | sort -rn | head
  500 /api/v1/users
  120 /api/v1/admin
```

Всплеск обращений к `admin` с незнакомого клиента — аномалия.

## Шаг 3: подозрительные паттерны

- обход авторизации (401/403 пачками);
- доступ к несуществующим путям (сканирование);
- необычные методы (PUT/DELETE);
- большие тела запросов (эксфильтрация).

```
$ grep -E ' (401|403) ' access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

## Шаг 4: связь с бэкендом

Шлюз логирует **upstream** — какой сервис обработан:

```
... "upstream_status": "200", "service": "user-service"
```

Так понимаешь, какой бэкенд атаковали.

## Шаг 5: что искать

- клиенты с аномальной активностью;
- попытки обхода авторизации;
- сканирование путей;
- изменения конфигурации шлюза;
- запросы к чувствительным эндпоинтам.

## Что мы теперь знаем

- Шлюз логирует все API-запросы.
- Агрегация выявляет аномалии.
- Паттерны: 401/403, несуществующие пути, редкие методы.
- Upstream указывает сервис.
- Ищем обход авторизации и сканирование.

## Если не сработало

- Логи не включены? Проверь конфиг шлюза.
- Нужен контекст? Смотри логи бэкенда.
- Нужны тела? Включи debug-логирование.

## Квиз

Проверь себя.

```quiz
- question: Что логирует API-шлюз?
  options:
    - 'только ошибки'
    - 'запросы: клиент, метод, путь, статус, upstream'
    - 'пароли'
    - 'обои'
  answer: 1
  explanation: 'Шлюз — центральная точка логирования API.'
- question: Признак сканирования в логах?
  options:
    - 'успешные запросы'
    - 'много запросов к несуществующим путям'
    - 'мало трафика'
    - 'много картинок'
  answer: 1
  explanation: 'Перебор путей оставляет 404-пачки.'
- question: Что означает upstream в логе?
  options:
    - 'клиент'
    - 'какой бэкенд обработан'
    - 'пароль'
    - 'сеть'
  answer: 1
  explanation: 'Upstream указывает целевой сервис за шлюзом.'
- question: Что искать в первую очередь?
  options:
    - 'обои'
    - 'попытки обхода авторизации (401/403)'
    - 'шрифты'
    - 'музыку'
  answer: 1
  explanation: 'Пачки 401/403 указывают на брутфорс/обход.'
```
''')

LESSONS["web-waf-cdn"] = dict(
parent="forensics-web-infra", order=2, diff="medium", mins=45,
title="WAF и CDN: что видно в защите и кэше",
tags="[forensics, web, waf, cdn, cloudflare, logs]",
prereq="[forensics-web-forensics]",
summary="Как использовать логи WAF и CDN в расследовании: блокировки, реальные IP за прокси и восстановление запросов из кэша.",
body=r'''
## Вопрос, с которого всё начинается

Перед сайтом стоит **WAF/CDN** (Cloudflare/Akamai/AWS). Он не только защищает, но и
**логирует** всё: запросы, блокировки, реальные IP. Разберём.

## Наш пример: Cloudflare

## Шаг 1: логи WAF

WAF логирует решения: пропущено/заблокировано/челлендж.

```
$ grep BLOCK waf.log | head
203.0.113.5  GET /?id=1' OR '1'='1  BLOCK  SQLi
```

Здесь видно атаку (SQLi) и её источник.

## Шаг 2: реальный IP за прокси

CDN прячет настоящий IP клиента. В логах есть заголовки:

```
$ grep -i 'cf-connecting-ip\|x-forwarded-for' access.log | head
```

`CF-Connecting-IP` — настоящий адрес. Без него ты видишь только IP CDN.

## Шаг 3: кэш как источник

CDN кэширует ответы. В кэше могут остаться:

- версии страниц (в т.ч. удалённые);
- ответы API;
- статические файлы.

```
$ curl -s http://cdn/old-page | head
```

Проверь `Cache-Control`/`Age` — если страница из кэша, она «заморожена».

## Шаг 4: восстановление запросов

Логи WAF/CDN показывают полный URL и заголовки:

```
$ jq '.ClientRequestURI, .ClientIP' cdn_log.json | head
```

Это позволяет восстановить, что именно отправлял атакующий (payload).

## Шаг 5: что искать

- блокировки по типам атак (SQLi/XSS/RCE);
- реальные IP за прокси;
- запросы, прошедшие WAF (bypass);
- изменения конфигурации WAF;
- страницы из кэша.

## Что мы теперь знаем

- WAF/CDN логирует запросы и решения.
- Реальный IP — в `CF-Connecting-IP`/`X-Forwarded-For`.
- Кэш хранит версии страниц.
- Логи дают полный payload.
- Ищем блокировки, bypass, смену правил.

## Если не сработало

- Логи не экспортируются? Включи Logpush/журналирование.
- Нужны тела? Смотри логи бэкенда.
- Прокси без логов? Анализируй сеть.

## Квиз

Проверь себя.

```quiz
- question: Что делает WAF?
  options:
    - 'ускоряет'
    - 'фильтрует запросы и логирует решения'
    - 'шифрует диск'
    - 'сканирует порты'
  answer: 1
  explanation: 'WAF блокирует атаки и ведёт логи.'
- question: Где реальный IP клиента за CDN?
  options:
    - 'в имени'
    - 'в заголовке CF-Connecting-IP/X-Forwarded-For'
    - 'в cookie'
    - 'в обои'
  answer: 1
  explanation: 'Прокси-заголовки несут настоящий адрес клиента.'
- question: Чем полезен кэш CDN для форензики?
  options:
    - 'ничем'
    - 'хранит версии страниц, в т.ч. удалённые'
    - 'шифрует'
    - 'сеть'
  answer: 1
  explanation: 'Кэш может сохранить контент, убранный с сервера.'
- question: Что искать в логах WAF?
  options:
    - 'обои'
    - 'блокировки атак и прошедшие bypass запросы'
    - 'музыку'
    - 'шрифты'
  answer: 1
  explanation: 'Блокировки показывают атаки; пропуски — обход.'
```
''')

LESSONS["web-git-repo"] = dict(
parent="forensics-web-infra", order=3, diff="medium", mins=45,
title="Git-репозитории: история, секреты и утечки",
tags="[forensics, web, git, secrets, repository]",
prereq="[forensics-web-forensics]",
summary="Как расследовать git-репозиторий: история коммитов, утёкшие секреты, удалённые ветки и .git на сервере.",
body=r'''
## Вопрос, с которого всё начинается

Из репозитория утекли секреты, или на сервере торчит `.git`. Git хранит **всю**
историю — даже то, что удалили. Разберём.

## Наш пример: репозиторий

## Шаг 1: история

```
$ git log --oneline --all | head
a1b2c3d add deploy key
9f8e7d6 fix
```

`--all` включает все ветки. Удалённые коммиты могут оставаться в reflog.

## Шаг 2: поиск секретов в истории

Секреты могли удалить позже, но они в истории:

```
$ git log -p --all | grep -iE 'AKIA|password|BEGIN.*PRIVATE KEY' | head
```

Или инструментами (`gitleaks`, `trufflehog`).

## Шаг 3: .git на сервере

Если `.git` доступен по HTTP, можно восстановить исходники:

```
$ curl -s http://target/.git/HEAD
ref: refs/heads/main
$ curl -s http://target/.git/config
```

Иногда доступны `objects` — репозиторий целиком.

## Шаг 4: авторство и время

```
$ git log --format='%an %ae %ad %s' | head
Ivan ivan@corp.local Thu Jan 14 03:20:00 2026 +0000 add deploy key
```

Необычный автор/время — зацепка.

## Шаг 5: что искать

- секреты в истории (ключи, пароли, токены);
- коммиты вне обычного графика;
- форс-пуш/переписанную историю (reflog);
- доступный `.git` на продакшене;
- ссылки на внешние репозитории.

## Что мы теперь знаем

- Git хранит всю историю, включая удалённое.
- `git log -p --all` ищет секреты.
- Доступный `.git` = утечка исходников.
- Автор/время коммитов — зацепки.
- Reflog хранит «потерянные» коммиты.

## Если не сработало

- История переписана? Смотри reflog и бэкапы.
- .git недоступен? Ищи зеркала/форки.
- Нужен масштаб? Используй gitleaks/trufflehog.

## Квиз

Проверь себя.

```quiz
- question: Почему git важен для форензики?
  options:
    - 'он красивый'
    - 'хранит всю историю, включая удалённые секреты'
    - 'он быстрый'
    - 'он шифрует'
  answer: 1
  explanation: 'История коммитов сохраняет удалённые позже данные.'
- question: Как искать секреты в истории?
  options:
    - 'git log -p --all | grep'
    - 'ls'
    - 'ping'
    - 'cp'
  answer: 0
  explanation: 'Полный diff истории выявляет ключи/пароли.'
- question: Чем опасен доступный .git на сервере?
  options:
    - 'ничем'
    - 'позволяет восстановить исходный код'
    - 'ускоряет'
    - 'шифрует'
  answer: 1
  explanation: 'Через .git/objects можно выкачать репозиторий.'
- question: Что такое reflog?
  options:
    - 'журнал ссылок, хранящий «потерянные» коммиты'
    - 'обои'
    - 'сеть'
    - 'шелл'
  answer: 0
  explanation: 'Reflog хранит историю перемещений HEAD.'
```
''')

LESSONS["web-jenkins-cicd"] = dict(
parent="forensics-web-infra", order=4, diff="hard", mins=50,
title="Jenkins и CI-серверы: расследование компромисса",
tags="[forensics, web, jenkins, cicd, rce]",
prereq="[forensics-web-forensics]",
summary="Как расследовать компромисс Jenkins: скрипт-консоль, креденшелы, джобы и следы выполнения команд.",
body=r'''
## Вопрос, с которого всё начинается

Jenkins даёт **RCE по дизайну** (скрипт-консоль, пайплайны). Компромисс CI-сервера
критичен: у него доступ к коду, секретам и продакшену. Разберём.

## Наш пример: Jenkins

## Шаг 1: доступ и логи

```
$ ls /var/log/jenkins/
jenkins.log
$ grep -i 'script\|groovy' jenkins.log | tail
```

Jenkins логирует запуск скриптов и джоб.

## Шаг 2: скрипт-консоль

`/script` позволяет выполнять Groovy на сервере:

```
$ grep 'script' /var/log/jenkins/access_log* | tail
203.0.113.5 - "POST /script HTTP/1.1" 200
```

Внешний доступ к `/script` — почти наверняка RCE.

## Шаг 3: креденшелы

Jenkins хранит секреты. Проверь:

- список credentials (кто добавлял);
- `config.xml` джоб (команды);
- историю изменений джоб.

```
$ ls /var/lib/jenkins/credentials.xml
```

## Шаг 4: джобы

Злоумышленник может создать джобу, выполняющую команды:

```
$ grep -rl 'curl\|bash -i' /var/lib/jenkins/jobs/*/config.xml
```

## Шаг 5: что искать

- обращения к `/script`, `/manage`;
- новые/изменённые джобы;
- утечку креденшелов;
- команды, тянущие внешние скрипты;
- новые пользователи/API-токены.

## Что мы теперь знаем

- Jenkins = RCE по дизайну (Groovy).
- `/script` и `/manage` — опасные эндпоинты.
- Креденшелы хранятся на сервере.
- Джобы содержат команды.
- Ищем скрипты, джобы, токены.

## Если не сработало

- Логи усечены? Смотри audit-плагин.
- Креденшелы зашифрованы? Нужен ключ Jenkins.
- Нужен контекст? Читай историю SCM.

## Квиз

Проверь себя.

```quiz
- question: Почему Jenkins опасен при компромиссе?
  options:
    - 'он медленный'
    - 'даёт RCE через скрипт-консоль и доступ к секретам'
    - 'он красивый'
    - 'он шифрует'
  answer: 1
  explanation: 'Groovy-скрипты выполняются на сервере с его правами.'
- question: Какой эндпоинт даёт RCE?
  options:
    - '/favicon'
    - '/script (Groovy)'
    - '/robots.txt'
    - '/index'
  answer: 1
  explanation: 'Скрипт-консоль выполняет произвольный Groovy.'
- question: Где искать креденшелы Jenkins?
  options:
    - 'в /etc/passwd'
    - 'в credentials.xml'
    - 'в браузере'
    - 'в шрифтах'
  answer: 1
  explanation: 'Jenkins хранит креденшелы в своём каталоге.'
- question: Признак компромисса CI?
  options:
    - 'успешная сборка'
    - 'новые джобы и команды, тянущие внешние скрипты'
    - 'много логов'
    - 'долгая сборка'
  answer: 1
  explanation: 'Внедрённые джобы выполняют код атакующего.'
```
''')

LESSONS["web-server-logs"] = dict(
parent="forensics-web-attack", order=1, diff="medium", mins=45,
title="Логи веб-сервера: чтение, фильтрация и аномалии",
tags="[forensics, web, logs, access-log, apache, nginx]",
prereq="[forensics-web-forensics]",
summary="Как читать access/error-логи веб-сервера: формат, фильтрация, выявление атак и корреляция.",
body=r'''
## Вопрос, с которого всё начинается

Веб-сервер оставил гигабайты `access.log`. Где среди них атака? Нужен метод, а не
перелистывание. Разберём.

## Наш пример: access.log

## Шаг 1: формат

Стандарт (combined):

```
$ tail -1 /var/log/nginx/access.log
203.0.113.5 - - [14/Jan/2026:03:20:00 +0000] "GET /admin.php?id=1 HTTP/1.1" 200 1234 "-" "sqlmap/1.7"
```

Поля: IP, время, запрос, статус, размер, referer, **User-Agent**. UA `sqlmap` — уже
сигнал.

## Шаг 2: фильтрация

```
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
  9000 203.0.113.5
```

Один IP с 9000 запросами — брутфорс/сканирование.

## Шаг 3: ищем атаки

```
$ grep -iE 'union.*select|<script|\.\./|/etc/passwd' access.log | head
```

Паттерны SQLi, XSS, path traversal видны прямо в URL.

```
$ grep -E ' (4[0-9]{2}|5[0-9]{2}) ' access.log | wc -l
```

## Шаг 4: ошибки

`error.log` содержит детали:

```
$ tail -3 /var/log/nginx/error.log
... PHP Fatal error: ... in /var/www/.../shell.php
```

Ошибки выдают путь к шеллу.

## Шаг 5: корреляция

- сопоставь IP с другими логами (auth, firewall);
- найди первый запрос атакующего (точка входа);
- проверь, что было загружено (POST на upload).

## Что мы теперь знаем

- Формат: IP, время, запрос, статус, UA.
- Агрегация по IP выявляет брутфорс.
- Паттерны атак видны в URL.
- error.log выдаёт пути и ошибки.
- Корреляция даёт точку входа.

## Если не сработало

- Логи ротированы? Проверь `.1`, `.gz`.
- Нет access.log? Смотри логи прокси/шлюза.
- Нужны тела POST? Включи отдельное логирование.

## Квиз

Проверь себя.

```quiz
- question: Что содержит access.log?
  options:
    - 'только ошибки'
    - 'IP, время, запрос, статус, UA'
    - 'пароли'
    - 'обои'
  answer: 1
  explanation: 'Combined-формат фиксирует запрос и клиента.'
- question: Как найти брутфорс?
  options:
    - 'по цвету'
    - 'агрегацией по IP (uniq -c)'
    - 'по размеру'
    - 'никак'
  answer: 1
  explanation: 'Один IP с массой запросов выделяется агрегацией.'
- question: Что искать в error.log?
  options:
    - 'погоду'
    - 'пути к файлам и ошибки PHP'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Ошибки раскрывают пути, включая шеллы.'
- question: Что даёт корреляция логов?
  options:
    - 'красоту'
    - 'точку входа и связь с другими событиями'
    - 'ускорение'
    - 'шифрование'
  answer: 1
  explanation: 'Сопоставление логов восстанавливает цепочку атаки.'
```
''')

LESSONS["web-webshell"] = dict(
parent="forensics-web-attack", order=2, diff="hard", mins=50,
title="Веб-шеллы: поиск, анализ и следы",
tags="[forensics, web, webshell, php, jsp, detection]",
prereq="[forensics-web-forensics]",
summary="Как находить и анализировать веб-шеллы: признаки, обфускация, места размещения и связанные артефакты.",
body=r'''
## Вопрос, с которого всё начинается

На сервере есть веб-шелл — файл, дающий удалённое управление через HTTP. Его нужно
найти, понять и связать с активностью. Разберём.

## Наш пример: PHP-шелл

## Шаг 1: где искать

Шеллы прячут в:

- `uploads/` (загружаемые файлы);
- изменённых темах/плагинах;
- `images/`, `cache/` (маскировка);
- корне каталога с случайным именем.

```
$ find /var/www -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' \) -newermt '2026-01-14 03:00'
```

## Шаг 2: паттерны

Типичные функции:

```
$ grep -rEn 'eval\(|assert\(|system\(|exec\(|passthru\(|base64_decode\(|preg_replace.*/e' /var/www/
```

`eval` + `base64_decode` — почти наверняка шелл.

## Шаг 3: обфускация

Шеллы обфусцируют:

- base64/gzinflate;
- конкатенация строк;
- динамические имена функций (`$f='sys'.'tem'`).

```
$ grep -rE '\$[a-z]+\(.*\$_(GET|POST|REQUEST)' /var/www/ | head
```

Вызов функции с параметром из запроса — классический шелл.

## Шаг 4: следы активности

Найди, что шелл делал:

```
$ grep -E 'shell\.php|/upload' /var/log/nginx/access.log | tail
```

И сопоставь с созданными файлами, процессами, сетевыми соединениями.

## Шаг 5: что искать

- файлы с eval/base64;
- вызовы системных функций с user-input;
- свежие файлы в webroot;
- POST-запросы к подозрительным путям;
- исходящие соединения от веб-сервера.

## Что мы теперь знаем

- Шеллы прячут в uploads/темах/маскировке.
- Паттерны: eval, base64_decode, system+user-input.
- Обфускация — base64, конкатенация, динамические имена.
- Логи показывают использование шелла.
- Связываем файл с активностью.

## Если не сработало

- Шелл закодирован? Декодируй base64/gzip.
- Нет доступа к файлам? Ищи по логам и процессам.
- Нужен масштаб? Используй YARA-правила для шеллов.

## Квиз

Проверь себя.

```quiz
- question: Где чаще прячут веб-шеллы?
  options:
    - 'в /etc'
    - 'в uploads/ и изменённых файлах webroot'
    - 'в /boot'
    - 'в шрифтах'
  answer: 1
  explanation: 'Uploads и файлы приложений — типичные места.'
- question: Какой паттерн выдаёт шелл?
  options:
    - 'echo'
    - 'eval/system с параметром из запроса'
    - 'var_dump'
    - 'print'
  answer: 1
  explanation: 'Выполнение кода/команд по пользовательскому вводу — суть шелла.'
- question: Зачем шеллы обфусцируют?
  options:
    - 'для красоты'
    - 'чтобы скрыть код от детекции'
    - 'для скорости'
    - 'для сети'
  answer: 1
  explanation: 'Base64/конкатенация усложняют обнаружение.'
- question: Как связать шелл с активностью?
  options:
    - 'по логам доступа и процессам'
    - 'по цвету'
    - 'по обои'
    - 'никак'
  answer: 0
  explanation: 'Логи и процессы показывают использование шелла.'
```
''')

LESSONS["web-oracle-db"] = dict(
parent="forensics-web-attack", order=3, diff="hard", mins=50,
title="Oracle-СУБД: аудит и следы компромисса",
tags="[forensics, web, oracle, database, audit]",
prereq="[forensics-web-forensics]",
summary="Как расследовать компромисс Oracle: аудит-логи, привилегии, экспорт данных и следы эксплуатации.",
body=r'''
## Вопрос, с которого всё начинается

Корпоративная СУБД Oracle скомпрометирована: украдены данные или выполнен код. Oracle
умеет вести **аудит**, но часто он выключен. Разберём.

## Наш пример: Oracle

## Шаг 1: аудит

Проверь, включён ли аудит:

```sql
SELECT value FROM v$parameter WHERE name = 'audit_trail';
```

`DB` означает запись в `aud$`; `NONE` — аудит выключен.

```
SELECT username, action_name, obj_name, timestamp
FROM dba_audit_trail ORDER BY timestamp DESC FETCH FIRST 5 ROWS ONLY;
```

## Шаг 2: привилегии

Компромисс часто идёт через лишние права:

```sql
SELECT grantee, privilege FROM dba_sys_privs WHERE grantee NOT IN ('SYS','SYSTEM');
```

Учётки с `DBA` или `CREATE ANY PROCEDURE` — потенциальные точки.

## Шаг 3: следы эксплуатации

- `UTL_FILE` (запись файлов);
- `DBMS_SCHEDULER` (задачи);
- Java-хранимые процедуры (RCE);
- `EXECUTE IMMEDIATE` в коде.

```sql
SELECT object_name, created FROM dba_objects
WHERE object_type='PROCEDURE' AND created > SYSDATE - 1;
```

Новая процедура — возможный бэкдор.

## Шаг 4: экспорт данных

Массовое чтение таблиц (эксфильтрация) видно в аудите:

```sql
SELECT username, COUNT(*) FROM dba_audit_trail
WHERE action_name='SELECT' GROUP BY username;
```

## Шаг 5: что искать

- выключенный аудит (сам по себе признак);
- новые учётки/привилегии;
- новые процедуры/задачи;
- массовые SELECT;
- доступ к чувствительным таблицам;
- сетевые соединения к БД.

## Что мы теперь знаем

- Oracle ведёт аудит (если включён).
- Лишние привилегии — путь компромисса.
- UTL_FILE/DBMS_SCHEDULER/Java — векторы RCE.
- Массовый SELECT = эксфильтрация.
- Ищем новые объекты и права.

## Если не сработало

- Аудит выключен? Смотри сеть и логи ОС.
- Нужны детали? Проверь unified audit (12c+).
- Нужен процесс? Анализируй память Oracle.

## Квиз

Проверь себя.

```quiz
- question: Что показывает audit_trail?
  options:
    - 'версию ОС'
    - 'куда пишется аудит Oracle'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'audit_trail определяет место записи аудита (DB/NONE/OS).'
- question: Какие пакеты Oracle дают RCE/запись файлов?
  options:
    - 'SELECT'
    - 'UTL_FILE/DBMS_SCHEDULER/Java'
    - 'INSERT'
    - 'COMMIT'
  answer: 1
  explanation: 'Эти средства позволяют файловые/командные операции.'
- question: Признак эксфильтрации из Oracle?
  options:
    - 'один SELECT'
    - 'массовые SELECT с одной учётки'
    - 'обновление'
    - 'индекс'
  answer: 1
  explanation: 'Аномально частые чтения указывают на вывод данных.'
- question: Что подозрительно в объектах БД?
  options:
    - 'старые таблицы'
    - 'новые процедуры/задачи'
    - 'индексы'
    - 'вьюхи'
  answer: 1
  explanation: 'Свежие процедуры могут быть бэкдором.'
```
''')

emit(HUBS, LESSONS)
