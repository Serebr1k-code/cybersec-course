---
id: cloud-azure-synapse
title: 'Azure Synapse Analytics: workspace, Spark и linked services'
category: cloud
parent: cloud-azure-services-deep
difficulty: hard
order: 2
tags: [cloud, azure, synapse, spark, adls, linked-service, exfil]
prerequisites: [cloud-azure-cosmos]
useful_for:
  - 'Пентест Azure'
  - 'Exfil данных из аналитики'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'Synapse Analytics: workspace, SQL/Spark-пулы, роль Synapse Administrator, доступ к ADLS Gen2 через managed identity и linked services, exfil через ноутбуки. Сквозной пример — ноутбук, читающий озеро данных под identity workspace.'
lab:
  kind: shell
  title: 'Практика: ноутбук Synapse и озеро данных'
  toolset: [core, python]
  workdir: /home/student/synapse
  files: [task.md, notebook.ipynb.txt, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Изучи ноутбук: `cat notebook.ipynb.txt` — найди путь abfss:// к озеру.'
    - 'Определи, под чьей identity читает код.'
    - 'Флаг — в notes.md: найди строку `nto` и запиши её в found.txt.'
---

## Вопрос, с которого всё начинается

Ты получаешь доступ к Synapse Studio или к утёкшему токену workspace. Вопрос: какие данные видит workspace, чьими правами он ходит в хранилище и можно ли через ноутбук вытащить содержимое озера данных? Ключевая идея: Synapse — это не просто SQL-движок, а платформа с managed identity, которая часто имеет доступ к ADLS Gen2, и через неё данные читаются в обход прав пользователя.

## Что такое Synapse Analytics

Synapse — аналитическая платформа Azure: SQL-пулы (выделенные и serverless), Spark-пулы, конвейеры, ноутбуки и интеграция с Power BI. Всё живёт внутри «workspace», у которого есть управляемая identity. Workspace читает и пишет в «озеро данных» — хранилище ADLS Gen2 — от имени своей identity или через linked services. Для атакующего важно: права в control-plane (ARM) и права на данные (SQL/Spark/ADLS) — разные, и workspace часто имеет широкий доступ к данным.

## Сквозной пример: ноутбук Synapse

Смотрим ноутбук, который читает озеро:
```
df = spark.read.parquet("abfss://data@acmelake.dfs.core.windows.net/raw/orders")
df.show(5)
```
Запись `abfss://` указывает на ADLS Gen2. Ноутбук исполняется на Spark-пуле под identity workspace, поэтому он видит всё, к чему у workspace есть права, — независимо от того, что разрешено твоему пользователю. Дальше проверим, что за данные и есть ли среди них секреты.

## Роли и права workspace

У Synapse есть роли: Synapse Administrator (полный контроль workspace), Synapse SQL Administrator, Synapse Artifact User, Synapse Compute Operator. Плюс — роли Azure RBAC на самом ресурсе. Роль Artifact User даёт читать артефакты (ноутбуки, скрипты, конвейеры), в которых часто лежат строки подключения и имена хранилищ. Роль Compute Operator позволяет запускать код на пулах. Комбинация «читать артефакты + запускать» = исполнение кода под identity workspace.

## Доступ к озеру данных

Озеро данных — это ADLS Gen2 (то есть Storage Account с иерархическим namespace). Доступ к нему выдают через RBAC (Storage Blob Data Reader/Contributor) на аккаунт или контейнер, ACL-и на путях, или через linked service с хранимым секретом. Workspace обычно имеет собственную identity с правами на озеро. Значит, любой код, исполняемый в workspace, читает данные, к которым у пользователя прямого доступа нет. Это и есть основной вектор exfil.

## Linked services и секреты

Linked service — это сохранённое подключение Synapse к внешнему сервису (другая база, хранилище, Key Vault). Оно аутентифицируется managed identity, ключом или секретом из Key Vault. Если linked service использует managed identity, компромисс workspace даёт доступ ко всем его источникам сразу. Если хранимый ключ — он лежит в workspace и может быть прочитан тем, кто может читать артефакты. Всегда перечисляй linked services: это карта того, куда workspace может ходить.

## SQL-пулы и serverless

Serverless SQL-пул позволяет запрашивать файлы прямо в озере (`OPENROWSET`). Выделенный SQL-пул хранит данные в собственных базах. В обоих случаях доступ к данным определяется правами на хранилище и логином SQL. Serverless особенно интересен для exfil: он читает файлы по пути и не требует копирования данных в базу. Если у тебя есть право запускать SQL в workspace, ты можешь выбрать файлы из озера, к которым у тебя как у пользователя нет доступа.

## Типовые мисконфиги

| Мисконфиг | Последствие | Как искать |
|---|---|---|
| Workspace identity с правами на всё озеро | exfil данных | RBAC на ADLS |
| Секреты в linked services | утечка кредов | linked services |
| Artifact User у широкого круга | чтение ноутбуков | роли Synapse |
| Открытый доступ к озеру | чтение извне | сеть ADLS |
| Секреты в ноутбуках | утечка | содержимое артефактов |
| Нет аудита запросов | незаметный exfil | логи workspace |

## Полный прогон: от workspace к данным

Шаги. Первый: получить доступ (портал, токен, SQL-логин). Второй: перечислить артефакты — ноутбуки и linked services. Третий: найти пути к озеру и имена хранилищ. Четвёртый: запустить ноутбук или serverless-запрос, читающий данные. Пятый: вытащить содержимое (или агрегаты, если объём велик). Шестой: закрепиться (создать ноутбук, linked service). Седьмой: подумать об аудите, потому что запросы логируются.

## Инструменты и команды

Полезны: `az synapse workspace list`, `az synapse role assignment list`, REST API Synapse, PySpark в ноутбуках (`spark.read`), serverless SQL (`OPENROWSET`, `sqlcmd`). Для ADLS — `az storage fs file list`, `azcopy`. Для чтения артефактов — REST `/notebooks`, `/linkedservices`.

## OPSEC и детект

Synapse пишет логи workspace и SQL-запросы; массовое чтение озера заметно. Запуск ноутбука оставляет артефакт и историю. Тихий сценарий — один serverless-запрос, выбирающий нужные столбцы, без копирования всего. Если в тенанте включён Defender и мониторинг ADLS, необычный доступ identity workspace к новым путям даёт алерт.

## Частые вопросы

Нужен ли доступ к ARM? Нет, если есть доступ к Synapse Studio или SQL-логин. Видит ли workspace все данные? Только то, к чему есть права у его identity. Помогают ли ACL? Да, но identity workspace часто включена в них. Можно ли читать без Spark? Да, serverless SQL. Что если linked service на Key Vault? Тогда нужен доступ к секрету в Key Vault.

## Что не сработает

Если identity workspace не имеет прав на хранилище, чтение не удастся. Private endpoint на озеро без доступа из workspace не даст сеть. Если артефакты недоступны, не будет и карты данных. И если в озере нет секретов, exfil даёт только данные, не креды.

## Разбор кейса: ноутбук как путь к озеру

История из практики. У аналитика была только роль Artifact User в Synapse, но workspace имел identity с правами Storage Blob Data Contributor на озеро. Аналитик изменил существующий ноутбук так, что тот начал читать конфиденциальные таблицы и печатать выборку. Так «только читатель артефактов» вытащил данные в обход прямых прав. Урок: смотри не на права пользователя, а на права identity, которая исполняет код.

## Что мы теперь знаем

1. Synapse исполняет код под identity workspace, у которой часто широкие права на озеро.
2. Control-plane и data-plane права в Synapse раздельны.
3. Linked services — карта доступов workspace и место хранения секретов.
4. Serverless SQL и Spark читают файлы озера в обход прав пользователя.
5. Запросы логируются, поэтому тихий exfil — точечный, а не «скачать всё».

## Квиз

Проверь себя.

```quiz
- question: "Под чьей identity исполняется код в Synapse?"
  options:
    - "Под identity workspace (managed identity)"
    - "Под identity пользователя всегда"
    - "Под identity Key Vault"
    - "Без identity"
  answer: 0
  explanation: "Код на пулах исполняется от имени workspace, чьи права могут быть шире пользовательских."
- question: "Что такое linked service?"
  options:
    - "Сохранённое подключение workspace к внешнему сервису"
    - "Роль Synapse"
    - "SQL-пул"
    - "Сетевой шлюз"
  answer: 0
  explanation: "Linked service описывает, куда и как workspace ходит за данными."
- question: "Почему serverless SQL удобен для exfil?"
  options:
    - "Читает файлы озера по пути без копирования в базу"
    - "Он отключает аудит"
    - "Он не имеет сети"
    - "Он только для чтения схемы"
  answer: 0
  explanation: "OPENROWSET выбирает данные прямо из файлов озера."
- question: "Что проверять в первую очередь в Synapse?"
  options:
    - "Артефакты и linked services"
    - "Цвет интерфейса"
    - "Размер окна"
    - "Версию браузера"
  answer: 0
  explanation: "Артефакты и подключения раскрывают пути к данным и секреты."
```

## Куда дальше

Дальше — Data Factory: конвейеры, которые двигают данные между сервисами и потому держат identity ко всем сразу. А пока главное: в Synapse код ходит данными от имени workspace, а не от твоего имени.

## Где пригодится

- Пентест Azure-аналитики.
- Exfil данных из озера через вычислительные сервисы.
- CTF-задачи категории cloud.
