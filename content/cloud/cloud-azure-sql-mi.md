---
id: cloud-azure-sql-mi
title: 'Azure SQL / Managed Instance: firewall, AAD-auth и exfil'
category: cloud
parent: cloud-azure-services-deep
difficulty: hard
order: 5
tags: [cloud, azure, sql, managed-instance, aad, firewall, exfil]
prerequisites: [cloud-azure-ai-services]
useful_for:
  - 'Пентест Azure SQL'
  - 'Exfil данных из БД'
  - 'CTF cloud'
estimated_minutes: 45
summary: 'Azure SQL Database и Managed Instance: firewall и private endpoint, SQL-логины и Entra-аутентификация, роли, exfil через linked servers и OPENROWSET, managed identity базы. Сквозной пример — строка подключения SQL-логина и обход firewall.'
lab:
  kind: shell
  title: 'Практика: строка подключения Azure SQL'
  toolset: [core, python]
  workdir: /home/student/azsql
  files: [task.md, conn.txt, notes.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Изучи строку подключения: `cat conn.txt` — какие сервер, база и логин?'
    - 'Обрати внимание, что подключение блокирует firewall, а не пароль.'
    - 'Флаг — в notes.md: найди строку `nto` и запиши её в found.txt.'
---

## Вопрос, с которого всё начинается

Ты находишь строку подключения к Azure SQL: сервер, база, логин, пароль. Вопрос: пустит ли firewall, что даёт этот логин, как он соотносится с Entra-аутентификацией, и можно ли через базу вытащить данные или дотянуться до других ресурсов. Начнём с того, что у Azure SQL две системы аутентификации — SQL-логины и Entra ID — и firewall, который проверяет источник.

## Что такое Azure SQL и Managed Instance

Azure SQL Database — управляемая база (PaaS), где ты не видишь ОС. Managed Instance — почти полный SQL Server в облаке, с доступом к сети и агентами. Обе поддерживают два пути входа: SQL-логины (логин/пароль внутри базы) и Entra ID (пользователь или managed identity). Плюс есть firewall на уровне сервера и базы, private endpoints и «Allow Azure services». Это ключевой момент: даже с валидным логином подключение может не пройти из-за firewall.

## Сквозной пример: строка подключения

Смотрим утёкший конфиг:
```
$ cat conn.txt
Server=tcp:acme-sql.database.windows.net,1433;Database=orders;
User ID=appuser;Password=EXAMPLEnotreal;
$ sqlcmd -S acme-sql.database.windows.net -U appuser -P EXAMPLEnotreal -d orders -Q "SELECT TOP 1 name FROM sys.tables"
Sqlcmd: Error: ... Reason: An instance-specific error occurred while establishing a connection. The server was not found or was not accessible.
```
Ошибка не про пароль, а про доступность — сработал firewall. Дальше проверяем, есть ли разрешённый источник или private endpoint.

## Firewall и private endpoint

Firewall Azure SQL — это список правил: IP-диапазоны, «Allow Azure services», правила уровня базы. Если правило разрешает твой источник, подключение пройдёт. Private endpoint вообще убирает публичный доступ, и тогда нужен доступ из сети. Атакующему важно: (1) firewall — это не аутентификация, он лишь ограничивает источник; (2) «Allow Azure services» разрешает очень много; (3) при private endpoint нужен pivot в ту же сеть. Проверяй firewall отдельно от логина.

## SQL-логины и Entra

SQL-логин живёт внутри базы и не связан с Entra. Entra-пользователь входит по токену, и его права определяются ролями (db_owner, db_datareader, custom) и Entra-группами. Managed identity сервиса может быть добавлена как пользователь базы — тогда сервис (App Service, Function) ходит в базу без пароля. Для атакующего это означает: пароль в конфиге — лишь один путь; если есть доступ к сервису с managed identity, база открыта без пароля.

## Роли и эскалация

Права внутри базы: db_owner (полный контроль базы), db_securityadmin, db_ddladmin и т. д. На уровне сервера — loginmanager, securityadmin. Если логин имеет право создавать пользователей или менять роли, он может эскалировать внутри базы. Плюс: если у логина есть права на несколько баз, он читает их все. Всегда перечисляй базы и роли — «маленький» логин часто имеет доступ к нескольким базам.

## Exfil и связанные серверы

Вытащить данные можно напрямую (SELECT), через bcp/BULK, через OPENROWSET к внешнему хранилищу (если база умеет), или через linked servers (в Managed Instance). Если база имеет managed identity с доступом к Storage, можно выгрузить данные в блоб. Плюс: если база — часть гибридной среды, из неё иногда видно другие серверы. Смотри не только на «читаю таблицы», но и на «куда база может писать».

## Типовые мисконфиги

| Мисконфиг | Последствие | Как искать |
|---|---|---|
| Allow Azure services | широкий доступ | firewall сервера |
| Пароль в конфиге/репо | вход в базу | grep connection string |
| db_owner у приложения | избыточные права | роли базы |
| Нет private endpoint | доступ из интернета | networking |
| Managed identity с правами на Storage | exfil в блоб | RBAC identity |
| Нет аудита | незаметный exfil | auditing базы |

## Полный прогон: от строки подключения к данным

Шаги. Первый: проверить firewall (подключение проходит?). Второй: подтвердить логин. Третий: перечислить базы и роли. Четвёртый: читать данные. Пятый: проверить права на запись и внешние источники. Шестой: выгрузить нужное (напрямую или в хранилище). Седьмой: закрепиться (новый логин) и учесть аудит.

## Инструменты и команды

Полезны: `sqlcmd`, `mssql-cli`, `impacket-mssqlclient`, `az sql server firewall-rule list`, `az sql db list`, T-SQL (`SELECT`, `sys.databases`, `sys.database_principals`). Для Entra-входа — токен и `sqlcmd --authentication-method ActiveDirectoryAccessToken`. Для exfil — `bcp`, `OPENROWSET`, linked servers.

## OPSEC и детект

Azure SQL пишет аудит и логи подключений; неудачные попытки видны. Массовая выгрузка заметна по объёму и по метрикам. Тихий сценарий — выборочные запросы к нужным таблицам. Если включён Defender for SQL, подозрительные паттерны доступа дают алерт.

## Частые вопросы

Пароль верный, но подключения нет — почему? Скорее всего firewall или private endpoint. Даёт ли SQL-логин доступ к другим базам? Если он там есть. Помогает ли Entra? Да, как второй путь и как managed identity. Можно ли выгрузить наружу? Если разрешены внешние источники. Оставляет ли след? Да, аудит базы.

## Что не сработает

Firewall без разрешённого источника не пустит. Private endpoint без сети не даст подключиться. Логин без прав не прочитает данные. И без внешних источников exfil останется ручным SELECT.

## Разбор кейса: пароль есть, доступа нет

История из практики. Пентестер нашёл валидную строку подключения к Azure SQL, но firewall отклонял все попытки. Оказалось, сервер разрешал только «Allow Azure services» и private endpoint. Он поднял функцию в том же тенанте (чьи исходящие IP попадали под правило) и оттуда подключился, а у логина были права db_owner. Урок: firewall проверяет источник, а не пользователя; при доступе к сервису в Azure правило «Allow Azure services» часто и есть ключ.

## Что мы теперь знаем

1. У Azure SQL две аутентификации: SQL-логины и Entra ID (включая managed identity).
2. Firewall и private endpoint ограничивают источник и проверяются отдельно от логина.
3. «Allow Azure services» — широкое правило, часто открывающее доступ.
4. Права базы (db_owner и др.) определяют чтение, запись и эскалацию.
5. Exfil возможен напрямую и через внешние источники под identity базы.

## Квиз

Проверь себя.

```quiz
- question: "Пароль верный, но подключение не проходит. Что проверить?"
  options:
    - "Firewall и private endpoint"
    - "Версию браузера"
    - "Цвет темы"
    - "Размер базы"
  answer: 0
  explanation: "Firewall проверяет источник и работает независимо от аутентификации."
- question: "Какие два пути входа есть у Azure SQL?"
  options:
    - "SQL-логины и Entra ID"
    - "Только пароль"
    - "Только сертификат"
    - "Только токен"
  answer: 0
  explanation: "Azure SQL поддерживает SQL-логины и Entra-аутентификацию, включая managed identity."
- question: "Что даёт managed identity сервиса в базе?"
  options:
    - "Вход в базу без пароля"
    - "Только чтение схемы"
    - "Доступ к DNS"
    - "Ничего"
  answer: 0
  explanation: "Managed identity добавляется как пользователь базы и ходит без пароля."
- question: "Почему правило Allow Azure services опасно?"
  options:
    - "Оно разрешает доступ множеству сервисов Azure"
    - "Оно отключает аудит"
    - "Оно шифрует канал"
    - "Оно удаляет базу"
  answer: 0
  explanation: "Правило открывает базу для широкого набора ресурсов Azure."
```

## Куда дальше

Это завершает подмодуль сервисов Azure. А пока главное: в Azure SQL firewall и аутентификация — разные вещи, и побеждает тот, кто проверит оба.

## Где пригодится

- Пентест баз данных в облаке.
- Exfil данных из managed-баз.
- CTF-задачи категории cloud.
