---
id: network-db-protocols
title: "Протоколы баз данных на проводе: MySQL, PostgreSQL, MSSQL"
category: network
parent: network-module-appprotos
difficulty: medium
order: 1
tags: [network, database, mysql, postgresql, mssql, tds, auth]
prerequisites: [network-module-appprotos, network-service-enum]
useful_for:
  - "CTF Network (БД-даммы)"
  - "Пентест: перехват и брутфорс БД"
  - "Работа (SOC): детект БД-аномалий"
estimated_minutes: 50
summary: "MySQL, PostgreSQL и MSSQL на проводе: handshake, методы аутентификации, что видно без TLS, как перехватить учётные данные и как защитить базы данных шифрованием и сегментацией."
---

Базы данных — лакомая цель: в них учётные данные, персональные данные и бизнес-логика. Их протоколы на проводе раскрывают версию, методы аутентификации и (без TLS) содержимое. Урок продолжает [`network-module-appprotos`](network-module-appprotos) и опирается на [`network-service-enum`](network-service-enum).

## MySQL/MariaDB: handshake и auth

MySQL-соединение начинается с **Server Greeting**: версия сервера, thread id, capability flags, salt (challenge). Клиент отвечает логином и хэшем пароля (mysql_native_password — SHA1-based challenge/response; caching_sha2 — новее).

```text
Server -> Client: protocol version, server version, capabilities, auth plugin, salt
Client -> Server: username, auth response, database
```

```bash
# Идентификация и версия
nmap -sV -p 3306 10.0.0.1
nmap -p 3306 --script mysql-info,mysql-enum 10.0.0.1
# Подключение
mysql -h 10.0.0.1 -u root -p
```

## PostgreSQL: StartupMessage и методы auth

PostgreSQL начинает с **StartupMessage** (клиент), затем сервер выбирает метод аутентификации: `trust`, `password` (cleartext!), `md5`, `scram-sha-256`. Метод `password` отправляет пароль **в открытом виде**.

```bash
# Идентификация
nmap -p 5432 --script pgsql-brute 10.0.0.1
# Подключение
psql "host=10.0.0.1 user=postgres dbname=postgres"
# Захват: искать метод auth и пароль
tshark -r cap.pcap -Y 'pgsql' -V | grep -iE "authentication|password" | head
```

## MSSQL: TDS и pre-login

**MSSQL** использует **TDS** (Tabular Data Stream). Pre-login-обмен раскрывает версию, порт, инстанс, шифрование. Аутентификация — SQL-логин или Windows (NTLM/Kerberos).

```bash
# Pre-login info
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info 10.0.0.1
# Брутфорс (малый список)
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt 10.0.0.1
```

## Что видно без TLS

- **версии** серверов (и известные CVE);
- **методы аутентификации** (cleartext vs challenge);
- **имена БД и пользователей**;
- **SQL-запросы и результаты** (если нет TLS);
- **NTLM-хэши** (при Windows-auth и релее).

```bash
# Перехватить MySQL-логин
tshark -r cap.pcap -Y 'mysql' -T fields -e mysql.user -e mysql.schema | head
# PostgreSQL-запросы
tshark -r cap.pcap -Y 'pgsql' -T fields -e pgsql.query | head
```

## Атаки

- **Перехват кред** — без TLS пароли/хэши видны;
- **Брутфорс** — слабые пароли БД;
- **NTLM relay** — при Windows-auth (см. `network-ntlm-relay`);
- **Эксплуатация CVE** — версии серверов;
- **Unauthenticated access** — trust/пустой пароль;
- **UDF/RCE** — через SQL (см. svc-database).

```bash
# Проверить trust-аутентификацию PostgreSQL (лаборатория)
psql "host=10.0.0.1 user=postgres" -c 'select version();'
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `nmap` (mysql-*, pgsql-*, ms-sql-*) | идентификация/брутфорс |
| `mysql`/`psql`/`sqlcmd` | клиенты |
| `tshark` | разбор протоколов |
| `netexec mssql` | MSSQL-проверки |
| `impacket` | MSSQL/NTLM |

```bash
# netexec по MSSQL
netexec mssql 10.0.0.1 -u user -p pass
# tshark: сводка
tshark -r cap.pcap -Y 'mysql || pgsql || tds' -T fields -e _ws.col.Protocol | sort | uniq -c
```

## Защита

| Мера | Против чего |
|---|---|
| TLS для БД (require SSL) | перехват |
| Сильные пароли + ротация | брутфорс |
| Не слушать наружу (bind localhost) | экспозиция |
| Сегментация БД | lateral movement |
| SCRAM вместо password/md5 | перехват хэшей |
| Обновления СУБД | CVE |
| Мониторинг запросов | детект |

## Частые ошибки

- **Оставлять БД на внешнем интерфейсе** — экспозиция.
- **`password`-auth в PostgreSQL** — пароль в открытом виде.
- **Игнорировать pre-login MSSQL** — раскрытие версии.
- **Не включать TLS** — креды/данные видны.
- **Брутить мега-словарём** — лок-аут/шум.
- **Забывать про NTLM-relay** — Windows-auth опасен.
- **Не мониторить SQL** — атаки невидимы.

## Что дальше / решение

После БД-протоколов переходите к [`network-tls-fingerprint`](network-tls-fingerprint). Для эксплуатации БД — svc-database и [`network-service-enum`](network-service-enum).

## Практика: перехват БД-трафика

```bash
# 1. Идентификация
nmap -sV -p 3306,5432,1433 10.0.0.1
# 2. MySQL: логин и схема из дампа
tshark -r cap.pcap -Y 'mysql' -T fields -e mysql.user -e mysql.schema | head
# 3. PostgreSQL: запросы
tshark -r cap.pcap -Y 'pgsql' -T fields -e pgsql.query | head
# 4. MSSQL: pre-login
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info 10.0.0.1
# 5. Проверить trust/пустой пароль (лаборатория)
psql "host=10.0.0.1 user=postgres" -c 'select version();'
```

## Сравнение БД-протоколов

| СУБД | Порт | Протокол | Auth | Cleartext-риск |
|---|---|---|---|---|
| MySQL | 3306 | MySQL wire | native/caching_sha2 | challenge |
| PostgreSQL | 5432 | Frontend/Backend | trust/password/md5/scram | `password` = cleartext |
| MSSQL | 1433 | TDS | SQL/NTLM/Kerberos | pre-login метаданные |
| Oracle | 1521 | TNS | различные | зависит |
| MongoDB | 27017 | MongoDB wire | SCRAM | без auth по умолчанию |

## Итог по БД-протоколам

БД-протоколы раскрывают больше, чем хотелось бы: версии, методы аутентификации, имена пользователей и (без TLS) запросы. Основные векторы — перехват кред, брутфорс, NTLM-relay и эксплуатация CVE по версии. Защита: обязательный TLS, SCRAM вместо password/md5, запрет внешнего прослушивания, сегментация и мониторинг запросов. Для пентеста — сначала проверьте, не слушает ли БД наружу и нет ли trust-аутентификации.

## Модель угроз БД в сети

Базы данных часто оказываются «внутри», и на них не распространяют те же требования, что на веб. Отсюда типичные проблемы:

- **прослушивание 0.0.0.0** — БД доступна из всей сети, а не только приложению;
- **trust/password-auth** — вход без пароля или с cleartext-паролем;
- **слабые пароли** администраторов БД;
- **отсутствие TLS** — креды и данные видны в дампе;
- **общие учётки** — нельзя атрибутировать действия.

```bash
# Проверить, слушает ли БД наружу (с точки атакующего)
nmap -Pn -p 3306,5432,1433,27017,6379 10.0.0.0/24 --open
# Проверить trust (PostgreSQL)
psql "host=10.0.0.1 user=postgres" -c 'select 1;' 2>&1 | head
# Redis/Mongo без пароля
redis-cli -h 10.0.0.1 ping
mongosh --host 10.0.0.1 --eval 'db.runCommand({ping:1})'
```

## Итоговый вывод

БД-протоколы раскрывают версии, методы аутентификации и (без TLS) содержимое. Практический чек-лист защиты: **bind на localhost**, **обязательный TLS**, **SCRAM/сильные пароли**, **сегментация**, **отдельные учётки** и **мониторинг запросов**. Для пентеста первым делом проверяйте доступность БД из сети и наличие trust/безпарольного доступа — это самые частые и самые критичные находки.

## Заметка о Redis, MongoDB и «NoSQL»-портах

Помимо классических СУБД, часто открыты Redis (6379) и MongoDB (27017) — оба по умолчанию **без аутентификации**. Это не «протокол на проводе» в строгом смысле, но те же грабли: сервис слушает наружу и не требует пароля.

```bash
# Redis без пароля
redis-cli -h 10.0.0.1 ping
redis-cli -h 10.0.0.1 config get dir
# MongoDB без auth
mongosh --host 10.0.0.1 --eval 'db.adminCommand({listDatabases:1})'
```

Вывод: при аудите БД всегда проверяйте «NoSQL»-порты. Открытый Redis даёт RCE через запись файлов, открытый MongoDB — прямой доступ к данным. Защита — bind на localhost, аутентификация и сегментация.

## Квиз

```quiz
- question: "Какой порт у MySQL по умолчанию?"
  options:
    - "3306"
    - "5432"
    - "1433"
    - "1521"
  answer: 0
  explanation: "MySQL — 3306, PostgreSQL — 5432, MSSQL — 1433."
- question: "Какой метод PostgreSQL отправляет пароль открыто?"
  options:
    - "password"
    - "scram-sha-256"
    - "md5"
    - "trust"
  answer: 0
  explanation: "Метод password передаёт пароль в cleartext."
- question: "Какой протокол использует MSSQL?"
  options:
    - "TDS"
    - "MySQL wire"
    - "RFB"
    - "TNS"
  answer: 0
  explanation: "MSSQL общается по Tabular Data Stream."
- question: "Что раскрывает pre-login MSSQL?"
  options:
    - "Версию, инстанс, шифрование"
    - "Пароль"
    - "Сертификат"
    - "Таблицы"
  answer: 0
  explanation: "Pre-login даёт метаданные сервера."
- question: "Какая защита закрывает перехват БД-кред?"
  options:
    - "Обязательный TLS для БД"
    - "Открыть порт наружу"
    - "password-auth"
    - "Отключить сегментацию"
  answer: 0
  explanation: "TLS шифрует аутентификацию и данные."
```

## Где пригодится

- **CTF:** задачи с БД-дампами и SQL.
- **Пентест:** перехват кред, брутфорс, relay.
- **SOC:** детект аномальных SQL-запросов.
- **Инженерия:** TLS, SCRAM, сегментация БД.
