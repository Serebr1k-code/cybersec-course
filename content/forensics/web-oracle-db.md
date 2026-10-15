---
id: web-oracle-db
title: 'Oracle-СУБД: аудит и следы компромисса'
category: forensics
parent: forensics-web-attack
difficulty: hard
order: 3
tags: [forensics, web, oracle, database, audit]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как расследовать компромисс Oracle: аудит-логи, привилегии, экспорт данных и следы эксплуатации.'
lab:
  kind: shell
  title: "Практика: аудит Oracle"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, oracle_audit.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Аудит Oracle (unified audit) логирует действия над объектами."
    - "DATA_PUMP export привилегированного пользователя — след выгрузки."
    - "`grep nto oracle_audit.txt > answer.txt`."
---

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

## Практический разбор: поиск бэкдора в схеме

Компромисс Oracle часто оставляет новые объекты в схеме. Ищем их по времени
создания и сравниваем с окном инцидента:

```sql
SELECT owner, object_name, object_type, created, last_ddl_time
FROM dba_objects
WHERE created > TIMESTAMP '2026-01-13 22:00:00'
ORDER BY created;
```

```
OWNER   OBJECT_NAME      OBJECT_TYPE   CREATED
APP     PROC_SYNC_CFG    PROCEDURE     2026-01-13 22:41:10
APP     TRG_AUDIT_HOOK   TRIGGER       2026-01-13 22:42:03
```

Триггер на таблице учёток, созданный сразу после подозрительной процедуры, —
классический бэкдор для перехвата логинов. Читаем исходник:

```sql
SELECT text FROM dba_source WHERE name='PROC_SYNC_CFG' ORDER BY line;
```

В теле ищем `EXECUTE IMMEDIATE`, `UTL_HTTP`, `UTL_FILE` — это векторы выполнения
команд и эксфильтрации.

## Unified Audit (12c+)

Начиная с 12c аудит ведётся в таблицах `UNIFIED_AUDIT_TRAIL`, и его сложнее
отключить незаметно:

```sql
SELECT event_timestamp, dbusername, action_name, object_name, client_ip
FROM unified_audit_trail
WHERE event_timestamp > TIMESTAMP '2026-01-13 22:00:00'
ORDER BY event_timestamp;
```

Поля `client_ip` и `dbusername` дают источник и субъект, а `action_name` —
операцию. Если unified audit включён, а старый `audit_trail` выключен, всё равно
есть след.

## Векторы RCE в Oracle

Oracle исторически даёт много путей к выполнению команд ОС. Основные:

| Вектор | Механизм | Признак |
|---|---|---|
| `UTL_FILE` | чтение/запись файлов | файлы в каталогах данных |
| `DBMS_SCHEDULER` | внешние задания | новые jobs |
| Java-процедуры | `dbms_java` | классы в схеме |
| `EXECUTE IMMEDIATE` | динамический SQL | в теле процедур |
| `DBMS_XSLPROCESSOR` | запись файлов | редко, но эффективно |

```sql
SELECT job_name, program_name, enabled FROM dba_scheduler_jobs
WHERE created > SYSDATE - 2;
```

Задание, вызывающее внешний скрипт или `dbms_java`, — явный индикатор.

## Сетевые следы: listener и TNS

Сетевые подключения к БД фиксируются не только в аудите, но и на уровне
listener и ОС:

```bash
$ lsnrctl status | grep -A3 'Service'
$ netstat -anp | grep 1521 | head
tcp 0 0 10.0.0.5:1521 203.0.113.5:51234 ESTABLISHED
```

Внешний IP, установивший соединение в момент инцидента, — точка входа. Логи
listener (`listener.log`) содержат время и адрес каждого подключения. Их
сопоставление с аудитом даёт полный путь: с какого адреса пришли, под какой
учёткой вошли и что делали.

## Чек-лист расследования Oracle

1. Проверь состояние аудита (`audit_trail`, unified audit).
2. Собери список учёток с избыточными привилегиями.
3. Найди новые объекты (процедуры, триггеры, задания) по времени.
4. Прочитай тела подозрительных объектов (`dba_source`).
5. Проверь массовые SELECT и доступ к чувствительным таблицам.
6. Изучи логи listener и сетевые соединения.
7. Оцени использование `UTL_FILE`/`DBMS_SCHEDULER`/Java.
8. Задокументируй цепочку и ограничения.

## Ограничения метода

- **Аудит может быть выключен.** Это само по себе признак, но лишает истории.
- **Аудит можно чистить.** Атакующий с правами DBA может удалять записи; ищи
  пропуски во времени.
- **Старые версии.** Unified audit доступен с 12c; на 11g полагайся на
  `aud$` и сеть.
- **Клиентские приложения.** Часть доступа идёт через приложение, а не напрямую
  в БД; логи приложения дополняют картину.

## Связь с ОС

СУБД — это процесс на хосте, поэтому расследование не ограничивается SQL:

- **Файлы данных.** `UTL_FILE` пишет в каталоги, доступные процессу Oracle.
- **Процессы.** `ps -ef | grep pmon` показывает экземпляры и их владельцев.
- **Логи ОС.** `/var/log/secure`, `syslog` фиксируют вход в ОС под учёткой
  `oracle`.
- **Планировщик ОС.** Внешние задания могут создавать cron-записи от `oracle`.

Связь БД и ОС артефактов даёт полную картину компромисса.

## Практический разбор: привилегии и пути эскалации

Компромисс Oracle редко начинается с DBA — чаще с лишнего права у приложения.
Ищем учётки, которые могут выполнять код или читать чужие таблицы:

```sql
SELECT grantee, privilege, admin_option
FROM dba_sys_privs
WHERE privilege IN ('CREATE ANY PROCEDURE','EXECUTE ANY PROCEDURE',
                    'CREATE ANY TRIGGER','ALTER SYSTEM')
ORDER BY grantee;
```

Учётка приложения с `CREATE ANY PROCEDURE` может создать процедуру, которая
выполнит `EXECUTE IMMEDIATE` и получит доступ к данным других схем. Проверяем
роли с широкими правами:

```sql
SELECT grantee, granted_role FROM dba_role_privs
WHERE granted_role IN ('DBA','IMP_FULL_DATABASE','EXP_FULL_DATABASE');
```

`IMP_FULL_DATABASE` позволяет импортировать объекты в чужие схемы — тоже путь
эскалации. Сопоставляя выданные права со временем инцидента, находят момент
повышения привилегий.

## Сравнение версий аудита

| Версия | Механизм | Отключение |
|---|---|---|
| 11g и раньше | `audit_trail` -> `aud$` | `ALTER SYSTEM SET audit_trail=NONE` |
| 12c+ | unified audit | сложнее, права `AUDIT_ADMIN` |
| 12c+ (смешанно) | оба механизма | каждый отдельно |

Если unified audit включён, а старый выключен, история сохраняется — и наоборот.
Проверяй оба, прежде чем утверждать, что следов нет.

## Частые заблуждения

- «Аудит включён по умолчанию» — на многих установках `audit_trail=NONE`, и
  истории операций просто нет.
- «DBA — единственный путь» — лишнее право приложения (`CREATE ANY PROCEDURE`)
  даёт код без DBA.
- «Массовый SELECT виден всегда» — без аудита эксфильтрация останется только в
  сетевом трафике.
- «Процедура безвредна» — тело процедуры может выполнять команды через
  `EXECUTE IMMEDIATE` или `dbms_java`.

## Что записать в отчёт

- Состояние аудита (включён/выключен, какой механизм).
- Учётки с избыточными привилегиями и время их выдачи.
- Новые объекты схемы (процедуры, триггеры, задания) с временем создания.
- Индикаторы RCE (`UTL_FILE`, `DBMS_SCHEDULER`, Java).
- Сетевые подключения (listener.log, `netstat`) с адресами.
- Ограничения: полнота аудита, доступность unified audit, логи приложения.

## Практический разбор: восстановление удалённых записей аудита

Атакующий с правами DBA может удалить записи из `aud$`, но данные часто
остаются в нераспределённых сегментах. Смотрим пропуски во времени:

```sql
SELECT TO_CHAR(timestamp,'YYYY-MM-DD HH24') h, COUNT(*)
FROM dba_audit_trail
GROUP BY TO_CHAR(timestamp,'YYYY-MM-DD HH24')
ORDER BY h;
```

Если в окне инцидента зияет «дыра» без записей, а вокруг активность есть — след
чистили. Тогда анализируют файлы данных ОС-средствами (`strings` по `aud$`
сегментам) или поднимают резервную копию БД. Даже после очистки остаются
косвенные следы: изменения `last_ddl_time` объектов и записи в alert log.

## Связь с экспортом данных

Массовая выгрузка данных — финальная цель компромисса. Её признаки:

- **`EXP`/`Data Pump`.** Запуск `expdp`/`exp` фиксируется в заданиях и логах.
- **`spool`/`UTL_FILE`.** Выгрузка через файловую систему.
- **Сетевой трафик.** Объём данных, ушедший к внешнему IP.
- **Большие SELECT.** Аудит покажет всплеск чтения чувствительных таблиц.

```sql
SELECT COUNT(*) FROM dba_audit_trail
WHERE action_name='SELECT' AND obj_name='CUSTOMERS'
  AND timestamp > SYSDATE - 1;
```

Сопоставление объёма чтения и исходящего трафика подтверждает эксфильтрацию.

## Что записать в отчёт

- Учётки и привилегии, задействованные в инциденте.
- Времена создания объектов и выполнения операций.
- Индикаторы RCE и использованные механизмы.
- Признаки и объём эксфильтрации.
- Ограничения: выключенный/очищенный аудит, отсутствие сетевых логов.

## Практический разбор: триггер-бэкдор

Триггер на таблице учёток может молча копировать логины и хэши в свою таблицу
при каждом входе. Ищем триггеры, созданные после инцидента:

```sql
SELECT owner, trigger_name, table_name, created
FROM dba_triggers
WHERE created > TIMESTAMP '2026-01-13 22:00:00';
```

Затем читаем тело:

```sql
SELECT trigger_body FROM dba_triggers WHERE trigger_name='TRG_AUDIT_HOOK';
```

Наличие `INSERT INTO` в «свою» таблицу с данными учётных записей — явный
бэкдор, который переживает смену пароля пользователя.

## Типовые индикаторы компромисса

| Индикатор | Значение |
|---|---|
| `audit_trail=NONE` | аудит выключен |
| новая процедура/триггер | бэкдор |
| `UTL_FILE`/`DBMS_SCHEDULER` | RCE |
| всплеск SELECT | эксфильтрация |
| внешний IP в listener.log | точка входа |

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
