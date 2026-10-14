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
  title: 'Практика: Oracle-СУБД'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
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
