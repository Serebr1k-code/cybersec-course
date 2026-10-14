---
id: mobile-android-contentprovider-sql
title: 'Content Provider SQL-инъекции deep'
category: mobile
parent: mobile-android-ipc-attacks
difficulty: expert
order: 4
tags: [android, contentprovider, sqli, provider, uri, sqlite]
prerequisites: [mobile-exported-provider, mobile-android-fileprovider]
useful_for:
  - 'Пентест мобильных приложений (Android)'
  - 'Bug bounty Android'
  - 'CTF Mobile'
estimated_minutes: 45
summary: 'Как ContentProvider строит SQL-запросы, где появляется инъекция через projection/selection/sortOrder, как её подтвердить через adb и как защититься параметрами.'
---

## Вопрос, с которого всё начинается

Content Provider — это «API к базе» внутри Android. Приложение вызывает
`getContentResolver().query(uri, projection, selection, selectionArgs, sortOrder)`. Казалось
бы, параметры — это безопасный bind. Но многие провайдеры собирают SQL **строками**, и тогда
`selection` становится точкой инъекции. Разберём, как это увидеть и подтвердить.

## Наш пример: провайдер заметок

В декомпилированном коде находим метод `query`:

```java
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    String q = "SELECT " + (projection != null ? projection[0] : "*")
             + " FROM notes WHERE " + selection
             + " ORDER BY " + sortOrder;
    return db.rawQuery(q, null);
}
```

Обратите внимание: `selection` и `sortOrder` подставлены в строку напрямую, а `rawQuery`
вызывается с `null` вместо аргументов. Значит, никакой параметризации нет — это SQL-инъекция.

## Шаг 1: как вызывается провайдер

Content Provider доступен по `content://<authority>/<path>`. Если он экспортирован (или
доступен другому приложению), вызвать его можно из любого приложения или через `adb`:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes
Row: 0 _id=1, title=Hello, body=world
```

`adb shell content` — встроенный инструмент, который умеет query/insert/update/delete.

## Шаг 2: точки инъекции

В `query` есть три потенциально опасных аргумента:

- **projection** — список колонок;
- **selection** — условие `WHERE`;
- **sortOrder** — `ORDER BY`.

В нашем коде инъекционен `selection`. Пробуем классическое условие, которое всегда истинно:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes     --where "1=1"
Row: 0 _id=1, title=Hello, body=world
Row: 1 _id=2, title=Secret, body=nto{...}
```

Мы получили строку, которую обычный фильтр не отдал бы. Дальше — UNION-запросы, чтобы вытащить
соседние таблицы (например, `users` с токенами).

## Шаг 3: подтверждение через UNION

Зная число колонок, добавляем `UNION SELECT`:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes     --where "1=0 UNION SELECT username,password,3 FROM users--"
Row: 0 _id=admin, title=admin, body=s3cr3t
```

`--` в SQLite — начало комментария, поэтому хвост запроса отбрасывается. Так из соседней
таблицы утекают логины и пароли.

## Шаг 4: инъекция в sortOrder и projection

Даже если `selection` параметризован, `sortOrder` и `projection` часто забывают. Инъекция в
`ORDER BY` подтверждается булевым тестом: разный порядок при истинном и ложном условии.
`projection` иногда позволяет подставить подзапрос вместо имени колонки.

Проверяем, как провайдер валидирует вход:

```bash
$ grep -rn "SQLiteQueryBuilder\|rawQuery\|selectionArgs" decompiled/smali/com/example/
```

Если видим `rawQuery` с `null` аргументами — почти наверняка инъекция.

## Шаг 5: как чинится

- Использовать `SQLiteQueryBuilder.setSelection()` и передавать `selectionArgs` — тогда
  значение уходит как bind-параметр, а не как SQL-код.
- Белый список допустимых колонок для `projection` и `sortOrder`.
- Не экспортировать провайдер без необходимости; защищать permission'ом.

## Шаг 6: почему это важно в отчёте

SQL-инъекция в провайдере — это утечка всей локальной базы приложения: токены, сессии,
переписка. При этом эксплуатируется тривиально через `adb`, а в реальном мире — из
установленного рядом приложения без каких-либо прав.

## Что мы теперь знаем

- Content Provider — «API к базе» по `content://`.
- Инъекция появляется, когда `selection`/`sortOrder`/`projection` конкатенируются в SQL.
- Подтверждается через `adb shell content query --where`.
- Защита — `selectionArgs` (bind) + белый список колонок.

## Шаг 7: как провайдер вообще строится

Content Provider наследуется от `android.content.ContentProvider` и реализует `query`,
`insert`, `update`, `delete`, `getType`. Внутри обычно лежит `SQLiteDatabase`. Правильный
вариант — `SQLiteQueryBuilder`:

```java
SQLiteQueryBuilder b = new SQLiteQueryBuilder();
b.setTables("notes");
b.setStrict(true);              // запрещает произвольные имена таблиц
b.setProjectionMap(PROJECTION); // белый список колонок
return b.query(db, projection, selection, selectionArgs, null, null, sortOrder);
```

`setStrict(true)` и `setProjectionMap` — это ровно те меры, которых не хватает уязвимому
провайдеру из нашего примера. Если их нет, а `selection` конкатенируется — ждите инъекцию.

## Шаг 8: сколько колонок и как это узнать

Для `UNION SELECT` нужно совпадение числа колонок. Определяют его по `ORDER BY`:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1 ORDER BY 1"
Row: ...
$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1 ORDER BY 3"
Row: ...
$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1 ORDER BY 4"
Error: no such column: 4
```

Ошибка на `ORDER BY 4` означает, что колонок три. Дальше `UNION SELECT a,b,c` даёт ровно три
колонки и не падает.

## Шаг 9: слепая инъекция

Если провайдер не возвращает данные (например, только `insert`/`update`), инъекция остаётся
**слепой**. Тогда используют булевы условия или тайминги:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes \
    --where "title='x' AND (SELECT substr(password,1,1) FROM users)='a'"
```

Разное поведение при истинном и ложном условии позволяет побайтово вытащить значение. В
SQLite удобен `randomblob()` для задержки, но в Android тайминги менее надёжны, поэтому чаще
используют булев вариант.

## Шаг 10: инъекция не только в query

`insert` может вставлять значения из `ContentValues` — они параметризуются, но **имена
колонок** иногда конкатенируются. `update` и `delete` повторяют те же точки, что и `query`.
Отдельный класс — инъекция в `sortOrder` через `ORDER BY (SELECT ...)`, которая позволяет
вытаскивать данные по одной ячейке.

## Шаг 11: как эксплуатируют из другого приложения

`adb` — только для проверки. В реальной атаке вредоносное приложение вызывает
`getContentResolver().query(...)` напрямую. Если провайдер экспортирован или защищён
тривиальным permission'ом, инъекция доступна без прав. Поэтому в отчёте важно указать
`android:exported` и permission провайдера: это определяет реальный радиус поражения.

## Шаг 12: рекомендации

- Всегда `selectionArgs` вместо конкатенации.
- `SQLiteQueryBuilder.setStrict(true)` + `setProjectionMap`.
- Белый список значений для `sortOrder`.
- `android:exported="false"` и защита permission'ом, если провайдер нужен только своему
  приложению.
- Не логировать SQL-запросы с пользовательскими данными.

## Шаг 13: как отличить настоящую инъекцию от ложной

Не всякая конкатенация опасна. Если провайдер вставляет в SQL **число**, полученное из
проверенного `Integer.parseInt`, или имя колонки из **белого списка**, инъекции нет. Признаки
настоящей инъекции:

- пользовательская строка попадает в SQL без валидации;
- `rawQuery`/`execSQL` вызывается с `null` вместо `selectionArgs`;
- нет `setProjectionMap` и `setStrict(true)`;
- нет проверки `sortOrder` на список допустимых колонок.

Практический тест: подставьте в параметр строку с `'`, `--`, `UNION`. Если провайдер падает с
SQL-ошибкой в логе или меняет результат — инъекция подтверждена.

## Шаг 14: смотрим лог

Android логирует SQL-ошибки, и это помогает подтвердить инъекцию даже «слепо»:

```bash
$ adb logcat | grep -i "SQLiteException\|syntax error"
E SQLiteLog: (1) near "UNION": syntax error
```

Сообщение `near "UNION": syntax error` означает, что наш текст действительно попал в
парсер SQL. Это сильное доказательство для отчёта — не только «данные другие», но и «сервер
разбирает наш ввод как SQL».

## Шаг 15: что ещё утекает

Провайдер почти всегда открывает доступ ко **всей** базе приложения, а не только к одной
таблице. Через `UNION` и `sqlite_master` можно перечислить таблицы:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes \
    --where "1=0 UNION SELECT name,sql,3 FROM sqlite_master--"
```

В `sqlite_master` лежит DDL всех таблиц — это карта базы. Дальше вытаскиваются токены сессий,
пароли (если хранятся небезопасно), история и персональные данные. Именно поэтому инъекцию в
провайдере в отчёте относят к высокому риску.

## Шаг 16: рекомендации и проверка исправления

После того как провайдер переписан на `SQLiteQueryBuilder` с `selectionArgs`, проверьте
исправление тем же `--where "1=1"`: теперь условие должно трактоваться как **значение**, а не
как SQL, и лишние строки не вернутся. Полезно добавить автотест, который шлёт кавычку и
спецсимволы в каждый параметр `query`/`insert`/`update`/`delete` и убеждается, что поведение
не меняется. Так инъекция не вернётся при следующем рефакторинге.

## Шаг 17: мини-чек-лист

Провайдер экспортирован? Как строит SQL — `rawQuery` или `SQLiteQueryBuilder`? Передаются ли
`selectionArgs`? Есть ли `setStrict(true)` и `setProjectionMap`? Проверяется ли `sortOrder`?
Попробуйте `--where "1=1"` и посмотрите, вернутся ли лишние строки. Если да — инъекция
подтверждена, и можно переходить к `UNION` и `sqlite_master`. Этот порядок действий
воспроизводим в любом аудите Android-провайдера.

## Шаг 18: разница между Android и «настоящим» вебом

SQL-инъекция в провайдере похожа на веб-SQLi, но есть отличия. Во-первых, поверхность уже —
вы обращаетесь не к HTTP-эндпоинту, а к `content://` URI, и число параметров ограничено
методами провайдера. Во-вторых, эксплуатируется чаще **локально**: вредоносное приложение
рядом, а не удалённый атакующий. В-третьих, `adb shell content` даёт удобный интерактивный
доступ без написания приложения. При этом принцип тот же: данные не должны становиться
кодом. Понимая это, вы переносите навык веб-инъекций на мобильную платформу почти без
потерь — меняется только транспорт и инструмент подтверждения.

## Шаг 19: автоматизация проверки

Чтобы не проверять каждый провайдер руками, полезно написать небольшой скрипт, который
перебирает `content://`-URI из манифеста и для каждого шлёт серию тестовых условий. На
первом шаге — безопасный `1=1`, на втором — `1=0`, на третьем — заведомо ломающий синтаксис
`'`. Если три ответа различаются, кандидат найден. Дальше уже вручную строится `UNION` и
вытаскиваются данные. Такой скрипт запускается на эмуляторе с установленным APK и даёт
быструю карту потенциальных инъекций по всему приложению. Для отчёта достаточно привести
таблицу «URI — параметр — результат теста», и она наглядно показывает масштаб проблемы.

## Квиз

Проверь себя.

```quiz
- question: Что делает Content Provider?
  options:
    - Отправляет SMS
    - Предоставляет доступ к базе данных приложения через content:// URI
    - Управляет сетью
    - Хранит пароли в Keystore
  answer: 1
  explanation: Провайдер — это фасад над SQLite/файлами, доступный по URI.
- question: Какой аргумент query() становится точкой инъекции при конкатенации?
  options:
    - Только uri
    - selection и/или sortOrder (иногда projection)
    - Только selectionArgs
    - Никакой
  answer: 1
  explanation: Строки, попадающие в SQL напрямую, позволяют инъекцию.
- question: Какая команда подтверждает SQLi в провайдере через adb?
  options:
    - adb shell content query --uri ... --where "1=1"
    - adb logcat
    - adb install
    - adb reboot
  answer: 0
  explanation: `content query --where` позволяет подставить произвольное условие.
- question: Как правильно защититься?
  options:
    - Отключить провайдер
    - Использовать selectionArgs (bind-параметры) и белый список колонок
    - Шифровать базу
    - Уменьшить размер таблиц
  answer: 1
  explanation: Bind-параметры отделяют данные от кода SQL.
```
