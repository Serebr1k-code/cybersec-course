---
id: mobile-exported-provider
title: "Content Providers: path traversal, SQL-инъекции и утечки"
category: mobile
parent: mobile-exported-components
difficulty: hard
order: 3
tags: [content-provider, path-traversal, sqli, exported, uri, android]
prerequisites: [mobile-exported-components, mobile-android-anatomy]
useful_for:
  - "CTF Mobile (чтение файлов/БД через provider)"
  - "Bug bounty (утечка данных через Content Provider)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Как экспортированные Content Providers раскрывают данные: path traversal в openFile, SQL-инъекции в query, обход проверок и извлечение файлов и БД."
lab:
  kind: shell
  title: "Практика: утечка через ContentProvider"
  toolset: [core, sqlite3]
  workdir: /home/student/task
  files: [task.md, databases/app.db]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Экспортированный провайдер отдаёт SQLite-базу `databases/app.db`."
    - "Посмотри список таблиц: `sqlite3 databases/app.db '.tables'`."
    - "Прочитай таблицу с секретами и запиши флаг: `sqlite3 databases/app.db 'SELECT * FROM secrets;' | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

Content Provider — единственный Android-компонент, который отдаёт **данные** по URI. Если он экспортирован, любое приложение может запросить у него строки из базы или файл. А если в обработке пути или SQL есть ошибка — можно вытащить всю базу целиком. Как это проверить?

## Наш пример: провайдеры в fdroid.apk

Возьмём `fdroid.apk`. Посмотрим, какие провайдеры объявлены в манифесте и экспортированы ли они:

```
$ grep -oE '<provider[^>]*authorities="[^"]*"[^>]*' fdroid_dec/AndroidManifest.xml | head
<provider android:authorities="org.fdroid.fdroid.install.ApkFileProvider" android:exported="false" android:grantUriPermissions="true" android:name="org.fdroid.install.ApkFileProvider"/>
<provider android:authorities="org.fdroid.fdroid.fileprovider" android:exported="false" android:grantUriPermissions="true" android:name="androidx.core.content.FileProvider"/>
<provider android:authorities="org.fdroid.fdroid.resources.AndroidContextProvider" android:exported="false" android:name="org.jetbrains.compose.resources.AndroidContextProvider"/>
```

Все провайдеры здесь `exported="false"` — правильная настройка. Но `grantUriPermissions="true"` означает, что доступ можно **выдать точечно** через флаг в Intent. Разберём, как provider устроен и где ломается.

## Шаг 1: что такое Content Provider

Provider даёт данные по адресу вида `content://authority/path`. Приложение запрашивает его через `ContentResolver`:

```java
Cursor c = getContentResolver().query(
    Uri.parse("content://com.example.provider/users"),
    null, null, null, null);
```

`authority` — уникальное имя провайдера, `path` — что именно запрашивают. Внутри провайдер обычно обращается к SQLite-базе. Отсюда два класса уязвимостей: **обход пути** (path traversal) и **SQL-инъекция** в параметрах запроса.

## Шаг 2: как найти экспортированный provider

Правила те же: `exported="true"` или `intent-filter` без явного `exported`. Дополнительно смотрим `grantUriPermissions` — он позволяет выдать доступ к конкретному URI другому приложению.

Из adb можно обратиться к провайдеру напрямую:

```
$ adb shell content query --uri content://com.example.provider/users
Row: 0 _id=1, name=admin, token=eyJhbGciOiJIUzI1NiJ9...
```

`content` — CLI-обёртка над `ContentResolver`. Если запрос вернул строки — провайдер доступен оболочке (экспортирован или ей выдан grant).

## Шаг 3: path traversal в openFile

Провайдеры, отдающие файлы, реализуют `openFile(uri, mode)`. Частая ошибка — склеивать путь без проверки:

```java
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File f = new File(getContext().getFilesDir(), uri.getLastPathSegment());
    return ParcelFileDescriptor.open(f, MODE_READ_ONLY);
}
```

Если `uri.getLastPathSegment()` не проверяется, запрос `content://.../../../databases/app.db` может вернуть чужой файл. Проверка:

```
$ adb shell content read --uri "content://com.example.provider/files/../../databases/app.db"
```

Если в ответ приходят байты базы — это утечка. Правильная защита — `File.getCanonicalPath()` и проверка, что путь остаётся внутри разрешённой директории.

## Шаг 4: SQL-инъекция в query

Вторая ошибка — конкатенация аргументов в SQL:

```java
String sql = "SELECT * FROM users WHERE name='" + selectionArgs[0] + "'";
db.rawQuery(sql, null);
```

Тогда `selection`/`selectionArgs` из внешнего запроса позволяют дописать условие:

```
$ adb shell content query --uri content://com.example.provider/users \
    --where "1=1) OR (1=1"
```

Правильно — использовать параметризованные запросы (`?` + `selectionArgs`), никогда не склеивать строки.

## Шаг 5: утечки через projection

Иногда инъекция не нужна: провайдер возвращает **все** колонки, включая те, что не должны быть видны. `projection` в `query(uri, projection, ...)` задаёт список колонок; если провайдер игнорирует ограничения, запрос `content://.../users` вернёт пароли и токены. Проверяйте, фильтрует ли провайдер колонки по правам вызывающего.

## Шаг 6: грант URI-разрешений

`grantUriPermissions="true"` сам по себе не уязвимость — это механизм выдачи доступа. Опасность в том, что флаг `FLAG_GRANT_READ_URI_PERMISSION` можно протащить через вложенный Intent и выдать доступ не тому получателю. Это связано с intent redirection (отдельный урок).

## Почему провайдер опаснее других компонентов

Activity показывает экран, Service выполняет работу, Receiver реагирует на событие — но все они оперируют «действиями». Provider оперирует **данными**. А данные — это то, что чаще всего представляет ценность: токены, сообщения, записи о платежах, персональная информация. Поэтому экспортированный провайдер — это не «ещё одна открытая дверь», а хранилище, выставленное наружу.

К тому же провайдер обычно напрямую связан с SQLite-базой приложения. Если в обработке URI или SQL есть ошибка, атакующий получает не один экран, а **всю базу**. Именно поэтому Content Provider — один из самых частых источников серьёзных находок в мобильных пентестах.

## Разбор реального сценария

Представим приложение-мессенджер с провайдером `content://com.example.chat/messages`. Провайдер экспортирован, чтобы виджет на рабочем столе мог показывать последние сообщения. Обработчик `query` строит SQL так:

```java
String sql = "SELECT * FROM messages WHERE thread='" + uri.getQueryParameter("thread") + "'";
```

Атакующее приложение запрашивает:

```
content://com.example.chat/messages?thread=' OR '1'='1
```

Склейка превращает условие в тавтологию, и возвращаются все сообщения всех потоков. Одна строка без параметризации — и приватная переписка утекает чужому приложению. Фикс тривиален (использовать `?` и `selectionArgs`), но без аудита его не делают.

## Частые вопросы

**«Провайдер экспортирован — это точно уязвимость?»** — нет, только если он отдаёт данные без проверки. **«Нужен ли root?»** — нет, достаточно `content query` или своего приложения. **«Как быстро проверить?»** — `content query --uri ...` и посмотреть, вернутся ли строки. **«Что важнее — path traversal или SQLi?»** — обе; первая отдаёт файлы, вторая — базу. **«Как защитить?»** — `exported="false"`, канонизация путей, параметризованный SQL, проверка вызывающего.

## Практический совет

Начинайте с вопроса: «какие данные отдаёт этот провайдер и кому?». Откройте его код и найдите `query`, `openFile`, `call`. Если путь или SQL собирается из внешних данных без параметризации — вы нашли уязвимость. Проверяйте не только экспортированные провайдеры: `grantUriPermissions` может выдать доступ к приватному провайдеру через вложенный Intent, и это отдельный вектор.

## Полный прогон от начала до конца

Соберём проверку провайдера в один сценарий. Сначала `grep '<provider'` по манифесту и список `authorities`. Затем для каждого провайдера — `exported` и `grantUriPermissions`. Дальше `adb shell content query --uri content://...` — если строки вернулись, провайдер доступен. Смотрим код `query`: есть ли склейка SQL. Смотрим `openFile`: канонизируется ли путь. Пробуем `content://.../../` и `--where` с инъекцией. Итог — подтверждённая утечка либо чистая конфигурация.

## Ещё один вектор: `call()`

Помимо `query` и `openFile`, у провайдера есть метод `call(method, arg, extras)` — произвольный вызов. Многие провайдеры реализуют через него свои операции («обновить», «синхронизировать»), не проверяя вызывающего. Экспортированный `call` без проверки — это тот же confused deputy, только через провайдер. Проверяйте, какие `method`-строки обрабатывает `call` и что они делают: иногда там оказывается выполнение действия с привилегиями приложения.

## Инструмент: sqlite3 — файл как база

`sqlite3` открывает файл БД и даёт SQL-консоль. В мобильной/веб-форензике это первый инструмент: приложения хранят данные в SQLite.

Ключи, которые пригодятся:
* `sqlite3 app.db` — открыть базу;
* `.tables` — список таблиц; `.schema <таблица>` — структура;
* `select * from <таблица>;` — вывести строки;
* `.dump` — весь дамп; `sqlite3 app.db "select ..."` — запрос одной командой.

### Рабочий пример (как в лаборатории)

```
$ sqlite3 .tables
secrets  users
```

Подсказка из лаборатории: `sqlite3 <db> '<SQL|.команда>' — эмуляция (вывод захвачен с реального sqlite3)`.

## Что мы теперь знаем

По-простому:

1. Provider отдаёт данные по `content://authority/path`.
2. Экспортированный provider доступен через `content query`.
3. Path traversal в `openFile` отдаёт произвольные файлы.
4. SQL-инъекция в `query` позволяет вытащить всю базу.
5. Правильная защита: `exported="false"`, канонизация путей, параметризованный SQL.

## На что смотреть дальше

- **Найдите провайдеры** и проверьте `exported` и `grantUriPermissions`.
- **Пробуйте `content query`** — быстрая проверка доступности.
- **Ищите `openFile`** и склейку путей — path traversal.
- **Ищите `rawQuery`/`execSQL`** с конкатенацией — SQL-инъекция.

## Квиз

Проверь себя.

```quiz
- question: "По какому адресу доступны данные Content Provider?"
  options:
    - "content://authority/path"
    - "file://path"
    - "http://authority/path"
    - "intent://path"
  answer: 0
- question: "Как проверить провайдер из adb?"
  options:
    - "adb shell content query --uri content://..."
    - "adb shell am start"
    - "adb install app.apk"
    - "adb shell logcat"
  answer: 0
- question: "Какая ошибка в `openFile` ведёт к path traversal?"
  options:
    - "Склейка пути без канонизации и проверки"
    - "Использование `ParcelFileDescriptor.open`"
    - "Проверка `getCanonicalPath`"
    - "Белый список директорий"
  answer: 0
- question: "Как защититься от SQL-инъекции в провайдере?"
  options:
    - "Параметризованными запросами с `selectionArgs`"
    - "Склейкой строк"
    - "Отключением базы"
    - "Использованием HTTPS"
  answer: 0
- question: "Что означает `grantUriPermissions='true'`?"
  options:
    - "Доступ к конкретному URI можно выдать другому приложению"
    - "Провайдер экспортирован всем"
    - "Провайдер зашифрован"
    - "Провайдер только для чтения"
  answer: 0
```

## Куда дальше

Мы разобрали Content Providers — самый «данные-ёмкий» компонент. В следующем уроке углубимся в **Binder и IPC**: как устроен низкоуровневый обмен между процессами и почему недоверенный `Parcel` — это отдельный класс атак. А пока запомни главное: provider — это база, выставленная в сеть приложений, и её надо проверять на обход пути и инъекции.

## Где пригодится

- **CTF Mobile:** вытаскивание флага из базы через provider.
- **Bug bounty:** экспортированный provider с path traversal — high/critical.
- **Пентест:** проверка OWASP MASVS-PLATFORM.
- **Работа:** ревью компонентов, отдающих данные.
