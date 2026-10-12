---
id: mobile-insecure-storage
title: "Небезопасное хранение данных: SharedPreferences, SQLite, файлы, логи"
category: mobile
parent: mobile-android-components
difficulty: easy
order: 1
tags: [android, storage, sharedpreferences, sqlite, keystore, secrets]
prerequisites: [mobile-android-anatomy]
useful_for:
  - "CTF Mobile (поиск флагов и токенов на устройстве)"
  - "Bug bounty (утечки данных в локальном хранилище)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Где Android-приложение хранит данные (SharedPreferences, SQLite, files, кэш, логи, внешняя память) и как найти там пароли, токены и флаги. Плюс как правильно — через Keystore и EncryptedSharedPreferences."
---

## Вопрос, с которого всё начинается

В прошлых уроках мы разобрали APK по слоям и научились читать манифест и код. Но код — это только половина истории. Приложение ещё и **хранит** данные на устройстве: сессии, токены, настройки, кэш. И очень часто хранит их так, что прочитать их может кто угодно с доступом к устройству.

Как найти то, что приложение записало на диск, и понять, что из этого — секрет?

## Наш пример: uncrack1.apk

Возьмём реальный APK — `uncrack1.apk` (учебное приложение OWASP UnCrackable). Начнём с самого внешнего: посмотрим, из чего он состоит.

```
$ unzip -l uncrack1.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
     1648  1980-00-00 00:00   AndroidManifest.xml
     1319  1980-00-00 00:00   META-INF/CERT.RSA
     5528  1980-00-00 00:00   classes.dex
     1260  1980-00-00 00:00   res/layout/activity_main.xml
     2748  1980-00-00 00:00   resources.arsc
```

APK — это ZIP. Внутри — манифест, код (`classes.dex`), ресурсы и подпись. Но нас сейчас интересует не содержимое архива, а то, **что приложение запишет на устройство при работе**.

## Шаг 1: читаем манифест — ищем разрешение на «болтливость»

Декодируем манифест тем же `apktool`, что и раньше, и смотрим ключевые атрибуты `application`:

```xml
<manifest package="owasp.mstg.uncrackable1">
  <application android:allowBackup="true"
               android:icon="@mipmap/ic_launcher"
               android:label="@string/app_name">
    <activity android:name="sg.vantagepoint.uncrackable1.MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
```

Обратите внимание на `android:allowBackup="true"`. Это флаг: система разрешает делать резервную копию данных приложения. Значит, даже без root часть данных можно вытащить через `adb backup`. Запомним это — вернёмся в шаг 4.

## Шаг 2: где вообще лежат данные приложения

У каждого Android-приложения есть приватная директория `/data/data/<package>/`. Туда пишут все стандартные механизмы хранения:

- **SharedPreferences** → `shared_prefs/*.xml` — мелкие пары «ключ-значение» (токены, флаги, настройки).
- **SQLite** → `databases/*.db` — база данных (пользователи, сессии, кэш).
- **Файлы** → `files/`, `cache/`, `no_backup/`.
- **Внешняя память** → `/sdcard/Android/data/<package>/` — доступна другим приложениям.

Доступ к `/data/data/<package>/` даёт либо root, либо `run-as`, либо отлаживаемая сборка (`debuggable`).

## Шаг 3: смотрим код — а как приложение работает с секретом

Декомпилируем `classes.dex` через `jadx` и открываем точку входа:

```java
public class MainActivity extends Activity {
    protected void onCreate(Bundle bundle) {
        if (c.a() || c.b() || c.c()) { a("Root detected!"); }
        if (b.a(getApplicationContext())) { a("App is debuggable!"); }
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
    }
    public void verify(View view) {
        String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
        if (a.a(obj)) { create.setTitle("Success!"); }
    }
}
```

Приложение хранит **сам секрет не на диске, а в коде** — функция `a.a()` расшифровывает эталон и сравнивает его с введённой строкой. Это тоже «небезопасное хранение», только вшитое в сборку. Но так делают не всегда: часто приложение сохраняет данные пользователя в SharedPreferences или SQLite, и тогда их видно прямо на диске.

## Шаг 4: читаем реальную базу приложения

Чтобы увидеть, как выглядит база приложения на диске, возьмём реальный APK, который кладёт SQLite-файл внутрь себя — `lichess.apk`. Достанем его базу из архива и откроем:

```
$ unzip -o lichess.apk 'assets/flutter_assets/assets/chess_openings.db' -d lic
  inflating: lic/assets/flutter_assets/assets/chess_openings.db

$ sqlite3 lic/assets/flutter_assets/assets/chess_openings.db ".tables"
Openings

$ sqlite3 lic/assets/flutter_assets/assets/chess_openings.db ".schema Openings"
CREATE TABLE Openings (
  name TEXT, eco TEXT, fen TEXT, moves TEXT, ...
);

$ sqlite3 lic/assets/flutter_assets/assets/chess_openings.db \
    "SELECT name,eco FROM Openings LIMIT 3;"
Alekhine Defense|B02
Alekhine Defense: Modern Variation|B04
Alekhine Defense: Scandinavian Variation|B02
```

Вот как выглядит работа с базой приложения: `sqlite3 <файл>` и дальше обычные SQL-команды. У рантайм-базы (`databases/app.db`) схема та же — `.tables`, `.schema`, `SELECT *`. Ищите таблицы с говорящими именами: `users`, `sessions`, `tokens`, `secrets`.

## Шаг 5: логи, бэкап и внешняя память

Три дополнительных места, где утекают данные:

**Логи.** Приложение может писать чувствительное в `logcat`:

```
$ adb logcat | grep -iE 'password|token|secret|flag'
D/CodeCheck( 4121): user_token=eyJhbGciOiJIUzI1NiJ9...
```

**Резервная копия.** Раз `allowBackup="true"`, пробуем `adb backup`:

```
$ adb backup -f backup.ab -apk owasp.mstg.uncrackable1
WARNING: adb backup is deprecated and may be removed in a future release
Now unlock your device and confirm the backup operation.
```

Получили `backup.ab` — распаковывается утилитой `abe.jar` в обычный tar.

**Внешняя память.** Файлы в `/sdcard/Android/data/<package>/` доступны другим приложениям с разрешением на чтение внешней памяти — то есть секрет из приватной директории может «утечь» туда.

## Полный прогон от начала до конца

Соберём всё в один маршрут по нашему `uncrack1.apk`:

1. **`unzip -l`** — видим слои APK, понимаем, что перед нами обычное приложение.
2. **`apktool d`** — декодируем манифест, находим `allowBackup="true"`.
3. **`jadx`** — открываем `MainActivity`, видим проверки root и `debuggable`.
4. **Устройство** — заходим в `/data/data/owasp.mstg.uncrackable1/`, читаем `shared_prefs`, `databases`, `files`.
5. **`adb backup`** — раз `allowBackup` включён, тянем копию и распаковываем.
6. **`logcat`** — смотрим, не пишет ли приложение секрет в лог.

Порядок именно такой: манифест и код дают подсказки ещё до того, как мы подключим устройство, а значит экономят время.

## Если данные зашифрованы

Современные приложения всё чаще пишут не в открытые SharedPreferences, а в `EncryptedSharedPreferences` или шифруют базу через SQLCipher. Данные на диске выглядят как случайный мусор — но ключ всё равно существует в памяти во время работы. Его перехватывают через Frida:

```javascript
Java.perform(function () {
  function hex(a) {
    return Array.prototype.map.call(a, function (b) {
      return ('0' + (b & 0xff).toString(16)).slice(-2);
    }).join('');
  }
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    console.log('key = ' + hex(key.getEncoded()));
    return this.init(mode, key);
  };
});
```

Мы получим реальный ключ в консоли и сможем расшифровать файл на компьютере. Полный разбор Frida — в отдельном уроке, здесь важно запомнить идею: **шифрование на диске не спасает, если ключ доступен процессу**.

## Что мы теперь знаем

По-простому:

1. Приложение хранит данные в `/data/data/<package>/`: `shared_prefs`, `databases`, `files`, `cache`.
2. Быстрый путь к секретам — SharedPreferences и SQLite; читаются обычным `cat` и `sqlite3`.
3. Логи (`logcat`) — частая утечка токенов и паролей.
4. `allowBackup="true"` открывает данные через `adb backup`.
5. Секрет может быть и в самом коде — тогда его ищут `jadx`-ом, а не на диске.
6. Шифрование хранилища не защищает, если ключ можно достать из памяти через Frida.

## На что смотреть дальше

- **Начинайте с манифеста:** `allowBackup`, `debuggable` — два флага, которые сразу расширяют доступ.
- **Проверяйте все хранилища по каскаду:** `shared_prefs` → `databases` → `files/cache` → external → logs.
- **Не забывайте про кэш:** токены любят оседать в `cache/` и HTTP-кэше.
- **Если база зашифрована** (SQLCipher) — ключ ищут в коде или перехватывают через Frida.

## Квиз

Проверь себя.

```quiz
- question: "Где Android-приложение чаще всего хранит токены и пароли «на скорую руку»?"
  options:
    - "В SharedPreferences (`shared_prefs/*.xml`)"
    - "В AndroidManifest.xml"
    - "В `res/values/strings.xml`"
    - "В Gradle-файлах"
  answer: 0
- question: "Что означает `android:allowBackup='true'`?"
  options:
    - "Система разрешает резервную копию данных приложения (например, через `adb backup`)"
    - "Приложение можно установить на любой телефон"
    - "Приложение не использует интернет"
    - "Приложение хранит данные в открытом виде"
  answer: 0
- question: "Какой командой открыть базу приложения на диске?"
  options:
    - "`sqlite3 databases/app.db`"
    - "`jadx databases/app.db`"
    - "`apktool d databases/app.db`"
    - "`strings databases/app.db`"
  answer: 0
- question: "Приложение пишет токен в `logcat`. Какой это класс уязвимости?"
  options:
    - "Утечка чувствительных данных через логи (CWE-532)"
    - "SQL-инъекция"
    - "XSS"
    - "Переполнение буфера"
  answer: 0
- question: "Клиентский флаг `is_premium=true` в SharedPreferences — уязвимость, если…"
  options:
    - "сервер доверяет этому флагу вместо проверки на своей стороне"
    - "всегда"
    - "никогда"
    - "приложение не использует HTTPS"
  answer: 0
```

## Куда дальше

Мы научились находить данные, которые приложение пишет на диск. В следующем уроке разберём **утечки через side-channels**: буфер обмена, скриншоты и системные интерфейсы, через которые секрет уходит, даже если на диске его нет. А пока запомни главное: сначала манифест (`allowBackup`, `debuggable`), потом каскад хранилищ — `shared_prefs` → базы → файлы → логи.

## Где пригодится

- **CTF Mobile:** самый быстрый путь к флагу — `shared_prefs`, базы и логи.
- **Bug bounty:** утечки токенов и PII в локальном хранилище — валидные находки.
- **Пентест:** проверка OWASP MASVS-STORAGE — приложение не хранит секреты в открытом виде.
- **Работа:** рекомендации разработчикам (Keystore, EncryptedSharedPreferences, `allowBackup=false`).
