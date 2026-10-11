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
## Что такое небезопасное хранение данных

Мобильное приложение хранит данные на устройстве: настройки, сессии, кэш, иногда пароли и ключи. Если хранение небезопасно, любой, кто получит доступ к устройству (или другое приложение с правами), сможет прочитать секреты. В пентесте небезопасное хранение — один из главных классов уязвимостей (OWASP MASVS-STORAGE). Цель модуля — научиться находить, где приложение хранит данные, и извлекать их.

## Где Android хранит данные

- **SharedPreferences** — `shared_prefs/*.xml` в приватной директории приложения. Часто хранит токены и флаги.
- **SQLite** — `databases/*.db`. Может содержать пользователей, сессии, кэш.
- **Файлы** — `files/`, `cache/`, `no_backup/`. Произвольные данные.
- **Keystore** — системное хранилище ключей (защищённое, но иногда используется неверно).
- **External storage** — `/sdcard/Android/data/<pkg>/`. Доступно другим приложениям.

## Доступ к приватным данным

На рутованном устройстве/эмуляторе:

```bash
adb shell
su
cd /data/data/com.example.app
ls -R
cat shared_prefs/*.xml
sqlite3 databases/app.db ".tables"
```

Или вытянуть всё на компьютер:

```bash
adb shell "run-as com.example.app tar -cf - ." > app_data.tar
```

`run-as` работает, если приложение `debuggable` или на рутованном устройстве.

## SharedPreferences

```bash
cat /data/data/com.example.app/shared_prefs/*.xml
```

Флаги и токены часто лежат прямо здесь в открытом виде. Если значения зашифрованы (EncryptedSharedPreferences) — ищите ключ или обходите через Frida.

## SQLite

```bash
sqlite3 /data/data/com.example.app/databases/app.db
sqlite> .tables
sqlite> .schema users
sqlite> SELECT * FROM users;
```

Ищите таблицы с «говорящими» именами: `users`, `sessions`, `secrets`, `flags`. Если база зашифрована (SQLCipher) — ищите ключ в коде.

## Логи

Приложение может писать чувствительные данные в лог:

```bash
adb logcat | grep -iE 'password|token|secret|flag'
```

Утечка через логи — частая и легко эксплуатируемая проблема.

## Резервные копии

Если `android:allowBackup="true"`, данные можно извлечь через `adb backup`:

```bash
adb backup -f backup.ab -apk com.example.app
# распаковать
java -jar abe.jar unpack backup.ab backup.tar
```

## Обход шифрования хранилища

Если данные зашифрованы, перехватите ключ через Frida, хукая `Cipher.init` или `EncryptedSharedPreferences`:

```javascript
var Cipher = Java.use('javax.crypto.Cipher');
Cipher.init.overload('int', 'java.security.Key').implementation = function (m, k) {
    console.log('key =', k.getEncoded());
    return this.init(m, k);
};
```

## Типичные ошибки и подводные камни

- **Смотреть только SharedPreferences** — проверьте SQLite и файлы.
- **Забыть про логи** — частая утечка.
- **Не проверить external storage** — доступно другим.
- **Игнорировать `allowBackup`** — лёгкий способ извлечь всё.
- **Полагать, что Keystore защищает** — ключ можно достать из рантайма.
- **Не обойти шифрование** — данные могут быть зашифрованы.
- **Забыть про кэш** — токены бывают в `cache/`.

## Справочная таблица

| Хранилище | Путь |
|-----------|------|
| SharedPreferences | `shared_prefs/*.xml` |
| SQLite | `databases/*.db` |
| Файлы | `files/`, `cache/` |
| External | `/sdcard/Android/data/<pkg>/` |
| Логи | `adb logcat` |
| Бэкап | `adb backup` |

## Что дальше / решение

План: получите доступ к приватной директории (`run-as`/root), изучите SharedPreferences, SQLite и файлы, проверьте логи, external storage и бэкапы. Если данные зашифрованы — обходите через Frida. Небезопасное хранение — один из самых частых классов уязвимостей, и находить его нужно в первую очередь, начиная с `shared_prefs`.

## Расширенный чек-лист по небезопасному хранению

Действуйте по списку. Первое: получите доступ к `/data/data/<pkg>/` через `run-as` или root. Второе: изучите `shared_prefs/*.xml` — там чаще всего токены и флаги. Третье: откройте `databases/*.db` через `sqlite3`, посмотрите `.tables` и содержимое. Четвёртое: пройдите `files/`, `cache/`, `no_backup/` — там бывают ключи и конфиги. Пятое: проверьте `/sdcard/Android/data/<pkg>/`. Шестое: `adb logcat | grep -iE 'pass|token|secret|flag'`. Седьмое: если `allowBackup=true`, сделайте `adb backup` и распакуйте. Восьмое: если данные зашифрованы — хукайте `Cipher.init`/`EncryptedSharedPreferences` через Frida, чтобы получить ключ.

## Как быстро найти секреты в данных

```bash
grep -rInE 'flag|token|secret|password|key' /data/data/com.example.app/
sqlite3 databases/app.db ".dump" | grep -iE 'flag|token'
```

Часто секрет лежит в неочевидном месте: в кэше HTTP-ответов, в логах, в `files/` с рандомным именем. Поэтому важно пройти все директории, а не только очевидные.

## Частые вопросы

«`run-as` не работает?» — приложение не debuggable; нужен root. «База зашифрована?» — SQLCipher; ищите ключ в коде/Frida. «Не нахожу данные?» — проверьте external storage и кэш. «Как извлечь всё сразу?» — `run-as pkg tar -cf - .`. «Что если allowBackup=false?» — остаётся root/run-as.

## Что дальше / решение

Итог: проверьте все хранилища (SharedPreferences, SQLite, файлы, external, логи, бэкапы), при шифровании — обходите через Frida. Небезопасное хранение — один из самых частых классов уязвимостей Android, и часто самый быстрый путь к секретам. Начинайте с `shared_prefs` и `databases`.

## Практический пример: флаг в SharedPreferences

Разберём сквозной сценарий. Дано приложение, которое сохраняет «сессию». Шаг 1: на рутованном эмуляторе заходим в приватную директорию: `adb shell su -c 'cat /data/data/com.example.app/shared_prefs/*.xml'`. Шаг 2: видим XML с полями `token`, `user`, `secret` — и, возможно, `flag`. Часто флаг лежит прямо здесь. Шаг 3: если значения зашифрованы (EncryptedSharedPreferences), хукаем `Cipher.init` через Frida и получаем ключ, либо перехватываем запись/чтение SharedPreferences. Шаг 4: если данных нет, проверяем SQLite: `sqlite3 databases/app.db ".dump" | grep -i flag`. Шаг 5: проверяем логи: `adb logcat | grep -i flag`.

Этот маршрут покрывает большинство задач на небезопасное хранение: shared_prefs → база → логи → файлы. Порядок именно такой, потому что shared_prefs — самое частое место для токенов и флагов.

## Как не пропустить данные

Пройдитесь по всем директориям рекурсивно: `ls -R /data/data/com.example.app`. Иногда секрет лежит в файле с рандомным именем в `cache/` или в `no_backup/`. Проверьте external storage: `/sdcard/Android/data/com.example.app/`. И не забудьте про HTTP-кэш — токены часто там.

## Частые вопросы

«`run-as` не работает?» — нужен root или debuggable APK. «Всё зашифровано?» — обходите через Frida. «Нет данных в shared_prefs?» — смотрите SQLite и файлы. «Как извлечь всё?» — `run-as pkg tar -cf - .` или `adb backup`. «Флаг в логах?» — `logcat`.

## Что дальше / решение

Итог: проверяйте все хранилища по каскаду — shared_prefs → databases → files/cache → external → logs → backup; при шифровании обходите через Frida. Небезопасное хранение — частый и легко эксплуатируемый класс уязвимостей, и часто самый короткий путь к секретам приложения.

## Итог по небезопасному хранению

Проверяйте хранилища по каскаду: shared_prefs → databases → files/cache → external → logs → backup. При шифровании обходите через Frida (хук `Cipher.init`). Небезопасное хранение — частый и легко эксплуатируемый класс уязвимостей, и часто самый короткий путь к секретам. Начинайте с `shared_prefs`, потому что именно там чаще всего лежат токены и флаги.

## Итог по небезопасному хранению

Проверяйте shared_prefs, databases, files/cache, external, logs, backup; при шифровании обходите через Frida. Начинайте с shared_prefs — там чаще всего токены и флаги.

## Квиз

```quiz
- question: "Где Android-приложение чаще всего хранит токены и пароли «на скорую руку»?"
  options:
    - "В SharedPreferences (`shared_prefs/*.xml`)"
    - "В AndroidManifest.xml"
    - "В Gradle-файлах"
    - "В `res/values/strings.xml`"
  answer: 0
- question: "Что позволяет вытащить данные приложения без root?"
  options:
    - "Только Magisk"
    - "`adb backup` при `android:allowBackup="true"`"
    - "Только Frida"
    - "Ничего, без root данные недоступны"
  answer: 1
- question: "Какой механизм правильно использовать для хранения криптоключей в Android?"
  options:
    - "Android Keystore"
    - "SharedPreferences"
    - "Внешняя память"
    - "Буфер обмена"
  answer: 0
- question: "Приложение пишет токен в `logcat`. Какой это класс уязвимости?"
  options:
    - "Утечка чувствительных данных через логи (CWE-532)"
    - "SQL-инъекция"
    - "XSS"
    - "Переполнение буфера"
  answer: 0
- question: "Клиентский флаг `is_premium=true` в SharedPreferences — это уязвимость, если…"
  options:
    - "всегда"
    - "сервер доверяет этому флагу вместо проверки на своей стороне"
    - "никогда"
    - "приложение не использует HTTPS"
  answer: 1
```

## Где пригодится

- **CTF Mobile:** самый быстрый путь к флагу — заглянуть в `shared_prefs`, базы и логи.
- **Bug bounty:** утечки токенов и PII в локальном хранилище — валидные находки, особенно с доказательством доступа к API.
- **Пентест:** проверка OWASP MASVS-STORAGE — что приложение не хранит секреты в открытом виде.
- **Работа:** рекомендации разработчикам (Keystore, EncryptedSharedPreferences, `allowBackup=false`).
