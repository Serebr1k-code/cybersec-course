---
id: forensics-mobile-android
title: "Android-форензика глубоко: ADB, бэкапы, app data"
category: forensics
parent: forensics-mobile
difficulty: hard
order: 1
tags: [android, adb, apk, sqlite, backups, mobile, forensics]
prerequisites: [forensics-mobile]
useful_for:
  - "CTF Forensics категория"
  - "Мобильная форензика"
  - "DFIR"
estimated_minutes: 45
summary: "Извлечение и анализ данных Android: ADB, backup, root-доступ, app data, SQLite-базы приложений, логи и артефакты системы."
---

## Вопрос, с которого всё начинается

Изъят Android-телефон. Нужно понять, какое приложение установлено, с кем человек переписывался и не «сливал» ли он данные. Но просто скопировать папку с телефона нельзя: Android изолирует данные приложений друг от друга.

Мы уже разбирали мобильные артефакты в общем виде (`forensics-mobile`). Теперь пройдём полный путь на конкретном устройстве: от подключения по USB до чтения базы переписки. По ходу разберёмся, почему доступ к данным зависит от **уровня извлечения**.

## Наш пример: телефон с приложением `com.example.app`

Подключаем устройство по USB и запускаем отладочный мост. **ADB** (Android Debug Bridge) — это инструмент, через который компьютер общается с телефоном.

```bash
$ adb devices
List of devices attached
4A8B1C2D	device
```

`device` в выводе означает, что телефон авторизован (на экране подтвердили отладку). Если бы стояло `unauthorized`, нужно было бы подтвердить запрос на самом телефоне.

## Шаг 1: выбираем уровень извлечения

Прежде чем что-то тянуть, важно понять, что нам доступно. Есть четыре уровня, и каждый даёт больше данных, чем предыдущий:

- **Логический** (без root) — только то, что видно через ADB: общее хранилище `/sdcard`, бэкапы, выгрузки через API.
- **Файловая система** (root) — прямой доступ к `/data/data/<пакет>/`, где лежат базы приложений.
- **Физический** — полный образ флеш-памяти (через EDL/JTAG или `dd` с root).
- **Облако** — бэкапы в Google Drive/Takeout.

Без root папка `/data/data/` недоступна — это защита песочницы Android. Поэтому начинаем с того, что можно.

## Шаг 2: собираем общее хранилище

`/sdcard` — это «внутренняя память» для пользователя: фото, загрузки, документы. Она доступна без root:

```bash
$ adb pull /sdcard/ /evidence/sdcard/
/sdcard/: 2312 files pulled. 8.1 GB/s
$ adb shell pm list packages > packages.txt
$ grep example packages.txt
package:com.example.app
```

`pm list packages` перечисляет установленные приложения (это их **пакеты** — уникальные имена вида `com.example.app`). Так мы находим интересующее приложение. Узнаём путь к его APK:

```bash
$ adb shell pm path com.example.app
package:/data/app/com.example.app-1/base.apk
```

## Шаг 3: пробуем `adb backup`

Если у приложения не отключён бэкап, `adb backup` может выгрузить его данные **без root**:

```bash
$ adb backup -apk -shared -all -f backup.ab
```

Современные телефоны спросят подтверждение на экране. Файл `.ab` — это **Android Backup**: заголовок плюс tar-архив, иногда зашифрованный. Распаковывается утилитой `abe` (Android Backup Extractor):

```bash
$ java -jar abe.jar unpack backup.ab backup.tar
$ tar xf backup.tar
$ ls apps/com.example.app/
f databases/  sp/  f/
```

Вот и данные приложения: `databases/` (SQLite-базы), `sp/` (shared_prefs). Если приложение объявлено `android:allowBackup="false"`, оно сюда не попадёт — тогда нужен root или облако.

## Шаг 4: читаем базы приложений (SQLite)

С root путь к данным приложения — `/data/data/com.example.app/`. Внутри:

- `databases/` — базы **SQLite** (файлы `.db`);
- `shared_prefs/` — XML-настройки;
- `files/`, `cache/` — файлы и кэш.

SQLite — это встроенная база данных в одном файле; открывается консольным клиентом `sqlite3`:

```bash
$ adb pull /data/data/com.example.app/databases/app.db
$ sqlite3 app.db
sqlite> .tables
users    messages    sessions
sqlite> SELECT username, password FROM users;
alice|5f4dcc3b5aa765d61d8327deb882cf99
```

`.tables` показывает список таблиц, `SELECT` — сами записи. Здесь мы нашли хеш пароля. Мессенджеры хранят переписку аналогично: у WhatsApp это `msgstore.db`, у браузера Chrome — `app_chrome/Default/History`.

## Шаг 5: ищем секреты в shared_prefs

Часто токены и пароли лежат не в базе, а в **shared_prefs** — простых XML-файлах настроек. Их удобно грепать:

```bash
$ grep -riE 'token|password|api[_-]?key' /evidence/appdata/*/shared_prefs/
<string name="auth_token">eyJhbGciOiJIUzI1NiJ9...</string>
```

Найденный `auth_token` — ключ доступа к сервису приложения; с ним можно запросить данные от имени пользователя.

## Шаг 6: разбираем APK

Чтобы понять, **что приложение умеет**, декомпилируем его APK. Инструмент `jadx` превращает байткод обратно в читаемый Java:

```bash
$ adb pull /data/app/com.example.app-1/base.apk app.apk
$ jadx -d src app.apk
$ grep -rE 'http://|https://' src/ | head -3
```

А `apktool` дополнительно достаёт ресурсы и `AndroidManifest.xml` — манифест с разрешениями (`uses-permission`) и точками входа. По нему видно, к чему приложение имело доступ (GPS, контакты, интернет) и какие компоненты открыты наружу.

## Шаг 7: системные артефакты и геолокация

Данные приложения — не всё. Устройство хранит системные артефакты, которые дают контекст: где человек был и чем пользовался.

```bash
$ adb pull /data/misc/wifi/WifiConfigStore.xml
$ adb shell dumpsys usagestats > usagestats.txt
$ adb logcat -d > logcat.txt
```

`WifiConfigStore.xml` — сохранённые Wi-Fi-сети (по их MAC-адресам можно установить геолокацию, если известны точки доступа). `dumpsys usagestats` — статистика запусков приложений, `logcat` — системный лог. А фото в `/sdcard/DCIM/` часто несут **EXIF** с GPS-координатами — это прямой след перемещений.

Комбинация Wi-Fi-сетей, статистики использования и GPS из фото восстанавливает маршрут человека по дням.

## Если данных нет

Не всегда всё гладко. Три частые причины пустоты:

- **`allowBackup="false"`** — приложение запретило бэкап; без root его данные не достать.
- **Шифрованные базы** — Telegram и Signal шифруют свои базы; нужен ключ из app data (root) или пароль.
- **Android всё сильнее закрывается** — file-based encryption включено по умолчанию, и на новых версиях `adb backup` работает всё реже.

Обходной путь без root — **облачные бэкапы** (Google Takeout): часть данных приложений уходит туда, и их можно получить правовым запросом.

## Полный разбор: от ADB к базе приложения

Соберём разбор Android в один сценарий.

1. **Уровень извлечения.** Логическое (без root) / файловое (root) / физическое.
2. **Общее хранилище.** `adb pull /sdcard` — фото, загрузки, документы.
3. **Бэкап приложений.** `adb backup -apk -shared -all -f backup.ab`, затем распаковка (`abe.jar`).
4. **Базы приложений.** `data/data/<pkg>/databases/*.db` (SQLite) — переписка, история.
5. **Секреты.** `shared_prefs/*.xml` — токены, ключи, настройки.
6. **APK.** `apktool`/`jadx` — понять логику и где хранятся данные.
7. **Системные артефакты.** `dumpsys` (активность), геолокация, журналы.

```bash
$ adb shell run-as com.example.app ls databases
$ adb pull /data/data/com.example.app/databases/app.db
```

## Шпаргалка путей Android

| Путь | Что внутри |
|------|-----------|
| `/sdcard` | общее хранилище |
| `data/data/<pkg>/databases` | SQLite приложения |
| `data/data/<pkg>/shared_prefs` | настройки, токены |
| `/data/system` | системные базы (root) |
| `/data/misc` | Wi-Fi, VPN (root) |

## Частые вопросы

**`run-as` не работает.** Приложение не debug-собрано — нужен root или физическое извлечение.

**`adb backup` пустой.** Современные приложения запрещают backup (`allowBackup=false`).

**База зашифрована.** Ключ в `shared_prefs` или в keystore; ищите рядом.

**Данные удалены.** Карвинг SQLite-страниц или физический образ.

## Что мы теперь знаем

- Уровень извлечения определяет доступ: без root `/data/data` закрыта, помогает `adb backup` или облако.
- `/sdcard` доступна всегда; `pm list packages`/`pm path` находят приложение и его APK.
- `.ab`-бэкап распаковывается `abe.jar` → tar с `databases/` и `sp/`.
- Базы приложений — это SQLite; читаются `sqlite3`, секреты часто в `shared_prefs`.
- APK декомпилируется `jadx`/`apktool`; манифест показывает разрешения и компоненты.

## Квиз

Проверь себя.

```quiz
- question: "Где Android-приложения хранят SQLite-базы?"
  options:
    - "/sdcard"
    - "/data/data/<package>/databases/"
    - "/system"
    - "/proc"
  answer: 1
  explanation: "Данные приложения изолированы в его песочнице /data/data/<пакет>/databases."
- question: "Что создаёт команда adb backup?"
  options:
    - "удаляет данные"
    - "резервную копию приложений и данных в файл .ab"
    - "шифрует диск"
    - "ничего"
  answer: 1
  explanation: ".ab — Android Backup (заголовок + tar), распаковывается abe.jar."
- question: "Чем декомпилировать APK в Java-исходники?"
  options:
    - "jadx"
    - "nmap"
    - "hashcat"
    - "zeek"
  answer: 0
  explanation: "jadx превращает байткод APK обратно в читаемый Java-код."
- question: "Где часто лежат токены и пароли приложения?"
  options:
    - "/system"
    - "shared_prefs/"
    - "/proc"
    - "/etc"
  answer: 1
  explanation: "shared_prefs — XML-настройки приложения, там нередко хранятся токены."
- question: "Почему без root не прочитать /data/data?"
  options:
    - "папка пустая"
    - "это песочница приложения, доступ закрыт правами"
    - "файлы зашифрованы"
    - "нужен Wi-Fi"
  answer: 1
  explanation: "Android изолирует данные приложений; без root доступен лишь adb backup или облако."
```

## Куда дальше

Мы разобрали Android-устройство от подключения до чтения баз и APK. В следующем уроке (`forensics-mobile-ios`) мы пройдём тот же путь для iPhone: посмотрим, как устроен бэкап iOS и где искать данные приложений. А пока главное запомни: **на Android данные приложения живут в `/data/data/<пакет>/`, туда ведёт либо root, либо `adb backup`, а базы читаются `sqlite3`**.

## Где пригодится

- **CTF Forensics:** задачи с Android-дампами.
- **Мобильная форензика:** реальные расследования.
- **DFIR:** инциденты с мобильными устройствами.
- **Malware analysis:** разбор Android-малвари (APK).
- **OSINT:** данные из приложений и геолокация.
