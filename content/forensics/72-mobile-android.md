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

## Уровни извлечения Android

1. **Логическое** (без root): ADB pull доступных файлов, `adb backup`, контакты/SMS через API.
2. **Файловая система** (root): прямой доступ к `/data/data/<package>/`.
3. **Физическое** (полный образ): через EDL/ISP/JTAG или с root (`dd`).
4. **Облако:** Google Drive/Takeout, WhatsApp/Telegram cloud.

Чем выше уровень, тем больше данных. Для CTF часто достаточно логического или дампа `/data`.

## ADB: базовые команды

```bash
adb devices
adb shell
adb pull /sdcard/ /evidence/sdcard/        # внешнее хранилище
adb shell pm list packages                  # список приложений
adb shell pm path com.example.app           # путь APK
adb pull /data/data/com.example.app/        # только с root
adb shell dumpsys                          # системная информация
adb shell dumpsys battery
adb shell dumpsys package com.example.app
```

## adb backup

```bash
# Полный бэкап (если разрешён приложением)
adb backup -apk -shared -all -f backup.ab
# Извлечение .ab (нужен abe.jar или Android Backup Extractor)
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

Современный Android ограничивает `adb backup` (нужно подтверждение на устройстве), но для старых устройств/CTF работает.

## App data и SQLite

Приложения хранят данные в `/data/data/<package>/`:

- `databases/` — SQLite-базы (`*.db`, `*.sqlite`).
- `shared_prefs/` — XML-настройки.
- `files/`, `cache/` — файлы и кэш.
- `lib/` — библиотеки.

```bash
# Извлечение (root)
adb pull /data/data/com.whatsapp/databases/msgstore.db
# Анализ
sqlite3 msgstore.db
sqlite> .tables
sqlite> SELECT * FROM message LIMIT 5;
```

Мессенджеры: WhatsApp (`msgstore.db`), Telegram (зашифрованы, ключ в `shared_prefs`), Signal (зашифрованы). Браузеры: Chrome (`/data/data/com.android.chrome/app_chrome/Default/History`).

## APK и его разбор

```bash
# Скачать APK
adb pull $(adb shell pm path com.example.app | cut -d: -f2) app.apk
# Декомпиляция
apktool d app.apk -o app_src
# Или jadx
jadx -d app_src app.apk
# Манифест
cat app_src/AndroidManifest.xml
```

Манифест даёт разрешения, компоненты, точки входа — важно для понимания, что приложение делало.

## Системные артефакты

- **`/data/system/`:** `packages.xml`, `usagestats/`, `batterystats/`, `accounts.db`.
- **`/data/misc/`:** `wifi/WifiConfigStore.xml`, `keystore/`, `bluetooth/`.
- **`/data/local/tmp/`:** часто dropzone атакующего.
- **`/system/etc/`:** системные конфиги.
- **`dmesg`, `logcat`:** системные/приложенческие логи.
- **`/sdcard/DCIM/`:** фото (с EXIF/GPS).

```bash
adb shell dumpsys usagestats        # статистика использования
adb shell dumpsys wifi
adb logcat -d > logcat.txt
```

## Практический пример: разбор устройства

```bash
# 1. Подключение и базовый сбор
adb devices
adb pull /sdcard/ /evidence/sdcard/
# 2. Список приложений
adb shell pm list packages > packages.txt
# 3. (root) выгрузка app data
adb pull /data/data/ /evidence/appdata/
# 4. Анализ SQLite
for db in $(find /evidence/appdata -name "*.db"); do sqlite3 "$db" ".tables"; done
# 5. shared_prefs
grep -riE 'password|token|key' /evidence/appdata/*/shared_prefs/
# 6. APK
adb pull /data/app/.../base.apk app.apk && jadx -d src app.apk
```

## Инструменты и команды

```bash
# ADB, abe (Android Backup Extractor), apktool, jadx
# Autopsy/Magnet AXIOM для автоматизации
# adb backup / adb pull / sqlite3
# MobSF для анализа APK
```

## adb backup детально и обход ограничений

`adb backup` создаёт `.ab` (Android Backup) — файл с заголовком и tar-архивом, опционально зашифрованный. Извлечение:

```bash
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar
```

Ограничения современного Android: приложения с `android:allowBackup="false"` не бэкапятся; требуется подтверждение на устройстве. Для старых устройств работает почти всегда. Альтернатива — **облачные бэкапы** (Google Takeout) и **root**-доступ.

## Root: Magisk и извлечение

С root доступны `/data/data`, `/data/system`, все базы. Получение root: разблокировка bootloader + Magisk (patch boot image). Для форензики лучше **не модифицировать** устройство (нарушает целостность) — но для CTF/лаборатории допустимо.

```bash
# Полный дамп /data (с root)
adb shell su -c "dd if=/dev/block/by-name/userdata of=/sdcard/userdata.img"
adb pull /sdcard/userdata.img
```

Физическое извлечение (без root): через EDL (Qualcomm), ISP, JTAG, или инструменты (Cellebrite, Oxygen) — вне CTF-контекста.

## Зашифрованные базы мессенджеров

- **WhatsApp:** `msgstore.db` (SQLite) + `msgstore.db.crypt14` (зашифрованный бэкап); ключ на устройстве.
- **Telegram:** базы зашифрованы (`cache4.db`); ключ в `shared_prefs`/`files`.
- **Signal:** SQLite + шифрование, ключ в `shared_prefs`.
- **Browsers:** Chrome History (SQLite), cookies (шифрованы).

Для расшифровки нужен ключ из app data (root) или passphrase.

## Инструменты и команды

```bash
# ADB
adb devices
adb shell pm list packages
adb shell pm path com.example.app
adb pull /sdcard/ /evidence/sdcard/
adb shell dumpsys usagestats > usagestats.txt
adb shell dumpsys wifi > wifi.txt
adb logcat -d > logcat.txt

# Backup
adb backup -apk -shared -all -f backup.ab
java -jar abe.jar unpack backup.ab backup.tar && tar xf backup.tar

# APK
adb pull $(adb shell pm path com.example.app | cut -d: -f2) app.apk
apktool d app.apk -o src
jadx -d src app.apk

# SQLite
sqlite3 /evidence/appdata/com.example/databases/app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# Инструменты
# MobSF (APK), Autopsy, Magnet AXIOM, Andriller
```

## Геолокация и системные артефакты

- **GPS:** `/data/data/com.google.android.gms/` (Google Location History), приложения карт.
- **Wi-Fi сети:** `/data/misc/wifi/WifiConfigStore.xml` — сохранённые сети (геолокация по BSSID).
- **Bluetooth:** `/data/misc/bluetooth/`.
- **Аккаунты:** `/data/system/accounts.db`.
- **Использование приложений:** `/data/system/usagestats/`.
- **Фото с EXIF GPS:** `/sdcard/DCIM/`.

```bash
adb pull /data/misc/wifi/WifiConfigStore.xml
adb pull /data/system/usagestats/
adb pull /sdcard/DCIM/ /evidence/dcim/
```

Комбинация Wi-Fi-сетей + GPS + фото даёт полную картину перемещений.

## APK: статический анализ

```bash
# Декомпиляция
apktool d app.apk -o app_src        # ресурсы + smali
jadx -d app_src app.apk             # Java-исходники
# Манифест: разрешения, компоненты, точки входа
cat app_src/AndroidManifest.xml
# Поиск секретов в ресурсах
grep -rE 'api[_-]?key|secret|token|http' app_src/ | head
# Анализ через MobSF (веб-интерфейс)
```

Манифест показывает `uses-permission` (доступ к GPS, контактам, интернету), `exported`-компоненты (векторы атаки), `network_security_config`. Секреты часто «зашиты» в строки/ресурсы.

## Итог

Android-форензика: определите уровень доступа (root/нет), соберите `/sdcard` и app data, разберите SQLite и shared_prefs, декомпилируйте APK. Системные артефакты (Wi-Fi, usagestats, accounts) дают контекст, логи — события. Облачные бэкапы — fallback при отсутствии root. `adb`/`apktool`/`jadx`/MobSF — базовый набор.

## Резюме

Уровень доступа → `/sdcard` + app data → SQLite/shared_prefs → APK → системные артефакты → логи. Облако как fallback, если нет root. adb/apktool/jadx/MobSF — базовый набор для извлечения и разбора данных Android-устройства. Помните: большинство секретов (токены, ключи, пароли) лежат в shared_prefs и базах приложений.

## Частые ошибки

- **Нет root — нет `/data/data`.** Используйте backup или облако.
- **Забыть про `/sdcard`** (внешнее хранилище).
- **Игнорировать `shared_prefs`.** Там токены/пароли.
- **Не проверить логи** (`logcat`, `dmesg`).
- **Не разобрать APK.** Манифест важен.
- **Зашифрованные базы** (Telegram/Signal) требуют ключа.

## Как не застрять

- **Определите уровень доступа** (root/нет).
- **Соберите `/sdcard` и app data.**
- **SQLite + shared_prefs** — главные источники.
- **Разберите APK** (jadx/apktool).
- **Логи** — `logcat`/`dmesg`.
- **Облако** как fallback.

## Квиз

```quiz
- question: "Где приложения Android хранят SQLite-базы?"
  options:
    - "/sdcard"
    - "/data/data/<package>/databases/"
    - "/system"
    - "/proc"
  answer: 1
- question: "Что делает `adb backup`?"
  options:
    - "удаляет данные"
    - "создаёт резервную копию приложений/данных (.ab)"
    - "шифрует"
    - "ничего"
  answer: 1
- question: "Чем разобрать APK в Java-исходники?"
  options:
    - "jadx"
    - "nmap"
    - "hashcat"
    - "zeek"
  answer: 0
- question: "Где часто хранятся токены/пароли приложения?"
  options:
    - "/system"
    - "shared_prefs/"
    - "/proc"
    - "/etc"
  answer: 1
- question: "Что нужно для доступа к /data/data без root?"
  options:
    - "ничего"
    - "обычно невозможно (нужен root или backup)"
    - "перезагрузка"
    - "ADB"
  answer: 1
```

## Где пригодится

- **CTF Forensics** — задачи с Android-дампами.
- **Мобильная форензика** — реальные расследования.
- **DFIR** — инциденты с мобильными устройствами.
- **Malware analysis** — разбор Android-малвари (APK).
- **OSINT** — данные из приложений.
