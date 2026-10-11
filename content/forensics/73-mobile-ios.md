---
id: forensics-mobile-ios
title: "iOS-форензика: бэкапы, keychain, app data"
category: forensics
parent: forensics-mobile
difficulty: hard
order: 2
tags: [ios, itunes-backup, keychain, mobile, forensics, sqlite]
prerequisites: [forensics-mobile]
useful_for:
  - "CTF Forensics категория"
  - "Мобильная форензика"
  - "DFIR"
estimated_minutes: 55
summary: "Анализ iOS-устройств и бэкапов: структура iTunes/Finder-бэкапа, Manifest.db, Keychain, app-базы, системные артефакты и методы извлечения."
---
iOS-форензика сложна из-за жёсткой защиты: шифрование по умолчанию, Secure Enclave, песочница приложений. Тем не менее бэкапы и (при джейлбрейке) файловая система дают много данных: сообщения, звонки, геолокацию, пароли. Этот урок — про структуру iTunes/Finder-бэкапа, Manifest.db, Keychain, app-базы и системные артефакты.

## Методы извлечения

| Метод | Данные | Условия |
|-------|--------|---------|
| iTunes/Finder backup | app-данные, медиа, keychain (если шифрован) | разблокировка/доверие |
| Логическое (AFC) | медиа, часть данных | джейлбрейк/AFC2 |
| Файловая система | всё | джейлбрейк |
| Физическое (checkm8) | всё | уязвимые устройства (A5–A11) |
| Облако (iCloud) | бэкап/синхронизация | правовые запросы |

Для большинства устройств реалистичен **бэкап**; физическое извлечение — только для уязвимых чипов.

## Структура бэкапа

```bash
$ ls ~/Library/Application\ Support/MobileSync/Backup/<UDID>/
Info.plist  Manifest.db  Manifest.plist  Status.plist  00/ 01/ ... ff/
# файлы бэкапа названы SHA1(domain-relativePath)
$ sqlite3 Manifest.db "SELECT fileID, domain, relativePath, flags FROM Files LIMIT 10;"
```

`Manifest.db` — карта: `fileID` (имя файла), `domain` (например, `AppDomain-com.apple.MobileSMS`), `relativePath`, `flags` (0 = файл, 1 = каталог). Файлы разложены по подкаталогам `00`–`ff` (первые 2 символа `fileID`).

```bash
# извлечь все файлы с сохранением структуры
$ python3 - <<'PY'
import sqlite3, os, shutil
db=sqlite3.connect('Manifest.db'); c=db.cursor()
for fid,dom,rel in c.execute("SELECT fileID,domain,relativePath FROM Files WHERE flags=0"):
    src=os.path.join(fid[:2],fid)
    if os.path.exists(src):
        dst=os.path.join('out',dom,rel); os.makedirs(os.path.dirname(dst),exist_ok=True)
        shutil.copy(src,dst)
PY
```

## Расшифровка бэкапа

Незашифрованный бэкап не содержит Keychain. Зашифрованный — содержит, но требует пароля.

```bash
$ python3 iphone_backup_decrypt.py <backup_dir> <password> -o decrypted/
$ backup_tool.py --backup <dir> --password <pw> --extract
```

## Manifest.db и Keychain

**Keychain** (`KeychainDomain`) в бэкапе — это `keychain-backup.plist`; расшифровывается паролем бэкапа. Инструменты: `iLEAPP`, `iOSbackup`, `chainbreaker`.

```bash
$ sqlite3 Manifest.db "SELECT fileID,relativePath FROM Files WHERE domain='KeychainDomain';"
# извлечь и разобрать
$ python3 -m ileapp -t itunes -i <backup> -o out/
```

## App-данные и системные артефакты

| Домен | Данные |
|-------|--------|
| `AppDomain-com.apple.MobileSMS` | `sms.db` (SMS/iMessage) |
| `HomeDomain` | `Library/SMS`, звонки, заметки |
| `AppDomain-com.apple.mobilephone` | история звонков |
| `AppDomain-com.apple.Maps` | геолокация |
| `AppDomain-<third-party>` | базы мессенджеров |
| `CameraRollDomain` | фото/видео (EXIF) |

```bash
# SMS/iMessage
$ sqlite3 sms.db "SELECT text, datetime(date/1000000000 + 978307200,'unixepoch') FROM message LIMIT 5;"
# звонки
$ sqlite3 CallHistory.storedata "SELECT ZADDRESS, ZDURATION FROM ZCALLRECORD LIMIT 5;"
# заметки
$ sqlite3 NoteStore.sqlite ".tables"
# геолокация
$ sqlite3 Cache.sqlite "SELECT * FROM Locations LIMIT 5;" 2>/dev/null
```

**Важно**: iOS-время (Core Data) — секунды с 2001-01-01 (`978307200` — смещение к Unix). Наносекунды в `sms.db` делятся на 1e9.

## Сторонние приложения

Мессенджеры хранят данные в своих доменах:

```bash
# WhatsApp: ChatStorage.sqlite
$ sqlite3 ChatStorage.sqlite "SELECT ZTEXT FROM ZWAMESSAGE LIMIT 5;"
# Telegram: cache4.db
$ sqlite3 cache4.db "SELECT * FROM messages LIMIT 5;"
# Signal: signal.sqlite
$ sqlite3 signal.sqlite ".tables"
```

## Разобранный пример

Дан iOS-бэкап. Нужно найти переписку и геолокацию.

```bash
# 1. Карта файлов
$ sqlite3 Manifest.db "SELECT domain,relativePath FROM Files WHERE relativePath LIKE '%sms%';"
AppDomain-com.apple.MobileSMS|Library/SMS/sms.db
# 2. Извлечь и прочитать
$ python3 extract_backup.py && sqlite3 out/AppDomain-com.apple.MobileSMS/Library/SMS/sms.db \
    "SELECT text FROM message ORDER BY date DESC LIMIT 5;"
# 3. Фото с GPS
$ exiftool -a -gps:all out/CameraRollDomain/Media/DCIM/*.JPG | head
# 4. Keychain (если бэкап зашифрован)
$ python3 iphone_backup_decrypt.py <dir> <pw> -o dec && chainbreaker keychain-backup.plist -p <pw>
```

## Справочная таблица

| Артефакт | Файл/домен |
|----------|-----------|
| SMS/iMessage | `sms.db` |
| Звонки | `CallHistory.storedata` |
| Геолокация | `Cache.sqlite`, EXIF |
| Заметки | `NoteStore.sqlite` |
| Keychain | `keychain-backup.plist` |
| WhatsApp | `ChatStorage.sqlite` |

## Частые ошибки

- **Считать незашифрованный бэкап полным** — нет Keychain.
- **Путать эпоху времени** (2001 vs 1970).
- **Игнорировать `Manifest.db`** — без него файлы безымянны.
- **Не извлекать сторонние app-домены** — там переписка.
- **Забывать про EXIF** — геолокация из фото.
- **Анализировать живое устройство** — меняет артефакты.

## Что дальше / решение

Конвейер: `Manifest.db` (карта) → извлечь домены → SQLite (сообщения/звонки) → `exiftool` (GPS) → `iphone_backup_decrypt`+`chainbreaker` (keychain). Связка: `forensics-mobile` (основы), `forensics-mobile-android` (Android), `forensics-sqlite` (базы), `forensics-apfs`.

## Системные артефакты и jailbreak

Помимо app-данных, в бэкапе/ФС есть системные артефакты:

| Артефакт | Данные |
|----------|--------|
| `HomeDomain` | настройки, `Library/SMS`, `Library/Preferences` |
| `SysContainerDomain` | системные контейнеры |
| `WirelessDomain` | WiFi-сети |
| `RootDomain` | `/var/mobile` |
| `KeyboardDomain` | словари клавиатуры (введённые слова!) |
| `AppDomain-com.apple.MobileMail` | почта |

```bash
# WiFi-сети
$ plutil -p out/WirelessDomain/Library/Preferences/com.apple.wifi.plist
# словарь клавиатуры (введённые пользователем слова)
$ plutil -p out/KeyboardDomain/Library/Keyboard/dynamic-text.dat
# заметки
$ sqlite3 out/HomeDomain/Library/Notes/notes.sqlite ".tables"
```

**Jailbreak-артефакты** (если устройство взломано): `/Applications/Cydia.app`, `dpkg`-логи, `fstab` с `rw`, `afc2`-сервис, подозрительные `LaunchDaemons` в `/Library/LaunchDaemons`.

```bash
$ ls out/RootDomain/Applications/ | grep -i cydia
$ grep -i 'jailbreak\|substrate\|cydia' out/*/Library/Logs/* 2>/dev/null
```

## Face ID/Touch ID и Secure Enclave

Биометрические данные и ключи Secure Enclave **не извлекаются** — они аппаратно защищены. Пароль устройства и биометрия — вне досягаемости; работайте с тем, что доступно (бэкап/ФС после разблокировки).

## Сводный чек-лист

1. `Manifest.db` — карта файлов.
2. Извлечь домены (Home, AppDomain, CameraRoll).
3. SQLite: SMS, звонки, заметки, сторонние приложения.
4. `exiftool` — GPS из фото.
5. `plutil` — WiFi/настройки/клавиатура.
6. `iphone_backup_decrypt`+`chainbreaker` — keychain.
7. Jailbreak-артефакты (если есть).
8. Свести таймлайн.

## Ограничения

- **Шифрование** — современные устройства защищены; без экрана многие данные недоступны.
- **Secure Enclave** — биометрия/ключи не извлекаются.
- **iCloud** — часть данных только в облаке.
- **Пароль бэкапа** — без него keychain недоступен.
- **Checkm8** работает только на уязвимых чипах (A5–A11).

## Сравнение Android/iOS

| Аспект | Android | iOS |
|--------|---------|-----|
| Доступность | ADB, root, образы | жёстко ограничена |
| Бэкап | `adb backup` (.ab) | iTunes/Finder backup |
| Шифрование | file-based (по умолчанию) | Data Protection |
| Keychain | Android Keystore | Secure Enclave |
| Сторонние app | APK-домены | AppDomain-* |
| Геолокация | Google location | Maps/Cache.sqlite |

Android обычно «открытее»; iOS полагается на бэкап. Обе платформы всё сильнее шифруют данные.

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `iLEAPP` | парсинг iOS-артефактов |
| `iphone_backup_decrypt` | расшифровка бэкапа |
| `chainbreaker` | Keychain |
| `libimobiledevice` | доступ к устройству |
| `sqlite3` | app-базы |
| `exiftool` | GPS из медиа |
| `plutil` | plist |

## Практические приёмы

- **Изолируйте сеть** (авиарежим) до извлечения.
- **Определите тип бэкапа** (шифрован/нет) — от этого зависит keychain.
- **Начинайте с `Manifest.db`** — карта файлов.
- **Извлекайте сторонние app-домены** — переписка.
- **Время** — Core Data с 2001 (Unix = +978307200).
- **Keychain только из зашифрованного** бэкапа + пароль.
- **Фиксируйте хеши** бэкапа и извлечённых файлов.

## Оформление результатов

В отчёте указывайте: метод извлечения, домены/файлы, извлечённые артефакты (сообщения, звонки, GPS), времена (нормализованные), ограничения (что недоступно из-за шифрования). Помните о приватности: переписка и геолокация — чувствительные данные, обращайтесь в рамках авторизации.

## Квиз

```quiz
- question: "Какой файл бэкапа iOS связывает domain/путь и хеш-имя файла?"
  options:
    - "Info.plist"
    - "Manifest.db"
    - "Status.plist"
    - "sms.db"
  answer: 1
- question: "Какую эпоху времени использует iOS (Cocoa)?"
  options:
    - "Unix 1970"
    - "2001-01-01 (Apple epoch)"
    - "1601"
    - "2000"
  answer: 1
- question: "Где хранятся SMS в iOS-бэкапе?"
  options:
    - "Library/SMS/sms.db"
    - "Library/CallHistoryDB"
    - "Library/Safari/History.db"
    - "Keychain"
  answer: 0
- question: "Что даёт зашифрованный бэкап по сравнению с обычным?"
  options:
    - "ничего"
    - "доступ к Keychain, Health и паролям"
    - "только медиа"
    - "только контакты"
  answer: 1
- question: "Как понять, зашифрован ли бэкап?"
  options:
    - "по размеру"
    - "по полю IsEncrypted в Info.plist"
    - "по имени папки"
    - "по Manifest.db"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с iOS-бэкапами и app-данными.
- **Мобильная форензика:** извлечение переписки, истории, настроек.
- **DFIR:** расследование мобильных инцидентов.
- **Судебная экспертиза:** доказательство сообщений и активности.
- **Анализ приложений:** понимание структуры хранения данных.
