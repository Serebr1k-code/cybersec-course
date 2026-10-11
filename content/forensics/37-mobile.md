---
id: forensics-mobile
title: "Введение в мобильную форензику"
category: forensics
parent: forensics-img-mobile
difficulty: hard
order: 1
tags: [mobile, android, ios, adb, sqlite, apk, backup, artifacts]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Мобильная экспертиза"
  - "Анализ Android/iOS"
estimated_minutes: 45
summary: "Основы мобильной форензики: извлечение данных Android (ADB, образ, backup) и iOS, разбор приложений (APK/IPA), базы SQLite, артефакты мессенджеров и геолокации."
---
Мобильная форензика — одна из самых востребованных областей: смартфон содержит переписку, геолокацию, пароли, фото и следы приложений. Android и iOS принципиально различаются по доступности данных: Android более открыт (ADB, образы), iOS жёстко защищён (шифрование, Secure Enclave). Этот урок — про извлечение данных Android и iOS, разбор приложений и типовые артефакты.

## Методы извлечения

| Уровень | Android | iOS |
|---------|---------|-----|
| Логическое (backup) | `adb backup`, `bmgr` | iTunes/Finder backup |
| Файловая система | root + `adb pull`, TWRP | jailbreak + AFC2 |
| Физическое (образ) | `dd` по eMMC/UFS, ISP | почти невозможно (шифр) |
| Облако | Google Takeout | iCloud (правовые запросы) |

Современные Android (шифрование по умолчанию, Android 10+) требуют разблокировки и часто root. iOS-бэкап (если не зашифрован) даёт много данных; зашифрованный бэкап — keychain.

## Android: ADB и backup

```bash
# подключение
$ adb devices
# логический бэкап (может требовать подтверждения на устройстве)
$ adb backup -apk -shared -all -f backup.ab
# конвертация .ab в tar
$ java -jar abe.jar unpack backup.ab backup.tar
$ tar -xf backup.tar -C extracted/
# извлечь данные приложения (root)
$ adb shell su -c 'tar czf /sdcard/app.tgz /data/data/com.app/.'
$ adb pull /sdcard/app.tgz
```

`.ab`-бэкап содержит `apps/` и `shared/`; keychain (Android 9+) — только на разблокированном устройстве.

## Android: структура и артефакты

| Путь | Содержимое |
|------|-----------|
| `/data/data/<pkg>/` | данные приложения (базы, prefs) |
| `/data/data/<pkg>/databases/*.db` | SQLite (сообщения, контакты) |
| `/data/system/` | accounts, gestures, packages |
| `/sdcard/` | медиа, загрузки |
| `/data/misc/wifi/` | WiFi-конфиги |
| `/data/system/dropbox/` | системные события |

```bash
# базы мессенджеров
$ sqlite3 msgstore.db "SELECT name FROM sqlite_master WHERE type='table';"
$ sqlite3 msgstore.db "SELECT key_remote_jid, data FROM messages LIMIT 5;"
# WhatsApp
$ sqlite3 /data/data/com.whatsapp/databases/msgstore.db
# геолокация
$ sqlite3 location.db "SELECT * FROM locations LIMIT 5;"
```

Android-приложения используют SQLite почти повсеместно — читайте их (см. `forensics-sqlite`).

## iOS: бэкап

```bash
# структура iTunes/Finder-бэкапа
$ ls ~/Library/Application\ Support/MobileSync/Backup/<UDID>/
Info.plist  Manifest.db  Manifest.plist  <40-char hash files>
# Manifest.db — карта файлов
$ sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files;"
# извлечь файл по его хешу
$ cp <hash> out/AppDomain-com.app-...-file.db
```

`Manifest.db` сопоставляет `fileID` (имя файла = SHA1 пути) с доменом и путём. Зашифрованный бэкап требует пароля (`backup password`), но содержит keychain.

```bash
# расшифровать бэкап
$ python3 iphone_backup_decrypt.py <backup_dir> <password> -o decrypted/
# инструменты: iLEAPP, ALEAPP, libimobiledevice
$ ileapp -i <backup> -o out/
```

## Разбор приложений (APK/IPA)

```bash
# APK: распаковка
$ apktool d app.apk -o app_src/
$ unzip -o app.apk -d app_unz/
# декомпиляция DEX
$ jadx -d app_java/ app.apk
# нативный код
$ jadx --show-bad-code app.apk
# IPA: это ZIP
$ unzip -o app.ipa -d app_ipa/
$ ls app_ipa/Payload/*.app/
```

Для iOS IPA содержит `Payload/App.app/` с бинарём (Mach-O) и `Info.plist`. Анализ строк и ключей API — `strings`, `class-dump`.

## Артефакты мессенджеров и геолокации

- **WhatsApp/Telegram/Signal**: SQLite-базы (`msgstore.db`, `cache4.db`).
- **Геолокация**: Google Maps history, `location.db`, снимки с GPS-EXIF.
- **Фото/медиа**: EXIF (дата, GPS, модель).
- **Аккаунты/пароли**: keychain (iOS), `accounts.db` (Android).

```bash
# EXIF из фото
$ exiftool -a -gps:all IMG_0001.jpg
$ exiftool -d '%Y-%m-%d %H:%M:%S' -DateTimeOriginal -GPSLatitude -GPSLongitude IMG*.jpg
```

## Разобранный пример

Дан Android-бэкап `backup.ab`. Нужно найти переписку и локацию.

```bash
$ java -jar abe.jar unpack backup.ab backup.tar
$ tar -xf backup.tar -C ext/
# найти базы
$ find ext/ -name '*.db' | head
ext/apps/com.whatsapp/db/msgstore.db
# прочитать сообщения
$ sqlite3 ext/apps/com.whatsapp/db/msgstore.db \
    "SELECT key_remote_jid, substr(data,1,40) FROM messages ORDER BY timestamp DESC LIMIT 5;"
# геолокация из фото
$ exiftool -a -gps:all ext/shared/DCIM/Camera/*.jpg | head
```

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| ADB | `adb devices`, `adb backup`, `adb pull` |
| .ab → tar | `abe.jar` |
| iOS backup | `Manifest.db`, `iphone_backup_decrypt` |
| Парсинг артефактов | ALEAPP (Android), iLEAPP (iOS) |
| APK | `apktool`, `jadx` |
| SQLite | `sqlite3` |
| EXIF | `exiftool` |

## Частые ошибки

- **Извлекать без блокировки сети** — облако может удалить/синхронизировать данные; включите авиарежим.
- **Игнорировать шифрование** — современный Android/iOS шифрует по умолчанию.
- **Разблокировать устройство «как обычно»** — меняет артефакты; фиксируйте состояние.
- **Читать SQLite без учёта WAL** — свежие записи в `-wal`/`-shm`.
- **Забывать про облачные копии** — часть данных только там.
- **Не считать хеши образа** — для цепочки улик.

## Что дальше / решение

Определите платформу и метод извлечения (backup/FS/образ) → разберите артефакты (SQLite, Manifest.db, EXIF) → для приложений — `jadx`/`apktool`. Связка: `forensics-mobile-android`, `forensics-mobile-ios` (глубоко), `forensics-sqlite` (базы), `forensics-img-mobile` (образы).

## Инструменты и автоматизация

| Инструмент | Платформа | Назначение |
|-----------|-----------|-----------|
| `adb` | Android | связь, backup, pull |
| `abe.jar` | любая | распаковка `.ab` |
| `Magnet AXIOM`/`Cellebrite` | коммерческие | полный разбор |
| ALEAPP | Android | парсинг артефактов |
| iLEAPP | iOS | парсинг артефактов |
| `libimobiledevice` | iOS | доступ к устройству |
| `jadx`/`apktool` | любая | разбор APK |
| `sqlite3` | любая | базы |

```bash
# ALEAPP: разбор извлечённых данных Android
$ python3 aleapp.py -t tar -i extracted.tar -o out/
# iLEAPP: разбор iOS-бэкапа
$ python3 ileapp.py -t itunes -i <backup_dir> -o out/
```

Автоматические парсеры строят таймлайны, извлекают сообщения, звонки, локации и пароли — это ускоряет первичный разбор в разы.

## Шифрование и доступность

Современные устройства шифруют данные по умолчанию. Ключи привязаны к экрану блокировки и Secure Enclave/StrongBox. Что это значит:

- **Android 7+**: file-based encryption; без экрана — часть данных недоступна.
- **iOS**: Data Protection; после блокировки многие файлы недоступны даже с джейлбрейком.
- **Облако**: часть данных синхронизируется (Google/iCloud) — отдельный источник.
- **Full FS access**: требует root (Android) или джейлбрейка (iOS), что меняет систему.

## Правовые и этические аспекты

Мобильная форензика затрагивает приватность: переписка, геолокация, биометрия. Работайте строго в рамках авторизации, фиксируйте согласие/ордер, минимизируйте копирование персональных данных и соблюдайте цепочку хранения. Перед разбором ставьте устройство в авиарежим (или изолируйте в Faraday-мешок), чтобы предотвратить удалённую очистку и синхронизацию.

## Чек-лист извлечения

1. Задокументировать устройство (модель, IMEI, ОС, состояние экрана).
2. Изолировать сеть (авиарежим/Faraday).
3. Получить метод извлечения (backup/FS/образ) в рамках авторизации.
4. Зафиксировать хеши.
5. Разобрать артефакты (SQLite, Manifest.db, EXIF).
6. Для приложений — `jadx`/`apktool`.
7. Свести таймлайн.
8. Зафиксировать IOC и отчёт.

## Квиз

```quiz
- question: "Что даёт `adb backup`?"
  options:
    - "физический образ"
    - "логический бэкап приложений"
    - "память"
    - "ядро"
  answer: 1
- question: "Где Android хранит настройки и токены приложения?"
  options:
    - "в `/system`"
    - "в `shared_prefs/*.xml`"
    - "в ядре"
    - "в `boot.img`"
  answer: 1
- question: "Как восстановить удалённые записи SQLite?"
  options:
    - "`sqlite3 app.db ".recover"` / free pages"
    - "`unzip`"
    - "`binwalk`"
    - "`dd`"
  answer: 0
- question: "Как связать файлы в iOS-бэкапе с путями?"
  options:
    - "по имени"
    - "через `Manifest.db` (SHA-1 от пути)"
    - "по расширению"
    - "никак"
  answer: 1
- question: "Где в APK искать hardcoded-секреты?"
  options:
    - "в `classes.dex` и ресурсах"
    - "в ядре"
    - "в MFT"
    - "в EVTX"
  answer: 0
```

## Где пригодится

- **CTF:** задачи с Android/iOS-артефактами.
- **Мобильная экспертиза:** извлечение переписок и геолокации.
- **Incident Response:** анализ компрометации мобильных устройств.
- **AppSec:** разбор APK/IPA на секреты.
- **Криминалистика:** доказательства из мессенджеров.
