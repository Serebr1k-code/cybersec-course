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
lab:
  kind: shell
  title: "Практика: найти сообщение в iOS-бэкапе"
  toolset: [core, plutil, sqlite]
  workdir: /home/student/task
  files: [task.md, notes.txt, Info.plist, Manifest.db, sms.db]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Определи, зашифрован ли бэкап: `plutil -p Info.plist` (ключ `IsEncrypted`)."
    - "Карта файлов — в `Manifest.db`: `sqlite3 Manifest.db \"SELECT fileID, domain, relativePath FROM Files\"`."
    - "Переписка лежит в `sms.db` (домен `AppDomain-com.apple.MobileSMS`)."
    - "Прочитай сообщения: `sqlite3 sms.db \"SELECT text FROM message\" | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается

Изъят iPhone. Прямого доступа к файловой системе нет — iOS зашифрована и закрыта песочницей, а биометрия защищена аппаратно. Но у нас есть **бэкап** устройства, снятый через Finder/iTunes. Задача: найти в нём переписку, историю звонков и следы перемещений.

В прошлом уроке мы разбирали Android, где данные лежат открыто в `/data/data/`. iOS устроена иначе: доступ к данным даёт именно **бэкап**, и он имеет свою структуру, которую мы разберём.

## Наш пример: каталог iOS-бэкапа

Бэкап — это папка с именем-идентификатором устройства (UDID):

```bash
$ ls ~/Library/Application\ Support/MobileSync/Backup/<UDID>/
Info.plist  Manifest.db  Manifest.plist  Status.plist  00/  01/  ...  ff/
```

Сразу видим странность: файлы разложены по подкаталогам `00`–`ff`, и имена у них не человеческие, а вроде `a1b2c3...`. Почему так — поймём через минуту.

## Шаг 1: определяем тип бэкапа

Первое, что нужно выяснить, — **зашифрован ли бэкап**. Это решает, получим ли мы доступ к паролям. Ответ лежит в `Info.plist` (файл настроек):

```bash
$ plutil -p Info.plist | grep -iE 'IsEncrypted|ProductType|ProductVersion'
"IsEncrypted" => 1
"ProductType" => "iPhone14,5"
"ProductVersion" => "17.4"
```

`IsEncrypted = 1` — бэкап зашифрован. Это хорошая новость для расследования: **незашифрованный** бэкап не содержит Keychain (хранилище паролей), а зашифрованный — содержит. Плата за это — пароль бэкапа, который надо получить у владельца или подобрать.

## Шаг 2: читаем карту файлов

Теперь ключевой файл — `Manifest.db`. Это база **SQLite**, которая сопоставляет «хеш-имя» файла в папке бэкапа с его реальным путём в системе телефона.

```bash
$ sqlite3 Manifest.db "SELECT fileID, domain, relativePath FROM Files LIMIT 5;"
a1b2c3d4...  HomeDomain          Library/Preferences/com.apple.mobiletimer.plist
e5f6a7b8...  AppDomain-com.apple.MobileSMS  Library/SMS/sms.db
9c0d1e2f...  CameraRollDomain    Media/DCIM/100APPLE/IMG_0001.JPG
```

Три колонки — три важных понятия. `fileID` — это хеш (SHA1) от домена и пути; именно он становится именем файла в бэкапе, поэтому имена «нечитаемые». `domain` — область данных: `HomeDomain` (системные настройки), `AppDomain-<пакет>` (данные приложения), `CameraRollDomain` (фото). `relativePath` — путь внутри домена.

Теперь понятно, зачем нужен `Manifest.db`: без него файлы в бэкапе **безымянные**. С ним мы знаем, где искать `sms.db` (переписка).

## Шаг 3: извлекаем нужные домены

Сопоставляя `fileID` с именем файла в подкаталоге, раскладываем бэкап обратно в человеческую структуру:

```bash
$ python3 - <<'PY'
import sqlite3, os, shutil
db = sqlite3.connect('Manifest.db')
for fid, dom, rel in db.execute("SELECT fileID,domain,relativePath FROM Files WHERE flags=0"):
    src = os.path.join(fid[:2], fid)
    if os.path.exists(src):
        dst = os.path.join('out', dom, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(src, dst)
PY
```

`flags=0` отбирает файлы (у каталогов другой флаг). Первые два символа `fileID` задают подкаталог, где лежит файл. После этого данные снова разложены по путям, как на телефоне.

## Шаг 4: читаем переписку и звонки

Теперь работаем как с обычными базами. SMS и iMessage лежат в `sms.db` домена `AppDomain-com.apple.MobileSMS`:

```bash
$ sqlite3 out/AppDomain-com.apple.MobileSMS/Library/SMS/sms.db \
  "SELECT text FROM message ORDER BY date DESC LIMIT 3;"
```

История звонков — в `CallHistory.storedata`, заметки — в `NoteStore.sqlite`. Но есть важная тонкость со временем: iOS хранит его не от Unix-эпохи (1970), а от **2001 года**. Разница — константа `978307200` секунд. В `sms.db` время ещё и в наносекундах, поэтому делят на `1e9`:

```bash
$ sqlite3 sms.db "SELECT datetime(date/1000000000 + 978307200,'unixepoch') FROM message LIMIT 3;"
```

Без этой поправки все даты уедут на 31 год — классическая ошибка.

## Шаг 5: геолокация из фото

Фото в `CameraRollDomain` сохраняют **EXIF** — метаданные, среди которых GPS-координаты (мы разбирали EXIF в `forensics-metadata`):

```bash
$ exiftool -a -gps:all out/CameraRollDomain/Media/DCIM/100APPLE/IMG_0001.JPG | head
GPS Latitude  : 55 deg 45' 21.00" N
GPS Longitude : 37 deg 37' 4.00" E
```

Каждый снимок с координатами — точка на карте перемещений. Вместе с геоданными приложения Maps (`Cache.sqlite`) это восстанавливает маршрут.

## Шаг 6: Keychain — пароли

Если бэкап зашифрован (а у нас `IsEncrypted = 1`), в домене `KeychainDomain` лежит `keychain-backup.plist` — зашифрованное хранилище паролей, сертификатов и ключей. Расшифровывается **паролем бэкапа**:

```bash
$ python3 iphone_backup_decrypt.py <backup_dir> <password> -o decrypted/
$ chainbreaker keychain-backup.plist -p <password>
```

`chainbreaker` печатает записи Keychain в читаемом виде: логины, пароли Wi-Fi, токены. Это часто самый ценный результат — но только при наличии пароля.

## Шаг 7: сторонние приложения и следы джейлбрейка

Штатных приложений мало — интереснее сторонние. Каждое хранит свою базу в своём домене: WhatsApp — `ChatStorage.sqlite`, Telegram — `cache4.db`, Signal — `signal.sqlite`. Их ищут по `Manifest.db`:

```bash
$ sqlite3 Manifest.db "SELECT domain,relativePath FROM Files WHERE relativePath LIKE '%ChatStorage%';"
AppDomain-net.whatsapp.WhatsApp|Library/ChatStorage.sqlite
```

А если устройство **взломано** (jailbreak), это тоже оставляет следы: приложение `Cydia`, логи `dpkg`, запись `rw` в `fstab`, служба `afc2`. Проверяются простым поиском:

```bash
$ ls out/RootDomain/Applications/ | grep -i cydia
$ grep -ri 'jailbreak\|substrate\|cydia' out/*/Library/Logs/ 2>/dev/null
```

Чего получить не удастся никогда — это биометрия и ключи **Secure Enclave** (аппаратный чип безопасности): они физически не извлекаются. Поэтому в отчёте честно указывают границы: что доступно из бэкапа, а что закрыто шифрованием.

## Полный разбор: от бэкапа к Keychain

Соберём разбор iOS-бэкапа в один сценарий.

1. **Тип бэкапа.** iTunes/Finder (каталог с `Manifest.db`) или iCloud; шифрованный требует пароль.
2. **Карта файлов.** `Manifest.db` (SQLite) сопоставляет domain/path → хеш-имя файла:
   ```sql
   sqlite> SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%sms%';
   ```
3. **Извлекаем домены.** `HomeDomain` (SMS, звонки), `AppDomain` (данные приложений).
4. **Переписка.** `sms.db` — сообщения; `CallHistory.storedata` — звонки.
5. **Геолокация.** EXIF фото + кэши локаций.
6. **Keychain.** `keychain-backup.plist` — пароли/токены (шифрован ключом бэкапа).
7. **Джейлбрейк.** Нестандартные домены/пакеты — признак модификации.

## Шпаргалка доменов iOS

| Домен | Что содержит |
|-------|--------------|
| HomeDomain | SMS, звонки, настройки |
| AppDomain | базы сторонних приложений |
| CameraRollDomain | фото/видео |
| RootDomain | системные файлы |
| KeychainDomain | пароли, сертификаты |

## Частые вопросы

**Бэкап зашифрован — что делать?** Нужен пароль бэкапа; без него содержимое недоступно.

**Чем iCloud-бэкап отличается?** Часть данных только в облаке; нужен доступ к аккаунту.

**Keychain читается?** Только при известном пароле бэкапа; иначе — зашифрован.

**Как понять, что устройство взломано?** Следы Cydia/Sileo, нестандартные домены, изменённые системные файлы.

## Что мы теперь знаем

- iOS-бэкап хранит файлы под хеш-именами; карту «хеш → путь» даёт `Manifest.db`.
- `IsEncrypted` в `Info.plist` определяет, доступен ли Keychain.
- Домены (`HomeDomain`, `AppDomain-*`, `CameraRollDomain`) разделяют данные по назначению.
- Время в iOS — от 2001 года (`+978307200` = Unix); в `sms.db` ещё делится на `1e9`.
- Переписка — `sms.db`, звонки — `CallHistory.storedata`, GPS — EXIF фото.
- Keychain доступен только из зашифрованного бэкапа при наличии пароля.

## Квиз

Проверь себя.

```quiz
- question: "Какой файл iOS-бэкапа связывает domain/путь с хеш-именем файла?"
  options:
    - "Info.plist"
    - "Manifest.db"
    - "Status.plist"
    - "sms.db"
  answer: 1
  explanation: "Manifest.db — SQLite-карта: fileID (имя файла) ↔ domain + relativePath."
- question: "Какую эпоху времени использует iOS (Cocoa/Core Data)?"
  options:
    - "Unix 1970"
    - "2001-01-01 (Apple epoch)"
    - "1601"
    - "2000"
  answer: 1
  explanation: "К Unix-времени прибавляют 978307200, чтобы перевести из Apple-эпохи."
- question: "Где в iOS-бэкапе лежат SMS/iMessage?"
  options:
    - "Library/SMS/sms.db"
    - "Library/CallHistoryDB"
    - "Library/Safari/History.db"
    - "KeychainDomain"
  answer: 0
  explanation: "Домен AppDomain-com.apple.MobileSMS, файл Library/SMS/sms.db."
- question: "Что даёт зашифрованный бэкап по сравнению с незашифрованным?"
  options:
    - "ничего"
    - "доступ к Keychain (паролям), Health и другим защищённым данным"
    - "только медиа"
    - "только контакты"
  answer: 1
  explanation: "Незашифрованный бэкап Keychain не содержит; для него нужен пароль бэкапа."
- question: "Как понять, зашифрован ли бэкап?"
  options:
    - "по размеру папки"
    - "по полю IsEncrypted в Info.plist"
    - "по имени UDID"
    - "по Manifest.db"
  answer: 1
  explanation: "Info.plist содержит ключ IsEncrypted — 1 означает шифрование."
```

## Куда дальше

Мы разобрали iOS-бэкап от карты файлов до Keychain. Дальше в ветке форензики мы перейдём к контейнерам и облачным артефактам — посмотрим, какие следы оставляет работа в Kubernetes и в облаке. А пока главное запомни: **iOS-бэкап хранит файлы под хеш-именами, `Manifest.db` возвращает им пути, а пароли лежат в Keychain только зашифрованного бэкапа**.

## Где пригодится

- **CTF:** задачи с iOS-бэкапами и app-данными.
- **Мобильная форензика:** извлечение переписки, истории, настроек.
- **DFIR:** расследование мобильных инцидентов.
- **Судебная экспертиза:** доказательство сообщений и активности.
- **Анализ приложений:** понимание структуры хранения данных в iOS.
