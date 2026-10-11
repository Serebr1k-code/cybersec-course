---
id: mobile-backup
title: "Backup-извлечение и злоупотребление ADB"
category: mobile
parent: mobile-storage-deep
difficulty: medium
order: 1
tags: [backup, adb, adb-backup, allowBackup, data-extraction, android]
prerequisites: [mobile-insecure-storage]
useful_for:
  - "CTF Mobile (извлечение данных/флага из backup)"
  - "Bug bounty (утечка данных через backup)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как извлекать данные приложения через adb backup и авто-бэкап, почему allowBackup=true опасен и как искать секреты в бэкапе."
---
## Введение

Android предоставляет штатный механизм резервного копирования приложения — и это отличный путь к его приватным данным. Если в манифесте стоит `android:allowBackup="true"` (значение по умолчанию до Android 12!), пользователь или злоумышленник с включённой отладкой может снять `adb backup` и получить SharedPreferences, SQLite, файлы, кэш. На Android 12+ ручной `adb backup` сильно ограничен, авто-бэкап идёт в облако Google по правилам `dataExtractionRules`; но старые и неправильно настроенные приложения остаются уязвимы.

## allowBackup и что он даёт

```xml
<application android:allowBackup="true" ... />
```

- `true` (и отсутствие атрибута) → данные попадают в backup.
- `false` → backup запрещён (правильно для приложений с секретами).
- `android:fullBackupContent` / `android:dataExtractionRules` → что именно бэкапить.
- `android:backupAgent` → кастомный агент (может расширять/ограничивать набор).

Ищите в декомпилированном манифесте:

```bash
apktool d app.apk -o out
grep -i "allowBackup\|fullBackupContent\|dataExtractionRules\|backupAgent" out/AndroidManifest.xml
```

## adb backup: пошагово

```bash
# включить отладку, подключить устройство
adb devices
# снять бэкап (-apk включает APK, -noshared без общих данных)
adb backup -f app.ab -apk -noshared com.target.app
# если приложение требует пароль на бэкап — появится диалог (можно пустой)
```

`app.ab` — контейнер (magic `ANDROID BACKUP`, может быть сжатый/зашифрованный). Разбираем через `abe` (Android Backup Extractor):

```bash
java -jar abe.jar unpack app.ab app.tar
tar -tf app.tar | head
tar -xf app.tar -C extracted/
ls extracted/apps/com.target.app/
```

Дальше ищем в `sp/` (SharedPreferences), `db/` (SQLite), `f/` (файлы), `r/` (кэш):

```bash
grep -rniE "password|token|secret|api[_-]?key|flag" extracted/ | head
sqlite3 extracted/apps/com.target.app/db/*.db ".tables"
```

## Авто-бэкап и облако

С Android 6 авто-бэкап (Auto Backup) включён по умолчанию для `allowBackup=true`, данные шифруются ключом устройства и лежат в Google Drive пользователя. Достать их без устройства сложно, но можно:

- через `bmgr` (backup manager) на устройстве/эмуляторе с adb root;
- через физический доступ и пароль устройства.

```bash
adb shell bmgr list transports
adb shell bmgr backupnow com.target.app
adb shell bmgr restore <token> com.target.app
```

`bmgr` особенно полезен в CTF на root-эмуляторе.

## iOS: бэкап через iTunes/Finder

Локальный бэкап iOS (`~/Library/Application Support/MobileSync/Backup/<UDID>/`) содержит данные приложений в каталогах с хэш-именами. Инструменты: `idevicebackup2` (libimobiledevice), `iMazing`, `iphone-dataprotection` (для расшифровки Keychain при известном пароле).

```bash
idevicebackup2 backup --full ~/iosbackup
sqlite3 ~/iosbackup/Manifest.db "select fileID,relativePath,domain from Files"
```

Файлы достаются по `fileID` (SHA1-имя); для расшифровки самого бэкапа нужен пароль.

## Разобранный пример

CTF: приложение с флагом в SharedPreferences и `allowBackup=true`. Решение:

1. `apktool d` → манифест показывает `allowBackup=true`.
2. `adb backup -f app.ab -apk com.target.app`.
3. `abe unpack app.ab app.tar` → `tar -xf`.
4. `grep -r flag extracted/` → флаг в `sp/settings.xml`.

## Частые ошибки и подводные камни

- Пытаться `adb backup` на Android 12+ без учёта ограничений — команда может вернуть пустой бэкап.
- Забыть пароль на бэкап: пустой пароль — тоже пароль, `abe` его примет.
- Искать только в `db/`, пропуская `sp/`, `f/`, `r/` (секреты часто в SharedPreferences).
- Не проверять `dataExtractionRules` — даже при `allowBackup=true` чувствительные пути можно исключить.
- Забывать про `adb restore` для проверки, что данные восстанавливаются в другое устройство.

## Справочная таблица

| Артефакт | Путь в бэкапе | Что искать |
|----------|---------------|------------|
| SharedPreferences | `sp/` | токены, настройки, флаги |
| SQLite | `db/` | PII, сессии |
| Файлы | `f/` | конфиги, ключи |
| Кэш | `r/` | временные секреты |
| iOS данные | `Manifest.db` | mapping fileID↔path |
| Keychain (iOS) | backup + пароль | пароли, ключи |

## Что дальше / решение

- **allowBackup=true и данные достаются** → оформите утечку (PII, токены).
- **Бэкап зашифрован паролем** → попробуйте пустой пароль/словарь через `abe`.
- **Backup закрыт** → переходите к root-доступу (`/data/data/<pkg>/`) или `run-as` для debuggable-сборок.
- **iOS** → снимайте локальный бэкап и разбирайте `Manifest.db`.
- Severity: секреты/PII в доступном бэкапе — High; отсутствие `allowBackup=false` при чувствительных данных — Medium/High.

## Извлечение данных без root: run-as и content

Если снять полный `adb backup` не удаётся (Android 12+, `allowBackup=false`), но сборка `debuggable`, данные достаются напрямую через `run-as`:

```bash
adb shell run-as com.target.app ls -la /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml
adb shell run-as com.target.app tar -c /data/data/com.target.app/ > dump.tar
```

Дополнительно проверяйте экспортированные content-провайдеры — они дают доступ к тем же данным без root:

```bash
adb shell content query --uri content://com.target.app.provider/users
adb shell content read --uri content://com.target.app.provider/files/../databases/app.db
```

## Облачный авто-бэкап: разбор и ограничения

Auto Backup кладёт данные в Google Drive пользователя, зашифрованные ключом устройства. Разбор возможен в трёх случаях: (1) есть root на устройстве и доступ к `/data/backup`; (2) есть пароль аккаунта и эмуляция восстановления через `bmgr`; (3) приложение хранит секреты, которые восстанавливаются на втором устройстве при том же аккаунте. Последнее — реальный вектор: если `dataExtractionRules` не исключает чувствительные файлы, данные «переезжают» на любой другой девайс под тем же Google-аккаунтом.

```bash
adb shell bmgr list transports
adb shell dumpsys backup | head -40
```

## Скрипт автоматизации извлечения

```bash
#!/usr/bin/env bash
PKG="$1"; OUT="dump_$PKG"; mkdir -p "$OUT"
adb backup -f "$OUT/app.ab" -apk -noshared "$PKG" </dev/null
java -jar abe.jar unpack "$OUT/app.ab" "$OUT/app.tar"
mkdir -p "$OUT/x" && tar -xf "$OUT/app.tar" -C "$OUT/x"
echo "== secrets =="
grep -rniE 'password|token|secret|api[_-]?key|flag|jwt' "$OUT/x" | head -50
echo "== sqlite =="
find "$OUT/x" -name '*.db' -exec sqlite3 {} '.tables' \;
```

Такой конвейер за один запуск отдаёт список секретов и таблиц — удобно для CTF и быстрого аудита.

## Правовые рамки

Резервное копирование чужих данных без разрешения — нарушение приватности и закона. В пентесте работайте только с тестовыми аккаунтами и устройствами в рамках scope; в bug bounty доказывайте утечку на собственных данных, не выгружая PII реальных пользователей.

## Восстановление бэкапа на другое устройство

Извлечение — это лишь половина дела. Вторая половина — показать, что данные переносимы, то есть восстановимы на другом устройстве под тем же аккаунтом. Это доказывает реальную утечку (не просто «файл лежит»), а переносимость секретов.

```bash
# восстановить бэкап на чистое устройство/эмулятор
adb restore app.ab
# либо через bmgr для облачного бэкапа
adb shell bmgr restore <dataset> com.target.app
```

Если токен сессии восстанавливается и работает на новом устройстве — это серьёзная находка: сессия переносима, и компрометация бэкапа равна компрометации аккаунта.

## Анализ iOS-бэкапа: Keychain и защищённые файлы

В локальном бэкапе iOS ключевые артефакты:

- `Manifest.db` — соответствие `fileID` (SHA1) реальным путям и доменам.
- `Keychain-backup.plist` — зашифрованные элементы Keychain; для расшифровки нужен пароль бэкапа.
- SQLite баз данных приложений (`Library/`, `Documents/`).
- `.plist` настроек.

```bash
# найти конкретный файл приложения
sqlite3 ~/iosbackup/Manifest.db \
  "select fileID,relativePath from Files where domain='AppDomain-com.example.app'"
# извлечь содержимое по fileID
cp ~/iosbackup/<first2chars>/<fileID> ./extracted
```

Если бэкап не зашифрован, Keychain-элементы с классом `kSecAttrAccessibleAlways` доступны напрямую — частая находка. Рекомендация — включать шифрование бэкапа и использовать защищённые классы доступности.

## Сравнение методов извлечения

| Метод | Условие | Что даёт | Сложность |
|-------|---------|----------|-----------|
| `adb backup` | allowBackup=true, <Android 12 | sp/db/f/r | низкая |
| `run-as` | debuggable | вся песочница | низкая |
| content-провайдер | exported | данные провайдера | низкая |
| root / `/data/data` | root | всё | средняя |
| iOS-бэкап | доступ к устройству | данные+Keychain | средняя |
| облачный авто-бэкап | аккаунт+устройство | набор по rules | высокая |

## Оценка и рекомендации

Приоритизируйте находки по чувствительности: приватные ключи и seed — Critical; токены сессий и PII — High; настройки без секретов — Low. В рекомендациях: `allowBackup=false` для приложений с секретами, явные `dataExtractionRules`, отказ от хранения секретов в SharedPreferences/plain-SQLite, использование Keystore/Keychain и шифрование локальных данных.

## Квиз

```quiz
- question: "Какой атрибут манифеста разрешает извлечение данных через adb backup?"
  options:
    - "android:allowBackup='true'"
    - "android:debuggable='true'"
    - "android:exported='true'"
    - "android:usesCleartextTraffic='true'"
  answer: 0
  explanation: "allowBackup=true позволяет снять бэкап приватных данных приложения."
- question: "Каким инструментом распаковать файл .ab (adb backup)?"
  options:
    - "abe (Android Backup Extractor)"
    - "jadx"
    - "apktool"
    - "frida"
  answer: 0
  explanation: "abe.jar превращает .ab в tar, который затем распаковывается."
- question: "Где в бэкапе чаще всего лежат токены и настройки?"
  options:
    - "В sp/ (SharedPreferences)"
    - "В AndroidManifest.xml"
    - "В classes.dex"
    - "В resources.arsc"
  answer: 0
  explanation: "SharedPreferences (sp/) хранит настройки и часто секреты."
- question: "Что изменилось в adb backup на Android 12+?"
  options:
    - "Ручной adb backup сильно ограничен"
    - "Он удалён полностью"
    - "Он требует root"
    - "Он шифруется автоматически без пароля"
  answer: 0
  explanation: "С Android 12 штатный adb backup ограничен; авто-бэкап идёт в облако."
- question: "Какой файл iOS-бэкапа сопоставляет хэш-имена реальным путям?"
  options:
    - "Manifest.db"
    - "Info.plist"
    - "payload.bin"
    - "backup.ab"
  answer: 0
  explanation: "Manifest.db хранит соответствие fileID ↔ relativePath."
```

## Где пригодится

- **CTF Mobile:** самый быстрый способ достать флаг из SharedPreferences/SQLite.
- **Bug bounty:** утечка PII через доступный backup — валидная находка.
- **Пентест:** проверка настроек резервного копирования перед релизом.
- **Forensics:** разбор локальных и облачных бэкапов при расследовании.
