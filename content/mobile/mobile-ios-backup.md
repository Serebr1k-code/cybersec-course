---
id: mobile-ios-backup
title: "iOS-бэкапы: извлечение и анализ данных без jailbreak"
category: mobile
parent: mobile-ios-advanced
difficulty: medium
order: 1
tags: [ios, backup, itunes, idevicebackup2, manifest, keychain, forensics, no-jailbreak]
prerequisites: [mobile-ios-basics]
useful_for:
  - "Пентест мобильных приложений (iOS)"
  - "Форензика iOS"
  - "Bug bounty iOS"
estimated_minutes: 50
summary: "Как устроен iTunes/Finder-бэкап iOS, как его извлечь (idevicebackup2, iMazing), расшифровать ManifestKeyBag и анализировать содержимое без jailbreak."
---

## Вопрос, с которого всё начинается

У тебя нет jailbreak, нет физического доступа к разблокированному устройству — но есть **резервная копия** iPhone, сделанная в Finder или iTunes. Что из данных приложения можно из неё вытащить и как?

Резервная копия — это не «слепок диска», а структурированный набор файлов с базой-индексом. Разберём её устройство.

## Наш пример: структура бэкапа

Возьмём реальную структуру бэкапа iOS. Каталог содержит файлы с «хешевыми» именами (по два hex-символа в подкаталогах) и два ключевых файла: `Manifest.plist` (метаданные) и `Manifest.db` (индекс всех файлов). Посмотрим индекс:

```
$ sqlite3 Manifest.db ".tables"
Files
$ sqlite3 -header -column Manifest.db "SELECT fileID, domain, relativePath FROM Files;"
fileID   domain                       relativePath
aaaa     AppDomain-com.demo.secapp    Library/Preferences/com.demo.secapp.plist
bbbb     AppDomain-com.demo.secapp    Documents/notes.db
cccc     CameraRollDomain             Media/DCIM/100APPLE/IMG_0001.JPG
dddd     HomeDomain                   Library/SMS/sms.db
```

Каждая строка — файл устройства: `fileID` (имя файла в бэкапе), `domain` (область: приложение, камера, домашний каталог), `relativePath` (путь внутри области). Это карта бэкапа.

## Шаг 1: домены — что где лежит

`domain` — это важнейшее поле. Оно говорит, к какой части системы относится файл:

| Домен | Что содержит |
|-------|--------------|
| `AppDomain-<bundle>` | данные конкретного приложения |
| `HomeDomain` | SMS, настройки, здоровье |
| `CameraRollDomain` | фото и видео |
| `MediaDomain` | медиатека |
| `RootDomain` | системные настройки |

Данные нашего приложения `DemoApp` лежат в `AppDomain-com.demo.secapp`. Именно туда стоит смотреть в первую очередь: там настройки, базы, кэш.

## Шаг 2: зашифрован ли бэкап

Это критичный вопрос. Бэкап бывает **незашифрованный** (пользователь не ставил пароль) и **зашифрованный**. Разница принципиальная: в незашифрованном бэкапе **нет** Keychain, а часть данных доступна напрямую. В шифрованном — есть всё, но нужен пароль.

Проверить шифрование можно по `Manifest.plist`:

```
$ python3 -c "import plistlib;d=plistlib.load(open('Manifest.plist','rb'));print('IsEncrypted:', d.get('IsEncrypted'))"
IsEncrypted: False
```

Если `IsEncrypted: True`, для разбора нужен инструмент вроде `iphone-dataprotection` и пароль бэкапа. Если `False` — работаем с файлами напрямую.

## Шаг 3: извлекаем данные приложения

Зная домен и `relativePath`, можно найти файл по его `fileID`. Имя файла в бэкапе — это `fileID`, разложенный по каталогам:

```
<backup>/aa/aaaa        # fileID = aaaa
```

То есть первые два символа `fileID` — имя подкаталога. Утилита `idevicebackup2` умеет распаковать бэкап целиком в читаемую структуру:

```
$ idevicebackup2 unback ./backup_dir/
$ ls backup_dir/AppDomain-com.demo.secapp/Library/Preferences/
com.demo.secapp.plist
```

Теперь перед нами обычные файлы: plist настроек, SQLite-базы, документы. Ищем секреты:

```
$ plutil -p com.demo.secapp.plist | grep -iE 'token|secret|password'
```

## Шаг 4: что даёт бэкап без Keychain

Даже без Keychain бэкап ценен: в `NSUserDefaults` (это как раз `Preferences/*.plist`) часто лежат токены, флаги, идентификаторы. Плюс базы данных приложения, кэш, cookies. Cookies — особенно интересны: они могут содержать сессионные токены веб-сессий. Проверяем:

```
$ find backup_dir -name '*.db' -o -name 'Cookies*' | head
```

`HomeDomain/Library/SMS/sms.db` — это SMS-база; `HomeDomain/Library/Preferences/*` — системные настройки. Для пентеста приложения главное — `AppDomain-<bundle>`.

## Шаг 5: зашифрованный бэкап

Если бэкап зашифрован, есть два пути. Первый — узнать пароль (часто это простой пароль пользователя; бэкапы можно перебирать офлайн, но это медленно). Второй — использовать утилиты, которые умеют расшифровывать бэкап при известном пароле:

```
$ iphone-dataprotection decrypt-backup -p PASSWORD -d ./backup_dir ./out
```

Внутри зашифрованного бэкапа лежит и Keychain (`KeychainDomain/keychain-2.db`) — тот самый, что мы разбирали в `mobile-ios-keychain`. Если пароль известен, оттуда достаются токены.

## Шаг 6: практический сценарий

Полный прогон выглядит так. Получаем бэкап, смотрим `Manifest.plist` — зашифрован ли. Если нет — распаковываем `idevicebackup2 unback`. Находим `AppDomain` нужного приложения. Ищем в plist и базах токены, ключи, cookies. Если бэкап зашифрован — ищем пароль или запрашиваем его у владельца в рамках теста.

## Шаг 7: ограничения

Бэкап даёт не всё. Во-первых, приложение может хранить секреты только в Keychain с сильным классом защиты — тогда без пароля бэкапа их нет. Во-вторых, начиная с iOS 11 бэкап разбит на части, и часть данных не сохраняется, если пользователь выключил бэкап для приложения. В-третьих, современные бэкапы почти всегда шифрованные. Поэтому бэкап — это один из источников, а не универсальный ключ.

## Шаг 8: инструменты и автоматизация

Разбирать бэкап вручную удобно, когда нужно проверить одну находку, но для полного анализа есть специализированные инструменты. `iBackup Viewer` показывает бэкап в виде дерева приложений и файлов. `iLEAPP` умеет работать прямо с каталогом бэкапа и строить HTML-отчёт по сотням артефактов. `iphone-dataprotection` расшифровывает зашифрованный бэкап при известном пароле и вытаскивает Keychain. Для автоматизации своего пайплайна можно парсить `Manifest.db` напрямую: индекс — это обычная SQLite, и по нему легко пройтись скриптом, выгружая нужные домены. Такой скрипт экономит часы при повторных прогонах.

Ещё один практический приём — сравнить два бэкапа одного приложения до и после действия (например, входа в аккаунт). Разница покажет, какие именно файлы создаёт или меняет приложение при этом действии, и приведёт прямо к хранилищу токена.

## Шаг 9: что не попадает в бэкап

Полезно понимать границы метода. В бэкап **не** попадают: данные, которые приложение пометило как исключённые (`NSURLIsExcludedFromBackupKey`), кэш, временные файлы, а также содержимое Keychain при незашифрованном бэкапе. Поэтому если токен нигде в файлах не нашёлся, а в Keychain есть — без шифрованного бэкапа или jailbreak его не достать. Это ограничение метода, и его честно указывают в отчёте. Отсюда практический вывод: бэкап хорошо подходит для быстрой проверки хранения данных, но для полной картины его дополняют файловой системой или шифрованным бэкапом.

## Шаг 10: разбираем Manifest.db запросом

`Manifest.db` — это SQLite-индекс всего бэкапа. Вместо ручного обхода папок удобнее сразу спрашивать, что принадлежит приложению:

```
$ sqlite3 Manifest.db ".tables"
Files
$ sqlite3 Manifest.db "SELECT DISTINCT domain FROM Files;"
AppDomain-com.demo.sec
HomeDomain
KeychainDomain
$ sqlite3 Manifest.db "SELECT fileID,relativePath FROM Files WHERE domain='AppDomain-com.demo.sec';"
a1|Library/Preferences/com.demo.sec.plist
a2|Documents/secret.txt
```

Колонка `domain` отделяет данные приложений (`AppDomain-<bundle>`) от системных (`HomeDomain`) и keychain (`KeychainDomain`). Имя файла на диске — не читаемый путь, а `fileID` (SHA-1 от domain+relativePath), поэтому реальный путь восстанавливают именно через `relativePath`. В **незашифрованном** бэкапе keychain-домен присутствует, но зашифрован отдельно; в зашифрованном — недоступен без пароля.

## Что мы теперь знаем

- Бэкап iOS — это `Manifest.plist` (метаданные) + `Manifest.db` (индекс) + файлы с хешевыми именами.
- `domain` указывает область: `AppDomain-<bundle>`, `HomeDomain`, `CameraRollDomain`.
- Незашифрованный бэкап не содержит Keychain; шифрованный — содержит, но нужен пароль.
- `idevicebackup2 unback` распаковывает бэкап в читаемую структуру.
- В `Preferences/*.plist` и базах приложения часто лежат токены.
- Зашифрованный бэкап расшифровывают при известном пароле.

## Квиз

Проверь себя.

```quiz
- question: Какой файл в бэкапе iOS является индексом всех файлов?
  options:
    - "Info.plist"
    - "Manifest.db"
    - "keychain-2.db"
    - "backup.tar"
  answer: 1
  explanation: "Manifest.db — SQLite-база с таблицей Files: fileID, domain, relativePath."
- question: Что означает домен AppDomain-com.demo.secapp?
  options:
    - "Системные настройки"
    - "Данные конкретного приложения com.demo.secapp"
    - "Фотографии"
    - "SMS"
  answer: 1
  explanation: "AppDomain-<bundle> — область данных конкретного приложения."
- question: Что принципиально отличает незашифрованный бэкап от шифрованного?
  options:
    - "Размер"
    - "В незашифрованном нет Keychain; шифрованный его содержит"
    - "Формат файлов"
    - "Ничего"
  answer: 1
  explanation: "Keychain сохраняется только в шифрованном бэкапе."
- question: Какая команда распаковывает бэкап в читаемую структуру?
  options:
    - "idevicebackup2 unback"
    - "jadx"
    - "class-dump"
    - "simctl openurl"
  answer: 0
  explanation: "unback разворачивает бэкап в каталоги по доменам и путям."
- question: Где в бэкапе чаще всего лежат токены приложения без Keychain?
  options:
    - "В Manifest.plist"
    - "В Library/Preferences/*.plist (NSUserDefaults) и базах приложения"
    - "В CameraRollDomain"
    - "В системных шрифтах"
  answer: 1
  explanation: "NSUserDefaults хранится как plist в Preferences, там часто остаются токены."
```

## Куда дальше

Бэкап — это логическое извлечение. Дальше разберём **форензику iOS** в целом: дампы файловой системы, checkm8, артефакты и инструменты анализа. Это следующий урок `mobile-forensics-ios`. А пока главное запомни: бэкап держится на `Manifest.db`, а шифрование определяет, доступен ли Keychain.

## Где пригодится

- **Пентест:** извлечение данных приложения без jailbreak.
- **Bug bounty:** доказательство небезопасного хранения через бэкап.
- **Форензика:** восстановление данных пользователя из копии.
- **CTF:** поиск флага в бэкапе iOS.
