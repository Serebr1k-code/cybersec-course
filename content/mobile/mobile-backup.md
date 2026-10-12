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

## Вопрос, с которого всё начинается

В уроке про небезопасное хранение мы выяснили, что данные приложения лежат в `/data/data/<package>/`, куда обычному пользователю доступа нет. Но есть механизм, который отдаёт эти данные **штатно, без root** — резервное копирование. Как им воспользоваться и почему это опасно?

## Наш пример: fdroid.apk и его флаг allowBackup

Возьмём реальный APK `fdroid.apk`. Декодируем манифест и посмотрим на атрибуты `application`:

```
$ apktool d -f -o fdroid_dec fdroid.apk
$ grep -oE 'android:(allowBackup|debuggable|usesCleartextTraffic)="[^"]*"' fdroid_dec/AndroidManifest.xml
android:allowBackup="true"
android:usesCleartextTraffic="true"
```

Строка `android:allowBackup="true"` — ключевая. Она разрешает системе делать резервную копию данных приложения. Именно на ней строится весь этот урок.

## Шаг 1: что даёт allowBackup

`allowBackup` управляет двумя каналами:

- **Локальный `adb backup`** — по команде с компьютера (нужна разблокировка и подтверждение на экране устройства).
- **Облачный авто-бэкап** — Android периодически сам отправляет данные в Google Drive.

Если флаг `false` — приложение исключено из бэкапа. Если `true` (или атрибут не указан — по умолчанию тоже `true`) — данные попадают в копию.

## Шаг 2: adb backup пошагово

Команда выглядит так:

```
$ adb backup -f backup.ab -apk org.fdroid.fdroid
WARNING: adb backup is deprecated and may be removed in a future release
Now unlock your device and confirm the backup operation.
```

Что здесь происходит: `-f backup.ab` — имя файла, `-apk` — включить в копию и сам APK, последний аргумент — имя пакета. На устройстве появится диалог подтверждения; без него копия не создастся.

Полученный `backup.ab` — это не tar, а свой контейнер. Распаковывается утилитой `abe.jar` (Android Backup Extractor):

```
$ java -jar abe.jar unpack backup.ab backup.tar
$ tar xf backup.tar
$ ls
apps/  shared/  ...
```

Внутри — файлы приложения: `shared_prefs`, базы, `files`. Дальше читаем их как обычно:

```
$ cat apps/org.fdroid.fdroid/sp/shared_prefs/*.xml
$ sqlite3 apps/org.fdroid.fdroid/db/*.db ".tables"
```

## Шаг 3: извлечение без root через run-as

Если приложение `debuggable` (или устройство рутовано), работает `run-as` — он запускает команду от имени приложения:

```
$ adb shell "run-as org.fdroid.fdroid tar -cf - ." > app_data.tar
$ tar tf app_data.tar | head
./shared_prefs/org.fdroid.fdroid_preferences.xml
./databases/
./files/
```

Одной командой вытаскиваем всю приватную директорию. Без `debuggable` и без root `run-as` вернёт `package not debuggable`.

## Шаг 4: доступ к Content Provider

Ещё один штатный канал — `content` через `adb`. Если провайдер экспортирован, данные можно запросить без кода:

```
$ adb shell content query --uri content://org.fdroid.fdroid/...
```

`content` — CLI-обёртка над `ContentResolver`. Она работает, только если у оболочки есть доступ к URI (экспортированный провайдер или выданный grant). Подробно — в уроке про Content Providers.

## Шаг 5: облачный авто-бэкап

Даже без `adb backup` данные могут уйти в облако. Управляется это `android:fullBackupContent` и настройками Google. Проверить, что именно бэкапится, можно через конфиг:

```xml
<full-backup-content>
  <include domain="sharedpref" path="."/>
  <exclude domain="sharedpref" path="secret.xml"/>
</full-backup-content>
```

Если разработчик забыл исключить файл с токеном — он уезжает в облако. Форензика облачных копий — отдельный урок.

## Шаг 6: iOS — iTunes/Finder-бэкап

На iOS аналог — локальная копия через `idevicebackup2` (libimobiledevice) или Finder. Копия — набор файлов с хэшированными именами и база `Manifest.db`. Разбор:

```
$ idevicebackup2 backup --full ./ios_backup
$ sqlite3 ios_backup/Manifest.db "SELECT fileID,domain,relativePath FROM Files LIMIT 5;"
```

Если бэкап не зашифрован, многие файлы читаются напрямую; зашифрованный бэкап защищён паролем, который можно подобрать офлайн.

## Полный прогон от начала до конца

Соберём извлечение данных в один сценарий для нашего `fdroid.apk`:

1. **`apktool d`** — декодируем манифест, убеждаемся, что `allowBackup="true"`.
2. **`adb backup -f backup.ab -apk org.fdroid.fdroid`** — подтверждаем операцию на экране устройства.
3. **`java -jar abe.jar unpack backup.ab backup.tar`** — распаковываем контейнер.
4. **`tar xf backup.tar`** — получаем дерево `apps/org.fdroid.fdroid/`.
5. **`sqlite3 .../*.db ".tables"`** — смотрим базы приложения.
6. **`grep -rInE 'token|secret' .`** — ищем секреты.
7. **Если `allowBackup=false`** — пробуем `run-as` (для `debuggable`) или `content query`.

Так мы получаем данные приложения, не имея root, — только за счёт конфигурации, которую разработчик оставил открытой.

## Если не сработало

- **`adb backup` возвращает пустой файл.** Пользователь не подтвердил операцию, либо приложение исключено из бэкапа (`allowBackup="false"` или `fullBackupContent`).
- **`run-as` пишет `package not debuggable`.** Нужна `debuggable`-сборка или root. Проверьте флаг `android:debuggable` в манифесте.
- **`content query` возвращает `Permission Denial`.** Провайдер не экспортирован или нет grant. Тогда нужен другой канал (root, `run-as`).
- **Данные зашифрованы.** В копии окажутся зашифрованные базы; ключ ищут в коде или перехватывают через Frida.
- **На iOS бэкап зашифрован.** Пароль подбирают офлайн (`hashcat`) или берут у владельца.

## Сравнение методов извлечения

| Метод | Нужен root | Нужен debuggable | Что даёт |
|-------|-----------|------------------|----------|
| `adb backup` | нет | нет | данные при `allowBackup=true` |
| `run-as` | нет | да | вся приватная директория |
| root-дамп | да | нет | полный образ `/data` |
| `content query` | нет | нет | данные экспортированного провайдера |
| iOS `idevicebackup2` | нет (jailbreak) | — | файлы бэкапа iOS |

Выбор метода диктуется условиями: если `allowBackup` включён — самый дешёвый путь; если сборка `debuggable` — `run-as`; если ничего — нужен root.

## Что фиксировать в отчёте

- **Какой флаг был в манифесте** (`allowBackup`, `debuggable`) — это корневая причина.
- **Каким методом извлечены данные** и что именно попало в руки.
- **Какие секреты найдены** (с доказательством — строкой из файла).
- **Рекомендации:** `allowBackup="false"`, `dataExtractionRules`, исключение секретов из бэкапа.

## Частые вопросы

**«`adb backup` не создаёт файл?»** — не подтвердили операцию на экране или `allowBackup=false`. **«`backup.ab` пустой?»** — приложение исключено из бэкапа. **«Хочу всё сразу?»** — `run-as pkg tar -cf - .` на debuggable-сборке. **«Нужен ли root?»** — для `adb backup`, `run-as` и `content` не нужен. **«А если приложение в облаке?»** — смотрите `fullBackupContent` и отдельный урок по облачной форензике.

## Что мы теперь знаем

По-простому:

1. `allowBackup="true"` открывает данные приложения для резервного копирования.
2. `adb backup` + `abe.jar` отдают содержимое `/data/data/<pkg>/` без root.
3. `run-as` работает для `debuggable`-сборок и рутованных устройств.
4. `content query` обращается к экспортированным провайдерам.
5. iOS-бэкап (iTunes/Finder) разбирается через `Manifest.db`.

## На что смотреть дальше

- **Первый вопрос — `allowBackup`.** Он в манифесте, смотреть его надо раньше всего.
- **Не забывайте про авто-бэкап.** Данные уходят в облако даже без `adb backup`.
- **`run-as` дешевле бэкапа**, но требует `debuggable`.
- **На iOS** бэкап — основной канал без jailbreak.

## Ограничения метода

`adb backup` не универсален: на новых версиях Android он помечен deprecated, а некоторые производители ограничивают его работу. Приложение может исключить себя из бэкапа через `allowBackup="false"` или `fullBackupContent`. Поэтому в отчёте важно указать, какой именно метод сработал и почему: это показывает, что вы не просто «предположили» утечку, а извлекли данные конкретным способом на конкретном устройстве.

## Квиз

Проверь себя.

```quiz
- question: "Что разрешает `android:allowBackup='true'`?"
  options:
    - "Резервное копирование данных приложения (adb backup и облако)"
    - "Установку на любые устройства"
    - "Использование интернета"
    - "Хранение данных в открытом виде"
  answer: 0
- question: "Чем распаковать файл backup.ab?"
  options:
    - "abe.jar (Android Backup Extractor)"
    - "jadx"
    - "apktool"
    - "zipalign"
  answer: 0
- question: "Что нужно, чтобы `run-as` сработал?"
  options:
    - "Сборка debuggable или root"
    - "Только Wi-Fi"
    - "Сторонняя клавиатура"
    - "Сертификат Let's Encrypt"
  answer: 0
- question: "Какой файл в iOS-бэкапе описывает, где лежат данные?"
  options:
    - "Manifest.db"
    - "Info.plist"
    - "classes.dex"
    - "resources.arsc"
  answer: 0
- question: "Что делать, если в fullBackupContent файл с токеном не исключён?"
  options:
    - "Токен уезжает в облачный авто-бэкап — это утечка"
    - "Ничего, файл не попадёт в копию"
    - "Приложение перестанет работать"
    - "Токен зашифруется автоматически"
  answer: 0
```

## Куда дальше

Мы научились извлекать данные приложения штатными механизмами. В следующем уроке — **Android-форензика**: как из добытых данных собрать цельную картину (артефакты, таймлайн, инструменты вроде ALEAPP). А пока запомни главное: `allowBackup`, `run-as` и `content query` — три дешёвых способа добраться до данных без root.

## Где пригодится

- **CTF Mobile:** извлечение флага из бэкапа или приватной директории.
- **Bug bounty:** демонстрация утечки данных через `allowBackup`.
- **Пентест:** проверка OWASP MASVS-STORAGE и конфигурации бэкапа.
- **Форензика:** получение данных для последующего анализа.
