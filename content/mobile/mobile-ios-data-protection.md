---
id: mobile-ios-data-protection
title: "iOS Data Protection: классы защиты файлов и атаки"
category: mobile
parent: mobile-ios-advanced
difficulty: hard
order: 4
tags: [ios, data-protection, nsfileprotection, encryption, keybag, forensics, files]
prerequisites: [mobile-ios-basics]
useful_for:
  - "Пентест мобильных приложений (iOS)"
  - "Форензика iOS"
  - "Bug bounty iOS"
estimated_minutes: 50
summary: "Классы Data Protection (NSFileProtectionComplete и др.), как они защищают файлы, как проверить их на устройстве и какие слабые классы создают утечки."
lab:
  kind: shell
  title: "Практика: секрет в дампе Keychain"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, keychain.plist]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Это plist. Посмотри его: `cat keychain.plist`."
    - "Секрет в поле `<data>` и закодирован base64. Вырежи значение: `grep data keychain.plist | cut -d'>' -f2 | cut -d'<' -f1`."
    - "Раскодируй и запиши: добавь `| base64 -d > found.txt`."
---

## Вопрос, с которого всё начинается

Приложение хранит на диске файл с токеном. Устройство украдено, но оно **заблокировано** паролем. Может ли злоумышленник прочитать этот файл? Ответ зависит от одного параметра — **класса защиты данных** файла. Как iOS защищает файлы и где эта защита ломается?

## Наш пример: файлы DemoApp и их защита

Вернёмся к `DemoApp` на jailbreak-устройстве. Данные приложения лежат в его песочнице:

```
$ ls -la /var/mobile/Containers/Data/Application/<uuid>/Documents/
-rw-r--r--  notes.db
-rw-r--r--  session.json
```

Файлы выглядят обычными, но у каждого есть невидимый атрибут — **класс защиты** (Data Protection class). Посмотрим его:

```
$ xattr -l session.json
com.apple.protection: NSFileProtectionComplete
```

`xattr` показывает расширенные атрибуты файла. `com.apple.protection` — и есть класс защиты. Он определяет, **когда** система расшифрует файл.

## Шаг 1: классы защиты

iOS шифрует данные на диске ключом, привязанным к паролю устройства. Класс защиты говорит, в какой момент ключ становится доступен:

| Класс | Когда доступен файл |
|-------|---------------------|
| `NSFileProtectionComplete` | только при разблокированном устройстве |
| `NSFileProtectionCompleteUnlessOpen` | можно дописать после блокировки |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | после первой разблокировки (доступен в фоне) |
| `NSFileProtectionNone` | всегда (шифрование только «на бумаге») |

Чем «слабее» класс, тем шире окно доступа. `None` означает, что файл фактически не защищён паролем. `UntilFirstUserAuthentication` — частый выбор для фоновой синхронизации, но он позволяет читать файл, даже когда экран заблокирован.

## Шаг 2: защита по умолчанию

Важно: iOS применяет `NSFileProtectionCompleteUntilFirstUserAuthentication` к файлам приложения **по умолчанию**. То есть «ничего не делать» — уже не худший вариант, но и не лучший. Приложение может усилить защиту, явно задав класс при создании файла:

```objc
[[NSFileManager defaultManager]
    createFileAtPath:path
    contents:data
    attributes:@{NSFileProtectionKey: NSFileProtectionComplete}];
```

Ключ `NSFileProtectionKey` задаёт класс. Если разработчик не указал его, действует значение по умолчанию.

## Шаг 3: что это даёт при разных сценариях

Разберём три ситуации.

**Устройство разблокировано, есть jailbreak.** Мы читаем все файлы напрямую — класс защиты не мешает, потому что ключи уже доступны.

**Устройство заблокировано, есть полный образ.** Здесь класс защиты решает всё. Файлы с `Complete` недоступны (их ключ выведен из памяти при блокировке), а с `UntilFirstUserAuthentication` и `None` — читаются.

**Есть только бэкап.** В незашифрованном бэкапе Keychain нет, но файлы приложения есть; класс защиты при бэкапе не сохраняется как ограничение, поэтому токен в `session.json` может утечь.

## Шаг 4: где ломается защита

Data Protection сильна, но у неё есть слабые места:

- **Файлы с `NSFileProtectionNone`** — читаются всегда, это прямая находка.
- **Данные в `NSUserDefaults`** — plist в `Library/Preferences`; класс защиты часто слабый.
- **Кэш и логи** — разработчики редко задумываются об их защите.
- **Скриншоты и снапшоты** — iOS делает снимок экрана при сворачивании, и он может остаться в кэше.
- **Данные в памяти** — если приложение не очищает буферы, секрет живёт в памяти после использования.

Проверять стоит всё: `ls` по песочнице, `xattr` на подозрительных файлах, поиск по `NSUserDefaults`.

## Шаг 5: как проверить класс защиты

Практический порядок: найти файл с секретом, посмотреть его `xattr`, оценить класс. Затем проверить сценарий блокировки: если файл с `Complete` — он защищён; если с `None` — нет. Дополнительно ищем секреты в `Preferences`, `Caches`, `tmp`. Наконец, проверяем, не остаётся ли секрет в памяти после использования (например, в неизменяемом объекте, который долго живёт).

## Шаг 6: связь с Keychain

Data Protection и Keychain — родственные механизмы: оба используют аппаратное шифрование и класс защиты (`kSecAttrAccessible` в Keychain, `NSFileProtection` в файлах). Правильная архитектура такая: короткоживущие секреты — в Keychain с `WhenUnlocked`, а крупные данные — в файлах с `Complete`. Ошибка — хранить токен в файле с `None` и одновременно считать, что он защищён.

## Шаг 7: что писать в отчёте

Находка формулируется как «файл X с классом защиты Y содержит секрет Z и доступен при условии W». Указывай конкретный файл, его класс и сценарий, при котором он читается. Это делает находку воспроизводимой и понятной. Если класс защиты слабый, но секрет можно перевыпустить — понижай критичность; если это долгоживущий токен — повышай.

## Шаг 8: сравнение с Android

Полезно сопоставить с Android, чтобы понять общий принцип. На Android шифрование диска (FBE, file-based encryption) также привязано к разблокировке: файлы делятся на «credential encrypted» и «device encrypted» — примерно аналог `Complete` и `UntilFirstUserAuthentication`. Разница в деталях: Android управляет доступом через ключи в Keystore и SELinux, а iOS — через классы Data Protection и Secure Enclave. Общий вывод один: чем слабее привязка к разблокировке, тем шире окно атаки. Если ты понимаешь один механизм, второй читается легко.

## Шаг 9: практический чек-лист

Проверяя приложение, пройди по списку:

| Что проверяем | Как |
|---------------|-----|
| Класс защиты файлов | `xattr -l` по песочнице |
| Секреты в Preferences | `grep` по `Library/Preferences` |
| Кэш и логи | `ls` по `Library/Caches`, `tmp` |
| Данные в бэкапе | разобрать бэкап (см. `mobile-ios-backup`) |
| Класс Keychain-записей | `kSecAttrAccessible` |

Так ты за пару минут поймёшь, защищены ли данные приложения на диске, и найдёшь слабые места для отчёта. Особое внимание — файлам, созданным приложением вручную: именно там чаще всего забывают указать класс защиты. Библиотеки и системные каталоги обычно защищены по умолчанию, а вот собственные `Documents` и `Library` — зона ответственности разработчика.

## Шаг 10: как читать класс защиты из дампа

Класс защиты записи виден в базе keychain, где он записан колонкой `pdmn` (protection domain). Посмотрим на реальный дамп:

```
$ sqlite3 keychain-2.db "SELECT acct,svce,pdmn FROM genp;"
user@demo.example|DemoAppToken|ak
refresh|DemoAppRefresh|ck
$ sqlite3 keychain-2.db "SELECT pdmn,count(*) FROM genp GROUP BY pdmn;"
ak|1
ck|1
```

`ak` — `kSecAttrAccessibleAfterFirstUnlock`: запись доступна после первой разблокировки, то есть фоновому процессу и — при физическом доступе — может быть прочитана без пароля. `ck` — `kSecAttrAccessibleWhenUnlocked`: только пока устройство разблокировано. Для токенов и паролей правильный выбор — `ck` или строже (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), иначе секрет переживёт блокировку и уйдёт в бэкап.

## Что мы теперь знаем

- Каждый файл iOS имеет класс защиты (`NSFileProtection`).
- Классы определяют, когда файл доступен: `Complete`, `UntilFirstUserAuthentication`, `None`.
- По умолчанию приложение получает `UntilFirstUserAuthentication`.
- `xattr -l` показывает класс защиты файла.
- Слабые места: `None`, `NSUserDefaults`, кэш, логи, снапшоты, память.
- Data Protection и Keychain используют общий принцип аппаратного шифрования.

## Квиз

Проверь себя.

```quiz
- question: Что определяет класс защиты файла на iOS?
  options:
    - "Размер файла"
    - "Момент, когда система расшифровывает и делает файл доступным"
    - "Формат файла"
    - "Имя владельца"
  answer: 1
  explanation: "NSFileProtection задаёт условие доступа: при блокировке, после первой разблокировки и т.д."
- question: Какой класс защиты делает файл доступным только при разблокированном устройстве?
  options:
    - "NSFileProtectionNone"
    - "NSFileProtectionComplete"
    - "NSFileProtectionCompleteUntilFirstUserAuthentication"
    - "NSFileProtectionUnlessOpen"
  answer: 1
  explanation: "Complete выводит ключ из памяти при блокировке, поэтому файл недоступен."
- question: Какой класс защиты применяется по умолчанию к файлам приложения?
  options:
    - "NSFileProtectionComplete"
    - "NSFileProtectionCompleteUntilFirstUserAuthentication"
    - "NSFileProtectionNone"
    - "Нет защиты"
  answer: 1
  explanation: "По умолчанию iOS использует UntilFirstUserAuthentication."
- question: Какая команда показывает класс защиты файла?
  options:
    - "xattr -l"
    - "chmod"
    - "ls -l"
    - "cat"
  answer: 0
  explanation: "xattr -l выводит расширенные атрибуты, включая com.apple.protection."
- question: Какое место часто остаётся без защиты и утекает через бэкап?
  options:
    - "NSUserDefaults (Preferences/*.plist)"
    - "Keychain с WhenUnlocked"
    - "Файлы с Complete"
    - "Secure Enclave"
  answer: 0
  explanation: "NSUserDefaults — обычный plist, класс защиты часто слабый, и он попадает в бэкап."
```

## Куда дальше

Мы разобрали, как iOS защищает данные на диске. Это завершает базовую ветвь iOS-анализа. Дальше можно переходить к автоматизации тестирования и работе с API — в следующих уроках `mobile-automation` и `mobile-api-testing`. А пока главное запомни: класс защиты файла определяет, когда секрет доступен, и `None` — это фактическое отсутствие защиты.

## Где пригодится

- **Пентест:** оценка защиты данных на устройстве.
- **Bug bounty:** доказательство небезопасного хранения.
- **Форензика:** понимание, что читается с заблокированного образа.
- **Аудит:** проверка классов защиты и Keychain.
