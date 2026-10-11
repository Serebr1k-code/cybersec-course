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
---
## Введение

Data Protection — механизм iOS, при котором каждый файл шифруется на диске ключом, привязанным к классу доступности (`NSFileProtection`). Класс определяет, **когда** файл расшифровывается: только при разблокированном устройстве, после первой разблокировки, всегда и т.д. Слабый класс (или `None`) означает, что данные доступны даже при заблокированном экране и попадают в бэкап — это классическая находка пентеста. Этот урок — про то, как классы работают, как их проверять и как это эксплуатируется (в т.ч. в форензике через keybag).

Data Protection отличается от Keychain: Keychain — отдельное хранилище секретов, Data Protection — защита файлов в песочнице. Часто путают.

## Классы защиты

| Класс | Когда доступен | В бэкап | Комментарий |
|-------|----------------|---------|-------------|
| `NSFileProtectionComplete` | только разблокировано | да | самый строгий (файл зашифрован и ключ выброшен при lock) |
| `NSFileProtectionCompleteUnlessOpen` | разблокировано; открытый файл остаётся | да | для активных загрузок |
| `NSFileProtectionCompleteUntilFirstUserAuthentication` | после первой разблокировки | да | дефолт многих файлов; доступен при lock |
| `NSFileProtectionNone` | всегда | да | **небезопасно** |

`Complete` выгружает ключ из памяти при блокировке — файл недоступен. `UntilFirstUserAuthentication` оставляет ключ после первой разблокировки до перезагрузки — данные читаемы при заблокированном экране. `None` — открытый текст (в смысле ключа, доступного всегда).

## Как приложение задаёт класс

```objectivec
// для одного файла
[[NSFileManager defaultManager]
   setAttributes:@{NSFileProtectionKey: NSFileProtectionComplete}
   ofItemAtPath:path error:&err];

// глобально для создаваемых файлов (в Info.plist: NSFileProtectionComplete)
```

В `Info.plist` можно задать дефолт для всех файлов приложения. Отсутствие значения — файлы наследуют класс по умолчанию (`UntilFirstUserAuthentication`).

## Проверка на устройстве (jailbreak)

```bash
# класс защиты конкретного файла
cycript -p TargetApp
cycript> [NSFileManager defaultManager] attributesOfItemAtPath:@"/var/mobile/Containers/Data/Application/<uuid>/Library/secret.db" error:nil]
# -> {"NSFileProtectionKey":"NSFileProtectionNone", ...}
```

Или из shell на jailbreak-устройстве:

```bash
find /var/mobile/Containers/Data/Application/<uuid>/ -exec \
  ls -lO {} \; | grep -v complete
```

Атрибут `-O` (`ls -lO`) показывает protection-флаг. Файлы без `complete` — кандидаты на находку.

## Полный сквозной пример: утечка БД с токенами

Дано: приложение хранит сессию в SQLite без защиты.

```bash
# 1. Находим контейнер приложения
cycript -p TargetApp
cycript> [[NSBundle mainBundle] bundleIdentifier]           # com.target.app
cycript> NSHomeDirectory()                                   # путь контейнера
# 2. Проверяем класс защиты БД
cycript> [NSFileManager defaultManager] attributesOfItemAtPath:@"/var/.../Library/Application Support/session.db" error:nil]
# -> NSFileProtectionKey = NSFileProtectionNone   <-- НАХОДКА
# 3. Читаем содержимое
sqlite3 "/var/.../Library/Application Support/session.db" ".tables"
sqlite3 "/var/.../Library/Application Support/session.db" "SELECT * FROM tokens;"
```

Результат: токены сессий читаются без разблокировки и попадут в незашифрованный бэкап. Это находка «Insecure Data Storage» уровня High.

## Форензика: keybag и извлечение при заблокированном экране

На уровне ОС ключи файлов хранятся в **keybag** (`/private/var/keybags/systembag.kb`). При извлечении дампа с заблокированного устройства восстановление возможно только для классов, чьи ключи доступны (`UntilFirstUserAuthentication` после первой разблокировки, `None`). Классы `Complete` без пароля не восстанавливаются. Инструменты форензики (Elcomsoft, Cellebrite, `iphone-dataprotection`) работают именно с keybag и классами:

```bash
# концептуально: перечислить классы и ключи в keybag
# iphone-dataprotection: keybagdump
python3 keybagdump.py systembag.kb | grep -i protection
```

Понимание классов критично для форензики: именно оно определяет, что реально можно извлечь.

## Связь с бэкапом и Keychain

Незашифрованный бэкап: файлы песочницы извлекаются, Keychain — нет. Зашифрованный: и то, и другое. Класс Data Protection определяет, попадут ли данные в бэкап (все классы, кроме `ThisDeviceOnly`-вариантов Keychain, в бэкап попадают). См. `mobile-ios-backup`.

## Частые ошибки

- **Проверка на симуляторе**: там Data Protection не enforced — находки невалидны.
- **Путаница с Keychain**: файл в `Documents/` не защищён Keychain; это разные механизмы.
- **`-O` не показывает флаг**: используйте `ls -lO` на jailbreak или `attributesOfItemAtPath`.
- **Считаете `UntilFirstUserAuthentication` безопасным**: при блокировке экрана данные всё ещё читаемы.
- **Игнор кэшей**: `Library/Caches`, `Library/Cookies` часто без защиты — тоже находки.
- **Неверный путь контейнера**: UUID меняется при переустановке — получайте через `NSHomeDirectory()`.

## Что дальше / решение

Находка: файлы с классом `None`/`UntilFirstUserAuthentication`, содержащие секреты. Проверьте также Keychain-классы (`mobile-ios-keychain`) и бэкап (`mobile-ios-backup`). Для полного дампа — jailbreak + checkm8 (`mobile-forensics-ios`). Рекомендация в отчёте: использовать `NSFileProtectionComplete` для чувствительных файлов и Keychain для секретов.

## Справочная таблица

| Класс | Доступ при lock | В бэкап |
|-------|-----------------|---------|
| Complete | нет | да |
| CompleteUnlessOpen | только открытый | да |
| UntilFirstUserAuthentication | да | да |
| None | да | да |

| Проверка | Команда |
|----------|---------|
| Класс файла | `attributesOfItemAtPath` |
| Все файлы | `ls -lO` (jailbreak) |
| Keybag | `keybagdump.py` |
| Секреты | `mobile-ios-keychain` |

## Проверка классов на реальном устройстве (скрипт)

Ручная проверка каждого файла утомительна. Скрипт рекурсивно проходит контейнер и печатает файлы с небезопасным классом:

```bash
#!/usr/bin/env bash
# на jailbreak-устройстве
CONTAINER="/var/mobile/Containers/Data/Application/<uuid>"
find "$CONTAINER" -type f -print0 | while IFS= read -r -d '' f; do
  cls=$(ls -lO "$f" 2>/dev/null | awk '{print $5}')
  case "$cls" in
    *complete*|*Complete*) : ;;          # защищено
    *) echo "UNPROTECTED: $f ($cls)" ;;
  esac
done | head -50
```

Через Cycript для конкретного файла:

```javascript
[NSFileManager defaultManager] attributesOfItemAtPath:@"/path/to/file" error:nil]
// смотрим NSFileProtectionKey
```

## Атаки: keybag и восстановление

При блокировке экрана класс `Complete` выбрасывает ключ файла из памяти. Класс `UntilFirstUserAuthentication` оставляет ключ после первой разблокировки — файл читаем. Форензик-инструменты работают с keybag:

```bash
# концептуально: перечислить ключи классов
python3 keybagdump.py systembag.kb | grep -iE 'protection|class'
```

Практический вывод: если чувствительный файл имеет класс `UntilFirstUserAuthentication`/`None`, его можно извлечь из дампа без разблокировки. Это меняет оценку серьёзности находки с «средне» на «высоко».

## Взаимодействие с бэкапом и Keychain

Data Protection определяет, попадут ли файлы в бэкап. Все классы (кроме Keychain-`ThisDeviceOnly`) в бэкап попадают — поэтому незашифрованный бэкап раскрывает файлы, но не Keychain. Зашифрованный раскрывает и Keychain. Проверяйте связку:

```bash
# файл приложения в бэкапе
sqlite3 Manifest.db "SELECT relativePath FROM Files WHERE domain='AppDomain-com.target.app' AND relativePath LIKE '%session%';"
# Keychain (при шифрованном бэкапе)
sqlite3 KeychainDomain/keychain-2.db "SELECT svce,acct FROM genp;"
```

## Кейс: утечка через кэш

Дано: приложение кэширует ответы API в `Library/Caches` с классом `None`.

```bash
# 1. Проверяем класс
ls -lO "/var/.../Library/Caches/api_cache.db"
# -> NSFileProtectionNone
# 2. Читаем содержимое при заблокированном экране (или из дампа)
sqlite3 api_cache.db "SELECT url,response FROM cache LIMIT 5;"
# 3. Находим токены/персональные данные в кэше
grep -a "eyJ" api_cache.db | head
```

Находка: кэш содержит токены/ПДн, доступные без разблокировки. Рекомендация — класс `Complete` для чувствительных кэшей.

## Рекомендации в отчёте

- Использовать `NSFileProtectionComplete` для секретов и кэшей с ПДн.
- Секреты — в Keychain (с `ThisDeviceOnly`), а не в файлах.
- Не хранить токены в `NSUserDefaults` (они не защищены классом файла так же строго).
- Исключать чувствительные данные из бэкапа (`NSURLIsExcludedFromBackupKey`).
- Проверять, что доступ при заблокированном экране невозможен для критичных данных.

## Автоматизированный аудит классов защиты

Ручная проверка классов Data Protection для десятков файлов утомительна. Напишем скрипт, который рекурсивно обходит контейнер и группирует файлы по классу. На jailbreak-устройстве используйте `ls -lO`; для удалённого анализа — заранее собранные атрибуты. Пример:

```bash
find "$CONTAINER" -type f | while read -r f; do
  cls=$(ls -lO "$f" 2>/dev/null | awk '{print $5}')
  echo "$cls|$f"
done | sort | awk -F'|' '{c[$1]++} END{for(k in c) print k, c[k]}'
```

Так вы сразу видите, сколько файлов в каждом классе и какие не защищены. Файлы с классом `None`/`UntilFirstUserAuthentication`, содержащие чувствительные данные, — приоритет для находок.

## Интеграция с мобильным тестовым фреймворком

В рамках MASVS-аудита проверку классов можно включить в общий скрипт: собрать контейнер, прогнать проверку классов, отметить файлы с секретами (grep по `token`, `eyJ`, `password`), связать с находками. Это автоматизирует рутину и делает аудит воспроизводимым.

## Что писать в отчёте

Для каждой находки укажите: путь файла, класс защиты, тип данных (токен/ПДн), доступность при блокировке, рекомендацию. Группируйте однотипные находки. Ясно разделяйте «защищено» и «уязвимо» — не преувеличивайте.

## Итоговый чек-лист аудита Data Protection

1. Получите контейнер приложения (jailbreak/дамп).
2. Определите класс защиты каждого чувствительного файла (`ls -lO` / `attributesOfItemAtPath`).
3. Отметьте файлы с `None`/`UntilFirstUserAuthentication`, содержащие секреты/ПДн.
4. Проверьте `Library/Caches`, `Library/Cookies`, `NSUserDefaults` — частые места утечек.
5. Сопоставьте с Keychain (`mobile-ios-keychain`) и бэкапом (`mobile-ios-backup`).
6. Оцените извлекаемость при заблокированном экране (keybag) — влияет на severity.

Рекомендация по умолчанию: `NSFileProtectionComplete` для критичных файлов, секреты — в Keychain с `ThisDeviceOnly`, исключение чувствительных данных из бэкапа.

## Квиз

```quiz
- question: "Какой класс Data Protection самый строгий?"
  options:
    - "NSFileProtectionNone"
    - "NSFileProtectionComplete"
    - "NSFileProtectionUntilFirstUserAuthentication"
    - "NSFileProtectionCompleteUnlessOpen"
  answer: 1
- question: "Что означает класс UntilFirstUserAuthentication?"
  options:
    - "Файл доступен после первой разблокировки, даже при заблокированном экране"
    - "Файл недоступен всегда"
    - "Файл только для чтения"
    - "Файл не попадает в бэкап"
  answer: 0
- question: "Почему проверка Data Protection на симуляторе невалидна?"
  options:
    - "На симуляторе механизм не enforced"
    - "Симулятор быстрее"
    - "На симуляторе нет файлов"
    - "Симулятор использует Android"
  answer: 0
- question: "Какой атрибут ls показывает protection-флаг?"
  options:
    - "-l"
    - "-a"
    - "-O"
    - "-Z"
  answer: 2
- question: "Что определяет, какие данные извлекаемы из дампа заблокированного устройства?"
  options:
    - "Классы Data Protection и keybag"
    - "Размер бэкапа"
    - "Версия Burp"
    - "Bundle id"
  answer: 0
```

## Где пригодится

- **Пентест iOS:** находки небезопасного хранения файлов.
- **Форензика:** понимание извлекаемости данных и keybag.
- **Bug bounty:** утечки секретов через файлы песочницы.
- **CTF:** Mobile/iOS-задачи с защитой файлов.
