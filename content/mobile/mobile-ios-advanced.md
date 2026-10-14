---
id: mobile-ios-advanced
title: "Модуль: Продвинутый анализ iOS"
category: mobile
parent: mobile-platforms-ios
difficulty: medium
order: 4
tags: [ios, mach-o, dyld, cycript, lldb, backup, data-protection, ssl]
prerequisites: [mobile-ios-basics]
useful_for:
  - "Пентест мобильных приложений (iOS)"
  - "Bug bounty iOS"
  - "Форензика iOS"
estimated_minutes: 25
summary: "Навигационный модуль: углублённый анализ iOS — Mach-O/dyld, Cycript/LLDB, backup-извлечение, Data Protection и SSL Kill Switch."
---
## Зачем отдельная ветвь по iOS

Базовый урок `mobile-ios-basics` даёт фундамент: IPA, class-dump, Hopper, Keychain. Но реальный пентест iOS-приложения требует гораздо большего: понять загрузчик Mach-O и динамический линкер dyld, научиться работать с runtime через Cycript и LLDB, извлекать данные из бэкапов, разбирать классы защиты файлов (Data Protection) и обходить pinning на уровне iOS (SSL Kill Switch). Эта ветвь закрывает именно эти пробелы.

Особенность iOS-пентеста в том, что без jailbreak многие техники недоступны: нельзя встроить Frida в системный процесс, нельзя читать чужую песочницу, нельзя дампить Keychain. Поэтому первая развилка — **jailbreak или нет**. При jailbreak мы работаем почти как с Android-root; без него — только перепаковка/инструментирование самого приложения (frida-gadget, sideload).

## Карта ветви

| Урок | Что закрывает |
|------|---------------|
| `mobile-ios-backup` | извлечение данных из iTunes/Finder-бэкапа (без jailbreak) |
| `mobile-ios-ssl-killswitch` | обход certificate pinning на iOS (SSL Kill Switch, Frida) |
| `mobile-ios-cycript` | runtime-интроспекция через Cycript + отладка LLDB |
| `mobile-ios-data-protection` | классы Data Protection, доступность файлов, атаки |

Смежные уроки вне ветви: `mobile-ios-static` (Mach-O, Swift), `mobile-ios-dynamic` (Frida/LLDB), `mobile-ios-keychain` (секреты), `mobile-ios-jailbreak` (детект/обход).

## Mach-O и dyld — фундамент

Любой iOS-бинарник — это Mach-O. Понимание его структуры (segments `__TEXT`, `__DATA`, `__LINKEDIT`; load commands `LC_SEGMENT`, `LC_LOAD_DYLIB`, `LC_ENCRYPTION_INFO`) нужно, чтобы находить зашифрованные секции (App Store-шифрование), анализировать imports и хукать символы. Динамический линкер **dyld** загружает фреймворки и вызывает `+load`/конструкторы; перехват dyld (`DYLD_INSERT_LIBRARIES`) — классический вектор для внедрения своей библиотеки (jailbreak/подписанные приложения).

```bash
# структура Mach-O
otool -l AppBinary | grep -A4 LC_ENCRYPTION_INFO
otool -hv AppBinary            # заголовок, флаги
otool -L AppBinary             # linked libraries
nm -u AppBinary | head         # неопределённые символы
```

`LC_ENCRYPTION_INFO.cryptid=1` означает, что бинарник зашифрован (App Store). Чтобы его реверсить, нужно снять расшифровку на jailbreak-устройстве (`frida-ios-dump`).

## Jailbreak vs no-jailbreak

| Аспект | Jailbreak | Без jailbreak |
|--------|-----------|---------------|
| Чтение песочницы | да (root) | нет |
| Дамп Keychain | да | нет |
| Frida-сервер | системный | frida-gadget в APK/IPA |
| MITM с системным CA | да | частично (per-app) |
| Дамп расшифрованного бинарника | да | нет |
| Обход pinning | проще | только в своём процессе |

Без jailbreak всё равно можно многое: перепаковать IPA с frida-gadget и подписать (sideload), перехватывать трафик per-app, анализировать бэкапы.

## Data Protection — почему это важно

iOS шифрует файлы на диске ключами, привязанными к классу защиты (`NSFileProtectionComplete`, `...UntilFirstUserAuthentication`, `...CompleteUnlessOpen`, `None`). Слабый класс (`None`/`UntilFirstUserAuthentication`) означает, что данные доступны даже при заблокированном экране — критичная находка. Разбираем в `mobile-ios-data-protection`.

## Что дальше / решение

Порядок: `mobile-ios-backup` → `mobile-ios-cycript` → `mobile-ios-ssl-killswitch` → `mobile-ios-data-protection`. Если устройство с jailbreak — начинайте с `mobile-ios-dynamic` и `mobile-ios-jailbreak`. Решение по умолчанию: отдельное тестовое iOS-устройство (checkra1n/palera1n-совместимое) + Frida + frida-ios-dump.

## Справочная таблица инструментов

| Инструмент | Назначение |
|-----------|-----------|
| `otool`/`jtool2` | разбор Mach-O |
| `class-dump`/`dsdump` | заголовки ObjC |
| `Cycript` | runtime-интроспекция |
| `lldb`/`debugserver` | отладка |
| `frida-ios-dump` | дамп расшифрованного бинарника |
| `idevicebackup2` | работа с бэкапами |
| `SSL Kill Switch 2` | обход pinning |

## Квиз

```quiz
- question: "Что означает `cryptid=1` в LC_ENCRYPTION_INFO?"
  options:
    - "Бинарник сжат"
    - "Бинарник зашифрован (App Store) и требует расшифровки для реверса"
    - "Это Swift"
    - "Это Mach-O без символов"
  answer: 1
- question: "Что из перечисленного возможно без jailbreak?"
  options:
    - "Дамп Keychain"
    - "Перехват трафика per-app и анализ бэкапа"
    - "Чтение чужой песочницы"
    - "Снятие расшифровки App Store"
  answer: 1
- question: "Зачем нужен frida-ios-dump?"
  options:
    - "Снять расшифрованный бинарник с jailbreak-устройства"
    - "Сканировать порты"
    - "Сделать бэкап"
    - "Подписать IPA"
  answer: 0
- question: "Что такое Data Protection в iOS?"
  options:
    - "Шифрование файлов ключами по классу доступности"
    - "Антивирус"
    - "Сетевой экран"
    - "Менеджер паролей"
  answer: 0
- question: "Какая библиотека реализует динамический линкер iOS?"
  options:
    - "libc"
    - "dyld"
    - "ld.so"
    - "ld-linux"
  answer: 1
```

## Где пригодится

- **Пентест iOS:** систематизация углублённого анализа.
- **Bug bounty:** бэкапы, pinning, Data Protection как источники находок.
- **Форензика:** извлечение и анализ данных iOS.
- **CTF:** Mobile/iOS-задачи.
