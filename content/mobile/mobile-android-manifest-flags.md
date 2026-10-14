---
id: mobile-android-manifest-flags
title: 'Модуль: флаги манифеста, влияющие на безопасность'
category: mobile
parent: mobile-android-ipc-runtime
difficulty: medium
order: 5
tags: [android, manifest, debuggable, allowbackup, flags, hardening, module]
prerequisites: [mobile-android-anatomy]
useful_for:
  - 'Навигация по ветке'
  - 'Пентест мобильных приложений'
estimated_minutes: 14
summary: 'Навигационный модуль: два флага манифеста, которые напрямую открывают данные приложения — android:debuggable и android:allowBackup.'
---

Есть атрибуты манифеста, которые выглядят безобидно, но напрямую влияют на доступ к данным. Два
самых важных — `android:debuggable` и `android:allowBackup`. Ошибка в них превращает приложение в
открытый архив.

## Что покрывает модуль

1. **android:debuggable** — разрешает отладку и `run-as`, то есть чтение данных приложения.
2. **android:allowBackup** — разрешает резервное копирование, в том числе через `adb backup`.

## Почему это важно

Оба флага — про доступ к приватным данным без эксплуатации уязвимостей. Если `debuggable="true"`
в релизе, любой может подключиться и вытащить файлы через `run-as`. Если `allowBackup="true"`, на
части версий Android данные выгружаются через `adb backup`. Это находки, которые легко проверить и
легко доказать.

## Чему вы научитесь

- Проверять `debuggable` и `allowBackup` в манифесте.
- Использовать `run-as` и `adb backup` для чтения данных.
- Понимать изменения в Android 12+.
- Давать конкретные рекомендации по исправлению.

## Связь с другими ветками

Хранение данных — `mobile-insecure-storage`; резервные копии — `mobile-backup`; аудит конфигурации
— `mobile-static-hardening`.

## Квиз

Проверь себя.

```quiz
- question: Что разрешает android:debuggable="true"?
  options:
    - Шифрование
    - Отладку и run-as
    - root
    - Смену IMEI
  answer: 1
  explanation: Флаг разрешает отладку и доступ к данным через run-as.
- question: Что разрешает android:allowBackup="true"?
  options:
    - Сеть
    - Резервное копирование, в том числе adb backup
    - Камеру
    - GPS
  answer: 1
  explanation: Флаг разрешает выгрузку данных приложения.
- question: Как проверить флаг в APK?
  options:
    - aapt dump xmltree AndroidManifest.xml
    - ifconfig
    - netstat
    - lsmod
  answer: 0
  explanation: aapt показывает атрибуты манифеста.
```

## Где пригодится

- Аудит конфигурации Android-приложения
- Bug bounty Android
