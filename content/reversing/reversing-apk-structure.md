---
id: reversing-apk-structure
title: "Анатомия APK/AAB/IPA: манифест, ресурсы, split-APK, подписи"
category: reversing
parent: reversing-mod-android2
difficulty: medium
order: 4
tags: [reversing, android, apk, aab, ipa, manifest, resources, signature]
prerequisites: [reversing-android-apk]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ мобильной малвари"
  - "Проверка целостности приложений"
estimated_minutes: 50
summary: "Как устроен APK (и AAB/IPA): ZIP-контейнер, AndroidManifest, resources.arsc, DEX, split-APK, схемы подписи v1–v4 и как их проверить."
lab:
  kind: shell
  title: "Практика: инвентаризация APK"
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, app.apk]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "APK — это ZIP-архив; `unzip -l app.apk` покажет его содержимое."
    - "Ищи `AndroidManifest.xml`, `classes.dex`, `resources.arsc`, `META-INF/`."
    - "Флаг лежит в одном из файлов APK; посмотри список, затем содержимое."
    - "`unzip -l app.apk > out.txt`, затем найди файл с флагом и извлеки его."
---

## Вопрос, с которого всё начинается

У тебя есть файл `app.apk`. Прежде чем декомпилировать код, хочется понять, что внутри: какие компоненты, есть ли нативные библиотеки, как подписано. С чего начать и на что смотреть?

## Наш пример

Возьмём `app.apk`. Посмотрим его содержимое:

```
$ unzip -l app.apk
  Length      Name
     1024    AndroidManifest.xml
   842140    classes.dex
    12300    resources.arsc
   102400    lib/arm64-v8a/libnative.so
     2048    META-INF/CERT.RSA
     4096    META-INF/MANIFEST.MF
```

Уже по списку видно: манифест, байткод, ресурсы, нативная библиотека, подписи. Разберём, что каждое значит.

## Шаг 1: APK — это ZIP-контейнер

APK — обычный ZIP-архив (часто без сжатия для некоторых файлов, чтобы быстрее читать). Внутри:

- `AndroidManifest.xml` — в бинарной форме (AXML), не текст.
- `classes.dex` (и `classesN.dex`) — байткод.
- `resources.arsc` — скомпилированные ресурсы (строки, размеры, ссылки).
- `res/` — ресурсы (картинки, layout).
- `lib/<abi>/` — нативные библиотеки по архитектурам.
- `META-INF/` — подписи (v1).

Первое действие при реверсе — инвентаризация: что есть, какие ABIs, сколько DEX-файлов.

## Шаг 2: AndroidManifest — карта приложения

Манифест в APK бинарный, но `aapt dump xmltree app.apk AndroidManifest.xml` или apktool показывают его текстом. Что смотреть: `package`, `versionCode`, список `<activity>`/`<service>`/`<receiver>`/`<provider>`, разрешения `<uses-permission>`, `android:debuggable`, `android:allowBackup`, `networkSecurityConfig`.

Для пентеста манифест — первый источник находок: экспортированные компоненты (`android:exported="true"`), слабые разрешения, отладочные флаги. Для реверса — точка входа (`LAUNCHER` activity) и имена классов, где искать логику.

## Шаг 3: resources.arsc и строки

`resources.arsc` — таблица ресурсов: строки, размеры, цвета, ссылки. Она нужна, потому что ресурсы скомпилированы в бинарный формат и адресуются по ID. Строки интерфейса (включая сообщения об ошибках и иногда ключи) лежат здесь, а не в DEX.

Для реверса это важно: если не находишь строку в DEX, проверь `resources.arsc`. Инструмент `aapt dump resources app.apk` выведет таблицу, а `apktool` разберёт её в XML.

## Шаг 4: split-APK и AAB

Современные приложения поставляются как **split-APK**: базовый APK плюс отдельные модули по ABI (`config.arm64_v8a.apk`), по плотности экрана (`config.xxhdpi.apk`), по языку. В Play Store используется **AAB** (Android App Bundle) — формат публикации, из которого Google генерирует split-APK для каждого устройства.

Для реверса это означает: одной `base.apk` может не хватить — код или ресурсы лежат в конфигурационных APK. Их нужно собрать вместе (`adb install-multiple` или apktool по каждому) и анализировать комплект. В AAB DEX-файлы лежат в `base/dex/`.

## Шаг 5: подписи v1–v4

APK подписывается в нескольких схемах. **v1 (JAR signing)**: подпись в `META-INF/` — `MANIFEST.MF`, `CERT.SF`, `CERT.RSA`. **v2**: подпись всего архива, блок в ZIP-структуре (виден как `APK Sig Block 42`). **v3**: как v2, но с ротацией ключей. **v4**: подпись для инкрементальной установки, лежит отдельно в `.apk.idsig`.

Проверка: `apksigner verify --print-certs app.apk`. Если приложение проверяет свою подпись внутри кода, оно сравнивает SHA-256 сертификата с эталоном — именно это ломается при repackaging (мы видели в уроке про smali).

## Шаг 6: находим артефакт практики

Внутри APK есть файл с артефактом. Инвентаризируем и извлекаем:

```
$ unzip -l app.apk | grep -iE 'secret|note|flag|readme'
$ unzip -p app.apk assets/notes.txt | grep nto
nto{apk_4n4t0my_spl1t_s1gn3d}
```

## Что мы теперь знаем

- APK — ZIP-контейнер: манифест (AXML), DEX, resources.arsc, lib/, META-INF/.
- Манифест — карта приложения: компоненты, разрешения, экспорт, debuggable.
- resources.arsc хранит строки; если не нашёл в DEX — ищи здесь.
- Split-APK и AAB делят приложение на модули по ABI/плотности/языку.
- Подписи: v1 (JAR), v2/v3 (ZIP-блок), v4 (idsig); проверка — apksigner.

## Квиз

Проверь себя.

```quiz
- question: "Чем является APK-файл по своей структуре?"
  options:
    - "ZIP-архивом с манифестом, DEX, ресурсами и подписями"
    - "Исполняемым файлом ELF"
    - "Базой данных SQLite"
    - "Текстовым файлом конфигурации"
  answer: 0
- question: "Где в APK хранятся строки интерфейса, если их нет в DEX?"
  options:
    - "В resources.arsc"
    - "В META-INF/"
    - "В lib/"
    - "В AndroidManifest.xml"
  answer: 0
- question: "Зачем нужны split-APK?"
  options:
    - "Чтобы доставлять только нужные модули (ABI, плотность, язык) конкретному устройству"
    - "Чтобы ускорить шифрование"
    - "Чтобы скрыть код от анализа"
    - "Чтобы уменьшить число разрешений"
  answer: 0
- question: "Какой инструмент проверяет подписи APK?"
  options:
    - "apksigner verify"
    - "objdump"
    - "strings"
    - "sqlite3"
  answer: 0
```

## Куда дальше

На этом модуль про форматы Android завершён. Пока главное запомни: **прежде чем декомпилировать — сделай инвентаризацию APK; подпись, манифест и resources.arsc часто дают ответы быстрее, чем код**.

## Где пригодится

- **Пентест мобильных приложений:** быстрый обзор поверхности атаки.
- **Анализ малвари:** определить ABIs, компоненты и встроенные данные.
- **Проверка целостности:** верификация подписи и версии схемы.
