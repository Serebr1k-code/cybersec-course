---
id: mobile-android-aab
title: 'App Bundle (AAB): bundletool и извлечение APK'
category: mobile
parent: mobile-android-build-formats
difficulty: medium
order: 2
tags: [aab, bundle, bundletool, play, asset-delivery]
prerequisites: [mobile-android-split-apk]
useful_for:
  - 'Реверс Android-приложений'
  - 'Пентест мобильных приложений'
  - 'CTF Mobile'
estimated_minutes: 40
summary: 'Что такое Android App Bundle (AAB), зачем Google Play его использует, как из .aab получить устанавливаемые APK через bundletool и как анализировать asset delivery.'
lab:
  kind: shell
  title: 'Практика: разбор AAB'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, aab.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`aab.txt` — структура App Bundle.'
    - 'Определи, какой модуль содержит основной код.'
    - 'В комментарии — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Вам достался файл `app.aab`, а не APK. `unzip -l app.aab` показывает какие-то `base/`, `BundleConfig.pb`, но не готовый APK. Установить его напрямую нельзя. Как из него получить APK для анализа и запуска?

## Наш пример: app.aab

```bash
$ file app.aab
app.aab: Zip archive data
$ unzip -l app.aab | head
  base/manifest/AndroidManifest.xml
  base/dex/classes.dex
  BundleConfig.pb
```

Внутри — модули (`base/`), а не готовый APK. Это AAB.

<!-- lab -->

## Шаг 1: что такое AAB

AAB (Android App Bundle) — формат публикации в Google Play. В нём приложение описано модулями:
base и фичи. Play сам генерирует под конкретное устройство нужный набор APK (тот самый split).
AAB — это «источник», а APK — «результат сборки под устройство».

## Шаг 2: bundletool

Официальный инструмент для работы с AAB — `bundletool`. Он умеет превращать AAB в APK-набор:

```bash
$ java -jar bundletool.jar build-apks --bundle=app.aab --output=app.apks        --mode=universal
```

`--mode=universal` просит собрать один универсальный APK (со всеми архитектурами и ресурсами) —
удобно для анализа. Результат `app.apks` — это тоже zip, внутри набор APK.

## Шаг 3: извлечение APK

```bash
$ unzip -l app.apks | grep apk
  universal.apk
$ unzip -o app.apks universal.apk
$ jadx -d out universal.apk
```

Теперь у нас обычный APK, который открывает JADX.

## Шаг 4: анализ модулей

Если нужен именно сплит под устройство, собирают без `universal` и подключают устройство:

```bash
$ java -jar bundletool.jar install-apks --apks=app.apks
```

Для анализа удобнее universal — он содержит всё. Но помните, что в реальности приложение
работает по сплитам, поэтому поведение может зависеть от конфигурации.

## Шаг 5: Play Asset Delivery

AAB поддерживает Play Asset Delivery — доставку ресурсов по требованию (install-time,
fast-follow, on-demand). Это значит, что часть ассетов может подгружаться позже и отсутствовать
в базовом APK. При реверсе стоит проверить, не тянет ли приложение ресурсы динамически.

## Шаг 6: защита

Так как AAB — источник, а не то, что ставится, проверки подписи и целостности применяются к
сгенерированным APK. Для анализа это не помеха: universal APK подписывается bundletool ключом,
который вы задаёте.

## Шаг 7: практика

Типовой порядок: получить AAB → build-apks universal → извлечь universal.apk → анализировать
JADX/MobSF. Если нужен сплит-набор — собрать без universal.

## Что мы теперь знаем

- AAB — формат публикации, а не устанавливаемый файл.
- Play генерирует APK-набор из AAB.
- bundletool build-apks делает APK из AAB.
- --mode=universal даёт один APK со всем.
- Play Asset Delivery доставляет ресурсы динамически.

## Квиз

Проверь себя.

```quiz
- question: Что такое AAB?
  options:
    - Формат APK
    - Формат публикации приложения в Play
    - Протокол
    - Библиотека
  answer: 1
  explanation: Из AAB Play генерирует APK.
- question: Как получить APK из AAB?
  options:
    - adb install
    - bundletool build-apks
    - zipalign
    - apktool d
  answer: 1
  explanation: bundletool собирает APK-набор.
- question: Что даёт --mode=universal?
  options:
    - Один APK со всеми архитектурами и ресурсами
    - Подпись
    - Root
    - Сжатие
  answer: 0
  explanation: Universal удобен для анализа.
- question: Что делает Play Asset Delivery?
  options:
    - Ставит root
    - Доставляет ресурсы по требованию
    - Шифрует сеть
    - Меняет язык
  answer: 1
  explanation: Часть ассетов подгружается позже.
```

## Куда дальше

Мы разобрали форматы поставки. Внутри DEX бывает больше одного файла — из-за лимита методов.
Дальше — multidex.

## Где пригодится

- Реверс приложений, опубликованных в Play.
- Понимание современной сборки Android.
- CTF по мобильному реверсу.
