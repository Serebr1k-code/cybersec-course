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

## Структура AAB изнутри

App Bundle — это zip с предсказуемой структурой. Вместо готового `AndroidManifest.xml` и
`classes.dex` в корне здесь лежат **модули** — подпапки, каждая со своим содержимым.

```bash
$ unzip -l app.aab
  BundleConfig.pb
  base/manifest/AndroidManifest.xml
  base/dex/classes.dex
  base/res/...
  base/assets/...
  feature_login/manifest/AndroidManifest.xml
  feature_login/dex/classes.dex
  asset_pack_assets/assets/...
  BUNDLE-METADATA/...
```

Разберём элементы. `BundleConfig.pb` — конфигурация сборки в формате protobuf (какие сплиты
создавать, как оптимизировать). `base/` — обязательный модуль с основным кодом и манифестом.
`feature_*/` — дополнительные модули (dynamic feature), код которых может доставляться по
требованию. `asset_pack_*/` — наборы ресурсов для Play Asset Delivery. `BUNDLE-METADATA/` —
служебные метаданные (например, про-гард-маппинги, если разработчик их включил).

Отличие от APK принципиальное: APK — это то, что ставится на устройство, а AAB — это то, из чего
Play **собирает** APK под конкретную конфигурацию.

## bundletool: сборка, установка, извлечение

`bundletool` — официальный инструмент Google для работы с AAB. Базовые команды:

```bash
# собрать APK-набор из AAB
$ java -jar bundletool.jar build-apks \
    --bundle=app.aab --output=app.apks \
    --ks=my.keystore --ks-pass=pass:secret --mode=universal

# установить набор на подключённое устройство
$ java -jar bundletool.jar install-apks --apks=app.apks
```

`build-apks` превращает AAB в файл `app.apks` — это тоже zip, внутри которого лежат
сгенерированные APK. `install-apks` подбирает нужные сплиты под подключённое устройство и
устанавливает их. Для анализа важнее первый шаг: получить APK на диск.

## Режимы сборки: universal, default, system

У `build-apks` есть несколько режимов, и выбор зависит от задачи.

- `--mode=universal` — один APK, содержащий все архитектуры, ресурсы и языки. Удобен для
  статического анализа, потому что в одном файле есть всё.
- `--mode=default` — набор сплитов, как их сгенерировал бы Play (по конфигурации устройства).
- `--mode=system` — APK для системного раздела (без сжатия части ресурсов).

Для реверса почти всегда берут `universal`. Но помните: в реальности приложение ставится
сплитами, и некоторые ветки кода могут выполняться только при наличии конкретного сплита. Если
поведение зависит от конфигурации — соберите `default` под нужный device-spec.

## device-spec и device-tier

Чтобы собрать сплиты «как для конкретного устройства», bundletool нужен его профиль —
`device-spec`. Его получают либо с подключённого устройства, либо описывают вручную.

```bash
$ java -jar bundletool.jar get-device-spec --output=device.json
$ java -jar bundletool.jar extract-apks \
    --apks=app.apks --device-spec=device.json --output-dir=out
```

`extract-apks` достаёт из набора ровно те сплиты, которые подошли бы этому устройству. Это
полезно, когда нужно воспроизвести именно то, что видит конкретный телефон: набор ABI, плотность,
язык.

Отдельно есть `device-tier` — «уровень устройства» из Play (по производительности). Некоторые
feature-модули доставляются только на определённые tier, поэтому их не будет в базовой сборке.

## Play Asset Delivery и динамические модули

AAB поддерживает доставку ресурсов и кода по требованию. Режимы Asset Delivery:

- **install-time** — ресурсы входят в установку, доступны сразу.
- **fast-follow** — докачиваются сразу после установки, в фоне.
- **on-demand** — загружаются приложением по запросу.

Dynamic feature-модули работают похоже: код `feature_*` может отсутствовать в базовом APK и
подгружаться позже. Для аналитика это означает, что «код есть не весь» — часть логики приедет
только при определённом сценарии. Стоит проверить, какие модули объявлены и как приложение их
запрашивает.

## Таблица: элементы AAB и их назначение

| Элемент | Назначение | Аналог в APK |
|---|---|---|
| BundleConfig.pb | конфигурация сборки | — |
| base/ | основной код и манифест | base.apk |
| feature_*/ | динамические модули | config-сплиты |
| asset_pack_*/ | наборы ресурсов | — |
| BUNDLE-METADATA/ | служебные данные | META-INF/ |

## Если не сработало

Если `build-apks` ругается на подпись, — задайте keystore (`--ks`) или разрешите
`--ks-pass`. bundletool требует ключ, потому что генерируемые APK нужно подписывать.

Если `install-apks` не находит устройство, — проверьте `adb devices` и включённую отладку.
bundletool использует adb под капотом.

Если universal APK не открывается в JADX, — возможно, файл внутри `app.apks` называется иначе.
Распакуйте `app.apks` и посмотрите список (`unzip -l app.apks | grep apk`).

## Ограничения

AAB не устанавливается напрямую — это формат публикации, а не поставки. Поэтому «просто открыть
AAB» нельзя; всегда нужен шаг конвертации. Проверки подписи и целостности применяются к
сгенерированным APK, а не к AAB, поэтому для анализа universal APK подписывается ключом,
который вы задали, — это не помеха.

Наконец, помните: AAB — источник, а устройство получает результат. Если анализировать только
universal, можно упустить поведение, зависящее от конфигурации. Для полноты картины сверяйте
universal со сплит-набором.

## Мини-практика: из AAB в APK за пять шагов

Полный путь от `.aab` до готового к анализу APK.

Шаг 1. Убедиться, что это AAB:

```bash
$ unzip -l app.aab | grep -E 'BundleConfig|base/manifest'
  BundleConfig.pb
  base/manifest/AndroidManifest.xml
```

Шаг 2. Собрать universal APK (нужен keystore; можно сгенерировать временный):

```bash
$ keytool -genkey -v -keystore tmp.jks -alias a -keyalg RSA -keysize 2048 \
    -validity 30 -storepass secret -keypass secret -dname "CN=tmp"
$ java -jar bundletool.jar build-apks --bundle=app.aab --output=app.apks \
    --ks=tmp.jks --ks-pass=pass:secret --ks-key-alias=a --mode=universal
```

Шаг 3. Распаковать набор и вытащить APK:

```bash
$ unzip -o app.apks universal.apk
$ file universal.apk
universal.apk: Android package (APK)
```

Шаг 4. Открыть в JADX:

```bash
$ jadx -d out universal.apk
```

Шаг 5. Если нужен именно сплит-набор — собрать `--mode=default` и извлечь под device-spec.

## Частые ошибки

Ошибка первая — пытаться `adb install app.aab`. AAB не устанавливается напрямую; нужен шаг
конвертации.

Ошибка вторая — забыть про ключ. `build-apks` без keystore падает; сгенерируйте временный, если
своего нет.

Ошибка третья — искать готовый APK в корне `.aab`. Его там нет: внутри модули (`base/`,
`feature_*`), а APK появляется только после bundletool.

Ошибка четвёртая — анализировать только universal и забывать про конфигурацию. Некоторые ветки
кода зависят от наличия конкретного сплита; если поведение важно, соберите под нужный
device-spec.

## Зачем это знать глубже, чем «сделать APK»

Понимание AAB важно не только чтобы получить файл для JADX. Оно объясняет, **почему** современные
APK приходят набором сплитов, **откуда** берутся dynamic feature-модули и **как** приложение
может догружать код позже. Это напрямую связано с темами multidex (почему DEX несколько) и
динамической загрузки (почему кода «не хватает» статически).

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
