---
id: mobile-android-anatomy
title: "Анатомия Android-приложения: APK, манифест, DEX и smali"
category: mobile
parent: mobile-platforms
difficulty: easy
order: 1
tags: [android, apk, manifest, dex, smali, apktool]
prerequisites: [mobile-intro]
useful_for:
  - "CTF Mobile (реверс APK)"
  - "Статический анализ Android-приложений"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как устроен APK изнутри: контейнер zip, AndroidManifest.xml, DEX-байткод, smali, ресурсы и нативные библиотеки. Как быстро распаковать и что искать в каждом слое."
---
## Что такое APK изнутри

APK (Android Package) — это обычный zip-архив со строго определённой структурой. Понимание этой структуры — основа статического анализа. Внутри:

- `AndroidManifest.xml` — «паспорт» приложения: компоненты, permissions, версии, deep links. В APK он в бинарном (AXML) формате, `apktool`/`jadx` декодируют его в читаемый XML.
- `classes.dex` — байткод Dalvik (может быть несколько: `classes2.dex`, `classes3.dex` при мультидексе).
- `res/` — ресурсы: строки, разметка, картинки.
- `resources.arsc` — скомпилированная таблица ресурсов.
- `lib/` — нативные библиотеки `.so` под разные ABI (arm64-v8a, armeabi-v7a, x86_64).
- `assets/` — произвольные файлы, часто с данными или конфигами.
- `META-INF/` — подписи.

```bash
unzip -l app.apk | head -30
```

## Распаковка: apktool против jadx

`apktool` даёт smali (ассемблер Dalvik) и декодированные ресурсы — идеально, когда нужно пропатчить и пересобрать APK:

```bash
apktool d -f app.apk -o app_smali
apktool b app_smali -o patched.apk
```

`jadx` даёт Java-подобный код, удобный для чтения логики:

```bash
jadx -d app_java app.apk
jadx-gui app.apk            # графический интерфейс с поиском
```

Практика: читайте логику в `jadx`, а патчите — в smali через `apktool`. Для простых задач достаточно `jadx`.

## AndroidManifest.xml: что искать

Манифест — первое, что нужно смотреть. Ключевые атрибуты:

- `android:exported="true"` у Activity/Service/Receiver/Provider — компонент доступен другим приложениям.
- `<intent-filter>` с `<data android:scheme=...>` — deep links.
- `<uses-permission>` — какие права просит приложение.
- `android:debuggable="true"` — можно отлаживать.
- `android:allowBackup="true"` — данные можно извлечь через `adb backup`.

```bash
grep -nE 'exported|scheme|permission|debuggable|allowBackup' app_smali/AndroidManifest.xml
```

## DEX и smali

DEX — байткод, который исполняет виртуальная машина Dalvik/ART. `jadx` конвертирует его в Java, но иногда Java-вид «врёт» (обфускация, генерация), и тогда читают smali. Смali — читаемый ассемблер; в нём видно точные вызовы методов, регистры, строки.

```smali
const-string v0, "https://api.example.com"
invoke-virtual {p0, v0}, Landroid/content/Context;->getSharedPreferences(...)
```

Поиск по smali: `grep -rn 'const-string' app_smali/smali | grep -i pass`.

## Ресурсы и строки

`res/values/strings.xml` — частый источник секретов и подсказок. Также смотрите `res/raw/`, `assets/`:

```bash
grep -rInE 'flag|secret|key|token' app_smali/res app_smali/assets
```

Строки могут быть зашифрованы; тогда ищите метод, который их расшифровывает (обычно Base64/XOR), и повторяйте его.

## Нативные библиотеки

Код в `lib/*/*.so` не декомпилируется `jadx`. Для него нужны Ghidra, IDA, radare2:

```bash
file lib/arm64-v8a/libnative.so
strings -n 6 lib/arm64-v8a/libnative.so | grep -i flag
```

Нативный код часто содержит проверки флага или криптографию — это тема отдельного модуля.

## Подпись и пересборка

После патча APK нужно подписать, иначе устройство его не установит:

```bash
apksigner sign --ks my.keystore patched.apk
# или
jarsigner -keystore my.keystore patched.apk alias
```

Для генерации ключа: `keytool -genkey -v -keystore my.keystore -alias a -keyalg RSA -keysize 2048 -validity 10000`.

## Инструменты и практика

| Задача | Инструмент |
|--------|-----------|
| Распаковать | `apktool d`, `unzip` |
| Декомпилировать | `jadx`, `jadx-gui` |
| Пересобрать | `apktool b` |
| Подписать | `apksigner` |
| Нативный код | Ghidra, radare2 |
| Секреты | `grep -r` |

## Типичные ошибки и подводные камни

- **Смотреть только Java** — smali и `.so` содержат больше.
- **Игнорировать манифест** — там экспортированные компоненты.
- **Забыть про мультидекс** — логика бывает в `classes2.dex`.
- **Не подписать после патча** — APK не установится.
- **Полагать, что `jadx` — истина** — обфускация искажает код.
- **Не проверить `assets/`** — там бывают ключи и конфиги.
- **Забыть про ABI** — нужный `.so` может быть только под arm64.

## Справочная таблица команд

```bash
unzip -l app.apk                       # структура
apktool d -f app.apk -o smali          # smali + ресурсы
jadx -d java app.apk                   # Java
grep -rIn 'flag\|secret\|key' java/    # поиск
strings -n 6 lib/arm64-v8a/*.so        # нативные строки
apktool b smali -o new.apk             # пересборка
apksigner sign --ks k.jks new.apk      # подпись
```

## Что дальше / решение

План: распакуйте APK (`apktool` + `jadx`), изучите манифест, найдите экспортированные компоненты и deep links, поищите секреты в ресурсах и коде, проверьте нативные библиотеки. Дальше переходите к динамическому анализу (Frida) и перехвату трафика. Освоив анатомию APK, вы сможете быстро ориентироваться в любом Android-приложении и понимать, где искать слабые места.

## Практический пример: от APK до флага

Разберём сквозной сценарий. Дан файл `challenge.apk`. Первое: `unzip -l challenge.apk` — видим `classes.dex`, `lib/arm64-v8a/libnative.so`, `res/`. Второе: `jadx -d out challenge.apk` и поиск строк: `grep -rIn 'flag' out/`. Находим класс `MainActivity` с методом `checkFlag`, который сравнивает ввод с чем-то, загруженным из нативной библиотеки через `nativeCheck`. Третье: смотрим `libnative.so`: `strings -n 6 out/resources/lib/arm64-v8a/libnative.so | grep -i flag`. Четвёртое: если строки нет (зашифрована), открываем `.so` в Ghidra и анализируем `JNI_OnLoad`/`nativeCheck`. Пятое: собрав логику, воспроизводим проверку или патчим smali и пересобираем APK.

Этот маршрут — типичный для CTF: статика в `jadx`, затем нативный код, затем патч. Ключ — не пытаться понять всё приложение, а идти по подсказкам: строка «flag», метод с «check» в имени, `System.loadLibrary`.

## Пересборка и подпись: частые грабли

После патча smali пересоберите APK: `apktool b smali -o patched.apk`. Не забудьте подписать — без подписи установка провалится. Если `apktool` ругается на ресурсы, попробуйте `--use-aapt2`. Если приложение проверяет подпись (signature check), патч подписи тоже придётся обходить — либо в коде, либо через Frida. Всегда тестируйте на эмуляторе с writable system.

## Частые вопросы

«`jadx` показывает мусор?» — обфускация; используйте `--deobf` и читайте smali. «Логика в `.so`?» — Ghidra/radare2. «Секретов в ресурсах нет?» — ищите в нативном коде и в рантайме. «Как понять, какой ABI?» — `unzip -l`, смотрите `lib/`. «APK не ставится?» — подпишите и проверьте `minSdkVersion`.

## Что дальше / решение

Итог: распакуйте APK, декомпилируйте, найдите точку проверки, проанализируйте нативный код при необходимости, воспроизведите или пропатчьте логику, пересоберите и подпишите. Держите `jadx-gui` и Ghidra под рукой. Освоив этот маршрут, вы будете решать большинство статических задач категории Mobile за считанные минуты.

## Практический пример: от APK до флага

Дан `challenge.apk`. Шаг 1: `unzip -l challenge.apk` — видим `classes.dex`, `lib/arm64-v8a/libnative.so`. Шаг 2: `jadx -d out challenge.apk`, затем `grep -rIn 'flag' out/` — находим `MainActivity.checkFlag`, вызывающий `nativeCheck`. Шаг 3: `strings -n 6 out/resources/lib/arm64-v8a/libnative.so | grep -i flag` — если строки нет, открываем `.so` в Ghidra. Шаг 4: восстанавливаем логику, при необходимости патчим smali. Шаг 5: `apktool b smali -o patched.apk` и `apksigner sign`. Это типовой маршрут: статика → нативный код → патч.

## Частые вопросы

«`jadx` показывает мусор?» — обфускация; `--deobf` и smali. «Логика в `.so`?» — Ghidra/radare2. «APK не ставится после патча?» — подпишите. «Несколько DEX?» — смотрите все. «Секретов нет?» — ищите в нативном коде. «Какой ABI нужен?» — `unzip -l`, смотрите `lib/`.

## Что дальше / решение

Итог: распакуйте, декомпилируйте, найдите точку проверки, проанализируйте нативный код, воспроизведите или пропатчьте логику, пересоберите и подпишите. Держите `jadx-gui` и Ghidra под рукой — этого достаточно для большинства статических задач.

## Квиз

```quiz
- question: "Что такое APK по своей сути?"
  options:
    - "Исполняемый бинарник ELF"
    - "Zip-архив с фиксированной внутренней структурой"
    - "Образ диска"
    - "База данных"
  answer: 1
- question: "В каком файле лежит исполняемый байткод Android?"
  options:
    - "resources.arsc"
    - "classes.dex"
    - "AndroidManifest.xml"
    - "META-INF/CERT.RSA"
  answer: 1
- question: "Какой флаг манифеста позволяет другим приложениям запускать Activity?"
  options:
    - "android:allowBackup="true""
    - "android:debuggable="true""
    - "android:exported="true""
    - "android:usesCleartextTraffic="true""
  answer: 2
- question: "Где чаще всего прячут нативную криптографию и проверки лицензии?"
  options:
    - "В resources.arsc"
    - "В lib/<abi>/*.so"
    - "В META-INF"
    - "В res/drawable"
  answer: 1
- question: "Почему важен `classes2.dex`?"
  options:
    - "Это резервная копия"
    - "При мультидексе часть кода/секретов может лежать там"
    - "Он содержит только ресурсы"
    - "Он всегда пустой"
  answer: 1
```

## Где пригодится

- **CTF:** Mobile/Reversing — разбор APK, поиск флагов в ресурсах, smali и нативных библиотеках.
- **Bug bounty:** первичный триаж мобильного приложения, поиск экспортированных компонентов и секретов.
- **Пентест:** этап «static analysis» по OWASP MASTG, составление карты поверхности атаки.
- **Работа:** AppSec-ревью релизов, оценка конфигурации манифеста перед публикацией.
