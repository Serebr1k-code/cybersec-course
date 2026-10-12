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
  - "CTF: Mobile/Reversing"
  - "Пентест: Android"
  - "Работа: AppSec"
estimated_minutes: 14
summary: "Как устроен APK изнутри: контейнер zip, AndroidManifest.xml, DEX-байткод, smali, ресурсы и нативные библиотеки. Как быстро распаковать и что искать в каждом слое."
---

## Вопрос, с которого всё начинается

В вводном уроке мы увидели, что APK — это ZIP-архив, и нашли секрет в коде через `jadx`. Но у APK внутри несколько слоёв, и в каждом можно найти своё: манифест, байткод, ресурсы, нативные библиотеки. Как разобрать APK системно и не пропустить зацепку?

В этом уроке мы «вскроем» один APK послойно и посмотрим, что лежит в каждом слое и что в нём искать.

## Наш пример: app.apk

Наш объект — `app.apk`. Мы пройдём по слоям от внешнего к внутреннему: контейнер → манифест → код → ресурсы → нативные библиотеки. Каждый слой отвечает на свой вопрос.

## Шаг 1: APK как ZIP-контейнер

```
$ unzip -l app.apk
  Length      Name
---------  ----
     4320   AndroidManifest.xml
  4821112   classes.dex
    12044   resources.arsc
   180233   res/layout/activity_main.xml
   512     META-INF/CERT.RSA
  9210044   lib/arm64-v8a/libnative.so
```

Слои APK:

- `AndroidManifest.xml` — описание приложения (бинарное).
- `classes.dex` — скомпилированный байткод (может быть `classes2.dex`, `classes3.dex`).
- `resources.arsc` — таблица ресурсов.
- `res/` — картинки, разметка, строки.
- `lib/` — нативные библиотеки `.so` под разные архитектуры.
- `META-INF/` — подпись приложения.

Уже здесь видно подсказку: есть `libnative.so` — значит, часть логики в нативном коде, и `jadx` её не покажет.

## Шаг 2: декодируем манифест

Бинарный манифест читается `apktool`:

```
$ apktool d app.apk -o app_decoded
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
```

Теперь открываем `app_decoded/AndroidManifest.xml`:

```xml
<manifest package="com.example.app">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:debuggable="false">
    <activity android:name=".MainActivity" android:exported="true"/>
    <activity android:name=".AdminActivity" android:exported="false"/>
    <receiver android:name=".BootReceiver" android:exported="true"/>
    <service android:name=".SyncService" android:exported="false"/>
  </application>
</manifest>
```

Что важно:

- **`package`** — идентификатор приложения.
- **`uses-permission`** — к чему есть доступ (интернет, камера).
- **`exported="true"`** у `MainActivity` и `BootReceiver` — эти компоненты доступны другим приложениям. У `AdminActivity` стоит `false` — он закрыт.
- **`debuggable="false"`** — отладка выключена (если `true`, приложение легко отлаживать).

## Шаг 3: код — DEX и smali

`classes.dex` — байткод виртуальной машины Dalvik. Есть два способа его читать:

- **`jadx`** — декомпилирует в Java (привычно и быстро).
- **`baksmali`** — разбирает в **smali**, низкоуровневый ассемблер Dalvik (точнее, но менее читаемо).

```
$ baksmali d classes.dex -o smali_out
$ ls smali_out/com/example/app | head
AdminActivity.smali
Api.smali
MainActivity.smali
```

Фрагмент `Api.smali`:

```
.method public static getApiKey()Ljava/lang/String;
    .locals 1
    const-string v0, "sk_live_51H..."
    return-object v0
.end method
```

`const-string` — загрузка строковой константы. Так выглядят захардкоженные секреты на уровне smali. Иногда `jadx` не справляется (обфускация), а `smali` читается.

## Шаг 4: ресурсы

`resources.arsc` и `res/` содержат строки, разметку и картинки. Строки часто хранят подсказки и URL:

```
$ grep -r "http" app_decoded/res/values/strings.xml
<string name="api_base_url">https://api.example.com/v2</string>
```

Так же ищут ключи, эндпоинты и тексты, которые разработчики «спрятали» в ресурсы.

## Шаг 5: нативные библиотеки

Файлы `lib/*.so` — это машинный код (C/C++). Их не декомпилируют в Java; для них нужны `Ghidra`, `IDA` или `radare2`. Нативные библиотеки часто содержат проверки, которые не хотят показывать в Java: лицензирование, криптографию, античит.

```
$ file app_decoded/lib/arm64-v8a/libnative.so
libnative.so: ELF 64-bit LSB shared object, ARM aarch64
```

Если важная логика ушла в `.so` — это сигнал: смотреть нужно реверс-инжиниринг нативного кода (отдельный урок).

## Шаг 6: где искать секреты

Соберём маршрут поиска:

1. **Манифест:** `exported`, разрешения, debuggable.
2. **Smali/Java:** `const-string` с ключами, URL, паролями.
3. **Ресурсы:** `strings.xml`, `res/raw/`.
4. **Нативные:** строки в `.so` (`strings libnative.so | grep -i key`).
5. **Ассеты:** `assets/` с конфигами и базами.

## Мультидекс и структура DEX

Крупные приложения не влезают в один DEX: у него лимит 65 536 методов (проблема «64K»). Поэтому APK содержит несколько файлов `classes.dex`, `classes2.dex` и так далее. При анализе проверяйте все — секрет может лежать во втором или третьем.

## Подпись приложения

Папка `META-INF/` содержит подпись: `CERT.RSA` и `CERT.SF`. Подпись гарантирует, что APK не изменяли после сборки. Для пентеста это важно: если пересобрать APK (например, добавить Frida-хуки), подпись сломается, и приложение может отказаться работать. Поэтому используют переподпись своим ключом (`apksigner`) или обход проверки.

```
$ apksigner verify --print-certs app.apk
Signer #1 certificate DN: CN=Example, O=Example Corp
```

## Обфускация и что с ней делать

Разработчики обфусцируют код (ProGuard/R8): имена классов и методов заменяются на `a`, `b`, `c`. Читать такой код тяжело, но:

- Строковые константы часто остаются — ищите `const-string`.
- Ресурсы и манифест не обфусцируются.
- Логика, вынесенная в `.so`, обфусцируется отдельно.

Обфускация замедляет анализ, но не останавливает его.

## Работа с ресурсами и ассетами вручную

Если `apktool` не справился с ресурсами, их достают напрямую. Картинки и файлы из `res/` и `assets/` — обычные файлы внутри ZIP:

```
$ unzip -o app.apk 'assets/*' -d extracted
$ ls extracted/assets
config.json  database.db
```

`database.db` — вшитая SQLite-база; её открывают `sqlite3` и ищут данные, которых не должно быть в клиенте.

## Быстрый старт: apkleaks

Для первого прохода есть `apkleaks` — он ищет в APK секреты и эндпоинты:

```
$ apkleaks -f app.apk
[+] URL: https://api.example.com/v2
[+] Secret: sk_live_51H...
```

Инструмент не заменяет ручной разбор, но экономит время.

## Что такое smali и зачем он нужен

Smali — человекочитаемое представление байткода Dalvik: каждая инструкция соответствует одной операции виртуальной машины. Он нужен, когда `jadx` не смог восстановить Java (обфускация, нестандартный код) или когда нужно **изменить** поведение приложения: правки вносят в smali, а затем пересобирают APK через `apktool b`.

```
$ apktool b app_decoded -o app_patched.apk
```

Так снимают проверки и добавляют свои хуки. Это основа патчинга Android-приложений.

## APK и Android App Bundle

Современные приложения часто распространяются как **AAB** (Android App Bundle) — из него Google Play генерирует APK под конкретное устройство. Если у вас `.aab`, его распаковывают `bundletool`, получая APK. Логика та же: внутри ZIP, манифест, DEX.

## Быстрая проверка перед разбором

Прежде чем углубляться, посмотрите на размер APK. Слишком маленький — возможно, код в нативной библиотеке. Слишком большой — много ресурсов, где тоже прячут данные. Размер подсказывает, куда смотреть в первую очередь.

## Что мы теперь знаем

По-простому:

1. APK — это ZIP из нескольких слоёв.
2. Манифест показывает компоненты и разрешения.
3. DEX — байткод; читается `jadx` или `baksmali` (smali).
4. Ресурсы и ассеты хранят строки и конфиги.
5. Нативные `.so` требуют отдельного реверса.

## На что смотреть дальше

- **Начинайте с манифеста.** `exported` и разрешения — быстрые находки.
- **Ищите `const-string`.** Это строковые константы — там секреты.
- **Не забывайте про `.so`.** Важная логика может быть в нативном коде.
- **Проверяйте ассеты.** `assets/` часто хранит конфиги и базы.

## Квиз

Проверь себя.

```quiz
- question: "Что содержит файл classes.dex?"
  options:
    - "Картинки"
    - "Скомпилированный байткод Dalvik"
    - "Подпись приложения"
    - "Сетевые настройки"
  answer: 1
- question: "Что означает exported=true у компонента?"
  options:
    - "Компонент доступен другим приложениям"
    - "Компонент выгружает данные в сеть"
    - "Компонент зашифрован"
    - "Компонент только для отладки"
  answer: 0
- question: "Какой инструмент разбирает DEX в smali?"
  options:
    - "jadx"
    - "baksmali"
    - "exiftool"
    - "binwalk"
  answer: 1
- question: "Что делать с файлами lib/*.so?"
  options:
    - "Читать jadx"
    - "Реверсить в Ghidra/IDA/radare2"
    - "Открывать в блокноте"
    - "Игнорировать всегда"
  answer: 1
- question: "Где часто хранятся строки с URL и ключами?"
  options:
    - "В res/values/strings.xml"
    - "В META-INF/CERT.RSA"
    - "В AndroidManifest.xml"
    - "В названии файла"
  answer: 0
```

## Куда дальше

В следующем уроке мы перейдём к **анализу приложения**: статике и динамике, `jadx` и `Frida`, и научимся находить уязвимости в компонентах. А пока запомни главное: APK разбирается послойно — контейнер, манифест, код, ресурсы, натив.

## Где пригодится

- **CTF (Mobile):** разбор APK и поиск скрытых данных.
- **Bug bounty:** анализ мобильных приложений и их API.
- **Пентест:** аудит Android-приложений по OWASP MASTG.
- **Реверс-инжиниринг:** понимание структуры Android-приложений.
