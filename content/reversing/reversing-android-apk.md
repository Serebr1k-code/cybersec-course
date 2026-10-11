---
id: reversing-android-apk
title: "Реверс Android APK"
category: reversing
parent: reversing-managed-dotnet-java
difficulty: medium
order: 1
tags: [reversing, android, apk, jadx, apktool, frida, smali, dalvik]
prerequisites: [reversing-managed-dotnet-java]
useful_for:
  - "CTF Reversing / Mobile"
  - "Анализ Android-приложений"
  - "Mobile pentest"
estimated_minutes: 55
summary: "Разбор APK: dex/Dalvik, jadx, apktool, smali, нативные библиотеки, Frida и репакинг."
---
**Реверс Android APK** — это разбор приложений на предмет логики, секретов, защиты и уязвимостей. APK — это zip с DEX-байткодом, нативными библиотеками, ресурсами и манифестом. Урок даёт полный практический workflow: распаковка (`apktool`), декомпиляция в Java (`jadx`), чтение smali, анализ нативного кода (`Frida`, JNI), динамический анализ и обход анти-эмуляции/root-детекции, с разобранным примером.

## Структура APK

APK — обычный ZIP. Ключевые элементы:

- **`classes.dex`** (иногда `classes2.dex`, ...) — скомпилированный DEX-байткод (Dalvik/ART).
- **`AndroidManifest.xml`** — компоненты (activities, services, receivers, providers), разрешения, точка входа.
- **`res/`** — ресурсы, `resources.arsc` — скомпилированные строки/стили.
- **`lib/<abi>/`** — нативные `.so` (arm64-v8a, armeabi-v7a, x86_64).
- **`assets/`** — произвольные файлы (модели, БД, шифрованные ресурсы).
- **`META-INF/`** — подписи (v1/v2/v3).

```bash
unzip -l app.apk | head -40
unzip -l app.apk | grep -E 'classes.*dex|lib/|assets/'
```

## Инструменты: apktool, jadx, dex2jar

| Инструмент | Назначение | Команда |
|---|---|---|
| `apktool` | распаковка/сборка, smali+ресурсы | `apktool d app.apk -o out` |
| `jadx` | декомпиляция в Java | `jadx -d out app.apk` |
| `dex2jar` | DEX → JAR | `d2j-dex2jar.sh app.apk` |
| `baksmali` | DEX → smali | `baksmali d classes.dex -o out` |
| `bytecode-viewer` | GUI-просмотр | — |

```bash
# apktool: получить smali и ресурсы (можно пересобрать)
apktool d -f -o app_out app.apk
# jadx: читаемый Java (лучше для понимания логики)
jadx -d app_java --show-bad-code app.apk
# dex2jar + procyon/cfr для отдельных классов
d2j-dex2jar.sh app.apk -o app.jar
```

## Декомпиляция и чтение smali

`jadx` даёт Java-подобный код — начните с него. `apktool` даёт **smali** (ассемблер Dalvik) — нужен, когда jadx не справляется (обфускация, повреждённый DEX) или для точных патчей.

```smali
# пример smali: проверка пароля
const-string v0, "s3cr3t"
invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
move-result v0
if-eqz v0, :cond_fail
```

Читайте `AndroidManifest.xml` (через `apktool` он в читаемом виде), чтобы найти точку входа, экспортированные компоненты и разрешения.

```bash
grep -rniE 'password|secret|api_key|token' app_out/smali* app_out/assets 2>/dev/null
grep -rn 'const-string' app_out/smali/com/target/ | grep -iE 'http|key|flag'
```

## Нативный код и JNI

Если логика в `.so`, jadx покажет только `native`-объявления. Анализ — Ghidra/IDA по архитектуре устройства (arm64 обычно).

```bash
file app_out/lib/arm64-v8a/libtarget.so
# ELF 64-bit LSB shared object, ARM aarch64
# в Ghidra: искать Java_<package>_<Class>_<method> экспорты
readelf -sW libtarget.so | grep Java_
```

JNI-функции именуются `Java_com_example_Class_method`; по ним видно соответствие Java↔native.

## Динамический анализ: Frida и Objection

```bash
# установка frida на устройство (root)
adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
# список процессов и хукинг
frida-ps -U
frida -U -f com.target.app -l hook.js --no-pause
# Objection: обход root-детекции и SSL pinning «из коробки»
objection -g com.target.app explore
```

Пример хука метода:

```javascript
Java.perform(function () {
  var C = Java.use("com.target.app.Login");
  C.checkPassword.implementation = function (pw) {
    console.log("checkPassword called with: " + pw);
    return true;   // обход проверки
  };
});
```

## Обход root-детекции и анти-эмуляции

Типовые проверки: наличие `su`/`busybox`, `test-keys` в build, приложения Superuser, `frida-server`, эмулятор (сенсоры, `ro.kernel.qemu`). Обход через Frida:

```javascript
Java.perform(function () {
  var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
  RootBeer.isRooted.implementation = function () { return false; };
  var Build = Java.use("android.os.Build");
  Build.TAGS.value = "release-keys";   // убрать test-keys
});
```

Для нативных проверок — хуки `fopen`/`access`/`stat` на пути `su`, `strstr` на «frida».

## Работа с ресурсами и манифестом

```bash
# строки из resources.arsc
aapt dump strings app.apk | grep -iE 'key|secret'
aapt dump badging app.apk | head
# декодировать assets (часто base64/AES)
python3 -c "import base64; print(base64.b64decode(open('assets/blob','rb').read()))"
```

## Разобранный пример: обход проверки лицензии

**Шаг 1. jadx → найти проверку.**

```java
public boolean isPro() {
    return getSharedPreferences("cfg",0).getBoolean("pro", false);
}
```

**Шаг 2. Frida → форсировать true.**

```javascript
Java.perform(function () {
  var M = Java.use("com.target.app.Premium");
  M.isPro.implementation = function () { return true; };
});
```

**Шаг 3. Если проверка нативная** — в Ghidra найти `Java_..._isPro` и пропатчить возврат (или хук `libtarget.so` через Frida `Interceptor.attach`).

**Шаг 4. Патч APK** (если нужен офлайн-вариант):

```bash
apktool d app.apk -o out
# правим smali: заменить if-eqz на if-nez / вернуть const/4 v0, 0x1
apktool b out -o patched.apk
# подпись
apksigner sign --ks my.keystore patched.apk
```

## Инструменты (таблица)

| Инструмент | Назначение | Пример |
|---|---|---|
| `apktool` | распаковка/сборка | `apktool d app.apk` |
| `jadx` | Java-декомпиляция | `jadx -d out app.apk` |
| `Frida` | динамический хукинг | `frida -U -f app -l h.js` |
| `Objection` | обход защит | `objection -g app explore` |
| `Ghidra` | нативный код | JNI-экспорты |
| `apksigner` | подпись | `apksigner sign ...` |

## Частые ошибки и подводные камни

- **Обфускация (ProGuard/R8).** Имена классов/методов переименованы — ориентируйтесь на строки и поведение, а не на имена.
- **Multi-DEX.** Логика может быть в `classes2.dex`; декомпилируйте все.
- **Native-only логика.** jadx бессилен, если всё в `.so` — переходите в Ghidra.
- **Frida не стартует.** Нужен совпадающий с устройством `frida-server` и root.
- **Packing.** Некоторые APK упакованы (оболочка расшифровывает DEX в рантайме) — дампите DEX из памяти.
- **Неверная подпись.** После патча APK не установится без переподписи и удаления старой версии.

## Что дальше / решение

Маршрут: **apktool/jadx → чтение логики и манифеста → анализ .so в Ghidra → динамика Frida/Objection → обход защит → патч/пересборка**. Для CTF — ищите флаг в строке/проверке; для аудита — экспортированные компоненты и хранение секретов. Дальше — `reversing-android-native` (глубокий нативный анализ), `reversing-frida-advanced` и `mobile-app-security-testing`.

## Дамп DEX из памяти при упаковке

Если APK упакован (оболочка расшифровывает DEX в рантайме), статический анализ даст лишь загрузчик.

```bash
# при root: найти расшифрованный DEX в памяти процесса
frida -U -f com.target.app -l dump.js
# dump.js: перебрать модули dex и сохранить
```

```javascript
// перебор загруженных DEX и дамп
var Process = Java.use("android.os.Process");
Java.perform(function () {
  // через DexFile / BaseDexClassLoader найти dex в памяти
});
```

Альтернатива — инструменты `frida-dexdump`/`DexExtractor`, которые сами находят и выгружают DEX. После дампа — декомпилируйте `jadx`.

## Обход SSL pinning: полный пример

```javascript
// Frida: отключить CertificatePinner (OkHttp)
Java.perform(function () {
  var Pinner = Java.use("okhttp3.CertificatePinner");
  Pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {};
});
```

Универсальный вариант — Objection:

```bash
objection -g com.target.app explore
# в консоли:
android sslpinning disable
android root disable
```

Для нативных пиннингов — хук `SSL_CTX_set_verify`/`X509_verify_cert` в `libssl.so` через `Interceptor`.

## Анализ хранения секретов

- **SharedPreferences** — `/data/data/<pkg>/shared_prefs/*.xml` (часто пароли/токены в открытом виде).
- **SQLite** — `/data/data/<pkg>/databases/*.db`.
- **Файлы** — `/data/data/<pkg>/files/`, кэш.
- **KeyStore** — ключи в hardware-backed хранилище (сложнее извлечь).
- **Firebase/облако** — ключи в `google-services.json`/строках.

```bash
adb shell "run-as com.target.app cat shared_prefs/cfg.xml"
adb shell "run-as com.target.app ls databases/"
```

## Ключевые выводы по реверсу APK

Итог: **jadx для логики, apktool для патча/ресурсов, Ghidra для .so, Frida/Objection для динамики и обхода защит**. При упаковке — дампите DEX из памяти. Проверяйте `assets`/SharedPreferences на секреты. Дальше — `reversing-android-native`, `reversing-frida-advanced` и `mobile-app-security-testing`.

## Пересборка и подпись: полный цикл патча

Иногда нужно не просто посмотреть, а модифицировать поведение навсегда (офлайн-патч).

```bash
# 1) распаковать
apktool d -f app.apk -o out
# 2) найти в smali нужную проверку и инвертировать переход
#    (if-eqz -> if-nez) или вернуть const/4 v0, 0x1 перед return
# 3) собрать
apktool b out -o patched.apk
# 4) выровнять и подписать (v2)
zipalign -p 4 patched.apk patched_aligned.apk
apksigner sign --ks debug.keystore --out final.apk patched_aligned.apk
# 5) удалить старую версию и установить
adb uninstall com.target.app
adb install final.apk
```

Важно: без удаления старой версии установка упадёт из-за несовпадения подписи. Для v1-подписи иногда достаточно `jarsigner`.

## Анализ сетевого взаимодействия и API

Многие проверки/флаги приходят с сервера. Перехват трафика с обходом pinning даёт понимание контракта.

```bash
# mitmproxy на устройстве (после обхода pinning)
mitmproxy -p 8080
# на Android: настроить прокси и установить CA в системный store (root)
```

Смотрите запросы к API: эндпоинты, заголовки, токены, форматы. Часто флаг/лицензия проверяется сервером, и логика на клиенте лишь отображает результат — тогда нужен анализ серверного контракта и подмена ответа через Frida.

## Полезные однострочники и автоматизация

```bash
# быстрый поиск секретов по всем ресурсам и smali
grep -rniE '(api[_-]?key|secret|password|token|BEGIN [A-Z ]*PRIVATE KEY)' app_out/ | head -50
# поиск URL и эндпоинтов
grep -rhoE 'https?://[a-zA-Z0-9./_-]+' app_out/smali* | sort -u | head
# декодирование base64-строк из assets
for f in app_out/assets/*; do base64 -d "$f" 2>/dev/null | strings | head; done
# проверка экспортированных компонентов (потенциальные точки входа)
grep -n 'exported="true"' app_out/AndroidManifest.xml
```

Экспортированные `activity`/`service`/`receiver`/`provider` — частые уязвимости Android (доступ к внутренним функциям без прав). Проверяйте `android:exported="true"` и права в манифесте: нередко через внешний intent можно вызвать привилегированную операцию.

## Квиз

```quiz
- question: "Что содержит `classes.dex` в APK?"
  options:
    - "Нативные библиотеки"
    - "Байткод Dalvik/ART"
    - "Ресурсы"
    - "Подпись"
  answer: 1
- question: "Каким инструментом удобнее всего читать декомпилированный Java-код APK?"
  options:
    - "apktool"
    - "jadx"
    - "x64dbg"
    - "binwalk"
  answer: 1
- question: "Какой инструмент позволяет перехватывать методы в рантайме Android?"
  options:
    - "gdb"
    - "jadx"
    - "Frida"
    - "Ghidra"
  answer: 2
- question: "Что нужно сделать после `apktool b` перед установкой APK?"
  options:
    - "Подписать APK (`apksigner`)"
    - "Распаковать его"
    - "Скомпилировать `.so`"
    - "Включить ASLR"
  answer: 0
- question: "Где искать логику, если jadx показывает метод с ключевым словом `native`?"
  options:
    - "В нативных `.so` в `lib/<abi>/`"
    - "В `resources.arsc`"
    - "В `META-INF`"
    - "В `classes2.dex`"
  answer: 0
```

## Где пригодится

- **CTF Mobile/Reversing:** задачи с APK — стандартная категория на многих CTF.
- **Mobile pentest:** поиск hardcoded-секретов, небезопасного хранения, обход клиентских проверок.
- **Android malware analysis:** разбор банковских троянов, dropper'ов, нативных компонентов.
- **Работа (mobile security):** аудит приложений, оценка защиты (обфускация, anti-tamper).
- **Собес:** вопросы про dex/smali/Frida — базовые для mobile security позиций.
