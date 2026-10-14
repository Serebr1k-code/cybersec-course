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
summary: "Разбор APK: структура архива, dex/Dalvik, AndroidManifest, smali и нативные библиотеки — на реальном APK."
lab:
  kind: shell
  title: 'Практика: разобрать APK-архив'
  toolset: [core, hex, rev]
  workdir: /home/student/task
  files: [task.md, small.apk]
  check: 'grep -q ''nto{d3x_m4g1c_1n_4pk}'' found.txt'
  hints:
    - "Повторение (`reversing-managed-dotnet-java`): APK — managed-контейнер; сначала `unzip -l small.apk`."
    - 'APK — это ZIP-архив: `unzip -l small.apk`.'
    - 'Ключевые элементы: `classes.dex` (код), `AndroidManifest.xml`, `resources.arsc`.'
    - 'Строки хранятся без сжатия: `strings small.apk | grep nto`.'
---

## Вопрос, с которого всё начинается

На CTF по Mobile дают файл `app.apk`. Это ZIP-архив, внутри — скомпилированный код и ресурсы. Как из архива добраться до логики приложения, найти точку входа и понять, где проверяется флаг или пароль? Android-приложения — это managed-код (Dalvik), но со своей структурой, и разбирать их удобнее специальными инструментами.

## Наш пример

Возьмём настоящий APK `small.apk` — минимальное Android-приложение. Сначала `file` и содержимое архива:

```bash
$ file small.apk
small.apk: Android package (APK), with gradle app-metadata.properties, with APK Signing Block
$ unzip -l small.apk
  Length      Name
     1180    classes.dex
     2148    AndroidManifest.xml
      568    res/drawable/ic_launcher_background.xml
      548    res/layout/activity_main.xml
     1696    resources.arsc
```

Ключевые элементы: **`classes.dex`** (код), **`AndroidManifest.xml`** (описание приложения), **`resources.arsc`** (ресурсы), **`res/`** (файлы). Разберём каждый.

## Шаг 1: dex — код в формате Dalvik

`classes.dex` — это скомпилированный код в формате **Dalvik Executable** (регистровая ВМ Android). Проверим магию:

```bash
$ xxd classes.dex | head -1
00000000: 6465 780a 3033 3500 7f82 d23e e1c0 17da  dex.035....>....
```

Первые байты — `64 65 78 0a`, то есть ASCII **`dex\n`**, дальше версия `035`. Так опознаётся dex. Внутри — классы, методы и **smali** (человекочитаемое представление Dalvik-байткода).

## Шаг 2: AndroidManifest — паспорт приложения

`AndroidManifest.xml` внутри APK хранится в **бинарном XML** (сжат), поэтому обычный просмотр даёт мусор. Разберём его через androguard:

```xml
<manifest package="io.github.skylot.android.smallapp" ...>
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
  <application android:debuggable="true" android:allowBackup="true" ...>
    <activity android:name="io.github.skylot.android.smallapp.MainActivity"
              android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
```

Читаем важное: **package** — имя пакета, **MainActivity** с `LAUNCHER` — точка входа (то, что запускается при клике на иконку). Атрибуты `debuggable="true"` и `exported="true"` — прямые подсказки для пентеста: с `debuggable` приложение можно отлаживать, `exported` делает компонент доступным другим приложениям.

## Шаг 3: классы и методы из dex

Теперь заглянем в сам код. androguard умеет читать dex напрямую:

```text
package: io.github.skylot.android.smallapp
main activity: io.github.skylot.android.smallapp.MainActivity
dex classes:
   Lio/github/skylot/android/smallapp/MainActivity;
       <init> ()V
       onCreate (Landroid/os/Bundle;)V
```

Имена классов записаны в **JVM-дескрипторах**: `Lio/.../MainActivity;` — это класс, `onCreate (Landroid/os/Bundle;)V` — метод, принимающий `Bundle` и возвращающий `void` (`V`). Точка входа логики — `onCreate`: там Activity инициализируется. В CTF-задачах проверку флага обычно прячут в `onCreate` или в вызываемых из него методах.

## Шаг 4: декомпиляция в Java

Dalvik-байткод читать тяжело, поэтому его декомпилируют обратно в Java. Инструменты:

- **jadx** — открывает APK и показывает Java-код; самый удобный старт.
- **apktool** — распаковывает APK в **smali** (байткод как текст) и декодирует ресурсы.
- **CFR / Procyon** — декомпиляторы `.dex`/`.class`.

Типичный конвейер: `jadx app.apk` → найти `MainActivity` → прочитать `onCreate` → найти проверку. Если декомпилятор спотыкается (обфускация), смотрят smali через apktool.

## Шаг 5: нативные библиотеки

Не всё в APK — managed. Часто рядом лежат **нативные `.so`** в папке `lib/` (по архитектурам: `arm64-v8a`, `armeabi-v7a`, `x86_64`). Критичная логика (проверка лицензии, крипто) специально выносится в C/C++, чтобы усложнить реверс. Признаки:

```bash
$ unzip -l app.apk | grep '\.so'
   lib/arm64-v8a/libnative.so
```

Если видишь `.so`, готовься к обычному нативному реверсу (ARM64) — это тема следующего урока. Связь managed ↔ native идёт через **JNI**: Java-метод с `native`-модификатором вызывает функцию в `.so`.

## Шаг 6: ресурсы и строки

Кроме кода, в APK есть ресурсы: `res/` (layout, drawables, строки) и `resources.arsc` (сводная таблица ресурсов). Для реверса важнее всего **строки** — они лежат в `res/values/strings.xml` (в скомпилированном виде в `resources.arsc`). Подсказки, тексты ошибок и иногда сами флаги часто там:

```bash
$ apktool d app.apk -o out
$ grep -ri 'flag' out/res/values/strings.xml
```

Декомпилированный `apktool`-ом проект даёт читаемые XML и **smali** — текстовый вид Dalvik-байткода. По smali удобно искать конкретные проверки, когда декомпилятор в Java спотыкается об обфускацию.

## Шаг 7: переупаковка (repacking)

Иногда проверку проще **запатчить**, чем обойти. Схема: `apktool d` (распаковать) → поправить smali → `apktool b` (собрать) → подписать → установить. Подпись нужна своя, потому что оригинальная после правок недействительна:

```bash
$ apktool b out -o patched.apk
$ apksigner sign --ks my.keystore patched.apk
$ adb install patched.apk
```

На CTF это редко нужно, но в пентесте (обход проверок целостности, отключение root-детекта) — стандартный приём. Плюс динамика: Frida позволяет перехватывать методы без переупаковки, что быстрее.

## Шаг 8: инструменты и порядок работы

- **jadx** / **jadx-gui** — декомпиляция APK в Java, быстрый старт.
- **apktool** — распаковка/сборка, smali, ресурсы.
- **androguard** — разбор APK/DEX из Python (мы им и пользовались).
- **Frida** / **objection** — динамика на устройстве или эмуляторе.
- **`unzip`**, **`strings`**, **`xxd`** — базовые шаги без установки чего-либо.

Порядок: `file` → `unzip -l` → manifest (точка входа, `debuggable`/`exported`) → jadx (Java) → smali/`resources.arsc` (если нужно) → `.so` (если есть). Этого конвейера достаточно для 90% задач.

## На что смотреть дальше

Разбирая незнакомый APK, не открывай сразу всё:

1. **`unzip -l`** — есть ли `.so` (нативная логика), сколько `classes*.dex`.
2. **Manifest** — точка входа, `debuggable`, `exported`, разрешения (`INTERNET`, `READ_SMS` и т.п. намекают на назначение).
3. **`res/values/strings.xml`** — тексты-подсказки и возможный флаг.
4. **`MainActivity.onCreate`** — где стартует логика приложения.
5. **Ссылки на `native`** — если есть, готовься к `.so`.

Частая ловушка — искать флаг только в Java и забыть про `resources.arsc` или нативные библиотеки. Проверяй все три места: код, ресурсы, `.so`.

## Шаг 9: типичные CTF-сценарии

Android-задачи на CTF повторяются в нескольких видах, и под каждый есть свой короткий путь:

- **Флаг в ресурсах** — ищи `strings.xml` и `resources.arsc`; часто флаг лежит открытым текстом.
- **Проверка в Java** — декомпилируй jadx-ом и найди сравнение в `onCreate`.
- **Логика в native** — `unzip -l | grep .so`, дальше нативный реверс ARM64.
- **Обфускация** — имена вида `a/b/c`; используй smali и динамику.
- **Шифрование ввода** — найди ключ в строках/ресурсах, воспроизведи расшифровку.

Большинство решений — это «распаковать → посмотреть manifest → jadx → найти проверку». Не усложняй, пока не увидел реальной обфускации.

<!-- lab -->

## Что мы теперь знаем

- APK — это ZIP: `classes.dex` (код), `AndroidManifest.xml` (описание), `resources.arsc`, `res/`.
- Код — Dalvik-байткод; магия `dex\n035` его опознаёт.
- Manifest в бинарном XML: точка входа — Activity с `LAUNCHER`; `debuggable`/`exported` — подсказки для пентеста.
- Декомпиляторы (`jadx`, `apktool`, CFR) возвращают Java/smali для чтения логики.
- Логику могут выносить в нативные `.so` через JNI — тогда нужен ARM-реверс.

## Куда дальше

Мы добрались до нативных библиотек внутри APK. Именно там прячут самую защищённую логику — и её реверс требует ARM64 и JNI. Об этом — в следующем уроке. А пока запомни конвейер: `file` → `unzip -l` → manifest (точка входа) → `jadx` (Java) → `.so` (если есть).

## Квиз

```quiz
- question: "Что такое APK по сути?"
  options:
    - "Исполняемый файл ARM"
    - "ZIP-архив с кодом (`classes.dex`), манифестом и ресурсами"
    - "Текстовый файл"
    - "Образ диска"
  answer: 1
  explanation: "APK — это ZIP: код в classes.dex, описание в AndroidManifest.xml, ресурсы в res/ и resources.arsc."
- question: "Какие первые байты у dex-файла?"
  options:
    - "`7f 45 4c 46`"
    - "`dex\\n` (`64 65 78 0a`)"
    - "`4d 5a`"
    - "`cafebabe`"
  answer: 1
  explanation: "Dalvik Executable начинается с ASCII `dex\\n` и номера версии, например 035."
- question: "Где в AndroidManifest указана точка входа приложения?"
  options:
    - "В теге `<uses-sdk>`"
    - "В `<activity>` с intent-filter MAIN/LAUNCHER"
    - "В `resources.arsc`"
    - "В имени пакета"
  answer: 1
  explanation: "Activity с действием MAIN и категорией LAUNCHER запускается при клике на иконку — это точка входа."
- question: "Почему AndroidManifest.xml не читается глазами прямо из архива?"
  options:
    - "Он зашифрован"
    - "Он хранится в бинарном XML (AXML), нужен декодер (apktool/androguard)"
    - "Он удалён"
    - "Это текстовый файл"
  answer: 1
  explanation: "В APK манифест — бинарный XML; его декодируют apktool или читают через androguard."
- question: "Зачем в APK кладут нативные `.so`?"
  options:
    - "Для иконок"
    - "Критичную логику (лицензии, крипто) выносят в C/C++ через JNI, чтобы усложнить реверс"
    - "Это обязательно для всех приложений"
    - "Для хранения строк"
  answer: 1
  explanation: "`.so` содержат нативный код, вызываемый из Java через JNI; их реверс — отдельная задача (ARM64)."
```

## Где пригодится

- **CTF Reversing / Mobile:** APK-задачи решаются по схеме «manifest → jadx → проверка».
- **Mobile pentest:** `debuggable`, `exported` и логика в `onCreate` — типовые находки при аудите.
- **Анализ Android-малвари:** стилеры и банкеры тоже APK; понимание структуры — первый шаг.
- **Bug bounty:** экспортированные компоненты и нативные библиотеки — поверхность атаки мобильных приложений.
