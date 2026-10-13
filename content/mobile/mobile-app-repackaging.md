---
id: mobile-app-repackaging
title: "Repackaging и клонирование приложений: патч, подпись, инъекция"
category: mobile
parent: mobile-android-root
difficulty: medium
order: 2
tags: [repackaging, apktool, apksigner, cloning, smali, patch, android, tamper]
prerequisites: [mobile-android-anatomy, mobile-static-analysis]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ малвари (обфускация/клоны)"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Перепаковка APK: декомпиляция, патч smali, добавление кода, повторная подпись и установка; клонирование, dual-app и защита от подмены."
lab:
  kind: shell
  title: "Практика: заметить следы перепаковки"
  toolset: [core, unzip]
  workdir: /home/student/task
  files: [task.md, app.apk]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Это ZIP-архив. Посмотри состав: `unzip -l app.apk`."
    - "Подозрительный файл в assets. Прочитай его: `unzip -p app.apk assets/backdoor.dat`."
    - "Токен внутри — base64. Раскодируй и запиши: `unzip -p app.apk assets/backdoor.dat | grep token | cut -d= -f2 | base64 -d > found.txt`."
---

## Вопрос, с которого всё начинается

Ты декомпилировал APK, нашёл проверку пароля в коде и хочешь её обойти. Но просто отредактировать `classes.dex` в архиве нельзя: при установке Android проверяет цифровую подпись, и любое изменение её ломает. Как изменить код приложения так, чтобы телефон его всё равно установил?

Ответ — **перепаковка**: разобрать APK на исходники, поправить код, собрать обратно и заново подписать своим ключом.

## Наш пример: uncrack1.apk

Возьмём учебное приложение `uncrack1.apk` (OWASP UnCrackable Level 1). В прошлых уроках мы декомпилировали его через `jadx` и увидели проверку секрета в `MainActivity`. Сейчас пройдём полный цикл перепаковки на нём.

Сначала посмотрим, из чего состоит APK:

```
$ unzip -l uncrack1.apk
  Length      Name
     1648   AndroidManifest.xml
     1319   META-INF/CERT.RSA
     5528   classes.dex
     1260   res/layout/activity_main.xml
     2748   resources.arsc
```

`META-INF/CERT.RSA` — это подпись. Она покрывает все файлы архива. Изменим `classes.dex` — и подпись перестанет совпадать, установка упадёт с `INSTALL_PARSE_FAILED_NO_CERTIFICATES`.

## Шаг 1: разбираем APK на smali

`jadx` умеет декомпилировать в Java, но собрать Java обратно в APK нельзя. Для сборки нужен **smali** — текстовое представление байткода DEX. Разбираем APK утилитой `apktool`:

```
$ java -jar apktool.jar d -f -o uncrack1_src uncrack1.apk
I: Using Apktool 2.9.3
I: Loading resource table...
I: Decoding AndroidManifest.xml...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
```

В каталоге `uncrack1_src/` появляются `smali/` (код), `res/` (ресурсы), `AndroidManifest.xml` (уже текстовый). Посмотрим на `apktool.yml` — это манифест сборки, где зафиксированы версии:

```
$ head -5 uncrack1_src/apktool.yml
version: 2.9.3
apkFileName: uncrack1.apk
```

## Шаг 2: находим, что править

Код проверки секрета лежит в smali. Откроем класс проверки:

```
$ find uncrack1_src/smali -name 'a.smali' | head -1
uncrack1_src/smali/sg/vantagepoint/a/a.smali
```

Внутри — метод `a(String)`, который возвращает `true`/`false`. Типовой обход — заставить его всегда возвращать `true`:

```
.method public static a(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1        # было: вычисление AES-секрета
    return v0
.end method
```

`const/4 v0, 0x1` кладёт в регистр `v0` значение `1` (истина), а `return v0` возвращает его. Это классический «патч логики» — мы не разбираем шифрование, а просто меняем вердикт проверки.

## Шаг 3: собираем обратно

Собираем модифицированный APK:

```
$ java -jar apktool.jar b -o uncrack1_repacked.apk uncrack1_src
I: Using Apktool 2.9.3
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: uncrack1_repacked.apk
```

Получился **неподписанный** APK. Установить его пока нельзя — Android требует подпись.

## Шаг 4: подписываем своим ключом

Подпись бывает двух видов: v1 (JAR-подпись, `META-INF/`) и v2/v3 (блочная, в самом APK). Начнём с простого — v1 через `jarsigner`. Сначала создадим ключ:

```
$ keytool -genkeypair -keystore demo.keystore -alias demo \
    -storepass android -keypass android -keyalg RSA -keysize 2048 \
    -validity 10000 -dname "CN=Demo, O=Test, C=NL"
Generating 2,048 bit RSA key pair and self-signed certificate
```

`-dname` задаёт поля сертификата: `CN` (common name), `O` (организация), `C` (страна). Теперь подписываем:

```
$ jarsigner -keystore demo.keystore -storepass android -keypass android \
    -sigalg SHA256withRSA -digestalg SHA-256 uncrack1_repacked.apk demo
```

Проверяем, что подпись встала:

```
$ keytool -printcert -jarfile uncrack1_repacked.apk | head -4
Owner: CN=Demo, O=Test, C=NL
Issuer: CN=Demo, O=Test, C=NL
Signature algorithm name: SHA256withRSA
```

Сертификат самоподписанный — Android это допускает для sideload (установка не из магазина). Для v2/v3-подписи используется `apksigner` (из build-tools) и `zipalign` для выравнивания.

## Шаг 5: что ломается и как это замечают

Перепаковка меняет подпись приложения. Сравним сертификаты оригинала и копии:

```
$ keytool -printcert -jarfile uncrack1.apk | grep SHA256
    SHA256: CB:E6:8A:B8:...:5B:1D
$ keytool -printcert -jarfile uncrack1_repacked.apk | grep SHA256
    SHA256: 83:B4:37:DE:...:EC:B9
```

Отпечатки разные. Приложение, которое «прибито» к оригинальному сертификату (проверяет свою подпись через `PackageManager.getPackageInfo(...).signatures`), заметит подмену и откажется работать. Это называется **tamper detection** — защита от изменения кода. Обход — либо патч самой проверки в smali, либо динамический хук через Frida (см. `mobile-integrity`).

## Шаг 6: перепаковка для других задач

Перепаковка нужна не только для патча логики. Типичные сценарии:

- **Инъекция Frida-gadget** — добавить `libfrida-gadget.so` в `lib/` и строку `System.loadLibrary("frida-gadget")` в smali, чтобы получить инструментирование без root.
- **Снятие pinning** — заменить `network_security_config.xml`, чтобы доверять пользовательскому CA.
- **Клонирование** — изменить имя пакета (`package="..."` в манифесте) и подпись, чтобы рядом с оригиналом встала вторая копия.

Клонирование — самый частый сценарий в bug bounty: ставим копию с другим package name и своим сертификатом, чтобы обойти проверки «приложение уже установлено».

## Шаг 7: если сборка падает

`apktool b` иногда не собирает APK из-за «хитрых» ресурсов. Признаки: ошибки `aapt` при сборке `resources.arsc`, «unknown file». Что делать:

- проверить версию `apktool` (старые версии ломаются на новых APK);
- использовать флаг `--use-aapt2` для сборки ресурсов через aapt2;
- при экзотических ресурсах — патчить `classes.dex` напрямую инструментами вроде `dexlib2`, не трогая ресурсы.

Помни: перепаковка меняет **только то, что ты поправил**. Всё остальное поведение приложения сохраняется, поэтому патч нужно тестировать — легко случайно сломать подпись ресурсов.

## Шаг 8: свой ключ подписи по шагам

Перепакованный APK нельзя установить без собственной подписи. Создаём keystore:

```
$ keytool -genkeypair -v -keystore lab.keystore -alias lab -keyalg RSA -keysize 2048 -validity 365 -storepass changeit -keypass changeit -dname "CN=Lab, O=Pentest"
Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 365 days
	for: CN=Lab, O=Pentest
[Storing lab.keystore]
```

Проверяем, что ключ на месте:

```
$ keytool -list -keystore lab.keystore -storepass changeit | head -12
Keystore type: PKCS12
...
Alias name: lab
Entry type: PrivateKeyEntry
```

Порядок важен: сначала `zipalign -p 4 app.apk app-aligned.apk`, только потом `apksigner sign --ks lab.keystore app-aligned.apk`. Если выровнять после подписи, подпись инвалидируется. И учитывай схему подписи: на Android 11+ проверяется v2+, одной v1 уже недостаточно.

## Что мы теперь знаем

- APK подписан; изменение кода ломает подпись, поэтому нужна перепаковка и повторная подпись.
- `apktool d` разбирает APK в smali, `apktool b` собирает обратно.
- smali — это текстовая форма байткода DEX; патч логики — это правка smali-метода.
- Свой ключ делается `keytool`, подпись — `jarsigner` (v1) или `apksigner` (v2/v3).
- Перепаковка меняет отпечаток сертификата — это ловят tamper-detection.
- Кроме патча логики, перепаковка нужна для gadget-инъекции, снятия pinning и клонирования.

## Квиз

Проверь себя.

```quiz
- question: Почему нельзя просто изменить `classes.dex` внутри APK и установить его?
  options:
    - "Android не читает classes.dex"
    - "Изменится содержимое, и цифровая подпись перестанет совпадать"
    - "APK станет слишком большим"
    - "Сломается манифест"
  answer: 1
  explanation: "Подпись покрывает файлы архива; любое изменение делает её недействительной."
- question: Что такое smali?
  options:
    - "Язык программирования Android"
    - "Текстовое представление байткода DEX"
    - "Формат ресурсов"
    - "Инструмент для подписи"
  answer: 1
  explanation: "smali — человекочитаемая форма байткода; apktool собирает его обратно в DEX."
- question: Какая команда собирает APK обратно из распакованного каталога?
  options:
    - "apktool d"
    - "apktool b"
    - "jadx"
    - "zipalign"
  answer: 1
  explanation: "d — decode, b — build."
- question: Что делает патч `const/4 v0, 0x1` перед `return v0`?
  options:
    - "Вызывает метод"
    - "Заставляет метод вернуть истину"
    - "Удаляет метод"
    - "Шифрует строку"
  answer: 1
  explanation: "В регистр кладётся 1, и метод всегда возвращает true."
- question: Как приложение может заметить перепаковку?
  options:
    - "По размеру APK"
    - "Сравнив отпечаток своего сертификата с ожидаемым"
    - "По имени файла"
    - "Оно не может"
  answer: 1
  explanation: "Это tamper detection: проверка собственной подписи через PackageManager."
```

## Куда дальше

Перепаковка даёт изменённый APK, но для его установки и особенно для обхода защиты часто нужен root — например, чтобы спрятать Magisk или встроить системный CA. В следующем уроке мы разберём, как легально получить root на своём устройстве и какие слои защиты при этом ломаются. А пока главное запомни: перепаковка — это разобрать → поправить smali → собрать → подписать своим ключом.

## Где пригодится

- **Пентест:** обход клиентских проверок (логин, pinning, integrity) без root.
- **Bug bounty:** клонирование приложения и инъекция инструментов для анализа.
- **Анализ малвари:** перепаковка образца в изолированной среде для наблюдения.
- **CTF:** Mobile-задачи, где нужно пропатчить проверку флага.
