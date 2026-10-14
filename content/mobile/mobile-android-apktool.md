---
id: mobile-android-apktool
title: 'apktool: разбор APK, патч smali и пересборка'
category: mobile
parent: mobile-android-re-tooling
difficulty: medium
order: 2
tags: [apktool, smali, rebuild, apksigner, zipalign, patch]
prerequisites: [mobile-static-analysis]
useful_for:
  - 'Патч Android-приложений'
  - 'Реверс и модификация'
  - 'CTF Mobile'
estimated_minutes: 42
summary: 'Полный цикл apktool: декомпиляция APK в smali и ресурсы, правка байткода smali, обратная сборка, подпись через apksigner и установка на устройство.'
lab:
  kind: shell
  title: 'Практика: патч smali-метода'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, Premium.smali]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`Premium.smali` — метод проверки премиума.'
    - 'Найди метод isPremium и пойми, какое значение он возвращает.'
    - 'Рядом с методом лежит флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Вы декомпилировали APK в JADX и увидели проверку лицензии — функция возвращает `false`, если
подписка не оплачена. Хочется заставить её всегда возвращать `true` и посмотреть, что будет.
Но JADX только читает: изменённый Java-код нельзя собрать обратно в APK. Нужен инструмент,
который работает на уровне, из которого APK реально собирается.

## Наш пример: app.apk и его проверка

Мы хотим пропатчить приложение так, чтобы метод `isPremium()` всегда возвращал истину. Сначала
разбираем APK:

```bash
$ apktool d app.apk -o app_out
I: Using Apktool 2.9.3
I: Copying assets and libs...
I: Decoding AndroidManifest.xml...
I: Baksmaling classes.dex...
```

`apktool` — инструмент, который разбирает APK на составляющие: ресурсы, манифест и **smali** —
человекочитаемое представление байткода DEX. Именно smali можно править и собирать обратно.

<!-- lab -->

## Шаг 1: структура результата

```bash
$ ls app_out
AndroidManifest.xml  apktool.yml  assets/  lib/  res/  smali/  smali_classes2/
```

Здесь `smali/` — байткод первого DEX, `smali_classes2/` — второго (приложение было multidex).
`apktool.yml` — служебный файл, который apktool использует при сборке.

## Шаг 2: находим метод для патча

```bash
$ grep -rn "isPremium" app_out/smali* | head
app_out/smali_classes2/com/example/Premium.smali:112: .method public isPremium()Z
```

Файл найден. Открываем его и смотрим реализацию:

```smali
.method public isPremium()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.endmethod
```

`.method ... ()Z` означает «метод без аргументов, возвращает boolean». `const/4 v0, 0x0`
кладёт в регистр `v0` значение 0 (ложь). `return v0` возвращает его.

## Шаг 3: патч smali

Меняем 0 на 1 (истина):

```smali
.method public isPremium()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.endmethod
```

Это вся суть smali-патча: найти нужную инструкцию и заменить константу/вызов. Часто патчат
не константу, а вызов проверки — например, заменяют `invoke-static {p0}, Lcheck;->verify()Z`
на `const/4 v0, 0x1`.

## Шаг 4: обратная сборка

```bash
$ apktool b app_out -o app_patched.apk
I: Building resources...
I: Building apk file...
```

`b` — build, `-o` — имя выходного APK. Результат не подписан и поэтому пока не устанавливается.

## Шаг 5: выравнивание и подпись

Android требует, чтобы APK был выровнен (zipalign) и подписан. Выравнивание ускоряет чтение
ресурсов, подпись подтверждает авторство:

```bash
$ zipalign -p 4 app_patched.apk app_aligned.apk
$ apksigner sign --ks debug.keystore --out app_signed.apk app_aligned.apk
```

`apksigner` — официальный инструмент подписи. Можно использовать тестовый keystore, но тогда
подпись будет отличаться от оригинальной — обновить поверх установленного приложения не
получится, придётся удалить старое.

## Шаг 6: установка и проверка

```bash
$ adb uninstall com.example
$ adb install app_signed.apk
Success
```

Запускаем — проверка пройдена. Мы изменили поведение приложения без доступа к исходникам.

## Шаг 7: типичные ошибки

- `apktool b` ругается на framework — для некоторых ресурсов нужен `apktool if framework-res.apk`.
- Ошибки 9-patch и ресурсов лечатся флагом `--use-aapt2` или обновлением apktool.
- `INSTALL_FAILED_UPDATE_INCOMPATIBLE` — подпись не совпала, нужно удалить оригинал.
- Если приложение проверяет подпись в рантайме, патч smali может не помочь — тогда нужна
  Frida-обёртка, возвращающая оригинальную подпись.

## Что мы теперь знаем

- apktool разбирает APK в smali и ресурсы и собирает обратно.
- Патч smali — замена инструкции/константы.
- Собранный APK надо выровнять и подписать.
- Смена подписи мешает обновлению поверх оригинала.
- Рантайм-проверки подписи требуют динамических методов.

## Квиз

Проверь себя.

```quiz
- question: Что такое smali?
  options:
    - Формат картинок
    - Человекочитаемое представление байткода DEX
    - Язык ресурсов
    - Протокол сети
  answer: 1
  explanation: smali это текстовый вид байткода Android.
- question: Что делает команда apktool b?
  options:
    - Разбирает APK
    - Собирает APK из распакованной папки
    - Ставит root
    - Подписывает APK
  answer: 1
  explanation: b это build.
- question: Зачем zipalign и apksigner?
  options:
    - Для скорости сети
    - Выровнять и подписать собранный APK
    - Для рекламы
    - Для root
  answer: 1
  explanation: Android требует выравнивания и подписи.
- question: Почему нельзя обновить приложение поверх оригинала после патча?
  options:
    - APK больше
    - Подпись отличается от оригинальной
    - Нет интернета
    - Нужен root
  answer: 1
  explanation: Android не даёт обновлять APK с другой подписью.
```

## Куда дальше

Мы научились патчить smali вручную. Дальше — как автоматизировать первичный разбор десятков
приложений через MobSF и его API, чтобы не делать одно и то же руками.

## Где пригодится

- Модификация Android-приложений без исходников.
- Обход простых проверок лицензии и оплаты.
- CTF Mobile и обучение реверсу.
