---
id: mobile-native-reversing
title: "Модуль: Реверс нативного кода и кросс-платформы"
category: mobile
parent: mobile-reverse-native
difficulty: hard
order: 4
tags: [android, native, so, arm64, jni, dart, flutter, react-native, hermes, reversing]
prerequisites: [mobile-static-analysis]
useful_for:
  - "Реверс-инжиниринг мобильных приложений"
  - "Пентест мобильных приложений"
  - "CTF Mobile"
estimated_minutes: 25
summary: "Навигационный модуль: углублённый реверс нативного кода (.so/ARM64), Dart/Flutter и React Native/Hermes-бандлов."
---
## Почему нативный реверс — отдельная ветвь

Современные мобильные приложения прячут критичную логику в нативном коде (C/C++) или в кросс-платформенных рантаймах (Flutter/Dart, React Native/Hermes). Java-декомпиляция (jadx) тут бесполезна: вы видите только тонкую обёртку `System.loadLibrary`/JNI-мосты, а вся логика — в `lib*.so`, в снапшоте Dart или в Hermes-байткоде. Эта ветвь — про то, как реверсить эти слои.

Базовый урок `mobile-reverse-native` даёт введение; здесь мы углубляемся в три конкретных стека: чистый нативный `.so` (ARM64/JNI), Flutter/Dart и React Native/Hermes. Каждый требует своего инструментария и подхода.

## Карта ветви

| Урок | Стек | Инструменты |
|------|------|-------------|
| `mobile-native-so-deep` | C/C++ .so, JNI | Ghidra, IDA, r2, Frida |
| `mobile-dart-reversing` | Flutter/Dart | blutter, reFlutter, jadx |
| `mobile-react-native-reversing` | React Native/Hermes | hermes-dec, jadx, frida |

Смежные: `mobile-android-native` (введение в JNI), `mobile-flutter` (обзор), `mobile-crossplatform` (Cordova/Xamarin).

## Нативный код: почему это сложно

- **Архитектуры**: arm64-v8a, armeabi-v7a, x86_64 — нужно реверсить нужную.
- **Символы удалены**: strip-бинари без имён функций.
- **JNI**: точка входа — `Java_<pkg>_<Class>_<method>` (в release — `RegisterNatives`, имена динамические).
- **Оптимизация**: O2/O3, инлайнинг, vectorization усложняют чтение.
- **Обфускация**: OLLVM (control-flow flattening), строковое шифрование, anti-debug.

Ключ к успеху — комбинация статики (Ghidra/IDA) и динамики (Frida на JNI/нативных функциях). Часто быстрее хукать, чем читать.

## Flutter/Dart

Flutter компилирует Dart в **AOT-снапшот** внутри `libapp.so`. Это не C++: нужны специфичные инструменты (`blutter`, `reFlutter`, `Doldrums`). `blutter` восстанавливает имена классов/функций и генерирует псевдо-C, который можно импортировать в IDA. `reFlutter` патчит снапшот для инъекции/дампов. Понимание пула объектов и хендлов Dart критично.

## React Native/Hermes

React Native с Hermes компилирует JS в **Hermes bytecode** (`index.android.bundle` — HBC). Инструменты: `hermes-dec`, `hbctool`, `hermes` CLI. Для JS-движка (не Hermes) бандл читается напрямую. Логика и API-ключи часто лежат в бандле — ищите строки и вызовы `fetch`/`axios`.

## Что дальше / решение

Определите стек: если в APK есть `libapp.so` и `libflutter.so` — Flutter (`mobile-dart-reversing`); если `index.android.bundle`/`libhermes.so` — RN (`mobile-react-native-reversing`); если `lib*.so` с JNI — нативный (`mobile-native-so-deep`). Решение по умолчанию: Ghidra (бесплатно) + Frida для динамики.

## Справочная таблица

| Признак | Стек |
|---------|------|
| libapp.so + libflutter.so | Flutter/Dart |
| index.android.bundle (HBC) | React Native/Hermes |
| lib*.so + System.loadLibrary | нативный C/C++ |
| assets/index.android.bundle (JS) | React Native (JSC) |

| Инструмент | Роль |
|-----------|------|
| Ghidra/IDA | статический реверс .so |
| blutter | Dart-снапшот |
| hermes-dec | Hermes bytecode |
| Frida | динамика/хуки |

## Квиз

```quiz
- question: "Какой файл указывает на Flutter-приложение?"
  options:
    - "libapp.so и libflutter.so"
    - "index.android.bundle"
    - "classes.dex"
    - "resources.arsc"
  answer: 0
- question: "Чем компилируется JS в React Native с Hermes?"
  options:
    - "В Hermes bytecode (HBC)"
    - "В DEX"
    - "В ARM64"
    - "В Dart"
  answer: 0
- question: "Какой инструмент восстанавливает Dart-снапшот?"
  options:
    - "blutter"
    - "jadx"
    - "apktool"
    - "nmap"
  answer: 0
- question: "Почему jadx бесполезен для нативной логики?"
  options:
    - "Логика в .so, а не в Java/DEX"
    - "jadx не открывает APK"
    - "Нужен root"
    - "Он только для iOS"
  answer: 0
- question: "Что такое RegisterNatives в контексте JNI?"
  options:
    - "Динамическая регистрация нативных методов"
    - "Список портов"
    - "Разрешение приложения"
    - "Сертификат"
  answer: 0
```

## Где пригодится

- **Реверс:** понимание современных мобильных стеков.
- **Пентест:** обход нативных проверок.
- **Bug bounty:** поиск секретов в бандлах/снапшотах.
- **CTF:** Mobile-задачи с нативным кодом.
