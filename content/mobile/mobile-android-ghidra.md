---
id: mobile-android-ghidra
title: 'Ghidra для Android native: JNI и headless-скрипты'
category: mobile
parent: mobile-android-re-tooling
difficulty: hard
order: 4
tags: [ghidra, native, jni, headless, so, decompile]
prerequisites: [mobile-android-native]
useful_for:
  - 'Реверс Android native'
  - 'Пентест мобильных приложений'
  - 'CTF Mobile'
estimated_minutes: 45
summary: 'Анализ нативной библиотеки Android в Ghidra: импорт .so, распознавание JNI-функций, декомпиляция проверок, headless-режим и автоматические скрипты.'
lab:
  kind: shell
  title: 'Практика: JNI-проверка из Ghidra'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, ghidra_decomp.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`ghidra_decomp.txt` — декомпилированная JNI-функция.'
    - 'Пойми, какую строку сравнивает проверка.'
    - 'В комментарии к проверке — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение проверяет что-то в нативном коде: в APK лежит `lib/arm64-v8a/libcheck.so`. JADX его
не разбирает, `strings` показывает только обрывки. Логика «зашита» в машинный код. Как её
прочитать? Нужен дизассемблер, понимающий ARM64.

## Наш пример: libcheck.so

Начинаем с базового осмотра файла:

```bash
$ file libcheck.so
libcheck.so: ELF 64-bit LSB shared object, ARM aarch64, dynamically linked
$ nm -D libcheck.so | grep Java
0000000000012a40 T Java_com_example_NativeChecker_check
```

`nm -D` показывает динамические символы. Символ с префиксом `Java_` — это **JNI**-функция:
мост между Java-кодом приложения и нативной библиотекой. JNI (Java Native Interface) — механизм,
через который Java вызывает нативный код. Имя `Java_com_example_NativeChecker_check`
кодирует пакет, класс и метод, который её вызывает.

## Шаг 1: импорт в Ghidra

Ghidra — бесплатный дизассемблер/декомпилятор от NSA. Создаём проект, импортируем `.so`,
соглашаемся на автоанализ. Ghidra определит архитектуру (AArch64) и найдёт функции.

## Шаг 2: находим JNI-функции

В Ghidra открываем Symbol Tree, ищем `Java_com_example_NativeChecker_check`. Именно эта функция
вызывается из Java. Декомпилированный вид (C-подобный псевдокод):

```c
undefined8 Java_com_example_NativeChecker_check(JNIEnv *env, jobject thiz, jstring input) {
  char *s = (*env)->GetStringUTFChars(env, input, 0);
  int ok = strcmp(s, "nto-example");
  return ok == 0;
}
```

Это упрощённый пример, но идея ясна: Ghidra восстановила логику — сравнивается строка. Реальные
проверки сложнее (хеши, шифрование), но подход тот же.

## Шаг 3: понимаем JNI-аргументы

Первый аргумент JNI-функции — `JNIEnv*` (таблица функций для работы с Java-объектами), второй —
`jobject`/`jclass` (сам объект), дальше идут аргументы Java-метода. В Ghidra типы этих
параметров часто «сырые», их полезно переопределить, чтобы декомпиляция читалась лучше.

## Шаг 4: строки и константы

Ghidra показывает ссылки на строки. Если строка «спрятана» (зашифрована), в декомпиляции
увидим вызов функции расшифровки — тогда переходим к ней и разбираем алгоритм. Полезно
использовать `Search > For Strings` и смотреть, кто на них ссылается (xref).

## Шаг 5: headless-режим

Ручной клик по каждой функции не масштабируется. Ghidra умеет работать без GUI:

```bash
$ analyzeHeadless /tmp/proj proj -import libcheck.so -postScript FindCheck.java
```

`analyzeHeadless` — консольный запуск анализа. `-postScript` выполняет скрипт после импорта.
Скрипт на Python (Ghidra API) может, например, напечатать все функции, вызывающие `strcmp`:

```python
# FindCheck.py (Ghidra)
for f in currentProgram.getFunctionManager().getFunctions(True):
    if 'check' in f.getName().lower():
        print(f.getName(), f.getEntryPoint())
```

## Шаг 6: подтверждение через Frida

Статика даёт гипотезу, динамика — подтверждение. Найденный адрес проверки хукаем Frida:

```javascript
var base = Module.findBaseAddress('libcheck.so');
Interceptor.attach(base.add(0x12a40), {
  onLeave: function (retval) { retval.replace(1); }
});
```

Так проверка всегда возвращает «успех» — мы подтвердили, что именно эта функция решает исход.

## Шаг 7: где Ghidra не идеальна

Декомпилятор восстанавливает логику приблизительно: типы могут быть неверны, оптимизации
запутывают поток. Для обфусцированного кода (OLLVM) читаемость падает — там помогают трассировка
и эмуляция.

## Что мы теперь знаем

- Нативный код Android лежит в `lib/*.so` и требует дизассемблера.
- JNI-функции видны по префиксу `Java_` в символах.
- Ghidra декомпилирует ARM64 в читаемый псевдокод.
- `analyzeHeadless` + скрипты автоматизируют анализ.
- Гипотезу из Ghidra подтверждают Frida-хуком.

## Квиз

Проверь себя.

```quiz
- question: По какому префиксу находят JNI-функции в символах?
  options:
    - native_
    - Java_
    - so_
    - jni_
  answer: 1
  explanation: Имена JNI-функций начинаются с Java_.
- question: Что делает analyzeHeadless?
  options:
    - Запускает GUI
    - Запускает анализ Ghidra без графического интерфейса
    - Подписывает APK
    - Ставит root
  answer: 1
  explanation: Headless это консольный режим.
- question: Чем подтверждают гипотезу из Ghidra?
  options:
    - Пересборкой APK
    - Frida-хуком по адресу функции
    - Перезагрузкой
    - Скриншотом
  answer: 1
  explanation: Динамика подтверждает статику.
- question: Почему JADX не разбирает libcheck.so?
  options:
    - Он платный
    - Он работает с DEX/Java, а не с машинным кодом
    - Нет библиотеки
    - Нет root
  answer: 1
  explanation: Для нативного кода нужен дизассемблер.
```

## Куда дальше

Ghidra помогает читать код глазами, но для проверок вроде «введи правильный пароль» есть
более мощный приём — символьное исполнение, которое находит вход автоматически. Дальше — angr.

## Где пригодится

- Реверс нативных библиотек Android.
- Анализ JNI-мостов между Java и C.
- CTF по мобильному реверсу.
