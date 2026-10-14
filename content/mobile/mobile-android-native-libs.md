---
id: mobile-android-native-libs
title: 'Нативные библиотеки: загрузка, символы и инъекции'
category: mobile
parent: mobile-android-re-advanced
difficulty: hard
order: 4
tags: [native, so, jni, injection, loadlibrary, dlopen]
prerequisites: [mobile-android-native]
useful_for:
  - 'Реверс Android native'
  - 'Пентест мобильных приложений'
  - 'CTF Mobile'
estimated_minutes: 42
summary: 'Как Android загружает .so-библиотеки, как устроен JNI-мост, как читать символы через readelf/nm и как выполняются инъекции кода (dlopen, подмена библиотеки, LD_PRELOAD).'
lab:
  kind: shell
  title: 'Практика: символы нативной библиотеки'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, nm_output.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`nm_output.txt` — вывод nm по libfoo.so.'
    - 'Найди экспортированную JNI-функцию.'
    - 'Рядом с ней — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

В APK лежат нативные библиотеки `lib/arm64-v8a/*.so`. Кто и когда их загружает? Как Java-код
вызывает C-функцию? И — главное для атакующего — можно ли подсунуть приложению свою библиотеку
вместо настоящей? Разберём жизненный цикл нативного кода.

## Наш пример: libfoo.so из app.apk

Смотрим, что за библиотека:

```bash
$ readelf -h libfoo.so | grep -E 'Type|Machine'
  Type: DYN (Shared object file)
  Machine: AArch64
```

`readelf` — инструмент для разбора ELF-файлов (формат исполняемых файлов Linux/Android). `DYN`
означает, что это разделяемая библиотека (shared object), а не исполняемый файл.

## Шаг 1: как Java загружает библиотеку

В Java-коде приложения:

```java
static { System.loadLibrary("foo"); }
```

`System.loadLibrary("foo")` заставляет систему найти `libfoo.so` и загрузить её в процесс.
Дальше Java может вызывать нативные методы, объявленные как `native`.

## Шаг 2: JNI-мост

Связь Java и C — через JNI. Java объявляет метод:

```java
public static native int check(String s);
```

А в C есть функция с именем, закодированным из класса и метода:

```c
JNIEXPORT jint JNICALL Java_com_example_NativeChecker_check(JNIEnv *env, jclass c, jstring s)
```

`JNIEXPORT`/`JNICALL` — макросы, `JNIEnv*` — таблица функций для работы с Java. По имени
`Java_...` система сопоставляет вызов.

## Шаг 3: чтение символов

```bash
$ nm -D libfoo.so | grep -i check
0000000000012a40 T Java_com_example_NativeChecker_check
$ readelf -s libfoo.so | grep FUNC | head
```

`nm -D` показывает динамические символы, `T` — определённый (экспортированный) символ. Так
находят точки входа, которые можно хукать.

## Шаг 4: инъекция через dlopen

`dlopen` — функция, которая загружает библиотеку в уже работающий процесс. Если приложение
уязвимо (например, загружает `.so` из внешнего каталога), можно подсунуть свою. Более
контролируемый путь — Frida:

```javascript
var dlopen = Module.findExportByName(null, 'dlopen');
```

## Шаг 5: подмена библиотеки

Самый простой приём на rooted-устройстве — заменить `libfoo.so` в каталоге приложения своей
версией (с той же архитектурой). Тогда при следующем запуске загрузится наш код. Это требует
доступа к каталогу данных приложения.

## Шаг 6: LD_PRELOAD на Android

На Linux `LD_PRELOAD` подставляет библиотеку до всех остальных. На Android он работает только
для процессов, запущенных с соответствующим окружением (обычно через `setprop wrap.<pkg>`),
поэтому чаще используют Frida или патч загрузчика.

## Шаг 7: защита

Разработчики защищаются: проверяют хеши `.so`, подписи, целостность загрузки, используют
anti-hook. Поэтому инъекция — это гонка: чем сложнее проверка, тем больше усилий на обход.

## Что мы теперь знаем

- `.so` — разделяемая библиотека, загружается через System.loadLibrary.
- JNI связывает Java-метод с C-функцией по имени.
- Символы читают через nm/readelf.
- Инъекция возможна через dlopen/подмену/Frida.
- Защита — проверки целостности и anti-hook.

## Квиз

Проверь себя.

```quiz
- question: Что делает System.loadLibrary?
  options:
    - Удаляет APK
    - Загружает нативную .so-библиотеку
    - Шифрует сеть
    - Ставит root
  answer: 1
  explanation: Она подключает shared object в процесс.
- question: По какому имени сопоставляется JNI-функция?
  options:
    - Случайному
    - Java_<пакет>_<класс>_<метод>
    - main
    - init
  answer: 1
  explanation: Имя кодирует класс и метод.
- question: Что показывает nm -D?
  options:
    - Ресурсы
    - Динамические символы библиотеки
    - Сеть
    - Разрешения
  answer: 1
  explanation: Так находят экспортируемые функции.
- question: Почему LD_PRELOAD на Android ограничен?
  options:
    - Он платный
    - Работает только для процессов с заданным окружением
    - Нет смысла
    - Удаляет код
  answer: 1
  explanation: Обычно используют Frida или патч.
```

## Куда дальше

Мы разобрали нативный слой. Но самая частая защита в приложениях — не native, а шифрование
строк в DEX. Дальше — как её снимать.

## Где пригодится

- Реверс и модификация нативного кода.
- Понимание JNI-мостов.
- CTF по мобильному реверсу.
