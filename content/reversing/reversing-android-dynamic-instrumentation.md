---
id: reversing-android-dynamic-instrumentation
title: "Динамическая инструментация Android: Frida, Xposed, Zygisk"
category: reversing
parent: reversing-mod-android
difficulty: hard
order: 4
tags: [reversing, android, frida, xposed, zygisk, instrumentation, hooking]
prerequisites: [reversing-android-apk]
useful_for:
  - "Пентест мобильных приложений"
  - "Анализ мобильной малвари"
  - "Обход защит в runtime"
estimated_minutes: 55
summary: "Инструментация Android в runtime: Frida (JS-хуки), Xposed (Java-хуки), Zygisk (нативный слой); как выбрать инструмент и не попасться детекту."
lab:
  kind: shell
  title: "Практика: Frida-хук в действии"
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md, hook.js]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Frida-скрипт — это JavaScript, который перехватывает функции через Interceptor.attach."
    - "Скрипт печатает аргументы перехваченной функции."
    - "Прочитай `hook.js` и найди строку-артефакт в его выводе (в файле hook.js есть комментарий-пример)."
    - "`strings -n 5 hook.js | grep nto > found.txt`, затем `check`."
---

## Вопрос, с которого всё начинается

Приложение шифрует трафик и проверяет целостность в runtime. Статический патч smali ломает подпись. Нужен способ менять поведение приложения **на лету**, не трогая файл. Как это делается на Android?

## Наш пример

Возьмём `hook.js` — Frida-скрипт, который перехватывает функцию шифрования. Посмотрим на его структуру:

```javascript
Java.perform(function () {
  var Cipher = Java.use('com.example.app.Crypto');
  Cipher.encrypt.implementation = function (data) {
    console.log('encrypt called with:', data);
    return this.encrypt(data);   // пропускаем дальше
  };
});
```

Всего несколько строк — но это уже полноценный хук. Разберём, как он работает и какие есть альтернативы.

## Шаг 1: три инструмента и три уровня

Инструментация Android бывает на трёх уровнях. **Frida** — динамическая, работает через инъекцию агента в процесс; скрипты на JavaScript, можно перехватывать и Java-методы (`Java.use`), и нативные функции (`Interceptor.attach`). **Xposed** — фреймворк, который модифицирует систему на этапе загрузки и позволяет Java-хуки «навсегда», без повторного подключения. **Zygisk** — часть Magisk, даёт нативные хуки и инъекцию на раннем этапе запуска процесса.

Выбор зависит от задачи: для быстрого исследования — Frida; для постоянной модификации — Xposed; для обхода ранних нативных проверок — Zygisk.

## Шаг 2: Frida — как подключиться и что перехватить

Frida состоит из сервера (запущенного на устройстве) и клиента (на компьютере). Подключение:

```
$ frida-ps -U                 # список процессов
$ frida -U -f com.example.app -l hook.js   # запустить и внедрить скрипт
```

Скрипт `hook.js` перехватывает метод `encrypt` класса `Crypto`. Ключевые конструкции: `Java.perform` (выполнить в контексте Java-машины), `Java.use` (получить класс), `.implementation =` (подменить тело). Внутри можно логировать аргументы, менять возвращаемое значение, вызывать оригинал.

## Шаг 3: перехват нативного слоя

Если логика в `.so`, используют `Interceptor`:

```javascript
Interceptor.attach(Module.getExportByName('libcrypto.so', 'AES_encrypt'), {
  onEnter(args) { console.log('in:', args[1].readByteArray(16)) },
  onLeave(retval) { console.log('out:', retval) }
})
```

`onEnter` срабатывает до вызова, `onLeave` — после. Это позволяет видеть ключи, plaintext и ciphertext в момент работы. Для проверок подписи перехватывают `open`/`access`/`strcmp`, а для сетевых — `SSL_write`/`SSL_read`.

## Шаг 4: Xposed и Zygisk — когда Frida не подходит

Frida оставляет следы (порт 27042, библиотека `frida-agent` в `/proc/self/maps`), и приложения, знающие об этом, её детектируют. Тогда используют Xposed: модуль регистрируется системой, и Java-хуки применяются без внешнего агента. Пример Xposed-хука:

```java
XposedHelpers.findAndHookMethod("com.example.app.Crypto", lpparam.classLoader,
    "encrypt", String.class, new XC_MethodHook() {
      protected void beforeHookedMethod(MethodHookParam p) { ... }
    });
```

Zygisk идёт ещё ниже: нативные хуки применяются к процессу zygote при его запуске, поэтому проверки, которые выполняются очень рано (до загрузки Java), уже можно обойти.

## Шаг 5: борьба с детектом инструментации

Приложение может проверять: список библиотек в `/proc/self/maps`, открытые порты, наличие `frida-server`, `ptrace`-статус. Обходы:

- **Скрыть Frida**: использовать `frida-gadget` вместо сервера, переименовать библиотеку, использовать Magisk DenyList.
- **Перехватить сам детект**: хукнуть функцию, которая ищет `frida` в maps, и вернуть «чисто».
- **Отложенный детект**: если приложение проверяет через время, хук должен стоять постоянно.

Общий принцип тот же, что и в детекте root: найди индикаторы, найди код, подмени результат.

## Шаг 6: находим артефакт практики

В `hook.js` есть пример вывода — в нём и лежит артефакт. Прочитаем:

```
$ strings -n 5 hook.js | grep nto
nto{fr1d4_h00k_j4v4_n4t1v3}
```

## Что мы теперь знаем

- Инструментация бывает на трёх уровнях: Frida (динамика), Xposed (Java-хуки), Zygisk (нативный слой).
- Frida: `Java.perform` + `Java.use` для Java, `Interceptor.attach` для нативных функций.
- `onEnter`/`onLeave` дают аргументы и возврат; можно видеть ключи и plaintext.
- Frida детектируется по порту/библиотеке; Xposed и Zygisk обходят ранние проверки.
- Обход детекта — та же схема: найти индикатор, найти код, подменить результат.

## Квиз

Проверь себя.

```quiz
- question: "Чем Frida перехватывает нативные функции?"
  options:
    - "Interceptor.attach с onEnter/onLeave"
    - "Java.use"
    - "smali-патчем"
    - "Пересборкой APK"
  answer: 0
- question: "Почему приложения иногда детектируют Frida?"
  options:
    - "Она оставляет следы: порт 27042 и библиотеку frida-agent в памяти"
    - "Frida меняет файл APK"
    - "Frida требует root всегда"
    - "Frida замедляет процессор"
  answer: 0
- question: "Для чего используют Zygisk вместо Frida?"
  options:
    - "Для нативных хуков на раннем этапе запуска процесса (zygote)"
    - "Для рисования интерфейса"
    - "Для скачивания APK"
    - "Для подписи приложения"
  answer: 0
- question: "Что делает Java.use в Frida?"
  options:
    - "Получает ссылку на Java-класс для хука его методов"
    - "Компилирует Java"
    - "Удаляет класс"
    - "Запускает эмулятор"
  answer: 0
```

## Куда дальше

Дальше — восстановление символов нативных `.so` и JNI-регистрация: как найти обработчики, когда имён нет. Пока главное запомни: **инструментация — это перехват в runtime; выбирай уровень под задачу и помни про детект**.

## Где пригодится

- **Пентест мобильных приложений:** увидеть ключи, обойти проверки, изменить логику.
- **Анализ малвари:** вскрыть шифрование и C2-обмен.
- **Разработка:** отладка без исходников.
