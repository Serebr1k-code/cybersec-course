---
id: mobile-dynamic-frida
title: "Динамический анализ и Frida: хукинг, Objection, рантайм-дамп"
category: mobile
parent: mobile-android-analysis
difficulty: medium
order: 2
tags: [android, dynamic-analysis, frida, objection, hooking, runtime]
prerequisites: [mobile-android-anatomy, mobile-static-analysis]
useful_for:
  - "CTF Mobile (обход проверок в рантайме)"
  - "Bug bounty (перехват и модификация трафика)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как запускать приложение под управлением Frida и Objection: установка сервера, списание флагов, перехват методов, дамп аргументов и возвращаемых значений, обход клиентских проверок в рантайме."
---
## Зачем нужен динамический анализ

Статический анализ показывает, что код *может* делать; динамический — что он делает *на самом деле*. Обфускация, шифрование строк, рантайм-генерация кода и проверки, зависящие от окружения, часто делают статику бесполезной. Динамический анализ запускает приложение и позволяет вмешиваться в его выполнение: смотреть значения переменных, подменять результаты функций, вызывать методы напрямую. Главный инструмент — Frida. Цель модуля — освоить хукинг, работу с Objection и рантайм-дамп данных.

## Frida: основы

Frida внедряет в процесс JavaScript-агента, который может перехватывать вызовы. Схема: на устройстве запущен `frida-server`, на компьютере — `frida` CLI или Python-биндинги.

```bash
# на устройстве (root)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# список процессов
frida-ps -U
# подключение к приложению
frida -U -f com.example.app -l hook.js
```

## Хукинг методов Java

Простейший хук — перехват метода и вывод аргументов/результата:

```javascript
Java.perform(function () {
    var MainActivity = Java.use('com.example.app.MainActivity');
    MainActivity.checkFlag.implementation = function (input) {
        console.log('input =', input);
        var ret = this.checkFlag(input);
        console.log('ret =', ret);
        return ret;
    };
});
```

Можно подменить возвращаемое значение — это ключ к обходу проверок:

```javascript
MainActivity.isRooted.implementation = function () {
    return false;   // всегда «не root»
};
```

## Хукинг нативного кода

Frida умеет хукать и нативные функции по адресу или имени:

```javascript
var nativeCheck = Module.findExportByName('libnative.so', 'nativeCheck');
Interceptor.attach(nativeCheck, {
    onEnter: function (args) { console.log('arg =', args[0]); },
    onLeave: function (retval) { console.log('ret =', retval); retval.replace(1); }
});
```

`retval.replace(1)` подменяет результат нативной функции — так обходят нативные проверки.

## Objection: автоматизация

Objection — обёртка над Frida с готовыми командами. Это самый быстрый способ обойти типовые защиты:

```bash
objection -g com.example.app explore
# внутри:
android root disable          # обход root detection
android sslpinning disable    # обход pinning
android hooking list activities
android hooking watch class_method com.example.app.MainActivity.checkFlag
android keystore list
```

Objection экономит время: вместо написания хуков вручную вы используете готовые команды.

## Рантайм-дамп данных

Иногда данные расшифровываются в памяти. Их можно дампить:

- **Дамп строк из памяти**: Frida-скрипты для поиска строк в heap.
- **Дамп расшифрованных файлов**: перехват `FileOutputStream.write`.
- **Дамп ключей**: перехват `Cipher.init` и извлечение ключа.

```javascript
var Cipher = Java.use('javax.crypto.Cipher');
Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    console.log('key =', key.getEncoded());
    return this.init(mode, key);
};
```

## Трассировка и поиск

Objection и Frida умеют трассировать вызовы:

```bash
android hooking watch class_method com.example.app.Crypto.decrypt --dump-args --dump-return
```

Это показывает реальные аргументы и результаты — то, что статически скрыто.

## Типичные ошибки и подводные камни

- **Неверная версия frida-server** — должна совпадать с версией клиента и архитектурой.
- **Приложение детектит Frida** — обходите через anti-anti-frida скрипты.
- **Хук не срабатывает** — неверное имя класса/метода или перегрузка (overload).
- **Краш при подмене** — неправильный тип возврата.
- **Забыть `Java.perform`** — хуки Java должны быть внутри.
- **Нативные адреса меняются** — используйте `findExportByName`, а не хардкод.
- **Эмулятор vs устройство** — поведение может отличаться.

## Справочная таблица

| Задача | Команда/код |
|--------|-------------|
| Запуск сервера | `frida-server &` |
| Список процессов | `frida-ps -U` |
| Подключение | `frida -U -f pkg -l hook.js` |
| Хук Java | `Cls.method.implementation` |
| Хук нативного | `Interceptor.attach` |
| Обход root | `android root disable` |
| Обход pinning | `android sslpinning disable` |
| Дамп ключа | хук `Cipher.init` |

## Что дальше / решение

План: установите `frida-server`, подключитесь к приложению, начните с Objection для быстрых побед (root/sslpinng disable), затем пишите собственные хуки для конкретных методов. Используйте `watch class_method` для трассировки, `implementation` для подмены. Для нативного кода — `Interceptor`. Динамический анализ раскрывает то, что скрыто статикой, и незаменим при обфускации и рантайм-проверках.

## Практический пример: перехват и подмена проверки

Разберём сквозной сценарий. Приложение `com.example.app` при старте проверяет, является ли устройство root, и при положительном результате закрывается. Мы хотим запустить его на эмуляторе с root. Шаг 1: запускаем `frida-server` и подключаемся. Шаг 2: смотрим, какой класс отвечает за проверку: `frida -U -f com.example.app` и `Java.enumerateLoadedClasses` либо Objection `android hooking list classes | grep -i root`. Шаг 3: хукаем метод `isRooted` и возвращаем `false`:

```javascript
Java.perform(function () {
    var Utils = Java.use('com.example.app.Utils');
    Utils.isRooted.implementation = function () {
        console.log('[+] bypass root check');
        return false;
    };
});
```

Шаг 4: приложение запускается. Далее перехватываем интересующий метод `decrypt` и смотрим аргументы и результат через `--dump-args --dump-return` в Objection. Получаем расшифрованные данные без реверса криптографии.

Этот пример показывает силу динамики: вместо анализа сложного кода мы просто наблюдаем и подменяем значения в рантайме.

## Рантайм-дамп расшифрованных данных

Если данные расшифровываются в памяти, их можно дампить, перехватывая запись:

```javascript
var FileOutputStream = Java.use('java.io.FileOutputStream');
FileOutputStream.write.overload('[B').implementation = function (buf) {
    console.log('writing', buf.length, 'bytes');
    return this.write(buf);
};
```

Аналогично перехватывайте `Cipher.doFinal`, чтобы получить расшифрованные байты, и `SharedPreferences`-запись, чтобы увидеть, что сохраняется. Это быстрее, чем реверс крипто-логики.

## Хукинг нативных проверок

Если проверка в `.so`, используйте `Interceptor.attach` по имени экспортируемой функции или по адресу (смещение от базы модуля). Для подмены результата — `retval.replace(...)`. Для поиска функции без экспорта используйте Ghidra, чтобы найти смещение, и `Module.findBaseAddress('libnative.so').add(offset)`.

## Частые вопросы

«Frida не подключается?» — проверьте версии и архитектуру. «Приложение падает при хуке?» — неверные типы/overload. «Не вижу нужный класс?» — используйте `enumerateLoadedClasses`. «Хук на нативный код не срабатывает?» — функция не экспортирована; найдите смещение. «Как быстро начать?» — Objection.

## Что дальше / решение

Итог: динамический анализ начинайте с Objection для быстрых побед, затем пишите точечные Frida-хуки для подмены проверок и наблюдения за данными. Для нативного кода — `Interceptor`. Комбинируйте дампы памяти и перехват крипто-функций вместо реверса. Динамика раскрывает то, что скрыто статикой, и незаменима при обфускации и рантайм-проверках.

## Расширенный чек-лист по Frida

Начните с Objection: `android root disable`, `android sslpinning disable`, `android hooking list activities`. Затем перейдите к точечным хукам. Полезные рецепты: перехват `Cipher.doFinal` для дампа расшифрованного; перехват `SharedPreferences.edit` для дампа сохраняемых данных; `enumerateLoadedClasses` для поиска классов по имени; `Java.choose` для поиска живых экземпляров объекта в heap. Для нативного кода — `Module.findExportByName`, `Interceptor.attach`, `NativeFunction` для вызова функций. Держите коллекцию готовых скриптов и адаптируйте их под задачу.

## Отладка хуков

Если хук не срабатывает, проверьте: правильность имени класса (через `enumerateLoadedClasses`), перегрузку метода (`overload`), момент загрузки (`Java.perform`, `setImmediate`). Печатайте `console.log` в начале `implementation`. Для нативных — проверьте, что модуль загружен (`Process.enumerateModules`). Ошибки Frida выводятся в консоль `frida`.

## Частые вопросы

«Frida крашит приложение?» — типы аргументов. «Не нахожу метод?» — overload/имя. «Хук на `.so` не работает?» — функция не экспортирована. «Как дампить память?» — `Memory.readByteArray` + `Memory.scan`. «Нужен GUI?» — используйте `frida-trace`.

## Что дальше / решение

Итог: динамический анализ строится на Objection (быстрые победы) + точечных Frida-хуках (подмена проверок, дамп данных) + Interceptor для нативного кода. Держите коллекцию скриптов, отлаживайте через логи, комбинируйте с обходом детекторов. Динамика раскрывает то, что скрыто статикой.

## Квиз

```quiz
- question: "Чем отличается `frida -f` от `frida -n`?"
  options:
    - "`-f` быстрее"
    - "`-f` запускает приложение и перехватывает с самого старта (spawn)"
    - "`-n` работает только на iOS"
    - "Разницы нет"
  answer: 1
- question: "Какой командой Objection отключает обход root-детекта?"
  options:
    - "android sslpinning disable"
    - "android root disable"
    - "android hooking list classes"
    - "android keystore list"
  answer: 1
- question: "Что произойдёт, если сервер валидирует флаг премиума самостоятельно?"
  options:
    - "Подмена на клиенте разблокирует функции"
    - "Подмена на клиенте не даст эффекта — нужен серверный обход"
    - "Приложение перезагрузится"
    - "Frida отключится"
  answer: 1
- question: "Для чего нужен `frida-server` на устройстве?"
  options:
    - "Для декомпиляции DEX"
    - "Как агент, в который внедряется скрипт внутри процесса"
    - "Для подписи APK"
    - "Для перехвата трафика"
  answer: 1
- question: "Как перехватить нативную функцию `strcmp` из библиотеки?"
  options:
    - "Java.use("strcmp")"
    - "Module.findExportByName + Interceptor.attach"
    - "apktool d"
    - "adb logcat"
  answer: 1
```

## Где пригодится

- **CTF:** Mobile — обход проверок, дамп флага из рантайма, реверс логики через хуки.
- **Bug bounty:** подтверждение клиентских уязвимостей, перехват API-токенов и запросов.
- **Пентест:** динамический этап по OWASP MASTG, проверка resilience-контролей на обходимость.
- **Работа:** исследование вредоносных/защищённых приложений, анализ поведения без исходников.
