---
id: mobile-frida-scripting
title: "Frida-скриптинг: хуки, трассировка и автоматизация"
category: mobile
parent: mobile-frida-tooling
difficulty: medium
order: 1
tags: [frida, scripting, hooking, tracing, automation, javascript]
prerequisites: [mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (быстрый хук нужного метода)"
  - "Bug bounty (трассировка логики, перехват аргументов)"
  - "Пентест: мобильные приложения"
estimated_minutes: 30
summary: "Практический Frida-скриптинг: структура скрипта, перехват аргументов и возвратов, трассировка вызовов, перечисление классов и подготовка скриптов для переиспользования."
---
## Архитектура Frida: сервер, агент, клиент

Frida работает по трёхзвенной схеме. **frida-server** запускается на устройстве (с root) и внедряется в процесс. **Агент** — это JavaScript, который исполняется внутри целевого процесса (через QuickJS/V8), имея доступ к его памяти и классам. **Клиент** — ваш инструмент на хосте (`frida`, `frida-trace`, Python-скрипт), который загружает агент и обменивается с ним сообщениями.

```bash
# версии frida-tools (хост) и frida-server (устройство) должны совпадать
pip install frida-tools
frida --version
adb push frida-server-16.x-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"
frida-ps -U                    # список процессов
frida-ps -Uai                  # только приложения (установленные)
frida -U -f com.target.app -l hook.js --no-pause
```

`-f` запускает приложение заново (spawn) и инжектит агент до старта — важно, когда проверки выполняются при запуске. `-n`/`-p` — attach к уже запущенному.

## Базовый API: Java.perform, use, overload, implementation

```javascript
Java.perform(function () {                       // дождаться загрузки ART
  var Session = Java.use('com.target.auth.Session');
  Session.getToken.overload().implementation = function () {
    var ret = this.getToken();                   // вызвать оригинал
    console.log('[+] getToken -> ' + ret);
    return ret;
  };
});
```

Ключевые моменты: `Java.perform` обязателен для работы с Java-классами; `Java.use('a.b.C')` даёт обёртку класса; `.overload(...)` выбирает перегрузку (иначе «ambiguous»); `.implementation` заменяет тело метода. `this` — экземпляр; для статических методов `this` — сам класс. Чтобы сохранить оригинал: `var orig = Session.getToken.overload(); ... orig.call(this)`.

## Хуки: аргументы, возврат, изменение поведения

```javascript
Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (input) {
    console.log('[cipher] in=' + bytesToHex(input));
    var out = this.doFinal(input);
    console.log('[cipher] out=' + bytesToHex(out));
    return out;
  };

  var Sp = Java.use('android.content.SharedPreferencesImpl');
  Sp.getString.overload('java.lang.String','java.lang.String').implementation = function (k, d) {
    var v = this.getString(k, d);
    console.log('[prefs] ' + k + ' = ' + v);
    return v;
  };
});

function bytesToHex(b) {
  var s = ''; for (var i = 0; i < b.length; i++)
    s += ('0' + (b[i] & 0xff).toString(16)).slice(-2);
  return s;
}
```

Хук на `Cipher.doFinal` дампит ключи/данные; на `SharedPreferences.getString` — секреты хранилища; на `MessageDigest.update` — вход хэширования. Меняя возврат (`return true`), обходят проверки (`isRooted`, `isEmulator`, `checkSignature`).

## Перехват нативного кода

```javascript
// адрес функции в библиотеке
var base = Module.findBaseAddress('libnative-lib.so');
var check = base.add(0x1234);                    // смещение из реверса
Interceptor.attach(check, {
  onEnter: function (args) { console.log('arg0=' + args[0]); },
  onLeave: function (retval) { console.log('ret=' + retval); retval.replace(1); }
});

// вызвать нативную функцию из JS
var f = new NativeFunction(Module.getExportByName('libc.so','system'), 'int', ['pointer']);
f(Memory.allocUtf8String('id'));
```

`Interceptor.attach` — база для нативных хуков (anti-debug, pinning в `.so`). `retval.replace(1)` подменяет возврат. `NativeFunction` позволяет вызывать функции напрямую. `Memory.allocUtf8String` создаёт строку в памяти процесса.

## Трассировка: Stalker и backtrace

```javascript
// трассировка всех вызовов метода и откуда он вызван
Java.perform(function () {
  var Thread = Java.use('java.lang.Thread');
  var Log = Java.use('android.util.Log');
  var m = Log.d.overload('java.lang.String','java.lang.String');
  m.implementation = function (t, msg) {
    console.log(Thread.currentThread().getStackTrace().join('\n'));
    return m.call(this, t, msg);
  };
});

// нативная трассировка потока (осторожно: медленно)
var t = Process.getCurrentThreadId();
Stalker.follow(t, { events: { call: true }, onReceive: function (e) {} });
```

Стек вызовов — быстрый способ понять, «кто вызывает» метод (полезно для нахождения точек входа проверок). `Stalker` даёт низкоуровневую трассировку, но сильно замедляет процесс — применяйте точечно.

## RPC: обмен данными с Python

```javascript
// агент
rpc.exports = {
  decrypt: function (hex) {
    var C = Java.use('com.target.crypto.CipherUtil');
    return C.decrypt(hex);
  },
  scan: function () {
    return Java.available;
  }
};
```

```python
# хост
import frida
session = frida.get_usb_device().attach('com.target.app')
script = session.create_script(open('agent.js').read())
script.load()
print(script.exports_sync.decrypt('Q0VF...'))
```

RPC превращает Frida из «смотреть» в «вызывать»: вы можете из Python дёргать методы приложения, автоматизировать перебор и собирать данные в удобном формате. `script.exports_sync` — синхронный вызов; для асинхронности используйте `script.exports`.

## Автоматизация: frida-trace и frida-tools

```bash
# трассировать все методы класса
frida-trace -U -f com.target.app -j '*!*getToken*'
# трассировать нативные экспорты
frida-trace -U -f com.target.app -i "open" -i "strcmp"
# прицепить свой скрипт
frida -U -f com.target.app -l hook.js --no-pause -o out.log
```

`frida-trace` генерирует заготовки хендлеров, которые можно править. Для массовых задач удобнее свой агент с RPC.

## Анти-детект и стабильность

- **Имя процесса:** Frida видна по строкам `frida`, `gum-js-loop`, портам 27042/27043. Меняйте имена (`frida-server -l 0.0.0.0:1234`, кастомный gadget).
- **frida-gadget:** встраивается в APK (`objection patchapk`), не требует отдельного сервера — сложнее детектится.
- **Тайминг:** spawn (`-f`) нужен, если проверка выполняется до загрузки вашего скрипта.
- **Краши:** хук на несуществующий метод/перегрузку роняет процесс; всегда проверяйте `Java.available` и оборачивайте в try/catch.

## Разобранный пример: дамп ключа AES

```javascript
Java.perform(function () {
  var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
  SecretKeySpec.$init.overload('[B','java.lang.String').implementation = function (key, alg) {
    console.log('[+] key=' + bytesToHex(key) + ' alg=' + alg);
    return this.$init(key, alg);
  };
  var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
  IvParameterSpec.$init.overload('[B').implementation = function (iv) {
    console.log('[+] iv=' + bytesToHex(iv));
    return this.$init(iv);
  };
});
```

Запуск: `frida -U -f com.target.app -l keydump.js --no-pause`. При первом же шифровании видим ключ и IV — дальше расшифровываем локально (`mobile-crypto-misuse`).

## Справочная таблица API

| Задача | API |
|--------|-----|
| Работа с Java | `Java.perform`, `Java.use`, `Java.choose` |
| Выбрать перегрузку | `.overload('sig')` |
| Заменить метод | `.implementation = function(){}` |
| Вызвать оригинал | `orig.call(this, args)` |
| Нативный хук | `Interceptor.attach(ptr, {onEnter,onLeave})` |
| Найти экспорт | `Module.getExportByName(lib, sym)` |
| Вызвать функцию | `new NativeFunction(addr,'int',['pointer'])` |
| Память | `Memory.allocUtf8String`, `Memory.readByteArray` |
| Стек | `Thread.currentThread().getStackTrace()` |
| RPC | `rpc.exports = {...}` / `script.exports_sync` |

## Типовые ошибки новичка

- **Забыть `Java.perform`.** Хуки «не срабатывают», потому что ART ещё не готов.
- **Не указать `overload`.** Frida кидает «ambiguous» на перегруженных методах.
- **Ломать процесс.** Хук на несуществующий класс/метод = краш; проверяйте доступность.
- **Детект по таймингу.** Если приложение проверяет окружение на старте, attach после запуска не поможет — нужен spawn.
- **Считать, что Frida «невидима».** Anti-Frida (`mobile-frida-detection`) реально ловит стандартную установку.

## Что дальше / решение

Базовый цикл: найти метод/функцию в статике → написать хук (Java или нативный) → снять проверку или дампнуть данные → автоматизировать через RPC/`frida-trace`. Если приложение детектит Frida — переходите к `mobile-frida-detection` (обход детекта) и `mobile-cert-pinning-deep`. Связанные уроки: `mobile-dynamic-frida` (обзор), `mobile-objection` (готовые команды), `mobile-android-native` (реверс `.so` под хуки). Решение — когда проверка обойдена или данные извлечены воспроизводимым скриптом.

## Frida и анти-детект: продвинутые приёмы

Стандартная Frida детектится: по именам потоков (`gum-js-loop`, `gmain`), по открытому порту 27042/27043, по строкам в памяти, по `frida-agent` в `/proc/self/maps`. Приёмы противодействия:

```bash
# 1. переименовать сервер и сменить порт
frida-server -l 0.0.0.0:1234
# 2. переименовать бинарник frida-server -> something else
mv frida-server /data/local/tmp/fsd && /data/local/tmp/fsd -l 0.0.0.0:1234 &
# 3. подключаться к нестандартному порту
frida -H 192.168.1.50:1234 -f com.target.app -l hook.js
```

```javascript
// спрятать следы в /proc/self/maps и потоках
var open = Module.getExportByName('libc.so', 'open');
Interceptor.attach(open, { onEnter: function (a) {
  var p = a[0].readUtf8String();
  if (p && p.indexOf('frida') !== -1) this.hide = true;
}, onLeave: function (r) { if (this.hide) r.replace(ptr(-1)); }});
```

Для обхода детекта по строкам (`grep -i frida`) помогает переименование модулей и патч `frida-gadget` с нестандартным именем. Если приложение использует несколько независимых проверок, глушите их по очереди, наблюдая в логе, какая срабатывает. Связанный урок — `mobile-frida-detection`.

## Отладка собственных скриптов

- **`console.log` не виден?** Используйте `send({...})` и `script.on('message', ...)` в клиенте — надёжнее.
- **Краши при attach:** оберните в `try { ... } catch (e) { console.log(e); }`; проверяйте `Java.available`.
- **`overload` не найден:** выведите сигнатуры через `Class.method.overloads.forEach(o => console.log(o.argumentTypes))`.
- **Медленно:** минимизируйте число хуков и не используйте `Stalker` без нужды.
- **`Java.choose`:** для перебора живых экземпляров класса (`Java.choose('com.a.B', {onMatch, onComplete})`) — удобно, чтобы найти объект с нужным состоянием.

## Квиз

```quiz
- question: "Что нужно обернуть Android-хуки в Frida?"
  options:
    - "Java.perform(function () { ... })"
    - "setTimeout"
    - "document.ready"
    - "console.log"
  answer: 0
  explanation: "Java.perform гарантирует, что VM Android готова."
- question: "Как подменить возврат метода на Android?"
  options:
    - "Cls.method.implementation = function () { return false; }"
    - "delete Cls.method"
    - "Cls.method = null"
    - "throw new Error()"
  answer: 0
  explanation: "Переопределение implementation возвращает своё значение."
- question: "Как перехватить нативную функцию по имени?"
  options:
    - "Module.findExportByName + Interceptor.attach"
    - "Java.use"
    - "ObjC.classes"
    - "Process.enumerateModules"
  answer: 0
  explanation: "Для нативных функций используется Interceptor."
- question: "Зачем вызывать оригинальный метод внутри хука?"
  options:
    - "Чтобы сохранить логику и получить реальный результат"
    - "Чтобы ускорить"
    - "Чтобы скрыть хук"
    - "Чтобы удалить метод"
  answer: 0
  explanation: "Иначе поведение приложения ломается."
- question: "Как перечислить загруженные классы?"
  options:
    - "Java.enumerateLoadedClasses"
    - "Java.use"
    - "Module.enumerateSymbols"
    - "Process.enumerateThreads"
  answer: 0
  explanation: "enumerateLoadedClasses обходит все классы в VM."
```

## Где пригодится

- **CTF Mobile:** быстрый хук нужного метода.
- **Bug bounty:** трассировка логики и перехват аргументов.
- **Пентест:** динамический анализ.
- **Работа:** автоматизация reverse engineering.
