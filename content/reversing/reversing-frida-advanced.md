---
id: reversing-frida-advanced
title: "Frida advanced: Stalker, hooking и RPC"
category: reversing
parent: reversing-taint-analysis
difficulty: expert
order: 2
tags: [reversing, frida, stalker, instrumentation, rpc, hooking, dbi]
prerequisites: [reversing-taint-analysis, reversing-dynamic-debug]
useful_for:
  - "CTF Reversing / Mobile"
  - "Malware analysis"
  - "Bug bounty"
estimated_minutes: 65
summary: "Продвинутый Frida: Stalker-трассировка, hooking функций/методов, Interceptor, RPC-экспорт и автоматизация."
---
Frida — самый популярный инструмент **динамической инструментации**: он внедряется в процесс и позволяет перехватывать функции, читать и менять память, трассировать исполнение (Stalker), вызывать методы и экспортировать API по RPC. Frida работает на Android, iOS, Linux, Windows, macOS и встраивается в собственные приложения. Базовый hooking прост, но реальные задачи (обход anti-Frida, Stalker-трассировка, RPC-автоматизация) требуют понимания внутренностей. В этом уроке — продвинутые приёмы Frida с полными примерами.

## Что такое Frida и как она работает

Frida состоит из двух частей: **клиент** (Python/Node/CLI на хосте) и **агент** (`frida-agent`, внедряемая библиотека) в процессе-цели. Агент исполняет JavaScript (на QuickJS/V8) и предоставляет API: `Interceptor`, `Stalker`, `Memory`, `Module`, `NativeFunction`, `Java`, `ObjC`. Связь — через канал (USB для Android, TCP, локальный). Режимы запуска: **attach** (к уже запущенному процессу) и **spawn** (запустить под Frida, чтобы успеть перехватить ранний код). Установка:

```bash
pip install frida-tools
frida --version
# на устройстве (Android): запушить frida-server нужной архитектуры
adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
frida-ps -U           # список процессов
```

## Interceptor: перехват функций

Основной API — `Interceptor.attach(target, callbacks)`. Target — адрес (`Module.getExportByName`) или `NativePointer`:

```javascript
var addr = Module.getExportByName("libc.so", "strcmp");
Interceptor.attach(addr, {
  onEnter: function (args) {
    console.log("strcmp(", args[0].readCString(), ",", args[1].readCString(), ")");
  },
  onLeave: function (retval) {
    console.log("=>", retval);
    retval.replace(0);           // подмена результата
  }
});
```

`onEnter` получает массив `args` (указатели), `onLeave` — `retval` (можно заменить через `replace`). `Interceptor.replace(target, NativeCallback)` полностью подменяет функцию. `Interceptor.revert(target)` снимает хук. Для перехвата по смещению: `ptr(module.base).add(0x1234)`.

## Java и ObjC hooking

На Android Frida умеет перехватывать Java-методы по классу и имени:

```javascript
Java.perform(function () {
  var App = Java.use("com.example.app.License");
  App.check.implementation = function (key) {
    console.log("check called with", key);
    var r = this.check(key);      // вызвать оригинал
    return true;                  // всегда успех
  };
  Java.enumerateLoadedClasses({ onMatch: function (n) { console.log(n); }, onComplete: function () {} });
});
```

На iOS — `ObjC.classes.ClassName['- method:']` с `implementation` и `ObjC.implement`. Java-хуки требуют `Java.perform` и работают, пока JVM/Dalvik активна.

## Stalker: трассировка исполнения

`Stalker` записывает поток исполнения (инструкции, вызовы, ветвления) с минимальным оверхедом. Пример трассировки вызовов:

```javascript
Stalker.follow(Process.getCurrentThreadId(), {
  events: { call: true, ret: false, exec: false },
  onReceive: function (events) {
    var e = Stalker.parse(events, { annotate: true, stringify: true });
    e.forEach(function (x) { console.log(x); });
  }
});
```

`Stalker.follow`/`Stalker.unfollow` включают/выключают трассировку; `Stalker.parse` декодирует события. Для покрытия (coverage) включают `events: { block: true }` и собирают уникальные блоки. Stalker мощнее, чем обычные хуки, и позволяет строить граф исполнения в рантайме.

## RPC: экспорт API из агента

RPC позволяет вызывать функции агента из Python-скрипта — идеально для автоматизации:

```javascript
rpc.exports = {
  decrypt: function (hex) {
    var buf = Memory.alloc(hex.length / 2);
    // ... расшифровка ...
    return buf.readByteArray();
  },
  hookcheck: function () {
    Interceptor.attach(Module.getExportByName(null, "check"), { onEnter: function () {} });
  }
};
```

```python
import frida
s = frida.attach("target")
script = s.create_script(open("agent.js").read())
script.load()
print(script.exports_sync.decrypt("deadbeef"))
```

Так из Python управляют перехватом и вызывают внутренние функции — основа для скриптов обхода проверок и автоматического анализа.

## Memory API и патчинг

`Memory` даёт доступ к памяти процесса:

```javascript
var p = Module.getExportByName(null, "verify");
Memory.protect(p, 8, 'rwx');
p.writeByteArray([0x90, 0x90]);          // NOP
console.log(hexdump(p, { length: 32, ansi: false }));
var s = Memory.allocUtf8String("hello"); // выделить строку
```

`Memory.scan(base, size, "48 8b ?? ??", callbacks)` ищет паттерны; `Memory.patchCode(addr, size, code => code.writeByteArray(...))` — безопасный патч с учётом прав. Так обходят проверки, не пересобирая бинарь.

## Anti-Frida и обход

Приложения детектируют Frida: поиск строк `frida`/`gum` в `/proc/self/maps`, проверка порта 27042, сканирование памяти на паттерны агента, проверка `TracerPid`. Обходы:

- запустить `frida-server` с переименованным именем (`mv frida-server fs`) и на другом порту (`-l 0.0.0.0:8888`);
- использовать `frida-gadget` вместо server (встраивается в APK);
- хук `open`/`fopen` для подмены содержимого `/proc/self/maps`;
- патч проверок (найти строку и NOP-нуть ветку);
- кастомная сборка Frida с изменёнными сигнатурами (`frida-core` пересборка).

## Полный разбор: автоматический обход проверки

**Шаг 1 — найти проверку:** в Ghidra/IDA находим функцию `verify`, экспортируемую или вызываемую из JNI. **Шаг 2 — хук через Frida:**

```javascript
var verify = Module.getExportByName("liblicense.so", "verify");
Interceptor.attach(verify, {
  onEnter: function (a) { console.log("key:", a[0].readCString()); },
  onLeave: function (r) { console.log("orig:", r); r.replace(1); }
});
```

**Шаг 3 — запуск:** `frida -U -f com.example.app -l hook.js --no-pause`. **Шаг 4 — проверка:** приложение принимает любой ключ. **Шаг 5 — автоматизация:** через RPC вызываем `verify` с разными входами и подбираем валидный ключ, если нужен именно он.

## Шпаргалка

| Задача | API |
|---|---|
| Хук функции | `Interceptor.attach(addr, {...})` |
| Подмена | `Interceptor.replace` |
| Java-метод | `Java.use("Cls").m.implementation` |
| ObjC-метод | `ObjC.classes.C['-m:']` |
| Трассировка | `Stalker.follow` |
| Поиск в памяти | `Memory.scan` |
| Патч кода | `Memory.patchCode` |
| Экспорт API | `rpc.exports` |
| Список процессов | `frida-ps -U` |

## Что дальше / решение

Маршрут: найдите целевую функцию, перехватите её `Interceptor.attach`, прочитайте аргументы/подмените результат, при необходимости включите Stalker для трассировки и RPC для автоматизации из Python. Для anti-Frida — переименуйте server/смените порт и пропатчьте проверки. Дальше изучайте frida-gadget для встраивания, Stalker-деобфускацию и интеграцию с QBDI для инструментации на уровне инструкций.

## Python API и автоматизация

Frida-агент можно управлять из Python, что превращает разовый хук в инструмент:

```python
import frida, sys
def on_message(msg, data):
    print(msg)
js = open("agent.js").read()
session = frida.get_usb_device().attach("com.example.app")
script = session.create_script(js)
script.on("message", on_message)
script.load()
sys.stdin.read()
```

Для spawn: `pid = device.spawn(["com.example.app"])`, затем `device.attach(pid)`, `device.resume(pid)`. `script.post({"type": "cmd"})` отправляет сообщение агенту, `send()` в JS — обратно. Так строят интерактивные консоли и автоматические фаззеры поверх Frida. Дополнительно `frida-trace` генерирует хук-скрипты автоматически: `frida-trace -U -f app -i "open*"`.

## Hook системных функций и сисколлов

Для анализа ввода-вывода перехватывают libc и сисколлы:

```javascript
["open","read","write","connect","send","recv"].forEach(function (n) {
  var a = Module.getExportByName(null, n);
  if (a) Interceptor.attach(a, {
    onEnter: function (args) {
      if (n === "open") this.path = args[0].readCString();
      if (n === "connect") console.log("connect fd", args[0].toInt32());
    },
    onLeave: function (r) { if (this.path) console.log(this.path, "->", r.toInt32()); }
  });
});
```

Так видят, какие файлы открывает приложение, куда подключается, что пишет. На Android это дополняют хуком `Java.use("java.net.Socket")`. Для обхода TLS-pinning перехватывают `SSL_read`/`SSL_write` (см. mobile-уроки).

## Работа с памятью: scan, hexdump, чтение структур

```javascript
var base = Process.enumerateModules()[0].base;
Memory.scan(base, 0x100000, "48 89 e5 48 83 ec", {
  onMatch: function (address, size) { console.log("found at", address); },
  onComplete: function () { console.log("done"); }
});
console.log(hexdump(ptr("0x7fff0000"), { length: 64, ansi: false }));
var val = ptr("0x600000").readU32();          // чтение
ptr("0x600000").writeU32(0x1337);             // запись
```

`NativeFunction` позволяет вызвать функцию по адресу: `var f = new NativeFunction(addr, 'int', ['pointer']); f(buf);`. Это удобно для вызова внутренних проверок с подготовленными аргументами.

## Frida на iOS и кросс-платформенность

На iOS Frida работает через `frida-server` на джейлбрейкнутом устройстве или `frida-gadget` внутри IPA. Hook ObjC:

```javascript
if (ObjC.available) {
  var cls = ObjC.classes.ViewController;
  Interceptor.attach(cls['- viewDidLoad'].implementation, {
    onEnter: function () { console.log("viewDidLoad"); }
  });
}
```

На Linux/Windows — те же `Interceptor`/`Stalker`, но без Java/ObjC. Это делает Frida универсальным инструментом для реверса и анализа malware на любой платформе.

## Stalker: покрытие и построение call graph

Stalker не только трассирует, но и позволяет строить покрытие и граф вызовов в рантайме. Для покрытия собирают уникальные адреса базовых блоков:

```javascript
var blocks = {};
Stalker.follow(Process.getCurrentThreadId(), {
  events: { block: true },
  onReceive: function (events) {
    Stalker.parse(events).forEach(function (ev) {
      blocks[ev[0].toString()] = true;
    });
  }
});
// позже: Object.keys(blocks).length
```

Для call graph перехватывают события `call`/`ret` и связывают вызывающий адрес с целью. Это позволяет увидеть, какие функции реально исполняются (полезно для распаковки и анти-обфускации). Stalker можно включать/выключать вокруг интересующего участка, ограничивая оверхед. Важно: Stalker работает на уровне потока, поэтому для многопоточных приложений его включают для конкретных тредов. Комбинация Stalker + `Interceptor` даёт и общую картину исполнения, и точечные хуки.

## Кросс-платформенные нюансы и стабильность

Frida на разных платформах имеет особенности. На Windows/Linux `Module.getExportByName(null, name)` ищет по всем модулям, на macOS нужно указывать конкретный модуль для некоторых символов. На Android хуки Java требуют, чтобы класс был уже загружен (`Java.perform` ждёт загрузки VM), иначе используйте `Java.enumerateLoadedClasses` или хук `ClassLoader`. При работе с 32-битными процессами указатели 4-байтные, что влияет на `readPointer`. Для стабильности: оборачивайте хуки в `try/catch`, проверяйте `ptr.isNull()`, не держите ссылки на Java-объекты между вызовами. `frida -U -f app --runtime=v8` переключает движок (QuickJS легче, V8 быстрее на сложных скриптах).

## Квиз

```quiz
- question: "Что делает Interceptor.attach?"
  options:
    - "Перехватывает вызов функции (onEnter/onLeave)"
    - "Сканирует память"
    - "Шифрует данные"
    - "Сканирует порты"
  answer: 0
  explanation: "Interceptor.attach даёт колбэки до/после вызова."
- question: "Что такое Stalker?"
  options:
    - "Механизм трассировки исполнения (инструкции/вызовы)"
    - "Отладчик ядра"
    - "Пакер"
    - "Формат файла"
  answer: 0
  explanation: "Stalker инструментирует поток исполнения."
- question: "Для чего RPC в Frida?"
  options:
    - "Экспорт функций процесса в Python/др. для автоматизации"
    - "Сканирование портов"
    - "Шифрование"
    - "Сжатие"
  answer: 0
  explanation: "rpc.exports позволяет вызывать функции из скрипта."
- question: "Что нужно для Java-хуков на Android?"
  options:
    - "Java.perform и Java.use"
    - "Только Stalker"
    - "Только nm"
    - "Только ldd"
  answer: 0
  explanation: "Java.perform подключается к ART VM."
- question: "Почему Frida может быть обнаружена?"
  options:
    - "По порту/строкам/потокам frida"
    - "По ASLR"
    - "По NX"
    - "По canary"
  answer: 0
  explanation: "Анти-анализ ищет признаки Frida (порт 27042, строки)."
```

## Где пригодится

- **CTF:** Reversing/Mobile.
- **Malware analysis:** динамика.
- **Bug bounty:** анализ клиентов.
- **Работа:** mobile/dynamic analysis.
