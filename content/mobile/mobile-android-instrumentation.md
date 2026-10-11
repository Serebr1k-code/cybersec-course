---
id: mobile-android-instrumentation
title: "Frida deep: RPC, разработка скриптов и патч памяти"
category: mobile
parent: mobile-frida-tooling
difficulty: hard
order: 3
tags: [frida, instrumentation, rpc, memory, hooking, android, patching]
prerequisites: [mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (автоматизация перебора, вызов внутренних функций)"
  - "Bug bounty (обход проверок в рантайме)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Продвинутый Frida: экспорт RPC-функций, вызов Java и нативных методов из скрипта, чтение/запись памяти и патч логики на лету."
---
## Введение

Базовый Frida (см. `mobile-dynamic-frida`) — это «подключиться и залогировать метод». Настоящая мощь Frida — в **управлении процессом**: экспорт RPC-функций, чтобы вызывать внутренние методы из Python, чтение и запись памяти, патч проверок на лету и автоматизация брутфорса. Этот урок — про продвинутые приёмы, которые превращают Frida из логгера в удалённый API над приложением.

Продолжает `mobile-dynamic-frida`. Пригодится всюду, где нужен интерактивный контроль над рантаймом: обход проверок, извлечение секретов, автоматизация.

## Экспорт RPC: Python ↔ Java

`rpc.exports` позволяет вызывать функции скрипта из Python/JS-клиента. Это превращает Frida в удалённый API над приложением.

```javascript
// hook.js
rpc.exports = {
  checkFlag: function (input) {
    var result = null;
    Java.perform(function () {
      var Checker = Java.use('com.ctf.Checker');
      result = Checker.checkFlag(input);
    });
    return result;
  },
  getSecret: function () {
    var s = null;
    Java.perform(function () {
      var C = Java.use('com.ctf.Checker');
      var inst = C.$new();
      s = inst.secret.value;   // доступ к приватному полю
    });
    return s;
  }
};
```

```python
# client.py
import frida
session = frida.get_usb_device().attach('com.ctf.challenge')
script = session.create_script(open('hook.js').read())
script.load()
print(script.exports_sync.check_flag('test'))
print(script.exports_sync.get_secret())
```

Так строится **брутфорс**: RPC-функция принимает гипотезу, приложение её проверяет, Python перебирает.

## Вызов Java-методов и работа с типами

```javascript
Java.perform(function () {
  var Cls = Java.use('com.ctf.FlagChecker');
  var ok = Cls.verify('guess');           // статический метод
  var obj = Cls.$new('arg');              // создание объекта
  obj.process();                          // метод экземпляра
  var fieldVal = obj.secretField.value;   // чтение поля
  obj.secretField.value = 'new';          // запись поля
  var buf = Java.array('byte', [0x41, 0x42]);
  Cls.handleBytes(buf);
});
```

Для нативных функций — `NativeFunction` и `Memory`:

```javascript
var f = new NativeFunction(Module.findExportByName('libcheck.so', 'check'),
                           'int', ['pointer']);
var buf = Memory.allocUtf8String('guess');
console.log(f(buf));
```

## Чтение и запись памяти, патч логики

```javascript
// заменить инструкцию (патч проверки)
var base = Module.findBaseAddress('libcheck.so');
var addr = base.add(0x1A2C);
console.log(hexdump(addr, { length: 16 }));
Memory.protect(addr, 4, 'rwx');
addr.writeByteArray([0x00, 0x00, 0x80, 0xD2]);  // mov x0, #0

// перезаписать возвращаемое значение хука
Interceptor.attach(fn, {
  onLeave: function (ret) { ret.replace(ptr(1)); }
});

// чтение памяти по указателю
var s = Memory.readUtf8String(ptr);
var b = Memory.readByteArray(ptr, 32);
```

Патч в Java-слое проще: переопределить метод (`.implementation = function () { return true; }`). Для нативного — `Interceptor.replace` либо `Memory` + `Memory.protect`.

## Разобранный пример: автоматический брутфорс через RPC

```javascript
// brute.js
rpc.exports = {
  try: function (i, ch) {
    var r = false;
    Java.perform(function () {
      var C = Java.use('com.ctf.Password');
      r = C.checkChar(i, ch);
    });
    return r;
  }
};
```

```python
# brute.py
import frida, string
session = frida.get_usb_device().attach('com.ctf.challenge')
script = session.create_script(open('brute.js').read()); script.load()
flag = ''
for i in range(0, 40):
    for c in string.printable:
        if script.exports_sync.try_(i, c):
            flag += c; print(flag); break
```

Классический CTF-паттерн: когда приложение проверяет ввод посимвольно, RPC + Python даёт флаг за секунды.

## Продвинутые приёмы: Stalker и трассировка

Когда нужно понять поток исполнения, используют `Stalker`:

```javascript
var target = Module.findExportByName('libtarget.so', 'verify');
Interceptor.attach(target, {
  onEnter: function () {
    Stalker.follow(Process.getCurrentThreadId(), {
      events: { call: true },
      onCallSummary: function (summary) { console.log(JSON.stringify(summary)); }
    });
  }
});
```

Stalker тяжелее обычных хуков, поэтому применяйте точечно: включайте на коротком участке и выключайте (`Stalker.unfollow`).

## Hook-генератор и перечисление классов

```bash
# сгенерировать заглушки хуков для класса
frida-trace -U -f com.ctf.challenge -j 'com.ctf.Checker!*'
```

Быстрый способ увидеть, какие методы класса вызываются и с какими аргументами, — `frida-trace` с шаблоном.

## Частые ошибки и подводные камни

- **Не оборачивать Java-код в `Java.perform`** — обращение к Java вне контекста VM падает.
- **Путать `exports_sync` и `exports`** — в Python удобнее синхронные, в JS — асинхронные.
- **Патчить память без `Memory.protect`** — страница может быть read-only.
- **Забыть про `overload`** — у метода с несколькими сигнатурами нужно указать нужную.
- **Слишком много логов** — Frida тормозит процесс; логируйте точечно.
- **Держать Stalker включённым** — процесс замедляется в разы, легко словить таймаут.

## Справочная таблица

| Задача | API |
|--------|-----|
| Экспорт функций | `rpc.exports` |
| Вызов Java-метода | `Java.use(...).method()` |
| Приватное поле | `obj.field.value` |
| Нативная функция | `NativeFunction` |
| Патч памяти | `Memory.protect` + `writeByteArray` |
| Замена возврата | `Interceptor.attach` → `onLeave` |
| Трассировка | `Stalker.follow` |

## Что дальше / решение

- **Посимвольная проверка** → RPC + Python брутфорс.
- **Клиентский гейт** → `.implementation = function(){return true;}`.
- **Логика в native** → `Interceptor.replace` или патч памяти по смещению.
- **Нужен поток исполнения** → Stalker точечно.
- Проверьте, не палится ли Frida (см. `mobile-frida-detection`): переименуйте сервер и смените порт.

## Хукинг нативных методов и JNI

Когда логика в `.so`, Frida работает с `Interceptor` и `NativeFunction`:

```javascript
// найти экспорт и захукать
var f = Module.findExportByName('libcheck.so', 'Java_com_ctf_Checker_verify');
Interceptor.attach(f, {
  onEnter: function (args) {
    // args[0]=JNIEnv*, args[1]=jobject, args[2]=jstring
    console.log('[verify] arg=' + Java.vm.getEnv().getStringUtfChars(args[2], null).readUtf8String());
  },
  onLeave: function (ret) {
    console.log('[verify] ret=' + ret);
  }
});
```

Если функция зарегистрирована динамически (`RegisterNatives`), экспорт не найдётся — ищите адрес по смещению от базы модуля (полученному из Ghidra/Blutter) и хукайте `base.add(offset)`.

## Обход anti-debug и anti-Frida в рантайме

```javascript
// спрятать распространённые индикаторы
Java.perform(function () {
  var D = Java.use('android.os.Debug');
  D.isDebuggerConnected.implementation = function () { return false; };
  var F = Java.use('android.app.Application');
  // прячем имя процесса frida-server через sysctl/ptrace проверки
});
```

Комбинируйте с переименованием frida-server и сменой порта (см. `mobile-frida-detection`).

## Автоматизация и CI

RPC-интерфейс удобно встраивать в тесты: скрипт загружается, вызывает методы приложения и проверяет ожидания. Это позволяет гонять проверки безопасности мобильного клиента в CI (например, убедиться, что pinning включён, что debuggable=false и т. д.).

## Справочная таблица продвинутых API

| API | Назначение |
|-----|-----------|
| `rpc.exports` | удалённый вызов из Python |
| `NativeFunction` | вызов нативной функции |
| `Interceptor.attach/replace` | хук/подмена |
| `Stalker.follow` | трассировка потока |
| `Memory.protect/read/write` | работа с памятью |
| `Java.array` | работа с массивами |
| `hexdump` | дамп памяти |

## Что делать дальше

- Для посимвольных проверок — RPC + Python.
- Для нативной логики — смещения из Ghidra/Blutter + `Interceptor`.
- Для сложного потока — Stalker точечно.
- Для скрытности — прячьте Frida и уменьшайте логи.

## Практический разбор: обход посимвольной проверки

Самый частый CTF-сценарий с RPC — посимвольная проверка флага. Нативная функция принимает индекс и символ и возвращает булево; Python перебирает.

```javascript
// brute.js
rpc.exports = {
  chk: function (i, ch) {
    var ok = false;
    Java.perform(function () {
      var C = Java.use('com.ctf.Checker');
      ok = C.checkAt(i, ch);
    });
    return ok;
  }
};
```

```python
# brute.py
import frida, string
dev = frida.get_usb_device()
s = dev.attach('com.ctf.challenge')
sc = s.create_script(open('brute.js').read()); sc.load()
flag = ''
for i in range(64):
    for c in string.ascii_letters + string.digits + '_{}':
        if sc.exports_sync.chk(i, c):
            flag += c; print(flag, flush=True); break
```

Если функция в native, RPC может вызывать её через `NativeFunction` по адресу из Ghidra.

## Отладка Frida-скриптов

- `console.log`/`console.error` внутри `Java.perform` — базовый вывод.
- Ошибки в хуках не роняют процесс, но печатаются в консоль Frida.
- Для сложных скриптов используйте TypeScript-шаблон (`frida-compile`) — типы ловят ошибки до запуска.
- Проверяйте перегрузки: `Cls.method.overloads` показывает список сигнатур.

```javascript
Java.perform(function () {
  var C = Java.use('com.ctf.Checker');
  console.log(C.checkAt.overloads.map(function (o) { return o.argumentTypes; }));
});
```

## Что дальше

- Для посимвольных проверок — RPC + Python (см. выше).
- Для нативной логики — `NativeFunction` + смещения из Ghidra/Blutter.
- Для сложного потока — Stalker точечно, с выключением.
- Для скрытности — переименование frida-server и смена порта.

## Квиз

```quiz
- question: "Что позволяет rpc.exports в Frida?"
  options:
    - "Вызывать функции скрипта из Python/JS-клиента (управлять приложением снаружи)"
    - "Компилировать Java в native"
    - "Ставить root"
    - "Подписывать APK"
  answer: 0
- question: "Как переопределить Java-метод так, чтобы он всегда возвращал true?"
  options:
    - "method.implementation = function () { return true; }"
    - "method.call(true)"
    - "Memory.write(true)"
    - "Java.use('true')"
  answer: 0
- question: "Что нужно сделать перед записью в read-only страницу памяти?"
  options:
    - "Memory.protect(addr, size, 'rwx')"
    - "Перезапустить приложение"
    - "Отключить ASLR"
    - "Ничего, запись всегда разрешена"
  answer: 0
- question: "Зачем нужен overload при хуке метода?"
  options:
    - "Выбрать нужную сигнатуру, если у метода несколько перегрузок"
    - "Ускорить хук"
    - "Обойти pinning"
    - "Расшифровать строки"
  answer: 0
- question: "Как RPC помогает в CTF с посимвольной проверкой ввода?"
  options:
    - "Позволяет из Python перебирать гипотезы, вызывая проверку приложения"
    - "Автоматически печатает флаг"
    - "Удаляет анти-отладку"
    - "Ставит сертификат CA"
  answer: 0
```

## Где пригодится

- **CTF Mobile:** брутфорс посимвольных проверок, вызов скрытых функций, извлечение полей.
- **Bug bounty:** обход клиентских проверок в рантайме, извлечение токенов/ключей.
- **Пентест:** динамический анализ защищённых приложений, оценка клиентской логики.
- **Работа:** автоматизация тестирования мобильных клиентов (CI + Frida).
