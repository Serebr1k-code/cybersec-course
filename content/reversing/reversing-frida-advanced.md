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
## Вопрос, с которого всё начинается

Ты разобрал crackme, нашёл функцию проверки лицензии — и хочешь посмотреть, что в неё приходит
в рантайме, не пересобирая программу. Или образец расшифровывает строку только в памяти, и статически
её не видно. Нужен инструмент, который **вклинивается в работающий процесс**, перехватывает вызовы и
меняет поведение на ходу.

Такой инструмент — **Frida**. Это фреймворк **динамической инструментации**: он внедряет в процесс
свою библиотеку (агент), а ты управляешь ею скриптом с хоста. Разберём его на живом примере.

## Наш пример

Соберём программу с проверкой лицензионного ключа: она сравнивает введённый ключ с секретом через
`strcmp` и печатает «licensed» или «trial».

```c
static int license_ok(const char *key){
    return strcmp(key, "LIC-FRIDA-2026") == 0;
}
int main(int argc, char **argv){
    puts(license_ok(argv[1]) ? "licensed" : "trial");
    return 0;
}
```

Проверяем обычное поведение:

```
$ ./lic LIC-FRIDA-2026
licensed
$ ./lic bad
trial
```

Задача: заставить программу напечатать «licensed» с неправильным ключом, **не трогая бинарник**.

## Шаг 1: как устроена Frida

Frida состоит из двух частей. **Клиент** (Python-скрипт на хосте) и **агент** (`frida-agent`,
внедряемая в процесс-цель библиотека). Агент исполняет JavaScript и даёт API: `Interceptor`,
`Stalker`, `Memory`, `Module`, `NativeFunction`, а для мобильных платформ — `Java` и `ObjC`. Связь
между ними — по каналу (локально, по TCP или USB для Android).

Есть два режима: **attach** (подключиться к уже запущенному процессу) и **spawn** (запустить процесс
под Frida, чтобы успеть перехватить код на самом раннем этапе). Для перехвата проверки лицензии нам
нужен `spawn` — программа должна быть под контролем с первой инструкции.

## Шаг 2: перехватываем strcmp через Interceptor

Главный API — `Interceptor.attach(target, callbacks)`. Ставим перехват на функцию `strcmp` и
печатаем её аргументы, а в `onLeave` подменяем возвращаемое значение на ноль (что для `strcmp`
означает «строки равны»):

```python
import frida, time
JS = """
var strcmp = Module.getGlobalExportByName("strcmp");
Interceptor.attach(strcmp, {
  onEnter: function (args) {
    console.log("[*] strcmp(" + args[0].readCString() + ", " + args[1].readCString() + ")");
  },
  onLeave: function (retval) {
    console.log("[*] retval = " + retval);
    retval.replace(ptr(0));       // притвориться, что строки равны
  }
});
"""
pid = frida.spawn(["./lic", "wrong"], stdio="inherit")
session = frida.attach(pid)
script = session.create_script(JS)
script.on("message", lambda m, d: print(m))
script.load()
frida.resume(pid)
time.sleep(1)
```

Запускаем с заведомо неверным ключом `wrong`:

```
$ python3 hook.py
licensed
[*] strcmp(wrong, LIC-FRIDA-2026)
[*] retval = 0x2b
```

Программа напечатала `licensed`, хотя ключ `wrong` — потому что наш хук вернул 0 из `strcmp`.
А в логе видно и настоящий секрет: `LIC-FRIDA-2026`. Это классический приём: перехватить сравнение
и подсмотреть ожидаемое значение.

Разберём колбэки. `onEnter` получает массив `args` — это указатели-аргументы (для x86-64 первые два
в `rdi`/`rsi`, для ARM64 — в `x0`/`x1`). `args[0].readCString()` читает строку по указателю.
`onLeave` получает `retval` — возвращаемое значение, которое можно **заменить** через
`retval.replace(...)`. Полная подмена функции делается через `Interceptor.replace(target,
NativeCallback)`, а снятие хука — `Interceptor.revert(target)`.

## Шаг 3: перехват внутренних функций по адресу

`strcmp` — экспортируемая функция из libc, её легко найти по имени. Но часто нужно перехватить
**свою** функцию, которая нигде не экспортирована. Тогда берут её адрес из символов или по смещению
от базы модуля:

```javascript
// по имени символа (если бинарник не stripped)
var target = DebugSymbol.fromName("license_ok").address;
// или по смещению от базы главного модуля
var base = Process.getModuleByName("lic").base;
var target = base.add(0x1136);
```

Дальше — тот же `Interceptor.attach`. Так перехватывают `check`, `decrypt`, генераторы ключей и
любые внутренние функции. Смещение берут из `objdump`/`rizin` заранее.

Продвинутые образцы умеют **детектировать Frida**: проверяют, не появился ли в процессе поток с
характерным именем, не лежит ли в памяти строка `frida-agent`, не открыт ли её порт. Против этого
используют переименование агента (`frida-server` с другим именем, `--runtime`), раннее подключение
через `spawn` (пока проверки ещё не сработали) или сборку собственного агента (gadget). Понимание
этого противостояния важно: Frida — мощный, но заметный инструмент.

## Шаг 4: трассировка инструкций через Stalker

`Interceptor` перехватывает вызовы, а **Stalker** идёт глубже: он инструментирует **каждую**
исполняемую инструкцию, строя трассу. Это нужно для разбора алгоритмов и ловли самомодификации:

```javascript
Stalker.follow(Process.getCurrentThreadId(), {
  transform: function (iterator) {
    var insn = iterator.next();
    console.log("0x" + insn.address.toString(16) + "  " + insn.mnemonic + " " + insn.opStr);
    iterator.keep();
  }
});
```

Вывод — поток инструкций:

```
0x7f23313b55f4  jmp 0x7f23313b5605
0x7f23313b5605  mov rdi, qword ptr [rbx + 0xa0]
```

Так видно, куда реально идёт исполнение (включая косвенные переходы, которых не видно статически).
Цена — сильное замедление: Stalker уместен на маленьком участке, а не на всей программе.

## Шаг 5: память, модули и мобильные платформы

Кроме перехвата, Frida даёт доступ к памяти и модулям: `Memory.readByteArray(addr, n)` читает
память (удобно снять расшифрованную строку), `Process.enumerateModules()` перечисляет загруженные
модули, `NativeFunction` вызывает функции внутри процесса. Типовой сценарий: программа расшифровывает
строку в буфер только в рантайме — ставим хук на функцию-дешифровщик, в `onLeave` читаем память по
указателю на результат и получаем открытый текст. На Android тот же принцип работает для
**Java**: `Java.perform(function(){ var C = Java.use("com.app.License"); C.check.implementation =
function(k){ ... }; })` — перехват метода по классу и имени. На iOS — через `ObjC`.

Именно поэтому Frida — основной инструмент анализа мобильных приложений: не нужно пересобирать APK,
достаточно перехватить метод и подменить его реализацию.

На Android перед работой на устройство кладут `frida-server` нужной архитектуры и запускают его:
`adb push frida-server /data/local/tmp/ && adb shell "chmod 755 /data/local/tmp/frida-server"`,
затем `adb shell "/data/local/tmp/frida-server &"`. После этого `frida-ps -U` показывает список
процессов на устройстве, а скрипт подключается к нужному приложению. Часто именно так ищут, например,
где приложение сравнивает пароль или проверяет лицензию.

## Что мы теперь знаем

- Frida — динамическая инструментация: клиент на хосте + агент в процессе, управляемый JavaScript.
- Режимы `spawn` (с самого начала) и `attach` (к запущенному процессу).
- `Interceptor.attach` даёт `onEnter` (аргументы) и `onLeave` (возврат, можно заменить).
- Внутренние функции ловят по `DebugSymbol.fromName` или по смещению от базы модуля.
- `Stalker` строит трассу всех инструкций — видно косвенные переходы.
- Для Android/iOS есть API `Java` и `ObjC` — перехват методов без пересборки.

## Квиз

Проверь себя.

```quiz
- question: 'Какой колбэк Interceptor.attach даёт доступ к возвращаемому значению функции?'
  options:
    - 'onLeave'
    - 'onEnter'
    - 'onReturn'
    - 'onExit'
  answer: 0
  explanation: 'onEnter получает аргументы, onLeave — retval, который можно заменить через replace.'
- question: 'Зачем использовать режим spawn вместо attach?'
  options:
    - 'Чтобы перехватить код с самого начала запуска, до его выполнения'
    - 'Чтобы ускорить программу'
    - 'Чтобы уменьшить размер бинарника'
    - 'Чтобы обойти ASLR'
  answer: 0
  explanation: 'spawn запускает процесс под Frida, поэтому ранний код тоже под контролем.'
- question: 'Что делает retval.replace(ptr(0)) в onLeave для strcmp?'
  options:
    - 'Подменяет результат на 0, то есть «строки равны»'
    - 'Печатает строку'
    - 'Ставит точку останова'
    - 'Завершает процесс'
  answer: 0
  explanation: 'strcmp возвращает 0 при равенстве строк; replace меняет возврат на ходу.'
- question: 'Чем Stalker отличается от Interceptor?'
  options:
    - 'Stalker инструментирует каждую инструкцию, Interceptor — вызовы функций'
    - 'Stalker работает только на Android'
    - 'Interceptor не умеет читать память'
    - 'Они полностью взаимозаменяемы'
  answer: 0
  explanation: 'Stalker даёт трассу инструкций (включая косвенные переходы), Interceptor — хуки вызовов.'
```

## Куда дальше

Frida — динамический инструмент: он перехватывает то, что реально исполнилось. В следующем уроке мы
посмотрим на **инструментацию ELF** — как встраивать свой код в бинарник статически (через
`LD_PRELOAD` и патчинг). А пока главное запомни: `spawn` + `Interceptor.attach` на функцию сравнения
плюс `retval.replace` — это самый быстрый способ обойти проверку, не трогая файл.

## Где пригодится

- **CTF Reversing:** обход проверок, вытаскивание секретов из рантайма.
- **Mobile:** перехват Java/ObjC-методов в Android/iOS без пересборки.
- **Malware analysis:** снятие расшифрованных строк, трассировка поведения.
