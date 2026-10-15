---
id: mobile-ios-frida-deep
title: 'Frida на iOS deep: перехват методов и обход детекта'
category: mobile
parent: mobile-ios-reversing
difficulty: expert
order: 4
tags: [ios, frida, hooking, interceptor, objc, anti-frida, gadget]
prerequisites: [mobile-ios-cycript-deep, mobile-frida-tooling]
useful_for:
  - 'Динамический анализ iOS'
  - 'Реверс iOS-приложений'
  - 'Пентест мобильных приложений'
estimated_minutes: 48
summary: 'Как Frida перехватывает Objective-C-методы на iOS: attach и spawn, Interceptor и ObjC-мосты, чтение и подмена аргументов, обход детекта Frida и работа через Gadget без jailbreak.'
lab:
  kind: shell
  title: 'Практика: разбор Frida-хука'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, hook.js, frida_out.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`hook.js` — скрипт перехвата метода.'
    - 'Найди в логе возвращённое секретное значение.'
    - 'Рядом с ним — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Cycript показал, как подменить метод вручную. Но ручная работа не масштабируется: нужно
перехватывать десятки методов, логировать аргументы, менять возвращаемые значения и делать это
скриптом, который запускается одной командой. Для этого существует Frida. Разберём его на iOS
от подключения до обхода защиты от самого Frida.

## Наш пример: перехват проверки сертификата

Приложение проверяет подлинность сервера методом `-[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:]`.
Мы хотим перехватить его и всегда принимать сертификат. Этот метод и будет нашим сквозным
примером.

## Шаг 1: найти процесс и подключиться

Frida видит процессы на устройстве:

```bash
$ frida-ps -U | grep MyApp
1234  MyApp
```

`-U` — подключиться по USB. Теперь можно запустить скрипт в процесс:

```bash
$ frida -U -n MyApp -l hook.js
```

## Шаг 2: spawn против attach

**attach** цепляется к уже запущенному процессу — удобно, но ранняя инициализация уже прошла.
**spawn** запускает приложение под контролем Frida и останавливает его до старта, чтобы
перехватить всё с самого начала:

```bash
$ frida -U -f com.example.myapp -l hook.js --no-pause
```

Для проверок, которые случаются рано (root/jailbreak-детект), нужен именно spawn.

## Шаг 3: перехват Objective-C метода

Скрипт на JavaScript обращается к ObjC-мостам Frida:

```javascript
if (ObjC.available) {
  var cls = ObjC.classes.NSURLSessionDelegate;
  var m = cls['- URLSession:didReceiveChallenge:completionHandler:'];
  Interceptor.attach(m.implementation, {
    onEnter: function (args) {
      console.log('challenge intercepted');
    }
  });
}
```

`Interceptor.attach` ставит **хук** на реализацию метода. В `onEnter` мы получаем управление
до тела метода и можем логировать аргументы.

## Шаг 4: чтение и подмена аргументов

Аргументы доступны как `args[2]`, `args[3]` (первые два — self и селектор). Можно подменить
поведение, вызвав блок `completionHandler` с нужным решением:

```javascript
var cb = new ObjC.Block(args[4]);
cb.implementation(0, null); // всегда доверять
```

Так проверка сертификата обходится на уровне логики приложения, без правки бинарника.

## Шаг 5: обход детекта Frida

Приложение может искать Frida по открытым портам, именам библиотек или строкам в памяти.
Типичный детект — сканирование `/proc/self/maps` на `frida` или проверка порта 27042. Обход:

```javascript
Interceptor.attach(Module.findExportByName(null, 'strstr'), {
  onEnter: function (a) {
    this.s = a[0];
  },
  onLeave: function (r) {
    if (this.s.readUtf8String().indexOf('frida') >= 0) r.replace(ptr(0));
  }
});
```

Мы подменяем результат `strstr`, чтобы поиск слова `frida` ничего не находил. Существует
готовый скрипт `frida-detection-bypass`, который закрывает большинство известных проверок.

## Шаг 6: работа без jailbreak через Gadget

На не-jailbreak устройстве Frida внедряют как `FridaGadget.dylib`: библиотеку добавляют в
IPA, переподписывают и запускают. При старте Gadget ждёт подключения на порту и даёт тот же
функционал. Это возвращает нас к уроку про Mach-O: `otool -L` как раз покажет такой Gadget в
зависимостях.

## Что мы теперь знаем

- Frida перехватывает методы через `Interceptor.attach` без пересборки приложения.
- spawn ловит всё с начала, attach — то, что происходит сейчас.
- Аргументы и возвращаемые значения можно читать и подменять.
- Детект Frida обходится хуком на строковые проверки и порты.
- Gadget даёт Frida без jailbreak.

## Если не сработало

Если Frida не видит процесс, проверьте версию `frida-server` и архитектуру. Если приложение
падает при attach — это анти-хукинг; запускайте через spawn и хукайте детект до его срабатывания.
Если метод Swift, ищите его через `Module.enumerateSymbols` и `Swift`-мосты, а не по ObjC-имени.

## Частые вопросы

**Frida требует root?** На jailbreak — нет, frida-server работает от root. Без jailbreak —
через Gadget и переподпись.

**Чем Interceptor отличается от swizzling?** Interceptor работает на уровне нативной
реализации, swizzling — на уровне ObjC-таблицы; оба подменяют поведение.

**Можно ли логировать все методы класса?** Да, перебором `ObjC.classes` и `$ownMethods`.

## Устройство Interceptor: onEnter, onLeave и retval

`Interceptor.attach` даёт две точки управления. `onEnter` вызывается до тела функции: здесь читают аргументы из `args[]` и сохраняют нужные значения в `this`, чтобы использовать их позже. `onLeave` вызывается после возврата: здесь доступен результат в `retval` и можно его изменить.

```javascript
var f = Module.findExportByName(null, 'strcmp');
Interceptor.attach(f, {
  onEnter: function (a) {
    this.a = a[0].readUtf8String();
    this.b = a[1].readUtf8String();
  },
  onLeave: function (r) {
    console.log(this.a + ' vs ' + this.b);
    r.replace(ptr(0));   // притвориться, что строки равны
  }
});
```

Ключевые правила: в `onEnter` нельзя предполагать, что указатели валидны — проверяйте через `ptr().isNull()`. Аргументы-указатели читаются методами `readUtf8String()`, `readPointer()`, `readByteArray(len)`. В `onLeave` `retval` — объект типа `NativePointer`, и `replace` меняет возвращаемое значение. Для методов, возвращающих `BOOL`/`int`, замена на `ptr(1)` — типовой приём обхода проверок.

## Reference: часто используемый Frida API

| API | Назначение |
|-----|------------|
| `frida-ps -U` | список процессов |
| `frida -U -f ID -l s.js` | spawn + скрипт |
| `ObjC.classes` | все ObjC-классы |
| `ObjC.classes.X.$ownMethods` | методы класса |
| `Interceptor.attach(ptr, cb)` | хук на функцию |
| `Module.findExportByName(null, n)` | адрес экспорта |
| `Module.findBaseAddress('X')` | база модуля |
| `Memory.readUtf8String(p)` | чтение строки |
| `ObjC.implement(m, fn)` | подмена ObjC-метода |
| `NativeFunction(addr, ret, args)` | вызов нативной функции |

Этого набора достаточно для 90 % задач: найти класс/функцию, перехватить, прочитать аргументы, подменить результат.

## Полный скрипт обхода SSL-pinning

На iOS проверка сертификата чаще всего идёт через `SecTrustEvaluate` (C-API) или через делегат `NSURLSession`. Универсальный обход хукает C-функцию:

```javascript
var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
if (SecTrustEvaluate) {
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
    return 0;   // errSecSuccess
  }, 'int', ['pointer', 'pointer']));
}
```

`Interceptor.replace` полностью заменяет функцию: вместо оригинальной логики выполняется наш callback. `NativeCallback` описывает сигнатуру — возвращаемый тип и типы аргументов. Возврат `0` означает «доверять». Этот приём обходит проверку, даже если она реализована в нативном коде, а не в ObjC.

Для более сложных случаев хукают `-[NSURLSessionDelegate ...]`, `- [NSURLConnection ...]` и методы `AFNetworking`, подменяя политику доверия (`AFSecurityPolicy`).

## Swift-методы и мангалинг

Swift-классы, не унаследованные от `NSObject`, не видны в `ObjC.classes`. Их методы имеют «мангалированные» имена вида `$s6MyApp10UserSessionC9isPremiumSbyF`. Найти их можно так:

```javascript
Process.enumerateModules().forEach(function (m) {
  Module.enumerateSymbolsSync(m.name).forEach(function (s) {
    if (s.name.indexOf('isPremium') >= 0) console.log(s.name, s.address);
  });
});
```

Дальше хукают по адресу `Interceptor.attach(s.address, {...})`. Мангалинг (name mangling) — это кодирование типа и модуля в имя символа; его можно раскодировать утилитой `swift-demangle` или онлайн-сервисом. Для чистых Swift-методов ObjC-мосты не работают, поэтому приходится идти через символы и адреса.

## Обход детекта Frida: полный список

Приложение может проверять:

- **порт 27042** (стандартный порт frida-server) — переопределите порт (`frida-server -l 0.0.0.0:9999`);
- **строки «frida», «gum», «gadget» в памяти** — хук `strstr`/`memmem`;
- **наличие файлов** `/usr/sbin/frida-server`, `frida` в путях — хук `stat`/`open`;
- **потоки с именем frida** — переименование или хук `pthread_getname_np`;
- **ptrace-детект** — запуск через spawn и хук `ptrace`.

Универсальная стратегия: запускать через `spawn` и вешать хуки на все функции, которые могут вернуть «frida найдена», **до** того, как приложение до них дойдёт. Готовые скрипты (frida-detection-bypass, objection) покрывают большинство проверок.

## Логирование без остановки

Для массового исследования удобно логировать, а не подменять: перебрать все методы класса и повесить хук на каждый.

```javascript
var cls = ObjC.classes.UserSession;
cls.$ownMethods.forEach(function (name) {
  var m = cls[name];
  if (!m) return;
  Interceptor.attach(m.implementation, {
    onEnter: function (a) { console.log(name, 'called'); }
  });
});
```

Это даёт полную картину вызовов: видно порядок, частоту и аргументы. Такой «трейс» часто показывает, какой именно метод решает исход, и уже его можно подменить точечно.

## Если не сработало

- **Frida не видит процесс.** Проверьте, что `frida-server` запущен от root и совпадает по архитектуре с устройством; для не-jailbreak используйте Gadget.
- **Приложение падает при attach.** Это анти-хукинг. Запускайте через spawn и хукайте детект раньше его срабатывания.
- **Метод не находится.** Он может быть Swift, нативным или вызываться динамически. Ищите через символы и трассировку.
- **Хук не срабатывает.** Возможно, вызывается другая реализация (переопределённая в подклассе). Проверьте через `$ownMethods` подкласса.
- **Замена возврата не помогает.** Проверка дублируется на сервере или в другой функции. Ищите все точки проверки.

## Ограничения

Frida мощен, но заметен: детект-механизмы эволюционируют, и обход требует поддержки. На устройствах с сильной защитой (Secure Enclave, PAC) часть хуков усложняется. Кроме того, Frida меняет процесс в памяти — для форензики это неприемлемо, а для реверса идеально. Выбирайте инструмент по задаче.

## Стабилизация сессии и скриптов

Держите скрипты в отдельных файлах и подключайте их флагом `-l`, а не пишите в интерактивной консоли: так их можно версионировать и переиспользовать. Для длинных сессий включайте логирование в файл (`frida -o log.txt`), чтобы не терять вывод при обрыве. И помните, что после перезапуска приложения все хуки снимаются — скрипт нужно применять заново.

## Квиз

Проверь себя.

```quiz
- question: Что делает spawn при запуске Frida?
  options:
    - Запускает приложение и ждёт до старта кода
    - Удаляет приложение
    - Шифрует процесс
    - Меняет обои
  answer: 0
  explanation: spawn останавливает приложение в самом начале, чтобы успеть перехватить всё.
- question: Какая функция Frida ставит хук на метод?
  options:
    - Interceptor.attach
    - console.log
    - JSON.parse
    - require
  answer: 0
  explanation: Interceptor.attach перехватывает вызов реализации.
- question: Какие аргументы приходят в onEnter?
  options:
    - Строки
    - Массив args с регистрами вызова
    - Файлы
    - Сокеты
  answer: 1
  explanation: args содержит self, селектор и далее аргументы.
- question: Как обычно детектируют Frida?
  options:
    - По цвету экрана
    - По портам, именам библиотек и строкам в памяти
    - По языку системы
    - По батарее
  answer: 1
  explanation: Защита ищет следы frida-server и его строки.
- question: Что такое FridaGadget?
  options:
    - Игра
    - Библиотека Frida, внедряемая в приложение для работы без jailbreak
    - Сертификат
    - Язык программирования
  answer: 1
  explanation: Gadget даёт функционал Frida на обычном устройстве после переподписи.
```

## Куда дальше

Frida объединяет статику и динамику: он знает структуру и подменяет поведение на лету. Дальше
логично перейти к sideloading и переподписи — ведь именно так Frida Gadget и попадает на
устройство без jailbreak.

## Где пригодится

- Обход SSL-pinning и клиентских проверок в iOS-приложениях.
- Динамический анализ защищённых банковских и платёжных приложений.
- Автоматизация реверса и CTF Mobile.
