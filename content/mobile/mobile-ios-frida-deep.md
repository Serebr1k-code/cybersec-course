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
