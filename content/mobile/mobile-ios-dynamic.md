---
id: mobile-ios-dynamic
title: "iOS dynamic analysis: Frida, LLDB и runtime-хуки"
category: mobile
parent: mobile-ios-analysis
difficulty: expert
order: 2
tags: [ios, dynamic, frida, lldb, debugserver, hooking, runtime, objc]
prerequisites: [mobile-ios-basics, mobile-ios-static]
useful_for:
  - "CTF Mobile (хук проверок в iOS)"
  - "Bug bounty (обход pinning/jailbreak на iOS)"
  - "Пентест мобильных приложений"
estimated_minutes: 45
summary: "Динамический анализ iOS: Frida-хуки на Objective-C/Swift, LLDB/debugserver, обход jailbreak/pinning, дамп памяти и трассировка в рантайме."
---

## Вопрос, с которого всё начинается

Статический анализ дал карту: мы знаем, что в `DemoApp` есть метод `isJailbroken` и функция `getToken`. Но приложение отказывается работать на jailbreak-устройстве, а токен вычисляется в рантайме и нигде не лежит в виде строки. Как увидеть и изменить поведение приложения, когда оно уже запущено?

Ответ — **динамический анализ**: мы подключаемся к живому процессу и вмешиваемся в его работу.

## Наш пример: DemoApp на устройстве

Наш объект — тот же `DemoApp`, но теперь он установлен на jailbreak-устройстве. Сразу оговоримся: без jailbreak динамика почти невозможна — нельзя встроиться в чужой процесс. Поэтому первая предпосылка — устройство с jailbreak и установленный `frida-server` (серверная часть Frida, которая работает на телефоне).

Проверим, что инструменты на месте:

```
$ frida --version
17.23.3
$ frida-ps -Uai | grep -i demo
PID  Name        Identifier
1234 DemoApp     com.demo.secapp
```

Флаг `-U` означает USB-устройство, `-a` — показывать приложения, `-i` — их идентификаторы. Мы видим, что приложение установлено и готово к работе.

## Шаг 1: Objection — готовые обходы

Писать хуки с нуля долго, поэтому начинают с **Objection** — надстройки над Frida с готовыми командами для типовых задач:

```
$ objection -g com.demo.secapp explore
com.demo.secapp on (iPhone: 17.4) [usb] #
```

Мы внутри интерактивной сессии. Первым делом снимем проверку jailbreak:

```
com.demo.secapp # ios jailbreak disable
(agent) Hooking jailbreak detection
(agent) Found 3 jailbreak detection methods
```

Objection нашёл и перехватил методы проверки. Теперь приложение считает, что запущено на чистом устройстве. Второй типовой обход — снятие привязки к сертификату (pinning):

```
com.demo.secapp # ios sslpinning disable
(agent) Hooking SecTrustEvaluate
```

После этого трафик можно перехватывать через прокси (см. `mobile-mitm-burp`).

## Шаг 2: что происходит внутри

Objection — это удобная обёртка, но чтобы понять механизм, посмотрим на «сырой» Frida. Хук на Objective-C метод выглядит так:

```javascript
if (ObjC.available) {
  var m = ObjC.classes.AuthManager['- isJailbroken'];
  Interceptor.attach(m.implementation, {
    onLeave: function (retval) {
      retval.replace(0);   // 0 = NO (не джейлбрейкнут)
    }
  });
}
```

Разберём по частям. `ObjC.classes.AuthManager` — обращение к классу из runtime. `'- isJailbroken'` — селектор метода (минус означает метод экземпляра, плюс — метод класса). `Interceptor.attach` ставит перехват на реализацию метода, а `onLeave` меняет возвращаемое значение: `retval.replace(0)` заставляет метод вернуть «нет». Именно это и делает `ios jailbreak disable`, только автоматически.

## Шаг 3: дампим секреты из рантайма

Теперь вытащим токен. Мы знаем из статики, что есть метод `getToken`:

```javascript
var t = ObjC.classes.AuthManager['- getToken'];
Interceptor.attach(t.implementation, {
  onLeave: function (retval) {
    console.log('token = ' + new ObjC.Object(retval));
  }
});
```

Когда приложение вызовет `getToken`, в консоль упадёт значение. `new ObjC.Object(retval)` оборачивает указатель в объект Objective-C, чтобы прочитать строку.

Извлечь данные можно и готовыми командами Objection:

```
com.demo.secapp # ios keychain dump
com.demo.secapp # ios nsuserdefaults get
com.demo.secapp # ios cookies get
```

Первая читает Keychain, вторая — настройки (`NSUserDefaults`), третья — cookies. Это три самых частых места, где приложение хранит сессию.

## Шаг 4: Swift и нативный код

Если метод написан на Swift, он может не быть виден через `ObjC.classes`. Тогда его ищут по манглированному символу и перехватывают нативно:

```javascript
var sym = Module.findExportByName(null, '$s6DemoApp11AuthManagerC8getTokenSSyF');
if (sym) {
  Interceptor.attach(sym, {
    onLeave: function (retval) {
      console.log('swift token: ' + new ObjC.Object(retval));
    }
  });
}
```

`Module.findExportByName(null, ...)` ищет символ во всех загруженных модулях. Если Swift-метод не экспортирован, его адрес находят иначе — через анализ дизассемблера и базовый адрес модуля.

## Шаг 5: LLDB — отладчик

Когда хука недостаточно (например, нужно понять, откуда пришло значение), подключают **LLDB** — отладчик:

```
$ lldb -n DemoApp
(lldb) breakpoint set -n '-[AuthManager isJailbroken]'
(lldb) process attach --name DemoApp
(lldb) thread return NO
```

`breakpoint set -n` ставит точку останова на метод, `process attach` подключается к процессу, а `thread return NO` принудительно возвращает «нет» из текущего кадра. LLDB удобен для точечного вмешательства, Frida — для повторяемых хуков.

## Шаг 6: если jailbreak нет

Иногда устройство не джейлбрейкнуть (новая версия iOS). Тогда применяют **frida-gadget**: нативную библиотеку, которую встраивают в IPA, переподписывают и ставят через sideload. Инструмент `objection patchipa` делает это автоматически:

```
$ objection patchipa --source DemoApp.ipa --codesign-signature <identity>
```

После этого приложение содержит Frida внутри себя и работает даже без jailbreak. Минус — меняется подпись, и tamper-проверки могут это заметить.

## Шаг 7: чем iOS-динамика отличается от Android

Полезно сравнить, потому что инструменты симметричны, а детали разные. На Android хуки пишут на Java (`Java.use`), на iOS — на Objective-C (`ObjC.classes`) или нативно (`Interceptor.attach` по символу). На Android отладка идёт через `jdwp`/Frida, на iOS — обычно через LLDB. Платформенная разница ещё и в том, что на iOS без jailbreak нельзя встроиться в чужой процесс, а на Android достаточно debuggable-сборки или root. Зато `objection` работает одинаково на обеих платформах: команды `ios ...` и `android ...` делают аналогичные вещи. Общий принцип один: найти проверку в статике — снять её в динамике — извлечь данные.

## Шаг 8: версии — частая причина «не подключается»

Прежде чем винить приложение, сверь версии Frida на хосте и `frida-server` на устройстве — они обязаны совпадать:

```
$ frida --version
17.23.3
```

Если билды разошлись, Objection падает с ошибкой вида `unable to connect to remote frida-server`. Список процессов на устройстве смотрят командой `frida-ps -U`: флаг `-U` выбирает USB-устройство. Пустой вывод означает, что `frida-server` не запущен (или не совпал по версии/архитектуре) — это не проблема приложения.

Второй подводный камень — PAC на `arm64e`: указатели подписаны, и часть хуков в нативном/Swift-коде требует `Module.findBaseAddress` и аккуратной работы с указателями. Если скрипт «молчит» на релизной сборке, сначала проверь, что процесс действительно 64-битный и что библиотека уже загружена в момент установки хука.

## Что мы теперь знаем

- Динамика iOS требует jailbreak (или frida-gadget в переподписанном IPA).
- Objection даёт готовые команды: `ios jailbreak disable`, `ios sslpinning disable`, `ios keychain dump`.
- Хук ObjC-метода — это `Interceptor.attach` с изменением возврата в `onLeave`.
- Swift-методы перехватывают по манглированному символу.
- LLDB позволяет ставить точки останова и принудительно менять возврат.
- Keychain, NSUserDefaults и cookies — три главных источника секретов.

## Квиз

Проверь себя.

```quiz
- question: Что делает команда `objection ios jailbreak disable`?
  options:
    - "Удаляет jailbreak"
    - "Перехватывает методы детекта jailbreak и заставляет их вернуть «нет»"
    - "Перезагружает устройство"
    - "Собирает IPA"
  answer: 1
  explanation: "Objection автоматически находит и хукает проверки jailbreak."
- question: Что означает `retval.replace(0)` в хуке?
  options:
    - "Удаляет метод"
    - "Подменяет возвращаемое значение метода на 0 (NO)"
    - "Меняет аргументы"
    - "Ставит точку останова"
  answer: 1
  explanation: "onLeave меняет возврат; 0 = ложь, поэтому детект «не срабатывает»."
- question: Почему Swift-методы сложнее перехватывать через ObjC.classes?
  options:
    - "Они зашифрованы"
    - "Часть методов не экспонирована в ObjC-runtime, их ищут по манглированному символу"
    - "Swift не поддерживает хуки"
    - "Они всегда приватные"
  answer: 1
  explanation: "Swift-методы могут отсутствовать в ObjC-runtime; используют нативные символы."
- question: Какая команда Objection дампит Keychain?
  options:
    - "ios nsuserdefaults get"
    - "ios keychain dump"
    - "ios cookies get"
    - "ios jailbreak disable"
  answer: 1
  explanation: "ios keychain dump читает содержимое Keychain приложения."
- question: Что такое frida-gadget?
  options:
    - "Прокси-сервер"
    - "Нативная библиотека Frida, встроенная в IPA для работы без jailbreak"
    - "Формат plist"
    - "Отладчик LLDB"
  answer: 1
  explanation: "Gadget встраивают в приложение и переподписывают, чтобы инструментировать без jailbreak."
```

## Куда дальше

Мы научились вмешиваться в работу приложения. Но секреты часто утекают не только через Keychain — их можно «увести» через URL-схемы. В следующем уроке разберём, как приложение открывается по ссылкам и почему это опасно. А пока главное запомни: динамика iOS — это Objection для типовых обходов и Frida/LLDB для нестандартных.

## Где пригодится

- **Пентест:** обход jailbreak- и pinning-проверок, дамп секретов.
- **Bug bounty:** демонстрация обхода защиты на реальном устройстве.
- **Анализ малвари:** наблюдение за поведением iOS-образца в рантайме.
- **CTF:** извлечение флага из Keychain или вычисляемого токена.
