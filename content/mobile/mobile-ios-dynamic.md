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
## Динамический анализ iOS: что и зачем

Статический анализ даёт карту, но проверки (jailbreak, pinning, anti-debug), секреты, вычисляемые в рантайме, и логика, размазанная по фреймворкам, видны только в динамике. Динамический анализ iOS — это запуск приложения на **jailbreak-устройстве** (или симуляторе, но там нет jailbreak-проверок и Keychain ведёт себя иначе) с инструментами: Frida (хуки ObjC/Swift/native), LLDB (отладка, breakpoints, память), `frida-ios-dump` (дешифровка), `objection` (готовые команды).

Ментальная модель: у вас есть возможность **изменять поведение** приложения в рантайме — подменять возвраты проверок, читать аргументы методов, вызывать методы, дампить память. Задача — найти проверку и снять её, либо извлечь данные.

## Подготовка устройства

```bash
# jailbreak (palera1n/unc0ver/dopamine в зависимости от версии iOS)
# SSH на устройство (обычно root@<ip>, пароль alpine)
ssh root@192.168.1.50

# установить frida-server (версия = версии frida-tools на хосте)
# через Cydia/Sileo пакет "frida", либо вручную:
scp frida-server-16.x-ios-arm64 root@192.168.1.50:/usr/sbin/frida-server
ssh root@192.168.1.50 'chmod +x /usr/sbin/frida-server && /usr/sbin/frida-server &'

frida-ps -Uai        # видим приложения iOS
frida-ps -U | grep -i target
```

Если jailbreak нет, но есть dev-подпись — можно отлаживать своё приложение через Xcode/LLDB, но проверки jailbreak на нём не сработают (их нет в среде).

## Frida на iOS: ObjC API

```javascript
if (ObjC.available) {
  // список классов
  var classes = ObjC.classes;
  // хук ObjC-метода: -[AuthManager getToken]
  var m = ObjC.classes.AuthManager['- getToken'];
  Interceptor.attach(m.implementation, {
    onLeave: function (retval) {
      console.log('[+] getToken -> ' + new ObjC.Object(retval));
    }
  });
  // хук метода с аргументами: -[LoginVC loginWithUser:pass:]
  var login = ObjC.classes.LoginVC['- loginWithUser:pass:'];
  Interceptor.attach(login.implementation, {
    onEnter: function (args) {
      console.log('user=' + new ObjC.Object(args[2]));
      console.log('pass=' + new ObjC.Object(args[3]));
    }
  });
}
```

Для ObjC номер аргумента смещён: `args[0]` = self, `args[1]` = selector, далее параметры. `new ObjC.Object(ptr)` разыменовывает объект. Frida на iOS — основной инструмент обхода проверок.

## LLDB: отладка, breakpoints, память

```bash
# запуск под LLDB (нужен debugserver на устройстве или Xcode)
lldb -n App
(lldb) process attach --name App
(lldb) breakpoint set -n "-[AuthManager isJailbroken]"
(lldb) breakpoint command add 1 -o "thread return NO"   # всегда возвращать false
(lldb) continue
(lldb) image lookup -rn getToken                        # найти адреса методов
(lldb) memory read --format s 0x104abc000               # читать строку
(lldb) register read x0                                 # возврат функции
```

`thread return` — мощный приём: заставляет функцию вернуть нужное значение, не выполняя тело. Так обходят jailbreak/pinning-проверки.

## Cycript и альтернативы

Cycript (устарел, но встречается в старых гайдах) позволял интерактивно вызывать ObjC из консоли. Сейчас его место заняли Frida и Objection. Objection даёт готовые команды:

```bash
objection -g com.target.app explore
ios jailbreak disable
ios sslpinning disable
ios keychain dump
ios nsuserdefaults get
ios cookies get
ios ui biometrics_bypass
```

Это самый быстрый путь для типовых задач; Frida — когда нужна нестандартная логика.

## Хуки ObjC-методов: практика

```javascript
// подмена возврата проверки
var J = ObjC.classes.JailbreakDetector['- isJailbroken'];
J.implementation = function () { return false; };   // всегда "нет jailbreak"

// перехват и модификация аргументов
var Enc = ObjC.classes.CryptoUtil['+ encrypt:withKey:'];
Enc.implementation = function (data, key) {
  console.log('key=' + new ObjC.Object(key));
  return this.encrypt_withKey_(data, key);
};
```

Именование селекторов: `- encrypt:withKey:` → JS `encrypt_withKey_`. Возврат ObjC-объекта — `ObjC.Object`; для bool используйте `ptr(0)`/`ptr(1)` при необходимости.

## Перехват Swift и нативного кода

Swift-методы в ObjC-runtime видны, только если помечены `@objc` (или класс наследует NSObject и метод экспонирован). Иначе ищите по манглированному имени:

```javascript
// найти символ через Module
var sym = Module.findExportByName(null, '$s6MyApp9AuthClassC8getTokenSSyF');
if (sym) Interceptor.attach(sym, {
  onLeave: function (rv) { console.log('ret=' + rv.readUtf8String()); }
});
// нативные функции — как на Android: Module/Interceptor/NativeFunction
```

Для Swift полезна связка статики (`swift-demangle` даёт имя символа) и динамики (attach по этому символу).

## Обход jailbreak и pinning

- **jailbreak-детект:** хуки на `FileManager.fileExistsAtPath:` (`/bin/bash`, `/Applications/Cydia.app`), `stat`, `fork`, `canOpenURL:cydia://`, `NSFileManager`. Проще — `objection ios jailbreak disable` или `thread return NO` в LLDB.
- **pinning:** хук на `SecTrustEvaluate`, `URLSession:didReceiveChallenge:`, `AFSecurityPolicy`. Objection `ios sslpinning disable` покрывает типовые.
- **anti-debug:** `ptrace(PT_DENY_ATTACH)`, `sysctl` (`P_TRACED`). Обходится хуком на `ptrace`/`sysctl`.

## Разобранный пример: обход jailbreak и чтение Keychain

```bash
$ objection -g com.target.app explore
com.target.app # ios jailbreak disable
(agent) [jailbreak] Hooking NSFileManager.fileExistsAtPath:
(agent) [jailbreak] Hooking canOpenURL:
(agent) [jailbreak] Hooking sysctl
com.target.app # ios keychain dump
{
  "svce": "com.target.app", "acct": "sessionToken",
  "data": "eyJhbGciOiJIUzI1NiIsInR5cCI6..."
}
com.target.app # ios cookies get
```

Приложение «поверило», что устройство чистое, а мы вытащили токен из Keychain. Это типичный сценарий динамического теста iOS.

## Справочная таблица инструментов

| Задача | Инструмент | Команда/API |
|--------|-----------|-------------|
| Хук ObjC | Frida | `ObjC.classes.C['- m'].implementation` |
| Отладка | LLDB | `breakpoint set`, `thread return` |
| Готовые команды | Objection | `ios sslpinning disable` |
| Дешифровка | frida-ios-dump | `python3 dump.py com.target.app` |
| Keychain | Objection | `ios keychain dump` |
| Нативные хуки | Frida | `Module.findExportByName` |
| Обход anti-debug | LLDB/Frida | хук `ptrace`/`sysctl` |

## Типовые ошибки новичка

- **Работать на симуляторе.** Там нет jailbreak-проверок и часть Keychain/Security API ведёт себя иначе.
- **Не совпасть версиями Frida.** Как на Android: server и tools должны совпадать.
- **Забыть про Swift.** ObjC-хук не поймает чистый Swift-метод — нужен attach по символу.
- **Путать `args[]` в ObjC.** `args[0]=self`, `args[1]=selector`, параметры с `args[2]`.
- **Считать, что `thread return` всегда работает.** На некоторых функциях нужен корректный тип возврата.

## Что дальше / решение

Порядок: подготовить jailbreak + frida-server → `frida-ps` → Objection для типовых обходов (jailbreak, pinning) → Frida/LLDB для нестандартных проверок и дампа данных → трафик (`mobile-mitm-burp`). Связанные уроки: `mobile-ios-basics`, `mobile-ios-static` (карта классов), `mobile-ios-keychain`, `mobile-frida-scripting`. Решение — когда проверка обойдена или данные (токен/флаг) извлечены воспроизводимо.

## Практический чек-лист iOS-динамики

1. Jailbreak + `frida-server` совпадающей версии; `frida-ps -Uai` видит приложение.
2. `objection -g <bundle> explore`, затем `ios jailbreak disable` и `ios sslpinning disable`.
3. Проверить трафик через прокси (`mobile-mitm-burp`) — читается ли HTTPS.
4. Найти интересные методы: `class-dump` (статика) → хук через Frida/Objection.
5. Снять проверки: `isJailbroken`, anti-debug (`ptrace`), целостность.
6. Извлечь данные: `ios keychain dump`, `ios nsuserdefaults get`, `ios cookies get`.
7. Дампнуть классы/память при необходимости (`ObjC.classes`, `memory search`).
8. Зафиксировать: команда + вывод + impact.

## Отличия от Android-динамики

На Android вы чаще пишете Java-хуки (`Java.use`), на iOS — ObjC-хуки (`ObjC.classes`) и нативные (`Interceptor.attach` по символу). Swift усложняет: часть методов не экспонирована в ObjC-runtime, и их приходится искать по манглированному символу. Отладка на iOS обычно через LLDB (`thread return`), на Android — через `jdwp`/Frida. Инструмент `objection` работает одинаково на обеих платформах, что удобно: команды `ios ...` и `android ...` симметричны. Общий принцип один: найти проверку в статике, снять её в динамике, извлечь данные.

## Квиз

```quiz
- question: "Какой инструмент подключается к iOS-процессу для хуков без пересборки?"
  options:
    - "Frida"
    - "jadx"
    - "apktool"
    - "binwalk"
  answer: 0
  explanation: "Frida перехватывает методы/функции в рантайме."
- question: "Каким LLDB-командой поставить точку останова на метод?"
  options:
    - "breakpoint set -n '-[Class method]'"
    - "run -x"
    - "image add"
    - "po $x0"
  answer: 0
  explanation: "breakpoint set -n задаёт breakpoint по имени символа."
- question: "Что делает objection ios sslpinning disable?"
  options:
    - "Хукает проверку сертификата, отключая pinning"
    - "Удаляет сертификат"
    - "Меняет TLS-версию"
    - "Шифрует трафик"
  answer: 0
  explanation: "Команда обходит pinning через хуки."
- question: "Зачем дампить память iOS-процесса?"
  options:
    - "Найти секреты/ключи в рантайме"
    - "Ускорить приложение"
    - "Подписать IPA"
    - "Сменить тему"
  answer: 0
  explanation: "В памяти могут быть ключи и токены, недоступные статически."
- question: "Почему iOS-динамику делают на джейлбрейке/Corellium?"
  options:
    - "Нужны привилегии для frida-server/debugserver"
    - "Так быстрее компилируется"
    - "Иначе нет Wi-Fi"
    - "Так требует Apple"
  answer: 0
  explanation: "Для инъекции и отладки нужны права на устройстве."
```

## Где пригодится

- **CTF Mobile:** обход защит и извлечение флага из рантайма.
- **Bug bounty:** перехват и анализ защищённого клиента.
- **Пентест:** динамический анализ iOS.
- **Работа:** reverse engineering и threat intel.
