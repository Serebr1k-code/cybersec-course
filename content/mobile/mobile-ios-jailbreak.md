---
id: mobile-ios-jailbreak
title: "Jailbreak-детект и его обход на iOS"
category: mobile
parent: mobile-ios-security
difficulty: hard
order: 3
tags: [ios, jailbreak, detection, bypass, frida, cycript, rootless]
prerequisites: [mobile-ios-basics, mobile-ios-dynamic]
useful_for:
  - "CTF Mobile (обход jailbreak-проверок)"
  - "Bug bounty (запуск защищённого iOS-приложения)"
  - "Пентест мобильных приложений"
estimated_minutes: 35
summary: "Как iOS-приложения детектируют jailbreak (файлы, fork, URL-схемы, sandbox-проверки) и как обходить эти проверки через Frida/Objection, включая rootless-джейлбрейки."
---
## Введение

Jailbreak-детект — это набор проверок, которыми iOS-приложение отказывается работать на скомпрометированном устройстве. Цель обхода — запустить защищённое приложение на джейлбрейк-устройстве, чтобы затем вести динамический анализ: обход SSL pinning, перехват криптоопераций, дамп памяти. Проверки бывают файловые, поведенческие, sandbox-проверки и проверки через URL-схемы; обход делается хуками на системные API, которые эти проверки используют, либо заменой высокоуровневого метода `isJailbroken`.

Важный принцип: не хукать «наугад». Сначала статикой найдите все места проверок, составьте их список, и только затем точечно нейтрализуйте каждую. Одна забытая проверка (например, `statfs`) снова уронит приложение.

## Что именно проверяет детект

- **Файлы:** `/Applications/Cydia.app`, `/bin/bash`, `/usr/sbin/sshd`, `/etc/apt`, `/private/var/lib/apt`, `/var/jb` (rootless), `/var/jb/usr/bin/...`.
- **fork():** на неджейлбрейке sandbox запрещает `fork` — если он работает, устройство скомпрометировано.
- **URL-схемы:** `canOpenURL:@"cydia://"` или `undecimus://`.
- **sandbox:** запись вне контейнера (`/private/`), проверка `statfs` на флаг `rw`.
- **Симлинки:** `/Applications` как симлинк.
- **getenv/dyld:** наличие Frida (`FridaGadget.dylib`, `frida-server`), подсчёт образов `_dyld_image_count`, проверка переменных окружения.
- **Свои обёртки:** метод `isJailbroken`/`isDeviceCompromised` в классе безопасности.

В декомпилированном коде ищите строки: `jailbroken`, `isJailbroken`, `Cydia`, `cydia://`, `fork`, `statfs`, `canOpenURL`, `substrate`, `MobileSubstrate`.

## Статический поиск проверок

```bash
# распаковать IPA
unzip app.ipa -d out
APP=out/Payload/*.app
# строки бинаря
strings -a "$APP/$(basename "$APP" .app)" | grep -iE "jail|cydia|substrate|fork|statfs|/var/jb" | sort -u
# если есть символы — class-dump покажет методы
class-dump -H "$APP/$(basename "$APP" .app)" -o headers/
grep -rn "jail" headers/ | head
```

Так вы получаете точный список проверок и класс, который их реализует. Часто всё собрано в один класс `SecurityChecks` или `JailbreakDetector`.

## Ручной обход через Frida

```javascript
// 1) файловые проверки
var NSFileManager = ObjC.classes.NSFileManager;
NSFileManager['- fileExistsAtPath:'].implementation =
  ObjC.implement(NSFileManager['- fileExistsAtPath:'], function (h, sel, path) {
    var p = new ObjC.Object(path).toString();
    if (p.indexOf('Cydia') !== -1 || p.indexOf('/var/jb') !== -1 ||
        p.indexOf('sshd') !== -1 || p.indexOf('/bin/bash') !== -1) return false;
    return h(path);
  });

// 2) canOpenURL для cydia://
var UIApp = ObjC.classes.UIApplication;
UIApp['- canOpenURL:'].implementation =
  ObjC.implement(UIApp['- canOpenURL:'], function (h, sel, url) {
    if (new ObjC.Object(url).toString().indexOf('cydia') !== -1) return false;
    return h(url);
  });

// 3) fork
var fork = Module.findExportByName(null, 'fork');
Interceptor.replace(fork, new NativeCallback(function () { return -1; }, 'int', []));

// 4) высокоуровневый метод приложения
var Cls = ObjC.classes.SecurityChecks;
if (Cls) {
  Cls['- isJailbroken'].implementation = function () { return false; };
}
```

## Objection: быстрый путь

```bash
objection -g com.target.app explore
# в консоли:
ios jailbreak disable
ios hooking list classes
ios hooking watch class SecurityChecks
```

Objection под капотом ставит те же хуки (fileExistsAtPath, canOpenURL, fork, Frida-детект) и часто достаточно, чтобы приложение запустилось.

## Rootless-джейлбрейки

Современные джейлбрейки (Dopamine, palera1n в rootless-режиме) используют префикс `/var/jb`, потому что системный раздел теперь read-only. Это отдельный класс проверок:

- `/var/jb/Applications/Cydia.app`;
- `/var/jb/usr/bin/...`;
- симлинк `/var/jb`.

Если в фильтре хука учитывать только классические пути — приложение всё равно определит rootless-джейлбрейк. Добавляйте `/var/jb` во все фильтры.

## Frida-детект и его обход

Приложение может искать Frida: имя процесса `frida-server`, загруженный образ `FridaGadget.dylib`, открытый порт 27042, специфичные строки в памяти. Обход:

```bash
# переименовать frida-server и сменить порт
mv /usr/sbin/frida-server /usr/sbin/frida-server-x
/usr/sbin/frida-server-x -l 0.0.0.0:6666
# подключение
frida -H 127.0.0.1:6666 -f com.target.app
```

Плюс хук на `_dyld_get_image_name`/`sysctl` (список процессов), чтобы скрыть артефакты, и на `getenv` для переменных окружения Frida.

## Разобранный пример

Приложение падает при запуске с сообщением «Jailbreak detected». Пентестер:

1. `class-dump` находит метод `-[SecurityChecks isJailbroken]`.
2. Хукает его: `Cls.isJailbroken.implementation = function(){ return false; }`.
3. Приложение запускается → можно переходить к SSL pinning и анализу API.

Если приложение использует несколько проверок, хук высокоуровневого метода покрывает все сразу — это самый эффективный путь.

## Частые ошибки и подводные камни

- Хукать только файловые проверки, забыв `fork`/`canOpenURL`/`statfs`.
- Не учитывать rootless-путь `/var/jb`.
- Прятать Frida частично: детект ловит и порт, и имя модуля, и переменные окружения.
- Хукать системный API, когда приложение использует свою обёртку — ищите `isJailbroken` в class-dump.
- Забывать, что детект может быть на уровне Swift (mangled-имена) — ищите `$s...jailbroken` в strings.

## Справочная таблица

| Проверка | API | Обход |
|----------|-----|-------|
| Файлы | `fileExistsAtPath:` | вернуть `false` |
| URL-схема | `canOpenURL:` | вернуть `false` |
| fork | `fork()` | `Interceptor.replace` → -1 |
| sandbox | `statfs` | подменить структуру |
| Симлинк | `lstat` | вернуть ошибку |
| Frida | `sysctl`/`dyld` | скрыть модуль/процесс |
| Обёртка | `isJailbroken` | вернуть `false` |

## Что дальше / решение

- **Обход удался** → переходите к SSL pinning bypass и анализу трафика.
- **Детект остался** → соберите все проверки (strings, class-dump) и захукайте каждую.
- **Frida палится** → переименуйте/перепортируйте, спрячьте модули.
- **Rootless** → добавьте `/var/jb` во все фильтры путей.
- Для отчёта: отсутствие детекта — не уязвимость; ценность в том, что вы получили доступ к анализу. Отдельно отметьте, если защита обходится тривиально (один хук), — это hardening-замечание.

## Swift-детект и mangled-имена

Современные приложения пишут детект на Swift, поэтому в `strings` имена выглядят как mangled-символы (`$s6Target14SecurityChecksC11isJailbrokenSbyF`). Ищите по подстрокам:

```bash
strings -a "$APP/$(basename "$APP" .app)" | grep -iE "jail|cydia|substrate|fork|statfs" | head
# Swift-метод можно восстановить
xcrun swift-demangle '$s6Target14SecurityChecksC11isJailbrokenSbyF'
# -> Target.SecurityChecks.isJailbroken() -> Swift.Bool
```

Затем хукайте метод по demangled-имени:

```javascript
var Cls = ObjC.classes.SecurityChecks; // Swift-класс виден как ObjC
if (Cls && Cls['- isJailbroken']) {
  Cls['- isJailbroken'].implementation = function () { return false; };
}
```

## Инструментальная проверка: frida-trace

Чтобы быстро найти все срабатывающие проверки, используйте `frida-trace` и следите, какие API дергаются при старте:

```bash
frida-trace -U -f com.target.app \
  -i "statfs" -i "fork" -i "access" -i "lstat" \
  -m "-[NSFileManager fileExistsAtPath:]" \
  -m "-[UIApplication canOpenURL:]"
```

Тот API, что вызывается сразу при запуске и приводит к падению, — это и есть проверка. Дальше точечно её нейтрализуйте.

## Проверка устойчивости защиты

Оценивая качество детекта, задайте вопросы:

- Собраны ли проверки в одном месте или разбросаны (легче обойти централизованные)?
- Есть ли обфускация имён методов безопасности?
- Проверяется ли целостность самого детекта (анти-тампер)?
- Учитываются ли rootless-пути и Swift?
- Есть ли Frida-детект и серверная проверка устройства (attestation)?

Если защита снимается одним хуком `isJailbroken → false`, это hardening-замечание для отчёта: детект носит «косметический» характер.

## Квиз

```quiz
- question: "Почему работающий fork() указывает на джейлбрейк?"
  options:
    - "На неджейлбрейк-устройстве sandbox запрещает fork"
    - "fork шифрует данные"
    - "fork нужен для TLS"
    - "fork есть только в Cydia"
  answer: 0
  explanation: "App sandbox на чистом iOS не разрешает fork."
- question: "Какой путь характерен для rootless-джейлбрейка?"
  options:
    - "/var/jb"
    - "/etc/passwd"
    - "/tmp"
    - "/private/var/mobile"
  answer: 0
  explanation: "Rootless-джейлбрейки используют префикс /var/jb."
- question: "Какой API проверяет доступность схемы cydia://?"
  options:
    - "canOpenURL:"
    - "fileExistsAtPath:"
    - "fork()"
    - "statfs()"
  answer: 0
  explanation: "UIApplication canOpenURL: проверяет, зарегистрирована ли схема."
- question: "Как скрыть frida-server от простого детекта?"
  options:
    - "Переименовать бинарь и сменить порт"
    - "Удалить приложение"
    - "Включить Wi-Fi"
    - "Переустановить iOS"
  answer: 0
  explanation: "Детект по имени процесса/порту 27042 обходится переименованием и сменой порта."
- question: "Что делает Objection для iOS-детекта?"
  options:
    - "ios jailbreak disable — ставит хуки на проверки"
    - "Удаляет Cydia"
    - "Перезагружает устройство"
    - "Шифрует IPA"
  answer: 0
  explanation: "Команда автоматически хукает файловые/fork/URL проверки."
```

## Где пригодится

- **CTF Mobile:** запуск защищённого приложения для доступа к флагу.
- **Bug bounty:** обход детекта — необходимый шаг перед анализом защищённого клиента.
- **Пентест:** подготовка среды динамического анализа iOS.
- **Работа:** оценка устойчивости клиента к скомпрометированной среде.
