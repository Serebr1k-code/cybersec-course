---
id: mobile-ios-cycript
title: "Cycript и LLDB: runtime-интроспекция iOS"
category: mobile
parent: mobile-ios-advanced
difficulty: hard
order: 3
tags: [ios, cycript, lldb, debugserver, runtime, objc, introspection, hooking]
prerequisites: [mobile-ios-basics, mobile-ios-dynamic]
useful_for:
  - "Пентест мобильных приложений (iOS)"
  - "Bug bounty iOS"
  - "Реверс-инжиниринг iOS"
estimated_minutes: 50
summary: "Runtime-интроспекция iOS через Cycript (объекты, методы, вызовы) и отладку LLDB/debugserver: точки останова, чтение регистров, вызов ObjC-методов."
---
## Введение

Cycript — интерактивная среда для исследования запущенного iOS-приложения: вы подключаетесь к процессу и вызываете ObjC-методы «на живую», читаете объекты, ищете инстансы классов, меняете состояние. LLDB — полноценный отладчик, который цепляется к приложению через `debugserver` и даёт точки останова, регистры, память. Вместе они заменяют Frida в части интроспекции и позволяют быстро понять логику без статики.

Это «хирургия» по рантайму: вместо долгого реверса вы спрашиваете у приложения, что оно делает прямо сейчас. Требуется jailbreak (для системного Cycript/debugserver) либо подписанный debug-билд на устройстве.

## Cycript: основы

```bash
# подключиться к процессу по имени или PID
cycript -p TargetApp
# или
cycript -p 1234
```

Внутри сессии:

```javascript
// все классы, содержащие 'Login'
Object.keys(ObjectiveC.classes).filter(n => n.indexOf('Login') >= 0)

// найти живые инстансы класса
var arr = []; for (var i in *); if ([i isKindOfClass:NSClassFromString('LoginViewController')]) arr.push(i); arr

// вызвать метод
[LoginViewController sharedInstance]
[[UIApplication sharedApplication] keyWindow]
[[NSUserDefaults standardUserDefaults] dictionaryRepresentation]

// прочитать/записать свойство
[*LoginViewController sharedInstance].username
[*LoginViewController sharedInstance].setUsername_("admin")
```

Cycript выполняет JavaScript с ObjC-мостом — можно читать приватные ivar, вызывать методы, менять UI.

## Поиск и вызов методов

```javascript
// список методов класса
Object.keys(NSClassFromString('LoginViewController').prototype)

// вызов метода с аргументами (селектор: двоеточия -> подчёркивания)
var vc = [LoginViewController alloc].init
[vc loginWithUser_password_("admin", "admin123")]

// чтение Keychain через класс приложения
[KeychainWrapper load:@"sessionToken"]
```

Так находят методы валидации, обходят проверки (вызвать успешный путь) и извлекают секреты в рантайме.

## LLDB + debugserver

```bash
# на устройстве запустить debugserver и прикрепить к приложению
# на ПК:
lldb
(lldb) platform select remote-ios
(lldb) process connect connect://<device-ip>:1234
```

Основные команды:

```
(lldb) image list                     # список загруженных образов
(lldb) br set -n "-[LoginViewController login]"   # точка останова по символу
(lldb) br set -a 0x100003f20          # по адресу
(lldb) c                              # continue
(lldb) po $x0                         # печать ObjC-объекта (arg0)
(lldb) expr -l objc -O -- [self username]
(lldb) memory read $x0                # чтение памяти
(lldb) register read                  # все регистры (arm64: x0..x7 args)
(lldb) thread backtrace               # стек
```

Arm64 ABI: первые 8 аргументов — в `x0..x7`, `x0` — `self`, `x1` — `_cmd` (селектор). Для ObjC-метода `po $x0` покажет объект, а имя метода — `po (char*)$x1`.

## Полный сквозной пример: перехват проверки пароля

Цель: найти метод проверки логина и заставить вернуть `true`.

```bash
cycript -p TargetApp
cycript> Object.keys(ObjectiveC.classes).filter(n=>/Auth/.test(n))
# -> ["AuthManager"]
cycript> Object.keys(NSClassFromString('AuthManager').prototype)
# -> ["validateUser:password:", ...]
```

Ставим точку останова в LLDB:

```
(lldb) br set -n "-[AuthManager validateUser:password:]"
(lldb) c
# вводим неверный пароль в UI -> срабатывает брейк
(lldb) po $x2        # username
(lldb) po $x3        # password
(lldb) thread return 1   # принудительно вернуть YES (bool)
(lldb) c
# UI пускает дальше с неверным паролем
```

`thread return` — мощный приём: пропускает выполнение метода и возвращает заданное значение. Для обхода проверок это быстрее, чем патч бинарника.

## Чтение памяти и секретов

```
(lldb) expr -l objc -O -- [[NSUserDefaults standardUserDefaults] dictionaryRepresentation]
(lldb) expr -l objc -O -- [KeychainWrapper load:@"apiToken"]
(lldb) memory read -f x -c 32 $x0
```

LLDB может вызывать ObjC-выражения прямо в процессе, включая доступ к Keychain от имени приложения.

## Частые ошибки

- **`cycript` не видит процесс**: нужен jailbreak или отладочный билд; проверьте `get-task-allow`.
- **Точка останова не срабатывает**: символ обфусцирован/Swift-mangled — ставьте по адресу из `image lookup -rn`.
- **Не тот регистр**: забыли, что `x0` — self, `x1` — селектор; аргументы начинаются с `x2`.
- **`thread return` не работает**: метод возвращает сложный тип — используйте `expr` с явным типом.
- **debugserver не подключается**: порт/USB-туннель, проверьте `iproxy`.
- **Cycript устарел для Swift**: Swift-классы видны хуже; используйте Frida/LLDB с `po`.

## Что дальше / решение

Cycript/LLDB — быстрый способ обойти клиентские проверки и понять логику. Для скриптуемых и воспроизводимых обходов переходите на Frida (`mobile-ios-dynamic`). Свяжите с `mobile-ios-ssl-killswitch` (обход pinning) и `mobile-ios-keychain` (секреты). Дальше — `mobile-ios-data-protection`.

## Справочная таблица

| Задача | Cycript | LLDB |
|--------|---------|------|
| Список классов | `Object.keys(ObjectiveC.classes)` | `image lookup -rn` |
| Инстансы | цикл по `*` | `po` в точке останова |
| Вызвать метод | `[obj method]` | `expr -l objc --` |
| Точка останова | — | `br set -n` |
| Вернуть значение | — | `thread return` |
| Аргументы | — | `x0..x7` |

## Cycript: продвинутые приёмы

Помимо чтения объектов, Cycript умеет искать по иерархии и вызывать приватные методы:

```javascript
// найти все UIViewController в иерархии окна
function allVCs(vc, out) { out.push(vc); [vc.childViewControllers] && [vc.childViewControllers].forEach(function(c){ allVCs(c,out); }); return out; }
allVCs([[UIApplication sharedApplication] keyWindow].rootViewController, [])

// перебрать методы класса по префиксу
Object.keys(NSClassFromString('Crypto').prototype).filter(function(m){ return /encrypt|decrypt|key/.test(m); })

// прочитать приватные ivar
var inst = [Crypto sharedInstance];
inst->__cstring__  // пример ivar (зависит от класса)
```

Через `choose()` (встроенная функция) можно найти инстансы:

```javascript
choose(LoginViewController)     // массив живых инстансов
choose(NSURLSession)
```

## LLDB: условные точки останова и скрипты

```text
(lldb) br set -n "-[AuthManager validate:]" -c '($x2 != 0)'
(lldb) br command add 1
> po $x0
> po $x2
> thread return 1
> DONE
```

`br command add` позволяет на точке останова автоматически печатать аргументы и возвращать нужное значение — это «скриптовый» обход проверок без правки бинарника. Для Swift-функций ищите mangled-имя:

```text
(lldb) image lookup -rn "validate"
(lldb) br set -a 0x100004f20
```

## Автоматизация через Frida вместо Cycript

Cycript интерактивен, но не скриптуется в CI. Frida даёт то же, но воспроизводимо:

```javascript
Java.perform(function(){});  // на iOS не нужен
if (ObjC.available) {
  var inst = ObjC.chooseSync(ObjC.classes.AuthManager)[0];
  console.log(inst.username().toString());
  inst.validate_("admin");   // вызвать метод
}
```

Комбинация: разведка в Cycript (быстро), затем перенос находок в Frida-скрипт (воспроизводимо).

## Кейс: обход проверки лицензии

```bash
# 1. Разведка
cycript -p TargetApp
cycript> choose(LicenseManager)
cycript> Object.keys(NSClassFromString('LicenseManager').prototype)
# -> ["isValid", "checkReceipt:", ...]
cycript> [[LicenseManager sharedInstance] isValid]
# -> false
```

В LLDB:

```text
(lldb) br set -n "-[LicenseManager isValid]"
(lldb) c
(lldb) thread return YES
(lldb) c
# приложение считает лицензию валидной
```

В Frida (для отчёта):

```javascript
var m = ObjC.classes.LicenseManager["- isValid"];
Interceptor.attach(m.implementation, { onLeave: function(r){ r.replace(ptr(1)); } });
```

## Ограничения инструментов

- **Cycript устарел** для новых iOS/Swift; часть классов не видна. Используйте Frida/LLDB.
- **Swift name mangling** усложняет поиск по символам — ищите по адресу или demangle.
- **Anti-debug** (`PT_DENY_ATTACH`, `ptrace`) может блокировать LLDB — обходите хуком `ptrace`.
- **`thread return`** не работает для методов, возвращающих структуры — используйте `expr`.
- **Jailbreak-требование**: без него ни Cycript, ни системный debugserver недоступны.
- **Скорость**: LLDB-брейки замедляют приложение — используйте условные точки.

## Сводная таблица приёмов

| Задача | Cycript | LLDB | Frida |
|--------|---------|------|-------|
| Найти класс | `choose()` | `image lookup` | `ObjC.classes` |
| Прочитать ivar | `inst->ivar` | `po` | `.value` |
| Вызвать метод | `[obj m]` | `expr` | `obj.m()` |
| Обойти проверку | вызвать успешный путь | `thread return` | `onLeave replace` |
| Скриптуемость | нет | частично | да |

## Практикум: обход проверки через LLDB

Разберём конкретный обход лицензии/проверки.

```bash
# подключение
lldb
(lldb) platform select remote-ios
(lldb) process connect connect://<ip>:1234
# находим метод
(lldb) image lookup -rn "isValid"
# ставим точку останова
(lldb) br set -n "-[LicenseManager isValid]"
(lldb) c
```

Когда брейк срабатывает (при запуске/проверке):

```text
(lldb) po $x0          # self
(lldb) po (char*)$x1   # selector
(lldb) thread return YES
(lldb) c
```

Приложение считает лицензию валидной. Для воспроизводимости переносим в Frida:

```javascript
var m = ObjC.classes.LicenseManager["- isValid"];
Interceptor.attach(m.implementation, { onLeave: function(r){ r.replace(ptr(1)); } });
```

Так обход становится скриптуемым и документируемым. Фиксируйте метод, аргументы и результат в отчёте.

## Продвинутая отладка Swift и работа с блоками

Современные iOS-приложения на Swift усложняют отладку: имена функций mangled, структуры передаются иначе. В LLDB ищите по demangled-имени (`image lookup -rn "validate"`), ставьте брейки по адресу, используйте `expr` с явными типами. Для Swift-методов соглашение вызова отличается от ObjC: `self` может быть в `x20`/`x22` (в зависимости от контекста), а не в `x0`. Практично ставить брейк и смотреть регистры через `register read`.

Блоки (closures) — важная часть iOS. В ObjC-блоках `completion` из challenge-обработчика можно перехватить и вызвать со своими аргументами (см. обход pinning). В Frida используйте `ObjC.Block` для работы с блоками. Это ключ к обходу асинхронных проверок.

## Работа с Swift-строками и типами

Swift-строки не C-строки; чтение через `po` в LLDB работает, но в Frida нужно знать layout. Для простых случаев хватает `ObjC`-моста (Swift-классы, наследующие NSObject, видны). Для чистого Swift — сложнее, используйте LLDB.

## Практический сценарий

Проверка лицензии в Swift: находим mangled-символ, ставим брейк, смотрим возврат, меняем через `thread return`. Для воспроизводимости — Frida-хук, если метод доступен через ObjC runtime, иначе патч бинарника (сложнее из-за подписи). Часто проще найти точку вызова и обойти её.

## Что писать в отчёте

Для каждой обойдённой проверки: метод, аргументы, способ обхода (LLDB/Frida/патч), влияние. Рекомендации: дублировать проверки на сервере, не полагаться на клиентскую логику, использовать App Attest.

## Квиз

```quiz
- question: "Что делает `thread return 1` в LLDB?"
  options:
    - "Прерывает метод и возвращает 1, пропуская тело"
    - "Завершает процесс"
    - "Печатает стек"
    - "Читает память"
  answer: 0
- question: "Какой регистр содержит self в ObjC-методе на arm64?"
  options:
    - "x1"
    - "x0"
    - "x2"
    - "sp"
  answer: 1
- question: "Для чего нужен Cycript?"
  options:
    - "Runtime-интроспекция ObjC-объектов в запущенном приложении"
    - "Статическая декомпиляция"
    - "Сетевой анализ"
    - "Создание бэкапа"
  answer: 0
- question: "Как преобразуется селектор `loginWithUser:password:` при вызове в Cycript?"
  options:
    - "loginWithUser:password:"
    - "loginWithUser_password_"
    - "loginWithUserPassword"
    - "loginWithUser->password"
  answer: 1
- question: "Что нужно для подключения LLDB к приложению на устройстве?"
  options:
    - "debugserver и (jailbreak/отладочная подпись)"
    - "Только Wi-Fi"
    - "Только Burp"
    - "Keychain"
  answer: 0
```

## Где пригодится

- **Пентест iOS:** быстрый обход клиентских проверок.
- **Bug bounty:** демонстрация обхода логина/лицензии.
- **Реверс:** понимание рантайм-логики без полного реверса.
- **CTF:** Mobile/iOS-задачи с runtime-проверками.
