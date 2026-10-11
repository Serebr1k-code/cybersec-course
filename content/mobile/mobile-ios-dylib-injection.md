---
id: mobile-ios-dylib-injection
title: "Инъекция dylib в iOS-приложение: re-sign и DYLD_INSERT_LIBRARIES"
category: mobile
parent: mobile-advanced-ios
difficulty: expert
order: 3
tags: [mobile, ios, dylib, injection, resign, frida, codesign]
prerequisites: [mobile-ios-ipa-analysis, mobile-ios-dynamic]
useful_for:
  - "CTF Mobile: инструментация без джейлбрейка"
  - "Пентест iOS: hooking и перехват методов"
estimated_minutes: 50
summary: "Как внедрить свою динамическую библиотеку в iOS-приложение: LC_LOAD_DYLIB, DYLD_INSERT_LIBRARIES, сборка dylib, re-sign через codesign, запуск на устройстве и симуляторе, обход проверок подписи."
---

## Зачем инжектить dylib

Frida на iOS требует джейлбрейка (или специальной сборки приложения с FridaGadget). Инъекция собственной dylib — более «природный» способ инструментации: вы добавляете библиотеку прямо в IPA, пересобираете и подписываете его своим сертификатом. Приложение загружает ваш код как обычную зависимость, и он выполняется в том же процессе с теми же правами. Это то, чем пользуются `objection` (через `patchipa`), `frida-ios-dump` и коммерческие инструменты.

Плюсы: работает без джейлбрейка (на устройстве разработчика или симуляторе), код грузится до `main`, можно перехватывать всё. Минусы: приложение надо переустановить, подпись меняется (приложение может это детектить), часть защит (биометрическая привязка, App Attest) ломается.

## Три способа загрузки библиотеки

1. **`LC_LOAD_DYLIB`** — добавляем запись в load commands бинарника, чтобы dyld грузил нашу dylib при старте. Используется `insert_dylib` или `optool`.
2. **`DYLD_INSERT_LIBRARIES`** — переменная окружения; работает, если бинарник не имеет `LC_MAIN`-специфичных ограничений и не hardened. На iOS переменную можно задать через `get-task-allow`-профиль или в отладочной сборке.
3. **Перепаковка через `objection patchipa`** — objection сам добавляет gadget-dylib и подписывает.

Первый способ самый надёжный для re-sign, потому что не зависит от окружения запуска.

## Сборка своей dylib

Пример dylib на Objective-C, которая хукает метод и логирует вызов:

```objc
// Inject.m
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

__attribute__((constructor))
static void init(void) {
    NSLog(@"[Inject] dylib loaded into %@", [[NSBundle mainBundle] bundleIdentifier]);
    Class cls = objc_getClass("LoginManager");
    SEL sel = sel_registerName("validatePassword:");
    Method m = class_getInstanceMethod(cls, sel);
    IMP orig = method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^BOOL(id self, NSString *pw){
        NSLog(@"[Inject] validatePassword: %@", pw);
        return ((BOOL(*)(id,SEL,NSString*))orig)(self, sel, pw);
    });
    method_setImplementation(m, hook);
}
```

Компиляция под arm64 для устройства:

```bash
xcrun -sdk iphoneos clang -arch arm64 -shared -o inject.dylib Inject.m \
  -framework Foundation -fobjc-arc
# проверить
lipo -info inject.dylib
```

## Внедрение через insert_dylib

```bash
git clone https://github.com/Tyilo/insert_dylib && cd insert_dylib && make
cp Payload/MyApp.app/MyApp MyApp.orig
./insert_dylib --strip-codesig --inplace @executable_path/inject.dylib MyApp
# в бинарнике появится LC_LOAD_DYLIB
otool -L MyApp | grep inject
```

Копируем dylib в `.app/`:

```bash
cp inject.dylib Payload/MyApp.app/
```

Для fat-бинарников внедряйте в каждый слайс или тонкий arm64 (устройства).

## Re-sign: подпись своим сертификатом

После модификации подпись недействительна. Переподписываем:

```bash
# 1) убрать старую подпись и entitlements (для теста — можно без них)
codesign --remove-signature Payload/MyApp.app/Frameworks/* 2>/dev/null
# 2) подписать вложенные бинарники
for f in Payload/MyApp.app/Frameworks/*; do
  codesign -f -s "iPhone Developer: Your Name (TEAMID)" "$f"
done
# 3) подписать основной бинарник
codesign -f -s "iPhone Developer: Your Name (TEAMID)" Payload/MyApp.app/MyApp
# 4) подписать бандл
codesign -f -s "iPhone Developer: Your Name (TEAMID)" --entitlements ent.plist Payload/MyApp.app
# 5) упаковать
zip -qr MyApp-injected.ipa Payload
```

Если приложение использует entitlements (push, keychain groups), их нужно пересоздать под свой профиль, иначе подпись не пройдёт. Часто проще использовать `ldid` для ad-hoc подписи на джейлбрейкнутом устройстве:

```bash
ldid -S Inject.entitlements Payload/MyApp.app/MyApp
```

## Установка и запуск

```bash
# на устройство через ideviceinstaller (нужен профиль разработчика)
ideviceinstaller -i MyApp-injected.ipa
# или через ios-deploy
ios-deploy --bundle Payload/MyApp.app
# на симулятор
xcrun simctl install booted Payload/MyApp.app
xcrun simctl launch --console booted com.example.app
```

В логах (`Console.app` или `simctl launch --console`) увидите `[Inject] dylib loaded`. Если приложение падает — dyld не нашёл dylib: проверьте путь в `LC_LOAD_DYLIB` (`@executable_path` — относительно бинарника).

## DYLD_INSERT_LIBRARIES (когда работает)

На macOS/симуляторе переменная работает напрямую:

```bash
DYLD_INSERT_LIBRARIES=/path/inject.dylib \
  /Applications/MyApp.app/Contents/MacOS/MyApp
```

На iOS-устройстве `DYLD_INSERT_LIBRARIES` игнорируется для подписанных приложений (кроме отладочных с `get-task-allow`), поэтому основной путь — `LC_LOAD_DYLIB`.

## Обход проверок целостности

Приложение может детектить re-sign:
- **Проверка `_CodeSignature`** — хеш бинарника не совпадает. Обход: хук `SecStaticCodeCheckValidity`/`SecCodeCheckValidity`.
- **Проверка teamID** — не ваш. Хук `SecCodeCopySigningInformation`.
- **Jailbreak/root detection** — перехват `stat("/Applications/Cydia.app")` и т.п.
- **Frida detection** — если используете gadget, переименуйте порт/имя.

```objc
// хук проверки подписи
#import <Security/Security.h>
static OSStatus (*orig_Check)(SecStaticCodeRef, SecCSFlags);
OSStatus my_Check(SecStaticCodeRef code, SecCSFlags flags) {
    return errSecSuccess;   // всегда «валидно»
}
__attribute__((constructor))
static void hook(void) {
    MSHookFunction((void*)SecStaticCodeCheckValidity, (void*)my_Check, (void**)&orig_Check);
}
```

(Используется `substrate.h` / `fishhook` для хука C-функций.)

## Инъекция через FridaGadget

Альтернатива — добавить `FridaGadget.dylib` и заставить приложение её загрузить, положив конфиг `FridaGadget.config`:

```json
{ "interaction": { "type": "script", "path": "/private/var/mobile/script.js" } }
```

или `"type": "listen", "address": "127.0.0.1", "port": 27042`. Это стандартный способ `objection patchipa`:

```bash
objection patchipa --source MyApp.ipa --codesign-signature "iPhone Developer: You (TEAMID)"
```

## Частые ошибки и подводные камни

- **Приложение сразу падает** — неверный путь dylib или не подписан вложенный фреймворк.
- **`codesign` ругается на entitlements** — используйте профиль с теми же правами.
- **dylib не грузится** — проверьте `otool -L`, что запись есть; для fat нужен arm64-слайс.
- **Frida не подключается** — порт занят/заблокирован; смените в конфиге.
- **На iOS 14+ `DYLD_*` не работает** — используйте `LC_LOAD_DYLIB`.

## Справочная таблица

| Метод | Требует | Когда применять |
|-------|---------|-----------------|
| LC_LOAD_DYLIB | re-sign | основной путь на устройстве |
| DYLD_INSERT_LIBRARIES | debug/get-task-allow | симулятор, отладка |
| FridaGadget | re-sign + config | готовый инструментарий |
| objection patchipa | сертификат | быстрый старт |

## Что дальше / решение

Соберите dylib с логикой перехвата, внедрите через `insert_dylib`, переподпишите своим сертификатом и запустите. Если приложение детектит re-sign — добавьте хуки проверок подписи. Дальше — `mobile-ios-dynamic` (Frida/Cycript) и `mobile-ios-data-protection`.

## Практический сценарий: перехват сетевого слоя

Частая задача — перехватить и модифицировать сетевые запросы, не настраивая прокси (например, при certificate pinning). Инъекция dylib позволяет перехватить методы сетевого клиента напрямую.

Пример для Objective-C `NSURLSession`:

```objc
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static IMP orig_dataTask;

__attribute__((constructor))
static void init(void) {
    Class cls = objc_getClass("NSURLSession");
    SEL sel = @selector(dataTaskWithRequest:completionHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    orig_dataTask = method_getImplementation(m);

    IMP hook = imp_implementationWithBlock(^id(id self, NSURLRequest *req, id handler){
        NSLog(@"[net] %@ %@", req.HTTPMethod, req.URL.absoluteString);
        NSLog(@"[net] headers: %@", req.allHTTPHeaderFields);
        // можно модифицировать req или ответ в handler
        return ((id(*)(id,SEL,NSURLRequest*,id))orig_dataTask)(self, sel, req, handler);
    });
    method_setImplementation(m, hook);
}
```

Для Swift-приложений сетевой слой может быть не в `NSURLSession`, а в сторонней библиотеке (Alamofire на `URLSession`, gRPC на `NIO`). Тогда перехватывайте на уровне C-функций:

```objc
// fishhook для перехвата C-функций
#import "fishhook.h"
static int (*orig_connect)(int, const struct sockaddr*, socklen_t);
static int my_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    NSLog(@"[net] connect fd=%d", fd);
    return orig_connect(fd, addr, len);
}
__attribute__((constructor))
static void hook_connect(void) {
    struct rebinding rb = {"connect", my_connect, (void**)&orig_connect};
    rebind_symbols(&rb, 1);
}
```

## Hooking без re-sign: варианты

Инъекция dylib — не единственный путь. Альтернативы:

- **FridaGadget** — та же инъекция, но вы получаете полноценную Frida-сессию; удобно для интерактивной работы.
- **Cydia Substrate / Substitute** — на джейлбрейкнутом устройстве хукает любой процесс без модификации IPA; `MSHookFunction`.
- **LLDB attach** — отладчик может вызывать функции и читать память, но не подменять реализации надолго.
- **Пассивный дамп** — если нужен только дамп памяти, хватит `frida-ios-dump` без своей dylib.

Выбор зависит от наличия джейлбрейка и требований к скрытности. На джейлбрейке Substrate обычно предпочтительнее: не меняется подпись, приложение не детектит re-sign.

## Диагностика загрузки dyld

Если dylib не грузится, проверьте по шагам:

```bash
# 1) запись присутствует?
otool -L Payload/MyApp.app/MyApp | grep -i inject
# 2) путь корректен?
otool -l Payload/MyApp.app/MyApp | grep -A2 LC_LOAD_DYLIB | grep inject
# 3) dylib на месте и нужной архитектуры?
lipo -info Payload/MyApp.app/inject.dylib
# 4) подпись dylib валидна?
codesign -v Payload/MyApp.app/inject.dylib
# 5) запуск с логом dyld
DYLD_PRINT_LIBRARIES=1 xcrun simctl launch --console booted com.example.app 2>&1 | grep -i inject
```

`DYLD_PRINT_LIBRARIES` покажет, что dyld реально загрузил. Если библиотека не в списке — проблема в load command или пути.

## Ограничения и риски

- **App Attest / DeviceCheck** — привязка к подписи и устройству; re-sign ломает.
- **Биометрическая привязка** — некоторые приложения привязывают ключ Keychain к подписи; после re-sign ключ недоступен.
- **Push-уведомления** — entitlements `aps-environment` нужно пересоздать, иначе push не придут.
- **Обновления** — инъекция делается заново для каждой версии.
- **Правовые рамки** — модификация чужого приложения допустима только в рамках авторизованного теста.

## Квиз

```quiz
- question: "Какой load command заставляет dyld загрузить вашу dylib при старте?"
  options:
    - "LC_LOAD_DYLIB"
    - "LC_CODE_SIGNATURE"
    - "LC_ENCRYPTION_INFO"
    - "LC_UUID"
  answer: 0
- question: "Почему после инъекции dylib нужно переподписывать приложение?"
  options:
    - "Модификация бинарника ломает исходную подпись"
    - "Иначе не сработает Wi-Fi"
    - "Иначе изменится размер APK"
    - "Иначе приложение станет на русском"
  answer: 0
- question: "Почему DYLD_INSERT_LIBRARIES не работает на iOS-устройстве для подписанного приложения?"
  options:
    - "Переменная игнорируется, кроме отладочных сборок с get-task-allow"
    - "Она работает только на Android"
    - "Её удалили из dyld"
    - "Она шифрует dylib"
  answer: 0
- question: "Какая функция проверяет валидность подписи и часто хукается?"
  options:
    - "SecStaticCodeCheckValidity"
    - "NSLog"
    - "objc_msgSend"
    - "UIApplicationMain"
  answer: 0
```

## Где пригодится

- **CTF:** инструментация iOS-приложения без джейлбрейка.
- **Пентест:** перехват методов и обход защит.
- **Bug bounty:** воспроизведение находки на модифицированной сборке.
