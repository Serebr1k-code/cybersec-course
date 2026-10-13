---
id: mobile-ios-static
title: "iOS static analysis: class-dump, Hopper, Swift и дешифровка"
category: mobile
parent: mobile-ios-analysis
difficulty: hard
order: 1
tags: [ios, static, class-dump, hopper, ghidra, swift, mach-o, frida-ios-dump]
prerequisites: [mobile-ios-basics]
useful_for:
  - "CTF Mobile (реверс iOS-бинарника)"
  - "Bug bounty (анализ iOS-клиента)"
  - "Пентест мобильных приложений"
estimated_minutes: 40
summary: "Глубокий статический анализ iOS: структура Mach-O, извлечение Objective-C/Swift, дешифровка App Store-сборок, работа в Hopper/Ghidra и поиск секретов/логики."
lab:
  kind: shell
  title: 'Практика: class-dump iOS'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, classdump.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`classdump.txt` — результат `class-dump` по бинарю iOS-приложения.'
    - 'Ищи методы с подозрительными именами (`token`, `secret`, `key`, `flag`).'
    - 'В одном из методов зашита строка-флаг — найди `nto{` и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Ты распаковал IPA и увидел, что код — это нативный Mach-O, а не DEX. На Android ты бы запустил `jadx` и получил почти исходник. Здесь так не выйдет: Objective-C и Swift компилируются в машинный код. Как тогда понять, что делает приложение, и найти в нём секреты или проверки?

Ответ — **статический анализ**: работаем не с исходником, а с метаданными и строками бинарника.

## Наш пример: DemoApp.ipa

Возьмём тот же `DemoApp.ipa`. Распакуем и перейдём в бандл:

```
$ unzip -q DemoApp.ipa -d app_ipa
$ cd app_ipa/Payload/DemoApp.app
$ ls
DemoApp  DemoApp.dylib  Info.plist
```

Статический анализ — это последовательность слоёв: сначала убедиться, что бинарник не зашифрован, затем снять «карту» классов, потом искать секреты в строках и конфигурации, и лишь в конце — читать логику в дизассемблере.

## Шаг 1: проверяем шифрование

Первое, что нужно сделать, — проверить `cryptid`. Если бинарник из App Store зашифрован, весь дальнейший анализ бесполезен:

```
$ python3 macho_lc.py DemoApp.dylib | grep -i encryption
  LC_ENCRYPTION_INFO_64
```

Наша сборка — локальная, шифрования нет. Если бы `cryptid` был равен `1`, пришлось бы сначала дешифровать бинарник прямо с устройства:

```
$ python3 dump.py com.demo.secapp      # frida-ios-dump -> decrypted.ipa
```

Инструмент `frida-ios-dump` работает через Frida на jailbreak-устройстве: он запускает приложение, выгружает расшифрованные сегменты памяти и собирает из них «чистый» IPA.

## Шаг 2: карта классов Objective-C

Objective-C хранит метаданные о классах и методах внутри бинарника. Утилита `class-dump` извлекает их и генерирует заголовки:

```
$ class-dump -H DemoApp -o headers/
$ ls headers/
AuthManager.h  CryptoUtil.h  DemoApp.h  NetworkClient.h
```

Теперь мы видим структуру приложения. `AuthManager` — логика входа, `CryptoUtil` — шифрование, `NetworkClient` — сеть. Посмотрим на один заголовок:

```
$ head -20 headers/AuthManager.h
@interface AuthManager : NSObject
- (BOOL)isJailbroken;
- (NSString *)getToken;
- (void)loginWithUser:(NSString *)user password:(NSString *)pass;
@end
```

Метод `isJailbroken` — проверка jailbreak, которую в динамике мы будем обходить. `getToken` — цель для дампа. Это и есть «карта», по которой дальше работают и статически, и динамически.

## Шаг 3: Swift-символы и деманглинг

Swift-классы часто не видны в ObjC-runtime, поэтому `class-dump` их пропускает. Их имена закодированы в **манглированных** символах — длинных строках вида `$s6MyApp...`. Утилита `swift-demangle` превращает их в читаемый вид:

```
$ nm -U DemoApp | swift-demangle | grep -i 'Auth\|Token\|Key'
DemoApp.AuthManager.getToken() -> Swift.String
DemoApp.SecureStore.apiKey.getter
```

Теперь видно, что есть `SecureStore.apiKey` — потенциально место хранения ключа. Манглирование — это схема, по которой компилятор кодирует типы и имена в символ; деманглер возвращает их обратно.

## Шаг 4: поиск секретов в строках

Самое быстрое, что даёт результат, — `strings` по бинарнику. В нативном коде остаются URL, ключи, сообщения об ошибках:

```
$ strings -a DemoApp | grep -iE 'api[_-]?key|secret|token|password'
s3cr3t
https://api.demo.example/v2
```

А ещё стоит поискать характерные шаблоны облачных ключей по всему бандлу:

```
$ grep -rInE 'AIza|AKIA|firebaseio|sk_live' app_ipa/
```

`AIza` — префикс ключей Google API, `AKIA` — AWS, `sk_live` — Stripe. Такие «отпечатки» ловят случайно захардкоженные ключи быстрее, чем чтение кода.

## Шаг 5: конфигурация и права

`Info.plist` уже смотрели; углубимся в две вещи — ATS и entitlements:

```
$ python3 -c "import plistlib;d=plistlib.load(open('Info.plist','rb'));print(d['NSAppTransportSecurity'])"
{'NSAllowsArbitraryLoads': True}
```

`NSAllowsArbitraryLoads` разрешает HTTP — значит, трафик можно перехватить без проблем с TLS. Дальше — entitlements, права приложения:

```
$ codesign -d --entitlements - DemoApp
[Keychain Access Groups] com.demo.secapp
[App Groups] group.com.demo.shared
```

`Keychain Access Groups` показывает, в какой группе лежат секреты Keychain, а `App Groups` — что данные могут быть доступны другим приложениям группы. Это прямо указывает, где искать токены.

## Шаг 6: зависимости

Посмотрим, какие библиотеки тянет бинарник:

```
$ otool -L DemoApp
DemoApp:
    @rpath/DemoApp.dylib
    /usr/lib/libSystem.B.dylib
```

Сторонние SDK (Firebase, аналитика, реклама) часто содержат собственные ключи и «болтливые» логи. Каждый встроенный фреймворк стоит проверить отдельно тем же `strings`.

## Шаг 7: чтение логики в дизассемблере

Только теперь, когда есть карта (`isJailbroken`, `getToken`), можно открыть бинарник в **Hopper**, **IDA** или бесплатном **Ghidra** и найти нужный метод по имени. Логика проверки пароля, сравнение хешей, алгоритм подписи — всё это читается в дизассемблере. Но идти туда «вслепую» бессмысленно: карта классов и строки уже сузили поиск до нескольких методов.

## Шаг 8: что искать

Чек-лист для статики iOS:

- проверки jailbreak (`isJailbroken`, `fileExistsAtPath:` с `/bin/bash`, `/Applications/Cydia.app`);
- проверки pinning (`SecTrustEvaluate`, `SecTrustSetPolicies`, встроенные `.cer`);
- секреты в строках и plist;
- опасные URL-схемы и обработчики `openURL`;
- entitlements и App Groups.

Каждая находка — это гипотеза для динамики: найденную проверку мы будем снимать хуком.

## Шаг 9: частые ошибки

Три ошибки съедают больше всего времени у новичка.

**Анализ зашифрованного бинарника.** Если `cryptid=1`, а дешифровку не сделали, `class-dump` вернёт пустые интерфейсы, а `strings` — почти ничего. Всегда проверяй `LC_ENCRYPTION_INFO_64` первым делом.

**Поиск только по бинарнику.** Секреты часто лежат не в главном `AppName`, а в ресурсах, plist, встроенных фреймворках или ассетах. Прогоняй `grep` по всему каталогу `Payload/`, а не только по бинарнику.

**Игнорирование Swift.** Если приложение написано на Swift, `class-dump` покажет мало: имена методов нужно деманглировать через `swift-demangle`, иначе ты просто не увидишь логику.

## Шаг 10: разбираем entitlements программно

Entitlements — XML-plist, вшитый в подпись. Их удобнее разбирать скриптом:

```
$ python3 -c "import plistlib; e=plistlib.load(open('entitlements.plist','rb')); print('application-identifier =', e.get('application-identifier')); print('get-task-allow =', e.get('get-task-allow')); print('associated-domains =', e.get('com.apple.developer.associated-domains'))"
application-identifier = ABCDE12345.com.demo.sec
get-task-allow = True
associated-domains = ['applinks:demo.example']
```

`get-task-allow=True` — красный флаг: это debug-сборка, её можно отлаживать и снимать дампы памяти без jailbreak; в релизе обязано быть `false`. Рядом смотри `keychain-access-groups` (какие приложения делят общий keychain) и `com.apple.developer.associated-domains` (какие домены отдают приложению Universal Links). Debug-entitlements в проде — серьёзная находка: атакующий с физическим доступом снимет дамп и вытащит секреты.

## Что мы теперь знаем

- iOS-статику начинают с проверки `cryptid`; зашифрованный бинарник сначала дешифруют.
- `class-dump` строит карту ObjC-классов и методов.
- Swift-имена получают через `swift-demangle`.
- `strings` и grep по «отпечаткам» быстро находят секреты.
- `Info.plist` и `codesign --entitlements` показывают конфигурацию и права.
- Логику читают в Hopper/IDA/Ghidra, но только после того, как карта сузила поиск.

## Квиз

Проверь себя.

```quiz
- question: Почему нельзя получить исходник iOS-приложения так же, как Java на Android?
  options:
    - "Бинарники зашифрованы"
    - "Objective-C и Swift компилируются в машинный код, а не в байткод с метаданными"
    - "iOS не использует бинарники"
    - "Исходники удаляются при сборке"
  answer: 1
  explanation: "Нативный машинный код не восстанавливается в исходник; работают дизассемблеры и метаданные."
- question: Что делает `class-dump`?
  options:
    - "Дешифрует бинарник"
    - "Извлекает метаданные ObjC-runtime в заголовочные файлы"
    - "Собирает IPA"
    - "Снимает pinning"
  answer: 1
  explanation: "class-dump читает runtime-метаданные и генерирует .h с классами и методами."
- question: Зачем нужен `swift-demangle`?
  options:
    - "Шифровать строки"
    - "Превращать манглированные Swift-символы в читаемые имена"
    - "Собирать проект"
    - "Проверять подпись"
  answer: 1
  explanation: "Swift кодирует имена в манглированные символы; деманглер их расшифровывает."
- question: Что показывает `codesign -d --entitlements -`?
  options:
    - "Строки бинарника"
    - "Права приложения: Keychain Access Groups, App Groups"
    - "Версию iOS"
    - "Список классов"
  answer: 1
  explanation: "Entitlements описывают, к каким группам Keychain и App Groups приложение имеет доступ."
- question: Почему `NSAllowsArbitraryLoads: True` важно для атакующего?
  options:
    - "Ускоряет приложение"
    - "Разрешает незашифрованный HTTP, упрощая перехват трафика"
    - "Отключает jailbreak-детект"
    - "Открывает Keychain"
  answer: 1
  explanation: "ATS ослаблен, поэтому часть трафика идёт по HTTP и легко перехватывается."
```

## Куда дальше

Статика дала нам карту: мы знаем, что есть `isJailbroken` и `getToken`, и где хранятся секреты. Но увидеть, как они работают в реальном времени, статика не может. В следующем уроке мы запустим приложение на jailbreak-устройстве и снимем эти проверки через Frida и Objection. А пока главное запомни: статический анализ iOS — это «сначала карта, потом дизассемблер», и начинается он с проверки шифрования.

## Где пригодится

- **Пентест:** построение карты приложения перед динамикой.
- **Bug bounty:** быстрый поиск секретов и опасных проверок в IPA.
- **CTF:** поиск флага в строках и метаданных iOS-бинарника.
- **Аудит:** проверка ATS и entitlements релизной сборки.
