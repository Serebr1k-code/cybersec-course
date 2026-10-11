---
id: mobile-objection
title: "Objection: runtime-манипуляции без написания скриптов"
category: mobile
parent: mobile-frida-tooling
difficulty: medium
order: 2
tags: [objection, frida, android, ios, ssl-pinning, root-detection, runtime]
prerequisites: [mobile-dynamic-frida]
useful_for:
  - "CTF Mobile (быстрый обход проверок)"
  - "Bug bounty (pinning/root bypass одной командой)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Objection поверх Frida: готовые команды для обхода SSL pinning, root/jailbreak-детекта, дампа хранилища, работы с классами и памяти — без написания скриптов."
---
## Что такое Objection и зачем он нужен

Objection — это runtime-фреймворк поверх Frida, который даёт **готовые команды** для типовых задач мобильного пентеста. Вместо написания JS-скрипта вы выполняете одну команду: отключить SSL pinning, обойти root/jailbreak-детект, выгрузить хранилище, перечислить классы, вызвать метод, посмотреть память. Это резко снижает порог входа и ускоряет работу: там, где Frida-скриптинг требует знания API, Objection работает «из коробки».

Когда Objection не подходит: нестандартные проверки (самодельный anti-debug, кастомный pinning), сложная логика (нужно переписать метод, а не только посмотреть). Тогда вы берёте за основу сгенерированный Objection скрипт и дописываете его руками (см. `mobile-frida-scripting`). Правило: **Objection для быстрых типовых вещей, Frida — для хирургии**.

## Установка и подключение

```bash
pip install objection
objection --version

# на устройстве/эмуляторе должен работать frida-server той же версии, что frida-tools
adb push frida-server /data/local/tmp/ && adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U                       # список процессов (проверка связи)

# подключение к запущенному приложению (attach)
objection -g com.target.app explore
# запуск приложения с инъекцией (spawn) и стартовой командой
objection -g com.target.app explore --startup-command "android sslpinning disable"
```

Внутри — интерактивная консоль с автодополнением и `help`. Команды сгруппированы: `android`, `ios`, `env`, `memory`, `heap`, `jobs`, `plugin`, `frida`.

## Обход SSL pinning

Самая частая задача. Objection подменяет сразу несколько механизмов pinning (OkHttp, TrustManager, нативные хуки).

```bash
# Android
android sslpinning disable
# iOS
ios sslpinning disable
```

Проверка: трафик приложения идёт через ваш Burp/mitmproxy без ошибок сертификата. Если приложение использует нативный pinning (напр. BoringSSL, Conscrypt с custom X509TrustManager), одной команды может не хватить — тогда комбинируйте с Frida-скриптами из `mobile-cert-pinning-deep`. Objection также умеет `android sslpinning disable --quiet` и выводит в лог, какие методы были перехвачены.

## Обход root/jailbreak-детекта

```bash
android root disable          # прячет признаки root
ios jailbreak disable         # прячет признаки jailbreak
```

`android root disable` перехватывает типовые проверки (`su` в PATH, `test-keys`, `Superuser.apk`, `Runtime.exec("su")`, `File.exists("/system/xbin/su")`) и подменяет их результат. Для продвинутого детекта (SafetyNet/Play Integrity, `mobile-integrity`) одной команды мало — нужны обходы через Frida + сертификаты.

## Хукинг методов: watch и трассировка

Objection умеет следить за вызовами методов и дампить аргументы/возвраты:

```bash
# найти класс
android hooking search classes target
android hooking search methods getToken

# следить за методом (выводит args и return в реальном времени)
android hooking watch class_method com.target.auth.Session.getToken --dump-args --dump-return
android hooking watch class com.target.crypto.CipherUtil --dump-args
# вызвать метод вручную (например, расшифровать строку)
android hooking call_method com.target.crypto.CipherUtil decrypt --args "Q0VF..."
```

Хуки на `Cipher.doFinal`, `SecretKeySpec.$init`, `SharedPreferences.getString` — быстрый способ увидеть ключи и секреты в рантайме.

## Работа с классами и памятью

```bash
# перечислить загруженные классы
android hooking list classes
android hooking list activities
android hooking list services

# память: поиск строк, дамп, изменение
memory list modules                 # загруженные модули/библиотеки
memory search "FLAG{" --string      # поиск в памяти
memory dump all /data/local/tmp/dump.bin
memory dump from_base 0x7f... 0x1000 /data/local/tmp/chunk.bin
```

Поиск в памяти (`memory search`) — прямой путь к флагу в CTF или к расшифрованным токенам в реальном приложении. `memory dump` полезен для последующего анализа нативных библиотек.

## Дамп хранилища

```bash
# Android
android hooking list activities
env                              # показать пути приложения
# выгрузка SharedPreferences/файлов — через shell приложения
sqlite connect /data/data/com.target.app/databases/app.db   # открыть БД в консоли
# читать файлы из-под приложения
file download /data/data/com.target.app/shared_prefs/auth.xml auth.xml

# iOS
ios keychain dump                # дамп Keychain
ios nsuserdefaults get           # NSUserDefaults
ios cookies get                  # cookies
```

Objection запускает команды **в контексте приложения**, поэтому обходит ограничения обычного `adb shell` (без root) и читает приватные файлы.

## Обход биометрии и анти-отладки

```bash
ios ui biometrics_bypass            # подменить результат биометрии на успех
android root disable                # часто тянет за собой и anti-debug
# список флагов окружения, влияющих на детект
env
```

Для биометрии на Android чаще нужен Frida-хук на `BiometricPrompt`/`FingerprintManager` — Objection покрывает iOS-часть «из коробки». Анти-отладка (`ptrace`, `TracerPid`) обходится скриптами; часть детектов Objection глушит вместе с root-детектом.

## Разобранный пример: полный прогон за пять минут

```bash
$ objection -g com.target.app explore
com.target.app (run) on (android: 13) [usb] # android sslpinning disable
(agent) [ssl] Starting SSL pinning bypass...
(agent) [ssl] Hooking OkHttp3 CertificatePinner.check
(agent) [ssl] Hooking javax.net.ssl.X509TrustManager
(agent) [ssl] Hooking TrustManagerImpl.checkTrustedRecursive

com.target.app # android root disable
(agent) [root] Bypassing root detection (12 checks)

com.target.app # android hooking watch class_method com.target.auth.Session.getToken --dump-return
(agent) [watch] getToken() -> "eyJhbGciOiJIUzI1NiIsInR5cCI6..."   # токен утёк

com.target.app # memory search "FLAG{" --string
(agent) [memory] Found at 0x7f9c2a40: FLAG{objection_makes_it_easy}

com.target.app # file download /data/data/com.target.app/shared_prefs/auth.xml auth.xml
```

За пять минут мы сняли pinning, обошли root-детект, вытащили токен и флаг. Это и есть сила Objection.

## Справочная таблица команд

| Задача | Android | iOS |
|--------|---------|-----|
| SSL pinning | `android sslpinning disable` | `ios sslpinning disable` |
| Root/jailbreak | `android root disable` | `ios jailbreak disable` |
| Хук метода | `android hooking watch class_method C.m --dump-args --dump-return` | `ios hooking watch method "-[C m]"` |
| Список классов | `android hooking list classes` | `ios hooking list classes` |
| Вызвать метод | `android hooking call_method C m --args ...` | `ios hooking call_method ...` |
| Поиск в памяти | `memory search "X" --string` | `memory search "X" --string` |
| Дамп хранилища | `sqlite connect ...` / `file download` | `ios keychain dump` |
| Биометрия | (Frida-хук) | `ios ui biometrics_bypass` |

## Типовые ошибки новичка

- **Версия frida-server ≠ frida-tools.** Самая частая причина «не подключается». Обновляйте обе синхронно.
- **Забыть про `--startup-command`.** Если приложение проверяет root на старте, инъекция после запуска может опоздать — используйте spawn.
- **Считать, что pinning снят.** Проверяйте трафик в прокси, а не только вывод Objection.
- **Игнорировать нативные проверки.** Objection хукает Java; нативный pinning/детект требует Frida в `.so`.
- **Работать без root/эмулятора с root.** Часть команд требует привилегий.

## Что дальше / решение

Стандартный сценарий: Objection → снять pinning и root-детект → перехватить трафик (`mobile-mitm-burp`) → найти секреты/токены (`memory search`, `watch`) → при необходимости углубиться Frida-скриптами (`mobile-frida-scripting`) или в native (`mobile-android-native`). Связанные уроки: `mobile-frida-tooling`, `mobile-dynamic-frida`, `mobile-frida-detection` (если Objection палится). Решение задачи — когда нужная проверка обойдена или данные извлечены, а результат воспроизводится командой.

## Objection + Burp: перехват и модификация на лету

Objection не заменяет прокси, но дополняет его. Связка: Objection снимает pinning и делает приложение «доверчивым», а Burp/mitmproxy видит и правит трафик.

```bash
# 1. на устройстве ставим пользовательский CA (для API<24 достаточно; выше — системный)
# 2. запускаем прокси на 8080, направляем устройство на него
# 3. objection -g com.target.app explore --startup-command "android sslpinning disable"
# 4. в Burp видим расшифрованный HTTPS; правим запросы (Repeater)
```

Дополнительно Objection умеет `env` — покажет `proxy`-настройки приложения, если оно использует собственный прокси-конфиг. Если pinning остаётся (нативный), комбинируйте с Frida-скриптом `frida-multiple-unpinning` или патчем APK.

## Расширение Objection: patchapk и плагины

`objection patchapk` встраивает frida-gadget прямо в APK — тогда устройство с root не нужно, а приложение запускается уже с инъекцией.

```bash
objection patchapk --source app.apk --architecture arm64
# → app.objection.apk, подписанный debug-ключом; ставим на устройство
adb install app.objection.apk
objection -g com.target.app explore   # gadget уже внутри
```

Плагины (`plugin load`) позволяют добавлять свои команды. Часть задач (кастомный anti-debug, специфичный pinning) решается собственным Frida-скриптом, который можно подгрузить через `plugin`.

## Практический чек-лист прогона Objection

1. Синхронизировать версии `frida-tools` и `frida-server`.
2. Подключиться (`-g pkg explore`), при необходимости spawn + `--startup-command`.
3. Снять pinning (`android sslpinning disable` / `ios sslpinning disable`).
4. Обоити root/jailbreak-детект (`android root disable` / `ios jailbreak disable`).
5. Поставить прокси (`mobile-mitm-burp`) и убедиться, что HTTPS читается.
6. Найти секреты: `memory search`, `android hooking watch class_method ... --dump-return`.
7. Выгрузить хранилище: `file download`, `sqlite connect`, `ios keychain dump`.
8. Зафиксировать в отчёте команды и вывод — Objection воспроизводим.

## Квиз

```quiz
- question: "Что такое Objection?"
  options:
    - "Обёртка над Frida с готовыми командами для мобильного пентеста"
    - "Декомпилятор APK"
    - "Сетевой сканер"
    - "Менеджер паролей"
  answer: 0
  explanation: "Objection даёт команды поверх Frida без написания скриптов."
- question: "Какая команда отключает SSL pinning на Android?"
  options:
    - "android sslpinning disable"
    - "android root disable"
    - "env"
    - "memory list"
  answer: 0
  explanation: "Команда ставит хуки на типовые реализации pinning."
- question: "Какая команда выгружает Keychain на iOS?"
  options:
    - "ios keychain dump"
    - "ios jailbreak disable"
    - "android hooking get"
    - "env"
  answer: 0
  explanation: "ios keychain dump выгружает элементы Keychain."
- question: "Что нужно для работы Objection на устройстве?"
  options:
    - "Frida (frida-server)"
    - "Только Xcode"
    - "Root-права хоста"
    - "Docker"
  answer: 0
  explanation: "Objection использует Frida для инъекции."
- question: "Что делать, если автопатч Objection не снял защиту?"
  options:
    - "Написать кастомный Frida-скрипт"
    - "Переустановить приложение"
    - "Сменить устройство"
    - "Отключить Wi-Fi"
  answer: 0
  explanation: "Кастомная реализация требует собственного хука."
```

## Где пригодится

- **CTF Mobile:** быстрый обход проверок одной командой.
- **Bug bounty:** pinning/root bypass для анализа трафика.
- **Пентест:** ускорение динамического анализа.
- **Работа:** экспресс-аудит защит клиента.
