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
lab:
  kind: shell
  title: 'Практика: Objection без скриптов'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, objection_session.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Objection даёт готовые команды: `android sslpinning disable`, `android root disable`.'
    - '`objection_session.log` — лог сессии.'
    - 'Среди вывода есть секрет — найди `nto{` и запиши в `found.txt`.'
---

## Вопрос, с которого всё начинается

Ты умеешь писать Frida-скрипты, но на каждой задаче повторяется одно и то же: снять pinning, отключить root-детект, посмотреть, что лежит в хранилище. Писать это руками каждый раз — долго. Есть ли инструмент, где всё это уже готово?

## Наш пример: быстро обойти защиту без скриптов

Возьмём защищённое приложение, которое нужно: запустить на рутованном устройстве, снять pinning и посмотреть локальное хранилище. Разберём, как сделать это командами **Objection** — надстройки над Frida.

## Шаг 1: что такое Objection

**Objection** — это инструмент поверх Frida с набором готовых команд. Он берёт на себя типовые задачи мобильного анализа: обход pinning и root-детекта, работу с классами, дамп хранилища, манипуляции с памятью. Идея простая: вместо Frida-скрипта ты вводишь команду.

Устанавливается через pip:

```
$ pip install objection
```

Objection сам поднимает Frida и подключается к приложению — отдельно настраивать ничего не нужно (кроме Frida-сервера на устройстве).

## Проверяем установку и команды вживую

Убеждаемся, что инструмент встал:

```
$ objection version
objection: 1.12.5
```

Теперь посмотрим верхнеуровневые команды:

```
$ objection --help
Usage: objection [OPTIONS] COMMAND [ARGS]...
Options:
  -N, --network            Connect using a network connection instead of USB.
  -n, --name TEXT          Name or bundle identifier to attach to.
  -s, --spawn              Spawn the target.
  -f, --foremost           Use the current foremost application.
Commands:
  api       Start the objection API server in headless mode.
  patchapk  Patch an APK with the frida-gadget.so.
  patchipa  Patch an IPA with the FridaGadget dylib.
  run       Run a single objection command.
  start     Start a new session
  version   Prints the current version and exits.
```

Здесь важно, что Objection умеет не только подключаться, но и **патчить APK** — встраивать Frida Gadget прямо в приложение (`patchapk`). Это спасает, когда приложение детектит Frida и обычное подключение обрывается: Gadget подключается изнутри. Смотрим его флаги:

```
$ objection patchapk --help
Options:
  -s, --source TEXT              The source APK to patch  [required]
  -a, --architecture TEXT        The architecture of the device ...
  -N, --network-security-config  Include a network_security_config.xml ...
  -t, --target-class TEXT        The target class to patch.
```

Флаг `-N, --network-security-config` добавляет конфиг, доверяющий пользовательским сертификатам, — без него на Android 7+ прокси-трафик не расшифруется.

## Шаг 2: подключение

Запуск на Android — по имени пакета:

```
$ objection -g com.target.app explore
com.target.app on (android: 14) [usb] #
```

Флаг `-g` означает «подключиться к приложению (и запустить его, если не запущено)». После подключения появляется интерактивная консоль Objection с командами. Список доступных команд — `help`.

Для iOS синтаксис похож, но подключение идёт по bundle id, а команды имеют префикс `ios`.

## Шаг 3: обход pinning и root

Две самые частые задачи решаются одной командой каждая:

```
com.target.app on (android: 14) [usb] # android sslpinning disable
com.target.app on (android: 14) [usb] # android root disable
```

`android sslpinning disable` подменяет проверки сертификатов в стандартных библиотеках (TrustManager, OkHttp, Conscrypt) — после этого трафик идёт через прокси. `android root disable` обнуляет типовые root-проверки. По сути это те же хуки, что мы писали руками, — Objection просто подставляет их автоматически.

Проверка результата: подключите прокси и посмотрите, появился ли трафик; для root — запустите приложение и убедитесь, что оно не закрывается.

## Шаг 4: работа с классами

Objection умеет перечислять и исследовать классы:

```
com.target.app on (android: 14) [usb] # android hooking list classes
com.target.app on (android: 14) [usb] # android hooking list activities
com.target.app on (android: 14) [usb] # android hooking search methods check
```

- `list classes` — все загруженные классы;
- `list activities` — активности (по ним видно структуру приложения);
- `search methods <подстрока>` — методы, содержащие подстроку.

Это быстрый способ понять поверхность приложения, не открывая jadx. Найденный метод можно захукать прямо из Objection:

```
com.target.app on (android: 14) [usb] # android hooking watch class_method com.target.app.Checker.check
```

Команда начнёт логировать каждый вызов метода с аргументами и результатом — без единой строчки скрипта.

## Шаг 5: хранилище и память

Objection умеет доставать данные приложения:

```
com.target.app on (android: 14) [usb] # android keystore list
com.target.app on (android: 14) [usb] # env
com.target.app on (android: 14) [usb] # memory list modules
com.target.app on (android: 14) [usb] # memory dump all dump.bin
```

- `keystore list` — содержимое Android Keystore;
- `env` — переменные окружения и пути приложения;
- `memory list modules` — загруженные библиотеки (видно, какие `.so` есть);
- `memory dump` — выгрузка памяти (полезно для поиска расшифрованных строк).

Для дампа DEX из памяти Objection тоже умеет: `android heap search instances` и подобные команды. Для серьёзной распаковки используют `frida-dexdump` (см. `mobile-frida-dexdump`).

## Шаг 6: когда Objection не хватает

Objection покрывает **типовые** задачи. Если приложение использует нестандартный TLS-стек, кастомные root-проверки или защиту от Frida, готовые команды не сработают. Тогда:

- **пишут свой Frida-скрипт** под конкретную проверку;
- **патчат APK** (убирают проверку из кода);
- **переносят анализ на реальное устройство**.

Полезно помнить: Objection сам использует Frida, поэтому если приложение детектит Frida, оно может закрыться и под Objection. В таком случае нужны меры сокрытия (см. `mobile-frida-detection`) или Frida Gadget.

## Шаг 7: типичный рабочий процесс

Порядок работы с Objection:

1. **Подключиться:** `objection -g com.target.app explore`.
2. **Снять базовые защиты:** `android sslpinning disable`, `android root disable`.
3. **Осмотреть поверхность:** `list activities`, `search methods`.
4. **Перехватить нужное:** `watch class_method`.
5. **Извлечь данные:** `keystore list`, `memory dump`.
6. **Если не хватает** — перейти к своему Frida-скрипту.

Такой цикл позволяет за минуты получить то, на что вручную ушли бы часы.

## Что мы теперь знаем

По-простому:

1. Objection — готовые команды поверх Frida для типовых задач.
2. Подключение: `objection -g <package> explore`.
3. `android sslpinning disable` и `android root disable` решают самые частые задачи.
4. `list classes`/`search methods`/`watch class_method` заменяют ручные хуки.
5. Для нестандартных защит нужен свой Frida-скрипт или патч APK.

## На что смотреть дальше

- **Начинайте с Objection.** Для типовых задач это быстрее всего.
- **Не заменяйте им понимание.** За командами стоят те же хуки.
- **Детект Frida ломает и Objection.** Нужны меры сокрытия.
- **Свои скрипты — для нестандартного.** Objection покрывает не всё.

## Квиз

Проверь себя.

```quiz
- question: "Чем Objection отличается от Frida?"
  options:
    - "Это надстройка над Frida с готовыми командами"
    - "Это другой эмулятор"
    - "Это прокси-сервер"
    - "Это формат APK"
  answer: 0
- question: "Какая команда снимает SSL pinning в Objection?"
  options:
    - "android sslpinning disable"
    - "android root disable"
    - "memory dump all"
    - "list activities"
  answer: 0
- question: "Что делает android hooking watch class_method?"
  options:
    - "Логирует каждый вызов метода с аргументами и результатом"
    - "Удаляет метод"
    - "Ставит root"
    - "Меняет сертификат"
  answer: 0
- question: "Почему Objection может не помочь с защищённым приложением?"
  options:
    - "Он использует Frida, которую приложение может детектить"
    - "Он работает только на iOS"
    - "Он не умеет команды"
    - "Он не поддерживает Android"
  answer: 0
- question: "Что делает команда android hooking list activities?"
  options:
    - "Показывает активности приложения"
    - "Удаляет активности"
    - "Компилирует APK"
    - "Скачивает сертификат"
  answer: 0
```

## Куда дальше

Мы освоили быстрый инструмент для типовых задач. В следующем уроке углубимся в Frida: RPC-экспорт функций, вызов внутренних методов и патч памяти — то, что нужно, когда готовых команд не хватает. А пока главное: Objection экономит время на рутине, но не отменяет понимания того, какие хуки он ставит.

## Где пригодится

- **CTF Mobile:** быстрый обход проверок одной командой.
- **Bug bounty:** pinning/root bypass для доступа к API.
- **Пентест:** осмотр поверхности приложения и извлечение данных.
- **Работа:** быстрая инструментация при разборе инцидентов.
