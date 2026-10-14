---
id: mobile-xctest
title: 'XCTest и XCUITest: нативное тестирование iOS'
category: mobile
parent: mobile-testing-automation
difficulty: medium
order: 3
tags: [ios, xctest, xcuitest, testing, xcode, xcresult]
prerequisites: [mobile-testing-workflow]
useful_for:
  - 'Автоматизация тестирования iOS'
  - 'Пентест мобильных приложений'
  - 'Реверс iOS-приложений'
estimated_minutes: 40
summary: 'XCTest и XCUITest — нативные фреймворки Apple: как устроены тест-кейсы, чем XCUITest отличается от XCTest, что хранит .xcresult и какие находки прячутся во вложениях отчёта.'
lab:
  kind: shell
  title: 'Практика: разбор XCTest-отчёта (.xcresult)'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, xcresult_summary.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`xcresult_summary.txt` — текстовый дамп результатов XCTest.'
    - 'Повтори шаг из `mobile-testing-workflow`: сначала пойми, что за артефакт.'
    - 'Найди упавший тест-кейс и вложение, которое он сохранил.'
    - 'В имени вложения — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

На Android у нас был Espresso — тест внутри процесса. У Apple своя пара инструментов:
**XCTest** для юнит-тестов и **XCUITest** для тестов интерфейса. Ты получил от команды
файл `.xcresult` — дамп прогона тестов, — и надо понять, что там внутри. Заодно проверить,
не утекло ли что-нибудь в приложенные скриншоты и логи.

## Что такое XCTest и XCUITest

**XCTest** — это фреймворк Apple для написания тестов на Swift или Objective-C. Тесты
бывают двух видов:

- **юнит-тесты** — проверяют функции и классы напрямую, без интерфейса;
- **UI-тесты (XCUITest)** — управляют приложением через **accessibility**-слой: находят
  кнопки и поля по их меткам и водят «палец» по экрану.

Ключевое отличие от Espresso: XCUITest **не живёт внутри процесса** приложения. Он
работает как отдельный процесс-«водитель» и общается с приложением через систему
доступности. Это ближе к Appium, чем к Espresso.

## Наш пример: дамп .xcresult

`.xcresult` — это папка-пакет, где лежат результаты: статусы тестов, тайминги и
**вложения** (attachments). Вот текстовый дамп (в практике ты разберёшь его):

```
Test Case '-[BankUITests testTransfer]' failed (0.412 seconds).
  Attachments:
    - nto{xcu1t3st_4tt4chm3nt_l34k}.png (screenshot on failure)
    - console.txt
Executed 1 test, with 1 failure
```

Читаем. Тест `testTransfer` упал, и система на падении **сохранила скриншот**. Имя
вложения — это и есть флаг в практике. Для пентестера важнее другое: вложения XCUITest
почти всегда содержат **скриншоты экрана и консольный лог** на момент падения. Если в этот
момент на экране были секретные данные (токен, номер карты), они окажутся в отчёте.

## Шаг 1: анатомия XCUITest

Тест на Swift выглядит так:

```swift
func testLogin() {
    let app = XCUIApplication()
    app.launch()
    app.textFields["login"].tap()
    app.textFields["login"].typeText("alice")
    app.secureTextFields["password"].typeText("hunter2")
    app.buttons["submit"].tap()
    XCTAssertTrue(app.staticTexts["balance"].waitForExistence(timeout: 3))
}
```

Здесь `XCUIApplication` — приложение под управлением теста, а элементы ищутся по
accessibility-меткам: `textFields["login"]`, `buttons["submit"]`. `XCTAssertTrue` — проверка,
которая при провале сохраняет скриншот.

## Шаг 2: где взять дамп отчёта

Из командной строки результаты прогона достаются так:

```
$ xcrun xcresulttool get --path Bank.xcresult --format json
```

`xcresulttool` — утилита Apple для чтения `.xcresult`. JSON удобно фильтровать через
`jq`. Именно так ты достанешь список вложений и поймёшь, какие скриншоты и логи уехали в
отчёт.

## Шаг 3: XCUITest и пентест

Три практических вывода:

1. **Тест — воспроизведение.** Написав XCUITest, ты можешь за минуты прогонять сложный
   сценарий (ввод данных, переходы) и смотреть, что утекает на экран.
2. **Accessibility-метки — это карта.** XCUITest ищет элементы по меткам; если метка
   осмысленная (`secureTextFields["password"]`), ты быстро поймёшь структуру экрана.
3. **Вложения — риск.** Скриншоты на падении часто содержат то, что видеть в отчёте не
   должны.

## Шаг 4: запуск

```
$ xcodebuild test -scheme Bank -destination 'platform=iOS Simulator,name=iPhone 15'
```

`xcodebuild test` собирает приложение и прогоняет тесты на выбранном симуляторе или
устройстве. Результат складывается в `.xcresult`, который мы и разбирали.

## Что мы теперь знаем

- XCTest — юнит-тесты, XCUITest — тесты интерфейса через accessibility.
- XCUITest не живёт внутри процесса приложения, в отличие от Espresso.
- `.xcresult` хранит статусы, тайминги и вложения (скриншоты, логи).
- Вложения на падении — частый источник утечек на пентесте.
- Читать отчёт — `xcrun xcresulttool get`.

## Квиз

Проверь себя.

```quiz
- question: Чем XCUITest отличается от XCTest?
  options:
    - XCUITest — это юнит-тесты, XCTest — UI-тесты
    - XCUITest управляет интерфейсом через accessibility, XCTest проверяет код напрямую
    - Это одно и то же
    - XCUITest работает только на Android
  answer: 1
  explanation: XCUITest — про интерфейс, XCTest — про юнит-проверки кода.
- question: Что хранит файл .xcresult?
  options:
    - Исходный код приложения
    - Статусы тестов, тайминги и вложения
    - Сертификаты подписи
    - Расшифрованный трафик
  answer: 1
  explanation: .xcresult — пакет результатов прогона, включая attachments.
- question: Почему вложения XCUITest интересны пентестеру?
  options:
    - Они замедляют тест
    - Скриншоты и логи на падении могут содержать секретные данные
    - Они шифруют данные
    - Они содержат ключи подписи
  answer: 1
  explanation: На падении сохраняется состояние экрана и консоль — иногда с секретами.
- question: Какой командой прочитать .xcresult из терминала?
  options:
    - xcrun xcresulttool get
    - adb logcat
    - ./gradlew connectedAndroidTest
    - maestro test
  answer: 0
  explanation: xcresulttool читает пакет результатов; --format json даёт удобный вывод.
- question: По чему XCUITest ищет элементы?
  options:
    - По координатам пикселей
    - По accessibility-меткам
    - По IP-адресу
    - По хешу файла
  answer: 1
  explanation: Элементы адресуются по accessibility-идентификаторам и меткам.
```

## Куда дальше

Остался четвёртый инструмент — **Maestro**, который показывает, что автоматизацию можно
описывать декларативно, без программирования. А пока запомни: отчёт XCTest — это не только
вердикт, но и коллекция скриншотов, которые надо читать как утечку.

## Где пригодится

- Разбор чужих `.xcresult` на предмет утёкших секретов во вложениях.
- Написание XCUITest для воспроизведения сценария пентеста.
- Понимание accessibility-структуры iOS-приложения при реверсе.
