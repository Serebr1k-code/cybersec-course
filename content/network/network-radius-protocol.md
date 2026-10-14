---
id: network-radius-protocol
title: "RADIUS: коды пакетов, атрибуты и шифрование пароля"
category: network
parent: network-module-access-aaa
difficulty: hard
order: 1
tags: [network, radius, aaa, 802.1x, wire]
prerequisites: [network-module-access-aaa]
useful_for:
  - "CTF Network (RADIUS-дампы)"
  - "Пентест: подделка ответов, слабый секрет"
  - "Работа: разбор учёта доступа"
estimated_minutes: 55
summary: "RADIUS на уровне байтов: код и идентификатор пакета, TLV-атрибуты, шифрование User-Password на общем секрете и Message-Authenticator, а также проксирование и типовые атаки."
lab:
  kind: shell
  title: "Практика: атрибут Reply-Message"
  toolset: [core, base64]
  workdir: /home/student/task
  files: [task.md, radius.log]
  check: "grep -q 'nto{' answer.txt"
  hints:
    - "Повторение (`network-module-access-aaa`): RADIUS — протокол AAA, атрибут = `Type = Value`; `head -n 8 radius.log`, `Reply-Message` — текстовый атрибут."
    - "`radius.log` — обмен Access-Request / Access-Accept."
    - "В ответе есть атрибут Reply-Message с base64-значением."
    - "Вырежи: `grep Reply-Message radius.log | cut -d: -f2`."
    - "Декодируй base64 и запиши флаг в `answer.txt`, затем `check`."
---

## Вопрос, с которого всё начинается

Ты видишь в дампе обмен между коммутатором и сервером на порт 1812. Пользователь вошёл. Но что именно сервер ответил и какие данные о сессии пришли вместе с ответом? Пароль в дампе зашифрован — как его вообще устроено это «шифрование»?

RADIUS — протокол из модуля [`network-module-access-aaa`](network-module-access-aaa). Разберём его на реальном обмене.

## Наш пример: Access-Request и Access-Accept

```
Code=1 (Access-Request)  Id=0x2A  User-Name="admin"
Code=2 (Access-Accept)   Id=0x2A  Reply-Message="Welcome"
```

Всего два пакета — запрос и ответ. Разберём, из чего они состоят.

## Шаг 1: заголовок RADIUS

Любой пакет RADIUS начинается с 20-байтового заголовка:

| Поле | Размер | Смысл |
|------|--------|-------|
| Code | 1 байт | тип пакета |
| Identifier | 1 байт | сопоставление запроса и ответа |
| Length | 2 байта | длина всего пакета |
| Authenticator | 16 байт | случайное число + проверка целостности |

**Code** бывает: `1` Access-Request, `2` Access-Accept, `3` Access-Reject, `4` Accounting-Request, `5` Accounting-Response, `11` Access-Challenge. **Identifier** должен совпадать в запросе и ответе — по нему NAS понимает, к какому запросу относится ответ.

## Шаг 2: атрибуты — TLV-структура

После заголовка идут **атрибуты** в формате Type-Length-Value:

| Type | Атрибут | Зачем |
|------|---------|-------|
| 1 | User-Name | имя пользователя |
| 2 | User-Password | пароль (зашифрован) |
| 4 | NAS-IP-Address | адрес NAS |
| 8 | Framed-IP-Address | адрес, выданный клиенту |
| 18 | Reply-Message | текст сообщения пользователю |
| 26 | Vendor-Specific | расширения вендоров |
| 80 | Message-Authenticator | HMAC-MD5 для целостности |

Имя пользователя обычно идёт **открытым текстом** — это уже утечка.

## Шаг 3: как «шифруется» User-Password

RADIUS не использует TLS. Пароль шифруется простой схемой:

```
b1 = MD5(shared_secret + Request_Authenticator)
c1 = p1 XOR b1
```

где `p1` — первый 16-байтовый блок пароля. Если пароль длиннее 16 байт, следующий блок XOR-ится с `MD5(secret + c1)`. То есть это **не** шифрование с ключом на сессию, а XOR с хешем от общего секрета. Знаешь секрет — расшифровал пароль.

## Шаг 4: Message-Authenticator и целостность

Поле `Authenticator` в ответе — это `MD5(Code + Id + Length + Request_Authenticator + Attributes + shared_secret)`. Атрибут **Message-Authenticator** (80) добавляет HMAC-MD5. Если NAS не проверяет Message-Authenticator, атакующий может подделать **Access-Accept** — это известная атака на RADIUS.

## Шаг 5: проксирование и атаки

RADIUS-серверы часто стоят за **прокси** (roaming между операторами). Прокси видят атрибуты и могут менять их. Типовые атаки:

- **слабый/дефолтный shared secret** → расшифровка пароля и подделка ответов;
- **отсутствие Message-Authenticator** → ответ-подделка (Access-Accept);
- **BlastRADIUS (2024)** → проталкивание атрибутов через прокси.

## Полный прогон: разбираем дамп

```
$ cat radius.log
Code=1 Access-Request Id=0x2A User-Name=admin
Code=2 Access-Accept  Id=0x2A Reply-Message:bnRve3I0ZDF1NV9yM3BseV9tM3NzNGczfQ==
$ grep Reply-Message radius.log | cut -d: -f2 | base64 -d
nto{r4d1u5_r3ply_m3ss4g3}
```

Мы нашли атрибут Reply-Message в ответе и декодировали флаг. Запиши его в `answer.txt` и набери `check`.

## Что мы теперь знаем

- RADIUS: 20-байтовый заголовок (Code, Id, Length, Authenticator) + TLV-атрибуты.
- Code 1/2/3 — запрос/принять/отклонить; Identifier связывает пару.
- User-Password = XOR с MD5(shared_secret + authenticator) — обратимо при знании секрета.
- Message-Authenticator защищает от подделки ответа; без него возможен Access-Accept-спуфинг.

## Шаг 6: Accounting и коды 4/5

Кроме аутентификации RADIUS ведёт **учёт**. `Accounting-Request` (Code=4) шлёт NAS, когда сессия начинается, обновляется и завершается, а сервер отвечает `Accounting-Response` (Code=5). Поле `Acct-Status-Type` различает события: `Start` (1), `Stop` (2), `Interim-Update` (3), `Accounting-On` (7), `Accounting-Off` (8).

Учётные пакеты несут `Acct-Session-Id`, объём трафика (`Acct-Input-Octets`/`Acct-Output-Octets`) и длительность. Для атакующего это ценно: по учётным данным видно, кто и когда был в сети, а подделка `Accounting-Request` может исказить биллинг или скрыть активность.

## Шаг 7: RADIUS-прокси и roaming

RADIUS-серверы редко стоят поодиночке. В roaming-схемах запрос идёт через цепочку **прокси**: NAS → домашний прокси → сервер. Прокси может менять атрибуты, добавлять свои и логировать. Проблема в том, что если прокси не проверяет `Message-Authenticator`, злоумышленник в середине цепочки может подделать ответ.

Ещё одна деталь — атрибут `Proxy-State` (33): он должен возвращаться без изменений, и по нему связывают цепочку. Его модификация ломает маршрут ответа.

## Разбор реального дампа: атрибуты запроса и ответа

Разберём, что именно несёт пакет:

```
$ cat radius.log
Code=1 Access-Request Id=0x2A
  User-Name=admin
  NAS-IP-Address=10.0.0.1
  Calling-Station-Id=00-11-22-33-44-55
Code=2 Access-Accept Id=0x2A
  Framed-IP-Address=10.20.30.40
  Reply-Message:bnRve3I0ZDF1NV9yM3BseV9tM3NzNGczfQ==
```

Из запроса видно пользователя, NAS и MAC клиента; из ответа — выданный IP и текстовое сообщение. `Calling-Station-Id` — это, по сути, след устройства в сети.

## Инструменты и защита

- `radtest user pass 127.0.0.1 0 secret` — проверить аутентификацию;
- `eapol_test` — эмуляция 802.1X-клиента;
- `radclient` — отправить произвольный пакет;
- `tshark -r dump.pcap -Y radius -T fields -e radius.code -e radius.id` — обзор.

Защита: **RADSEC** (RADIUS over TLS, порт 2083), длинные случайные shared secrets, обязательная проверка `Message-Authenticator`, изоляция прокси и мониторинг аномальных Access-Accept.

## EAP и 802.1X: где RADIUS в схеме

RADIUS — это транспорт для **EAP** в схемах 802.1X. Клиент (supplicant) на устройстве, точка доступа/коммутатор (authenticator) и сервер RADIUS (authentication server). Клиент и сервер обмениваются EAP-сообщениями, а authenticator их **инкапсулирует** в RADIUS-атрибут `EAP-Message` (79) и подписывает `Message-Authenticator`. Так EAP-TLS, PEAP и EAP-TTLS доезжают до сервера.

Отсюда важный вывод: если `Message-Authenticator` не проверяется, можно вклиниться в EAP-обмен и, например, подсунуть «успех» или вытянуть хеш для офлайн-взлома. Именно поэтому проверка этого атрибута — обязательное требование безопасности.

## Сравнение RADIUS и Diameter

**Diameter** — «наследник» RADIUS для телеком-сетей (LTE/5G). Он тоже AAA, но поверх **TCP/SCTP**, с явными сессиями, capability negotiation и расширяемыми AVP. RADIUS проще и живёт в корпоративных сетях, Diameter — в мобильных ядрах.

Для разбора это значит: если ты видишь AAA-трафик поверх UDP на 1812 — это RADIUS; если поверх TCP/SCTP с «AVP» и командами `S6a`/`Gx` — это Diameter. Понимая разницу, легче выбрать инструменты и понять, где искать уязвимости.

## Практический чек-лист разбора RADIUS

1. **Сгруппируй по Identifier.** Запрос и ответ с одинаковым Id — одна транзакция; так восстанавливается диалог.
2. **Определи код.** 1/2/3 — аутентификация; 4/5 — учёт. Это сразу задаёт, что искать дальше.
3. **Выпиши User-Name.** Часто открыт — это уже утечка.
4. **Проверь Message-Authenticator.** Есть ли атрибут 80? Если нет — NAS может принять подделку.
5. **Расшифруй User-Password (при наличии секрета).** XOR с `MD5(secret + Request-Authenticator)` — воспроизводится на Python в пару строк.
6. **Посмотри прокси-цепочку.** Атрибут `Proxy-State` покажет, шёл ли запрос через прокси.

Итог — карта доступа: кто, когда, с какого MAC и с каким результатом. Для атакующего это либо пароль (при слабом секрете), либо вектор подделки Access-Accept; для защищающегося — материал для проверки политик.

## Итог: RADIUS в современной инфраструктуре

RADIUS остаётся самым распространённым AAA-протоколом: Wi-Fi, VPN, проводной 802.1X, NAC — всё это в конечном счёте разговаривает с RADIUS-сервером. Поэтому умение читать RADIUS-трафик — базовый навык для тех, кто работает с корпоративной сетью.

Ключевые находки при разборе: имя пользователя открытым текстом, слабый или дефолтный shared secret (дающий расшифровку пароля), отсутствие `Message-Authenticator` (позволяющее подделать Access-Accept) и прокси-цепочки, через которые можно вклиниться. Каждая из них — отдельный пункт отчёта.

Для защищающейся стороны зрелая схема выглядит так: длинные случайные секреты, обязательная проверка `Message-Authenticator`, **RADSEC** (RADIUS over TLS) для транспорта, изоляция прокси и мониторинг аномальных Accept/Reject. Для телекома следующий шаг — Diameter, но принцип остаётся: AAA-трафик нельзя пускать открытым по недоверенной сети.

## Частые вопросы по RADIUS

**Почему RADIUS на UDP, если он про безопасность?** Исторически — ради простоты и скорости при массовых подключениях. Надёжность частично компенсируют повторами, но именно UDP-природа упрощает подделку ответа, если нет `Message-Authenticator`.

**Где именно шифруется пароль?** Только атрибут `User-Password`. Всё остальное (имя, адрес, MAC, группы) идёт открытым текстом. Поэтому RADIUS нельзя считать «шифрующим» протоколом.

**Что такое `Proxy-State`?** Атрибут, который прокси добавляет и требует вернуть без изменений. По нему связывают цепочку прокси и маршрутизируют ответ.

**Как защититься на транспорте?** Использовать **RADSEC** (RADIUS over TLS): тогда весь обмен шифруется, а не только пароль. Для внутренних сетей — изоляция и строгая проверка `Message-Authenticator`.

**Чем RADIUS отличается от TACACS+?** Транспортом (UDP против TCP), объёмом шифрования (пароль против всего тела) и назначением (доступ к сети против управления оборудованием).

## Квиз

Проверь себя.

```quiz
- question: "Сколько байт занимает заголовок RADIUS?"
  options:
    - "8"
    - "16"
    - "20"
    - "32"
  answer: 2
  explanation: "Code(1) + Id(1) + Length(2) + Authenticator(16) = 20 байт."
- question: "Зачем нужен Identifier в RADIUS?"
  options:
    - "Для шифрования пароля"
    - "Чтобы сопоставить ответ с запросом"
    - "Для сжатия"
    - "Для маршрутизации"
  answer: 1
  explanation: "Ответ несёт тот же Identifier, что и запрос."
- question: "Как шифруется User-Password в RADIUS?"
  options:
    - "AES-256"
    - "XOR с MD5(shared_secret + authenticator)"
    - "RSA"
    - "Не шифруется"
  answer: 1
  explanation: "Простая XOR-схема на основе MD5 от общего секрета."
- question: "От чего защищает Message-Authenticator?"
  options:
    - "От перехвата пароля"
    - "От подделки ответа (например, Access-Accept)"
    - "От DoS"
    - "От сжатия"
  answer: 1
  explanation: "HMAC-MD5 поверх пакета ловит подделку, если NAS его проверяет."
```

## Куда дальше

Дальше — [`network-tacacs`](network-tacacs): тот же принцип «NAS ↔ сервер», но поверх TCP и с шифрованием всего тела. А пока запомни: **RADIUS не шифрует пароль по-настоящему — он XOR-ит его с хешем от общего секрета**.

## Где пригодится

- **CTF:** Network — разбор AAA-дампов.
- **Пентест:** подделка Access-Accept, слабый секрет.
- **Работа (SOC):** детект аномальных Accept/Reject.
- **Администрирование:** настройка 802.1X и NAC.
