---
id: reversing-protobuf-grpc
title: "Реверс protobuf, gRPC и Thrift"
category: reversing
parent: reversing-protocols
difficulty: hard
order: 1
tags: [reversing, protobuf, grpc, thrift, serialization, protocol]
prerequisites: [reversing-protocols]
useful_for:
  - "CTF Reversing"
  - "Bug bounty (API)"
  - "Reverse-engineering клиентов"
estimated_minutes: 55
summary: "Разбор protobuf/gRPC/Thrift: wire-format, .proto из бинарника, реконструкция сообщений и gRPC-методов."
lab:
  kind: shell
  title: 'Практика: декод protobuf без схемы'
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md, msg.pb]
  check: 'grep -q ''150'' answer.txt'
  hints:
    - 'Первый байт `08` = (1<<3)|0. Следующий байт — varint.'
    - 'Varint `96 01` = 0x96 | (0x01<<7) = 150.'
    - '`echo 150 > answer.txt` затем `check`.'
---
## Вопрос, с которого всё начинается

Ты перехватил трафик мобильного клиента. Вместо читаемого JSON — бинарный блоб: `08 2a 12 11 ...`.
Что это и что внутри? Так выглядит **protobuf** — бинарный формат сериализации от Google, который
используют многие API (а поверх него — gRPC). Без схемы (`.proto`) сообщение кажется мусором, но
его можно декодировать и восстановить структуру прямо из трафика и бинарника клиента.

Это частый и очень прибыльный шаг для API-анализа, bug bounty и реверса закрытых клиентов.
Разберём wire-format и восстановление схемы на конкретном сообщении.

Опираемся на прошлый урок: мы умеем перехватывать трафик и смотреть на бинарник клиента
(`strings`). Теперь разберём сам формат.

## Наш пример

У нас есть файл `msg.bin` — тело одного protobuf-сообщения, вырезанное из трафика:

```
$ xxd msg.bin
00000000: 082a 1211 6164 6d69 6e40 6578 616d 706c  .*..admin@exampl
00000010: 652e 636f 6d1a 0b0a 0974 6f6b 656e 5f61  e.com....token_a
00000020: 6263                                     bc
```

Читать это глазами бессмысленно. Разберём формат — и блоб превратится в понятные поля.

## Шаг 1: wire-format — как устроен protobuf

Protobuf сериализует поля как последовательность **tag + value**. Tag — это число, в котором
упакованы **номер поля** и **wire-type** (способ кодирования значения):

```text
tag = (field_number << 3) | wire_type
```

Wire-type бывает четырёх видов:

| Wire type | Значение | Для чего |
|---|---|---|
| 0 | varint | int32/64, uint, bool, enum |
| 1 | 64-bit (little-endian) | fixed64, double |
| 2 | length-delimited | string, bytes, вложенное сообщение |
| 5 | 32-bit (little-endian) | fixed32, float |

Разберём наш блоб вручную. Первый байт `08` = `0b0000_1000`: сдвигаем вправо на 3 → поле **1**,
младшие 3 бита → wire-type **0** (varint). Следующий байт `2a` = 42 — значение. Дальше `12` =
`0b0001_0010`: поле **2**, wire-type **2** (length-delimited). Затем `11` = 17 — длина, и 17 байт
строки `admin@example.com`. Потом `1a` = поле **3**, wire-type 2, вложенное сообщение длиной `0b`
(11 байт): внутри `0a 09` (поле 1, строка длиной 9) + `token_abc`.

Ключевое следствие: **поля адресуются номерами, а не именами**. Имён в wire-формате нет — их
надо восстанавливать отдельно.

## Шаг 2: декодируем без схемы

Не обязательно считать байты вручную — есть `protoc` с режимом `--decode_raw`, который не требует
`.proto`:

```
$ protoc --decode_raw < msg.bin
1: 42
2: "admin@example.com"
3 {
  1: "token_abc"
}
```

Мы получили структуру: поле 1 — число 42, поле 2 — email, поле 3 — вложенное сообщение с полем 1
`token_abc`. Имён пока нет, но смысл уже угадывается.

## Шаг 3: восстанавливаем имена

Имена полей берут из трёх источников:

1. **Строки в бинарнике клиента.** В Go/Rust/debug-сборках имена и теги часто остаются:

```
$ strings -a client | grep -iE 'user_id|email|token'
user_id
email
auth.token
```

2. **Дескрипторы.** Многие бинарники несут сериализованный `FileDescriptorProto` (protobuf
   reflection) — его находят по строкам имён и декодируют тем же `decode_raw`.
3. **Плагины** Ghidra/IDA для protobuf и `pbtk` (Protobuf Toolkit).

Сопоставляя порядок строк с номерами полей (`user_id`→1, `email`→2, `auth.token`→3), получаем
схему.

## Шаг 4: собираем .proto и декодируем с именами

Запишем восстановленную схему:

```proto
syntax = "proto3";
package api;
message Auth { string token = 1; }
message GetUserReq { int32 user_id = 1; string email = 2; Auth auth = 3; }
```

Теперь `protoc` разбирает блоб **с именами**:

```
$ protoc --decode=api.GetUserReq svc.proto < msg.bin
user_id: 42
email: "admin@example.com"
auth {
  token: "token_abc"
}
```

Тот же блоб, но теперь читаемый. Так из «нечитаемого» сообщения получается воспроизводимый
запрос, который можно варьировать для тестирования.

## Шаг 5: gRPC и Thrift

**gRPC** — это RPC поверх HTTP/2, где метод вызывается по пути `/<package.Service>/<Method>`, а
тело — protobuf. HTTP/2 усложняет перехват: нужен HTTP/2-aware прокси (mitmproxy) или Wireshark с
диссектором. Если на сервере включён **reflection**, схему можно получить без бинарника:

```
$ grpcurl -plaintext target:50051 list
$ grpcurl -plaintext target:50051 describe api.Users
$ grpcurl -plaintext -import-path . -proto svc.proto \
      -d '{"user_id":42,"email":"admin@example.com","auth":{"token":"token_abc"}}' \
      target:50051 api.Users/GetUser
```

Если reflection выключен — передаёшь свой `.proto`, восстановленный из бинарника.

**Thrift** (Facebook) — ещё один RPC/сериализационный формат (Cassandra, Hadoop). Два протокола:
`TBinaryProtocol` (field-type + field-id + value, конец — field-id 0) и `TCompactProtocol` (сжатый,
с delta-кодированием и зигзаг-varint). Имена методов/полей тоже часто остаются в бинарнике
клиента (`strings client | grep -iE 'getUser|UserService|thrift'`).

## Где искать имена в разных языках

Самая трудоёмкая часть — имена. Ориентиры по языку клиента:

- **Go:** строки-теги `protobuf:"..."` и `json:"user_id"` остаются в бинарнике —
  `strings client | grep 'protobuf:'`.
- **Java/Kotlin (Android):** декомпилируй APK (`jadx`) и ищи `parseFrom`/`Builder`; имена — в
  таблицах `Descriptor`.
- **Rust (prost):** имена полей и `::prost::Message` в metadata.
- **C++:** `FileDescriptorProto` компилируется в таблицы — декодируй тем же `decode_raw`.
- **Python:** `*_pb2.py` — открытый исходник; схема может лежать прямо в байткоде.

## Что мы теперь знаем

- Protobuf кодирует поля как **tag + value**, где `tag = (field_number << 3) | wire_type`.
- Поля адресуются **номерами**, имён в wire-формате нет.
- `protoc --decode_raw` декодирует без схемы, показывая номера и значения.
- Имена восстанавливают из строк/дескрипторов бинарника или reflection сервера.
- С собранным `.proto` декод идёт с именами, а запросы воспроизводятся (`grpcurl`).
- gRPC = HTTP/2 + protobuf; Thrift — родственный формат с двумя протоколами.

## На что смотреть дальше

- `decode_raw` даёт номера и типы, но **не имена** — без схемы их придётся сопоставлять вручную.
- Один wire-type (varint) может быть int, bool или enum — однозначности нет.
- gRPC нельзя разобрать простым прокси: нужен HTTP/2-aware инструмент.
- gRPC может сжимать сообщения (gzip) — распакуй перед декодированием.
- Thrift и protobuf — разные форматы, не применяй приёмы одного к другому.
- Не игнорируй streaming: в одном потоке может быть много сообщений.

## Почему protobuf реверсится даже без .proto

Protobuf — это **бинарный** формат сериализации, и его wire-format самодостаточен: каждое поле кодируется как `(номер поля, тип)`, за которым идут данные. Номера и типы есть **в самих данных**, поэтому сообщение можно разобрать, даже не имея `.proto`-схемы. Схема нужна лишь для **имён** полей и их смысла — но не для структуры. Это делает реверс protobuf принципиально возможным.

Wire-format кодирует тег как varint: `(field_number << 3) | wire_type`. Типы: `0` — varint (int32/64, bool, enum), `1` — 64-бит (fixed64/double), `2` — length-delimited (string, bytes, вложенные сообщения, repeated packed), `5` — 32-бит (fixed32/float). Из потока байт вы восстанавливаете дерево полей: номер → тип → значение, причём вложенные сообщения рекурсивно. Единственная неоднозначность — число и порядок полей; но это восстанавливается по контексту.

Дальше имена берут из бинарника: в C++ protobuf-описания попадают в `.proto`-дескрипторы внутри ELF/PE; в Go — в виде строк и таблиц; в Python — в сгенерированных модулях. `strings`, поиск по сигнатурам, Ghidra-скрипты находят эти дескрипторы. Собрав `.proto` (номера и типы из трафика, имена из дескрипторов), можно декодировать сообщения читаемо. gRPC добавляет HTTP/2-обёртку и метод (`/Service/Method`), Thrift — свой компактный бинарный протокол с похожей идеей.

## Если не сработало

- **Сообщение не декодируется.** Проверьте, не сжат ли поток (gzip) и не обёрнут ли в TLS; сначала снимите обёртку.
- **Поля «прыгают».** Возможно, это не protobuf, а Thrift/FlatBuffers/Cap'n Proto — у каждого свой формат; сверьте сигнатуры.
- **Имена не находятся в строках.** В C++ дескрипторы могут быть сжаты/обфусцированы; ищите по номерам полей и структуре, либо в отладочных символах.
- **repeated-поля слиты.** В proto3 они кодируются packed (внутри length-delimited); не путайте с вложенным сообщением.
- **Нужен сервер для проверки.** Для gRPC поднимите отражение (reflection) или перехватите трафик прокси — так видны методы и схемы.

## Частые вопросы

**Можно ли обойтись без .proto?** Да, структура восстанавливается из wire-format; схема нужна только для имён.

**Что такое gRPC reflection?** Опциональная возможность сервера отдавать свои `.proto`-описания; если включена, схему можно получить без реверса.

**Как быстро декодировать поток?** `protoc --decode_raw` (или `python`-библиотеки) покажет дерево полей без схемы; затем подставьте имена.

**Чем Thrift отличается?** У Thrift свой бинарный/компактный протокол с полями-номерами, похожий принцип, но другая разметка; инструменты — `thrift`, `fbthrift`.

## Квиз

Проверь себя.

```quiz
- question: "Что кодирует tag в protobuf?"
  options:
    - "Номер поля и wire-type"
    - "Длину строки"
    - "CRC"
    - "IP-адрес"
  answer: 0
  explanation: "tag = (field_number << 3) | wire_type."
- question: "Как декодировать protobuf без схемы?"
  options:
    - "protoc --decode_raw или blackboxprotobuf"
    - "nm"
    - "ldd"
    - "objdump -d"
  answer: 0
  explanation: "decode_raw показывает номера полей и значения без .proto."
- question: "Что такое gRPC?"
  options:
    - "RPC поверх HTTP/2 с protobuf-сообщениями"
    - "Формат файла"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "gRPC использует HTTP/2 и protobuf."
- question: "Как перечислить gRPC-методы?"
  options:
    - "grpcurl list (при включённом reflection)"
    - "nm"
    - "strings"
    - "objdump"
  answer: 0
  explanation: "grpcurl использует server reflection для списка методов."
- question: "Где искать имена protobuf-полей?"
  options:
    - "В строках бинарника/дескрипторах"
    - "В GOT"
    - "В ELF-заголовке"
    - "В ASLR"
  answer: 0
  explanation: "Имена часто остаются в бинарнике или descriptor'ах."
```

## Куда дальше

Мы научились превращать бинарные блобы в читаемые сообщения и восстанавливать схему. Дальше возьмём
eBPF — технологию наблюдения за ядром Linux, которая встречается и в защите, и в малвари. А пока
главное запомни: **protobuf адресует поля номерами**, и связка `decode_raw` + строки бинарника
даёт схему даже без исходного `.proto`.

## Где пригодится

- **CTF:** Reversing — протоколы и сериализация.
- **Bug bounty:** анализ API (IDOR, обход авторизации).
- **Reverse-engineering клиентов:** формат запросов закрытых приложений.
- **Работа:** API analysis, интеграция сервисов.
