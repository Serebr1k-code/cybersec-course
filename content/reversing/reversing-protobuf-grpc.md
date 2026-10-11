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
---
Многие клиенты и сервисы общаются не текстовым JSON, а бинарными протоколами сериализации: **protobuf** (Google), **gRPC** (RPC поверх HTTP/2 на protobuf) и **Thrift** (Facebook). Без `.proto`/`.thrift`-схемы сообщения выглядят как бессмысленные блобы, но их можно декодировать и восстановить структуру прямо из трафика и бинарника клиента. Это частый и очень прибыльный шаг для API-анализа, bug bounty и реверса закрытых клиентов (мобильные приложения, десктоп-софт, IoT). Этот урок — практический разбор всех трёх форматов от wire-format до вызова методов.

## Protobuf wire-format

Protobuf сериализует поля как последовательность **tag + value**. Tag — это varint:

```text
tag = (field_number << 3) | wire_type
```

Wire-type определяет способ кодирования значения:

| Wire type | Значение | Используется для |
|-----------|----------|------------------|
| 0 | varint | int32/64, uint, sint, bool, enum |
| 1 | 64-bit (little-endian) | fixed64, sfixed64, double |
| 2 | length-delimited | string, bytes, вложенные message, packed repeated |
| 5 | 32-bit (little-endian) | fixed32, sfixed32, float |

Примеры декодирования вручную:

```text
08 96 01            -> tag=0x08 => field 1, wire 0 (varint); value=0x96 0x01 => 150
12 03 61 62 63      -> tag=0x12 => field 2, wire 2 (len); len=3; "abc"
1D 00 00 80 3F      -> tag=0x1D => field 3, wire 5 (fixed32); float 1.0
```

Ключевое следствие: **поля адресуются номерами, не именами**. Имена в wire-формате отсутствуют — их надо восстанавливать из схемы или из бинарника.

## Восстановление .proto без схемы

Три источника имён и типов:

1. **Строки в бинарнике.** В debug-сборках, Go и Rust имена полей/сообщений часто остаются в `.rodata` (Go хранит `protobuf`-теги, Rust — в metadata).
2. **Дескрипторы.** Многие бинарники содержат сериализованный `FileDescriptorProto` (protobuf reflection). Его находят поиском по строкам-именам и декодируют.
3. **Плагины Ghidra/IDA** для protobuf (`protobuf-descriptor`), а также `pbtk` (Protobuf Toolkit).

Декодирование без схемы:

```bash
# protoc --decode_raw (входит в protobuf)
echo '08011203616263' | xxd -r -p | protoc --decode_raw
# 1: 150
# 2: "abc"

# blackboxprotobuf (Python) — рекурсивно декодирует вложенные сообщения
python3 - <<'EOF'
from blackboxprotobuf import decode_message
data = bytes.fromhex('08011203616263')
print(decode_message(data))
EOF
```

`decode_raw` показывает номера полей и предполагаемые значения; `blackboxprotobuf` дополнительно рекурсивно разбирает вложенные message и угадывает типы. Имена всё равно придётся сопоставлять вручную (по смыслу и логике клиента).

## gRPC: HTTP/2 + protobuf

gRPC — это RPC, где метод вызывается по path `/<package.Service>/<Method>`, а тело — protobuf (или JSON при transcoding). Транспорт — HTTP/2, что усложняет перехват (нужен HTTP/2-aware прокси).

```bash
# Если на сервере включён reflection — можно всё перечислить без схемы
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 list my.package.Service
grpcurl -plaintext target:50051 describe my.package.Service
# Вызвать метод
grpcurl -plaintext -d '{"id": 1}' target:50051 my.package.Service/GetUser
# Если reflection выключен — передать свои .proto
grpcurl -plaintext -import-path ./proto -proto svc.proto -d '{"id":1}' target:50051 my.Service/Get
```

Перехват трафика:

```bash
# mitmproxy видит HTTP/2 и gRPC (в т.ч. streaming)
mitmproxy --mode regular --ssl-insecure
# Wireshark: фильтр http2, включить dissection protobuf (настроить .proto)
tshark -r capture.pcap -d tcp.port==50051,http2 -Y http2
```

Для клиента без reflection схему восстанавливают из бинарника: ищите строки `/my.package.Service/Method` и имена полей, сопоставляйте с protobuf-блобами в трафике.

## Thrift: TBinary и TCompact

Thrift — ещё один RPC/сериализационный фреймворк, распространённый в инфраструктуре (Cassandra, Hadoop, многие микросервисы). Два основных протокола:

- **TBinaryProtocol** — простое бинарное кодирование: структура = последовательность полей (field-type + field-id + value), конец — field-id 0.
- **TCompactProtocol** — сжатый, с delta-кодированием field-id и зигзаг-varint.

Реверс:

```bash
# Декодировать сырое сообщение (если есть .thrift)
thrift --gen py -out gen svc.thrift
# Анализ сгенерированных классов (Java/Python) — имена методов/полей
# Строки в бинарнике клиента
strings -a client | grep -iE "getUser|UserService|thrift"
```

Как и в protobuf, имена методов/полей часто остаются в бинарнике (в сгенерированных классах). Формат TCompact компактнее, но разбирается теми же средствами — с учётом delta-кодирования.

## Практический workflow

```text
1) Захватить трафик (mitmproxy для gRPC, tcpdump для Thrift).
2) Определить протокол: gRPC (HTTP/2, content-type application/grpc),
   Thrift (TBinary/TCompact), или «сырой» protobuf.
3) Декодировать без схемы (protoc --decode_raw / blackboxprotobuf).
4) Восстановить номера/типы полей по wire-type и значениям.
5) Сопоставить с логикой клиента (декомпиляция: имена полей, методы).
6) Построить схему (.proto) -> генерировать запросы, фаззить, искать IDOR/инъекции.
```

## Разобранный пример: от блоба до рабочего gRPC-запроса

```bash
# 1) Из перехваченного HTTP/2-потока вырезаем protobuf-тело (msg.bin)
# 2) Декодируем без схемы
protoc --decode_raw < msg.bin
# 1: 42
# 2: "admin@example.com"
# 3 { 1: "token_abc" }

# 3) Имена полей из бинарника клиента
strings -a client | grep -iE "user_id|email|auth|token"
# -> "user_id", "email", "auth.token"  (порядок совпадает с номерами 1,2,3)

# 4) Пишем .proto
cat > svc.proto <<'EOF'
syntax = "proto3";
package api;
message Auth { string token = 1; }
message GetUserReq { int32 user_id = 1; string email = 2; Auth auth = 3; }
message User { string name = 1; string role = 2; }
service Users { rpc GetUser(GetUserReq) returns (User); }
EOF

# 5) Вызываем через grpcurl с найденной схемой
grpcurl -plaintext -import-path . -proto svc.proto \
        -d '{"user_id":42,"email":"admin@example.com","auth":{"token":"token_abc"}}' \
        target:50051 api.Users/GetUser

# 6) Меняем user_id -> проверяем IDOR
grpcurl -plaintext -import-path . -proto svc.proto \
        -d '{"user_id":1,"email":"x","auth":{"token":"token_abc"}}' \
        target:50051 api.Users/GetUser
```

Так из «нечитаемого» блоба получается воспроизводимый запрос, который можно варьировать для тестирования авторизации и инъекций.

## Где искать имена полей в разных языках

Восстановление имён — самая трудоёмкая часть. Ориентиры по языкам клиента:

- **Go.** Сгенерированные `.pb.go` содержат строки-теги и таблицы `protoimpl`; в бинарнике остаются строки вида `json:"user_id"` и `protobuf:"..."`. Ищите `strings client | grep 'protobuf:'`.
- **Java/Kotlin (Android).** Protobuf-классы генерируются в `com.google.protobuf`; имена полей часто в строках `Descriptor`-таблиц. Декомпилируйте APK (jadx) и ищите `parseFrom`, `Builder`.
- **Rust (prost).** Имена в metadata; в бинарнике — строки-имена полей и `::prost::Message`.
- **C++.** Дескрипторы компилируются в таблицы (`FileDescriptorProto`); их находят по строкам имён сообщений и декодируют тем же `decode_raw`.
- **Python.** `*_pb2.py` — открытый исходник; если клиент на Python, схема может быть прямо в байткоде (см. `reversing-python-bytecode`).

Дополнительный источник — **`.proto`-файлы, отданные сервером** (gRPC reflection: `grpcurl describe` возвращает готовую схему в текстовом виде).

## Справочник инструментов

| Инструмент | Назначение | Пример |
|------------|------------|--------|
| `protoc --decode_raw` | декод без схемы | `protoc --decode_raw < msg.bin` |
| `blackboxprotobuf` | рекурсивный декод | `decode_message(data)` |
| `grpcurl` | gRPC-клиент/reflection | `grpcurl -plaintext host list` |
| `mitmproxy` | перехват HTTP/2/gRPC | `mitmproxy --ssl-insecure` |
| `tshark` | разбор pcap (http2) | `tshark -d tcp.port==50051,http2` |
| `pbtk` | Protobuf Toolkit | анализ дескрипторов |
| `thrift --gen` | генерация классов из .thrift | `thrift --gen py svc.thrift` |
| `strings` | поиск имён полей | `strings client \| grep user_id` |

## Частые ошибки

- **Нет схемы — нет имён.** `decode_raw` даёт только номера и типы; имена ищите в бинарнике/дескрипторах.
- **Путать wire-types.** Тип поля выводится по wire-type, но varint может быть int/bool/enum — однозначно не всегда.
- **Сложность HTTP/2.** gRPC нельзя разобрать простым прокси; нужен HTTP/2-aware инструмент (mitmproxy/Wireshark).
- **Сжатие.** gRPC может использовать gzip/сжатие на уровне message — распакуйте перед декодированием.
- **Thrift vs protobuf.** Разные форматы и фрейминги; не применяйте приёмы одного к другому.
- **Reflection отключён.** `grpcurl list` может не работать — тогда схема только из бинарника.
- **Игнорирование streaming.** gRPC streaming-методы дают много сообщений в одном потоке; разбирайте все кадры.

## Что делать дальше / решение

1. Определите протокол по трафику (content-type, HTTP/2, фрейминг Thrift).
2. Декодируйте без схемы (`protoc --decode_raw`, `blackboxprotobuf`).
3. Восстановите имена/типы из бинарника клиента (строки, дескрипторы).
4. Соберите `.proto`/`.thrift` и проверьте `grpcurl describe`/генерацией клиента.
5. Воспроизведите запросы и переходите к тестированию (IDOR, инъекции, обход авторизации).
6. Оформите схему как артефакт — она пригодится для фаззинга и отчёта.

## Квиз

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
    - "grpcurl list (при reflection)"
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

## Где пригодится

- **CTF:** Reversing — протоколы.
- **Bug bounty:** анализ API.
- **Reverse-engineering клиентов:** формат запросов.
- **Работа:** API analysis, integration.
