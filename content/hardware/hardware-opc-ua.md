---
id: hardware-opc-ua
title: 'OPC UA: безопасность, сертификаты и обход'
category: hardware
parent: hardware-mod-ics-app
difficulty: hard
order: 1
tags: [hardware, ics, opcua, scada, certificates, security-policy]
prerequisites: [hardware-ics, hardware-mod-ics-protocols]
useful_for:
  - 'Пентест АСУ ТП'
  - 'CTF Hardware/ICS'
  - 'Аудит промышленных протоколов'
estimated_minutes: 45
summary: 'OPC UA: адресное пространство, эндпоинты и security policies, сертификаты, анонимные сессии и типовые ошибки конфигурации, ведущие к обходу.'
lab:
  kind: shell
  toolset: [core, python]
  workdir: /home/student/opcua
  files: [task.md, notes.md, opcua.log]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`opcua.log` — OPC UA-сессия с эндпоинтами.'
    - 'Смотри SecurityPolicy, UserTokenPolicy и чтение узлов.'
    - 'Найди флаг: `grep nto opcua.log | cut -d= -f2 > found.txt`.'
---

## Вопрос, с которого всё начинается

OPC UA задуман как безопасный промышленный протокол: шифрование, подписи, сертификаты. Но в реальных АСУ ТП он часто настроен так, что «безопасность» остаётся на бумаге.

Вопрос урока: как устроена защита OPC UA и где она ломается конфигурацией.

## Наш пример: OPC UA-сервер

У нас есть дамп сессии с OPC UA-сервером. Видны эндпоинты, согласование политики безопасности и чтение узла. Разберём, какая политика была выбрана и что это значит.

## Шаг 1: адресное пространство и узлы

OPC UA представляет данные как **узлы** (nodes) в адресном пространстве: переменные, объекты, методы. У каждого узла есть **NodeId** (идентификатор) и атрибуты, главный — **Value**.

```text
$ grep -m2 'NodeId' opcua.log
Read ns=2;s=Machine.Temperature -> 72.4
Read ns=2;s=Machine.Setpoint -> 70.0
```

Здесь `ns=2;s=Machine.Temperature` — строковый NodeId в пространстве имён 2. Чтение значения — базовый сервис.

## Шаг 2: эндпоинты и security policy

При подключении клиент запрашивает **GetEndpoints** — список доступных точек входа, у каждой своя **SecurityPolicy**. Политики бывают:

- **None** — без шифрования и подписи.
- **Basic128Rsa15 / Basic256 / Basic256Sha256** — разные уровни.
- **Aes128Sha256RsaOaep / Aes256Sha256RsaPss** — современные.

```text
$ grep -n 'SecurityPolicy' opcua.log
Endpoint: SecurityPolicy=None, SecurityMode=None
Endpoint: SecurityPolicy=Basic256Sha256, SecurityMode=SignAndEncrypt
```

Сервер отдаёт оба. Если клиент выберет **None**, сессия будет открытой.

## Шаг 3: анонимные сессии

Даже при хорошей политике сервер может разрешить **Anonymous** аутентификацию. Тогда любой подключается без учётных данных.

```text
$ grep -n 'UserToken' opcua.log
UserTokenPolicy: Anonymous
UserTokenPolicy: UserName
ActivateSession: anonymous=true -> OK
```

Частая ошибка: политика SignAndEncrypt, но токен Anonymous. Шифрование есть, но доступа лишён никто.

## Шаг 4: сертификаты

OPC UA использует X.509-сертификаты. Слабые места:

1. **Self-signed без проверки** — сервер принимает любой сертификат.
2. **Просроченные сертификаты** — приложение отключает проверку, чтобы «работало».
3. **Один сертификат на всех** — компрометация одного даёт доступ ко всем.
4. **Доверие всему хранилищу** — если в trust list попал лишний сертификат.

## Шаг 5: практический обход

Типичный сценарий пентеста:

1. `GetEndpoints` → найти эндпоинт с `None`.
2. Если его нет — проверить, разрешён ли Anonymous.
3. Если и это закрыто — посмотреть, принимает ли сервер произвольный сертификат (MITM).
4. Через разрешённую сессию — перечислить узлы и найти методы (методы могут выполнять действия на оборудовании).

```text
$ python3 -c "print('UAExpert / opcua-client: connect, browse, read, call method')"
UAExpert / opcua-client: connect, browse, read, call method
```

Инструменты: UaExpert, `opcua-client`, Prosys, `nmap --script opcua-info`.

## Что мы теперь знаем

- OPC UA описывает данные как узлы с NodeId и атрибутами.
- Каждый эндпоинт имеет SecurityPolicy; политика None = открытая сессия.
- Anonymous-токен обнуляет смысл шифрования.
- Сертификаты часто не проверяются — возможен MITM.
- Методы-узлы могут управлять оборудованием.

## Квиз

```quiz
- question: Что определяет SecurityPolicy в OPC UA?
  options:
    - Алгоритмы аутентификации/шифрования сессии
    - Список узлов
    - IP-адрес сервера
  answer: 0
  explanation: Политика задаёт криптографию сессии; None = без защиты.
- question: Чем опасна политика None?
  options:
    - Сессия без шифрования и подписи
    - Она медленная
    - Она несовместима с TCP
  answer: 0
  explanation: None означает полностью открытую сессию.
- question: Почему Anonymous-токен подрывает защиту?
  options:
    - Доступ получает кто угодно, даже при шифровании
    - Он слишком короткий
    - Он ломает сертификат
  answer: 0
  explanation: Анонимная сессия не требует учётных данных.
- question: Какая типичная ошибка с сертификатами OPC UA?
  options:
    - Проверка отключена или принимается любой сертификат
    - Слишком длинный ключ
    - Слишком много узлов
  answer: 0
  explanation: Отсутствие проверки сертификата открывает MITM.
```

## Куда дальше

Дальше разберём **CIP/EtherNet-IP** — промышленный Ethernet с объектной моделью. А пока запомни: OPC UA ломается не криптографией, а настройками.

## Где пригодится

- **Пентест:** аудит АСУ ТП и производств.
- **CTF:** категория Hardware/ICS.
- **Работа:** проектирование и проверка OPC UA.
- **Дальше по дереву:** `hardware-cip-enip`, `hardware-mod-ics-protocols`.
