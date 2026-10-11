---
id: network-iot-messaging
title: "MQTT, CoAP и AMQP: протоколы IoT-обмена и их слабости"
category: network
parent: network-module-services
difficulty: medium
order: 4
tags: [network, mqtt, coap, amqp, iot, pubsub, broker]
prerequisites: [network-module-services]
useful_for:
  - "CTF Network (IoT-протоколы)"
  - "Пентест: открытые брокеры, топики, IoT"
  - "Работа (SOC): детект IoT-аномалий"
estimated_minutes: 55
summary: "MQTT, CoAP и AMQP: как работают pub/sub и брокеры, почему открытый MQTT даёт контроль над IoT, что видно на проводе, инструменты (mosquitto, mqtt-pwn) и защита."
---

IoT-устройства общаются через лёгкие протоколы обмена сообщениями: MQTT, CoAP, AMQP. Их безопасность часто сводится к одному брокеру, который бывает открыт, без пароля и без шифрования — тогда атакующий читает и публикует команды всех устройств. Урок продолжает [`network-module-services`](network-module-services).

## MQTT: pub/sub и брокер

**MQTT** — модель публикация/подписка через **брокер**. Клиенты публикуют в **топики** (иерархия через `/`) и подписываются на них (с wildcards `+`, `#`). Порты: 1883 (plain), 8883 (TLS), 8083 (websocket).

```text
client -> broker: CONNECT, PUBLISH, SUBSCRIBE, PINGREQ
topic: home/livingroom/temperature
wildcard: home/+/temperature , home/#
```

```bash
# Подписаться на всё (если брокер открыт)
mosquitto_sub -h 10.0.0.1 -t '#' -v
# Опубликовать команду
mosquitto_pub -h 10.0.0.1 -t 'home/light' -m 'ON'
# Без аутентификации? Проверить
mosquitto_sub -h 10.0.0.1 -t '$SYS/#' -v
```

## Открытый брокер = контроль

Если брокер без аутентификации, атакующий:

- **читает** все топики (датчики, статусы, команды);
- **публикует** свои команды (открыть замок, включить реле);
- **подписывается на wildcard** `#` и видит всё.

```bash
# Перечислить топики (через retained/системные)
mosquitto_sub -h 10.0.0.1 -t '#' -v -W 5
# Найти устройства
mosquitto_sub -h 10.0.0.1 -t '$SYS/broker/clients/#' -v
```

## CoAP: REST для constrained-устройств

**CoAP** (5683/udp) — REST-подобный протокол (GET/PUT/POST/DELETE) поверх UDP для маломощных устройств. Шифрование — **DTLS** (5684), но часто отключено.

```bash
# Установить coap-client
coap-client -m get coap://10.0.0.1/.well-known/core
# Прочитать ресурс
coap-client -m get coap://10.0.0.1/sensors/temp
# Записать (если разрешено)
coap-client -m put coap://10.0.0.1/actuator -e 'ON'
```

## AMQP: очереди сообщений

**AMQP** (5672/tcp) — полноценный протокол очередей (RabbitMQ и др.). Дефолтный пользователь **guest/guest** (обычно ограничен localhost, но иногда нет).

```bash
# Проверить доступ (через rabbitmqadmin/pika)
# guest/guest
python3 -c "import pika; c=pika.BlockingConnection(pika.ConnectionParameters('10.0.0.1')); print('connected')"
```

## Практика: исследование IoT-обмена

```bash
# 1. Найти брокеры
nmap -p 1883,8883,5672,5683 -sU -sV 10.0.0.1
# 2. Открытый MQTT?
mosquitto_sub -h 10.0.0.1 -t '#' -v -W 10
# 3. CoAP discovery
coap-client -m get coap://10.0.0.1/.well-known/core
# 4. Захватить трафик
sudo tcpdump -i eth0 -nn 'tcp port 1883 or udp port 5683'
tshark -r cap.pcap -Y 'mqtt' -T fields -e mqtt.topic | sort -u
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `mosquitto_sub/pub` | MQTT |
| `mqtt-pwn` | MQTT-разведка/эксплуатация |
| `coap-client` | CoAP |
| `pika`/`rabbitmqadmin` | AMQP |
| `tcpdump`/`tshark` | захват и разбор |

```bash
# mqtt-pwn: автоматизированная разведка
# mqtt-pwn> connect 10.0.0.1; mqtt-pwn> scan; mqtt-pwn> topics
```

## Атаки

- **Открытый брокер** — чтение/публикация;
- **Wildcard-подписка** — утечка всех топиков;
- **CoAP без DTLS** — чтение/запись ресурсов;
- **AMQP guest/guest** — доступ к очередям;
- **Ретрансляция команд** — реплей IoT-команд;
- **Логика устройств** — команда «включить/открыть».

## Защита

| Мера | Против чего |
|---|---|
| Аутентификация брокера (user/pass, TLS) | открытый доступ |
| ACL на топики | wildcard-утечки |
| MQTT over TLS (8883) | перехват |
| DTLS для CoAP | чтение/запись |
| Сменить guest/guest в AMQP | доступ к очередям |
| Сегментация IoT-сети | lateral movement |

## Частые ошибки

- **Оставлять брокер без пароля** — полный контроль.
- **Разрешать wildcard `#`** — утечка всех топиков.
- **CoAP без DTLS** — открытая запись.
- **AMQP с guest/guest наружу** — доступ.
- **Считать IoT «внутренним»** — брокер виден из сети.
- **Не логировать публикации** — атаки невидимы.
- **Забывать про retained-сообщения** — они сохраняются на брокере.

## Что дальше / решение

После IoT-обмена вернитесь к [`network-module-services`](network-module-services). Для SMB/LDAP/NFS — [`network-service-enum`](network-service-enum).

## Практика: MQTT и CoAP

```bash
# 1. Найти брокеры и CoAP
nmap -p 1883,8883,5672 -sV 10.0.0.1
nmap -sU -p 5683 10.0.0.1
# 2. Открытый MQTT: подписаться на всё
mosquitto_sub -h 10.0.0.1 -t '#' -v -W 10
# 3. Системные топики (устройства/клиенты)
mosquitto_sub -h 10.0.0.1 -t '$SYS/#' -v -W 5
# 4. CoAP discovery и чтение
coap-client -m get coap://10.0.0.1/.well-known/core
coap-client -m get coap://10.0.0.1/sensors/temp
# 5. Захват трафика
sudo tcpdump -i eth0 -nn 'tcp port 1883 or udp port 5683'
tshark -r cap.pcap -Y 'mqtt' -T fields -e mqtt.topic | sort -u
```

## Сравнение IoT-протоколов

| Протокол | Транспорт | Порт | Модель | Шифрование |
|---|---|---|---|---|
| MQTT | TCP | 1883/8883 | pub/sub | TLS (опц.) |
| CoAP | UDP | 5683/5684 | request/response | DTLS (опц.) |
| AMQP | TCP | 5672 | очереди | TLS (опц.) |
| HTTP | TCP | 80/443 | request/response | TLS |
| XMPP | TCP | 5222 | messaging | TLS |

## Чек-лист IoT-обмена

1. Есть ли **брокеры без аутентификации** (1883/5672)?
2. Разрешены ли **wildcard-подписки** (`#`)?
3. Используется ли **TLS/DTLS**?
4. Сменены ли **дефолтные creds** (guest/guest)?
5. Ограничен ли доступ **ACL** на топики?
6. Сегментирована ли **IoT-сеть**?
7. Логируются ли **публикации/подписки**?

```bash
# Быстрая проверка MQTT
mosquitto_sub -h 10.0.0.1 -t '$SYS/broker/version' -v -W 3
```

Вывод: IoT-обмен держится на брокере. Если он открыт — контроль над устройствами полный. Защита: аутентификация, TLS/DTLS, ACL на топики, смена дефолтов и сегментация IoT-сети.

## Дополнительно: автоматизация IoT-разведки

```bash
# mqtt-pwn: интерактивная разведка брокера
# mqtt-pwn> connect 10.0.0.1
# mqtt-pwn> scan
# mqtt-pwn> topics
# mqtt-pwn> subscribe-all
# Ручная подписка на системные топики
mosquitto_sub -h 10.0.0.1 -t '$SYS/#' -v -W 5
# CoAP: обойти все ресурсы
for r in $(coap-client -m get coap://10.0.0.1/.well-known/core | tr ',' '\n'); do
  echo "$r"; coap-client -m get "coap://10.0.0.1/$r" 2>/dev/null
done
```

Автоматизация позволяет быстро пройти все топики/ресурсы и найти устройства, статусы и команды.

## Итог по IoT-обмену

IoT-протоколы (MQTT/CoAP/AMQP) просты и эффективны, но их безопасность целиком зависит от брокера:

- **открытый брокер** — контроль над всеми устройствами;
- **wildcard `#`** — утечка всех топиков;
- **CoAP без DTLS** — чтение/запись ресурсов;
- **guest/guest в AMQP** — доступ к очередям.

Защита: аутентификация брокера, TLS/DTLS, ACL на топики, смена дефолтов и сегментация IoT-сети. Это закрывает и утечку данных, и управление устройствами.

## Заметка о retained-сообщениях и истории

MQTT поддерживает **retained**-сообщения: последнее сообщение топика хранится на брокере и отдаётся новому подписчику. Это удобно для IoT (актуальный статус) и одновременно — источник утечки: подписавшись на `#`, вы получаете последние статусы всех устройств.

```bash
# Retained-сообщения приходят сразу после подписки
mosquitto_sub -h 10.0.0.1 -t '#' -v -W 5
# QoS и will-сообщения тоже раскрывают поведение устройств
```

Практический вывод: история и retained-сообщения могут содержать команды, статусы и даже секреты (токены, ключи). Проверяйте их при аудите брокера, а на защите — ограничивайте wildcard-подписки ACL и не храните чувствительные данные в retained.

## Квиз

```quiz
- question: "Какой порт у MQTT без TLS?"
  options:
    - "1883"
    - "8883"
    - "5672"
    - "5683"
  answer: 0
  explanation: "1883 — plain MQTT, 8883 — TLS."
- question: "Чем опасен MQTT-брокер без аутентификации?"
  options:
    - "Можно читать и публиковать в любые топики"
    - "Он шифрует слишком сильно"
    - "Он блокирует порты"
    - "Он меняет MAC"
  answer: 0
  explanation: "Открытый брокер даёт контроль над обменом IoT."
- question: "Поверх чего работает CoAP?"
  options:
    - "UDP (с опциональным DTLS)"
    - "TCP"
    - "ICMP"
    - "GRE"
  answer: 0
  explanation: "CoAP — UDP-протокол, защита — DTLS."
- question: "Какие дефолтные учётные данные у AMQP/RabbitMQ?"
  options:
    - "guest/guest"
    - "admin/admin"
    - "root/root"
    - "user/pass"
  answer: 0
  explanation: "guest/guest — стандарт, часто ограничен localhost."
- question: "Что даёт wildcard-подписка '#' в MQTT?"
  options:
    - "Все топики брокера"
    - "Только системные"
    - "Ничего"
    - "Только один топик"
  answer: 0
  explanation: "'#' подписывает на всю иерархию топиков."
```

## Где пригодится

- **CTF:** задачи с MQTT/CoAP и топиками.
- **Пентест:** открытые брокеры, IoT-устройства.
- **SOC:** детект аномальных публикаций и брокеров.
- **Инженерия:** ACL, TLS, DTLS, сегментация IoT.
