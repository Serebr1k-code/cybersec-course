---
id: net-iot-protocols
title: 'IoT-протоколы в форензике: MQTT, CoAP и следы устройств'
category: forensics
parent: forensics-net-ot
difficulty: hard
order: 2
tags: [network, iot, mqtt, coap, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как анализировать трафик интернета вещей: MQTT-топики, CoAP и типичные слабости, приводящие к компромиссу устройств.'
lab:
  kind: shell
  title: 'Практика: IoT-протоколы в форензике'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

В сети сотни датчиков и умных устройств. Они общаются не по HTTP, а по **MQTT** и
**CoAP** — лёгким протоколам. Если устройство взломали, следы будут именно там.
Разберём, как их читать.

## Наш пример: MQTT-трафик

## Шаг 1: что такое MQTT

MQTT — протокол «публикация/подписка» через брокер. Порт 1883 (или 8883/TLS).
Устройства публикуют в **топики** (например, `home/livingroom/temp`) и подписываются
на них.

```
$ tshark -r iot.pcap -Y 'mqtt' -T fields -e mqtt.conack.flags -e mqtt.topic -e mqtt.msg | head
```

## Шаг 2: CONNECT без пароля

Классическая слабость — брокер без аутентификации:

```
$ tshark -r iot.pcap -Y 'mqtt.conflags' -T fields -e ip.src -e mqtt.username | head
10.10.40.5	
10.10.40.9	admin
```

Пустое поле `mqtt.username` означает анонимное подключение — любой может
публиковать и подписываться. Так злоумышленник получает контроль над всеми
устройствами через брокер.

## Шаг 3: подмена команд

Найдём публикации в управляющие топики:

```
$ tshark -r iot.pcap -Y 'mqtt.msgtype==3' -T fields -e mqtt.topic -e mqtt.msg | grep -i 'cmd\|set'
home/garage/door/cmd	OPEN
```

Публикация `OPEN` в топик двери гаража — прямое управление физическим устройством.
Неавторизованная такая публикация = компромисс.

## Шаг 4: CoAP

CoAP — UDP-протокол для ограниченных устройств (порт 5683):

```
$ tshark -r iot.pcap -Y 'coap' -T fields -e coap.code -e coap.opt.uri_path | head
1	config
```

`code=1` (GET) или `2` (POST). POST на `/config` может менять настройки устройства.

## Шаг 5: следы и слабости

- дефолтные пароли (`admin`/`admin`);
- открытый брокер MQTT;
- прошивки без подписи;
- устройства с постоянными уязвимостями.

Смотри логи брокера (Mosquitto):

```
$ grep -i 'New client connected' /var/log/mosquitto/mosquitto.log | tail
```

## Что мы теперь знаем

- MQTT — pub/sub через брокер (1883).
- Анонимный MQTT = полный контроль над устройствами.
- Публикации в `.../cmd` управляют физикой.
- CoAP — UDP-протокол для мелких устройств (5683).
- Логи брокера фиксируют подключения.

## Если не сработало

- Трафик шифрован (8883)? Нужны ключи.
- Нет дампа? Читай логи брокера и устройства.
- Нужны команды? Смотри MQTT-топики и CoAP POST.

## Квиз

Проверь себя.

```quiz
- question: Как работает MQTT?
  options:
    - 'запрос-ответ'
    - 'публикация/подписка через брокер'
    - 'файловый обмен'
    - 'почта'
  answer: 1
  explanation: 'MQTT — модель pub/sub с центральным брокером.'
- question: Чем опасен MQTT без аутентификации?
  options:
    - 'медленный'
    - 'любой может публиковать и управлять устройствами'
    - 'шифрует'
    - 'ничем'
  answer: 1
  explanation: 'Анонимный доступ даёт контроль над всеми топиками.'
- question: Что означает публикация в топик .../cmd?
  options:
    - 'лог'
    - 'команда устройству'
    - 'ошибка'
    - 'обновление'
  answer: 1
  explanation: 'Топики cmd/set управляют физическими действиями.'
- question: Какой транспорт у CoAP?
  options:
    - 'TCP'
    - 'UDP'
    - 'ICMP'
    - 'SCTP'
  answer: 1
  explanation: 'CoAP работает поверх UDP (порт 5683).'
```
