---
id: forensics-net-ot
title: "Модуль: промышленные, IoT и облачные сети"
category: forensics
parent: forensics-network-advanced
difficulty: hard
order: 8
tags: [network, ics, scada, iot, modbus, vpc, flow-logs, forensics, roadmap]
prerequisites: [forensics-network-deep]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ промышленных и облачных сетей"
estimated_minutes: 13
summary: "Этап ветки «сеть»: сети, которые не похожи на классические — промышленные протоколы (Modbus/SCADA), IoT-протоколы и облачные журналы потоков (VPC Flow Logs)."
---

Классический интернет — это TCP/IP, HTTP, DNS. Но есть целые миры со своими
протоколами: заводы говорят на **Modbus**, датчики — на **MQTT/CoAP**, а облака пишут
**flow logs** вместо pcap. Форензика там строится иначе.

## Что покрывает этот модуль

- **ICS/SCADA** — промышленные протоколы и их анализ.
- **IoT** — MQTT, CoAP и следы устройств.
- **Облачные сети** — VPC Flow Logs вместо дампа.

## Рекомендуемый порядок изучения

1. `net-ics-scada` — промышленный контур.
2. `net-iot-protocols` — интернет вещей.
3. `net-cloud-vpcflow` — облачные журналы потоков.

## Что вы будете уметь

- Читать Modbus/DNP3 и понимать, что делал оператор.
- Анализировать MQTT-трафик и находить подмену команд.
- Восстанавливать сетевую активность по VPC Flow Logs.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| Modbus-кадры | что писали в PLC | `tshark` |
| MQTT-топики | что публиковали датчики | `tshark` |
| VPC Flow Logs | кто с кем общался в облаке | Athena/S3 |

## Куда дальше

Открывай урок **«ICS/SCADA в форензике»** — начнём с промышленного контура.
