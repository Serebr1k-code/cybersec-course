---
id: net-dhcp
title: 'DHCP в форензике: кто получал какие адреса и когда'
category: forensics
parent: forensics-net-lan
difficulty: medium
order: 2
tags: [network, dhcp, leases, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как по DHCP-логам и дампу восстановить, какое устройство получало какой IP и в какое время.'
lab:
  kind: shell
  title: 'Практика: DHCP в форензике'
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

У тебя есть IP-адрес из лога, но какой машине он принадлежал? Адреса выдаются
динамически, поэтому IP сам по себе мало о чём говорит. Связь «IP ↔ устройство»
восстанавливается по **DHCP**. Разберём, где это искать.

## Наш пример: лиз DHCP

## Шаг 1: что делает DHCP

При подключении устройство рассылает `DHCPDISCOVER`, получает `DHCPOFFER`, запрашивает
`DHCPREQUEST` и подтверждает `DHCPACK`. Сервер запоминает выдачу в **lease** (аренду).

## Шаг 2: серверные лизы

```
$ grep -A4 'lease 10.10.20.9' /var/lib/dhcp/dhcpd.leases
lease 10.10.20.9 {
  starts 3 2026/01/14 03:15:00;
  ends 3 2026/01/14 15:15:00;
  hardware ethernet 02:42:0a:0a:14:09;
  client-hostname "kali";
}
```

Здесь всё: IP, время начала/конца аренды, **MAC** и имя клиента. Имя `kali` — уже
зацепка. Пара «IP + MAC» связывает сетевой лог с конкретным устройством.

## Шаг 3: DHCP в дампе

Если серверных логов нет, смотрим трафик:

```
$ tshark -r capture.pcap -Y 'bootp' -T fields -e ip.src -e bootp.option.hostname -e bootp.hw.mac_addr -e bootp.ip.your | head
0.0.0.0	kali	02:42:0a:0a:14:09	10.10.20.9
```

`bootp.ip.your` — запрошенный адрес. Так восстанавливаешь историю даже без сервера.

## Шаг 4: клиентские следы

На клиенте остаётся история аренды:

```
$ journalctl -u NetworkManager | grep -i dhcp | tail
Jan 14 03:15:00 host NetworkManager[500]: dhcp4 (eth0): address 10.10.20.9
```

А на Windows — в Event Log (`Microsoft-Windows-Dhcp-Client`).

## Шаг 5: сопоставляем

Собираем связку:

```
03:15:00  DHCPACK 10.10.20.9 -> 02:42:0a:0a:14:09 (kali)
03:20:00  SSH from 10.10.20.9
```

Теперь IP из SSH-лога однозначно привязан к устройству.

## Что мы теперь знаем

- DHCP выдаёт IP и запоминает аренду (lease).
- `dhcpd.leases` содержит IP, MAC, имя, время.
- В дампе DHCP виден через `tshark -Y bootp`.
- Клиентские следы — в journald/Event Log.
- Пара IP↔MAC связывает сеть с устройством.

## Если не сработало

- Сервер — Windows? Смотри `DhcpSrvLog-*.log`.
- Лиз истёк и перезаписан? Используй дамп и логи клиентов.
- Нужен производитель? Определи OUI из MAC.

## Квиз

Проверь себя.

```quiz
- question: Что хранит DHCP-лиз?
  options:
    - 'пароль'
    - 'IP, MAC, имя клиента и время аренды'
    - 'маршруты'
    - 'файлы'
  answer: 1
  explanation: 'Lease фиксирует привязку IP↔MAC и срок аренды.'
- question: Где искать DHCP-лизы на Linux-сервере?
  options:
    - 'в /etc/passwd'
    - 'в /var/lib/dhcp/dhcpd.leases'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'dhcpd.leases — база выданных аренд ISC DHCP.'
- question: Как увидеть DHCP в дампе?
  options:
    - 'по фильтру http'
    - 'tshark -Y bootp'
    - 'по фильтру arp'
    - 'по фильтру dns'
  answer: 1
  explanation: 'DHCP использует BOOTP-формат; фильтр tshark — bootp.'
- question: Зачем сопоставлять IP и MAC?
  options:
    - 'для красоты'
    - 'чтобы привязать сетевой лог к конкретному устройству'
    - 'чтобы ускорить сеть'
    - 'чтобы шифровать'
  answer: 1
  explanation: 'IP динамический, MAC стабилен — связка даёт идентификацию.'
```
