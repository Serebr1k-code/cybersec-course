---
id: net-wireless-80211
title: 'Wi-Fi 802.11 в форензике: подключения и их следы'
category: forensics
parent: forensics-net-lan
difficulty: hard
order: 3
tags: [network, wireless, 80211, wpa, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как анализировать 802.11-кадры: ассоциации устройств, SSID, рукопожатия WPA и следы подключений.'
lab:
  kind: shell
  title: 'Практика: Wi-Fi 802.11 в форензике'
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

Устройство подключалось к беспроводной сети — а значит, где-то остался след: MAC,
SSID, время ассоциации. Если снят Wi-Fi-дамп, из него можно восстановить, кто и когда
подключался. Разберём, как читать 802.11.

## Наш пример: дамп Wi-Fi

## Шаг 1: типы кадров

В 802.11 три класса кадров:

- **management** — beacon, probe, association;
- **control** — ack, rts/cts;
- **data** — сами данные.

Для форензики важнее всего management: там видны SSID и ассоциации.

## Шаг 2: список сетей

```
$ tshark -r wifi.pcap -Y 'wlan.fc.type_subtype==8' -T fields -e wlan.ssid -e wlan.bssid | sort -u
CorpWiFi	02:42:0a:0a:14:01
Guest	02:42:0a:0a:14:02
```

`subtype==8` — это beacon. BSSID — MAC точки доступа.

## Шаг 3: кто подключался

Ассоциация — subtype 0/1 (assoc req/resp):

```
$ tshark -r wifi.pcap -Y 'wlan.fc.type_subtype==0' -T fields -e wlan.sa -e wlan.ssid | head
02:42:0a:0a:14:09	CorpWiFi
```

`wlan.sa` — MAC клиента. Так видно, какие устройства и к каким сетям подключались.

## Шаг 4: WPA-рукопожатие

Ключи WPA получаются из 4-way handshake. Если он есть в дампе, можно проверить пароль
офлайн:

```
$ tshark -r wifi.pcap -Y 'eapol' -T fields -e wlan.sa -e wlan.bssid | head
02:42:0a:0a:14:09	02:42:0a:0a:14:01
```

Пары клиент↔AP — кандидаты для проверки (это уже атакующая сторона, но в защитном
расследовании важно понять, что рукопожатие **перехвачено**).

## Шаг 5: следы на устройстве

На самом хосте остаётся список известных сетей:

```
$ cat /etc/NetworkManager/system-connections/*.nmconnection | grep -i ssid
ssid=CorpWiFi
```

А на macOS — в `com.apple.wifi.plist` (может содержать историю SSID и времени).

## Что мы теперь знаем

- Management-кадры несут SSID и ассоциации.
- `tshark` фильтрует по `wlan.fc.type_subtype`.
- BSSID — MAC точки доступа, `wlan.sa` — клиент.
- EAPOL-кадры = WPA-рукопожатие.
- Список известных сетей остаётся на хосте.

## Если не сработало

- Трафик шифрован? SSID и ассоциации всё равно видны в management.
- Нет дампа? Ищи профили сетей на хосте.
- Нужны данные? Расшифровка требует ключа/рукопожатия.

## Квиз

Проверь себя.

```quiz
- question: Какие кадры 802.11 важнее всего для форензики?
  options:
    - 'control'
    - 'management (beacon/probe/assoc)'
    - 'data'
    - 'нижние'
  answer: 1
  explanation: 'Management-кадры содержат SSID и ассоциации в открытом виде.'
- question: Что такое BSSID?
  options:
    - 'пароль сети'
    - 'MAC-адрес точки доступа'
    - 'имя клиента'
    - 'канал'
  answer: 1
  explanation: 'BSSID идентифицирует конкретную точку доступа.'
- question: Что дают EAPOL-кадры?
  options:
    - 'SSID'
    - 'WPA-рукопожатие для проверки пароля'
    - 'DNS'
    - 'ARP'
  answer: 1
  explanation: 'Из 4-way handshake можно офлайн проверить пароль WPA.'
- question: Где на Linux остаются известные Wi-Fi-сети?
  options:
    - 'в /etc/passwd'
    - 'в /etc/NetworkManager/system-connections/'
    - 'в /boot'
    - 'в /var/log/kern.log'
  answer: 1
  explanation: 'NetworkManager хранит профили подключений с SSID.'
```
