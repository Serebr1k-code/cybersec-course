---
id: network-module-wireless
title: "Беспроводные технологии глубоко: Wi-Fi, Zigbee, NFC и радио"
category: network
parent: network-mitm-wireless
difficulty: easy
order: 1
tags: [network, wireless, wifi, wpa2, wpa3, zigbee, nfc, sdr]
prerequisites: [network-wireless-80211, network-mitm-wireless]
useful_for:
  - "CTF Network (беспроводные задачи)"
  - "Пентест: Wi-Fi, IoT-радио, NFC"
  - "Работа (SOC): детект беспроводных атак"
estimated_minutes: 60
summary: "Модуль по беспроводным технологиям: как устроены Wi-Fi (802.11, WPA2/WPA3), Zigbee/Z-Wave, NFC/RFID и SDR; какие атаки возможны и как от них защищаться."
---

Беспроводной домен — «периметр без провода»: сигнал выходит за пределы здания, и перехватить его может любой в радиусе. Wi-Fi, Zigbee, NFC и радио — разные технологии с разными моделями безопасности, но общий принцип один: если канал доступен, его можно слушать и атаковать. Этот модуль — база для [`network-wpa2-attacks`](network-wpa2-attacks), [`network-zigbee-zwave`](network-zigbee-zwave) и [`network-nfc-rfid`](network-nfc-rfid), опирается на [`network-wireless-80211`](network-wireless-80211).

## Зачем отдельный модуль

Беспроводные сети — частый вход в корпоративную сеть и в устройства IoT:

- **Wi-Fi** — корпоративный доступ, гостевые сети, Wi-Fi как транспорт;
- **Zigbee/Z-Wave** — умный дом, промышленный IoT, датчики;
- **NFC/RFID** — физический доступ, платежи, идентификация;
- **SDR** — универсальный радиоприёмник для анализа любых протоколов.

Понимание этих технологий нужно и для атаки, и для защиты.

## Wi-Fi: 802.11 и безопасность

802.11-кадры делятся на management (beacon, probe, auth, assoc, deauth), control (RTS/CTS/ACK) и data. Безопасность эволюционировала: WEP → WPA → WPA2 (CCMP) → WPA3 (SAE). Каждый шаг закрывал слабости предыдущего.

```bash
# Мониторить Wi-Fi
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
# Собрать handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

## WPA2/WPA3 и их слабости

**WPA2-PSK** аутентифицируется 4-way handshake; его можно перехватить и перебрать офлайн. **PMKID** позволяет получить материал для перебора без клиента. **WPA3-SAE** устойчив к офлайн-перебору, но имеет свои проблемы (downgrade, side-channel). Подробно — в [`network-wpa2-attacks`](network-wpa2-attacks) и [`network-wpa3`](network-wpa3).

## Zigbee, Z-Wave и IoT-радио

**Zigbee** работает поверх IEEE 802.15.4 (2.4 ГГц), использует сеть с координатором и ключами. Слабости: слабые/дефолтные ключи, отсутствие ротации, replay. **Z-Wave** (sub-GHz) имеет S0 (слабый) и S2 (сильный) классы безопасности. Подробно — в `network-zigbee-zwave`.

## NFC/RFID

**RFID/NFC** работают на разных частотах (125 кГц, 13.56 МГц, 860–960 МГц UHF). **Mifare Classic** использует сломанный шифр Crypto1. Клонирование карт доступа и релей NFC — классические атаки. Подробно — в `network-nfc-rfid`.

## SDR и сниффинг

**SDR** (Software Defined Radio) — приёмопередатчик, где обработка сигнала идёт в софте (GNU Radio, gqrx). Позволяет слушать и декодировать почти любой протокол: от пультов до датчиков.

```bash
# gqrx — визуальный SDR
gqrx
# rtl_433 — декодирование датчиков 433/868 МГц
rtl_433 -f 433.92M -F json
# HackRF — передача (только в лаборатории)
hackrf_transfer -r out.bin -f 433920000 -s 2000000
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `aircrack-ng` | Wi-Fi: захват, deauth, перебор |
| `hcxdumptool`/`hcxtools` | PMKID, handshake |
| `bettercap` | Wi-Fi/BLE MITM |
| `killerbee`/`z-attack` | Zigbee |
| `Proxmark3`/`nfcpy` | RFID/NFC |
| `rtl_433`/`gqrx` | SDR |

```bash
# Захватить Wi-Fi-трафик
sudo tcpdump -i wlan0mon -nn -w wifi.pcap
tshark -r wifi.pcap -Y 'wlan.fc.type_subtype==8' | head   # beacons
```

## Атаки: карта векторов

- **Deauth/disassoc** — разрыв соединений, сбор handshake;
- **Evil twin** — поддельная точка доступа (см. `network-evil-twin`);
- **PMKID/KRACK/WPS** — атаки на WPA2 (см. `network-wpa2-attacks`);
- **Zigbee replay/key** — на IoT-радио;
- **NFC relay/clone** — на физический доступ;
- **SDR replay** — на пульты и датчики.

## Типовые ошибки

- **Игнорировать беспроводной периметр** — сигнал выходит за стены.
- **Считать WPA2 «безопасным» по умолчанию** — зависит от пароля.
- **Забывать про WPS** — пин-брутфорс.
- **Не менять дефолтные ключи Zigbee** — тривиальный перехват.
- **Считать NFC «близким»** — релей работает на расстоянии.
- **Путать частоты** — 125 кГц, 13.56 МГц, 2.4 ГГц.
- **Не использовать SDR** — половина устройств остаётся «чёрным ящиком».

## Что дальше / решение

Пройдите [`network-wpa2-attacks`](network-wpa2-attacks), [`network-zigbee-zwave`](network-zigbee-zwave), [`network-nfc-rfid`](network-nfc-rfid). Для Wi-Fi-специфики — [`network-wireless-80211`](network-wireless-80211), [`network-wpa3`](network-wpa3), [`network-evil-twin`](network-evil-twin).

## Практика: обзор беспроводного периметра

```bash
# 1. Wi-Fi: включить монитор и просканировать
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
# 2. Bluetooth/BLE
sudo hcitool lescan
sudo bettercap -iface hci0   # BLE-разведка
# 3. Sub-GHz датчики
rtl_433 -f 433.92M -F json
# 4. NFC/RFID (при наличии ридера)
pm3 --> hf search; pm3 --> lf search
```

За несколько минут вы получаете карту беспроводного окружения: точки доступа, клиенты, BLE-устройства, sub-GHz датчики и карты.

## Сравнение беспроводных технологий

| Технология | Частота | Радиус | Безопасность |
|---|---|---|---|
| Wi-Fi (802.11) | 2.4/5/6 ГГц | десятки м | WPA2/WPA3 |
| Bluetooth/BLE | 2.4 ГГц | ~10 м | pairing |
| Zigbee | 2.4 ГГц | десятки м | ключи сети |
| Z-Wave | sub-GHz | десятки м | S0/S2 |
| NFC/RFID | 125 кГц / 13.56 МГц | см | тип карты |
| LoRa | sub-GHz | км | зависит от приложения |

## Чек-лист беспроводной безопасности

1. Какие **SSID** вещают и какие режимы (WPA2/WPA3/WPS)?
2. Есть ли **rogue AP** и **evil twin**?
3. Используется ли **802.11w (PMF)**?
4. Как защищены **IoT-радио** сети (ключи, ротация)?
5. Контролируется ли **физический доступ** (карты, NFC)?
6. Мониторятся ли **deauth** и аномалии?
7. Сегментирован ли **гостевой Wi-Fi**?

```bash
# Быстрый снимок Wi-Fi
sudo airodump-ng wlan0mon --band abg
# Поиск rogue AP (сравнить с инвентарём BSSID)
sudo airodump-ng wlan0mon | grep -i '<BSSID>'
```

Практический вывод: беспроводной периметр нельзя «закрыть» — сигнал выходит за стены. Защита строится на сильной криптографии, мониторинге эфира, сегментации и физическом контроле.

## Радио-гигиена и мониторинг

Беспроводной эфир нельзя «закрыть», но можно контролировать:

```bash
# 1. Инвентаризация: список своих BSSID
sudo airodump-ng wlan0mon -w inv
# 2. Поиск rogue AP: BSSID вне инвентаря
# сравнить захваченные BSSID с белым списком
# 3. Мониторинг deauth (признак атаки)
tshark -r wifi.pcap -Y 'wlan.fc.type_subtype==12' | wc -l
# 4. Мониторинг WPS
sudo wash -i wlan0mon
```

Дополнительные меры:

- **802.11w (PMF)** — защита management-кадров;
- **WIPS** (Wireless IPS) — автоматический детект rogue AP и deauth;
- **Сегментация** — гостевой Wi-Fi в отдельном VLAN;
- **802.1X** — индивидуальные credentials вместо общего PSK;
- **Экранирование** — снижение утечки сигнала за периметр.

```bash
# Проверить поддержку PMF точкой доступа
tshark -r wifi.pcap -Y 'wlan.rsn.capabilities.mfpc==1' | head
```

## Итоговый вывод

Беспроводной домен требует постоянного мониторинга: инвентарь BSSID, детект deauth/rogue, контроль WPS. В сочетании с WPA3, PMF и сегментацией это делает беспроводную атаку дорогой и заметной.

## Быстрый старт: что взять в поле

- **Wi-Fi:** адаптер с monitor/injection (Alfa), `aircrack-ng`, `hcxdumptool`, `bettercap`.
- **IoT-радио:** RTL-SDR (`rtl_433`), адаптер 802.15.4 (`killerbee`), Proxmark3.
- **SDR:** HackRF/PortaPack для приёма и передачи sub-GHz.
- **NFC/RFID:** Proxmark3, ChameleonMini, Flipper Zero.

```bash
# Единый снимок окружения
sudo airmon-ng start wlan0; sudo airodump-ng wlan0mon &
rtl_433 -f 433.92M -F json &
sudo hcitool lescan
```

Минимальный набор покрывает Wi-Fi, sub-GHz, BLE и NFC — основные беспроводные технологии в пентесте. Дальше — по задаче: Zigbee требует отдельного 802.15.4-адаптера, а для анализа сигналов нужен SDR.

## Квиз

```quiz
- question: "Какая аутентификация используется в WPA3?"
  options:
    - "SAE (Dragonfly)"
    - "PSK 4-way"
    - "WEP"
    - "Open"
  answer: 0
  explanation: "WPA3 использует SAE, устойчивый к офлайн-перебору."
- question: "Что позволяет получить PMKID?"
  options:
    - "Материал для офлайн-перебора без клиента"
    - "Пароль в открытом виде"
    - "Сертификат"
    - "MAC точки доступа"
  answer: 0
  explanation: "PMKID берётся из одного кадра и годится для перебора."
- question: "Поверх какого стандарта работает Zigbee?"
  options:
    - "IEEE 802.15.4"
    - "802.11"
    - "802.3"
    - "Bluetooth"
  answer: 0
  explanation: "Zigbee использует 802.15.4 на 2.4 ГГц."
- question: "Какой шифр сломан в Mifare Classic?"
  options:
    - "Crypto1"
    - "AES"
    - "ChaCha20"
    - "RSA"
  answer: 0
  explanation: "Crypto1 восстановлен, что позволяет клонировать карты."
- question: "Для чего нужен SDR?"
  options:
    - "Для приёма и декодирования произвольных радиосигналов"
    - "Для шифрования Wi-Fi"
    - "Для назначения IP"
    - "Для управления VLAN"
  answer: 0
  explanation: "SDR обрабатывает сигнал в софте, декодируя протоколы."
```

## Где пригодится

- **CTF:** задачи с беспроводными протоколами и дампами.
- **Пентест:** Wi-Fi, IoT-радио, NFC, физический доступ.
- **SOC:** детект deauth, rogue AP, аномалий радио.
- **Инженерия:** настройка WPA3, ротация ключей, сегментация.
