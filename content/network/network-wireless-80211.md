---
id: network-wireless-80211
title: "802.11 Wi-Fi: WPA2/WPA3, handshake, PMKID и evil twin"
category: network
parent: network-mitm-wireless
difficulty: hard
order: 1
tags: [network, wireless, wifi, wpa2, pmkid, handshake, aircrack]
prerequisites: [network-mitm, network-arp-deep]
useful_for:
  - "CTF Network (wireless-задачи)"
  - "Пентест: аудит беспроводных сетей"
  - "Работа: защита Wi-Fi и расследования"
estimated_minutes: 50
summary: "Как устроен Wi-Fi, как перехватить и взломать WPA2-handshake/PMKID, что такое evil twin и почему WPA3 меняет правила."
---

Беспроводные сети — единственный канал, который атакующий может слушать, не имея физического доступа к проводу. Этот урок разбирает 802.11 от кадров до практического взлома WPA2 (handshake и PMKID), подделки точек доступа и того, как WPA3/SAE закрывает часть этих атак.

## Кадры 802.11 и режимы

Wi-Fi — это канальный уровень с собственным набором кадров:

- **Management:** Beacon (реклама AP), Probe Request/Response, Authentication, Association.
- **Control:** RTS/CTS, ACK.
- **Data:** полезная нагрузка.

Режимы: **infrastructure** (через AP), **ad-hoc**, **monitor** (для захвата — интерфейс слушает весь эфир).

Ключевое понятие — **BSSID** (MAC точки доступа) и **SSID** (имя сети). Для захвата нужен адаптер с поддержкой monitor mode и injection.

## WPA2: 4-way handshake

Аутентификация WPA2-Personal (PSK) завершается 4-сторонним рукопожатием:

1. AP → клиент: ANonce.
2. Клиент → AP: SNonce + MIC.
3. AP → клиент: GTK, подтверждение.
4. Клиент → AP: подтверждение.

Из этого handshake можно вывести **PMK** = PBKDF2(passphrase, SSID, 4096). Затем — **PTK**, и MIC проверяется оффлайн. Отсюда классическая атака: перехватить handshake → оффлайн-перебор пароля.

## PMKID-атака (без клиента)

В 2018 обнаружено: точка доступа в первом кадре handshake может включать **PMKID** = HMAC-SHA1(PMK, ...). PMKID можно запросить напрямую у AP (RSN IE), **не дожидаясь клиента**. Это делает атаку пассивнее и надёжнее.

## Evil twin и captive portal

Evil twin — поддельная точка доступа с тем же SSID:

- клиент подключается к «лучшей» AP атакующего;
- через captive portal собирают учётные данные Wi-Fi или корпоративного портала;
- возможен downgrade: заставить клиента использовать открытую сеть и перехватить трафик.

Дополнение — **deauth-атака**: поддельный кадр деаутентификации выкидывает клиента, провоцируя переподключение и handshake (или подключение к evil twin).

## Инструменты и команды

Перевод адаптера в monitor mode:

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon          # обзор сетей
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
```

Захват handshake и деаутентификация (только в своей сети/лаборатории):

```bash
# спровоцировать переподключение клиента
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# проверка, что handshake пойман
aircrack-ng cap-01.cap
```

PMKID-атака:

```bash
sudo hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
hcxpcapngtool -o hash.hc22000 pmkid.pcapng
hashcat -m 22000 hash.hc22000 wordlist.txt
```

## Разобранный пример: от захвата до пароля

Сценарий: своя тестовая сеть `LAB-WIFI`.

1. `airmon-ng start wlan0` → `wlan0mon`.
2. `airodump-ng wlan0mon` → находим BSSID и канал `LAB-WIFI`.
3. `airodump-ng -c 6 --bssid <BSSID> -w lab wlan0mon`.
4. `aireplay-ng --deauth 5 -a <BSSID> wlan0mon` → клиент переподключается, handshake записан.
5. `aircrack-ng lab-01.cap` → если пароль слабый, он найдётся; иначе — `hashcat -m 22000` с правилами/масками.
6. Вывод: стойкость WPA2-Personal упирается в энтропию пароля. Длинная случайная фраза делает перебор бесполезным.

## Защита

- **Длинные случайные пароли** (≥20 символов) — делают оффлайн-перебор нереальным.
- **WPA3/SAE** — устойчив к оффлайн-перебору handshake (см. `network-wpa3`).
- **802.11w (PMF)** — защита management-кадров от deauth-спуфинга.
- **WPA2-Enterprise (802.1X)** — сертификаты вместо PSK; защита от evil twin через проверку сертификата.
- **Мониторинг:** WIDS/WIPS, детект rogue AP и deauth-штормов.

## Частые ошибки

- **Искать пароль без handshake/PMKID.** Нечего перебирать, пока не пойман материал.
- **Использовать только aircrack-ng.** Для GPU-скорости нужен hashcat (`-m 22000`).
- **Забыть про PMF.** Без 802.11w deauth-атака работает; с PMF — нет.
- **Считать WPA2 «взломанным» при слабом пароле.** Ломается не протокол, а пароль.

## WPA3 и SAE: принципиально другой handshake

WPA3-Personal заменяет PSK-обмен на **SAE** (Simultaneous Authentication of Equals) — это PAKE-протокол (Password-Authenticated Key Exchange) на основе схемы Dragonfly над эллиптической кривой. Вместо четырёх EAPOL-сообщений с общим PSK стороны выполняют обмен *commit* и *confirm*: сначала каждая сторона передаёт скаляр и точку кривой, затем подтверждает вычисленный общий секрет. Ключевые свойства:

- **Forward secrecy.** Даже зная пароль, перехваченный handshake нельзя «переиграть»: сессионный ключ прошлых сессий из него не выводится. Классический offline-перебор захваченного WPA3-хэша невозможен — остаётся только активный online-перебор против живой точки доступа.
- **Обязательный PMF.** Управляющие кадры защищаются (802.11w), поэтому простой deauth для форсирования переподключения не срабатывает.
- **Защита от словарных атак на пароль** на уровне протокола: одна попытка угадывания требует активного участия AP.

**Transition mode** (WPA2/WPA3 mixed) — самая частая мисконфигурация. Точка принимает и WPA2-, и WPA3-клиентов. Атакующий отвечает на probe request поддельным beacon/probe response с WPA2-возможностями, клиент откатывается к 4-way handshake, который затем ломается офлайн обычным способом. Это **downgrade attack**.

## Dragonblood: известные атаки на SAE

Исследование Vanhoef & Ronen («Dragonblood», 2019) дало набор атак:

| Атака | Суть | Статус |
|-------|------|--------|
| Timing side-channel | По времени ответа на commit-сообщение перебирается пароль | закрыто патчами |
| Cache-based side-channel | Анализ кэша процесса hostapd | закрыто |
| DoS commit-flood | Флуд commit перегружает AP вычислениями | частично, rate-limit |
| Downgrade в transition mode | Форсирование WPA2-клиента | требует мисконфигурации |
| Group downgrade | Подмена supported groups в beacon | закрыто |

Практические инструменты: `dragonslayer` (downgrade + DoS), `wpa3-ftm`, модифицированный `hostapd-wpe` для подделки SAE. Проверка устойчивости точки:

```bash
# downgrade: слушаем beacon и проверяем, рекламирует ли AP WPA2 в transition mode
sudo tcpdump -i wlan0mon -e -s 256 type mgt subtype beacon | grep -i wpa
# активный флуд commit (только в своей лаборатории!)
dragonslayer --interface wlan0mon --bssid AA:BB:CC:DD:EE:FF --attack dos
```

## Криптография: от PSK до PTK

Понимание вывода ключей объясняет, почему для офлайн-крекинга нужен SSID и почему PMKID так ценен.

```text
PMK  = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 256)     # соль = имя сети
PTK  = PRF-512(PMK, "Pairwise key expansion",
               min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))
KCK  = PTK[0:16]    # EAPOL MIC
KEK  = PTK[16:32]   # шифрование Key Data
TK   = PTK[32:48]   # шифрование данных
```

Отсюда следует: **SSID обязателен** для крекинга (он — соль PBKDF2), а PMKID вычисляется как `HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)` и извлекается из первого EAPOL-кадра без клиента. Поэтому один PMKID заменяет целый handshake.

## Оборудование и режим монитора

Не любой адаптер умеет monitor mode **и** инъекцию. Рабочие чипсеты:

| Чипсет | Адаптер (пример) | Диапазон | Примечание |
|--------|------------------|----------|------------|
| Atheros AR9271 | TP-Link TL-WN722N v1 | 2.4 ГГц | классика, kali-ready |
| RTL8812AU | Alfa AWUS036ACH | 2.4/5 ГГц | нужен драйвер aircrack-ng |
| RTL8814AU | Alfa AWUS1900 | 2.4/5 ГГц | 4 потока |
| MT7612U | Alfa AWUS036ACM | 2.4/5 ГГц | стабильная инъекция |

```bash
sudo airmon-ng check kill            # убить мешающие NetworkManager/wpa_supplicant
sudo airmon-ng start wlan0           # -> wlan0mon
sudo iw dev wlan0mon set channel 6   # фиксируем канал; hopping — только для survey
sudo iwconfig wlan0mon txpower 30    # поднять мощность передатчика
```

## Deauth, beacon flooding и почему это работает

В WPA2 управляющие кадры (deauth, disassoc) **не аутентифицированы**, если не включён PMF (802.11w). Поэтому атакующий может подделать deauth с адресом AP и разорвать соединение любого клиента.

```bash
# массовый deauth, чтобы поймать переподключение и handshake
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
# флуд beacon-фреймами (засорить список сетей у клиента)
sudo mdk4 wlan0mon b -f /tmp/ssids.txt -s 1000
# клиент выпал из сети -> ловим handshake на переподключении
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
```

Контрмера — **802.11w (PMF)**: кадры управления получают MIC, и подделанный deauth отбрасывается.

## Разобранный пример 2: PMKID → hashcat 22000

Продолжение практики из основного урока. Клиента нет, но AP отдаёт PMKID.

```bash
# 1. Снимаем PMKID-кадр (не нужен клиент)
sudo hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
# 2. Конвертируем в единый формат 22000
hcxpcapngtool -o hash.hc22000 -E essidlist dump.pcapng
# 3. Крекинг
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt -O -w 3
```

Вывод `hcxpcapngtool`:
```text
PMKID(s) written to hash.hc22000
EAPOL pairs written to hash.hc22000
```
Результат `hashcat`: `hash.hc22000:MyWifiPass` — пароль восстановлен за минуты, потому что PMKID не требует ни клиента, ни полного handshake. Режимы hashcat: `22000` (PMKID+EAPOL), `2500` (WPA-EAPOL-PBKDF2), `16800` (PMKID legacy).

## Сравнительная таблица: атака, условие, защита

| Атака | Что нужно | Что защищает |
|-------|-----------|--------------|
| 4-way handshake crack | клиент + deauth + SSID | длинная парольная фраза (>=20 симв.), WPA3 |
| PMKID crack | только beacon (нет клиента) | WPA3-only, отключение PMKID |
| Evil twin | клиент ищет сеть | 802.1X/enterprise, cert pinning, VPN |
| Deauth / beacon flood | monitor mode | 802.11w (PMF) |
| Downgrade WPA3→WPA2 | transition mode | WPA3-only, отключить mixed |
| Dragonblood timing | живой SAE-обмен | обновлённый hostapd/прошивка |

## Квиз

```quiz
- question: "Что извлекается из 4-way handshake для оффлайн-перебора WPA2?"
  options:
    - "PMK и MIC, позволяющие проверить пароль оффлайн"
    - "Только SSID"
    - "MAC-адрес клиента"
    - "IP-адрес"
  answer: 0
  explanation: "Из handshake выводят PMK/PTK и проверяют MIC оффлайн при переборе passphrase."
- question: "Чем PMKID-атака отличается от обычного захвата handshake?"
  options:
    - "Не требует подключённого клиента"
    - "Работает только на WPA3"
    - "Не требует monitor mode"
    - "Взламывает WEP"
  answer: 0
  explanation: "PMKID можно получить напрямую у AP, не дожидаясь клиентского handshake."
- question: "Что делает deauth-атака?"
  options:
    - "Шифрует трафик"
    - "Поддельным management-кадром выкидывает клиента, провоцируя переподключение"
    - "Меняет канал AP"
    - "Отключает WPA2"
  answer: 1
  explanation: "Поддельный деаутентификационный кадр заставляет клиента переподключиться и отдать handshake."
- question: "Какая технология защищает management-кадры от спуфинга deauth?"
  options:
    - "802.11w (PMF)"
    - "802.1Q"
    - "WPA2-PSK"
    - "DHCP snooping"
  answer: 0
  explanation: "Protected Management Frames (802.11w) аутентифицирует management-кадры."
- question: "Почему WPA3/SAE устойчив к оффлайн-перебору?"
  options:
    - "Он не использует пароль"
    - "SAE — аутентифицированный обмен, где handshake нельзя проверить оффлайн по словарю"
    - "Он шифрует MAC"
    - "Он использует WEP"
  answer: 1
  explanation: "SAE (Dragonfly) меняет протокол так, что оффлайн-проверка пароля невозможна."
```

## Где пригодится

- **CTF:** wireless-задачи на разбор handshake и восстановление пароля.
- **Пентест:** аудит беспроводной инфраструктуры, rogue AP, evil twin.
- **Bug bounty:** редко напрямую; при оценке физического периметра.
- **Работа (SOC/IR):** детект rogue AP, deauth-штормов и расследование инцидентов Wi-Fi.
