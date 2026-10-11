---
id: network-ipsec-ike
title: "IPsec и IKE глубоко: режимы, фазы и атаки на согласование"
category: network
parent: network-module-vpn
difficulty: medium
order: 1
tags: [network, ipsec, ike, esp, ah, vpn, aggressive-mode]
prerequisites: [network-module-vpn, network-vpn]
useful_for:
  - "CTF Network (IPsec/IKE)"
  - "Пентест: анализ и атаки на IPsec"
  - "Работа (SOC): детект IKE-аномалий"
estimated_minutes: 60
summary: "IPsec изнутри: AH/ESP, транспортный и туннельный режимы, IKEv1/v2 и их фазы, aggressive mode и его утечки, NAT-T, инструменты ike-scan и strongSwan, защита."
---

IPsec — самый «корпоративный» VPN: его используют для site-to-site и удалённого доступа. Он состоит из двух частей: **IKE** (согласование ключей) и **ESP/AH** (защита данных). Ошибки в IKE (aggressive mode, слабые алгоритмы) — классические векторы атаки. Урок продолжает [`network-module-vpn`](network-module-vpn).

## Что такое IPsec

IPsec — набор протоколов на сетевом уровне. Компоненты:

- **IKE** — обмен ключами и параметрами (UDP 500, NAT-T 4500);
- **ESP** — шифрование + аутентификация (proto 50);
- **AH** — аутентификация заголовка без шифрования (proto 51);
- **SA** — Security Association: однонаправленный набор параметров.

SA идентифицируется тройкой: SPI (индекс), IP получателя, протокол (ESP/AH).

## AH и ESP

| Протокол | Шифрование | Аутентификация | NAT-friendly |
|---|---|---|---|
| ESP | да | да | да (с NAT-T) |
| AH | нет | да (весь пакет) | нет (ломается NAT) |

AH аутентифицирует весь IP-пакет, включая адреса, поэтому несовместим с NAT. ESP шифрует payload и работает через NAT при использовании NAT-T (инкапсуляция в UDP 4500).

## Транспортный и туннельный режимы

- **Transport** — защищает только payload исходного IP-пакета; адреса видны. Используется host-to-host.
- **Tunnel** — инкапсулирует весь IP-пакет в новый; адреса скрыты. Используется site-to-site и удалённым доступом.

```text
Transport: [IP hdr][ESP hdr][encrypted payload]
Tunnel:    [new IP hdr][ESP hdr][encrypted [orig IP hdr][payload]]
```

## IKEv1 и IKEv2

**IKEv1** — две фазы: Phase 1 (защищённый канал, main или aggressive mode) и Phase 2 (SA для данных). **IKEv2** — упрощён, устойчивее, поддерживает MOBIKE, но всё ещё допускает слабые настройки.

| Свойство | IKEv1 | IKEv2 |
|---|---|---|
| Фазы | 2 | 2 (упрощены) |
| Режимы Phase 1 | main, aggressive | только один |
| Утечка в aggressive | да (ID/хэш) | нет |
| MOBIKE | нет | да |

## Aggressive mode и его утечка

В **aggressive mode** (IKEv1) идентификатор и хэш передаются в открытом виде до установления шифрования. Атакующий может:

- узнать **идентификатор** (email/имя пользователя);
- собрать **хэш PSK** для офлайн-перебора;
- определить группу и алгоритмы.

```bash
# Обнаружить IKE и его режим
sudo ike-scan -M -A 10.0.0.1
# Получить детали (main mode)
sudo ike-scan -M 10.0.0.1
# nmap-скрипт версии
sudo nmap -sU -p 500 --script ike-version 10.0.0.1
```

## Фазы IKE на проводе

```bash
# Захватить IKE
sudo tcpdump -i eth0 -nn 'udp port 500 or udp port 4500'
# Разобрать фазы и тип обмена
tshark -r cap.pcap -Y 'isakmp' -T fields -e isakmp.version -e isakmp.exchangetype -e isakmp.flags | head
# Найти aggressive mode (exchange type 4, IKEv1)
tshark -r cap.pcap -Y 'isakmp.exchangetype==4' | head
```

## Атаки на IPsec

- **PSK-перебор** — из aggressive mode хэша (`psk-crack`, hashcat);
- **Downgrade** — заставить выбрать DES/3DES/MD5;
- **Offline dictionary** — если PSK слабый;
- **SA-инъекция** — поддельные пакеты в существующую SA;
- **DoS** — заваливание IKE-обмена;
- **Metadata** — кто с кем и как часто.

```bash
# Перебор PSK из aggressive mode (лаборатория)
# psk-crack -d words.txt aggressive.psk
# hashcat -m 5400 aggressive.hash words.txt
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `ike-scan` | обнаружение, режим, fingerprint |
| `nmap --script ike-version` | версия и вендор |
| `strongswan`/`swanctl` | сервер/клиент IKEv2 |
| `psk-crack` | перебор PSK (aggressive) |
| `tcpdump`/`tshark` | захват и разбор |

```bash
# strongSwan: поднять IKEv2-сервер
sudo swanctl --load-all
sudo swanctl --list-sas
# Клиент
sudo swanctl --initiate --child net
```

## Защита

| Мера | Против чего |
|---|---|
| IKEv2 вместо IKEv1 | aggressive mode-утечки |
| Отключить aggressive mode | сбор хэшей PSK |
| Сильный PSK / сертификаты | перебор |
| Только AEAD (AES-GCM, SHA-256) | downgrade |
| Строгие proposals (без DES/3DES) | слабые алгоритмы |
| MFA поверх VPN | компрометация PSK |
| Мониторинг IKE-обмена | аномалии |

```text
# strongSwan: строгий proposal
esp_proposals = aes256gcm16-sha256-modp2048
ike_proposals = aes256gcm16-sha256-modp2048
```

## Частые ошибки

- **Оставлять IKEv1 aggressive** — утечка идентификатора и хэша.
- **Слабый PSK** — перебор за минуты.
- **Разрешать DES/3DES/MD5** — downgrade.
- **AH через NAT** — не работает.
- **Игнорировать NAT-T** — обрыв туннеля за NAT.
- **Не менять ключи** — долгоживущие SA.
- **Не логировать IKE** — атаки невидимы.

## Что дальше / решение

После IPsec переходите к [`network-sstp-l2tp`](network-sstp-l2tp) (PPP-based VPN). Для современных решений — [`network-wireguard`](network-wireguard).

## Практика: ike-scan и разбор ответов

```bash
# Main mode: узнать параметры
sudo ike-scan -M 10.0.0.1
# Aggressive mode: получить идентификатор (осторожно)
sudo ike-scan -M -A 10.0.0.1
# Показать поддерживаемые трансформы
sudo ike-scan -M --trans=5,2,1,2 10.0.0.1
# Идентифицировать вендор по vendor ID
sudo ike-scan -M --showbackoff 10.0.0.1
```

Ответ в aggressive mode содержит **ID и хэш PSK** — это и есть утечка. Хэш можно перебрать офлайн.

## Лаборатория: strongSwan

```bash
# Конфигурация IKEv2 (swanctl)
cat > /etc/swanctl/conf.d/lab.conf <<'EOF'
connections {
  lab {
    version = 2
    proposals = aes256gcm16-sha256-modp2048
    local_addrs = 10.0.0.1
    remote_addrs = 0.0.0.0/0
    local { auth = psk; id = server }
    remote { auth = psk; id = client }
    children { net { local_ts = 10.0.0.0/24; esp_proposals = aes256gcm16-sha256 } }
  }
}
secrets { ike-lab { id-1 = server; id-2 = client; secret = S3cretPSK } }
EOF
sudo swanctl --load-all
sudo swanctl --list-sas
```

Сравните с IKEv1 aggressive: в IKEv2 идентификаторы защищены, а proposals можно жёстко ограничить, исключив слабые алгоритмы.

## Чек-лист IPsec

1. Версия IKE (v2 предпочтительна).
2. Отключён ли **aggressive mode**?
3. Только **AEAD** (AES-GCM/ChaCha20) и SHA-256+?
4. **Сильный PSK** или сертификаты?
5. Настроен ли **NAT-T** для клиентов за NAT?
6. Регулярная **ротация ключей**?
7. Мониторинг **IKE-обмена** и ошибок?

```bash
# Снимок конфигурации
sudo swanctl --list-conns
sudo ipsec statusall | head
```

Вывод: IPsec надёжен, если IKEv2, сильный PSK/сертификаты, строгие proposals и ротация. Слабости почти всегда — из-за legacy-настроек (IKEv1, aggressive, DES/3DES), а не из-за протокола.

## Итог по IPsec

IPsec защищает трафик на сетевом уровне и остаётся стандартом корпоративных VPN. Его слабости почти всегда конфигурационные:

- **IKEv1 aggressive mode** — утечка ID/хэша;
- **слабый PSK** — офлайн-перебор;
- **legacy-алгоритмы** (DES/3DES/MD5) — downgrade;
- **долгоживущие SA** — компрометация без ротации.

```bash
# Итоговая проверка
sudo ike-scan -M 10.0.0.1 | grep -iE "SA=|Main|Aggressive"
sudo nmap -sU -p 500 --script ike-version 10.0.0.1
```

Практическое правило: **IKEv2 + сильный PSK или сертификаты + AEAD-only proposals + ротация**. Это закрывает все практические векторы, оставляя лишь метаданные (кто с кем), которые не устраняются в принципе.

## Квиз

```quiz
- question: "Какой протокол IPsec только аутентифицирует, не шифруя?"
  options:
    - "AH (proto 51)"
    - "ESP (proto 50)"
    - "IKE"
    - "GRE"
  answer: 0
  explanation: "AH аутентифицирует весь пакет, но не шифрует."
- question: "Почему AH плохо работает через NAT?"
  options:
    - "Он аутентифицирует IP-адреса, которые NAT меняет"
    - "Он не поддерживает IPv4"
    - "Он шифрует заголовок"
    - "Он использует TCP"
  answer: 0
  explanation: "Изменение адресов NAT ломает проверку целостности AH."
- question: "Чем опасен aggressive mode в IKEv1?"
  options:
    - "Утечка идентификатора и хэша PSK до шифрования"
    - "Он медленный"
    - "Он требует IPv6"
    - "Он блокирует ESP"
  answer: 0
  explanation: "Хэш PSK можно собрать и перебрать офлайн."
- question: "Что защищает трафик в туннельном режиме?"
  options:
    - "Весь исходный IP-пакет инкапсулируется"
    - "Только payload"
    - "Только заголовок TCP"
    - "Ничего"
  answer: 0
  explanation: "Tunnel-режим скрывает и адреса, и payload."
- question: "Какая мера устраняет утечки aggressive mode?"
  options:
    - "Перейти на IKEv2 и отключить aggressive mode"
    - "Включить AH"
    - "Использовать 3DES"
    - "Отключить NAT-T"
  answer: 0
  explanation: "IKEv2 не имеет aggressive mode-утечек."
```

## Где пригодится

- **CTF:** задачи с IKE-дампами и PSK.
- **Пентест:** обнаружение IPsec, перебор PSK, downgrade.
- **SOC:** детект aggressive mode и аномалий IKE.
- **Инженерия:** строгие proposals, IKEv2, сертификаты.
