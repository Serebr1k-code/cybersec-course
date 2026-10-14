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
lab:
  kind: shell
  title: "Практика: разбор IKE и aggressive mode"
  toolset: [core, tshark]
  workdir: /home/student/task
  files: [task.md, ike.pcap]
  check: "grep -q 'client@corp.local' answer.txt"
  hints:
    - "Начни с обзора: `tshark -r ike.pcap -Y isakmp -T fields -e isakmp.version -e isakmp.exchangetype`."
    - "Тип обмена 4 при версии 1 — это aggressive mode: он отдаёт идентификатор до шифрования."
    - "Достань FQDN: `tshark -r ike.pcap -Y 'isakmp.exchangetype==4' -T fields -e isakmp.id.data.fqdn`."
---

## Вопрос, с которого всё начинается

Компания соединяет офисы через **IPsec** — это стандартный корпоративный VPN. Ты нашёл на периметре открытые порты 500 и 4500 (UDP) и хочешь понять, что там за VPN, насколько крепка его аутентификация и можно ли её сломать. IPsec состоит из двух частей: **IKE** (согласование ключей) и **ESP/AH** (защита данных).

Слабости обычно прячутся в IKE. Разберём.

Этот урок продолжает [`network-module-vpn`](network-module-vpn) и [`network-vpn`](network-vpn).

## Наш пример: опрашиваем IKE

Видим открытый UDP/500. Опрашиваем сервис:

```
$ sudo ike-scan -M 10.0.0.1
10.0.0.1        Main Mode Handshake returned HDR=(CKY-R=...)
    SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024)
    VID=...
```

Сервер ответил параметрами: шифр 3DES, хэш SHA1, аутентификация **PSK** (общий пароль), группа modp1024. Уже видно слабые места — legacy-алгоритмы и общий пароль. Разберём, почему это важно.

## Шаг 1: что такое IPsec

IPsec — набор протоколов на сетевом уровне:

- **IKE** — обмен ключами и параметрами (UDP 500, NAT-T 4500);
- **ESP** — шифрование + аутентификация (IP-протокол 50);
- **AH** — только аутентификация заголовка (IP-протокол 51);
- **SA** (Security Association) — однонаправленный набор параметров.

| Протокол | Шифрование | Аутентификация | NAT-friendly |
|---|---|---|---|
| ESP | да | да | да (с NAT-T) |
| AH | нет | да (весь пакет) | нет |

AH аутентифицирует весь IP-пакет, включая адреса, поэтому **несовместим с NAT** (NAT их меняет). ESP шифрует payload и работает через NAT при использовании NAT-T.

## Шаг 2: режимы

- **Transport** — защищает только payload; адреса видны (host-to-host).
- **Tunnel** — инкапсулирует весь IP-пакет в новый; адреса скрыты (site-to-site, удалённый доступ).

```text
Transport: [IP hdr][ESP hdr][encrypted payload]
Tunnel:    [new IP hdr][ESP hdr][encrypted [orig IP hdr][payload]]
```

## Шаг 3: IKEv1 против IKEv2

**IKEv1** имеет две фазы: Phase 1 (защищённый канал, main или **aggressive** mode) и Phase 2 (SA для данных). **IKEv2** упрощён и устойчивее.

| Свойство | IKEv1 | IKEv2 |
|---|---|---|
| Режимы Phase 1 | main, aggressive | только один |
| Утечка в aggressive | да (ID/хэш) | нет |
| MOBIKE | нет | да |

## Шаг 4: aggressive mode и его утечка

В **aggressive mode** (IKEv1) идентификатор и хэш передаются в открытом виде **до** установления шифрования. Проверим, поддерживает ли сервер aggressive mode:

```
$ sudo ike-scan -M -A 10.0.0.1
10.0.0.1        Aggressive Mode Handshake returned HDR=(CKY-R=...)
    SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024)
    KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=client@corp.local)
    Hash(20 bytes)
```

Мы получили **идентификатор** (`client@corp.local`) и **хэш PSK**. Теперь хэш можно перебрать офлайн:

```
$ psk-crack -d wordlist.txt aggressive.psk
Starting psk-crack on aggressive.psk
Found key: "S3cretPSK"
```

Пароль найден — и теперь можно подключиться к VPN как легитимный клиент.

## Шаг 5: фазы IKE на проводе

```
$ tshark -r cap.pcap -Y 'isakmp' -T fields -e isakmp.version -e isakmp.exchangetype | head
1    4
1    2
```

`exchangetype 4` при версии 1 — это aggressive mode. Так аномалию видно в дампе.

## Шаг 6: защита

| Мера | Против чего |
|---|---|
| **IKEv2** вместо IKEv1 | aggressive mode-утечки |
| Отключить aggressive mode | сбор хэшей PSK |
| Сильный PSK / сертификаты | перебор |
| Только AEAD (AES-GCM, SHA-256) | downgrade |
| Строгие proposals (без DES/3DES) | слабые алгоритмы |
| MFA поверх VPN | компрометация PSK |

Строгий proposal в strongSwan:

```text
ike_proposals = aes256gcm16-sha256-modp2048
esp_proposals = aes256gcm16-sha256-modp2048
```

Ключевой вывод: слабости IPsec почти всегда **конфигурационные** (IKEv1, aggressive, DES/3DES), а не в самом протоколе.

## Если не сработало

`ike-scan` не даёт ответа или PSK не подбирается? Проверь:

- **NAT-T.** За NAT IKE идёт на UDP 4500 — пробуй оба порта.
- **Main mode вместо aggressive.** В main mode хэш PSK недоступен — офлайн-перебор невозможен.
- **Сильный PSK.** Даже собрав хэш, подобрать сложный пароль не выйдет — используй словарь/правила, но не бесконечный перебор.
- **IKEv2.** Там нет aggressive mode, и перебирать нечего — вектор закрыт.

## Инструменты

| Инструмент | Назначение |
|---|---|
| `ike-scan` | обнаружение, режим, fingerprint |
| `nmap --script ike-version` | версия и вендор |
| `strongswan` / `swanctl` | сервер/клиент IKEv2 |
| `psk-crack` | перебор PSK (aggressive) |
| `tcpdump` / `tshark` | захват и разбор |

## Лаборатория: strongSwan

Подними IKEv2-сервер и сравни его с IKEv1 aggressive:

```
$ sudo swanctl --load-all
$ sudo swanctl --list-sas
```

В конфиге задай строгий proposal (`aes256gcm16-sha256-modp2048`) и PSK. В IKEv2 идентификаторы защищены, а набор алгоритмов жёстко ограничен — именно это закрывает утечки aggressive mode. Дополнительно можно поднять старый strongSwan с IKEv1 aggressive и убедиться, что `ike-scan -A` вытаскивает ID и хэш — так видно разницу между «уязвимо» и «исправлено».

## NAT-T и почему AH не проходит через NAT

Когда IPsec-клиент находится за NAT, его внутренний адрес не виден снаружи. Протокол **NAT-T** (NAT Traversal) решает это, инкапсулируя ESP в UDP-пакеты на порт **4500** — так NAT корректно отслеживает сессию. Поэтому на периметре всегда проверяют оба порта: 500 (IKE) и 4500 (NAT-T).

А вот **AH** через NAT не работает принципиально: он аутентифицирует весь IP-пакет вместе с адресами, а NAT их подменяет — проверка целостности падает. Поэтому в реальных сетях с NAT используют ESP, а не AH.

## Шаг 7: IKEv2 изнутри — почему он закрывает утечки

IKEv2 сократил фазы до двух обменов и сделал идентификаторы защищёнными. Первый обмен — **IKE_SA_INIT**: стороны договариваются о криптоалгоритмах, обмениваются nonce и Diffie-Hellman. Второй — **IKE_AUTH**: здесь идёт аутентификация, и всё содержимое уже **зашифровано** ключом из первого обмена.

```
$ tshark -r ikev2.pcap -Y 'isakmp' -T fields -e isakmp.version -e isakmp.exchangetype
2    34
2    35
```

`version 2`, exchangetype `34` (IKE_SA_INIT) и `35` (IKE_AUTH) — это уже не aggressive mode. Идентификатор клиента летит внутри зашифрованного IKE_AUTH, а не в открытом виде, поэтому трюк с `ike-scan -A` не работает.

Практический вывод: если сервер отвечает на IKEv2, PSK-перебора не будет — остаётся брутфорс «в лоб» (медленно и шумно) либо поиск PSK в конфигах других сервисов.

## Шаг 8: как находить IPsec в разведке

IPsec не виден как веб-сервис, поэтому его ищут по портам и фингерпринтам.

- **UDP 500** — IKE (основной).
- **UDP 4500** — NAT-T.
- **IP proto 50/51** — ESP/AH (не TCP/UDP, портов нет).

nmap проверяет версию и вендор через NSE:

```
$ sudo nmap -sU -p500,4500 --script ike-version 10.0.0.1
500/udp open  isakmp
| ike-version:
|   vendor: strongSwan
|   attributes: IKEv2
```

`ike-version` вытаскивает вендор и поддержку IKEv2, а `ike-scan` — точный набор алгоритмов. Сопоставив вендор с известными версиями, быстро понимаешь, что за устройство на периметре (Cisco ASA, strongSwan, Fortigate) и какие у него типовые мисконфиги.

## PSK против сертификатов

Два способа аутентификации в IKE дают принципиально разную стойкость:

- **PSK (pre-shared key)** — общий пароль у всех клиентов. Если он слаб, а включён aggressive mode, хэш перебирается офлайн. Даже без aggressive брутфорс «в лоб» по IKE идёт, но медленно.
- **Сертификаты (EAP-TLS/X.509)** — у каждого клиента свой ключ; перебирать нечего. Единственный вектор — кража ключа или слабая проверка сертификата сервера.

Правило: **PSK годится только для site-to-site между двумя устройствами**, где его нельзя подобрать интерактивно. Для удалённого доступа сотрудников — только сертификаты и MFA.

## Что искать в захваченном дампе

Если у тебя есть PCAP с IKE, разбор сводится к нескольким фильтрам:

```
$ tshark -r cap.pcap -Y 'isakmp' -T fields -e isakmp.version -e isakmp.exchangetype
1    2     # main mode (IKEv1)
1    4     # aggressive mode — утечка
2    34    # IKE_SA_INIT (IKEv2)
```

`exchangetype 4` при версии 1 — красный флаг: ищи в кадрах ID и Hash. Если видишь `version 2` с типами 34/35 — утечек нет, и перебор бесполезен.

## Что мы теперь знаем

- IPsec = IKE (согласование) + ESP/AH (данные); ESP шифрует, AH только аутентифицирует.
- AH несовместим с NAT; ESP работает через NAT-T (UDP 4500).
- Aggressive mode IKEv1 отдаёт идентификатор и хэш PSK до шифрования.
- Хэш PSK перебирается офлайн (`psk-crack`), после чего вход в VPN возможен.
- Защита — IKEv2, отключение aggressive, сильный PSK/сертификаты, AEAD-only.
- В дампе aggressive mode — это `version 1, exchangetype 4`; IKEv2 — `version 2, types 34/35`.
- PSK подходит только для site-to-site; для пользователей — сертификаты и MFA.

## Квиз

Проверь себя.

```quiz
- question: 'Какой протокол IPsec только аутентифицирует, не шифруя?'
  options:
    - 'AH (proto 51)'
    - 'ESP (proto 50)'
    - 'IKE'
    - 'GRE'
  answer: 0
  explanation: 'AH аутентифицирует весь пакет, но не шифрует.'
- question: 'Почему AH плохо работает через NAT?'
  options:
    - 'Он аутентифицирует IP-адреса, которые NAT меняет'
    - 'Он не поддерживает IPv4'
    - 'Он шифрует заголовок'
    - 'Он использует TCP'
  answer: 0
  explanation: 'Изменение адресов NAT ломает проверку целостности AH.'
- question: 'Чем опасен aggressive mode в IKEv1?'
  options:
    - 'Утечка идентификатора и хэша PSK до шифрования'
    - 'Он медленный'
    - 'Он требует IPv6'
    - 'Он блокирует ESP'
  answer: 0
  explanation: 'Хэш PSK можно собрать и перебрать офлайн.'
- question: 'Что защищает трафик в туннельном режиме?'
  options:
    - 'Весь исходный IP-пакет инкапсулируется'
    - 'Только payload'
    - 'Только заголовок TCP'
    - 'Ничего'
  answer: 0
  explanation: 'Tunnel-режим скрывает и адреса, и payload.'
- question: 'Какая мера устраняет утечки aggressive mode?'
  options:
    - 'Перейти на IKEv2 и отключить aggressive mode'
    - 'Включить AH'
    - 'Использовать 3DES'
    - 'Отключить NAT-T'
  answer: 0
  explanation: 'IKEv2 не имеет aggressive mode-утечек.'
```

## Куда дальше

Мы разобрали IPsec и слабости согласования ключей. Дальше — PPP-based VPN (L2TP/SSTP), которые часто встречаются наряду с IPsec. А пока запомни: **IPsec крепок ровно настолько, насколько строги его proposals и аутентификация.**

## Где пригодится

- **CTF:** задачи с IKE-дампами и PSK.
- **Пентест:** обнаружение IPsec, перебор PSK, downgrade.
- **SOC:** детект aggressive mode и аномалий IKE.
- **Инженерия:** строгие proposals, IKEv2, сертификаты.
