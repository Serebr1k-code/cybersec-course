---
id: network-ssh-tunnel
title: "SSH-туннели: локальный, удалённый, динамический и их применение"
category: network
parent: network-tunneling
difficulty: medium
order: 3
tags: [network, ssh, tunnel, port-forward, socks, pivot]
prerequisites: [network-covert, network-firewall-piercing]
useful_for:
  - "CTF Network (pivot и туннели)"
  - "Пентест: доступ к внутренним сервисам"
  - "Работа: безопасный удалённый доступ"
estimated_minutes: 50
summary: "Три вида SSH-перенаправления портов, их практическое применение для pivoting и обхода сетевых ограничений."
---
SSH умеет перенаправлять порты, превращая одну легитимную сессию в канал доступа к внутренним сервисам. Это базовый инструмент pivoting: с compromised-хоста вы «протаскиваете» трафик к БД, панелям и другим сегментам. Главное достоинство — туннель выглядит как обычный SSH-трафик и редко блокируется. Урок опирается на [`network-covert`](network-covert) и [`network-firewall-piercing`](network-firewall-piercing).

## Три вида перенаправления

| Тип | Флаг | Смысл | Типовое применение |
|-----|------|-------|--------------------|
| **Локальный** | `-L [bind:]lport:host:port` | локальный порт → удалённая цель через SSH-сервер | доступ к внутреннему сервису |
| **Удалённый** | `-R [bind:]rport:host:port` | удалённый порт → локальная/третья цель | reverse-доступ, публикация сервиса |
| **Динамический** | `-D [bind:]port` | локальный SOCKS-прокси через SSH | проксирование множества целей |

Дополнительно: `-N` (не выполнять команду), `-f` (в фон), `-T` (без tty), `-J` (jump host), `-W` (stdio-перенаправление), `-o ServerAliveInterval`, `-o ExitOnForwardFailure`, `-C` (сжатие), `-4`/`-6` (семейство адресов).

Ключ к пониманию: `-L` открывает порт **локально** (у вас) и ведёт к цели **с точки зрения SSH-сервера**; `-R` открывает порт **на сервере** и ведёт к цели с вашей стороны.

## Практическое применение

```bash
# Локальный: внутренняя БД 10.0.0.5:3306 -> localhost:3307
ssh -N -L 3307:10.0.0.5:3306 user@bastion
mysql -h 127.0.0.1 -P 3307 -u root -p

# Удалённый: опубликовать локальный 8080 на сервере (reverse)
ssh -N -R 8080:127.0.0.1:8080 user@attacker-host
# (на attacker-host localhost:8080 -> ваш локальный сервис)

# Динамический SOCKS5 (прокси на всё через bastion)
ssh -N -D 1080 user@bastion
curl --socks5 127.0.0.1:1080 http://10.0.0.5/
proxychains4 nmap -sT -Pn 10.0.0.5

# Через jump host
ssh -J jumphost user@internal
# stdio-перенаправление (для инструментов, требующих сокет)
ssh -W 10.0.0.5:445 user@bastion
```

## Настройки, которые важны

- **`ServerAliveInterval 30`** — keepalive, чтобы туннель не отвалился.
- **`ExitOnForwardFailure yes`** — не оставлять «полутуннель».
- **`GatewayPorts yes`** на сервере — чтобы `-R` слушал не только localhost.
- **`AllowTcpForwarding`** на сервере — может быть `no` (тогда туннели запрещены).
- **`PermitOpen`** — ограничение целей.
- **`ClientAliveInterval`** на сервере — серверный keepalive.

```bash
# ~/.ssh/config
Host bastion
  HostName 203.0.113.10
  User analyst
  ServerAliveInterval 30
  ExitOnForwardFailure yes
  # автозапуск туннеля при подключении:
  LocalForward 3307 10.0.0.5:3306
```

## Разобранный пример: доступ к внутренней БД

```bash
# 1. Есть доступ к bastion, внутренняя сеть 10.0.0.0/24
# 2. Пробрасываем MySQL
ssh -N -L 3307:10.0.0.5:3306 user@bastion &
# 3. Подключаемся как к localhost
mysql -h 127.0.0.1 -P 3307 -u app -p
# 4. Нужны ещё сервисы? Динамический прокси
ssh -N -D 1080 user@bastion &
proxychains4 -q nmap -sT -Pn -p22,80,443,3306 10.0.0.0/24
# 5. Для внутреннего веб-сервера
curl --socks5-hostname 127.0.0.1:1080 http://10.0.0.7/
```

Проверка, что туннель жив и слушает:

```bash
ss -ltnp | grep -E '3307|1080'
# tcp LISTEN 0 128 127.0.0.1:3307 0.0.0.0:* users:(("ssh",pid=1234,...))
```

## Защита (для администраторов)

- `AllowTcpForwarding no` (если не нужны туннели) или `PermitOpen`-whitelist.
- `GatewayPorts no` (по умолчанию `-R` слушает только localhost).
- Логировать необычные перенаправления; мониторить длительные SOCKS-сессии.
- Ограничить `-D` через политику; MFA на bastion.
- Отдельный `Match`-блок для групп, которым forwarding не нужен.

```bash
# /etc/ssh/sshd_config
Match Group contractors
    AllowTcpForwarding no
    PermitOpen none
```

## Частые ошибки

- **Забывать `-N`** — SSH откроет shell и туннель закроется с сессией.
- **Не использовать keepalive** — туннель отваливается по таймауту.
- **Путать направления `-L` и `-R`** — «локальный порт → цель» vs «удалённый порт → цель».
- **Полагать `-R` публичным** — без `GatewayPorts` он слушает только localhost.
- **Игнорировать `AllowTcpForwarding`** — сервер может запрещать перенаправление.
- **Не проверять `ExitOnForwardFailure`** — «полурабочий» туннель вводит в заблуждение.
- **Пробрасывать через localhost-цель неверно** — цель в `-L` разрешается на стороне сервера, а в `-R` — на вашей.

## Продвинутые схемы

- **Многоуровневый pivot**: `ssh -J jump1,jump2 user@target` (ProxyJump) — цепочка jump-хостов.
- **SOCKS через jump**: `ssh -D 1080 -J bastion user@internal` — динамический прокси «сквозь» цепочку.
- **Обратный SOCKS**: `ssh -R 1080 user@attacker` + `DynamicForward` на клиенте — прокси со стороны сервера.
- **`-W` (stdio)**: `ssh -W 10.0.0.5:443 user@bastion` — сырой поток к цели, удобно для инструментов, требующих сокет (например, `proxychains` или `ProxyCommand`).
- **ProxyCommand**: `ssh -o ProxyCommand='ssh -W %h:%p bastion' target`.

```bash
# ~/.ssh/config — удобные профили
Host internal-db
  HostName 10.0.0.5
  ProxyJump bastion
  LocalForward 3307 127.0.0.1:3306
```

## Автопереподключение и надёжность

```bash
# autossh — держит туннель живым
autossh -M 0 -N -D 1080 user@bastion \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes
```

`ExitOnForwardFailure` гарантирует, что при неудаче проброса SSH завершится, а не останется «полутуннелем». `ServerAliveInterval` шлёт keepalive. Для systemd-юнита используйте `Restart=always`.

## Проксификация инструментов

Не все инструменты умеют SOCKS. Используйте `proxychains`:

```bash
# /etc/proxychains4.conf -> socks5 127.0.0.1 1080
proxychains4 -q nmap -sT -Pn -p22,445 10.0.0.0/24
proxychains4 -q curl http://10.0.0.7/
proxychains4 -q smbclient -L //10.0.0.9 -N
proxychains4 -q ssh user@10.0.0.5          # цепочка SSH через SOCKS
```

`nmap` через SOCKS работает только в `-sT` (connect), без raw-сканов (SYN/UDP/OS-detect). Для UDP-сканов нужен туннель на уровне IP (`ssh -w`/VPN).

## OPSEC и следы

- SSH-туннели **легитимны** и потому малозаметны, но в логах видны `direct-tcpip`/`session`-каналы.
- Длительные SOCKS-сессии и необычные `-D`-подключения — индикатор.
- `GatewayPorts yes` + `-R` на внешний адрес = потенциальный backdoor; аудируйте.
- Мониторьте `sshd`-логи на множественные `direct-tcpip` с одного пользователя.
- Счётчики `bytes_sent`/`bytes_received` в логах SSH показывают объём проксированного трафика.

## SSH-туннели в контейнерах и облаке

- В **Kubernetes** SSH-туннель к поду: `kubectl port-forward` (аналог `-L`), либо `ssh` через `kubectl exec`.
- В **облаке** bastion-хост часто единственная точка входа — `ssh -J bastion` или SSM/IAP-туннели.
- **Контейнер** без SSH: используйте `socat`/`chisel` внутри, либо `nsenter` на хосте.
- **Проброс в namespace**: `kubectl port-forward svc/db 3307:3306`.

## Диагностика проблем

```bash
# Туннель открылся, но сервис недоступен
ss -ltnp | grep 3307                 # слушает ли локальный порт
ssh -v -N -L 3307:10.0.0.5:3306 user@bastion   # verbose
# Разрешает ли сервер проброс?
grep -iE 'AllowTcpForwarding|PermitOpen|GatewayPorts' /etc/ssh/sshd_config
# Цель видит только bastion? Проверить с bastion
ssh user@bastion 'nc -vz 10.0.0.5 3306'
```

Частая причина: цель доступна только с bastion (нужен проброс **с** bastion), либо сервер запрещает forwarding.

## Что дальше / решение

Дерево решений при pivot:

1. **Есть SSH-доступ к хосту-мосту** → используйте его.
2. **Нужен один сервис** → `-L` (внутренний сервис к себе) или `-R` (свой сервис наружу).
3. **Нужно много целей** → `-D` SOCKS + `proxychains` (только `-sT` для nmap).
4. **Цепочка хостов** → `-J`/`ProxyJump` или `ProxyCommand`.
5. **Туннель отваливается** → `autossh` + `ServerAliveInterval` + `ExitOnForwardFailure`.
6. **Сервер запрещает forwarding** → ищите другой протокол (chisel/ligolo/socat), см. [`network-covert`](network-covert).

Решение-эвристика: для доступа к внутренней сети через один хост — `-D` + proxychains; для публикации reverse-шелла/сервиса — `-R` с `GatewayPorts` на своей стороне.

## Резюме

- `-L` локальный, `-R` обратный, `-D` SOCKS.
- `-J` для цепочек, `-W` для сырого потока, `ProxyCommand` в конфиге.
- Keepalive + `ExitOnForwardFailure` для надёжности.
- `proxychains` для инструментов без SOCKS.
- Администраторам — `AllowTcpForwarding`/`PermitOpen` для контроля.

## Агент и X11: удобно, но опасно

**Agent forwarding** (`-A`) и **X11 forwarding** (`-X`) расширяют поверхность атаки:

- `-A` пробрасывает ваш `ssh-agent` на удалённый хост — при компрометации хоста атакующий может использовать ваши ключи (но не украсть сами ключи). Риск: lateral movement от вашего имени.
- `-X` открывает X11-канал — старый протокол легко перехватить/подделать; используйте `-X` только через `ssh -Y` в доверенной сети, лучше `-o ForwardX11Trusted=no`.

```bash
ssh -A user@bastion          # agent forwarding (осторожно)
ssh -X user@host             # X11 (недоверенный)
ssh -Y user@host             # X11 доверенный (ещё опаснее)
```

## Туннелирование не-TCP

SSH перенаправляет только **TCP**. UDP (DNS, VoIP, игры) через `-L`/`-D` не пойдёт напрямую. Варианты:

- `-w local:tun` — L3-туннель (TUN), тогда любой IP-протокол, включая UDP, идёт через SSH.
- Обернуть UDP в TCP (socat/udptunnel), но это меняет характеристики.
- Для полноценного pivoting — `sshuttle` (проксирует по правилам, поддерживает DNS).

```bash
# sshuttle: прокси для подсети, включая DNS, без SOCKS
sshuttle -r user@bastion 10.0.0.0/24
# L3-туннель
sudo ssh -w 0:0 user@bastion
sudo ip addr add 172.16.0.1/30 dev tun0; sudo ip link set tun0 up
```

## SSH в условиях фильтрации

Если исходящий SSH (22) заблокирован:

- **Смена порта**: сервер слушает 443/8443 — `ssh -p 443 user@host`.
- **sslh**: один порт 443 обслуживает и SSH, и HTTPS — трафик выглядит как TLS.
- **ProxyCommand + netcat/openssl**: `ssh -o ProxyCommand='openssl s_client -connect host:443 -quiet' user@target`.
- **Port knocking**: сервер открывает 22 только после последовательности «стуков».

```bash
# SSH через HTTPS-туннель (ProxyCommand)
ssh -o ProxyCommand='ncat --proxy proxy:8080 --proxy-type http %h %p' user@host
```

## Полезные однострочники диагностики

```bash
ssh -Q cipher                       # список поддерживаемых шифров
ssh -o PreferredAuthentications=publickey -v user@host   # как проходит аутентификация
ssh -O check user@bastion           # статус master-соединения (ControlMaster)
```

`ControlMaster`/`ControlPersist` в конфиге переиспользует одно соединение для нескольких туннелей — меньше нагрузки и следов.

## Квиз

```quiz
- question: "Какой флаг SSH создаёт локальный SOCKS-прокси?"
  options:
    - "-D"
    - "-L"
    - "-R"
    - "-N"
  answer: 0
  explanation: "-D поднимает динамическое перенаправление (SOCKS)."
- question: "Что делает `ssh -L 8080:10.0.0.5:80 user@host`?"
  options:
    - "Локальный порт 8080 перенаправляет на 10.0.0.5:80 через host"
    - "Удалённый 8080 идёт на локальный 80"
    - "Создаёт SOCKS-прокси"
    - "Копирует файлы"
  answer: 0
  explanation: "-L пробрасывает удалённую цель на локальный порт."
- question: "Когда используют `-R`?"
  options:
    - "Когда нужно опубликовать локальный сервис на удалённом хосте (reverse)"
    - "Когда нужен SOCKS"
    - "Когда нужно скопировать файлы"
    - "Когда нужно сжать трафик"
  answer: 0
  explanation: "-R делает обратный проброс: удалённый порт ведёт к вам."
- question: "Зачем добавляют ServerAliveInterval?"
  options:
    - "Чтобы туннель не отваливался по таймауту"
    - "Чтобы включить шифрование"
    - "Чтобы ускорить SSH"
    - "Чтобы включить IPv6"
  answer: 0
  explanation: "Keepalive-пакеты поддерживают соединение живым."
- question: "Какая настройка SSH-сервера ограничивает перенаправление портов?"
  options:
    - "AllowTcpForwarding no / PermitOpen"
    - "PasswordAuthentication"
    - "X11Forwarding"
    - "UsePAM"
  answer: 0
  explanation: "AllowTcpForwarding/PermitOpen управляют разрешёнными перенаправлениями."
```

## Где пригодится

- **CTF:** pivot к внутренним сервисам через одну SSH-сессию.
- **Пентест:** доступ к БД/панелям в закрытых сегментах.
- **Работа:** безопасный удалённый доступ, jump-хосты.
- **Red team:** скрытые каналы через легитимный SSH.
- **Администрирование:** защита SSH от злоупотребления туннелями.
