#!/usr/bin/env python3
"""Deepen thin forensics lessons — run 4 (linux-net-artifacts, apple-silicon, arp-mac, package-logs, cicd)."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["linux-network-artifacts"] = """## Полный набор источников сетевой активности

Сеть на Linux оставляет следы в нескольких местах. Полезно знать их все:

| Источник | Что даёт | Живёт |
|---|---|---|
| `ss -tunap` | сокеты + процессы | сейчас |
| `/proc/net/tcp`, `udp` | сырые таблицы в hex | сейчас |
| `/proc/net/unix` | unix-сокеты | сейчас |
| `conntrack -L` | история соединений | пока живёт запись |
| `ip neigh` / `/proc/net/arp` | ARP/MAC | кэш |
| `nstat` / `/proc/net/netstat` | счётчики (retrans, errors) | с загрузки |
| `lsof -i` | сокеты по файлам | сейчас |
| `auditd` | execve + connect | по правилам |
| `journald`/syslog | события сети, DNS | по ротации |
| `/etc/hosts`, `resolv.conf` | статическая конфигурация | пока файл |

Комбинация «сейчас» + «история» + «конфигурация» даёт полную картину: с кем хост общался,
через какой процесс и как это настроено.

## Чтение /proc/net/tcp: hex-адреса

Когда нет `ss`/`netstat`, таблицы читают напрямую. Адрес там в hex и **little-endian по
байтам**:

```
$ cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  ...
   0: 0A0A1405:D426 CB007105:01BB 01 00000000:00000000 ...
```

- `0A0A1405` → `0A.0A.14.05` → `10.10.20.5`;
- `CB007105` → `CB.00.71.05` → `203.0.113.5`;
- `D426` = 54322, `01BB` = 443;
- `st` = `01` (ESTABLISHED), `0A` = LISTEN, `06` = TIME_WAIT.

Быстрая расшифровка:

```
$ awk 'NR>1{print $2, $3, $4}' /proc/net/tcp | while read l r s; do
    echo "$s $(printf '%d' 0x${l##*:}) <- $(printf '%d' 0x${r##*:})"
  done
```

## conntrack детально

Netfilter conntrack хранит состояние каждого потока и, в отличие от `/proc/net/tcp`,
помнит и закрытые соединения (пока запись не истекла):

```
$ conntrack -L -p tcp --dport 443
tcp 6 431999 ESTABLISHED src=10.10.20.5 dst=203.0.113.5 sport=54322 dport=443 \\
    src=203.0.113.5 dst=10.10.20.5 sport=443 dport=54322 [ASSURED] mark=0 use=1
$ conntrack -L | awk '{print $5, $6}' | sort | uniq -c | sort -rn | head
```

`ESTABLISHED`, `TIME_WAIT`, `CLOSE_WAIT` показывают, какие соединения были. Если
conntrack-модуль не загружен — истории нет, остаются только логи firewall (`iptables -j
LOG`, `nft` с логированием).

## Сокет ↔ inode ↔ процесс

Ядро связывает процесс и соединение через inode сокета. Это позволяет найти все процессы,
использующие сокет:

```
$ ss -tnp | grep 203.0.113.5
tcp ESTAB 0 0 10.10.20.5:54322 203.0.113.5:443 users:(("x",pid=991,fd=4))
$ ls -l /proc/991/fd/4
... 4 -> socket:[45678]
$ grep -rl 45678 /proc/*/fdinfo/ 2>/dev/null
```

Если процесс уже завершился, inode сокета «повисает» в `/proc/net/tcp` без владельца — это
признак недавно закрытого соединения. Тогда смотри `auditd` (`connect`, `execve`) и
историю `journald`.

## Другие артефакты: DNS, auditd, eBPF

- **DNS-запросы** — `journalctl -u systemd-resolved`, `dnsmasq`-логи, `/var/log/named`;
- **auditd** — правила на `syscall connect`/`execve` дают точное время и PID;
- **eBPF** — `bpftrace`/`bcc` могут логировать соединения в реальном времени;
- **`~/.bash_history`** — команды `curl`, `nc`, `scp` выдают адреса;
- **`/etc/hosts`, `/etc/resolv.conf`** — подмена DNS-сервера часто остаётся здесь.

## Практический разбор CTF

Задача: «какой процесс связался с C2». Порядок:

```
$ ss -tunap | grep -v '127.0.0.1\\|::1'      # активные соединения
$ conntrack -L 2>/dev/null | grep -v '127.0.0.1' | awk '{print $5, $6, $7, $8}' | sort -u
$ ip neigh show                               # кто был рядом
$ grep -a 'connect(' /var/log/audit/audit.log | tail
```

Найдя PID, смотрим `/proc/<pid>/exe` (что за бинарь) и `/proc/<pid>/cwd` (откуда запущен).

## Ограничения

- `/proc/net/*` показывает **только** текущие сокеты — после закрытия записи исчезают.
- conntrack хранит ограниченное число записей и очищается по таймауту.
- Без прав root часть информации (`-p`, conntrack, auditd) недоступна.
- Зашифрованный трафик виден как «соединение есть», но содержимого нет.
- Данные в `/proc` меняются ежемоментно — фиксируй их до выключения хоста."""

ADDS["macos-apple-silicon"] = """## Что меняется в загрузке

Apple Silicon использует цепочку доверия, начинающуюся с **Boot ROM**, и проверяет
каждый этап по подписи. Это меняет подход к «загрузке с внешнего носителя»:

- **Boot Policy** — можно ли грузиться с внешнего диска, задаётся отдельно для каждой
  системы; по умолчанию запрещено.
- **Recovery** — доступна по удержанию кнопки питания; требует пароля администратора.
- **Secure Boot** — три режима: `Full`, `Medium`, `Permissive`; влияет на то, что можно
  загрузить.

```
$ bputil -d          # показать boot policy (в recovery)
$ system_profiler SPiBridgeDataType | head
```

Практический вывод: чтобы загрузить внешний форензик-образ, нужно снять boot policy —
а это **изменение состояния** системы, которое обязано быть в отчёте.

## Rosetta 2 и его артефакты

x86-бинарники на Apple Silicon исполняются через **Rosetta 2** (трансляция). Это оставляет
следы:

- пакет `/Library/Apple/usr/libexec/oah/` и `RosettaUpdateAuto`;
- записи в unified log о трансляции;
- файл `rosetta` в кэшах.

```
$ pgrep -lf oahd          # демон трансляции
$ log show --predicate 'subsystem == "com.apple.oahd"' --last 1h | head
```

Если подозрительный бинарник — x86, он всё равно запустится; но факт использования Rosetta
сужает список возможных авторов (не все тулы имеют arm64-версию).

## Secure Enclave (SEP) и что в нём

Secure Enclave Processor — отдельный сопроцессор с собственной ОС. В нём хранятся:

- ключи шифрования диска (FileVault) — выводятся из пароля + SEP;
- ключи Touch ID / Face ID;
- ключи iCloud Keychain (частично);
- ключи Apple Pay.

Извлечь ключ из SEP **штатно невозможно** — он не покидает чип. Следствия для форензики:

- без пароля пользователя расшифровать том не получится;
- Touch ID «привязан» к устройству, перенос невозможен;
- при перезагрузке нужно вводить пароль заново (SEP не хранит разблокированный ключ в
  энергонезависимом виде).

## Унифицированная память и сбор дампа

На Apple Silicon память общая для CPU, GPU и Neural Engine. Это значит:

- классического «отдельного видеопамять-дампа» нет;
- порядок размещения структур в памяти может отличаться от Intel;
- многие Intel-ориентированные плагины Volatility не работают на arm64-дампах.

Сбор живой памяти требует отключённого SIP или особых привилегий; для arm64-дампов
используют инструменты с поддержкой ARM (например, `osxpmem`-форки, `mac memory`).
Дампы снимаются **до** выключения, пока ключи FileVault ещё в памяти.

## APFS, снапшоты и раздельные тома

macOS на Apple Silicon использует APFS с несколькими томами в одной группе:

| Том | Роль |
|---|---|
| System | только чтение, подписан, монтируется в `/` |
| Data | пользовательские данные, в `/System/Volumes/Data` |
| Preboot | загрузочные данные, ключи |
| VM | swap |
| Recovery | среда восстановления |

APFS ведёт **снапшоты** (в т.ч. автоматические Time Machine local snapshots) — это
форензик-золото: можно вернуться к состоянию до атаки:

```
$ diskutil apfs listSnapshots /
$ tmutil listlocalsnapshots /
$ mount_apfs -s com.apple.TimeMachine.2026-01-13... /dev/disk3s1 /mnt
```

## Чек-лист сбора и анализа

1. Определить платформу (`uname -m`, `system_profiler SPHardwareDataType`).
2. Проверить SIP (`csrutil status`) и boot policy (`bputil -d`).
3. Снять живые данные (память, `log show`, `fseventsd`) до выключения.
4. Снять образ с разблокированного тома (FileVault открыт).
5. Найти APFS-снапшоты и сравнить состояния.
6. Учесть Rosetta-артефакты, если анализируешь x86-бинарники.

## Ограничения

- Без пароля/разблокировки — диск не прочитать (аппаратное шифрование).
- Secure Boot + boot policy затрудняют внешний сбор.
- Многие инструменты не поддерживают arm64 — проверяй совместимость.
- SEP не даёт вытащить ключи — «обойти» это невозможно штатными средствами."""

ADDS["net-arp-mac"] = """## Формат ARP-пакета

ARP — простой протокол с фиксированной структурой. Понимание полей помогает читать дамп:

| Поле | Размер | Смысл |
|---|---|---|
| Hardware type | 2 | 1 = Ethernet |
| Protocol type | 2 | 0x0800 = IPv4 |
| HW addr len | 1 | 6 для Ethernet |
| Proto addr len | 1 | 4 для IPv4 |
| Opcode | 2 | 1 = request, 2 = reply |
| Sender HW addr | 6 | MAC отправителя |
| Sender proto addr | 4 | IP отправителя |
| Target HW addr | 6 | MAC цели (нули в запросе) |
| Target proto addr | 4 | IP цели |

Именно поэтому в запросе `Target HW addr` пуст (хост не знает MAC), а в ответе заполнен.

## Типы MAC-адресов

Первый байт MAC кодирует тип адреса:

| Признак | Значение |
|---|---|
| младший бит 0 | unicast (один получатель) |
| младший бит 1 | multicast (группа) |
| все биты 1 (`ff:ff:ff:ff:ff:ff`) | broadcast |
| второй бит = 1 | локально администрируемый (не заводской) |
| первые 3 байта (OUI) | производитель |

`02:42:...` — второй бит выставлен, значит локально администрируемый: так задают MAC
виртуальные интерфейсы Docker (`02:42:ac:...`) и другие гипервизоры. `00:0c:29` — VMware,
`08:00:27` — VirtualBox, `52:54:00` — QEMU/KVM.

```
$ grep -iE '^(0242|000c29|080027|5254)' /usr/share/nmap/nmap-mac-prefixes
```

## ARP-спуфинг: как детектировать

Атака состоит в том, что злоумышленник шлёт **незапрошенные** ARP-ответы (gratuitous
ARP), привязывая IP шлюза к своему MAC. Детект строится на аномалиях:

- один IP анонсируется с **разных** MAC в коротком окне;
- массовые ARP-ответы без предшествующих запросов;
- MAC шлюза сменился (сверь с эталоном);
- ARP-ответы приходят чаще, чем раз в обычный таймаут кэша.

```
$ tshark -r capture.pcap -Y 'arp.opcode==2' -T fields \\
    -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort | uniq -c | sort -rn | head
$ tshark -r capture.pcap -Y 'arp.opcode==1' | wc -l   # сколько было запросов
```

Если ответов на порядок больше запросов — почти наверняка спуфинг.

## Gratuitous ARP и другие аномалии

- **Gratuitous ARP** (IP отправителя = IP цели) — нормален при смене MAC/старте
  интерфейса, но массовый поток — атака или misconfiguration.
- **ARP-probe** (target IP = 0.0.0.0) — проверка дубликата адреса, норма.
- **Флуд ARP** — DoS или попытка исчерпать таблицу коммутатора.
- **Reverse ARP (RARP)** — устаревший, может указывать на легаси-устройство.

Контекст решает: единичный gratuitous ARP при загрузке — норма, сотни в минуту — нет.

## IPv6: NDP вместо ARP

В IPv6 ARP заменён на **NDP** (Neighbor Discovery Protocol, ICMPv6):

```
$ tshark -r capture.pcap -Y 'icmpv6.type==135 || icmpv6.type==136'
```

Тип 135 — Neighbor Solicitation (аналог ARP-запроса), 136 — Neighbor Advertisement
(аналог ответа). Спуфинг в IPv6 называется **NA spoofing** и детектируется теми же
признаками (один адрес с разных MAC). Не забывай про IPv6 — атаки на него часто
«невидимы» для тех, кто смотрит только ARP.

## Практический разбор CTF

Задача: «найди MITM в сегменте». Шаги:

```
$ tshark -r capture.pcap -Y 'arp' -T fields -e frame.time -e arp.opcode \\
    -e arp.src.proto_ipv4 -e arp.src.hw_mac > arp.tsv
$ awk '$2==2{print $3, $4}' arp.tsv | sort | uniq -c | sort -rn | head
$ awk '{print $4}' arp.tsv | sort | uniq -c          # какие MAC вообще светились
```

Дальше сопоставляем «чужой» MAC с известными вендорными префиксами и ищем хост с таким
MAC. Часто флаг лежит в MAC/имени атакующего хоста.

## Ограничения

- ARP виден только в **своём** L2-сегменте; на маршрутизаторе его уже нет.
- Кэш ARP быстро истекает — без дампа история теряется.
- Инкапсуляция (VXLAN, GRE) скрывает исходный ARP.
- Шифрованные туннели L2 (IPsec) делают ARP нечитаемым извне."""

ADDS["linux-package-logs"] = """## Полный набор артефактов менеджеров пакетов

Кроме `dpkg.log` есть ещё несколько источников — их стоит проверять вместе:

| Артефакт | Что содержит |
|---|---|
| `/var/log/dpkg.log` | install/remove/purge/upgrade (Debian/Ubuntu) |
| `/var/log/apt/history.log` | команды apt + Requested-By |
| `/var/log/apt/term.log` | вывод установки (иногда с предупреждениями) |
| `/var/lib/dpkg/status` | текущее состояние всех пакетов |
| `/var/lib/dpkg/info/` | файлы и скрипты (maintainer scripts) |
| `/var/log/dnf.log`, `yum.log` | RHEL/Fedora |
| `/var/lib/rpm/` | база rpm |
| `/var/log/apt/eipp.log.xz` | расширенная история apt |

`/var/lib/dpkg/info/*.list` хранит список файлов пакета — по нему видно, что именно
«приехало» вместе с пакетом, включая конфиги и скрипты.

## dpkg: логи и статус

```
$ grep -E 'install |remove |purge ' /var/log/dpkg.log | tail
$ grep -A3 -B1 'netcat' /var/log/dpkg.log.1 /var/log/dpkg.log
$ dpkg -l | awk '$1=="ii"{print $2, $3}' | head     # установленные пакеты
```

Обрати внимание на **время и версию**: свежий install пакета, которого нет в базовом
образе, — подозрительно. Особенно если это тул вроде `nmap`, `netcat`, `socat`, `tcpdump`,
`chisel`, `frp`.

## apt: history и term

`apt/history.log` даёт командную строку, что критично для восстановления намерения:

```
$ grep -E 'Start-Date|Commandline|Install:|Remove:' /var/log/apt/history.log | tail -20
Start-Date: 2026-01-14  03:20:08
Commandline: apt-get install -y nmap socat
Requested-By: www-data (33)
Install: nmap:amd64 (7.94), socat:amd64 (1.7.4.1)
```

`Requested-By: www-data` означает, что установку запустил веб-сервер — почти наверняка
через RCE веб-приложения. Это прямой индикатор компромисса.

## rpm/yum/dnf

На RHEL-семействе:

```
$ rpm -qa --last | head -10
$ grep -iE 'Installed|Erased' /var/log/dnf.log | tail
$ dnf history list | head
$ rpm -qi nmap | grep -E 'Install Date|Vendor'
```

`dnf history` показывает целые транзакции с командами — аналог apt history.

## Верификация целостности пакета

Чтобы понять, изменён ли бинарник после установки:

```
$ debsums -c                       # Debian: файлы, не совпадающие с пакетом
$ rpm -Va | grep -v '^S.5'         # RHEL: проверка всех файлов
$ dpkg -V                          # пересчёт хэшей установленных пакетов
```

Если `debsums`/`rpm -V` показывает расхождение — файл пакета подменён (троянизация).

## Ручная установка: следы без менеджера

Если бинарник скопирован вручную (curl/wget), в dpkg/apt его не будет. Тогда:

```
$ stat /usr/bin/suspicious | grep -E 'Modify|Change'
$ grep -aiE 'wget|curl|chmod \\+x|scp' ~/.bash_history /root/.bash_history
$ find / -newermt '2026-01-14 03:00' -type f -not -path '/proc/*' 2>/dev/null | head
$ grep -a 'execve' /var/log/audit/audit.log | grep suspicious | tail
```

`find -newermt` по времени инцидента — быстрый способ найти всё, что появилось в окне.

## Практический разбор и чек-лист

1. Найти подозрительный бинарник (`find`, `stat`, `debsums`).
2. Проверить `dpkg.log`/`apt/history.log`/`dnf.log` на его пакет.
3. Если пакет есть — взять время, версию, Commandline, Requested-By.
4. Проверить `remove`/`purge` в коротком окне (заметание следов).
5. Если пакета нет — искать ручную установку (`bash_history`, `auditd`, `find -newermt`).
6. Проверить целостность (`debsums -c`, `rpm -Va`).

## Ограничения

- Логи ротируются и сжимаются — проверяй `.1`, `.gz` (`zgrep`).
- В контейнерах пакеты ставятся в слой образа — смотри `Dockerfile`/`docker history`.
- Умный атакующий чистит `dpkg.log` — тогда опирайся на `auditd`, `find`, метки файлов.
- `Requested-By` может отсутствовать у старых версий apt."""

ADDS["forensics-cicd"] = """## Типы CI/CD и их артефакты

Каждая система хранит свой набор следов, и знать их важно:

| Система | Где искать историю | Особенность |
|---|---|---|
| GitHub Actions | API `/actions/runs`, artifacts | логи в вебе, ephemeral runners |
| GitLab CI | `/pipelines`, job logs | `CI_*` переменные |
| Jenkins | `builds/`, `jenkins.log` | Groovy-скрипты, `build.xml` |
| ArgoCD | Application history | sync-события в кластер |
| Azure DevOps | `/pipelines/runs` | service connections |

Общее правило: у каждой системы есть **история запусков** (кто, когда, из какого
коммита), **логи шагов** и **артефакты**. Их комбинация и восстанавливает атаку.

## Логи запусков: что смотреть

Запуск описывается набором полей, и аномалия почти всегда в одном из них:

```
$ ci list-builds --pipeline deploy-prod --limit 10
#1239  main        success  2026-03-09T10:00:00Z  alice
#1240  main        success  2026-03-10T03:08:00Z  alice
#1241  feature/x   success  2026-03-10T03:12:00Z  bot    <-- аномалия
```

Красные флаги:

- ветка/форк, из которой деплой в прод обычно не идёт;
- сервисный аккаунт (`bot`) вместо человека;
- нетипичное время (03:12 ночи);
- изменение самого файла пайплайна (`.github/workflows/*.yml`) в том же коммите;
- шаги, которых нет в обычном пайплайне (`curl` на внешний хост, установка тула).

## Секреты и их ротация

Пайплайн читает секреты из менеджера или переменных CI. При компрометации нужно понять,
**какие** секреты утекли и их отозвать:

```
$ ci get-run #1241 --secrets-accessed
$ vault audit list -path=secret/
```

Проверяй аудит менеджера секретов (Vault, AWS Secrets Manager, GitLab masked variables):
кто и когда читал секреты, не расширяли ли права перед запуском. Все прочитанные во время
инцидента секреты подлежат ротации — даже если неясно, утекли ли они.

## Раннеры: компрометация и следы

Раннер — машина, исполняющая пайплайн. Если это self-hosted раннер, он часто живёт
долго и хранит кэши, ключи и рабочие каталоги между запусками:

```
$ ls ~/actions-runner/_work/ /var/lib/jenkins/workspace/
$ grep -aiE 'token|secret|password' ~/actions-runner/_diag/*.log | head
```

Признаки компрометации раннера: изменение его образа, установка пакетов вне пайплайна,
обращения к секретам из шага, который их не должен видеть, сетевые соединения к внешним
адресам во время сборки. Ephemeral (одноразовые) раннеры снижают риск, но затрудняют
форензику — машина уже уничтожена, остаются только логи.

## Артефакты и образы: диффы

Самый частый вектор — **внедрение кода в артефакт сборки** (образ). Сравнение с
предыдущим артефактом выдаёт добавленное:

```
$ docker history app:1.2.4-x
$ docker save app:1.2.4-x -o new.tar && docker save app:1.2.3 -o old.tar
$ mkdir n o && tar -xf new.tar -C n && tar -xf old.tar -C o
$ diff -rq o/ n/ | head
```

Любой лишний слой, файл или изменённый бинарник — след. Также проверяй манифесты,
SBOM и подписи (`cosign verify`).

## Практический разбор CTF

Задача: «через какой запуск произошла компрометация». Порядок:

```
$ ci list-builds --limit 50 | grep -vE 'main .* alice'    # нетипичные запуски
$ ci get-build #1241 --logs | grep -iE 'curl|wget|chmod|base64|token'
$ ci get-build #1241 --changed-files
$ docker history app:1.2.4-x | grep -iE 'ADD|COPY|RUN'
```

Флаг часто лежит в логе шага (вывод `env`, случайно залогированный токен) или в
добавленном файле артефакта.

## Ограничения

- Логи CI хранятся ограниченное время (у GitHub Actions по умолчанию 90 дней) — потом
  исчезают.
- Ephemeral-раннеры уничтожаются — живых артефактов нет.
- Секреты в логах могут быть замаскированы (`***`) — тогда их не восстановить из логов.
- Пайплайн может быть «доверенным» — вывод строится только на сравнении с нормой.

## Если сработало / не сработало

Если логи недоступны — работай по артефактам и метаданным запусков (кто/когда/коммит).
Если раннер уничтожен — ищи его логи и внешние обращения. Если подозрение на секреты —
ротируй всё, к чему имел доступ запуск, не дожидаясь доказательств утечки."""

def main() -> int:
    base = "content/forensics/"
    for lid, add in ADDS.items():
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
        if not m:
            print("SKIP (no quiz):", lid); continue
        if "## Квиз" in add or "## Где пригодится" in add:
            raise SystemExit("bad add for " + lid)
        out = s[:m.start()] + add + "\n\n" + s[m.start():]
        open(path, "w", encoding="utf-8").write(out)
        print("deepened", lid, "+", len(add.split()), "tokens")
    return 0

if __name__ == "__main__":
    sys.exit(main())
