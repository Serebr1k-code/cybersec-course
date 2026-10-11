---
id: network-snmp
title: "SNMP: энумерация, утечки и злоупотребление community-строками"
category: network
parent: network-portscan
difficulty: medium
order: 4
tags: [network, snmp, enumeration, community, mib, udp]
prerequisites: [network-portscan, network-nmap-deep]
useful_for:
  - "CTF Network (SNMP-задачи)"
  - "Пентест: разведка сетевого оборудования"
  - "Работа: защита и мониторинг SNMP"
estimated_minutes: 45
summary: "Как SNMP устроен, почему community-строка = пароль, и как вытащить из устройства конфигурацию, интерфейсы и учётки."
---
SNMP (Simple Network Management Protocol) — протокол управления сетевым оборудованием (роутеры, коммутаторы, принтеры, ИБП, серверы, АТС). В версиях v1/v2c аутентификация — это **community-строка**, передаваемая в открытом виде. Слабая строка (`public`, `private`) = фактический пароль на чтение (а иногда и запись) всей конфигурации устройства. Урок опирается на [`network-portscan`](network-portscan) и [`network-nmap-deep`](network-nmap-deep).

## Как устроен SNMP: модель менеджер-агент

SNMP — это не «один запрос», а архитектура из трёх ролей:

- **Менеджер** (manager) — система мониторинга (Zabbix, Nagios, LibreNMS, PRTG), которая опрашивает устройства.
- **Агент** (agent) — демон на устройстве (`snmpd` на Linux, встроенный SNMP на Cisco/Juniper), который отвечает на запросы.
- **MIB** (Management Information Base) — база описаний объектов; сами данные лежат в дереве **OID** (Object Identifier), например `1.3.6.1.2.1.1.5` = `sysName`.

Порты: запросы менеджера — **UDP/161**, traps (асинхронные уведомления от агента к менеджеру) — **UDP/162**. SNMP полностью работает поверх UDP — это и делает его быстрым, и делает перебор шумным и медленным (нет TCP-подтверждений, потери пакетов).

Операции протокола:

| Операция | Смысл |
|---|---|
| `GET` | прочитать один OID |
| `GETNEXT` | «следующий» OID (используется для обхода дерева) |
| `GETBULK` | пакетный обход (только v2c/v3) |
| `SET` | **записать** значение OID (нужен rw-доступ) |
| `TRAP` / `INFORM` | уведомление от агента |
| `RESPONSE` | ответ агента |

Community-строка — не только «пароль», но и «право»: `ro` (read-only) или `rw` (read-write). Одно устройство может иметь несколько community: одна read-only для мониторинга, другая read-write для администрирования. Строка `private` по традиции даёт `rw`.

## Версии и их безопасность

- **v1** — базовая, только community, нет bulk.
- **v2c** — bulk-запросы, 64-битные счётчики, но аутентификация всё та же открытая community. Самая распространённая версия «в дикой природе» и самая уязвимая.
- **v3** — пользователи, уровни безопасности:
  - `noAuthNoPriv` — фактически как v2c, только с именем пользователя;
  - `authNoPriv` — HMAC-аутентификация (MD5 или SHA), но данные открыты;
  - `authPriv` — аутентификация **и** шифрование (DES или AES).

`authPriv` — единственный по-настоящему защищённый режим. `noAuthNoPriv` практически так же уязвим, как v2c: перехватив пакет, вы читаете всё.

## Что можно вытащить из устройства

- **Системное** (`system`, `1.3.6.1.2.1.1`): `sysDescr` (модель/версия прошивки), `sysName`, `sysContact`, `sysLocation`, `sysUpTime`.
- **Интерфейсы** (`ifTable`, `1.3.6.1.2.1.2.2`): список, статусы, `ifPhysAddress` (MAC), скорости.
- **IP-адреса** (`ipAddrTable`, `1.3.6.1.2.1.4.20.1.1`) и **маршруты** (`ipRouteTable`, `1.3.6.1.2.1.4.21`).
- **ARP-таблица** (`ipNetToMediaTable`, `1.3.6.1.2.1.3.1.1`) — соседи в сети: мгновенная карта сегмента.
- **TCP/UDP-таблицы** (`tcpConnTable`, `udpTable`) — какие сервисы слушают.
- **Процессы** (`hrSWRun*`, `1.3.6.1.2.1.25.4`) и **установленное ПО** (`hrSWInstalled*`, `1.3.6.1.2.1.25.6`) — версии, уязвимости.
- **Учётки** — иногда в vendor-MIB, в `sysContact`/`sysLocation`, в логах через traps.
- **Конфигурация** — через write-доступ (`SET`) или vendor-MIB (Cisco `CISCO-CONFIG-COPY-MIB`).

## Инструменты и команды

```bash
# Перебор community-строк (быстро, UDP)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.0.0.5
# Скан UDP/161 + NSE-скрипты
nmap -sU -p 161 --script snmp-info,snmp-brute,snmp-sysdescr 10.0.0.5

# Ручной опрос
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.1       # system
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.2.2.1.2 # ifDescr (интерфейсы)
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.4.20.1.1 # ipAdEntAddr
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.3.1.1.2  # atPhysAddress (ARP)
snmpbulkwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1       # v2c bulk
snmpget -v2c -c public 10.0.0.5 1.3.6.1.2.1.1.5.0      # один OID

# "Человеческий" отчёт
snmp-check 10.0.0.5 -c public
# Запись (если community rw!)
snmpset -v2c -c private 10.0.0.5 1.3.6.1.2.1.1.5.0 s "hacked"
```

`snmp-check` агрегирует всё в читаемый отчёт — начните с него, он сам обходит основные ветки MIB.

## Разобранный пример: community public → учётки и интерфейсы

```bash
# 1. Находим community
onesixtyone -c communities.txt 10.0.0.5
# -> 10.0.0.5 [public]
# 2. Общий отчёт
snmp-check 10.0.0.5 -c public | tee snmp.txt
# 3. Система и интерфейсы
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.1
# SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software, C2960
# SNMPv2-MIB::sysName.0 = STRING: sw-floor3
# SNMPv2-MIB::sysContact.0 = STRING: admin / Passw0rd!
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.2.2.1.2
# IF-MIB::ifDescr.1 = STRING: FastEthernet0/1
# IF-MIB::ifDescr.24 = STRING: GigabitEthernet0/1
# 4. Ищем секреты в vendor-MIB / sysContact / sysLocation
grep -iE 'pass|admin|community|user' snmp.txt
# 5. ARP-таблица -> новые хосты
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.3.1.1.2
```

Слабая строка = утечка топологии, а иногда и пароль администратора прямо в `sysContact`. Из ARP-таблицы вы бесплатно получаете список живых хостов сегмента — это разведка без единого сканирующего пакета.

## OID-навигация и полезные ветки

```bash
# system: sysDescr(1.3.6.1.2.1.1.1), sysName(1.5), sysContact(1.4), sysLocation(1.6)
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.1
# interfaces: ifDescr(2.2.1.2), ifPhysAddress(2.2.1.6)
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.2.2.1.2
# IP: ipAdEntAddr(4.20.1.1), ipRouteTable(4.21)
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.4.20.1.1
# ARP: ipNetToMediaPhysAddress(3.1.1.2)
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.3.1.1.2
# TCP/UDP-таблицы
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.6.13
# процессы/ПО (HOST-RESOURCES-MIB)
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.25.4.2.1.2   # hrSWRunName
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.25.6.3.1.2   # hrSWInstalledName
```

Если `snmpwalk` всего дерева «зависает», ограничьте глубину: укажите конкретный OID-префикс и добавьте `-Cc` (не падать на ошибках) или `-t 2 -r 0` (короткий таймаут, без ретрансмиссий) — на медленных устройствах это спасает минуты.

## Перебор community-строк

```bash
# onesixtyone — быстрый перебор по списку
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i hosts.txt
# snmp-brute NSE
nmap -sU -p161 --script snmp-brute 10.0.0.5
```

Список community невелик: `public`, `private`, `cisco`, `manager`, `admin`, названия вендоров. Перебор **маленький** (не rockyou) — UDP медленный и шумный, а большие словари на UDP-сервис — это трата времени и засвет. Начните с дефолтных + названий компании/вендора.

## SNMPv3 и его аудит

```bash
# Обнаружение v3-пользователей
nmap -sU -p161 --script snmp-info 10.0.0.5
# Опрос v3 (если известны креды)
snmpwalk -v3 -l authPriv -u monitor -a SHA -A authpass -x AES -X privpass 10.0.0.5
```

v3 с `noAuthNoPriv` практически так же уязвим, как v2c. Проверяйте уровень безопасности: `snmpwalk -v3 -l noAuthNoPriv -u <user>` без пароля проходит — значит шифрования нет.

## Write-доступ, RCE и MITM через SNMP

Если community даёт `rw`, через `SET` можно менять параметры, а на некоторых устройствах — загрузить конфиг с командой (vendor-specific) или включить telnet. Классика: изменение `sysLocation` не даёт RCE, но смена community/конфигов — путь к полному контролю. Отдельная техника — **SNMP-спуфинг**: подделав ответ агента, можно отравить мониторинг или, при rw, записать в устройство нежелательные значения.

## Защита

- Использовать **SNMPv3** с authPriv (SHA + AES).
- Не оставлять `public`/`private`; ACL по IP.
- Отключить SNMP там, где он не нужен.
- Мониторить необычные `GET`/`SET` и смену community.
- Разнести read-only и read-write роли на разные пользователи v3.

## Частые ошибки

- **Забывать UDP** — nmap по умолчанию сканирует TCP; нужен `-sU -p 161`.
- **Останавливаться на `public`** — проверьте `private` (rw) и vendor-строки.
- **Не ходить по OID'ам** — `snmpwalk` всего дерева может занять минуты.
- **Игнорировать `sysContact`/`sysLocation`** — там бывают пароли.
- **Пробовать перебор по словарю без ограничения** — UDP-скан медленный и шумный.
- **Забывать про traps** — UDP/162 тоже слушают, а trap может содержать учётные данные.

## Что дальше / решение

Маршрут: **найти community (onesixtyone) → snmp-check для общей картины → snmpwalk по ключевым ветвям (system/if/ip/arp/hrSW) → grep секретов → при rw попробовать SET**. Из ARP-таблицы строим карту сегмента и переходим к атакам канального уровня. Дальше — [`network-arp-deep`](network-arp-deep), [`network-layer2-attacks`](network-layer2-attacks) и [`network-portscan`](network-portscan). Для отчётности фиксируйте строку, права (ro/rw) и извлечённые данные.

## Что писать в отчёте

- Найденные community-строки и права (ro/rw).
- Извлечённые данные (интерфейсы, маршруты, ARP, ПО).
- Признаки утечки секретов (sysContact/sysLocation).
- Рекомендации: SNMPv3 authPriv, ACL, отключение SNMP.

## SNMP-traps, логирование и мониторинг как источник данных

Помимо опроса, SNMP умеет **push**: агент отправляет `TRAP` на UDP/162 при событии (link up/down, перезагрузка, ошибка питания, вход пользователя). Для пентестера это ценно с двух сторон. Во-первых, если у вас есть доступ к менеджеру мониторинга (Zabbix/LibreNMS), вы получаете историческую телеметрию всей сети: какие хосты жили, когда падали, какие интерфейсы меняли статус. Во-вторых, traps иногда содержат фрагменты конфигурации или имена пользователей в текстовых полях. Перехват UDP/162 (`tcpdump -i eth0 udp port 162 -A`) в сегменте мониторинга может выдать массу внутренней информации без единого активного запроса.

Обратный сценарий — **SNMP-спуфинг**: подделав trap, можно создать ложную тревогу, отвлечь дежурную смену или, наоборот, скрыть реальную атаку, «зашумив» канал ложными событиями. При rw-доступе иногда удаётся изменить настройки trap-получателя и перенаправить поток телеметрии на свой хост.

## Автоматизация опроса и разбор вывода

Для регулярных задач удобно оборачивать `snmpwalk` в скрипт и сохранять вывод в структурированный вид. `snmpwalk -Oqn` печатает «числовые» OID (без MIB-имён), что стабильнее для парсинга; `-Oq` убирает тип значения. `snmpdf` показывает использование дисков на хосте (`hrStorage`), `snmpnetstat` — сетевые соединения и маршруты в стиле `netstat`. Для массовой разведки удобен `snmpwalk` по списку хостов с общим community — но помните про шум и лимит скорости.

```bash
# Числовые OID, без типов — стабильный парсинг
snmpwalk -v2c -c public -Oqn 10.0.0.5 1.3.6.1.2.1.2.2.1.2 | awk -F'.' '{print $NF}'
# Диски и сетевые соединения
snmpdf   -v2c -c public 10.0.0.5
snmpnetstat -v2c -c public 10.0.0.5 -an
# Обход всего дерева с защитой от зависания
snmpwalk -v2c -c public -t 2 -r 0 -Cc 10.0.0.5 1.3.6.1.2.1
```

## Квиз

```quiz
- question: "Как называется «пароль» SNMPv1/v2c?"
  options:
    - "Community string"
    - "PSK"
    - "Token"
    - "Salt"
  answer: 0
  explanation: "Community-строка передаётся в открытом виде и служит аутентификацией."
- question: "На каком порту и протоколе работают SNMP-запросы?"
  options:
    - "UDP/161"
    - "TCP/161"
    - "UDP/162"
    - "TCP/443"
  answer: 0
  explanation: "Запросы — UDP/161, traps — UDP/162."
- question: "Что даёт SNMPv3 по сравнению с v2c?"
  options:
    - "Аутентификацию и шифрование"
    - "Более высокую скорость"
    - "IPv6"
    - "Сжатие данных"
  answer: 0
  explanation: "v3 добавляет пользователей, хэширование (MD5/SHA) и шифрование (DES/AES)."
- question: "Какой инструмент делает «человеческий» отчёт по SNMP?"
  options:
    - "snmp-check"
    - "smbmap"
    - "macof"
    - "chisel"
  answer: 0
  explanation: "snmp-check агрегирует системную, сетевую и другую информацию в читаемый вид."
- question: "Почему community private опасна?"
  options:
    - "Она часто даёт write-доступ к устройству"
    - "Она read-only"
    - "Она шифрует трафик"
    - "Она меняет MAC"
  answer: 0
  explanation: "Строка private нередко настроена на read-write, позволяя менять конфигурацию."
```

## Где пригодится

- **CTF:** задачи с SNMP-энумерацией и извлечением секретов.
- **Пентест:** разведка сетевого оборудования и топологии.
- **Работа:** аудит конфигурации SNMP, переход на v3.
- **SOC:** детект необычных SNMP-запросов.
- **Мониторинг:** понимание MIB/OID для легитимного опроса.
