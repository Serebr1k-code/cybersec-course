---
id: network-service-enum
title: "Глубокая энумерация сервисов: SMB, RDP, LDAP, NFS"
category: network
parent: network-portscan
difficulty: medium
order: 3
tags: [network, enumeration, smb, rdp, ldap, nfs, null-session]
prerequisites: [network-portscan, network-nmap-deep]
useful_for:
  - "CTF Network (энумерация сервисов)"
  - "Пентест: разведка внутренней сети"
  - "Работа: аудит конфигураций сервисов"
estimated_minutes: 55
summary: "Как выжимать максимум информации из SMB, RDP, LDAP и NFS: null-сессии, анонимные бинды, шары, пользователи и версии."
---
Открытый порт — это ещё не уязвимость. Реальная ценность появляется на этапе энумерации: версии, пользователи, шары, политики, конфигурации. Этот урок — про глубокую энумерацию самых «вкусных» корпоративных сервисов: SMB, RDP, LDAP, NFS, а также WinRM, MSSQL и SNMP.

Разберём, что именно можно вытащить из каждого сервиса, какими инструментами и как это превращается в креды и доступ.

## SMB (445/139)

SMB — сервис номер один в Windows-сетях: файлы, принтеры, именованные каналы, аутентификация. Что энумерируем:

- версия и диалект (SMB1/2/3);
- подпись (signing) — включена или нет (влияет на relay);
- шары и права доступа;
- пользователи, группы, политики паролей;
- сессии.

```bash
# базовая энумерация
nxc smb 10.0.0.0/24
nxc smb 10.0.0.5 -u '' -p ''            # null session
nxc smb 10.0.0.5 -u guest -p ''
nxc smb 10.0.0.5 --shares -u user -p pass
nxc smb 10.0.0.5 --users -u user -p pass
nxc smb 10.0.0.5 --pass-pol -u '' -p ''

# низкоуровнево
smbclient -L //10.0.0.5 -N
smbmap -H 10.0.0.5 -u user -p pass
enum4linux-ng -A 10.0.0.5
rpcclient -U '' -N 10.0.0.5
```

Признаки, которые сразу важны: `signing: False` (потенциал для NTLM relay), доступ на чтение/запись к шарам (`ADMIN$`, `C$`, `SYSVOL`), null-сессия с доступом к списку пользователей.

## RDP (3389)

RDP интересен как цель для брута, проверки NLA и как источник информации о системе:

```bash
nxc rdp 10.0.0.5 -u user -p pass
# проверка, включён ли Network Level Authentication
nmap --script rdp-enum-encryption,rdp-ntlm-info -p 3389 10.0.0.5
# скриншот без аутентификации (устаревшие конфигурации)
nmap --script rdp-vuln-ms12-020 -p 3389 10.0.0.5
```

`rdp-ntlm-info` отдаёт NetBIOS-имя, DNS-домен, версию ОС — полезно для фингерпринта без логина.

## LDAP (389/636)

LDAP — каталог Active Directory. Анонимный bind часто разрешён и выдаёт всю структуру:

```bash
# анонимный bind и дамп
ldapsearch -x -H ldap://10.0.0.5 -b "dc=corp,dc=local"
ldapsearch -x -H ldap://10.0.0.5 -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName
nxc ldap 10.0.0.5 -u '' -p '' --users
nxc ldap 10.0.0.5 -u user -p pass --groups --dc-list

# поиск описаний с паролями (частая утечка)
ldapsearch -x -H ldap://10.0.0.5 -b "dc=corp,dc=local" "(description=*pass*)"
```

Ключевые находки: список пользователей (для брута и AS-REP), группы администраторов, `userPassword`/`description` с паролями, настроенные SPN (для Kerberoasting).

## NFS (2049)

NFS часто экспортирует каталоги без аутентификации:

```bash
showmount -e 10.0.0.5
# /srv/share  *
mount -t nfs 10.0.0.5:/srv/share /mnt/nfs -o nolock
ls -la /mnt/nfs
# если no_root_squash — можно создавать suid-бинари
```

`showmount -e` — первая команда. Экспорт `*` без ограничений — частая мисконфигурация, дающая чтение (и иногда запись) файлов.

## WinRM (5985/5986)

WinRM — «удалённый PowerShell». Если у вас есть креды и порт открыт — это прямой путь к выполнению команд:

```bash
nxc winrm 10.0.0.5 -u user -p pass
# [+] corp\user:pass (Pwn3d!)  ← админский доступ
evil-winrm -i 10.0.0.5 -u user -p pass
```

`(Pwn3d!)` в netexec означает, что учётка административна — можно выполнять код.

## MSSQL (1433)

```bash
nxc mssql 10.0.0.5 -u user -p pass
nxc mssql 10.0.0.5 -u user -p pass -q "SELECT @@version"
# включить xp_cmdshell (если есть права)
nxc mssql 10.0.0.5 -u sa -p pass -x "whoami"
```

MSSQL с правами `sysadmin` даёт RCE через `xp_cmdshell` — это классический шаг эскалации в Windows-сетях.

## SNMP (161/udp)

SNMP v1/v2c использует community-строку как «пароль» в открытом виде. Дефолтные `public`/`private` часто не меняют:

```bash
onesixtyone -c communities.txt 10.0.0.5
snmpwalk -v2c -c public 10.0.0.5
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.25.4.2.1.2   # процессы
snmpwalk -v2c -c public 10.0.0.5 1.3.6.1.2.1.6.13.1.3     # TCP-порты
snmp-check 10.0.0.5 -c public
```

SNMP отдаёт процессы, порты, пользователей, интерфейсы — богатая карта хоста.

## Автоматизация энумерации

```bash
# netexec по всей подсети, все протоколы
nxc smb 10.0.0.0/24 -u '' -p ''
nxc ldap 10.0.0.0/24 -u '' -p ''
nxc winrm 10.0.0.0/24 -u user -p pass
nxc rdp 10.0.0.0/24 -u user -p pass
```

`netexec` (бывший CrackMapExec) — стандарт де-факто: один инструмент, много протоколов, единый вывод, детект `(Pwn3d!)`.

## От находок к доступу

| Находка | Следующий шаг |
|---|---|
| `signing: False` | NTLM relay (Responder + ntlmrelayx) |
| Список пользователей | брут/спрей, AS-REP roasting |
| SPN у пользователя | Kerberoasting |
| Экспорт NFS `*` | чтение/запись файлов |
| `xp_cmdshell` доступен | RCE на MSSQL-хосте |
| SNMP `public` | карта хоста, иногда креды в OID |
| WinRM `(Pwn3d!)` | удалённое выполнение команд |

## Частые ошибки

- Сканировать только TCP — SNMP/DHCP/NTP остаются за кадром.
- Не пробовать null/guest-сессии на SMB/LDAP — часто открыты.
- Игнорировать NFS — `showmount -e` занимает секунду.
- Брутить вслепую без списка пользователей — сначала энумерация.
- Забыть про `--pass-pol` — политика паролей подсказывает стратегию спрея.

## Что дальше / решение

Методика: `nmap -sV` → `nxc` по всем протоколам → углубление в найденное. Каждая находка (пользователь, шара, community) — вход для следующего шага. Энумерация — это где выигрывается пентест: без списка пользователей и понимания сервисов эксплуатация превращается в перебор.

## Разобранный пример: от null-сессии к домену

Цель `10.10.10.10`, Windows-контроллер домена. Шаги:

```bash
# 1. проверяем подпись и null-сессию
nxc smb 10.10.10.10 -u '' -p ''
# SMB  10.10.10.10  445  DC01  [*] Windows Server 2019
#      signing:False
```

`signing:False` — зелёный свет для NTLM relay. Дальше:

```bash
# 2. список пользователей через null RID-cycling
nxc smb 10.10.10.10 -u '' -p '' --rid-brute
# 1103: CORP\alice (SidTypeUser)
# 1104: CORP\bob   (SidTypeUser)
```

```bash
# 3. политика паролей (порог блокировки, сложность)
nxc smb 10.10.10.10 -u '' -p '' --pass-pol
# Minimum password length: 8, Lockout threshold: None
```

Отсутствие lockout → можно спрейить. Собираем список пользователей и переходим к следующему этапу — спрей по SMB/WinRM.

## Reference-таблица: порты и что с ними делать

| Порт | Сервис | Первый шаг |
|---|---|---|
| 445 | SMB | `nxc smb --shares --users --pass-pol` |
| 139 | NetBIOS | `nbtscan`, legacy-энумерация |
| 3389 | RDP | `nxc rdp`, `rdp-ntlm-info` |
| 389/636 | LDAP(S) | `ldapsearch -x`, `nxc ldap` |
| 2049 | NFS | `showmount -e`, mount |
| 5985/5986 | WinRM | `nxc winrm`, `evil-winrm` |
| 1433 | MSSQL | `nxc mssql`, `xp_cmdshell` |
| 161/udp | SNMP | `onesixtyone`, `snmpwalk` |
| 88 | Kerberos | AS-REP/Kerberoast |
| 135 | MSRPC | `rpcclient`, epmapper |

## Чек-лист энумерации

1. SMB: версия, signing, null/guest, шары, пользователи, политика паролей.
2. LDAP: анонимный bind, пользователи, группы, описания, SPN.
3. RDP: NLA, NTLM-info, версия ОС.
4. NFS: `showmount -e`, права экспорта, no_root_squash.
5. WinRM/MSSQL: проверка кред и админского доступа.
6. SNMP: community-строки, дамп процессов/портов.
7. Свести находки в таблицу «находка → следующий шаг».

## Квиз

```quiz
- question: "Что позволяет сделать null-сессия SMB?"
  options:
    - "Перечислить шары и иногда пользователей без аутентификации"
    - "Получить root"
    - "Расшифровать трафик"
    - "Включить IPv6"
  answer: 0
  explanation: "Null-сессия даёт анонимное перечисление шар и метаданных."
- question: "Какой скрипт nmap отдаёт имя домена/версию Windows до аутентификации по RDP?"
  options:
    - "rdp-ntlm-info"
    - "smb-os-discovery"
    - "http-title"
    - "dns-zone-transfer"
  answer: 0
  explanation: "rdp-ntlm-info раскрывает NTLM-информацию (домен, хост, версия) без логина."
- question: "Что опасно в экспорте NFS с опцией no_root_squash?"
  options:
    - "Клиент root получает root на файлах сервера — можно записать authorized_keys"
    - "NFS шифруется"
    - "Отключается Kerberos"
    - "Включается IPv6"
  answer: 0
  explanation: "no_root_squash сохраняет права root клиента на сервере — прямой путь к RCE."
- question: "Какой запрос проверяет анонимный бинд LDAP?"
  options:
    - "ldapsearch -x -H ldap://host -b dc=... (objectClass=user)"
    - "showmount -e"
    - "smbclient -L"
    - "rdp-ntlm-info"
  answer: 0
  explanation: "Анонимный ldapsearch часто раскрывает пользователей и структуру каталога."
- question: "Какой признак SMB-хоста открывает возможность NTLM-релея?"
  options:
    - "SMB signing отключён"
    - "SMB1 включён"
    - "Открыт 3389"
    - "Разрешён NFS"
  answer: 0
  explanation: "Без подписи SMB аутентификацию можно переслать (см. network-ntlm-relay)."
```

## Где пригодится

- **CTF:** энумерация сервисов для поиска пути дальше.
- **Пентест:** разведка внутренней сети, сбор имён/шар.
- **Работа:** аудит конфигураций SMB/RDP/LDAP/NFS.
- **Red team:** подготовка к lateral movement.
- **SOC:** понимание, что видит атакующий при энумерации.
