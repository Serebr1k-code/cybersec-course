---
id: network-vnc-rdp
title: "VNC и RDP: удалённый рабочий стол и его атаки"
category: network
parent: network-module-services
difficulty: medium
order: 3
tags: [network, vnc, rdp, rfb, bluekeep, nla, remote-desktop]
prerequisites: [network-module-services, network-service-enum]
useful_for:
  - "CTF Network (VNC/RDP-задачи)"
  - "Пентест: брутфорс и CVE удалённого доступа"
  - "Работа (SOC): детект RDP/VNC-атак"
estimated_minutes: 55
summary: "VNC (RFB) и RDP: как устроена аутентификация, где хранятся пароли VNC, NLA/CredSSP и BlueKeep в RDP, инструменты и защита удалённого доступа."
---

VNC и RDP дают удалённый рабочий стол — и являются одной из самых популярных целей: слабые пароли, отсутствие шифрования у части реализаций VNC и исторические CVE у RDP. Урок продолжает [`network-module-services`](network-module-services).

## VNC: протокол RFB

**VNC** использует **RFB** (Remote Framebuffer): сервер отправляет изменения «фреймбуфера», клиент — события ввода. Порт — **5900 + номер экрана** (5901 — второй экран).

Аутентификация VNC:

- **None** — без пароля (полный доступ);
- **VNC Authentication** — DES-«шифр» с паролем до 8 символов (слабый);
- **пользовательские схемы** — через дополнительные механизмы.

```bash
# Обнаружить и подключиться
nmap -p 5900,5901 --script vnc-info,vnc-brute 10.0.0.1
vncviewer 10.0.0.1:1
# Скриншот без полного доступа
vncsnapshot 10.0.0.1:1 out.jpg
```

## Пароли VNC: где искать

VNC-пароль хранится в отдельном файле, часто зашифрован слабым ключом (известный статичный DES-ключ). Если файл доступен — пароль восстанавливается мгновенно.

```bash
# Файл пароля (Linux/Windows)
# ~/.vnc/passwd ; HKLM\...\WinVNC4\Password
# Расшифровать известным ключом
# vncpwdump / vncpasswd decrypt
strings ~/.vnc/passwd | head
```

## RDP: протокол и аутентификация

**RDP** (3389/tcp) — проприетарный протокол Microsoft. Уровни безопасности:

- **RDP Security** — старое, шифрование на уровне протокола;
- **TLS** — шифрование TLS;
- **NLA** (CredSSP) — аутентификация **до** установления сессии.

NLA уменьшает поверхность (нет «предсессионной» обработки), но перебор credentials остаётся.

```bash
# Информация о шифровании и NLA
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.0.0.1
# Проверка уязвимостей
nmap -p 3389 --script rdp-vuln-ms12-020 10.0.0.1
```

## BlueKeep и другие CVE

**BlueKeep** (CVE-2019-0708) — pre-auth RCE в RDP (Windows XP/7/2003/2008). Классический пример «RDP-уязвимости», эксплуатируемой без аутентификации. Есть и другие (MS12-020, DejaBlue).

```bash
# Проверить уязвимость BlueKeep (NSE)
nmap -p 3389 --script rdp-vuln-ms12-020,rdp-enum-encryption 10.0.0.1
# Metasploit (лаборатория)
# msf> use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

## Брутфорс credentials

```bash
# RDP-брутфорс (малый список!)
hydra -L users.txt -P pass.txt rdp://10.0.0.1
# netexec (бывший crackmapexec)
netexec rdp 10.0.0.1 -u user -p pass
# Подключение
xfreerdp /v:10.0.0.1 /u:user /p:pass
```

## Практика: полный цикл

```bash
# 1. Идентификация
nmap -sV -p 3389,5900,5901 10.0.0.1
# 2. Безопасность RDP
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 10.0.0.1
# 3. VNC без пароля?
nmap -p 5900 --script vnc-info 10.0.0.1
# 4. Малый перебор (только известные/дефолтные creds)
hydra -L users.txt -P small.txt rdp://10.0.0.1
# 5. Подключиться при успехе
xfreerdp /v:10.0.0.1 /u:user /p:pass /cert:ignore
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `nmap` (rdp-*, vnc-*) | идентификация и CVE |
| `hydra`/`netexec` | брутфорс |
| `xfreerdp`/`rdesktop` | RDP-клиент |
| `vncviewer`/`vncsnapshot` | VNC-клиент/скриншот |
| `vncpwdump` | восстановление пароля VNC |

## Атаки

- **VNC без пароля** — полный доступ;
- **Слабый VNC-пароль** — DES-обфускация ломается;
- **Брутфорс RDP/VNC** — слабые credentials;
- **BlueKeep/MS12-020** — pre-auth RCE;
- **MITM** — перехват при отсутствии TLS/NLA.

```bash
# Перехват RDP-хендшейка
tshark -r cap.pcap -Y 'rdp' -T fields -e rdp.security.protocol | head
```

## Защита

| Мера | Против чего |
|---|---|
| NLA для RDP | pre-auth CVE/брутфорс |
| Обновления (BlueKeep) | RCE |
| Сильные пароли + MFA | брутфорс |
| VPN/RD Gateway вместо прямого RDP | экспозиция |
| VNC за SSH/VPN, сильный пароль | перехват/слабый пароль |
| Ограничение доступа по IP | экспозиция |

## Частые ошибки

- **Оставлять VNC без пароля** — мгновенный доступ.
- **Слабый VNC-пароль (≤8 симв.)** — ломается.
- **RDP наружу без NLA** — BlueKeep/брутфорс.
- **Игнорировать обновления** — pre-auth RCE.
- **Путать 5900 и 5901** — разные экраны.
- **Брутить мега-словарём** — бан/лок-аут, EV-отрицательно.
- **Не логировать входы** — атаки невидимы.

## Что дальше / решение

После VNC/RDP переходите к [`network-iot-messaging`](network-iot-messaging). Для других сервисов — [`network-service-enum`](network-service-enum) и [`network-module-services`](network-module-services).

## Практика: VNC и RDP

```bash
# 1. Идентификация
nmap -sV -p 3389,5900,5901 10.0.0.1
# 2. Безопасность RDP и уязвимости
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 10.0.0.1
# 3. VNC: без пароля?
nmap -p 5900 --script vnc-info 10.0.0.1
vncsnapshot 10.0.0.1:0 shot.jpg 2>/dev/null
# 4. Малый перебор (дефолты/известные)
hydra -L users.txt -P small.txt rdp://10.0.0.1
netexec rdp 10.0.0.1 -u user -p pass
# 5. Подключиться
xfreerdp /v:10.0.0.1 /u:user /p:pass /cert:ignore
```

## Сравнение VNC и RDP

| Свойство | VNC | RDP |
|---|---|---|
| Порт | 5900+ | 3389 |
| Протокол | RFB | RDP |
| Шифрование | слабое/опц. | TLS/NLA |
| Аутентификация | VNC-пароль (≤8) | домен/локальные creds |
| Известные CVE | реализации | BlueKeep и др. |
| Клиент | vncviewer | xfreerdp/rdesktop |

## Чек-лист удалённого доступа

1. Есть ли **VNC без пароля**?
2. Ограничен ли VNC-пароль (**≤8 символов**)?
3. Использует ли RDP **NLA**?
4. Обновлён ли сервер (**BlueKeep**)?
5. Есть ли **MFA** и ограничение по IP?
6. Доступен ли RDP/VNC **напрямую из интернета**?
7. Логируются ли **попытки входа**?

```bash
# Снимок безопасности RDP
nmap -p 3389 --script rdp-enum-encryption 10.0.0.1
```

Вывод: VNC и RDP — популярная цель. VNC часто без/со слабым паролем, RDP — с историческими pre-auth CVE. Защита: NLA, MFA, обновления, отсутствие прямой экспозиции и сильные пароли.

## Дополнительно: перехват и NLA

```bash
# Перехватить RDP-хендшейк (видно протокол безопасности)
tshark -r cap.pcap -Y 'rdp' -T fields -e rdp.security.protocol | head
# VNC: проверить, есть ли пароль
nmap -p 5900 --script vnc-info 10.0.0.1
# VNC-скриншот без пароля (если auth None)
vncsnapshot 10.0.0.1:0 shot.jpg
# RDP: определить поддержку NLA
nmap -p 3389 --script rdp-enum-encryption 10.0.0.1
```

Если RDP без NLA — уязвим к pre-auth CVE; если VNC без пароля — скриншот и управление доступны сразу.

## Итог по VNC/RDP

Удалённый рабочий стол — популярная цель:

- **VNC** — пароль ≤8 символов, иногда без пароля, слабая обфускация;
- **RDP** — NLA уменьшает поверхность, но перебор и BlueKeep остаются;
- **экспозиция** — прямой RDP/VNC из интернета резко повышает риск.

Защита: **NLA + MFA**, обновления, отсутствие прямой экспозиции (VPN/RD Gateway), сильные пароли и мониторинг попыток входа. VNC — за SSH/VPN и с сильным паролем.

## Заметка о брутфорсе и lockout

RDP/VNC-брутфорс — популярный, но рискованный путь: политика блокировки учётной записи (lockout) может «положить» реальных пользователей, а шумный перебор детектируется.

```bash
# Проверить политику блокировки (если есть доступ к домену)
netexec smb 10.0.0.1 --pass-pol
# Малый перебор: дефолты и известные креды
hydra -L users.txt -P small.txt rdp://10.0.0.1
```

Практическое правило: **никогда не лить мега-словарь на сетевой сервис**. Сначала проверяйте без аутентификации (VNC без пароля, анонимный FTP, NLA-настройки), затем — маленький набор (дефолты + собранные креды). Мега-словари — только для офлайн-хэшей.

## Квиз

```quiz
- question: "Какой порт у VNC для первого экрана?"
  options:
    - "5900"
    - "3389"
    - "5901"
    - "23"
  answer: 0
  explanation: "5900 — первый экран, 5901 — второй."
- question: "Что такое NLA в RDP?"
  options:
    - "Аутентификация до установления сессии (CredSSP)"
    - "Новый протокол графики"
    - "Сжатие экрана"
    - "Шифрование диска"
  answer: 0
  explanation: "Network Level Authentication снижает поверхность атаки."
- question: "Какая уязвимость RDP даёт pre-auth RCE?"
  options:
    - "BlueKeep (CVE-2019-0708)"
    - "Heartbleed"
    - "POODLE"
    - "Shellshock"
  answer: 0
  explanation: "BlueKeep эксплуатируется без аутентификации."
- question: "Чем слаба VNC-аутентификация по умолчанию?"
  options:
    - "Пароль до 8 символов и слабая обфускация"
    - "Она требует сертификат"
    - "Она слишком длинная"
    - "Она использует AES-256"
  answer: 0
  explanation: "Классический VNC-пароль ограничен 8 символами."
- question: "Какая защита снижает риск RDP наружу?"
  options:
    - "NLA + MFA + доступ через VPN/Gateway"
    - "Открытый порт 3389"
    - "Отключение TLS"
    - "VNC без пароля"
  answer: 0
  explanation: "Слои аутентификации и отсутствие прямой экспозиции."
```

## Где пригодится

- **CTF:** задачи с VNC/RDP и скриншотами.
- **Пентест:** брутфорс, CVE, доступ к рабочему столу.
- **SOC:** детект RDP/VNC-брутфорса и аномалий.
- **Инженерия:** NLA, MFA, RD Gateway, обновления.
