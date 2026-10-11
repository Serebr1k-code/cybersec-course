---
id: forensics-registry-hives
title: "Реестр Windows: SAM, SYSTEM, SECURITY и поиск следов"
category: forensics
parent: forensics-win-registry
difficulty: hard
order: 4
tags: [registry, sam, system, security, ntuser, regripper, hives]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Глубокий разбор кустов реестра Windows: учётные записи и хеши (SAM), службы и USB (SYSTEM), политики и LSA (SECURITY), история пользователя (NTUSER.DAT)."
---
Реестр Windows — центральное хранилище конфигурации системы и пользователей. В форензике он ценен тем, что почти каждое действие оставляет след в реестре: установка ПО, автозапуск, подключение USB, входы, история файлов. Кусты реестра — это обычные файлы, которые можно анализировать офлайн. Этот урок — глубокий разбор SAM, SYSTEM, SECURITY и NTUSER.DAT с практическими командами.

## Кусты реестра

| Куст | Путь | Что внутри |
|------|------|-----------|
| `SAM` | `System32\config\SAM` | локальные пользователи, RID, хеши |
| `SYSTEM` | `System32\config\SYSTEM` | службы, USB, ControlSet, время |
| `SECURITY` | `System32\config\SECURITY` | LSA secrets, кэш домена, политики |
| `SOFTWARE` | `System32\config\SOFTWARE` | установленный софт, Run-ключи |
| `NTUSER.DAT` | `C:\Users\<user>\` | история пользователя, UserAssist, RecentDocs |
| `UsrClass.dat` | `...\Local Settings\` | Shellbags, расширения файлов |
| `Amcache.hve` | `appcompat\Programs\` | запуск/установка программ |

Копии кустов лежат в `System Volume Information` (теневые копии) — часто содержат более старые версии.

## SAM: пользователи и хеши

SAM хранит локальные учётные записи и хеши NT/LM. Их можно извлечь офлайн и передать в hashcat.

```bash
# RegRipper
$ rip.pl -r SAM -f sam
$ rip.pl -r SAM -p samparse
# через secretsdump (impacket) нужны SAM + SYSTEM (+SECURITY)
$ secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
[*] Target system bootKey: 0x...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
# кэш доменных паролей (DCC2) из SECURITY
$ secretsdump.py -sam SAM -system SYSTEM -security SECURITY -security LOCAL
```

Хеши NT (NTLM) ломаются `hashcat -m 1000`; DCC2 — `-m 2100`.

## SYSTEM: службы, USB, время

```bash
# службы (в т.ч. установленные злоумышленником)
$ rip.pl -r SYSTEM -p services
$ rip.pl -r SYSTEM -p svc
# USB-устройства (USBSTOR)
$ rip.pl -r SYSTEM -p usb
# время последней загрузки/выключения
$ rip.pl -r SYSTEM -p shutdown
$ rip.pl -r SYSTEM -p timezone
# ControlSet — активная конфигурация
$ rip.pl -r SYSTEM -p controlset
```

ControlSet001 обычно активен; `Select\Current` указывает номер. Автозапуск через `Services` (`ImagePath`, `Start`) — популярная персистентность.

## SECURITY: LSA secrets

```bash
$ secretsdump.py -security SECURITY -system SYSTEM LOCAL
[*] LSA Secrets
[*] DPAPI_SYSTEM ...
[*] $MACHINE.ACC ...
# политики паролей
$ rip.pl -r SECURITY -p policy
```

LSA secrets содержат пароли служб, авто-логин, DPAPI-ключи. DPAPI master keys позволяют расшифровать сохранённые пароли браузеров/RDP.

## NTUSER.DAT: история пользователя

```bash
$ rip.pl -r NTUSER.DAT -f ntuser
# UserAssist (запущенные программы)
$ rip.pl -r NTUSER.DAT -p userassist
# RecentDocs (последние документы)
$ rip.pl -r NTUSER.DAT -p recentdocs
# Run-ключи (автозапуск пользователя)
$ rip.pl -r NTUSER.DAT -p run
# TypedPaths, TypedURLs
$ rip.pl -r NTUSER.DAT -p typedpaths
```

UserAssist хранит запущенные программы с ROT13-кодированием имён и счётчиком запусков; RecentDocs — открытые файлы; Run — автозапуск. Shellbags (в `UsrClass.dat`) — просмотренные папки (см. `forensics-shellbags`).

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `RegRipper` (`rip.pl`) | плагины по кустам |
| `hivex`/`hivexregedit` | доступ к кустам на Linux |
| `reged`/`reglookup` | CLI-навигация |
| `secretsdump.py` | хеши, LSA secrets, DCC |
| `Registry Explorer` | GUI (Eric Zimmerman) |
| `python-registry` | парсинг на Python |

```bash
# Linux: смонтировать куст и прочитать ключ
$ hivexregedit --export NTUSER.DAT '\Software\Microsoft\Windows\CurrentVersion\Run' run.reg
$ reglookup -p '/Software/Microsoft/Windows/CurrentVersion/Run' NTUSER.DAT
```

## Разобранный пример

Дан набор кустов из `C:\Windows\System32\config` и `NTUSER.DAT`. Нужно доказать запуск и закрепление.

```bash
# 1. Пользователи и хеши
$ secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL | tee creds.txt
Administrator:500:...:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1001:...:8846f7eaee8fb117ad06bdd830b7586c:::
# 2. Службы-персистентность
$ rip.pl -r SYSTEM -p services | grep -iE 'evil|updater|run'
evil_svc  ImagePath= C:\ProgramData\evil\svc.exe  Start= 2
# 3. Автозапуск пользователя
$ rip.pl -r NTUSER.DAT -p run
Run: Updater = C:\Users\bob\AppData\Roaming\evil.exe
# 4. Запущенные программы
$ rip.pl -r NTUSER.DAT -p userassist | grep -i evil
UEME_RUNPATH: C:\Users\bob\AppData\Roaming\evil.exe (2)
# 5. USB
$ rip.pl -r SYSTEM -p usb
USBSTOR\Disk&Ven_Generic&Prod_Flash ... S/N 0123456789
```

Итог: служба `evil_svc`, Run-ключ `Updater`, UserAssist-запись о запуске — согласованная картина закрепления.

## Частые ошибки

- **Анализировать кусты на живой системе** — они заблокированы; работайте с копиями.
- **Забывать про ControlSet** — активен не всегда 001.
- **Игнорировать SECURITY** — без него не получить LSA secrets и DPAPI.
- **Путать NTUSER.DAT (пользователь) и SYSTEM (машина).**
- **Не проверять теневые копии** — там старые версии с удалёнными ключами.
- **Верить только одному ключу** — коррелируйте Run + Services + UserAssist + EVTX.

## Что дальше / решение

Соберите кусты (`config\*`, `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`) → прогоните `RegRipper`/`secretsdump` → извлеките хеши/секреты/автозапуск → сшейте с EVTX и ФС. Связка: `forensics-registry-deep` (внутренности и транзакции), `forensics-windows-execution` (запуск), `forensics-usb-devices` (USB), `forensics-shellbags` (папки).

## Теневые копии и восстановление удалённых ключей

Живой реестр можно восстановить из **теневых копий** (`System Volume Information`, VSS), где хранятся старые снимки кустов. Атакующий мог удалить ключ автозапуска после срабатывания, но он останется в теневой копии.

```bash
# список теневых копий
$ vshadowinfo disk.img
$ vshadowmount disk.img /mnt/vss
# найти старые версии кустов
$ find /mnt/vss -name SAM -o -name NTUSER.DAT
# сравнить с текущими
$ rip.pl -r /mnt/vss/.../NTUSER.DAT -p run
```

Другой путь — транзакционные журналы `.LOG1`/`.LOG2`, лежащие рядом с кустами. Если куст «грязный» (dirty), журналы содержат незакоммиченные изменения; их применяют через `yarp` (Yet Another Registry Parser) или `hivex`.

## RegRipper: плагины и вывод

`RegRipper` — это набор плагинов (`.pl`), каждый извлекает конкретную информацию. Список и запуск:

```bash
$ rip.pl -l                       # список плагинов
$ rip.pl -r SYSTEM -a             # прогнать все плагины для SYSTEM
$ rip.pl -r NTUSER.DAT -p userassist -p recentdocs
# GUI: Registry Explorer (Zimmerman) с bookmarks
```

Полезные плагины: `run`, `runonce`, `services`, `svc`, `usb`, `usbdevices`, `mountdev`, `bam`, `userassist`, `recentdocs`, `typedurls`, `shellbags`, `networklist`, `timezone`, `shutdown`, `autoruns`, `environment`.

## Сравнение инструментов

| Инструмент | Платформа | Особенность |
|-----------|-----------|-------------|
| RegRipper | кроссплатформенный (Perl) | множество плагинов, CLI |
| Registry Explorer | Windows | GUI, bookmarks, теневые копии |
| `secretsdump.py` | кроссплатформенный | хеши, LSA, DCC |
| `hivex`/`hivexregedit` | Linux | экспорт ключей в `.reg` |
| `reglookup`/`reged` | Linux | навигация и поиск |
| `python-registry` | Python | программный доступ |

Для быстрого триажа — `RegRipper`; для глубокого разбора с книжными закладками — `Registry Explorer`; для хешей — `secretsdump`.

## Практические замечания

- **Активный ControlSet** определяйте по `Select\Current` (обычно 1), а не по умолчанию.
- **LastWrite-время ключа** — важный артефакт: показывает, когда ключ менялся; для `Run`-ключей это время закрепления.
- **Большие кусты** (`SOFTWARE`, `Amcache.hve`) обрабатывайте потоково, иначе память кончится.
- **Кусты блокируются** на живой системе; копируйте через `reg save` (требует прав) или из теневой копии.
- **NTUSER.DAT без загрузки профиля** читается офлайн, но `UsrClass.dat` может быть «грязным» — применяйте журнал.

## Квиз

```quiz
- question: "В каком кусте хранятся локальные NT-хеши?"
  options:
    - "SYSTEM"
    - "SAM"
    - "SECURITY"
    - "SOFTWARE"
  answer: 1
- question: "Что хранит ветка `Enum\USBSTOR`?"
  options:
    - "пароли"
    - "информацию о подключённых USB-носителях"
    - "автозапуск"
    - "браузер"
  answer: 1
- question: "Какое кодирование применяется в UserAssist?"
  options:
    - "base64"
    - "ROT13"
    - "XOR"
    - "hex"
  answer: 1
- question: "Где хранятся Shellbags?"
  options:
    - "только в SAM"
    - "в UsrClass.dat / NTUSER.DAT"
    - "в SYSTEM"
    - "в EVTX"
  answer: 1
- question: "Что такое LSA secrets?"
  options:
    - "журнал"
    - "секреты служб и кешированные домен-креды в SECURITY"
    - "USB"
    - "prefetch"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с SAM/SYSTEM/NTUSER.DAT.
- **DFIR:** восстановление картины активности пользователя и системы.
- **Threat Hunting:** поиск персистентности (Run, Winlogon, Services).
- **Криминалистика:** доказательство подключения устройств и запуска программ.
- **Пентест:** извлечение хешей из захваченных кустов.
