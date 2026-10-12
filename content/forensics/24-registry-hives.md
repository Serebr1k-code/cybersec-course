---
id: forensics-registry-hives
title: "Реестр Windows: SAM, SYSTEM, SECURITY и поиск следов"
category: forensics
parent: forensics-win-registry
difficulty: hard
order: 3
tags: [registry, sam, system, security, ntuser, regripper, hives]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Глубокий разбор кустов реестра Windows: учётные записи и хеши (SAM), службы и USB (SYSTEM), политики и LSA (SECURITY), история пользователя (NTUSER.DAT)."
---

## Вопрос, с которого всё начинается

Тебе передали набор файлов из папки `C:\Windows\System32\config` — `SAM`, `SYSTEM`,
`SECURITY` — и один `NTUSER.DAT`. Никаких логов и диска целиком. Можно ли из них понять,
кто заходил в систему, что запускалось и как закрепились?

Да. **Реестр** Windows — центральное хранилище настроек, и почти каждое действие
оставляет в нём след. Кусты реестра — обычные файлы, которые разбирают офлайн. В этом
уроке мы вытащим из них хеши, службы и автозапуск.

## Наш пример: набор кустов

Реестр хранится в нескольких **кустах** (hive) — отдельных файлах-«деревьях»:

| Куст | Путь | Что внутри |
|------|------|-----------|
| `SAM` | `config\SAM` | локальные пользователи, RID, хеши |
| `SYSTEM` | `config\SYSTEM` | службы, USB, ControlSet, время |
| `SECURITY` | `config\SECURITY` | LSA secrets, кэш домена, политики |
| `SOFTWARE` | `config\SOFTWARE` | установленный софт, Run-ключи |
| `NTUSER.DAT` | `C:\Users\<user>\` | история пользователя, UserAssist |

## Шаг 1: SAM — пользователи и хеши

`SAM` хранит локальные учётные записи и их хеши. Извлечь их можно офлайн, сложив SAM
вместе с SYSTEM (из SYSTEM берётся ключ, которым зашифрованы хеши):

```bash
$ secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
[*] Target system bootKey: 0x...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

Вторая часть строки — это **NTLM-хеш** пароля. Его можно ломать офлайн: `hashcat -m 1000`.

## Шаг 2: SYSTEM — службы и USB

`SYSTEM` показывает, какие службы установлены и как они запускаются — популярный способ
закрепления:

```bash
$ rip.pl -r SYSTEM -p services | grep -iE 'evil|updater'
evil_svc  ImagePath= C:\ProgramData\evil\svc.exe  Start= 2
```

`RegRipper` (`rip.pl`) — набор плагинов для разбора кустов; `-p services` берёт данные
по службам. Служба `evil_svc` с `Start= 2` (автозапуск) — явный след.

Там же лежит история USB-устройств:

```bash
$ rip.pl -r SYSTEM -p usb
USBSTOR\Disk&Ven_Generic&Prod_Flash ... S/N 0123456789
```

## Шаг 3: SECURITY — LSA secrets

```bash
$ secretsdump.py -security SECURITY -system SYSTEM LOCAL
[*] LSA Secrets
[*] DPAPI_SYSTEM ...
[*] $MACHINE.ACC ...
```

**LSA secrets** — пароли служб, данные авто-логина и ключи DPAPI, которыми расшифровывают
сохранённые пароли браузеров и RDP. Без куста SECURITY их не достать.

## Шаг 4: NTUSER.DAT — история пользователя

```bash
$ rip.pl -r NTUSER.DAT -p run
Run: Updater = C:\Users\bob\AppData\Roaming\evil.exe
$ rip.pl -r NTUSER.DAT -p userassist | grep -i evil
UEME_RUNPATH: C:\Users\bob\AppData\Roaming\evil.exe (2)
```

Ключ `Run` — автозапуск при входе пользователя. `UserAssist` хранит список запущенных
программ, причём имена там закодированы **ROT13** (простой сдвиг букв) — плагин
декодирует их сам. Число в скобках — сколько раз программа запускалась.

## Шаг 5: сводим картину

У нас три независимых подтверждения: служба `evil_svc`, Run-ключ `Updater` и запись
`UserAssist` о запуске `evil.exe`. Совпадение нескольких ключей и есть доказательство —
одному ключу доверять нельзя.

## Шаг 6: инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `RegRipper` (`rip.pl`) | плагины по кустам |
| `hivex`/`hivexregedit` | доступ к кустам на Linux |
| `secretsdump.py` | хеши, LSA secrets, кэш домена |
| `Registry Explorer` | GUI (Eric Zimmerman) |
| `python-registry` | разбор на Python |

```bash
$ hivexregedit --export NTUSER.DAT '\Software\...\Run' run.reg
$ rip.pl -r SYSTEM -a          # прогнать все плагины для SYSTEM
```

## Шаг 7: теневые копии и удалённые ключи

Атакующий мог удалить ключ автозапуска после срабатывания — но он останется в
**теневой копии** (`System Volume Information`, VSS), где хранятся старые снимки кустов:

```bash
$ vshadowinfo disk.img
$ vshadowmount disk.img /mnt/vss
$ find /mnt/vss -name SAM -o -name NTUSER.DAT
$ rip.pl -r /mnt/vss/.../NTUSER.DAT -p run
```

Другой путь — транзакционные журналы `.LOG1`/`.LOG2` рядом с кустами: если куст
«грязный», их применяют через `yarp` или `hivex`.

## Шаг 8: RegRipper подробнее

`RegRipper` — это набор плагинов, каждый извлекает конкретную информацию:

```bash
$ rip.pl -l                       # список плагинов
$ rip.pl -r SYSTEM -a             # все плагины для SYSTEM
$ rip.pl -r NTUSER.DAT -p userassist -p recentdocs
```

Полезные плагины: `run`, `runonce`, `services`, `svc`, `usb`, `mountdev`, `bam`,
`userassist`, `recentdocs`, `typedurls`, `shellbags`, `networklist`, `timezone`,
`shutdown`, `environment`.

## Шаг 9: практические замечания

- **Активный ControlSet** определяйте по `Select\Current`, а не по умолчанию.
- **LastWrite-время** ключа показывает, когда он менялся; для `Run` это момент закрепления.
- **Большие кусты** (`SOFTWARE`, `Amcache.hve`) обрабатывайте потоково.
- **Кусты заблокированы** на живой системе — копируйте через `reg save` или из теневой копии.
- **`UsrClass.dat`** может быть «грязным» — применяйте журнал.

## Шаг 10: SOFTWARE и Amcache

Куст `SOFTWARE` и файл `Amcache.hve` отвечают на вопрос «что установлено и запускалось»:

```bash
$ rip.pl -r SOFTWARE -p installed
$ amcache.py -f Amcache.hve | head
```

`Amcache` хранит сведения о программах, которые запускались или устанавливались, включая
хеши исполняемых файлов. Это помогает найти подозрительный бинарь, даже если его уже
удалили, и сопоставить его с базой вирусов.

## Шаг 11: BAM и время запуска

Ветка `BAM` (Background Activity Moderator) в SYSTEM хранит последние запущенные
программы с временем — аналог UserAssist, но на уровне системы:

```bash
$ rip.pl -r SYSTEM -p bam | head
\Device\HarddiskVolume3\ProgramData\evil\svc.exe  ... 2024-03-01 09:12:09
```

Сопоставив BAM, UserAssist и Prefetch, можно доказать не только факт запуска, но и
примерное время — а это уже полноценная хронология.

## Шаг 12: как выглядит итог

Найденное удобно свести в таблицу «факт → значение → источник», чтобы каждый пункт
можно было перепроверить:

| Факт | Значение | Источник |
|------|----------|----------|
| Пользователи | Administrator, bob | SAM |
| Хеш bob | NTLM `8846...` | SAM + SYSTEM |
| Персистентность | `evil_svc` (Start=2) | SYSTEM |
| Запуск | `evil.exe` (2 раза) | NTUSER.DAT |
| USB | S/N 0123456789 | SYSTEM |

Такую таблицу легко защищать: для каждой строки указано, откуда взято значение.

## Что мы теперь знаем

- Реестр состоит из кустов-файлов; их анализируют офлайн.
- SAM + SYSTEM дают локальные NTLM-хеши (`hashcat -m 1000`).
- SYSTEM хранит службы (персистентность) и историю USB.
- SECURITY содержит LSA secrets и ключи DPAPI.
- NTUSER.DAT — автозапуск (`Run`) и запущенные программы (`UserAssist`, ROT13).

## На что смотреть дальше

- **Активный ControlSet** — определяйте по `Select\Current`, обычно это не всегда 001.
- **LastWrite-время ключа** — для `Run` это момент закрепления.
- **Теневые копии** — в `System Volume Information` лежат старые версии кустов.
- **Коррелировать ключи** — Run + Services + UserAssist + EVTX вместе, а не по одному.

## Квиз

Проверь себя.

```quiz
- question: "В каком кусте хранятся локальные NT-хеши?"
  options:
    - "SYSTEM"
    - "SAM"
    - "SECURITY"
    - "SOFTWARE"
  answer: 1
- question: "Что хранит ветка `Enum\\USBSTOR`?"
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
- question: "Что такое LSA secrets?"
  options:
    - "журнал"
    - "секреты служб и кешированные домен-креды в SECURITY"
    - "USB"
    - "prefetch"
  answer: 1
- question: "Почему реестр нельзя анализировать на живой системе?"
  options:
    - "он пустой"
    - "кусты заблокированы — работайте с копиями"
    - "нет прав"
    - "он зашифрован"
  answer: 1
```

## Куда дальше

Реестр рассказал, *что* установлено и запускалось. Но чтобы доказать, что программа
**выполнялась**, нужны артефакты выполнения — Prefetch, ShimCache, Amcache, LNK. О них —
в следующих уроках по Windows. А пока запомни: **одного ключа мало — подтверждай
несколькими**.

## Где пригодится

- **CTF:** задачи с SAM/SYSTEM/NTUSER.DAT.
- **DFIR:** восстановление картины активности пользователя и системы.
- **Threat Hunting:** поиск персистентности (Run, Services).
- **Криминалистика:** доказательство подключения устройств и запуска программ.
- **Пентест:** извлечение хешей из захваченных кустов.
