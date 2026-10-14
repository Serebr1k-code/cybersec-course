---
id: forensics-windows-persistence
title: "Персистентность Windows: Run, службы, задачи, WMI"
category: forensics
parent: forensics-win-volatile
difficulty: hard
order: 4
tags: [windows, persistence, autoruns, run-key, services, scheduled-tasks, wmi, mitre]
prerequisites: [forensics-win-volatile]
useful_for:
  - "CTF Forensics категория"
  - "Incident Response (Windows)"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Механизмы автозапуска Windows и их следы: ключи Run/RunOnce, службы, планировщик задач, WMI-подписки, Winlogon, IFEO и COM hijack. Как найти вредоносную персистентность и отличить её от легитимной."
lab:
  kind: shell
  title: 'Практика: охота на персистентность'
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, autoruns.txt, persist.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Список точек автозапуска — в `autoruns.txt`.'
    - 'Обрати внимание на записи, запускающие powershell с флагом -enc из каталога Temp.'
    - 'Разбор делает учебный `python3 persist.py`.'
    - '`python3 persist.py | grep nto > found.txt`.'
---

## Вопрос, с которого всё начинается

Малварь удалили — процесс убит, файл стёрт. Но после перезагрузки она снова тут. Почему? Потому что где-то в системе осталась **точка автозапуска**: запись, которая при старте запускает программу заново. Таких механизмов в Windows десятки, и задача форензики — найти их все. Разберём, где искать и как отличить вредоносный автозапуск от легитимного.

## Наш пример: список автозапуска

У нас есть `autoruns.txt` — выгрузка точек автозапуска, похожая на то, что показывает утилита **Autoruns**:

```bash
$ cat autoruns.txt
[HKLM\Run]        OneDrive    C:\Program Files\Microsoft OneDrive\OneDrive.exe /background
[HKLM\Run]        SysHelper   C:\Users\Public\svchost.exe -k netsvcs
[Service]         WSearch     C:\Windows\System32\SearchIndexer.exe /Embedding
[Service]         UpdaterSvc  powershell.exe -nop -w hidden -enc SQBFAFgA...
[Task]            GoogleUpdate C:\Program Files\Google\Update\GoogleUpdate.exe
[Task]            \MicrosoftEdgeUpdate ...
[WMI]             EventFilter->CommandLineEventConsumer "C:\Users\Public\svchost.exe"
```

Мы видим записи из разных механизмов. Первое впечатление «всё выглядит системным» — и это ловушка: малварь маскируется под системные имена.

## Шаг 1: ключи Run — самый простой автозапуск

Ключи `Run`/`RunOnce` — классика. Их знают все, и потому их проверяют первыми:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `...\RunOnce`

Подозрительное здесь — путь `C:\Users\Public\svchost.exe`. Настоящий `svchost.exe` живёт в `C:\Windows\System32`, а **не** в `Public`. Имя скопировано, путь — нет. Это признак маскировки: атакующий назвал файл системно, чтобы беглый взгляд не насторожился.

## Шаг 2: службы

Служба запускается при старте системы и обычно работает с высокими правами — потому это любимый механизм персистентности. Ключ в реестре: `HKLM\SYSTEM\CurrentControlSet\Services\<Name>`. Смотрим на `ImagePath`:

```
[Service] UpdaterSvc  powershell.exe -nop -w hidden -enc SQBFAFgA...
```

Здесь сразу два красных флага: служба, запускающая **PowerShell** (а не исполняемый файл службы), да ещё с `-nop -w hidden -enc` (скрытый запуск обфусцированной base64-команды). Легитимная служба так не выглядит. Это техника **T1543.003 (Windows Service)** из MITRE ATT&CK.

## Шаг 3: планировщик задач

Задачи (`C:\Windows\System32\Tasks\`, реестр `...\Schedule\TaskCache`) запускаются по расписанию или по событию (логin, старт, idle). Их плюс для атакующего — можно привязать запуск к событию и остаться незамеченным. Наш список чистых задач (`GoogleUpdate`, `MicrosoftEdgeUpdate`) — норма; подозрительной была бы задача, запускающая скрипт из `Temp`/`Public` от имени SYSTEM.

## Шаг 4: WMI-подписки — «невидимая» персистентность

WMI-подписки (`__EventFilter` + `CommandLineEventConsumer`) — механизм, о котором многие забывают. Событие (например, вход в систему) активирует consumer, и тот запускает команду. В файловой системе **нет ни задачи, ни ключа Run** — только записи в репозитории WMI (`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`). Поэтому их ищут отдельно:

```
[WMI]  __EventFilter            Name=UpdaterFilter Query="SELECT * FROM __InstanceModificationEvent ..."
[WMI]  CommandLineEventConsumer Name=UpdaterConsumer CommandLine="C:\Users\Public\svchost.exe"
[WMI]  __FilterToConsumerBinding
```

Связка «фильтр → consumer» — это и есть автозапуск. Наш `persist.py` разбирает список и помечает подозрительное:

```bash
$ python3 persist.py
[PERSIST] entries=7
[PERSIST] Run\SysHelper   -> C:\Users\Public\svchost.exe  [SUSPICIOUS: wrong svchost path]
[PERSIST] Service UpdaterSvc -> powershell -enc  [SUSPICIOUS: hidden encoded cmd]
[PERSIST] WMI binding -> C:\Users\Public\svchost.exe  [SUSPICIOUS: WMI persistence]
[PERSIST] key=nto{p3rs1st3nc3_run_s3rv1c3_task}
```

```bash
$ python3 persist.py | grep nto > found.txt
```

## Шаг 5: другие места

Полный список механизмов велик; запомним основные:

| Механизм | Где | Признак злоупотребления |
|----------|-----|--------------------------|
| Run/RunOnce | HKCU/HKLM ...\Run | путь вне System32, необычный бинарь |
| Services | HKLM\SYSTEM\...\Services | PowerShell/скрипт в ImagePath |
| Scheduled Tasks | System32\Tasks | скрипт из Temp, запуск от SYSTEM |
| WMI subscriptions | wbem\Repository | фильтр→consumer |
| Winlogon (Shell/Userinit) | HKLM\...\Winlogon | подмена на сторонний exe |
| IFEO Debugger | ...\Image File Execution Options | перехват запуска легитимной программы |
| COM hijack | HKCU\Software\Classes\CLSID | подмена DLL по GUID |
| Startup folder | Start Menu\Programs\Startup | ссылка на подозрительный файл |
| Logon scripts | ...\Group Policy\Scripts | скрипт вне политики домена |
| Boot execute | Session Manager | ранний запуск до входа |

Один механизм можно спрятать, но **все сразу** — сложно: поэтому при разборе проверяют весь список, а не только Run.

## Шаг 6: таймлайн и легитимность

Ключевой вопрос — «когда это появилось». Времена создания файлов и ключей реестра (`LastWriteTime` ключа!) сопоставляют с моментом компрометации:

```bash
$ fls -r -m C: disk.raw | grep -i 'public\\svchost.exe'
0|C:/Users/Public/svchost.exe|...|2024-03-01 22:16:03
```

Если файл создан сразу после подозрительного входа (событие 4624) и совпадает по времени с записями Run/службы — картина складывается. `LastWriteTime` самого ключа реестра тоже хранится в кустах и показывает, когда запись появилась или изменилась.

## Если не сработало

- **Не нашли автозапуск, но малварь возвращается** → проверьте WMI-подписки, COM hijack, службы через `svchost` (аргумент `-k`), а также задачи с триггером по событию.
- **Запись выглядит легитимной** → сверьте путь с эталонным (эталонный `svchost` — в `System32`); посмотрите подпись файла и время создания.
- **Автозапуск «сам» исчез** → возможно, это был одноразовый `RunOnce` или задача, удаляющая себя; ищите следы в журналах и USN.
- **Реестр не читается** → возьмите офлайн-копию кустов (`SAM`, `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) и разбирайте RegRipper-ом.

## На что смотреть защитнику

- Мониторинг изменений в `Run`, `Services`, `Tasks` и создания WMI-подписок (Sysmon EID 1/11/13, Windows EID 4697/4698).
- Ограничение прав на `C:\Users\Public` и `Temp` — частые места для маскировки.
- Регулярная инвентаризация автозапуска (Autoruns-базовая линия) — тогда любое отклонение заметно.

## Что мы теперь знаем

- **Персистентность** — механизм автозапуска; их десятки, и искать надо не только Run.
- Признаки злоупотребления: путь вне `System32`, PowerShell/скрипт в `ImagePath`, запуск от SYSTEM из Temp.
- **WMI-подписки** не видны в файлах — только в репозитории WMI.
- Время создания файла и `LastWriteTime` ключа связывают запись с моментом атаки.
- Полный список механизмов проверяют целиком — малварь прячет один, но не все.

## Квиз

Проверь себя.

```quiz
- question: "Где лежит классический ключ автозапуска для всех пользователей?"
  options:
    - "HKCU\\...\\Run"
    - "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    - "HKLM\\SYSTEM\\Services"
    - "C:\\Windows\\Temp"
  answer: 1
  explanation: "HKLM Run запускает программу для всех пользователей при входе."
- question: "Чем подозрителен путь C:\\Users\\Public\\svchost.exe?"
  options:
    - "ничем, это системный файл"
    - "настоящий svchost.exe находится в System32, а не в Public"
    - "файл слишком маленький"
    - "у него нет расширения"
  answer: 1
  explanation: "Маскировка под системное имя с неверным путём — типичный приём малвари."
- question: "Почему WMI-подписки сложно найти в файловой системе?"
  options:
    - "они удаляются сразу"
    - "они хранятся только в репозитории WMI, а не в виде файла-скрипта или задачи"
    - "они зашифрованы"
    - "они в оперативной памяти"
  answer: 1
  explanation: "Фильтр→consumer живёт в wbem\\Repository\\OBJECTS.DATA, а не как отдельный файл автозапуска."
- question: "Какой ImagePath службы выглядит вредоносным?"
  options:
    - "C:\\Windows\\System32\\services.exe"
    - "powershell.exe -nop -w hidden -enc <base64>"
    - "C:\\Windows\\System32\\svchost.exe -k netsvcs"
    - "C:\\Windows\\System32\\SearchIndexer.exe"
  answer: 1
  explanation: "Служба, запускающая скрытый закодированный PowerShell, — классическая персистентность."
- question: "Что связывает найденную запись автозапуска с моментом атаки?"
  options:
    - "имя файла"
    - "время создания файла и LastWriteTime ключа реестра"
    - "размер файла"
    - "владелец файла"
  answer: 1
  explanation: "Таймстемпы файлов и ключей позволяют сопоставить запись с временем компрометации."
```

## Куда дальше

Мы закончили ветку волатильных и системных артефактов Windows. В следующем модуле (`forensics-win-telemetry`) перейдём к телеметрии: Defender/EDR, централизованные журналы и следы RDP. А пока главное запомни: **персистентность ищут во всех механизмах автозапуска, а не только в Run**.

## Где пригодится

- **CTF:** задача «как малварь закрепляется» и флаг в одной из точек автозапуска.
- **IR:** полная очистка после инцидента — найти и убрать все точки закрепления.
- **Threat Hunting:** охота на WMI-подписки и COM hijack, которые не видны «на глаз».
- **MITRE ATT&CK:** маппинг находок на техники Persistence (T1543, T1547, T1053).
