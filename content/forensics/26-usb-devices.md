---
id: forensics-usb-devices
title: "USB и device forensics: следы подключений устройств"
category: forensics
parent: forensics-win-registry
difficulty: medium
order: 4
tags: [usb, usbstor, setupapi, lnk, devices, registry, dfir]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Криминалистика (утечки на носители)"
estimated_minutes: 40
summary: "Как восстановить историю подключения USB-устройств: реестр USBSTOR, SetupAPI, LNK-файлы, MountPoints и привязка файлов к конкретной флешке."
lab:
  kind: shell
  title: "Практика: USB-устройства по setupapi.dev.log"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, setupapi.dev.log]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Формат `USB\\VID_xxxx&PID_xxxx\\<serial>`."
    - "Ищи строки установки устройства."
    - "`grep -i nto setupapi.dev.log > found.txt`."

---

## Вопрос, с которого всё начинается

Нужно доказать, что злоумышленник скопировал данные на флешку и вынес их. Флешки у нас
нет. Но Windows фиксирует подключения устройств в нескольких местах — и по этим следам
можно восстановить всю картину.

В этом уроке мы пройдём от факта «подключалась флешка» до «с неё открывали конкретный
файл» и свяжем файл с конкретным носителем.

## Наш пример: флешка SanDisk

Смотрим ключ реестра `USBSTOR`:

```bash
$ rip.pl -r SYSTEM -p usb
USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00
  S/N: 4C530001120523116345
  Last Connected: 2024-03-01 12:00:00
```

`USBSTOR` — раздел реестра, где для каждого USB-**накопителя** хранится производитель,
модель и **серийный номер**, а также время первого и последнего подключения. Серийный
номер уникален — именно по нему связывают все остальные артефакты.

## Шаг 1: не путать USB и USBSTOR

- `Enum\USB` — само устройство (интерфейс USB).
- `Enum\USBSTOR` — именно **накопители** (mass storage).
- `Enum\SCSI` — внешние диски, подключённые иначе.
- `Enum\WpdBusEnumRoot` — телефоны (MTP).

Накопитель всегда ищите в `USBSTOR`. Для наглядности можно выгрузить ключ целиком:

```bash
$ hivexregedit --export SYSTEM '\ControlSet001\Enum\USBSTOR' usbstor.reg
```

## Шаг 2: буква диска и серийник тома

Ключ `MountedDevices` сопоставляет букву (`\DosDevices\E:`) с бинарным идентификатором
тома, внутри которого лежит **Volume Serial Number**:

```bash
$ rip.pl -r SYSTEM -p mountdev | grep -i dosdevices
\DosDevices\E: -> dmio:ID... Serial: 4C53-0001
```

Теперь мы знаем: флешка получила букву `E:`, а её том имеет серийный номер `4C53-0001`.
Серийник тома — отдельный идентификатор, не путайте его с серийником устройства из
`USBSTOR`.

## Шаг 3: точное время подключения

`setupapi.dev.log` — текстовый журнал установки драйверов. Здесь время подключения
записано с точностью до секунды:

```bash
$ grep -iA3 'USBSTOR' setupapi.dev.log | grep 'Section start'
>>>  Section start 2024/03/01 12:00:03.123
```

## Шаг 4: какие файлы открывали с носителя

Ярлыки `.lnk` в папке `Recent` содержат не только путь целевого файла, но и **Volume
Serial Number** тома, на котором он лежал:

```bash
$ LECmd.exe -d Recent --csv out --csvf lnk.csv
$ grep -i 'E:\\' out/lnk.csv
secret.docx, E:\backup\secret.docx, Volume Serial: 4C53-0001
```

Серийник `4C53-0001` совпадает с тем, что был в `MountedDevices`. Это и есть
доказательство: файл открывали именно с этой флешки, а не с любого диска.

## Шаг 5: навигация по папкам

**Shellbags** (в `UsrClass.dat`) фиксируют просмотренные папки, включая папки на съёмных
носителях, с временем доступа:

```bash
$ SBECmd.exe -d . --csv out --csvf sb.csv
$ grep -i 'E:' out/sb.csv
```

## Шаг 6: события подключения в EVTX

```bash
$ EvtxECmd.exe -f System.evtx --csv out --csvf system.csv
$ grep -i usbstor out/system.csv
```

Событие **20001** (DriverFrameworks) фиксирует подключение устройства и содержит
`InstanceId` вида `USBSTOR\Disk&Ven_...&Serial` — то же, что в реестре, но с точным
временем. Это независимое подтверждение.

## Привязка файлов к носителю в деталях

Ключевой вопрос — «какие файлы скопированы на эту флешку». Ответ собирается из
нескольких источников:

1. **LNK в `Recent`** — файлы, открытые с носителя, с Volume Serial.
2. **Jump Lists** — недавние документы приложения.
3. **Shellbags** — навигация по каталогам носителя.
4. **Prefetch** — «Files referenced» может содержать пути с буквой съёмного диска.

```bash
$ JLECmd.exe -d AutomaticDestinations --csv out
$ SBECmd.exe -d . --csv out --csvf sb.csv && grep -i 'E:' out/sb.csv
```

Volume Serial из LNK (`4C53-0001`) совпадает с `MountedDevices` — это и доказывает
связь файла именно с этим накопителем, а не с любым диском.

## Другие виды устройств

- `Enum\USB` — само устройство (интерфейс USB).
- `Enum\SCSI` — внешние диски.
- `Enum\WpdBusEnumRoot` — телефоны (MTP).
- Событие **20001** (DriverFrameworks) — подключение PnP-устройства.

```bash
$ evtx_dump -o json System.evtx | jq 'select(.Event.System.EventID==20001)' | head
```

## Практические ограничения

- **Серийник USBSTOR** генерируется драйвером и может быть подделан прошивкой.
- **`setupapi.dev.log` ротируется** (`.log`, `.log1`…) — старые записи теряются.
- **Windows 10+** меньше пишет в USBSTOR (использует `USB` и `WpdBusEnumRoot`).
- **Буквы дисков переиспользуются** — `E:` в разное время = разные носители.
- **Виртуальные USB** (RDP-проброс, `usbip`) не оставляют «физического» серийника.

## Итоговая реконструкция

«2024-03-01 12:00:03 устройство SanDisk Cruzer (S/N 4C530001120523116345) подключено
(setupapi + USBSTOR + Event 20001), получило букву `E:` (MountedDevices, Volume Serial
4C53-0001); с него открыт `E:\backup\secret.docx` (LNK, серийник совпадает);
пользователь просматривал каталог `E:\backup` (Shellbags)». Такая связка независимых
источников — стандарт доказывания в DFIR.

## Полный прогон от подключения до файла

Соберём всю историю по шагам:

```bash
# 1. USBSTOR — модель, серийник, время
$ rip.pl -r SYSTEM -p usb
# 2. MountedDevices — буква и серийник тома
$ rip.pl -r SYSTEM -p mountdev | grep -i dosdevices
# 3. setupapi — точное время подключения
$ grep -iA3 'USBSTOR' setupapi.dev.log | grep 'Section start'
# 4. LNK — открытые с носителя файлы
$ LECmd.exe -d Recent --csv out --csvf lnk.csv && grep -i 'E:\\' out/lnk.csv
# 5. Shellbags — просмотренные каталоги
$ SBECmd.exe -d . --csv out --csvf sb.csv | grep -i 'E:'
```

Каждый шаг добавляет деталь: модель и время (USBSTOR), букву (MountedDevices), секунду
подключения (setupapi), файл (LNK) и навигацию (Shellbags). Итог — доказанная привязка
файла к конкретному носителю.

## События EVTX о подключении

| Event ID | Лог | Смысл |
|----------|-----|-------|
| 20001 | DriverFrameworks-UserMode | подключение устройства |
| 20003 | DriverFrameworks-UserMode | отключение |
| 6416 | Security | новое устройство распознано |

Событие 20001 содержит `InstanceId` вида `USBSTOR\Disk&Ven_...&Serial` — то же, что в
реестре, но с точным временем. Это независимое подтверждение факта подключения.

## Что мы теперь знаем

- `USBSTOR` хранит модель, серийный номер и время подключения накопителя.
- `MountedDevices` связывает букву диска с серийным номером тома.
- `setupapi.dev.log` даёт точное время установки.
- LNK и Shellbags доказывают работу с файлами на носителе.
- EVTX 20001 подтверждает подключение независимо от реестра.

## На что смотреть дальше

- **Серийник USBSTOR генерируется драйвером** и может быть подделан прошивкой.
- **`setupapi.dev.log` ротируется** (`.log1`…) — старые записи могут пропасть.
- **Буквы дисков переиспользуются** — `E:` в разное время может быть разными носителями.
- **MTP-устройства** (телефоны) фиксируются иначе, чем mass-storage.
- **Проверяйте `Prefetch`** на пути с буквой съёмного диска — процесс мог работать с
  файлами на флешке напрямую.
- **Сверяйте серийник тома в LNK с `MountedDevices`** — только их совпадение доказывает
  связь файла с конкретным носителем.

## Квиз

Проверь себя.

```quiz
- question: "Какой ключ хранит вендора/продукт/серийник USB-носителя?"
  options:
    - "`MountedDevices`"
    - "`Enum\\USBSTOR`"
    - "`SAM`"
    - "`Run`"
  answer: 1
- question: "Где фиксируется время ПЕРВОГО подключения USB?"
  options:
    - "в `setupapi.dev.log`"
    - "в `SAM`"
    - "в Prefetch"
    - "в SRUM"
  answer: 0
- question: "Что связывает букву диска с устройством?"
  options:
    - "`USBSTOR`"
    - "`MountedDevices`"
    - "`NTUSER.DAT`"
    - "`EVTX`"
  answer: 1
- question: "Какие артефакты доказывают работу с файлами на флешке?"
  options:
    - "только Prefetch"
    - "LNK и Shellbags"
    - "SAM"
    - "MFT"
  answer: 1
- question: "Зачем нужен серийный номер USB-устройства?"
  options:
    - "для сжатия"
    - "для привязки файлов/действий к конкретному носителю"
    - "для шифрования"
    - "для удаления"
  answer: 1
```

## Куда дальше

Мы собрали доказательства использования носителя. Но злоумышленник может попытаться
**уничтожить следы**: почистить логи, подделать метки, затереть данные. В следующем
уроке мы научимся замечать такие попытки. А пока запомни: **серийный номер — мост между
устройством и файлами**.

## Где пригодится

- **CTF:** задачи «следы флешки».
- **DFIR:** расследование утечек данных на носители.
- **Криминалистика:** доказательство подключения устройства.
- **Корпоративная безопасность:** контроль неавторизованных носителей.
- **Threat Hunting:** выявление перемещения данных.
