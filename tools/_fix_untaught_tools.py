#!/usr/bin/env python3
"""Add a short teaching section for the tool a lab uses but the lesson never
introduced (labalign: lab-tool-untaught). Method (b) from the task: introduce
the tool with a worked example so lab ⊆ lesson holds.

For each id: insert `## Инструмент: …` right before the `## Квиз` heading.
"""
import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTENT = os.path.join(ROOT, "content")

SECTIONS = {
"forensics-autopsy": """## Инструмент: mmls (разметка разделов)

Прежде чем Autopsy покажет файлы, нужно понять, где на образе начинается
файловая система. Это делает `mmls` из Sleuth Kit — консольный разбор таблицы
разделов:

```
$ mmls usb.E01
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
00:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
01:  -----   0000000000   0000002047   0000002048   Unallocated
02:  00:00   0000002048   0000409599   0000407552   NTFS (0x07)
```

`Start` раздела (в секторах) — это offset, с которого начинается ФС; его же
принимают `fls`/`icat`. Autopsy делает то же самое графически, но `mmls`
показывает разметку напрямую и незаменим, когда GUI не открывает образ.
""",
"forensics-evidence-handling": """## Инструмент: cmp и sha256sum (верификация копии)

Целостность копии доказывают двумя способами. Быстрая побайтовая проверка —
`cmp`: она молчит, если файлы идентичны, и печатает первое расхождение:

```
$ cmp evidence_A.dd evidence_B.dd
evidence_A.dd evidence_B.dd differ: byte 4097, line 1
```

Криптографическая — `sha256sum`, которой сверяют хеш копии с эталоном:

```
$ sha256sum evidence_A.dd evidence_B.dd
9f2c…  evidence_A.dd
9f2c…  evidence_B.dd
```

Совпадение `cmp` (exit 0) И хешей — условие, при котором копию можно считать
достоверной. `evidence_check.py` в лабе автоматизирует обе проверки.
""",
"forensics-fs-internals": """## Инструмент: dumpe2fs и debugfs (ext2/3/4)

Параметры суперблока ext-ФС читает `dumpe2fs`:

```
$ dumpe2fs ext4.img
Filesystem volume name:   <none>
Filesystem features:      has_journal ext_attr resize_inode
Inode count:              8192
Journal inode:            8
```

А `debugfs` даёт доступ к структурам напрямую — в том числе к списку удалённых
inode (`lsdel`) и чтению файла по пути:

```
$ debugfs -R "lsdel" ext4.img
 Inode  Owner  Mode    Size    Blocks   Time deleted
  12   1000  100644   40      1      ...
$ debugfs -R "cat /secret.txt" ext4.img
```

Именно `lsdel` показывает, что после удаления данные ещё живы в невыделенных
блоках, а журнал (`Journal inode`) хранит недавние метаданные.
""",
"forensics-fs-structure": """## Инструмент: mmls (таблица разделов)

`mmls` из Sleuth Kit разбирает таблицу разделов (MBR/GPT) и печатает список
смещений — это первый шаг к любой файловой системе:

```
$ mmls disk.img
DOS Partition Table
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
02:  00:00   0000002048   0000004095   0000002048   Linux (0x83)
```

`Start` — offset раздела в секторах; умножив на 512, получают байтовое
смещение, с которого начинается ФС. Сигнатуру MBR (`55 aa`) при этом видно
прямо в загрузочном секторе.
""",
"forensics-img-captures": """## Инструмент: Volatility (vol)

Дамп памяти разбирают Volatility 3 командой `vol` — плагинами:

```
$ vol -f mem.raw windows.pslist
PID    PPID   ImageFileName   Offset(V)   ...
4      0      System          0x8a0b…
612    4      smss.exe        0x8a1c…
```

`windows.pslist` — процессы, `windows.netscan` — сетевые соединения,
`windows.cmdline` — аргументы запуска. Снимок диска/памяти фиксирует
волатильные данные, которые не переживут выключение, поэтому память снимают
первой.
""",
"forensics-img-mobile": """## Инструмент: simg2img (Android sparse image)

Образ `userdata.img` из Android часто не «сырой», а sparse — с разрежённым
форматом, где подряд идут заголовки и блоки данных. Его нельзя читать как
обычный диск, пока не развернёшь:

```
$ xxd -l 4 userdata.img
00000000: 3aff 26ed                                :.&.
$ simg2img userdata.img userdata.raw
$ file userdata.raw
userdata.raw: Linux rev 1.0 ext4 filesystem data
```

Магия `3a ff 26 ed` — признак Android sparse image. `simg2img` превращает его
в обычный raw-образ, с которым работают все остальные инструменты.
""",
"forensics-storage-layers": """## Инструмент: pvs и pvscan (LVM)

Прежде чем читать логические тома, нужно найти физические. Это делают
`pvscan` (обзор) и `pvs` (таблица):

```
$ pvscan pv.img
  PV /dev/loop0  VG vg0  lvm2 [1.00 GiB / 0 free]
$ pvs pv.img
  PV         VG   Fmt  Attr PSize   PFree
  pv.img     vg0  lvm2 a--  1.00g      0
```

`LABELONE` в секторе 1 и строка `LVM2 001` — подпись Physical Volume. Собрав
цепочку PV → VG → LV, вы получаете логический том, который и нужно
проанализировать; ниже виртуального тома может лежать ещё слой (QCOW2).
""",
"forensics-win-execution": """## Инструмент: PECmd (разбор Prefetch)

Файл Prefetch (`*.pf`) доказывает, что программа запускалась. Читают его
утилитой PECmd:

```
$ PECmd POWERSHELL.EXE-1A2B3C4D.pf
POWERSHELL.EXE-1A2B3C4D.pf
  Run count:   3
  Last run:    2026-02-10 09:14:03
  Volume:      \\VOLUME{...}
  Directories: \\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32
```

Магия `SCCA` в начале файла подтверждает формат. Сопоставив `Run count` и
время последнего запуска с AmCache, можно доказать факт исполнения даже без
других следов.
""",
"forensics-win-logs": """## Инструмент: evtx_dump (разбор EVTX)

Windows-журнал `.evtx` — бинарный; в текст его переводит `evtx_dump` из
python-evtx:

```
$ xxd -l 7 Security.evtx
00000000: 456c 6646 696c 65                      ElfFile
$ evtx_dump.py Security.evtx -o events.json
$ grep -o '"EventID":[0-9]*' events.json | sort | uniq -c
```

Магия `ElfFile` — подпись формата EVTX. На выходе — JSON, где по `EventID`
ищут события: 4624 — вход в систему, 4688 — создание процесса, 1102 —
очистка журнала.
""",
"forensics-win-misc": """## Инструмент: stat (метаданные файла)

`stat` показывает временные метки и inode файла — то, что `ls -l` скрывает:

```
$ stat tmp/.hidden_backdoor.sh
  File: tmp/.hidden_backdoor.sh
  Size: 148        Blocks: 8          IO Block: 4096   regular file
Access: (0755/-rwxr-xr-x)  Uid: (    0/    root)
Modify: 2026-02-10 09:14:03
 Change: 2026-02-10 09:14:05
```

Расхождение `Modify` и `Change` — классический признак «timestomping», а
несовпадение времени создания файла и журнала входа выдаёт анти-форензику.
""",
"forensics-win-registry": """## Инструмент: RegRipper (rip.pl)

Кусты реестра — бинарные (`regf`); читает их RegRipper плагинами:

```
$ xxd -l 4 SOFTWARE
00000000: 7265 6766                                regf
$ rip.pl -r SOFTWARE -p soft_run
soft_run v.20200525
SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
  LastWrite Time 2026-02-10 09:14:03Z
  Updater -> C:\\Users\\Public\\upd.exe
```

Плагин `soft_run` печатает ключ автозапуска Run с временем последней записи.
Именно связка «значение Run + LastWrite Time» доказывает закрепление в системе.
""",
"pwn-brop": """## Инструмент: ROPgadget

Гаджеты (последовательности инструкций, заканчивающиеся `ret`) ищет
`ROPgadget`:

```
$ ROPgadget --binary brop | grep 'pop rdi'
0x0000000000401213 : pop rdi ; ret
0x0000000000401230 : pop rsi ; pop r15 ; ret
```

В blind ROP адреса неизвестны заранее, но найденный через утечку базовый
гаджет (`ret` = stop gadget) позволяет перебирать остальные: `pop rdi; ret`
нужен, чтобы положить адрес в первый аргумент вызова.
""",
"pwn-musl": """## Инструмент: readelf

`readelf` показывает заголовки ELF без запуска файла. Для статического бинаря
динамической секции нет вовсе:

```
$ file chall
chall: ELF 64-bit LSB executable, statically linked, stripped
$ readelf -d chall
There is no dynamic section in this file.
$ readelf -h chall | grep Entry
  Entry point address: 0x401000
```

Отсутствие `NEEDED`-записей и `PT_INTERP` означает, что библиотеки вкомпилены:
эксплуатация идёт не через PLT/GOT, а через прямые syscall-гаджеты.
""",
"pwn-static-no-libc": """## Инструмент: readelf

`readelf` разбирает заголовки статического ELF. Ключевое отличие от
динамического — отсутствие интерпретатора:

```
$ readelf -l staticapp | grep -i interp
$ readelf -h staticapp | grep Entry
  Entry point address: 0x401000
```

Пустой вывод по `INTERP` означает, что динамического линкера нет, и точка
входа `e_entry` задаёт старт программы. Тогда для RCE используют прямые
syscall-гаджеты (`syscall; ret`) вместо вызовов libc.
""",
"reversing-crypto-binaries": """## Инструмент: xorbin (проверка XOR-ключа)

Когда «шифр» в бинаре сводится к XOR с константой, проверку удобно делать
утилитой `xorbin`: она применяет ключ к строке и показывает результат.

```
$ xorbin 'nt0{r3v3rs3_x0r}'
ciphertext: ...
```

XOR симметричен, поэтому `input = target ^ key` и `target = input ^ key` —
одна и та же операция. Найдя в дизассемблере константу (`0x5a`), вы тем же
ключом восстанавливаете ожидаемый вход.
""",
"reversing-elf-instrumentation": """## Инструмент: образец crackme6

Объект разбора — бинарь `crackme6`. Это ELF, который сравнивает введённый
пароль со строкой из `.rodata`:

```
$ strings crackme6 | grep -i -E 'pass|open'
0p3n_s3s4m3
$ objdump -d crackme6 | grep -A2 strcmp
```

Строка-пароль лежит в `.rodata` открытым текстом, а сравнение идёт через
`strcmp` (его видно в дизассемблере). Инструментация (LD_PRELOAD или патч)
позволяет подменить сравнение и получить флаг, не подбирая пароль.
""",
"reversing-go-advanced": """## Инструмент: go tool nm

Символы Go-бинаря восстанавливают из таблицы `pclntab`. Даже после `strip`
утилита `nm` из тулчейна Go (`go tool nm`) находит имена функций:

```
$ go tool nm gobin2
  4b1a20 T main.main
  4b1f40 T main.checkPassword
  4c0200 T runtime.morestack
```

Префикс `T` — текстовый символ. Имя `main.checkPassword` прямо указывает на
функцию проверки: дизассемблируем её и находим сравнение. `pclntab` —
встроенная таблица соответствия адресов и имён, которую Go не убирает при
`strip`, поэтому символы «выживают».
""",
"reversing-packing-upx": """## Инструмент: objdump

Упакованный бинарь выдаёт себя маленьким числом импортов и «шумным»
дизассемблером. Быстрая проверка — `objdump`:

```
$ objdump -h packed | grep -E 'text|UPX'
$ objdump -d packed | head
```

У UPX-стаба секция обычно называется `UPX0`/`UPX1`, а код на входе — распаковщик,
а не логика программы. После распаковки `objdump -d` показывает нормальный
код, и дальше реверс идёт как обычно.
""",
"reversing-module-symbolic": """## Инструмент: образец crackme

Объект разбора — бинарь `crackme`: он проверяет пароль ветвлениями, которые
неудобно проходить руками. Символический движок (angr/z3) трактует вход как
символ и ищет путь к «успеху»:

```
$ file crackme
crackme: ELF 64-bit LSB executable
$ python3 solve.py
```

`solve.py` описывает проверку как ограничения над байтами входа и решает их
солвером: на выходе — строка, ведущая к ветке успеха, без перебора.
""",
"reversing-symbolic-recipe": """## Инструмент: образец keygenme

Объект разбора — `keygenme`: бинарь, который принимает ключ и проверяет его
несколькими арифметическими условиями. Вместо ручного перебора условия
переводят в систему ограничений и решают солвером:

```
$ file keygenme
keygenme: ELF 64-bit LSB executable
$ strings keygenme | grep -i key
```

Каждая проверка (`if (x*3 == 42)`) становится ограничением для z3; решив всю
систему, получают валидный ключ, не подбирая его в лоб.
""",
}

def find(slug):
    for p in glob.glob(os.path.join(CONTENT, "**", "*.md"), recursive=True):
        t = open(p, encoding="utf-8", errors="replace").read()
        m = re.search(r'^id:\s*["\']?([^"\'\n]+)', t, re.M)
        if m and m.group(1).strip() == slug:
            return p
    return None

def main():
    n = 0
    for slug, sec in SECTIONS.items():
        p = find(slug)
        if not p:
            print("MISS", slug); continue
        t = open(p, encoding="utf-8").read()
        if "## Инструмент" in t and sec.split("\n")[0] in t:
            print("SKIP", slug); continue
        m = re.search(r'^## Квиз\s*$', t, re.M)
        if not m:
            print("NOQUIZ", slug); continue
        t = t[:m.start()] + sec + "\n" + t[m.start():]
        open(p, "w", encoding="utf-8").write(t)
        n += 1
    print("inserted", n)

if __name__ == "__main__":
    main()
