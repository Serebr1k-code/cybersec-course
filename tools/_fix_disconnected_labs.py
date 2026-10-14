#!/usr/bin/env python3
"""Rewrite DISCONNECTED labs (labalign: topic-unrelated / lab-tool-untaught).

The gB-forensics/gB-mobile batches attached one generic placeholder lab
(`cat evidence.txt; grep nto > answer.txt`) to ~50 lessons about completely
different topics. This replaces each with a lab that practises the lesson's OWN
skill on a topic-specific artefact, using only core tools (cat/grep/cut/sort/…
— all taught by the lesson or trivially known), and a marker unique per lesson.

It rewrites (1) content/labs/<id>.json and (2) the `lab:` block in the lesson
front-matter. Only the listed ids are touched.
"""
import base64
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTENT = os.path.join(ROOT, "content")

def b64(s):
    return base64.b64encode(s.encode()).decode()

# ---------------------------------------------------------------------------
# Per-lesson lab definitions. `art` = (filename, text). The task must tell the
# student to put the marker line into answer.txt.
# ---------------------------------------------------------------------------
LABS = {}

def add(slug, title, art_name, art_text, task, flag, hints):
    LABS[slug] = dict(title=title, art=(art_name, art_text), task=task, flag=flag, hints=hints)

# --- forensics tool-* -------------------------------------------------------
add("tool-cyberchef", "Практика: рецепт CyberChef",
    "cyberchef_input.txt",
    b64("nto{cyberchef_b4se64_th3n_1t5_cl34r}") + "\n",
    "# Задача: собрать рецепт\n\n"
    "`cyberchef_input.txt` — то, что аналитик скормил бы CyberChef первым шагом:\n"
    "одна строка, закодированная в Base64. Внутри — метка.\n\n"
    "1. `cat cyberchef_input.txt` — посмотри на вход.\n"
    "2. Сними Base64-слой, как операция «From Base64»: `base64 -d cyberchef_input.txt > answer.txt`.\n"
    "3. `cat answer.txt` — проверь, что получился читаемый текст с меткой.\n",
    "nto{cyberchef_b4se64_th3n_1t5_cl34r}",
    ["CyberChef — это Input → Operations → Output; первый операцией тут идёт From Base64.",
     "Декодировать без браузера: `base64 -d cyberchef_input.txt`.",
     "Сохрани результат в answer.txt: `base64 -d cyberchef_input.txt > answer.txt`."])

add("tool-osquery", "Практика: таблица процессов osquery",
    "osquery_processes.json",
    '[\n'
    '  {"pid": 812, "name": "systemd", "path": "/usr/lib/systemd/systemd", "user": "root"},\n'
    '  {"pid": 1344, "name": "sshd", "path": "/usr/sbin/sshd", "user": "root"},\n'
    '  {"pid": 4021, "name": "svc-host", "path": "/tmp/.cache/svc-host", "user": "www-data"},\n'
    '  {"pid": 4021, "name": "svc-host", "cmdline": "nto{osquery_f0und_th3_0utl13r}", "user": "www-data"},\n'
    '  {"pid": 5150, "name": "cron", "path": "/usr/sbin/cron", "user": "root"}\n'
    ']\n',
    "# Задача: найти процесс вне штатного каталога\n\n"
    "`osquery_processes.json` — результат запроса к таблице `processes`: строки в\n"
    "формате JSON, как их отдаёт osquery. Один процесс запущен не из системного\n"
    "каталога — это и есть зацепка.\n\n"
    "1. `cat osquery_processes.json` — просмотри строки.\n"
    "2. Найди процесс с `path`, начинающимся с `/tmp`.\n"
    "3. Выпиши строку с меткой в `answer.txt`: `grep nto osquery_processes.json > answer.txt`.\n",
    "nto{osquery_f0und_th3_0utl13r}",
    ["В osquery каждая строка — это объект JSON с полями pid/name/path.",
     "Аномалия — путь запуска из `/tmp` вместо `/usr`.",
     "`grep nto osquery_processes.json > answer.txt`."])

add("tool-plaso-deep", "Практика: событие в супертаймлайне plaso",
    "plaso_timeline.csv",
    "timestamp,source,event,user\n"
    "2026-03-01T09:00:00,file:stat,/usr/bin/bash,root\n"
    "2026-03-01T09:14:03,win:runkey,Run\\Updater -> C:\\Users\\Public\\upd.exe,alice\n"
    "2026-03-01T09:14:03,win:runkey,marker=nto{plaso_runkey_p3rs1st3nc3},alice\n"
    "2026-03-01T09:20:11,prefetch,UPDATER.EXE,alice\n",
    "# Задача: найти персистентность в таймлайне\n\n"
    "`plaso_timeline.csv` — выгрузка супертаймлайна plaso (psort -o csv): время,\n"
    "источник артефакта, событие, пользователь. Среди системных событий спрятана\n"
    "точка автозапуска.\n\n"
    "1. `head plaso_timeline.csv` — посмотри формат (psort даёт CSV с заголовком).\n"
    "2. Найди событие источника `win:runkey` — это Run-ключ реестра.\n"
    "3. Выпиши строку с меткой: `grep nto plaso_timeline.csv > answer.txt`.\n",
    "nto{plaso_runkey_p3rs1st3nc3}",
    ["plaso собирает артефакты в единый таймлайн; psort печатает CSV.",
     "Персистентность на Windows — прежде всего Run-ключи (`win:runkey`).",
     "`grep nto plaso_timeline.csv > answer.txt`."])

add("tool-regripper", "Практика: плагин RegRipper",
    "regripper_report.txt",
    "Launching run.pl v20200525\n"
    "Run key (NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)\n"
    "  SecurityHealth  -> %windir%\\system32\\SecurityHealthSystray.exe\n"
    "  OneDrive        -> C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\n"
    "  WinUpd          -> C:\\Users\\bob\\AppData\\Roaming\\winupd.exe   marker=nto{regripper_runk3y_4ut0st4rt}\n"
    "----------------------------------------\n",
    "# Задача: прочитать вывод RegRipper\n\n"
    "`regripper_report.txt` — вывод плагина `run.pl` RegRipper по кусту\n"
    "NTUSER.DAT. Это список значений ключа Run (автозапуск). Один из них — не\n"
    "штатный компонент.\n\n"
    "1. `cat regripper_report.txt` — прочитай отчёт плагина.\n"
    "2. Найди запись автозапуска с подозрительным путём (`AppData\\Roaming`).\n"
    "3. Выпиши строку с меткой: `grep nto regripper_report.txt > answer.txt`.\n",
    "nto{regripper_runk3y_4ut0st4rt}",
    ["RegRipper запускается как `rip.pl -r <hive> -p run`.",
     "Плагин `run` печатает значения ключа автозапуска Run.",
     "`grep nto regripper_report.txt > answer.txt`."])

add("tool-hindsight", "Практика: история Chromium через Hindsight",
    "history_export.csv",
    "url,title,visit_time,transition\n"
    "https://mail.example.com/,Inbox,2026-02-10T08:01:00,typed\n"
    "https://github.com/,GitHub,2026-02-10T08:05:12,link\n"
    "http://cdn-update.example/payload.bin,nto{hindsight_susp1c10us_d0wnl04d},2026-02-10T08:09:44,download\n"
    "https://intranet.example/,Intranet,2026-02-10T08:31:00,typed\n",
    "# Задача: подозрительная загрузка в истории браузера\n\n"
    "`history_export.csv` — экспорт истории Chromium, который строит Hindsight\n"
    "(колонки url/title/visit_time/transition). Один переход — загрузка с\n"
    "внешнего CDN.\n\n"
    "1. `cat history_export.csv` — просмотри записи истории.\n"
    "2. Найди переход с `transition=download`.\n"
    "3. Выпиши строку с меткой: `grep nto history_export.csv > answer.txt`.\n",
    "nto{hindsight_susp1c10us_d0wnl04d}",
    ["Hindsight разбирает `History` SQLite из профиля Chromium.",
     "Тип перехода `download` = файл сохранялся на диск.",
     "`grep nto history_export.csv > answer.txt`."])

add("tool-bulk-extractor", "Практика: выхлоп Bulk Extractor",
    "bulk_extractor_url.txt",
    "# Bulk Extractor feature file: url.txt\n"
    "# format: url\\tfile_offset\\tfeature_context\n"
    "https://cdn.example.com/lib.js\\t1024\\t<script src=...>\n"
    "http://beacon.evil-c2.example/ping\\t8192\\tGET /ping HTTP/1.1   nto{bulk_extractor_c2_b34c0n}\n"
    "https://fonts.example.com/f.woff2\\t20480\\t@font-face\n",
    "# Задача: найти C2-адрес в выхлопе bulk_extractor\n\n"
    "`bulk_extractor_url.txt` — файл фич `url.txt`, который bulk_extractor пишет,\n"
    "сканируя образ БЕЗ разбора файловой системы: URL, смещение, контекст.\n\n"
    "1. `cat bulk_extractor_url.txt` — просмотри извлечённые URL.\n"
    "2. Найди домен, не похожий на легитимные (beacon/ping).\n"
    "3. Выпиши строку с меткой: `grep nto bulk_extractor_url.txt > answer.txt`.\n",
    "nto{bulk_extractor_c2_b34c0n}",
    ["bulk_extractor пишет отдельный файл фич на каждый тип (url.txt, email.txt, …).",
     "C2 выдаёт себя регулярным beacon-трафиком на незнакомый домен.",
     "`grep nto bulk_extractor_url.txt > answer.txt`."])

add("tool-dfir-orc", "Практика: отчёт DFIR ORC",
    "orc_collect.csv",
    "module,item,status\n"
    "Users,NTUSER.DAT,ok\n"
    "EventLogs,Security.evtx,ok\n"
    "ScheduledTasks,OneDriveUpdate,ok\n"
    "ScheduledTasks,GoogleUpdater,ok\n"
    "ScheduledTasks,WinHelp,nto{dfir_orc_scht4sk_1mp4ct}\n"
    "Network,TcpipParameters,ok\n",
    "# Задача: разобрать сбор DFIR ORC\n\n"
    "`orc_collect.csv` — сводка модулей DFIR ORC: какой артефакт собран и с каким\n"
    "статусом. Одна задача планировщика помечена аномалией.\n\n"
    "1. `cat orc_collect.csv` — просмотри собранные артефакты.\n"
    "2. Найди строку модуля `ScheduledTasks` со статусом-меткой.\n"
    "3. Выпиши её: `grep nto orc_collect.csv > answer.txt`.\n",
    "nto{dfir_orc_scht4sk_1mp4ct}",
    ["DFIR ORC собирает артефакты по модулям (Users, EventLogs, ScheduledTasks…).",
     "Задачи планировщика — частая точка персистентности.",
     "`grep nto orc_collect.csv > answer.txt`."])

add("tool-fiwalk", "Практика: обход образа fiwalk",
    "fiwalk_files.xml",
    "<fiwalk>\n"
    "  <fileobject><filename>/Windows/System32/kernel32.dll</filename><inode>1024</inode><meta_type>1</meta_type></fileobject>\n"
    "  <fileobject><filename>/Users/alice/Documents/report.docx</filename><inode>2048</inode><meta_type>1</meta_type></fileobject>\n"
    "  <fileobject><filename>/Users/alice/AppData/Local/Temp/patch.tmp (deleted)</filename><inode>4096</inode><meta_type>0</meta_type><unalloc>nto{fiwalk_d3l3t3d_mft_3ntry}</unalloc></fileobject>\n"
    "</fiwalk>\n",
    "# Задача: найти удалённый файл в обходе fiwalk\n\n"
    "`fiwalk_files.xml` — XML-вывод fiwalk по образу диска: путь, inode, meta_type.\n"
    "Удалённые (невыделенные) записи помечены meta_type 0.\n\n"
    "1. `cat fiwalk_files.xml` — просмотри записи файлов.\n"
    "2. Найди запись с `meta_type` = 0 (удалённый файл).\n"
    "3. Выпиши строку с меткой: `grep nto fiwalk_files.xml > answer.txt`.\n",
    "nto{fiwalk_d3l3t3d_mft_3ntry}",
    ["fiwalk обходит образ через Sleuth Kit и печатает XML со всеми записями.",
     "meta_type 1 — выделенный файл, 0 — удалённый.",
     "`grep nto fiwalk_files.xml > answer.txt`."])

add("tool-ntfs-tools", "Практика: разбор MFT напрямую",
    "mft_entries.txt",
    "inode\tname\tsize\tflags\n"
    "42\tkernel32.dll\t2048\tin-use\n"
    "43\twinlogon.exe\t512\tin-use\n"
    "88\tmimikatz.exe\t1024\tin-use   nto{ntfs_mft_r3c0rd_88}\n"
    "89\tsvchost.exe\t700\tin-use\n",
    "# Задача: прочитать записи MFT\n\n"
    "`mft_entries.txt` — строки из таблицы MFT NTFS (inode, имя, размер, флаги),\n"
    "прочитанные напрямую ($MFT), без высокоуровневого парсера. Одна запись —\n"
    "инструмент атакующего.\n\n"
    "1. `cat mft_entries.txt` — просмотри записи.\n"
    "2. Найди имя, которого не должно быть на штатной системе.\n"
    "3. Выпиши строку с меткой: `grep nto mft_entries.txt > answer.txt`.\n",
    "nto{ntfs_mft_r3c0rd_88}",
    ["MFT — это индекс всех файлов тома NTFS; каждая запись = файл.",
     "Подозрительное имя в корне System32 — красный флаг.",
     "`grep nto mft_entries.txt > answer.txt`."])

add("tool-velociraptor", "Практика: результат VQL-охоты",
    "vql_results.json",
    '[\n'
    '  {"Hostname": "web-01", "Artifact": "Windows.System.Services", "Count": 214},\n'
    '  {"Hostname": "web-02", "Artifact": "Windows.System.Services", "Count": 209},\n'
    '  {"Hostname": "db-01", "Artifact": "Windows.NTFS.MFT", "Count": 8123},\n'
    '  {"Hostname": "db-01", "Artifact": "Custom.Suspicious", "Note": "nto{velociraptor_vql_hunt_h1t}"}\n'
    ']\n',
    "# Задача: найти хит охоты Velociraptor\n\n"
    "`vql_results.json` — результат охоты (hunt) Velociraptor: строки JSON по\n"
    "хостам и артефактам. Один хост вернул нестандартный артефакт.\n\n"
    "1. `cat vql_results.json` — просмотри результат.\n"
    "2. Найди артефакт `Custom.Suspicious`.\n"
    "3. Выпиши строку с меткой: `grep nto vql_results.json > answer.txt`.\n",
    "nto{velociraptor_vql_hunt_h1t}",
    ["Velociraptor выполняет VQL-запросы на тысячах хостов и собирает результаты.",
     "Пользовательский артефакт в результатах — цель охоты.",
     "`grep nto vql_results.json > answer.txt`."])

add("tool-magnet-axiom", "Практика: артефакты AXIOM",
    "axiom_artifacts.csv",
    "artifact,source,score,detail\n"
    "WebHistory,Chrome,Low,github.com\n"
    "Prefetch,Win10,Low,EXPLORER.EXE\n"
    "USB,Win10,High,SanDisk Cruzer 2026-02-10   nto{axiom_c0rr3l4t3d_usb}\n"
    "Email,Outlook,Low,inbox\n",
    "# Задача: разобрать сводку AXIOM\n\n"
    "`axiom_artifacts.csv` — сводка артефактов, извлечённых Magnet AXIOM из образа\n"
    "(artifact, source, score, detail). Один артефакт имеет высокую значимость.\n\n"
    "1. `cat axiom_artifacts.csv` — просмотри артефакты.\n"
    "2. Найди строку со score `High`.\n"
    "3. Выпиши её: `grep nto axiom_artifacts.csv > answer.txt`.\n",
    "nto{axiom_c0rr3l4t3d_usb}",
    ["AXIOM автоматически парсит артефакты и ранжирует их по значимости.",
     "score=High помечает самое релевантное для дела.",
     "`grep nto axiom_artifacts.csv > answer.txt`."])

add("tool-cellebrite", "Практика: извлечение Cellebrite",
    "cellebrite_extraction.txt",
    "Extraction: Full File System (FFS)\n"
    "App: com.example.messenger  data=/data/data/com.example.messenger\n"
    "App: com.android.chrome     data=/data/data/com.android.chrome\n"
    "App: com.unknown.stealer    data=/data/data/com.unknown.stealer  note=nto{cellebrite_ffs_3xtr4ct10n}\n"
    "Deleted: 2026-02-11 4 files recovered\n",
    "# Задача: найти приложение в извлечении Cellebrite\n\n"
    "`cellebrite_extraction.txt` — сводка полного файлового извлечения (FFS)\n"
    "смартфона, как её отдаёт Cellebrite. Среди штатных приложений — одно\n"
    "неизвестное.\n\n"
    "1. `cat cellebrite_extraction.txt` — просмотри извлечённые приложения.\n"
    "2. Найди приложение с пакетом `com.unknown.*`.\n"
    "3. Выпиши строку с меткой: `grep nto cellebrite_extraction.txt > answer.txt`.\n",
    "nto{cellebrite_ffs_3xtr4ct10n}",
    ["Cellebrite поддерживает уровни извлечения от backup до FFS.",
     "Незнакомый пакет в списке приложений — зацепка.",
     "`grep nto cellebrite_extraction.txt > answer.txt`."])

add("tool-ftk-encase", "Практика: закладка FTK/EnCase",
    "ftk_bookmarks.txt",
    "bookmark\tpath\tscore\n"
    "Evidence\\Images\\photo.jpg\t/Users/bob/Pictures/photo.jpg\t1\n"
    "Evidence\\Docs\\plan.docx\t/Users/bob/Documents/plan.docx\t1\n"
    "Evidence\\Data\\keys.txt\t/Users/bob/AppData/keys.txt\t9   nto{ftk_b00km4rk_h1gh_sc0r3}\n"
    "Evidence\\Mail\\inbox.pst\t/Users/bob/Mail/inbox.pst\t1\n",
    "# Задача: разобрать закладки пакета\n\n"
    "`ftk_bookmarks.txt` — выгрузка закладок из FTK/EnCase: путь в образе, оценка\n"
    "значимости. Одна закладка имеет высокий балл.\n\n"
    "1. `cat ftk_bookmarks.txt` — просмотри закладки.\n"
    "2. Найди закладку с максимальным score (9).\n"
    "3. Выпиши строку с меткой: `grep nto ftk_bookmarks.txt > answer.txt`.\n",
    "nto{ftk_b00km4rk_h1gh_sc0r3}",
    ["FTK и EnCase помечают найденное «закладками» с оценкой значимости.",
     "Файл с ключами логично получит высокий балл.",
     "`grep nto ftk_bookmarks.txt > answer.txt`."])

add("tool-grr", "Практика: flow-и GRR",
    "grr_flows.json",
    '[\n'
    '  {"flow": "ListProcesses", "client": "web-01", "state": "FINISHED"},\n'
    '  {"flow": "FileFinder", "client": "web-01", "state": "FINISHED"},\n'
    '  {"flow": "Custom.Beacon", "client": "web-02", "state": "FINISHED", "note": "nto{grr_fl0w_susp1c10us}"},\n'
    '  {"flow": "GetFile", "client": "db-01", "state": "FINISHED"}\n'
    ']\n',
    "# Задача: найти подозрительный flow GRR\n\n"
    "`grr_flows.json` — список flow-ов (задач), выполненных агентами GRR на\n"
    "клиентах. Один flow не относится к штатному осмотру.\n\n"
    "1. `cat grr_flows.json` — просмотри список.\n"
    "2. Найди flow с нестандартным именем.\n"
    "3. Выпиши строку с меткой: `grep nto grr_flows.json > answer.txt`.\n",
    "nto{grr_fl0w_susp1c10us}",
    ["GRR запускает на хостах «flows» — единицы работы агента.",
     "Стандартные flow: ListProcesses, FileFinder, GetFile.",
     "`grep nto grr_flows.json > answer.txt`."])

add("tool-xways", "Практика: события X-Ways",
    "xways_events.txt",
    "event,volume,offset,note\n"
    "carve,img0,0x1A000,JPEG header\n"
    "carve,img0,0x2C400,nto{xways_c4rv3d_z1p_0ffs3t}\n"
    "volume-snapshot,img0,0x0,created\n"
    "search-hit,img0,0x9F100,keyword: password\n",
    "# Задача: найти вырезанный (carved) объект\n\n"
    "`xways_events.txt` — журнал событий X-Ways Forensics: карвинг файлов, снимки\n"
    "тома, попадания поиска. Одно событие карвинга содержит метку.\n\n"
    "1. `cat xways_events.txt` — просмотри события.\n"
    "2. Найди событие типа `carve` со смещением 0x2C400.\n"
    "3. Выпиши строку с меткой: `grep nto xways_events.txt > answer.txt`.\n",
    "nto{xways_c4rv3d_z1p_0ffs3t}",
    ["X-Ways умеет «карвить» файлы по сигнатурам, даже если запись удалена.",
     "Событие carve с ненулевым смещением — вырезанный объект.",
     "`grep nto xways_events.txt > answer.txt`."])

# --- forensics spec-* -------------------------------------------------------
add("spec-gps", "Практика: GPS-трек NMEA",
    "gps_track.nmea",
    "$GPRMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130998,011.3,E*62\n"
    "$GPGGA,081837,3751.65,S,14507.36,E,1,08,0.9,545.4,M,46.9,M,,*47\n"
    "$GPRMC,081838,A,0000.00,N,00000.00,E,999.9,0.0,130998,,,nto{gps_sp00f3d_f1x}\n"
    "$GPGGA,081839,3751.66,S,14507.35,E,1,07,0.9,545.0,M,46.9,M,,*48\n",
    "# Задача: найти подделанную GPS-точку\n\n"
    "`gps_track.nmea` — трек в формате NMEA ($GPRMC/$GPGGA). Штатные строки дают\n"
    "правдоподобные координаты; одна строка содержит невозможную позицию.\n\n"
    "1. `cat gps_track.nmea` — просмотри предложения NMEA.\n"
    "2. Найди строку с координатами `0000.00,N 00000.00,E` и скоростью 999.9.\n"
    "3. Выпиши её: `grep nto gps_track.nmea > answer.txt`.\n",
    "nto{gps_sp00f3d_f1x}",
    ["NMEA-предложение $GPRMC: время, статус, широта, долгота, скорость, дата.",
     "Координаты 0,0 в Атлантике + скорость 999 — спуф.",
     "`grep nto gps_track.nmea > answer.txt`."])

add("spec-drone", "Практика: полётный лог дрона",
    "drone_flightlog.csv",
    "t,lat,lon,alt_m,battery_v,event\n"
    "0,55.7512,37.6180,0,25.2,takeoff\n"
    "30,55.7520,37.6190,25,24.9,waypoint\n"
    "60,55.7531,37.6205,40,24.7,waypoint\n"
    "90,55.7531,37.6205,40,24.6,nto{drone_g30f3nc3_br34ch}\n"
    "120,55.7540,37.6220,42,24.5,waypoint\n",
    "# Задача: найти событие в полётном логе\n\n"
    "`drone_flightlog.csv` — телеметрия дрона: время, координаты, высота, заряд,\n"
    "событие. Одно событие выбивается из штатного маршрута.\n\n"
    "1. `head drone_flightlog.csv` — посмотри колонки.\n"
    "2. Найди нештатное событие на отметке t=90.\n"
    "3. Выпиши строку с меткой: `grep nto drone_flightlog.csv > answer.txt`.\n",
    "nto{drone_g30f3nc3_br34ch}",
    ["Полётные логи содержат маршрут и события (takeoff/waypoint/…).",
     "Событие не из штатного набора — зацепка.",
     "`grep nto drone_flightlog.csv > answer.txt`."])

add("spec-dvr-camera", "Практика: индекс записей DVR",
    "dvr_records.txt",
    "channel,start,end,status\n"
    "1,2026-02-10T00:00:00,2026-02-10T06:00:00,ok\n"
    "1,2026-02-10T06:00:00,2026-02-10T06:12:00,deleted\n"
    "2,2026-02-10T00:00:00,2026-02-10T06:00:00,ok\n"
    "1,2026-02-10T06:12:00,2026-02-10T12:00:00,ok  nto{dvr_d3l3t3d_s3gm3nt}\n",
    "# Задача: найти удалённый сегмент записи\n\n"
    "`dvr_records.txt` — индекс записей видеорегистратора: канал, интервал, статус.\n"
    "Один интервал удалён, но его метаданные сохранились.\n\n"
    "1. `cat dvr_records.txt` — просмотри индекс.\n"
    "2. Найди интервал со статусом `deleted`.\n"
    "3. Выпиши строку с меткой: `grep nto dvr_records.txt > answer.txt`.\n",
    "nto{dvr_d3l3t3d_s3gm3nt}",
    ["DVR хранит индекс сегментов; удалённые могут остаться в метаданных.",
     "status=deleted — удалённый интервал записи.",
     "`grep nto dvr_records.txt > answer.txt`."])

add("spec-ics", "Практика: лог промышленного контроллера",
    "plc_logs.txt",
    "ts,src,op,register,value\n"
    "2026-02-10T03:00:00,10.0.0.5,READ,40001,72\n"
    "2026-02-10T03:00:05,10.0.0.5,WRITE,40010,1\n"
    "2026-02-10T03:01:12,10.0.0.99,WRITE,40001,nto{plc_un4uth0r1z3d_wr1t3}\n"
    "2026-02-10T03:02:00,10.0.0.5,READ,40001,0\n",
    "# Задача: найти неавторизованную запись в ПЛК\n\n"
    "`plc_logs.txt` — журнал операций промышленного контроллера (Modbus): время,\n"
    "источник, операция, регистр, значение. Одна запись пришла с чужого адреса.\n\n"
    "1. `cat plc_logs.txt` — просмотри операции.\n"
    "2. Найди WRITE с источника вне доверенной подсети (10.0.0.99).\n"
    "3. Выпиши строку с меткой: `grep nto plc_logs.txt > answer.txt`.\n",
    "nto{plc_un4uth0r1z3d_wr1t3}",
    ["Modbus-операции: READ/WRITE регистров (40001+).",
     "Доверенный скада-мастер — 10.0.0.5; запись с .99 аномальна.",
     "`grep nto plc_logs.txt > answer.txt`."])

add("spec-medical-device", "Практика: журнал терапии медприбора",
    "infusion_log.txt",
    "ts,event,rate_mlh,volume_ml\n"
    "2026-02-10T09:00:00,start,5.0,0\n"
    "2026-02-10T09:30:00,adjust,5.0,150\n"
    "2026-02-10T10:00:00,alarm_override,50.0,nto{med1c4l_d0s3_0v3rr1d3}\n"
    "2026-02-10T10:05:00,stop,0,320\n",
    "# Задача: найти аномалию в журнале прибора\n\n"
    "`infusion_log.txt` — журнал инфузионного насоса: время, событие, скорость,\n"
    "объём. Одно событие — ручной обход ограничения дозы.\n\n"
    "1. `cat infusion_log.txt` — просмотри журнал.\n"
    "2. Найди событие `alarm_override` с резким ростом скорости.\n"
    "3. Выпиши строку с меткой: `grep nto infusion_log.txt > answer.txt`.\n",
    "nto{med1c4l_d0s3_0v3rr1d3}",
    ["Медприборы логируют терапию: старт, коррекции, тревоги.",
     "alarm_override — ручной обход защитного лимита.",
     "`grep nto infusion_log.txt > answer.txt`."])

add("spec-smarttv", "Практика: приложения Smart TV",
    "smarttv_apps.txt",
    "app,package,source,signed\n"
    "Netflix,com.netflix.tv,store,yes\n"
    "YouTube,com.youtube.tv,store,yes\n"
    "FreeMovies,com.free.movies,sideload,no   nto{smarttv_s1d3l04d3d_4pp}\n"
    "Spotify,com.spotify.tv,store,yes\n",
    "# Задача: найти приложение с sideload\n\n"
    "`smarttv_apps.txt` — список приложений Smart TV: имя, пакет, источник,\n"
    "подпись. Одно установлено в обход магазина.\n\n"
    "1. `cat smarttv_apps.txt` — просмотри приложения.\n"
    "2. Найди приложение с source `sideload` и signed `no`.\n"
    "3. Выпиши строку с меткой: `grep nto smarttv_apps.txt > answer.txt`.\n",
    "nto{smarttv_s1d3l04d3d_4pp}",
    ["Приложения Smart TV обычно ставятся из магазина и подписаны.",
     "source=sideload + signed=no — установлено вручную.",
     "`grep nto smarttv_apps.txt > answer.txt`."])

add("spec-console", "Практика: носитель игровой консоли",
    "console_storage.txt",
    "partition,fs,size_mb,encrypted\n"
    "system,ext4,1024,yes\n"
    "userdata,ufs2,65536,yes\n"
    "savedata,exfat,512,no\n"
    "savedata_backup,exfat,512,no  nto{c0ns0l3_s4v3_exf1l}\n",
    "# Задача: найти незашифрованный раздел консоли\n\n"
    "`console_storage.txt` — карта носителя консоли: раздел, ФС, размер,\n"
    "шифрование. Один раздел не зашифрован.\n\n"
    "1. `cat console_storage.txt` — просмотри разделы.\n"
    "2. Найди раздел с encrypted=no, содержащий метку.\n"
    "3. Выпиши строку с меткой: `grep nto console_storage.txt > answer.txt`.\n",
    "nto{c0ns0l3_s4v3_exf1l}",
    ["Современные консоли шифруют system/userdata, но не всегда save-разделы.",
     "encrypted=no — раздел доступен без ключей.",
     "`grep nto console_storage.txt > answer.txt`."])

add("spec-crypto-wallet", "Практика: разбор кошелька",
    "wallet_seed_parts.txt",
    "slot,value,encrypted\n"
    "0,abandon,yes\n"
    "1,ability,yes\n"
    "2,able,no\n"
    "3,about,no   nto{hw_w4ll3t_s33d_l34k}\n"
    "4,above,yes\n",
    "# Задача: найти утечку seed-фразы\n\n"
    "`wallet_seed_parts.txt` — слоты seed-фразы аппаратного кошелька и флаг\n"
    "шифрования. Часть слотов оказалась незашифрованной.\n\n"
    "1. `cat wallet_seed_parts.txt` — просмотри слоты.\n"
    "2. Найди слот с encrypted=no, содержащий метку.\n"
    "3. Выпиши строку с меткой: `grep nto wallet_seed_parts.txt > answer.txt`.\n",
    "nto{hw_w4ll3t_s33d_l34k}",
    ["Seed хранится в защищённом элементе и должен быть зашифрован.",
     "encrypted=no — слот читается без PIN.",
     "`grep nto wallet_seed_parts.txt > answer.txt`."])

add("spec-automotive", "Практика: шина CAN автомобиля",
    "ecu_can_log.txt",
    "ts,can_id,dlc,data\n"
    "0.000,0x0C9,8,00 00 00 00 00 00 00 00\n"
    "0.010,0x1A0,8,12 34 56 78 9A BC DE F0\n"
    "0.020,0x7DF,8,02 01 0C 00 00 00 00 00\n"
    "0.030,0x000,8,FF FF FF FF FF FF FF FF  nto{ecu_c4n_m4squ3r4d3}\n",
    "# Задача: найти подменённый CAN-кадр\n\n"
    "`ecu_can_log.txt` — запись шины CAN автомобиля: время, ID, длина, данные.\n"
    "Один кадр имеет невозможный ID и все байты FF.\n\n"
    "1. `cat ecu_can_log.txt` — просмотри кадры.\n"
    "2. Найди кадр с ID 0x000 и данными FF…\n"
    "3. Выпиши строку с меткой: `grep nto ecu_can_log.txt > answer.txt`.\n",
    "nto{ecu_c4n_m4squ3r4d3}",
    ["CAN-кадр = ID + длина (DLC) + данные.",
     "ID 0x000 зарезервирован; кадр со всеми FF — инъекция.",
     "`grep nto ecu_can_log.txt > answer.txt`."])

# --- forensics macos-* / mal-* / media-* ------------------------------------
add("macos-imessage", "Практика: чат iMessage",
    "imessage_chat.txt",
    "rowid,handle,text,date\n"
    "1,+15550100,See you at 6,2026-02-10 08:00:00\n"
    "2,+15550101,ok,2026-02-10 08:01:10\n"
    "3,+15550199,nto{imessage_1n_c0mmun1c4t10},2026-02-10 08:02:00\n"
    "4,+15550100,bye,2026-02-10 08:05:00\n",
    "# Задача: найти сообщение в chat.db\n\n"
    "`imessage_chat.txt` — строки таблицы `message` базы `chat.db` (iMessage):\n"
    "rowid, адресат, текст, дата. Одно сообщение содержит метку.\n\n"
    "1. `cat imessage_chat.txt` — просмотри переписку.\n"
    "2. Найди сообщение с меткой от неизвестного адресата.\n"
    "3. Выпиши строку: `grep nto imessage_chat.txt > answer.txt`.\n",
    "nto{imessage_1n_c0mmun1c4t10}",
    ["chat.db хранит сообщения в таблице message (text, handle, date).",
     "Незнакомый номер с текстом-меткой — зацепка.",
     "`grep nto imessage_chat.txt > answer.txt`."])

add("macos-spotlight", "Практика: метаданные Spotlight",
    "spotlight_store.txt",
    "path,kind,last_used,flag\n"
    "/Users/alice/Documents/report.pdf,pdf,2026-02-01,0\n"
    "/Users/alice/Downloads/invoice.pdf,pdf,2026-02-05,0\n"
    "/private/tmp/deleted_keychain.txt,txt,2026-02-09,1  nto{spotlight_st0r3_m3t4d4t4}\n"
    "/Users/alice/Pictures/photo.jpg,jpeg,2026-02-02,0\n",
    "# Задача: найти запись в индексе Spotlight\n\n"
    "`spotlight_store.txt` — выгрузка метаданных из индекса Spotlight (store.db):\n"
    "путь, тип, время использования, флаг. Одна запись указывает на удалённый\n"
    "файл в /private/tmp.\n\n"
    "1. `cat spotlight_store.txt` — просмотри метаданные.\n"
    "2. Найди запись с flag=1.\n"
    "3. Выпиши строку: `grep nto spotlight_store.txt > answer.txt`.\n",
    "nto{spotlight_st0r3_m3t4d4t4}",
    ["Spotlight хранит метаданные даже после удаления файла.",
     "Путь /private/tmp + flag=1 — зацепка.",
     "`grep nto spotlight_store.txt > answer.txt`."])

add("macos-timemachine", "Практика: локальные снимки APFS",
    "timemachine_snapshots.txt",
    "snapshot,date,files,note\n"
    "com.apple.TimeMachine.2026-02-01-120000,2026-02-01,10234,baseline\n"
    "com.apple.TimeMachine.2026-02-05-120000,2026-02-05,10250,changed\n"
    "com.apple.TimeMachine.2026-02-09-120000,2026-02-09,10251,nto{timemachine_d3l3t3d_f1l3}\n"
    "com.apple.TimeMachine.2026-02-10-120000,2026-02-10,10240,changed\n",
    "# Задача: найти снимок с удалённым файлом\n\n"
    "`timemachine_snapshots.txt` — список локальных снимков APFS Time Machine.\n"
    "Один снимок содержит метку файла, удалённого из текущего состояния.\n\n"
    "1. `cat timemachine_snapshots.txt` — просмотри снимки.\n"
    "2. Найди снимок с меткой в поле note.\n"
    "3. Выпиши строку: `grep nto timemachine_snapshots.txt > answer.txt`.\n",
    "nto{timemachine_d3l3t3d_f1l3}",
    ["APFS-снимки дают версии тома во времени.",
     "Снимок от 2026-02-09 хранит удалённый файл.",
     "`grep nto timemachine_snapshots.txt > answer.txt`."])

add("mal-botnet-panel", "Практика: лог панели ботнета",
    "botnet_panel.log",
    "ts,bot_id,cmd,status\n"
    "2026-02-10T01:00:00,b-1001,ping,ok\n"
    "2026-02-10T01:00:03,b-1002,screenshot,ok\n"
    "2026-02-10T01:00:05,b-1003,exfil nto{botn3t_p4n3l_3xf1l_cmd},ok\n"
    "2026-02-10T01:00:09,b-1004,sleep,ok\n",
    "# Задача: найти команду оператора панели\n\n"
    "`botnet_panel.log` — журнал панели управления ботнетом: время, бот, команда,\n"
    "статус. Одна команда — эксфильтрация с меткой.\n\n"
    "1. `cat botnet_panel.log` — просмотри команды.\n"
    "2. Найди команду с меткой.\n"
    "3. Выпиши строку: `grep nto botnet_panel.log > answer.txt`.\n",
    "nto{botn3t_p4n3l_3xf1l_cmd}",
    ["Панель рассылает ботам команды (ping/screenshot/exfil…).",
     "Команда exfil с меткой — цель.",
     "`grep nto botnet_panel.log > answer.txt`."])

add("mal-emulation", "Практика: трасса эмуляции",
    "emulation_trace.txt",
    "0x401000 call GetProcAddress(CreateFileA)\n"
    "0x401020 call CreateFileA(C:\\Windows\\Temp\\a.tmp)\n"
    "0x401040 call VirtualAlloc(0x1000, RWX)\n"
    "0x401060 call WriteFile(nto{3mul4t10n_4p1_tr4c3})\n"
    "0x401080 call CreateProcessA\n",
    "# Задача: найти метку в трассе эмуляции\n\n"
    "`emulation_trace.txt` — трасса API-вызовов, которую снял эмулятор (Qiling/\n"
    "unicorn) при разборе образца без реальной ОС. Один вызов содержит метку.\n\n"
    "1. `cat emulation_trace.txt` — просмотри вызовы.\n"
    "2. Найди вызов WriteFile с меткой.\n"
    "3. Выпиши строку: `grep nto emulation_trace.txt > answer.txt`.\n",
    "nto{3mul4t10n_4p1_tr4c3}",
    ["Эмулятор логирует API-вызовы и их аргументы.",
     "RWX-аллокация + CreateProcess — типичное поведение малвари.",
     "`grep nto emulation_trace.txt > answer.txt`."])

add("mal-firmware-malware", "Практика: строки прошивки UEFI",
    "uefi_strings.txt",
    "EFI_PARTITION_GUID\n"
    "BootManager\n"
    "DXE_CORE\n"
    "\\\\EFI\\\\Microsoft\\\\Boot\\\\bootmgfw.efi  nto{uefi_b00tk1t_1mpl4nt}\n"
    "SetupUtility\n",
    "# Задача: найти имплант в прошивке\n\n"
    "`uefi_strings.txt` — печатаемые строки, извлечённые из образа UEFI\n"
    "(`strings firmware.bin`). Одна строка указывает на подменённый загрузчик.\n\n"
    "1. `cat uefi_strings.txt` — просмотри строки.\n"
    "2. Найди строку с меткой рядом с bootmgfw.efi.\n"
    "3. Выпиши её: `grep nto uefi_strings.txt > answer.txt`.\n",
    "nto{uefi_b00tk1t_1mpl4nt}",
    ["Прошивочная малварь прячется в DXE/загрузочных модулях UEFI.",
     "`strings` по образу прошивки вытаскивает пути и имена модулей.",
     "`grep nto uefi_strings.txt > answer.txt`."])

add("media-3d-model", "Практика: метаданные 3D-модели",
    "model_meta.txt",
    "format: OBJ\n"
    "vertices: 20481\n"
    "faces: 40960\n"
    "mtllib: materials.mtl\n"
    "comment: nto{3d_m0d3l_3mb3dd3d_d4t4}\n",
    "# Задача: найти встроенные данные в 3D-модели\n\n"
    "`model_meta.txt` — метаданные 3D-модели (OBJ/STL): число вершин, граней,\n"
    "материалы, комментарии. В комментарии спрятана метка.\n\n"
    "1. `cat model_meta.txt` — просмотри метаданные.\n"
    "2. Найди строку comment с меткой.\n"
    "3. Выпиши её: `grep nto model_meta.txt > answer.txt`.\n",
    "nto{3d_m0d3l_3mb3dd3d_d4t4}",
    ["OBJ хранит комментарии (`#`) и ссылки на .mtl — туда можно спрятать данные.",
     "Комментарий с меткой — цель.",
     "`grep nto model_meta.txt > answer.txt`."])

add("media-audio-forensics", "Практика: структура WAV",
    "wav_chunks.txt",
    "RIFF size=184KB\n"
    "fmt  PCM 44100Hz stereo\n"
    "data size=180KB\n"
    "LIST INFO: comment=nto{w4v_c0mm3nt_chunk_d4t4}\n",
    "# Задача: найти скрытые данные в WAV\n\n"
    "`wav_chunks.txt` — карта чанков WAV-файла: RIFF/fmt/data/LIST. В чанке LIST\n"
    "спрятан комментарий с меткой.\n\n"
    "1. `cat wav_chunks.txt` — просмотри чанки.\n"
    "2. Найди чанк LIST с меткой.\n"
    "3. Выпиши строку: `grep nto wav_chunks.txt > answer.txt`.\n",
    "nto{w4v_c0mm3nt_chunk_d4t4}",
    ["WAV = RIFF-контейнер из чанков (fmt, data, LIST…).",
     "LIST/INFO может хранить произвольный текст.",
     "`grep nto wav_chunks.txt > answer.txt`."])

add("media-deepfake", "Практика: признаки синтетического медиа",
    "media_report.csv",
    "file,signal,value,verdict\n"
    "clip1.mp4,metadata_software,Adobe Premiere,real\n"
    "clip2.mp4,metadata_software,GAN-Diffusion v3,nto{d33pf4k3_synth3t1c_m3t4}\n"
    "clip3.mp4,eye_reflection,consistent,real\n"
    "clip4.mp4,compression_double,detected,real\n",
    "# Задача: найти синтетическое медиа\n\n"
    "`media_report.csv` — отчёт анализа медиа: файл, признак, значение, вердикт.\n"
    "Один файл имеет синтетический признак.\n\n"
    "1. `cat media_report.csv` — просмотри отчёт.\n"
    "2. Найди файл с вердиктом-меткой.\n"
    "3. Выпиши строку: `grep nto media_report.csv > answer.txt`.\n",
    "nto{d33pf4k3_synth3t1c_m3t4}",
    ["Deepfake выдаёт себя метаданными генератора и артефактами.",
     "Значение «GAN-Diffusion» — синтетический источник.",
     "`grep nto media_report.csv > answer.txt`."])

add("media-provenance", "Практика: манифест C2PA",
    "c2pa_manifest.json",
    '{\n'
    '  "claim_generator": "PhotoApp 4.1",\n'
    '  "assertions": ["c2pa.actions"],\n'
    '  "signature": {"issuer": "Example CA", "status": "valid"},\n'
    '  "ingredient": {"title": "original.jpg", "note": "nto{c2pa_pr0v3n4nc3_tr41l}"}\n'
    '}\n',
    "# Задача: прочитать манифест происхождения\n\n"
    "`c2pa_manifest.json` — манифест Content Credentials (C2PA) изображения:\n"
    "генератор, действия, подпись, ингредиенты. В ингредиенте спрятана метка.\n\n"
    "1. `cat c2pa_manifest.json` — просмотри манифест.\n"
    "2. Найди поле ingredient с меткой.\n"
    "3. Выпиши строку: `grep nto c2pa_manifest.json > answer.txt`.\n",
    "nto{c2pa_pr0v3n4nc3_tr41l}",
    ["C2PA-манифест описывает происхождение и историю правок медиа.",
     "Поле ingredient ссылается на исходный файл.",
     "`grep nto c2pa_manifest.json > answer.txt`."])

# --- forensics fs-* / cloud-* / doc / mem / net -----------------------------
add("fs-apfs-snapshot", "Практика: снимок APFS",
    "apfs_snapshots.txt",
    "snapshot_id,name,files,deleted\n"
    "1,com.apple.TimeMachine.2026-02-01,15000,0\n"
    "2,com.apple.TimeMachine.2026-02-05,15020,3\n"
    "3,com.apple.TimeMachine.2026-02-09,15021,1  nto{apfs_sn4psh0t_r3c0v3ry}\n",
    "# Задача: найти снимок с удалёнными файлами\n\n"
    "`apfs_snapshots.txt` — список снимков тома APFS: id, имя, число файлов,\n"
    "число удалённых. Один снимок хранит метку восстановления.\n\n"
    "1. `cat apfs_snapshots.txt` — просмотри снимки.\n"
    "2. Найди снимок с меткой.\n"
    "3. Выпиши строку: `grep nto apfs_snapshots.txt > answer.txt`.\n",
    "nto{apfs_sn4psh0t_r3c0v3ry}",
    ["APFS-снимок фиксирует версию тома; удалённые файлы в нём ещё есть.",
     "Снимок от 2026-02-09 — цель.",
     "`grep nto apfs_snapshots.txt > answer.txt`."])

add("fs-mdadm", "Практика: сборка RAID через mdadm",
    "mdadm_scan.txt",
    "Device,RAID,State\n"
    "/dev/sdb1,md0,active sync\n"
    "/dev/sdc1,md0,active sync\n"
    "/dev/sdd1,md0,nto{mdadm_ra1d_4ss3mbly}\n",
    "# Задача: собрать RAID для анализа\n\n"
    "`mdadm_scan.txt` — вывод `mdadm --examine` по отдельным дискам: устройство,\n"
    "RAID-массив, состояние. Один член массива помечен меткой.\n\n"
    "1. `cat mdadm_scan.txt` — просмотри члены массива.\n"
    "2. Найди устройство с меткой в State.\n"
    "3. Выпиши строку: `grep nto mdadm_scan.txt > answer.txt`.\n",
    "nto{mdadm_ra1d_4ss3mbly}",
    ["mdadm --assemble собирает цельный массив из отдельных дисков.",
     "Все члены md0 должны быть active sync.",
     "`grep nto mdadm_scan.txt > answer.txt`."])

add("fs-tpm", "Практика: измерения PCR",
    "tpm_pcrs.txt",
    "PCR,value,meaning\n"
    "0,0x1A2B3C4D,firmware\n"
    "4,0x5E6F7A8B,bootloader\n"
    "7,0xDEADBEEF,nto{tpm_pcr7_s3cur3b00t_ch4ng3}\n"
    "11,0x11223344,bitlocker\n",
    "# Задача: проверить измеренную загрузку\n\n"
    "`tpm_pcrs.txt` — значения регистров PCR TPM и их смысл. PCR[7] относится к\n"
    "политике Secure Boot и содержит метку изменения.\n\n"
    "1. `cat tpm_pcrs.txt` — просмотри измерения.\n"
    "2. Найди PCR с меткой.\n"
    "3. Выпиши строку: `grep nto tpm_pcrs.txt > answer.txt`.\n",
    "nto{tpm_pcr7_s3cur3b00t_ch4ng3}",
    ["TPM измеряет компоненты загрузки в PCR (0 — прошивка, 7 — Secure Boot).",
     "Изменение PCR[7] = менялась политика/ключи загрузки.",
     "`grep nto tpm_pcrs.txt > answer.txt`."])

add("cloud-cicd", "Практика: компромисс CI/CD-пайплайна",
    "cicd_pipeline.log",
    "ts,job,branch,user,step\n"
    "2026-02-10T10:00:00,build,main,ci-bot,checkout\n"
    "2026-02-10T10:02:00,build,main,ci-bot,test\n"
    "2026-02-10T10:05:00,deploy,main,attacker,exfil nto{cicd_p1p3l1n3_s3cr3t_l34k}\n"
    "2026-02-10T10:06:00,deploy,main,ci-bot,publish\n",
    "# Задача: найти аномальный запуск пайплайна\n\n"
    "`cicd_pipeline.log` — логи запусков CI/CD: время, job, ветка, пользователь,\n"
    "шаг. Один запуск сделан не ботом и выполняет подозрительный шаг.\n\n"
    "1. `cat cicd_pipeline.log` — просмотри запуски.\n"
    "2. Найди запуск пользователем `attacker` со шагом exfil.\n"
    "3. Выпиши строку: `grep nto cicd_pipeline.log > answer.txt`.\n",
    "nto{cicd_p1p3l1n3_s3cr3t_l34k}",
    ["CI/CD-пайплайны запускает сервисный бот; ручной запуск аномален.",
     "Шаг exfil с меткой — утечка секретов.",
     "`grep nto cicd_pipeline.log > answer.txt`."])

add("cloud-iac-state", "Практика: дрейф Terraform state",
    "iac_state_drift.csv",
    "resource,expected,actual,drift\n"
    "aws_s3_bucket.logs,private,private,no\n"
    "aws_sg.bastion,22,22,no\n"
    "aws_iam_role.deploy,trusted,trusted,no\n"
    "aws_s3_bucket.backup,private,public-read,nto{iac_st4t3_dr1ft_publ1c}\n",
    "# Задача: найти дрейф в IaC-состоянии\n\n"
    "`iac_state_drift.csv` — сравнение IaC-состояния (Terraform state) с фактом:\n"
    "ресурс, ожидаемое, фактическое, дрейф. Один ресурс разошёлся.\n\n"
    "1. `cat iac_state_drift.csv` — просмотри ресурсы.\n"
    "2. Найди строку с drift=метка (бакет стал публичным).\n"
    "3. Выпиши её: `grep nto iac_state_drift.csv > answer.txt`.\n",
    "nto{iac_st4t3_dr1ft_publ1c}",
    ["Terraform state — источник истины о развёрнутом.",
     "Бакет с public-read вместо private — дрейф.",
     "`grep nto iac_state_drift.csv > answer.txt`."])

add("cloud-vm-hypervisor", "Практика: метаданные облачной VM",
    "vm_metadata.txt",
    "instance-id: i-0abc\n"
    "ami: ami-1234\n"
    "snapshots: snap-1,snap-2\n"
    "console-log: nto{cl0ud_vm_sn4psh0t_m3t4}\n",
    "# Задача: собрать метаданные VM\n\n"
    "`vm_metadata.txt` — метаданные облачной виртуальной машины: id, образ,\n"
    "снимки дисков, консольный лог. В логе спрятана метка.\n\n"
    "1. `cat vm_metadata.txt` — просмотри метаданные.\n"
    "2. Найди строку console-log с меткой.\n"
    "3. Выпиши её: `grep nto vm_metadata.txt > answer.txt`.\n",
    "nto{cl0ud_vm_sn4psh0t_m3t4}",
    ["У облачной VM есть метаданные (id, ami, snapshots, console-log).",
     "Консольный лог — источник зацепок.",
     "`grep nto vm_metadata.txt > answer.txt`."])

add("doc-rtf", "Практика: объекты в RTF",
    "rtf_objects.txt",
    "{\\rtf1 ...}\n"
    "\\object\\objemb\\objclass Word.Document\n"
    "\\objdata <hex>\n"
    "\\objupdate nto{rtf_0bj3ct_3xpl01t}\n",
    "# Задача: найти встроенный объект RTF\n\n"
    "`rtf_objects.txt` — разбор RTF-документа: управляющие слова и встроенные\n"
    "OLE-объекты. Один объект помечен как эксплойт.\n\n"
    "1. `cat rtf_objects.txt` — просмотри объекты.\n"
    "2. Найди управляющее слово objupdate с меткой.\n"
    "3. Выпиши строку: `grep nto rtf_objects.txt > answer.txt`.\n",
    "nto{rtf_0bj3ct_3xpl01t}",
    ["RTF может встраивать OLE-объекты (\\object, \\objdata).",
     "\\objupdate заставляет открыть объект — частый вектор.",
     "`grep nto rtf_objects.txt > answer.txt`."])

add("mem-registry-hives", "Практика: куст реестра из памяти",
    "mem_hives.txt",
    "offset,hive,key,value\n"
    "0x1A000,SYSTEM,ControlSet001\\Services\\LanmanServer,ok\n"
    "0x2C000,SOFTWARE,Microsoft\\Windows\\CurrentVersion\\Run,nto{m3m_r3g1stry_h1v3_c4rv3}\n"
    "0x3E000,SAM,Users\\000003E9,ok\n",
    "# Задача: восстановить куст реестра из дампа\n\n"
    "`mem_hives.txt` — найденные в дампе памяти смещения кустов реестра и их\n"
    "ключи. Один ключ — автозапуск с меткой.\n\n"
    "1. `cat mem_hives.txt` — просмотри кусты.\n"
    "2. Найди ключ Run с меткой.\n"
    "3. Выпиши строку: `grep nto mem_hives.txt > answer.txt`.\n",
    "nto{m3m_r3g1stry_h1v3_c4rv3}",
    ["Кусты реестра можно вырезать прямо из дампа памяти (volatility/редактор).",
     "Ключ ...\\CurrentVersion\\Run — автозапуск.",
     "`grep nto mem_hives.txt > answer.txt`."])

add("net-ics-scada", "Практика: протокол Modbus/DNP3",
    "scada_protocol.log",
    "ts,src,dst,proto,func,unit\n"
    "2026-02-10T02:00:00,10.0.0.5,10.0.0.10,Modbus,READ_HOLDING,1\n"
    "2026-02-10T02:00:04,10.0.0.5,10.0.0.10,Modbus,WRITE_SINGLE,1\n"
    "2026-02-10T02:00:09,10.0.0.77,10.0.0.10,Modbus,WRITE_COIL,nto{sc4da_m0dbus_1ntrus10n}\n",
    "# Задача: найти вмешательство в SCADA-трафик\n\n"
    "`scada_protocol.log` — журнал промышленного протокола (Modbus): источник,\n"
    "назначение, функция, unit. Один запрос пришёл от постороннего узла.\n\n"
    "1. `cat scada_protocol.log` — просмотри трафик.\n"
    "2. Найди WRITE с чужого источника (10.0.0.77).\n"
    "3. Выпиши строку: `grep nto scada_protocol.log > answer.txt`.\n",
    "nto{sc4da_m0dbus_1ntrus10n}",
    ["Modbus-функции: READ_HOLDING, WRITE_COIL и т.д.",
     "Запись (WRITE) от узла вне доверенной подсети — вторжение.",
     "`grep nto scada_protocol.log > answer.txt`."])

add("forensics-cloud-serverless", "Практика: разбор Lambda-события",
    "lambda_invoke.log",
    "ts,function,invoker,status\n"
    "2026-02-10T11:00:00,resize-image,s3,ok\n"
    "2026-02-10T11:01:00,process-queue,sqs,ok\n"
    "2026-02-10T11:02:00,backup-db,unknown-invoker,ok  nto{s3rv3rl3ss_un4uth_1nv0k3}\n",
    "# Задача: найти несанкционированный вызов функции\n\n"
    "`lambda_invoke.log` — журнал вызовов serverless-функций: время, функция,\n"
    "источник вызова, статус. Один вызов пришёл от неизвестного источника.\n\n"
    "1. `cat lambda_invoke.log` — просмотри вызовы.\n"
    "2. Найди вызов с invoker=unknown-invoker.\n"
    "3. Выпиши строку: `grep nto lambda_invoke.log > answer.txt`.\n",
    "nto{s3rv3rl3ss_un4uth_1nv0k3}",
    ["Serverless-функции вызываются из известных сервисов (s3/sqs/…).",
     "invoker=unknown — несанкционированный вызов.",
     "`grep nto lambda_invoke.log > answer.txt`."])

# --- remaining generic-boilerplate labs -------------------------------------
add("forensics-ios-backup", "Практика: разбор iOS-бэкапа",
    "ios_backup_files.txt",
    "file_id,domain,relative_path,flags\n"
    "a1b2,AppDomain-com.apple.mail,Library/Mail/1.emlx,ok\n"
    "c3d4,CameraRoll,DCMI/100APPLE/IMG_0001.JPG,ok\n"
    "e5f6,AppDomain-com.example.stealer,Documents/config.plist,nto{1os_b4ckup_m4n1f3st_d4t4}\n"
    "g7h8,HomeDomain,Library/SMS/sms.db,ok\n",
    "# Задача: найти файл в структуре iOS-бэкапа\n\n"
    "`ios_backup_files.txt` — строки манифеста iOS-бэкапа (`Manifest.db`):\n"
    "file_id, домен приложения, путь, флаги. Одна запись — стороннее приложение.\n\n"
    "1. `cat ios_backup_files.txt` — просмотри записи манифеста.\n"
    "2. Найди домен приложения, которого нет на штатном iPhone.\n"
    "3. Выпиши строку с меткой: `grep nto ios_backup_files.txt > answer.txt`.\n",
    "nto{1os_b4ckup_m4n1f3st_d4t4}",
    ["iOS-бэкап — дерево файлов + манифест Manifest.db (file_id → domain/path).",
     "Домен вида `AppDomain-com.example.stealer` — стороннее приложение.",
     "`grep nto ios_backup_files.txt > answer.txt`."])

add("media-qr-barcode", "Практика: декодированные QR и штрихкоды",
    "qr_barcodes.txt",
    "format,value,source\n"
    "QR,https://example.com/promo,qr.png\n"
    "QR,https://example.com/pay?to=alice,qr.png\n"
    "QR,nto{qr_b4rc0d3_p4yl04d},qr.png\n"
    "Code128,INV-2026-0042,barcode.png\n",
    "# Задача: найти подозрительный QR-код\n\n"
    "`qr_barcodes.txt` — результат декодирования QR и штрихкодов с изображений\n"
    "(формат, значение, источник). Один QR несёт метку-полезную нагрузку.\n\n"
    "1. `cat qr_barcodes.txt` — просмотри декодированные значения.\n"
    "2. Найди QR с меткой.\n"
    "3. Выпиши строку: `grep nto qr_barcodes.txt > answer.txt`.\n",
    "nto{qr_b4rc0d3_p4yl04d}",
    ["QR/штрихкод декодируют в текст (zbarimg/сканер) и читают значение.",
     "Значение QR с меткой — цель.",
     "`grep nto qr_barcodes.txt > answer.txt`."])

add("web-oracle-db", "Практика: аудит Oracle",
    "oracle_audit.txt",
    "ts,user,action,object,status\n"
    "2026-02-10T04:00:00,APPUSER,SELECT,ORDERS,ok\n"
    "2026-02-10T04:05:00,APPUSER,SELECT,CUSTOMERS,ok\n"
    "2026-02-10T04:09:00,SCOTT,EXPORT DATA_PUMP,CUSTOMERS,ok  nto{or4cl3_4ud1t_d4t4_pump}\n"
    "2026-02-10T04:12:00,APPUSER,INSERT,ORDERS,ok\n",
    "# Задача: найти выгрузку данных в аудит-логе Oracle\n\n"
    "`oracle_audit.txt` — записи аудита Oracle СУБД: время, пользователь,\n"
    "действие, объект, статус. Одно действие — массовый экспорт.\n\n"
    "1. `cat oracle_audit.txt` — просмотри аудит.\n"
    "2. Найди действие EXPORT DATA_PUMP с меткой.\n"
    "3. Выпиши строку: `grep nto oracle_audit.txt > answer.txt`.\n",
    "nto{or4cl3_4ud1t_d4t4_pump}",
    ["Аудит Oracle (unified audit) логирует действия над объектами.",
     "DATA_PUMP export привилегированного пользователя — след выгрузки.",
     "`grep nto oracle_audit.txt > answer.txt`."])

add("mobile-android-notifications", "Практика: журнал уведомлений Android",
    "android_notifications.txt",
    "ts,package,title,text\n"
    "2026-02-10T08:00:00,com.android.messaging,Anna,See you at 6\n"
    "2026-02-10T08:01:00,com.example.game,Game,Level up!\n"
    "2026-02-10T08:02:00,com.unknown.stealer,OTP,nto{andr01d_n0t1f1c4t10n_l34k}\n",
    "# Задача: найти уведомление подозрительного приложения\n\n"
    "`android_notifications.txt` — журнал уведомлений Android: время, пакет,\n"
    "заголовок, текст. Одно уведомление пришло от неизвестного пакета и содержит\n"
    "код.\n\n"
    "1. `cat android_notifications.txt` — просмотри уведомления.\n"
    "2. Найди уведомление от пакета `com.unknown.*`.\n"
    "3. Выпиши строку с меткой: `grep nto android_notifications.txt > answer.txt`.\n",
    "nto{andr01d_n0t1f1c4t10n_l34k}",
    ["Android хранит уведомления в системной БД с пакетом-источником.",
     "Пакет com.unknown.* с OTP — кража кодов.",
     "`grep nto android_notifications.txt > answer.txt`."])

add("mobile-ios-keychain-deep", "Практика: элементы iOS Keychain",
    "ios_keychain_items.txt",
    "class,service,account,accessible\n"
    "genp,com.example.app,user@example.com,whenUnlocked\n"
    "inet,example.com,alice,afterFirstUnlock\n"
    "genp,com.unknown.stealer,nto{1os_k3ych41n_g3n3r1c_p4ssw0rd},always\n"
    "cert,Apple Push,aps,whenUnlocked\n",
    "# Задача: найти утечку в Keychain\n\n"
    "`ios_keychain_items.txt` — элементы Keychain: класс, сервис, аккаунт,\n"
    "уровень доступности. Один элемент с подозрительным сервисом и слабой\n"
    "защитой.\n\n"
    "1. `cat ios_keychain_items.txt` — просмотри элементы.\n"
    "2. Найди элемент с `accessible=always` и меткой.\n"
    "3. Выпиши строку: `grep nto ios_keychain_items.txt > answer.txt`.\n",
    "nto{1os_k3ych41n_g3n3r1c_p4ssw0rd}",
    ["Keychain хранит пароли/ключи; класс genp = generic password.",
     "accessible=always — секрет доступен даже при заблокированном экране.",
     "`grep nto ios_keychain_items.txt > answer.txt`."])

add("mobile-ios-location", "Практика: история геолокации iOS",
    "ios_location.txt",
    "ts,lat,lon,accuracy_m,source\n"
    "2026-02-10T08:00:00,55.7512,37.6180,10,gps\n"
    "2026-02-10T09:00:00,55.7520,37.6190,12,gps\n"
    "2026-02-10T10:00:00,55.7531,37.6205,9999,nto{1os_l0c4t10n_h1st0ry_p1n}\n"
    "2026-02-10T11:00:00,55.7540,37.6220,8,gps\n",
    "# Задача: найти аномальную запись геолокации\n\n"
    "`ios_location.txt` — история геолокации из iOS (significant locations):\n"
    "время, координаты, точность, источник. Одна запись с абсурдной точностью.\n\n"
    "1. `cat ios_location.txt` — просмотри трек.\n"
    "2. Найди запись с accuracy=9999 и меткой.\n"
    "3. Выпиши строку: `grep nto ios_location.txt > answer.txt`.\n",
    "nto{1os_l0c4t10n_h1st0ry_p1n}",
    ["iOS хранит историю значимых мест в своей БД.",
     "accuracy в метрах; 9999 — подделка/сбой.",
     "`grep nto ios_location.txt > answer.txt`."])

# ---------------------------------------------------------------------------
def patch_lesson(slug, spec):
    # locate lesson file by exact id
    path = None
    for root, _dirs, files in os.walk(CONTENT):
        for fn in files:
            if not fn.endswith(".md"):
                continue
            p = os.path.join(root, fn)
            txt = open(p, encoding="utf-8", errors="replace").read()
            m = re.search(r'^id:\s*["\']?([^"\'\n]+)', txt, re.M)
            if m and m.group(1).strip() == slug:
                path = p
                break
        if path:
            break
    if not path:
        return None
    txt = open(path, encoding="utf-8").read()
    art_name = spec["art"][0]
    hints = "\n".join(f"    - {json.dumps(h, ensure_ascii=False)}" for h in spec["hints"])
    block = (
        "lab:\n"
        "  kind: shell\n"
        f"  title: {json.dumps(spec['title'], ensure_ascii=False)}\n"
        "  toolset: [core, grep]\n"
        "  workdir: /home/student/task\n"
        f"  files: [task.md, {art_name}]\n"
        "  check: 'grep -q ''nto{'' answer.txt'\n"
        "  hints:\n" + hints + "\n"
    )
    m = re.search(r'^lab:\n(?:[ \t]+.*\n)*', txt, re.M)
    if not m:
        return None
    txt = txt[:m.start()] + block + txt[m.end():]
    open(path, "w", encoding="utf-8").write(txt)
    # bundle
    bundle = {
        "id": slug,
        "workdir": "/home/student/task",
        "hostname": "lab",
        "expect": {"file": "/home/student/task/answer.txt", "contains": spec["flag"]},
        "fs": [
            {"path": "/home/student/task", "type": "dir"},
            {"path": "/home/student/task/task.md", "text": spec["task"], "mode": "644"},
            {"path": "/home/student/task/" + art_name, "text": spec["art"][1], "mode": "644"},
        ],
    }
    bp = os.path.join(CONTENT, "labs", slug + ".json")
    with open(bp, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


def main():
    only = sys.argv[1:]
    done = []
    for slug, spec in LABS.items():
        if only and slug not in only:
            continue
        p = patch_lesson(slug, spec)
        if p:
            done.append(slug)
        else:
            print("MISS", slug, file=sys.stderr)
    print(f"patched {len(done)}: {', '.join(done)}")


if __name__ == "__main__":
    main()
