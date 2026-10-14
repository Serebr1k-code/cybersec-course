#!/usr/bin/env python3
"""lab-fix-tools.py — add a tool-teaching section to lessons whose lab requires a
tool the lesson body never mentions (docs/LABS.md rule 1: "lab subset of lesson").

For each requested lesson id it:
  1. finds the specialized tools the lab invokes but the body never names;
  2. pulls the tool's REAL replay example/output from content/labs/<id>.json
     (so the worked example matches exactly what the student sees in the lab);
  3. sanitizes any leaked flag / hidden answer;
  4. inserts a `## Инструмент: <tool>` section (intro + flags + worked example)
     right before the lesson's `## Что мы теперь знаем` / `## Квиз` section.

Usage: python3 tools/lab-fix-tools.py <lesson-id> [<lesson-id> ...]
       python3 tools/lab-fix-tools.py --all-flagged [--category CAT]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# import lab-align by path (the module name has a dash)
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "labalign", os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab-align.py"))
labalign = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(labalign)

CONTENT = "content"

# tool -> (heading tail, intro paragraph, bullet list of key flags)
T = {
    "tshark": (
        "tshark: Wireshark в консоли",
        "`tshark` — это Wireshark без графики: он читает дамп (`-r файл.pcap`) и печатает "
        "ровно то, что ты попросишь. Главный инструмент, когда графической оболочки нет "
        "или разбор надо автоматизировать.",
        [
            "`-r <файл.pcap>` — читать дамп (без него tshark слушает живой интерфейс);",
            "`-nn` — не резолвить имена/порты: видно «как есть» и быстрее;",
            "`-Y '<фильтр>'` — display-фильтр, оставить только нужные пакеты (`http.request`, `dns`, `eapol`, `ospf`);",
            "`-T fields -e <поле>` — вместо сводки печатать значения полей (`-e ip.src -e tcp.dstport -e http.host`);",
            "`-q -z follow,tcp,ascii,N` — собрать TCP-поток номер N и показать его как текст.",
        ]),
    "objdump": (
        "objdump: дизассемблер",
        "`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему "
        "считают смещения буферов, находят вызовы и адреса — основа статического разбора.",
        [
            "`objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);",
            "`objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;",
            "`objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);",
            "в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.",
        ]),
    "readelf": (
        "readelf: разбор ELF",
        "`readelf` читает заголовки ELF-файла: архитектуру, тип, секции, сегменты и "
        "включённые защиты. С него начинается любой разбор нативного бинарника.",
        [
            "`readelf -h <файл>` — заголовок: класс (32/64), машина, точка входа;",
            "`readelf -S <файл>` — таблица секций (`.text`, `.plt`, `.got`, `.data`);",
            "`readelf -s <файл>` — таблица символов (как `nm`, но с секциями и типами);",
            "`readelf -l <файл>` — сегменты программы; ищи `GNU_STACK`/`GNU_RELRO`, чтобы понять защиты.",
        ]),
    "nm": (
        "nm: таблица символов",
        "`nm` перечисляет символы бинарника: имена функций и глобальных переменных с их "
        "адресами. Если символы не срезаны, это самый быстрый способ найти нужную функцию.",
        [
            "`nm <файл>` — все символы с адресами;",
            "`nm -C <файл>` — демутируй C++-имена (читаемые сигнатуры);",
            "`T`/`t` — код (глобальный/локальный), `R`/`r` — только чтение (`.rodata`), `D`/`B` — данные;",
            "нижний регистр = локальный символ, верхний = глобальный/экспортируемый.",
        ]),
    "whois": (
        "whois: регистрационные данные",
        "`whois` запрашивает регистрационные записи: домены, IP-блоки и автономные системы "
        "(AS). Незаменим, чтобы связать адрес или префикс с оператором.",
        [
            "`whois <домен>` — регистратор, даты, NS, контакты;",
            "`whois <IP>` — какой диапазон и организация владеют адресом;",
            "`whois AS<номер>` — данные автономной системы: имя, организация, маршруты;",
            "в BGP-задачах по `as-name`/`descr` видно, кто «увёл» префикс.",
        ]),
    "openssl": (
        "openssl: крипто-швейцарский нож",
        "`openssl` — консольный набор для шифрования, хеширования и работы с "
        "сертификатами. В лаборатории им проверяют алгоритм и параметры.",
        [
            "`openssl enc -d -aes-128-ecb -K <hex> -in <файл>` — расшифровать файл (режим и ключ — по задаче);",
            "`openssl enc -d -aes-128-cbc -K <hex> -iv <hex> -in <файл>` — CBC требует IV;",
            "`openssl x509 -in cert.pem -text -noout` — разобрать сертификат;",
            "`openssl dgst -sha256 <файл>` — посчитать хеш.",
        ]),
    "sqlite3": (
        "sqlite3: файл как база",
        "`sqlite3` открывает файл БД и даёт SQL-консоль. В мобильной/веб-форензике это "
        "первый инструмент: приложения хранят данные в SQLite.",
        [
            "`sqlite3 app.db` — открыть базу;",
            "`.tables` — список таблиц; `.schema <таблица>` — структура;",
            "`select * from <таблица>;` — вывести строки;",
            "`.dump` — весь дамп; `sqlite3 app.db \"select ...\"` — запрос одной командой.",
        ]),
    "sleuthkit": (
        "sleuthkit: разбор файловой системы",
        "Инструменты Sleuth Kit (`fls`, `icat`, `mactime`, `fsstat`) работают с образом "
        "диска напрямую, не монтируя его: перечисляют файлы и вытаскивают содержимое.",
        [
            "`fsstat image.dd` — параметры файловой системы;",
            "`fls -r image.dd` — рекурсивный список файлов (в т.ч. удалённых);",
            "`icat image.dd <inode>` — вытащить содержимое файла по inode;",
            "`mactime -b bodyfile` — построить таймлайн по MAC-временам.",
        ]),
    "cryptsetup": (
        "cryptsetup: LUKS и шифрование диска",
        "`cryptsetup` открывает и создаёт зашифрованные контейнеры (LUKS/dm-crypt). "
        "В лаборатории им вскрывают образ, зная пароль или найдя его.",
        [
            "`cryptsetup luksDump image.img` — заголовок LUKS: версия, слоты ключей;",
            "`cryptsetup open image.img name` — открыть контейнер как `/dev/mapper/name`;",
            "`cryptsetup close name` — закрыть;",
            "после `open` том монтируется обычным `mount`.",
        ]),
    "dig": (
        "dig: DNS-запросы",
        "`dig` шлёт DNS-запросы и показывает ответ целиком: записи, авторитетные серверы, "
        "флаги. Основной инструмент DNS-разведки.",
        [
            "`dig <имя>` — A-запись; `dig <имя> TXT` — текст (часто там секреты);",
            "`dig +short <имя> <тип>` — только значение, без «шапки»;",
            "`dig @<сервер> <имя>` — спросить конкретный резолвер;",
            "`dig axfr <домен> @<ns>` — попытка переноса зоны.",
        ]),
    "sqlmap": (
        "sqlmap: автоматизация SQL-инъекций",
        "`sqlmap` находит и эксплуатирует SQL-инъекции: определяет СУБД, извлекает данные, "
        "при удаче — выполняет команды. В лаборатории он разбирает сохранённый HTTP-запрос.",
        [
            "`sqlmap -r req.txt -p id` — тестировать параметр `id` из сохранённого запроса;",
            "`sqlmap -u '<url>' --batch` — без интерактива;",
            "`sqlmap -r req.txt --dbs` — перечислить базы; `--tables -D <db>` — таблицы;",
            "`--dump` — выгрузить данные таблицы.",
        ]),
    "binwalk": (
        "binwalk: поиск вложенных форматов",
        "`binwalk` ищет внутри файла сигнатуры других форматов — архивы, ФС, сжатые "
        "данные — и при необходимости извлекает их.",
        [
            "`binwalk firmware.bin` — сканировать на вложенные форматы;",
            "`binwalk -e firmware.bin` — извлечь найденное в `_firmware.bin.extracted/`;",
            "`binwalk -E firmware.bin` — энтропия (видно шифрование/сжатие);",
            "`binwalk -eM` — рекурсивное извлечение.",
        ]),
    "exiftool": (
        "exiftool: метаданные файлов",
        "`exiftool` показывает и правит метаданные: EXIF у фото, документов, "
        "мультимедиа. Часто там GPS, автор, ПО и скрытые поля.",
        [
            "`exiftool file.jpg` — все метаданные;",
            "`exiftool -a -u file.jpg` — включая дубликаты и неизвестные теги;",
            "`exiftool -gps:all file.jpg` — только GPS;",
            "`exiftool -Comment file` — конкретное поле.",
        ]),
    "gdb": (
        "gdb: отладчик",
        "`gdb` управляет исполнением программы: точки останова, пошаговое выполнение, "
        "просмотр регистров и памяти. Основной динамический инструмент.",
        [
            "`gdb ./prog` — открыть бинарник; `run` — запустить;",
            "`break <функция>` / `b *<адрес>` — точка останова;",
            "`info registers`, `x/16gx $rsp` — регистры и стек;",
            "`disassemble <функция>` — дизассемблер без выхода из отладчика.",
        ]),
    "ROPgadget": (
        "ROPgadget: поиск гаджетов",
        "`ROPgadget` ищет в бинарнике короткие последовательности инструкций, "
        "заканчивающиеся `ret` — строительные блоки ROP-цепочек.",
        [
            "`ROPgadget --binary ./prog` — все гаджеты;",
            "`ROPgadget --binary ./prog --only 'pop|ret'` — только нужные;",
            "`ROPgadget --binary ./prog | grep 'pop rdi'` — конкретный гаджет;",
            "`--ropchain` — автоматическая сборка цепочки (когда применимо).",
        ]),
    "googler": (
        "googler: поиск из консоли",
        "`googler` выполняет поисковые запросы из терминала и печатает результаты — "
        "удобно для OSINT без браузера и для операторов поиска.",
        [
            "`googler 'site:example.com filetype:pdf'` — операторы Google работают;",
            "`googler -n 20 'запрос'` — больше результатов;",
            "`googler --json 'запрос'` — машиночитаемый вывод;",
            "операторы (`site:`, `filetype:`, `intitle:`) — суть OSINT-разведки.",
        ]),
}

GENERIC = (
    "инструмент лаборатории",
    "Этот инструмент нужен для шага лаборатории — ниже рабочий пример с ним.",
    ["смотри `--help` инструмента;", "вывод ниже снят с реального окружения."],
)


def sanitize(text, expect_val):
    text = re.sub(r"nto\{[^}]*\}", "nto{…}", text)
    if expect_val:
        text = text.replace(expect_val, "…")
    return text


def best_case(tool_spec, expect_val):
    cases = tool_spec.get("cases") or []
    for c in cases:
        out = c.get("output", "")
        if "nto{" not in out and (not expect_val or expect_val not in out):
            return c
    return cases[0] if cases else None


def build_section(tool, bundle, lesson_title):
    heading, intro, flags = T.get(tool, GENERIC)
    heading = heading.replace(": ", " — ", 1)
    spec = (bundle.get("tools") or {}).get(tool) or {}
    expect_val = (bundle.get("expect") or {}).get("contains")
    ex = best_case(spec, expect_val)
    parts = [f"## Инструмент: {heading}", "", intro, "", "Ключи, которые пригодятся:"]
    parts += ["* " + b for b in flags]
    if ex:
        cmd = sanitize((ex.get("example") or "").strip(), expect_val)
        out = sanitize((ex.get("output") or "").rstrip("\n"), expect_val)
        parts += ["", "### Рабочий пример (как в лаборатории)", "",
                  "```", f"$ {tool} {cmd}".rstrip(), out, "```", ""]
        helpstr = (spec.get("help") or "").strip()
        if helpstr:
            parts.append(f"Подсказка из лаборатории: `{helpstr}`.")
    return "\n".join(parts) + "\n"


def insert_section(text, section):
    for anchor in ("\n## Что мы теперь знаем", "\n## Квиз"):
        i = text.find(anchor)
        if i != -1:
            return text[:i] + "\n" + section + text[i:]
    # fallback: append before trailing tail
    return text.rstrip() + "\n\n" + section


def fix_lesson(path, cat, lid):
    raw = open(path, encoding="utf-8", errors="replace").read()
    fm, body = labalign.parse_front(raw)
    lab = labalign.fm_lab_block(fm)
    if not lab.strip():
        return []
    bp = os.path.join(CONTENT, "labs", lid + ".json")
    if not os.path.exists(bp):
        return []
    bundle = json.load(open(bp, encoding="utf-8"))
    req = set((bundle.get("tools") or {}).keys())
    for e in bundle.get("fs", []):
        if str(e.get("path", "")).endswith("task.md"):
            req |= labalign.tools_in_commands(e.get("text", ""))
    req |= labalign.tools_in_commands(lab)
    missing = [t for t in sorted(req)
               if t in labalign.TOOL_PATTERNS and t not in labalign.BASIC
               and not labalign.mentioned(t, body)]
    if not missing:
        return []
    added = []
    new = raw
    for tool in missing:
        heading, _, _ = T.get(tool, GENERIC)
        heading = heading.replace(": ", " — ", 1)
        if f"## Инструмент: {heading}" in new:
            continue
        sec = build_section(tool, bundle, lid)
        new = insert_section(new, sec)
        added.append(tool)
    if added:
        open(path, "w", encoding="utf-8").write(new)
    return added


def flagged_ids(root, category):
    lessons = labalign.load_lessons(root, [category] if category else sorted(
        d for d in os.listdir(root)
        if os.path.isdir(os.path.join(root, d)) and not d.startswith((".", "_"))))
    labalign.enrich(lessons, root)
    out = []
    for lid, L in lessons.items():
        if not L["lab"].strip():
            continue
        req = L.get("req_tools", set())
        miss = [t for t in req if t in labalign.TOOL_PATTERNS
                and t not in labalign.BASIC and not labalign.mentioned(t, L["body"])]
        if miss:
            out.append((L["cat"], lid, L["path"]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--all-flagged", action="store_true")
    ap.add_argument("--category", default=None)
    args = ap.parse_args()

    if args.all_flagged:
        targets = flagged_ids(CONTENT, args.category)
    else:
        targets = []
        for lid in args.ids:
            for cat in sorted(os.listdir(CONTENT)):
                p = os.path.join(CONTENT, cat, lid + ".md")
                if os.path.exists(p):
                    targets.append((cat, lid, p))
                    break
    done = 0
    for cat, lid, path in targets:
        added = fix_lesson(path, cat, lid)
        if added:
            done += 1
            print(f"  {cat}/{lid}: +{added}")
    print(f"lessons patched: {done}")


if __name__ == "__main__":
    main()
