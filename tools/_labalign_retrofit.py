#!/usr/bin/env python3
"""One-shot retrofit: chain a prerequisite sub-step into the first batch of
network labs (rule: lab = lesson + reminder of the path, docs/LABS.md).

For each lesson id it (1) appends a `## Повторение (`<prereq-id>`)` step to the
bundle's task.md text and (2) prepends a matching hint to the lesson front-matter.
Only additive edits; bundle JSON formatting is preserved by string-replacing the
escaped task.md value.
"""
import json
import os
import re
import sys

# id -> (prereq-id referenced, appended task.md block, new hint line)
EDITS = {
    "network-ntcip": (
        "network-snmp",
        "\n## Повторение (`network-snmp`)\n\n"
        "Прежде чем искать секрет, вспомни разбор SNMP-walk из `network-snmp`: "
        "вывод — это пары `OID = значение`. Отдели объекты MIB от служебных строк:\n\n"
        "    grep '=' snmpwalk.txt | head\n\n"
        "Так видно, какие ветки OID опрошены (`1.3.6.1.4.1.1206` — enterprise NTCIP), "
        "и что `community = public` стоит рядом с ответами устройства.\n",
        "Повторение (`network-snmp`): SNMP-walk — пары `OID = значение`; сначала "
        "`grep '=' snmpwalk.txt | head`, чтобы отделить MIB-объекты от служебных строк.",
    ),
    "network-zeek": (
        "network-tcpdump",
        "\n## Повторение (`network-tcpdump`)\n\n"
        "Zeek-лог — тот же трафик, что ты разбирал в `network-tcpdump`, только уже "
        "структурированный. Вспомни направление потока (кто клиент, кто сервер) и "
        "посмотри шапку соединений:\n\n"
        "    head -n 5 conn.log\n\n"
        "Поля `id.orig_h` (источник) и `id.resp_h` (назначение) — те же src/dst, "
        "что и в выводе tcpdump.\n",
        "Повторение (`network-tcpdump`): Zeek-лог — структурированный трафик; "
        "сначала `head -n 5 conn.log` и вспомни направление потока (orig_h/resp_h).",
    ),
    "network-ids-suricata": (
        "network-zeek",
        "\n## Повторение (`network-zeek`)\n\n"
        "`fast.log` Suricata — однострочный журнал алертов, как `notice.log` в "
        "`network-zeek`. Сначала посмотри формат строки (время, 5-tuple, сигнатура):\n\n"
        "    head -n 3 fast.log\n\n"
        "Первый адрес в 5-tuple — источник, второй — цель.\n",
        "Повторение (`network-zeek`): сначала `head -n 3 fast.log` — как в zeek "
        "`notice.log`, строка это время + 5-tuple + сигнатура.",
    ),
    "network-dns-tunnel": (
        "network-dns-attacks",
        "\n## Повторение (`network-dns-attacks`)\n\n"
        "Анатомия DNS-запроса разбиралась в `network-dns-attacks`: слева — метки "
        "поддомена, справа — зона. Посмотри на первую метку запросов:\n\n"
        "    cut -d' ' -f1 queries.log | head\n\n"
        "Аномально длинная первая метка = данные, а общий «хвост» всех таких "
        "запросов — это зона туннеля.\n",
        "Повторение (`network-dns-attacks`): слева метки поддомена, справа зона; "
        "`cut -d' ' -f1 queries.log | head` — длинная метка = данные.",
    ),
    "network-lin-bus": (
        "network-can-bus",
        "\n## Повторение (`network-can-bus`)\n\n"
        "Кадр шины — это `ID` + `data`, как в `network-can-bus`. Сначала выпиши, "
        "какие ID вообще встречаются в логе:\n\n"
        "    grep 0x lin.log | head\n\n"
        "Сравни с schedule table мастера — так сразу виден кадр «вне расписания».\n",
        "Повторение (`network-can-bus`): кадр = `ID` + `data`; сначала "
        "`grep 0x lin.log | head` и сверь ID со schedule table.",
    ),
    "network-uds": (
        "network-can-bus",
        "\n## Повторение (`network-can-bus`)\n\n"
        "UDS ходит поверх шины, и кадр здесь тоже `ID` + `payload` (как в "
        "`network-can-bus`). Сначала посмотри, между какими ID идёт обмен:\n\n"
        "    grep TX uds.log | head\n\n"
        "`[TX]` — запрос сканера, `[RX]` — ответ ECU; направление отличай по префиксу.\n",
        "Повторение (`network-can-bus`): кадр = `ID` + `payload`; "
        "`grep TX uds.log | head` — `[TX]` запрос сканера, `[RX]` ответ ECU.",
    ),
    "network-rtsp-onvif": (
        "network-http1-deep",
        "\n## Повторение (`network-http1-deep`)\n\n"
        "RTSP — HTTP-подобный протокол из `network-http1-deep`: стартовая строка "
        "`МЕТОД URI RTSP/1.0`, затем заголовки `Имя: значение`. Убедись, что "
        "узнаёшь структуру:\n\n"
        "    head -n 8 rtsp-trace.txt\n\n"
        "Методы OPTIONS/DESCRIBE и заголовок `Content-Length` — те же, что и в HTTP.\n",
        "Повторение (`network-http1-deep`): RTSP — HTTP-подобный; "
        "`head -n 8 rtsp-trace.txt`, стартовая строка + заголовки `Имя: значение`.",
    ),
    "network-radius-protocol": (
        "network-module-access-aaa",
        "\n## Повторение (`network-module-access-aaa`)\n\n"
        "RADIUS — протокол AAA (Authentication, Authorization, Accounting) из модуля "
        "`network-module-access-aaa`. Каждый атрибут ответа — пара `Type = Value`. "
        "Посмотри список атрибутов Access-Accept:\n\n"
        "    head -n 8 radius.log\n\n"
        "`Reply-Message` — обычный текстовый атрибут, его значение здесь в base64.\n",
        "Повторение (`network-module-access-aaa`): RADIUS — протокол AAA, атрибут = "
        "`Type = Value`; `head -n 8 radius.log`, `Reply-Message` — текстовый атрибут.",
    ),
}


def patch_bundle(lid, block):
    path = f"content/labs/{lid}.json"
    raw = open(path, encoding="utf-8").read()
    b = json.loads(raw)
    entry = None
    for e in b.get("fs", []):
        if str(e.get("path", "")).endswith("task.md"):
            entry = e
            break
    if entry is None:
        print(f"  !! {lid}: no task.md in bundle")
        return False
    old = entry.get("text", "")
    if "## Повторение" in old:
        print(f"  -- {lid}: task.md already has Повторение, skipping")
        return False
    new = old + block
    old_esc = json.dumps(old, ensure_ascii=False)[1:-1]
    new_esc = json.dumps(new, ensure_ascii=False)[1:-1]
    if old_esc not in raw:
        print(f"  !! {lid}: escaped task.md text not found verbatim")
        return False
    raw = raw.replace(old_esc, new_esc, 1)
    json.loads(raw)  # validate
    open(path, "w", encoding="utf-8").write(raw)
    return True


def patch_hint(lid, hint):
    path = f"content/network/{lid}.md"
    raw = open(path, encoding="utf-8").read()
    if "Повторение (`" in raw:
        print(f"  -- {lid}: lesson already has a Повторение hint")
        return False
    m = re.search(r"^(\s*)hints:\s*$", raw, re.M)
    if not m:
        print(f"  !! {lid}: no hints: block in front-matter")
        return False
    indent = m.group(1) + "  "
    ins = f"{indent}- {json.dumps(hint, ensure_ascii=False)}\n"
    pos = m.end() + 1
    raw = raw[:pos] + ins + raw[pos:]
    open(path, "w", encoding="utf-8").write(raw)
    return True


def main():
    ok = 0
    for lid, (prereq, block, hint) in EDITS.items():
        if not os.path.exists(f"content/labs/{lid}.json"):
            print(f"  !! {lid}: bundle missing")
            continue
        a = patch_bundle(lid, block)
        b = patch_hint(lid, hint)
        if a and b:
            ok += 1
            print(f"  ok {lid} <- {prereq}")
    print(f"patched {ok}/{len(EDITS)}")


if __name__ == "__main__":
    main()
