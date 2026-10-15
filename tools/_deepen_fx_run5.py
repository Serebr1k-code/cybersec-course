#!/usr/bin/env python3
"""Top-up pass for two lessons that fell under 1200 after dedupe."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["macos-apple-silicon"] = """## Unified log и трассировка на Apple Silicon

Системный журнал macOS (`unified log`) — главный источник событий на современном Mac, и
на Apple Silicon он особенно важен, потому что многие традиционные артефакты (например,
старые `.plist`-логи) ушли. Читать его нужно через `log`:

```
$ log show --last 2h --predicate 'process == "sshd"' | head
$ log show --start "2026-01-14 03:00:00" --end "2026-01-14 04:00:00" > window.log
$ log collect --output case.logarchive --last 1d
```

`log collect` создаёт `.logarchive`, который можно анализировать офлайн. Обрати внимание:
журнал хранится ограниченное время и сжимается, поэтому для инцидента его нужно выгружать
**сразу**. На arm64 события трансляции Rosetta и работы SEP тоже попадают сюда — по ним
видно, что запускалось и когда.

## Сбор памяти: инструменты и ограничения arm64

Дамп памяти на Apple Silicon снимают только с живой системы и только при ослабленном SIP.
Инструменты должны поддерживать arm64 — Intel-бинарники через Rosetta не смогут читать
физическую память. Что важно помнить:

- порядок структур ядра (KASLR, `kernel_task`) отличается от Intel;
- плагины Volatility для macOS часто завязаны на x86 — проверяй совместимость;
- ключи FileVault и session keys живут в памяти до выключения — дамп нужно снять раньше;
- на M-серии адресное пространство единое, поэтому «градация» CPU/GPU-памяти иная.

Если собрать память нельзя, максимум извлекают из `logarchive`, APFS-снапшотов и
пользовательских артефактов — но ключи из SEP это не даст."""

ADDS["net-arp-mac"] = """## ARP в виртуальных сетях и контейнерах

Большая часть современной инфраструктуры виртуализирована, и это меняет картину ARP:

- **Docker** использует bridge-сеть `172.17.0.0/16` с MAC `02:42:ac:11:xx:xx` — по
  префиксу `02:42:ac:11` сразу видно контейнер;
- **KVM/QEMU** даёт гостям MAC с OUI `52:54:00`;
- **VMware** — `00:0c:29`, **VirtualBox** — `08:00:27`, **Hyper-V** — `00:15:5d`;
- **VXLAN/EVPN** инкапсулирует ARP, и на физическом коммутаторе он уже не виден.

Для форензики это значит: незнакомый MAC — не всегда «атакующий», часто это просто
виртуалка. Сверяй OUI с известными префиксами гипервизоров, прежде чем делать вывод.

## Практика: построение карты сегмента

Соберём полную карту «IP ↔ MAC ↔ вендор» из дампа:

```
$ tshark -r capture.pcap -Y 'arp.opcode==2' -T fields \\
    -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort -u > map.tsv
$ while IFS=$'\\t' read ip mac; do
    oui=$(echo "$mac" | tr -d ':' | cut -c1-6 | tr 'A-Z' 'a-z')
    vendor=$(grep -i "^$oui" /usr/share/nmap/nmap-mac-prefixes | cut -d' ' -f2-)
    echo "$ip  $mac  ${vendor:-unknown}"
  done < map.tsv
```

На выходе — таблица, по которой сразу видно аномалии: два MAC на один IP, MAC неизвестного
вендора на месте шлюза, «локально администрируемый» MAC у устройства, которое должно быть
заводским. Именно такие расхождения и указывают на спуфинг или на скрытый хост в сегменте."""

def main() -> int:
    base = "content/forensics/"
    for lid, add in ADDS.items():
        path = base + lid + ".md"
        s = open(path, encoding="utf-8").read()
        m = re.search(r"^## Квиз\s*$", s, re.MULTILINE)
        if not m:
            print("SKIP (no quiz):", lid); continue
        out = s[:m.start()] + add + "\n\n" + s[m.start():]
        open(path, "w", encoding="utf-8").write(out)
        print("topped", lid, "+", len(add.split()), "tokens")
    return 0

if __name__ == "__main__":
    sys.exit(main())
