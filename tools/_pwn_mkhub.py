#!/usr/bin/env python3
"""Generate short 'module' roadmap hub lessons for the pwn tree.

Hubs are navigation modules (title starts with 'Модуль:'), which the
thin-lessons auditor intentionally skips. They only need valid front-matter,
a handful of '## ' sections, a fenced quiz and '## Где пригодится'.
"""
import os

HUBS = {
    "pwn-linux-user-cve": dict(
        title="Linux user-space CVE",
        parent="pwn-cve-exploitation",
        order=1,
        prereq="pwn-nday",
        covers="локальное повышение привилегий через ошибки в setuid-программах и загрузчике",
        bullets=[
            "`sudo` (Baron Samedit) — переполнение кучи в парсере аргументов.",
            "`pkexec` (PwnKit) — выход за границы массива `argv`.",
            "Ядро памяти (Dirty COW) — гонка в copy-on-write.",
            "`ld.so` (Looney Tunables) — переполнение в парсере `GLIBC_TUNABLES`.",
        ],
        why="User-space идёт первым: меньше переменных, воспроизводимость почти 100%, не нужен спрей кучи ядра.",
        can=["Определять уязвимую версию по строке и патчу.", "Собирать минимальный PoC и читать результат обратно."],
        q=[
            ("Что объединяет эти четыре CVE?", ["Все требуют доступа к ядру", "Все дают локальный root без эксплуатации памяти ядра", "Все сетевые", "Все в Windows"], 1, "Это user-space уязвимости локального повышения привилегий."),
            ("Почему user-space разбирают раньше kernel?", ["Он быстрее", "Меньше переменных и выше воспроизводимость", "Не нужен shell", "Не нужен root"], 1, "User-space эксплойты проще отлаживать и стабилизировать."),
            ("Что общего у Baron Samedit и Looney Tunables?", ["Гонка", "Загрузка подложенной библиотеки", "Сетевой парсинг", "SQL"], 1, "Оба в итоге заставляют привилегированный процесс загрузить нашу .so."),
        ],
        where=["Повышение привилегий на Linux-хостах.", "Разбор публичных PoC для setuid-программ.", "Аудит загрузчика и setuid-кода."],
    ),
    "pwn-linux-kernel-cve": dict(
        title="Linux kernel CVE",
        parent="pwn-cve-exploitation",
        order=2,
        prereq="pwn-kernel-core",
        covers="эксплуатацию уязвимостей ядра Linux: netfilter, nf_tables, io_uring и свежие гонки",
        bullets=[
            "nf_tables — CVE-2023-32233 и CVE-2024-1086.",
            "netfilter — CVE-2022-0185 и CVE-2022-2588.",
            "io_uring — серия уязвимостей асинхронного ввода-вывода.",
            "Сводка свежих kernel CVE и методология kernelCTF.",
        ],
        why="Kernel идёт после user-space: нужны спрей кучи, обход KASLR и понимание аллокаторов ядра из предыдущих уроков.",
        can=["Собирать kernel-эксплойт из примитива UAF/переполнения.", "Стабилизировать через modprobe_path и обход KASLR."],
        q=[
            ("Что нужно для kernel-эксплойта помимо примитива?", ["Только shell", "Спрей кучи и обход KASLR", "Только сеть", "Только пароль"], 1, "Примитив бесполезен без раскладки памяти и знания адресов."),
            ("Какой подсистеме посвящён CVE-2024-1086?", ["netfilter/nf_tables", "USB", "Wi-Fi", "Блочный слой"], 0, "CVE-2024-1086 — use-after-free в nf_tables."),
            ("Зачем в kernel-эксплойте modprobe_path?", ["Для сети", "Как цель перезаписи для выполнения команды от root", "Для шифрования", "Для логов"], 1, "Перезапись modprobe_path — популярный способ получить root-выполнение."),
        ],
        where=["Локальное повышение привилегий до root на Linux.", "Эксплуатация n-day в ядре.", "Подготовка к kernelCTF."],
    ),
    "pwn-windows-cve": dict(
        title="Windows CVE",
        parent="pwn-cve-exploitation",
        order=3,
        prereq="pwn-windows-intro",
        covers="известные уязвимости Windows: сетевые (SMB, Kerberos) и локальные (CLFS, драйверы)",
        bullets=[
            "CLFS и PrintNightmare — локальное повышение привилегий.",
            "EternalBlue (MS17-010) — удалённый код через SMBv1.",
            "Zerologon (CVE-2020-1472) — обход аутентификации в Netlogon.",
        ],
        why="Windows-блок требует понимания PE, SMB и Kerberos, поэтому идёт после соответствующей подготовки.",
        can=["Отличать сетевой RCE от локального EoP.", "Применять публичные эксплойты с учётом версии патча."],
        q=[
            ("Что делает Zerologon?", ["Шифрует диск", "Обходит аутентификацию Netlogon", "Ставит обновление", "Пишет в реестр"], 1, "CVE-2020-1472 позволяет сбросить пароль DC без аутентификации."),
            ("EternalBlue эксплуатирует протокол...", ["Kerberos", "SMBv1", "HTTP", "LDAP"], 1, "MS17-010 — переполнение в SMBv1."),
            ("PrintNightmare относится к классу...", ["Удалённый DoS", "Локальное/удалённое повышение привилегий через Spooler", "XSS", "SQLi"], 1, "Печально известный баг в Windows Print Spooler."),
        ],
        where=["Локальное и сетевое повышение привилегий в Windows.", "Red team в AD-сетях.", "Разбор патчей Windows."],
    ),
    "pwn-container-cve": dict(
        title="Container escape CVE",
        parent="pwn-cve-exploitation",
        order=4,
        prereq="pwn-sandbox-escape",
        covers="побег из контейнеров и оркестраторов через известные уязвимости ядра и runtime",
        bullets=[
            "overlayfs (CVE-2021-3493 / CVE-2023-0386) — повышение привилегий и побег.",
            "runc/Docker escape CVE — обход изоляции runtime.",
            "Kubernetes escape CVE — от пода к ноде.",
        ],
        why="Контейнеры добавляют изоляцию namespaces/cgroups; их баги рассматриваются последними, опираясь на kernel-эксплуатацию.",
        can=["Оценивать, ограничивает ли контейнер вектор.", "Планировать побег из пода к хосту."],
        q=[
            ("Что эксплуатирует CVE-2021-3493?", ["SMB", "overlayfs в Ubuntu-ядре", "Kerberos", "DNS"], 1, "Баг в overlayfs-патче Ubuntu давал root."),
            ("Побег из контейнера обычно ведёт...", ["К хосту", "К другому контейнеру", "В интернет", "К базе"], 0, "Цель побега — получить доступ к хосту-ноде."),
            ("Что нужно проверить прежде всего для побега?", ["Пароль", "Возможности (capabilities) и общие mount'ы", "Версию браузера", "Логи"], 1, "Capabilities и shared mounts определяют доступные примитивы."),
        ],
        where=["Пентест контейнерных сред.", "Побег из пода Kubernetes.", "Оценка риска устаревшего ядра в контейнерах."],
    ),
}

TEMPLATE = '''---
id: {id}
title: "Модуль: {title}"
category: pwn
parent: {parent}
difficulty: medium
order: {order}
tags: [pwn, module, roadmap, cve]
prerequisites: [{prereq}]
useful_for:
  - "Эксплуатация реальных CVE"
  - "Red team: повышение привилегий"
estimated_minutes: 10
summary: "Навигационный модуль: {covers}."
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «{title}»: {covers}.

{bullets}

## Почему такой порядок

{why}

## Что вы сможете после этапа

{can}

## Квиз

Проверь себя.

```quiz
{quiz}```

## Где пригодится

{where}
'''


def bullet_block(items):
    return "\n".join(f"- {x}" for x in items)


def can_block(items):
    return "\n".join(f"- {x}" for x in items)


def where_block(items):
    return "\n".join(f"- {x}" for x in items)


def quiz_block(qs):
    out = []
    for question, options, ans, expl in qs:
        out.append(f"- question: {question}")
        out.append("  options:")
        for o in options:
            out.append(f'    - "{o}"')
        out.append(f"  answer: {ans}")
        out.append(f"  explanation: {expl}")
    return "\n".join(out) + "\n"


def main():
    base = "content/pwn"
    for hid, spec in HUBS.items():
        path = os.path.join(base, hid + ".md")
        if os.path.exists(path):
            print("skip existing", path)
            continue
        text = TEMPLATE.format(
            id=hid, title=spec["title"], parent=spec["parent"], order=spec["order"],
            prereq=spec["prereq"], covers=spec["covers"],
            bullets=bullet_block(spec["bullets"]),
            why=spec["why"], can=can_block(spec["can"]),
            quiz=quiz_block(spec["q"]),
            where=where_block(spec["where"]),
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        print("wrote", path)


if __name__ == "__main__":
    main()
