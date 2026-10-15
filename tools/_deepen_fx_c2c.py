#!/usr/bin/env python3
"""Batch C2c — third layer for cloud-storage, container-runtime, mal-script-js."""
from __future__ import annotations
import re, sys

ADDS = {}

ADDS["cloud-storage"] = r"""## Мини-чек-лист расследования

1. Собери server access logs и CloudTrail за период.
2. Построй топ клиентов по IP и User-Agent.
3. Найди `ListBucket` + массовые `GET` (эксфильтрация).
4. Проверь смену политик и создание ключей.
5. Проверь публичность бакета (`--no-sign-request`).
6. Восстанови удалённые версии, если нужно.
7. Сопоставь с прокси/приложением/VPC Flow Logs.
8. Зафиксируй выводы со ссылками на строки логов.

Этого набора достаточно для большинства дел об утечке из объектного хранилища."""

ADDS["forensics-cloud-container-runtime"] = r"""## Связанные атаки на оркестратор

Побег из контейнера — лишь один слой. Часто атакующий двигается через Kubernetes:

- **кража service account token** — `/var/run/secrets/kubernetes.io/serviceaccount/token`
  внутри пода; по нему — запросы к API;
- **злоупотребление RBAC** — если у роли широкие права (`cluster-admin`), токен даёт
  контроль над кластером;
- **доступ к etcd** — хранилище секретов кластера (порт 2379), часто без TLS;
- **admission/validating webhooks** — их подмена позволяет пропускать вредоносные поды;
- **kubelet API (10250)** — прямой запуск/exec в поды.

В расследовании проверяй не только рантайм, но и: какие токены были в поде, какие
RBAC-правила, был ли доступ к API-серверу, не создавались ли новые поды/секреты.
Хеш и версии kubelet/API-сервера — тоже часть картины.

## Мини-чек-лист расследования

1. Зафиксируй версии runc/containerd/kernel/Kubernetes.
2. Сверь хеши бинарников рантайма с эталоном пакета.
3. Проверь конфигурацию подозрительных подов (privileged, capabilities, mounts).
4. Найди процессы вне namespace и их cgroup.
5. Просмотри `journalctl -u containerd` и auditd на exec в runc.
6. Проверь service account tokens и RBAC-права.
7. Оцени применимость известных CVE по версиям.
8. Задокументируй каждый шаг командой и выводом.

Этот чек-лист покрывает и CVE-побеги, и конфигурационные пути, и движение по кластеру."""

ADDS["mal-script-js"] = r"""## Расшифровка PowerShell EncodedCommand на практике

Base64 в PowerShell — это UTF-16LE, а не ASCII. Правильная последовательность:

```
$ echo 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA' | base64 -d | iconv -f UTF-16LE -t UTF-8
IEX (New-Object Net.WebClient)
```

Частая ошибка — декодировать только Base64 и остановиться: получается «мусор» из-за
неверной кодировки. Добавь `iconv -f UTF-16LE`. Если строка декодируется в ещё одну
Base64-строку — декодируй повторно, пока не получишь осмысленный код. В отчёт
включай каждый слой отдельно: исходная строка → Base64 → UTF-16LE → текст команды.

## Мини-чек-лист разбора скрипта

1. Определи тип и язык (JS / PowerShell / shell / HTA).
2. Найди кодировки (Base64, hex, `[char]`, `unescape`).
3. Декодируй послойно, фиксируя каждый уровень.
4. Выпиши URL, IP, пути, имена файлов.
5. Найди функцию запуска (`IEX`, `eval`, `.Run`, `mshta`).
6. Восстанови цепочку: загрузчик → второй этап → действие.
7. Сформируй IOC и YARA-строки.
8. Задокументируй метод, не запуская образец.

Этого достаточно, чтобы безопасно разобрать типовой скриптовый загрузчик и описать
его в отчёте."""

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
        print("appended", lid)
    return 0

if __name__ == "__main__":
    sys.exit(main())
