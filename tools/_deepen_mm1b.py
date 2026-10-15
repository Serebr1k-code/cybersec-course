#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Second additive pass for the mm1 slice lessons still under 1200 real words."""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARK = "<!-- deepen-mm1b -->"

ADD = {}

ADD['mobile-frida-detection'] = r"""
## Как отличить anti-debug от anti-Frida

Проверки бывают нацелены на разные инструменты, и обход у них разный. Прежде чем что-то
хукать, определите, что именно сработало:

| Признак в поведении | Что ищут | Что делать |
|---------------------|----------|-----------|
| Приложение падает сразу после `attach` | отладчик, `ptrace` | `spawn`, хук `ptrace` |
| Падает при `frida -U -n` | процесс/порт Frida | сменить порт, gadget |
| Работает, но функции пусты | серверный детект | подменить запрос |
| Падает через пару секунд | тайминги | хук времени, меньше хуков |

Отладчик (`ptrace`) и Frida оставляют разные следы: первый виден по `TracerPid`, вторая —
по строкам `frida`/`gum` в памяти и по нестандартному потоку. Разделяя эти случаи, вы не
тратите время на обход того, чего приложение не проверяет.
"""

ADD['mobile-ios-urlscheme'] = r"""
## Что видно в Info.plist и как это читать

Схемы и их роли объявлены в `Info.plist` внутри IPA. Читать удобнее через `plutil`:

```bash
$ unzip -o app.ipa -d ipa
$ plutil -p ipa/Payload/DemoApp.app/Info.plist | grep -A4 CFBundleURLTypes
```

В `CFBundleURLSchemes` перечислены схемы приложения, а `CFBundleURLName` — логическое имя.
Если рядом стоит `LSApplicationQueriesSchemes`, приложение ещё и проверяет наличие других
программ — иногда это утечка списка установленного. Читая plist, вы сразу получаете список
точек входа для `simctl openurl`, не угадывая схемы наугад.
"""

ADD['mobile-notifications'] = r"""
## Локальные уведомления и их подделка

Не все уведомления приходят из сети: приложение может создать **локальное** уведомление
само (`UNUserNotificationCenter` на iOS, `NotificationManager` на Android). Это отдельный
вектор: если текст или deep link локального уведомления зависит от данных, полученных
извне (например, из ответа API), атакующий влияет на то, что увидит и куда нажмёт
пользователь. Проверяйте, кто формирует текст и цель перехода: доверенное значение из
кода или подставляемое извне. Подделанное уведомление выглядит «как настоящее», потому
что исходит от самого приложения, и потому особенно опасно для фишинга.
"""

ADD['mobile-android-cleartext'] = r"""
## Частые вопросы по cleartext

**Если `usesCleartextTraffic=false`, HTTP точно не пойдёт?** Нет: WebView с
`MIXED_CONTENT_ALWAYS_ALLOW` или нативный сокет обходят этот флаг.

**Хватит ли `android:usesCleartextTraffic="true"` в манифесте, чтобы это была находка?**
Сам флаг — лишь разрешение; находкой он становится, когда в коде есть `http://`-адреса,
и трафик реально утекает.

**Почему на эмуляторе всё по HTTPS, а на устройстве — HTTP?** Приложение может
переключать базовый URL по сборке или по региону; проверяйте обе конфигурации.

**Как быстро найти проблему статически?** `grep -rn 'http://' out/sources` плюс разбор
`network_security_config.xml`; вместе они дают список доменов-исключений за минуту.
"""

ADD['misc-blockchain-tools'] = r"""
## Отладка через трассировку

Когда тест ведёт себя непонятно, помогает трассировка вызовов. Флаг `-vvvv` печатает
каждый вызов с аргументами, возвратом и записью в storage:

```bash
$ forge test --match-test testExploit -vvvv
```

В выводе ищите строки `emit` (события), `SSTORE` (запись в storage) и `CALL`/`DELEGATECALL`.
Именно по `SSTORE` видно, в какой момент и какое значение перезаписывается — это ключ к
пониманию эксплойта. Если транзакция «не проходит», добавьте `--debug` и выполните её
интерактивно: вы сможете шагать по opcodes и смотреть стек, как в отладчике. Для чужой
транзакции тот же результат даёт `cast run <hash> --rpc-url $ARCHIVE_RPC`.
"""

ADD['misc-regex'] = r"""
## Разбор одного лога целиком: пошагово

Возьмём строку из веб-лога и пройдём путь от «сырого» текста до структурированных данных:

```
10.0.0.5 - - [01/Mar/2026:04:11:31 +0000] "GET /admin?id=1 HTTP/1.1" 200 512
```

1. Начните с якоря времени: `\[([^\]]+)\]` — берёт всё между квадратными скобками.
2. Добавьте IP: `^(\S+)`.
3. Запрос: `"([^"]*)"` — всё между кавычками.
4. Код и размер: `\s(\d{3})\s(\d+)$`.

Итоговый шаблон:

```python
pat = re.compile(r'^(\S+).*?\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\d+)$')
```

Прогоняйте шаблон построчно и сразу проверяйте на нескольких строках, включая «битые»:
если лог содержит строку без кавычек, жадный `.*` «съест» лишнее. Пошаговое наращивание
шаблона и проверка на каждой итерации надёжнее, чем писать всё сразу.
"""

ADD['misc-git-forensics'] = r"""
## Работа с bare-репозиторием и объектами вне веток

Иногда на диске остаётся только `bare`-репозиторий (`project.git`) без рабочего дерева.
Он полностью пригоден для анализа:

```bash
$ git --git-dir=project.git log --all --oneline
$ git --git-dir=project.git cat-file -p HEAD
```

Объекты, не достижимые ни из одной ветки (после `filter-branch`, `rebase`, `gc`), лежат в
`lost-found` и в `refs/original`. Проверьте их отдельно:

```bash
$ git --git-dir=project.git fsck --unreachable
$ git --git-dir=project.git show <dangling-commit>
```

Даже если ветку удалили, объекты живут до следующего `gc` с `prune`. Поэтому «мы удалили
секрет и сделали force-push» почти никогда не означает, что секрет исчез из клона —
он остаётся в объектах до принудительной сборки мусора.
"""

ADD['misc-pwntools-bash'] = r"""
## Как не потерять соединение: retry и логирование

Сетевой сервис может разорвать соединение (таймаут, рестарт). Оберните логику в функцию
с повторными попытками и логируйте всё, что приходит:

```python
def solve_once(host, port):
    io = remote(host, port)
    io.recvuntil(b'? ')
    io.sendline(b'42')
    return io.recvall()

for attempt in range(3):
    try:
        print(solve_once(HOST, PORT))
        break
    except EOFError:
        print('retry', attempt)
```

`context.log_level = 'debug'` печатает каждый `send`/`recv` — незаменимо, когда скрипт
«работает локально, но не удалённо». Логируйте в файл (`io = remote(...)` с
перенаправлением через `tee`), чтобы после падения видеть последний обмен. И всегда
передавайте хост и порт аргументами: один и тот же скрипт тогда гоняется и против
`socat`-обёртки локально, и против реального сервиса.
"""


def find(lid: str):
    for cat in ("forensics", "mobile", "misc"):
        p = os.path.join(ROOT, "content", cat, lid + ".md")
        if os.path.exists(p):
            return p
    return None


def main() -> int:
    n = 0
    for lid, add in ADD.items():
        path = find(lid)
        if not path:
            print("MISSING", lid, file=sys.stderr)
            continue
        t = open(path, encoding="utf-8").read()
        if MARK in t:
            print("skip (already)", lid)
            continue
        m = re.search(r"^## Квиз\s*$", t, re.MULTILINE)
        if not m:
            print("NO QUIZ", lid, file=sys.stderr)
            continue
        block = MARK + "\n" + add.strip() + "\n\n"
        t = t[:m.start()] + block + t[m.start():]
        open(path, "w", encoding="utf-8").write(t)
        print("deepened", lid)
        n += 1
    print("done:", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
