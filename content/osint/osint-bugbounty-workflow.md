---
id: osint-bugbounty-workflow
title: "OSINT в bug bounty: scope, методология и автоматизация"
category: osint
parent: osint-workflow
difficulty: medium
order: 2
tags: [osint, bugbounty, workflow, scope, recon, automation]
prerequisites: [osint-collection]
useful_for:
  - "Bug bounty"
  - "Пентест"
  - "CTF категория OSINT"
estimated_minutes: 30
summary: "Как встроить OSINT в bug bounty: чтение scope, приоритизация активов, конвейер разведки, автоматизация и границы допустимого."
---
В bug bounty OSINT — это фундамент: именно разведка определяет, сколько вы найдёте. Программы платят за уязвимости на **in-scope** активах, поэтому задача разведки — расширить карту активов в рамках правил и приоритизировать их. Хорошо поставленный OSINT-конвейер отличает охотника, который находит баги регулярно, от того, кто «щупает» главную страницу.

## Теория: где OSINT в жизненном цикле bug bounty

Цикл: **scope → recon → enumeration → vuln discovery → exploitation → report**. OSINT занимает первые два этапа и частично третий:
- **scope** — понять, что разрешено (домены, поддомены, IP, мобильные приложения).
- **recon** — собрать все активы (поддомены, IP, технологии, люди).
- **enumeration** — понять, что на них работает.
- **vuln discovery** — сопоставить технологии с известными уязвимостями.

Принцип: **чем шире карта, тем больше поверхность** — но всё строго в рамках scope.

## Чтение scope

Scope-страница программы (HackerOne, Bugcrowd, YesWeHack) задаёт:
- **in-scope:** `*.example.com`, `api.example.com`, конкретные IP, мобильные приложения.
- **out-of-scope:** `marketing.example.com`, третьи стороны, соцсети.
- **правила:** запрет на DoS, авто-сканеры, социальную инженерию.

Критично: `*.example.com` **не** включает `example.com` в некоторых программах и **не** включает аффилированные домены (`example-cdn.net`). Всегда перечитывайте.

Практика: сохраните scope в файл и валидируйте каждый найденный актив:

```bash
# пример валидации поддомена по scope-паттерну
grep -E '\.example\.com$' all_subdomains.txt > in_scope.txt
```

## Конвейер разведки

Классический пассивно-активный конвейер:

```bash
# 1. Пассивные источники поддоменов
subfinder -d example.com -all -silent > subs.txt
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' \
  | sed 's/\*\.//g' | sort -u >> subs.txt
amass enum -passive -d example.com >> subs.txt

# 2. Дедупликация
sort -u subs.txt > subs_unique.txt

# 3. Проверка живости
httpx -l subs_unique.txt -silent -status-code -title -tech-detect -o live.txt

# 4. Скриншоты
gowitness file -f live.txt
```

`httpx` — сердце конвейера: он проверяет, какие хосты отвечают, и сразу снимает технологии. Флаги:

```bash
httpx -l subs.txt -sc -title -tech-detect -server -cdn -ip -cname -o live.txt
httpx -l subs.txt -ports 80,443,8080,8443 -sc -o ports.txt
```

## Приоритизация активов

Не все активы равны. Приоритет — по признакам «интересности»:

| Признак | Почему важно |
|---------|--------------|
| dev/staging/test | слабее защита, отладочные функции |
| admin/panel/internal | панели управления |
| api/graphql | бизнес-логика, IDOR |
| old/legacy | устаревший стек, CVE |
| auth/sso/login | аутентификация |
| файлы `.git`, `.env`, backup | утечки |

```bash
grep -iE 'dev|staging|test|admin|api|internal|old|legacy|uat|qa' live.txt | tee priority.txt
```

## Автоматизация и инструменты

Типовой набор охотника:

| Инструмент | Задача |
|-----------|--------|
| `subfinder`/`amass` | поддомены |
| `httpx` | проверка живости, технологии |
| `nuclei` | известные уязвимости по шаблонам |
| `katana`/`gau` | сбор URL (crawl + archive) |
| `ffuf`/`feroxbuster` | перебор путей |
| `dnsx` | DNS-запросы в масштабе |
| `notify` | уведомления о новых активах |
| `trufflehog`/`gitleaks` | секреты в репозиториях |

`gau` (GetAllUrls) собирает URL из архивов и Common Crawl:

```bash
gau example.com | sort -u > urls.txt
katana -u https://example.com -d 3 -silent >> urls.txt
```

`nuclei`:

```bash
nuclei -l live.txt -severity critical,high -silent -o findings.txt
```

## Разобранный пример: от scope к находке

Дано: программа `*.example.com`.

Шаг 1 — пассивный сбор:

```bash
subfinder -d example.com -all -silent | sort -u > subs.txt
wc -l subs.txt
# 312
```

Шаг 2 — живость и технологии:

```bash
httpx -l subs.txt -sc -title -tech-detect -silent | grep -v '000' | tee live.txt
```

Фрагмент:

```
https://dev.example.com [200] [Dev Portal] [nginx, React]
https://api.example.com [401] [API] [Express]
https://old.example.com [200] [Legacy] [Apache, PHP 5.6]
```

Шаг 3 — приоритизация: `old.example.com` на PHP 5.6 — устаревший, `dev.example.com` — среда разработки.

Шаг 4 — проверка `.git` и backup:

```bash
ffuf -u https://old.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,403 -t 50 -s | grep -iE 'git|backup|env|sql'
```

Шаг 5 — находка: открытый `/.git/config` → возможен дамп исходников → отдельный вектор.

Итог: из 312 поддоменов выделены приоритетные и найден первый кандидат.

## Границы и этика

- **Не выходите за scope.** Активы вне scope — не ваши, даже если уязвимы.
- **Не запускайте авто-сканеры, если запрещено.** Некоторые программы запрещают `nuclei`/`ffuf` без предупреждения.
- **Не тестируйте third-party.** CDN, SaaS-вендоры — обычно out-of-scope.
- **Не эксплуатируйте сверх PoC.** Минимальное доказательство, затем отчёт.
- **Не публикуйте без разрешения.** Соблюдайте disclosure policy.

## Ошибки и подводные камни

- **Игнорировать scope-правила.** Бан из программы — потеря доступа и репутации.
- **Сканировать только главную.** 90% находок — на поддоменах.
- **Забывать про мобильные приложения.** Часто в scope, но их не трогают.
- **Не проверять аффилированные домены.** Покупки/дочерние компании — золото.
- **Полагаться только на автоматизацию.** Ручная логика находит то, что не найдёт шаблон.
- **Не сохранять результаты.** Без истории вы пересканируете одно и то же.

## Что дальше / решение

Bug bounty-конвейер сводит все ветки OSINT в один процесс. Дальше: **CTF-рецепты** (`osint-ctf-recipes`) для игрового контекста, **AI-assisted** (`osint-ai-assisted`) для ускорения, **картирование поверхности атаки** (`osint-attack-surface`) для финальной карты. Итог: пассивный сбор → живость → приоритизация → ручная проверка → отчёт; соблюдение scope — обязательное условие.

## Полный автоматизированный конвейер

Сводим инструменты в один скрипт с уведомлениями о новых активах.

```bash
#!/usr/bin/env bash
# recon-pipeline.sh — пассивно-активный конвейер bug bounty
DOMAIN="$1"
OUT="recon-$DOMAIN"
mkdir -p "$OUT" && cd "$OUT" || exit

# 1. поддомены (несколько источников)
subfinder -d "$DOMAIN" -all -silent > subs.txt
amass enum -passive -d "$DOMAIN" 2>/dev/null | grep -E '^[a-z0-9.-]+$' >> subs.txt
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' \
  | sed 's/\*\.//g' >> subs.txt
sort -u subs.txt -o subs.txt

# 2. живые хосты + технологии
httpx -l subs.txt -sc -title -tech-detect -server -cdn -silent > live.txt

# 3. URL из архивов и краулеров
cat subs.txt | while read -r h; do gau "$h" 2>/dev/null; done | sort -u > urls.txt
katana -list subs.txt -d 2 -silent 2>/dev/null >> urls.txt
sort -u urls.txt -o urls.txt

# 4. сканирование известных уязвимостей
nuclei -l live.txt -severity critical,high,medium -silent -o nuclei.txt

# 5. уведомление о новых активах
sort -u subs.txt > subs.new
[ -f subs.old ] && comm -13 subs.old subs.new | notify -silent
mv subs.new subs.old

echo "Готово. Смотрите live.txt, urls.txt, nuclei.txt"
```

## Фильтрация и дедупликация результатов

Автоматизация порождает шум. Полезные фильтры:

```bash
# уникальные хосты, отвечающие 200/401/403
grep -E '\[(200|401|403)\]' live.txt | sort -u > interesting.txt
# параметры в URL (кандидаты на инъекции)
grep -oE '[?&][a-zA-Z0-9_]+=' urls.txt | sort | uniq -c | sort -rn | head -20
# интересные расширения
grep -iE '\.(env|git|bak|sql|zip|config|json)$' urls.txt | sort -u
# JS-файлы (секреты, эндпоинты)
grep -iE '\.js$' urls.txt | sort -u > js.txt
```

## Извлечение секретов из JS и репозиториев

JS-бандлы часто содержат API-ключи и внутренние URL:

```bash
cat js.txt | while read -r u; do curl -s "$u"; done > alljs.txt
grep -oE '(api[_-]?key|token|secret|aws_|AIza)[^"]{0,60}' alljs.txt | sort -u
```

Для GitHub-репозиториев:

```bash
trufflehog github --org=example-org --only-verified
gitleaks detect --source ./repo --report-format json -r leaks.json
```

## Приоритизация и ручная проверка

Автоматика находит кандидатов; находки — за ручной работой:
- **Логика** (IDOR, race, business logic) — не детектится сканером.
- **Цепочки** (SSRF → metadata → cloud) — только вручную.
- **Аутентификация** (JWT, OAuth) — требует анализа.

Правило: автоматика для карты, руки — для уязвимостей.

## Работа с новыми активами (continuous recon)

Программа живёт долго; активы появляются постоянно. Настройте мониторинг:

```bash
# notify: уведомление о новых поддоменах
subfinder -d example.com -silent | notify -silent -bulk
# amass с базой: отслеживание изменений
amass enum -d example.com -active -o current.txt
diff previous.txt current.txt
```

Автоматизация через cron + `notify` даёт «первым» заходить на новые хосты — важное преимущество в bug bounty.

## Работа с мобильными приложениями

Если в scope есть мобильные приложения:
- **APK/IPA** → `apktool`, `jadx` → эндпоинты, ключи, секреты.
- **Frida** → обход SSL pinning → перехват API.
- **MobSF** → авто-анализ.

```bash
apktool d app.apk -o src
grep -rniE 'https?://[a-z0-9.-]+' src | grep -vE 'schemas|w3.org' | sort -u | head
```

Часто мобильное приложение раскрывает API, недоступный из веба.

## Квиз

```quiz
- question: "Что делает `httpx` в конвейере bug bounty?"
  options:
    - "Подбирает пароли"
    - "Проверяет живость хостов и снимает технологии"
    - "Строит DNS-зону"
    - "Криптует трафик"
  answer: 1
- question: "Почему `dev`/`staging` поддомены приоритетны?"
  options:
    - "Они быстрее"
    - "Обычно слабее защищены и содержат отладочные функции"
    - "Они бесплатны"
    - "Они не в scope"
  answer: 1
- question: "Что собирает `gau`?"
  options:
    - "Поддомены"
    - "URL из архивов и Common Crawl"
    - "Пароли"
    - "Сертификаты"
  answer: 1
- question: "Почему нельзя выходить за scope, даже если актив уязвим?"
  options:
    - "Это медленно"
    - "Это нарушение правил программы и потенциально незаконно"
    - "Актив не резолвится"
    - "Это неэффективно"
  answer: 1
- question: "Какой инструмент ищет секреты в репозиториях?"
  options:
    - "httpx"
    - "trufflehog / gitleaks"
    - "nuclei"
    - "subfinder"
  answer: 1
```

## Где пригодится

- **Bug bounty:** системный конвейер разведки и приоритизации.
- **Пентест:** адаптация под авторизованный внешний периметр.
- **Red team:** карта активов для выбора вектора.
- **CTF:** структурированный подход к веб/infra-задачам.
- **Мониторинг:** отслеживание появления новых поддоменов.
