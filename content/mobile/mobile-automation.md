---
id: mobile-automation
title: "Автоматизация мобильного тестирования: MobSF и CI"
category: mobile
parent: mobile-testing-workflow
difficulty: medium
order: 1
tags: [mobsf, automation, ci, static-analysis, dynamic-analysis, devsecops, mobile]
prerequisites: [mobile-intro]
useful_for:
  - "CTF Mobile (быстрый автоматический скан)"
  - "Bug bounty (триаж клиента)"
  - "Пентест мобильных приложений"
estimated_minutes: 30
summary: "Как автоматизировать мобильный анализ: MobSF (статический и динамический скан), генерация отчётов, интеграция в CI/CD и место автоматизации в методологии."
---
## Зачем автоматизировать мобильный анализ

Ручной анализ даёт максимальную глубину, но стоит дорого: на один APK уходят часы. Автоматизация решает три задачи. Первая — **быстрый триаж**: за пару минут получить список зашитых секретов, экспортированных компонентов, небезопасных флагов и потенциальных уязвимостей, чтобы понять, куда копать руками. Вторая — **масштаб**: когда в bug bounty десятки приложений или в релизе сотни сборок, прогонять каждую вручную невозможно. Третья — **регрессии в CI**: автоматический скан ловит появление нового секрета или открытого компонента ещё до релиза.

Важно понимать место автоматизации в методологии: это не замена ручному анализу, а его «ускоритель». Сканер не поймёт бизнес-логику, не построит цепочку захвата аккаунта и не найдёт IDOR в API. Зато он соберёт факты (манифест, строки, конфиги, трекеры) и разложит их по категориям, а вы уже идёте по списку.

## MobSF: что это и варианты запуска

Mobile Security Framework (MobSF) — самый распространённый open-source инструмент автоматического анализа APK/IPA. Он объединяет статический анализ (разбор DEX, манифеста, ресурсов, строк) и динамический (запуск на эмуляторе с Frida, перехват трафика, дампы). Поддерживает Android, iOS, Windows.

```bash
# 1. Docker — самый простой и воспроизводимый способ
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# 2. Из исходников (для кастомизации)
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
./run.sh 127.0.0.1:8000
```

После запуска UI доступен на `http://localhost:8000`. REST API защищён ключом, который генерируется при старте и печатается в логе; его можно задать переменной окружения `MOBSF_API_KEY`.

```bash
# получить ключ (в логе контейнера) или задать свой
docker run -e MOBSF_API_KEY=supersecret -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

## REST API: полный цикл сканирования

Автоматизация строится на REST API. Цикл состоит из четырёх шагов: загрузка файла, запуск скана, ожидание, получение отчёта.

```bash
KEY=supersecret
HOST=http://localhost:8000

# 1) загрузка — возвращает hash файла
curl -s -F "file=@target.apk" $HOST/api/v1/upload \
  -H "Authorization: $KEY"
# {"file_name":"target.apk","hash":"a1b2c3...","scan_type":"apk","status":"success"}

# 2) запуск скана (для apk/ipa)
curl -s -X POST $HOST/api/v1/scan \
  -d "scan_type=apk&file_name=target.apk&hash=a1b2c3..." \
  -H "Authorization: $KEY"

# 3) отчёты
curl -s -X POST $HOST/api/v1/report_json \
  -d "hash=a1b2c3..." -H "Authorization: $KEY" -o report.json
curl -s -X POST $HOST/api/v1/download_pdf \
  -d "hash=a1b2c3..." -H "Authorization: $KEY" -o report.pdf

# 4) поиск строк (secrets) и сравнение с предыдущим сканом
curl -s -X POST $HOST/api/v1/search \
  -d "query=api_key&hash=a1b2c3..." -H "Authorization: $KEY"
curl -s -X POST $HOST/api/v1/compare \
  -d "hash1=a1b2c3...&hash2=d4e5f6..." -H "Authorization: $KEY"
```

Разбор `report_json` удобно делать `jq`, вытаскивая только значимые поля:

```bash
jq '{score:.appsec.security_score,
     exported:[.manifest.exported_activities[]?.name],
     secrets:[.secrets[]?|{k:.metadata, v:.value}],
     perms:[.permissions[]?]}' report.json
```

## Что реально даёт отчёт MobSF

Отчёт группирует находки по важности. Практический чек-лист того, на что смотреть в первую очередь:

- **Security Score** — грубая оценка (0–100) и разбивка High/Medium/Low/Warning.
- **Manifest Analysis** — `android:debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, список exported-компонентов без permission.
- **Hardcoded Secrets** — API-ключи, токены, пароли, найденные в DEX и ресурсах (через регулярки и entropy).
- **Trackers** — сторонние SDK (аналитика, реклама), иногда с известными утечками.
- **Network Security Config** — какие домены в cleartext, какой trust-anchors, pinning.
- **Code Analysis** — опасные API: `WebView.addJavascriptInterface`, `Runtime.exec`, небезопасный `Cipher.getInstance`.
- **APK Certificate** — самоподписанный, отладочный сертификат, слабый алгоритм подписи.

Важно: MobSF помечает **потенциальные** проблемы. Например, `addJavascriptInterface` — это «warning», а не «high», пока вы не докажете, что через мост утекает токен. Поэтому отчёт — карта, а не приговор.

## mobsfscan: SAST для исходников и CI

Для проверки **исходного кода** (не APK) есть `mobsfscan` — отдельный SAST-движок на Semgrep-правилах.

```bash
pip install mobsfscan
mobsfscan --json -o mobsfscan.json ./src
mobsfscan --sarif -o mobsfscan.sarif ./src      # для GitHub code scanning
```

Он находит те же классы проблем (WebView-мосты, cleartext, hardcoded keys, небезопасная криптография), но на этапе разработки. В CI это дешевле, чем собирать APK.

## Динамический анализ в MobSF

MobSF умеет запускать приложение на подключённом эмуляторе/устройстве и собирать динамику:

```bash
# предварительно: adb devices должен видеть эмулятор с root
# в UI: Dynamic Analyzer → выбрать устройство → запустить приложение
# затем: экспорт логов, HTTP-трафика (через встроенный прокси), Frida-логов
```

Динамика даёт: реальные HTTP(S)-запросы (если снят pinning), вызовы API, содержимое логов, список файлов, созданных приложением, сработавшие Frida-скрипты. Это быстрый способ увидеть, «куда ходит» приложение, без ручной настройки прокси.

## Интеграция в CI/CD

Типовой pipeline: собрать APK → прогнать MobSF → упасть, если score ниже порога или появились High-находки.

```yaml
# GitHub Actions (фрагмент)
- name: Start MobSF
  run: docker run -d -p 8000:8000 -e MOBSF_API_KEY=${{ secrets.MOBSF_KEY }} \
       opensecurity/mobile-security-framework-mobsf:latest
- name: Scan APK
  run: |
    HASH=$(curl -s -F "file=@app-release.apk" localhost:8000/api/v1/upload \
      -H "Authorization: ${{ secrets.MOBSF_KEY }}" | jq -r .hash)
    curl -s -X POST localhost:8000/api/v1/scan \
      -d "scan_type=apk&file_name=app-release.apk&hash=$HASH" \
      -H "Authorization: ${{ secrets.MOBSF_KEY }}"
    curl -s -X POST localhost:8000/api/v1/report_json -d "hash=$HASH" \
      -H "Authorization: ${{ secrets.MOBSF_KEY }}" -o report.json
    jq -e '.appsec.security_score >= 60' report.json   # quality gate
```

Quality gate должен опираться на **дельту**, а не на абсолют: сравнивайте отчёт с базовым (`/api/v1/compare`) и блокируйте только **новые** High-находки. Иначе легаси-проект с сотней старых warning никогда не пройдёт сборку.

## Альтернативы и вспомогательные инструменты

| Инструмент | Назначение | Ключевая команда |
|------------|-----------|------------------|
| MobSF | Полный статический+динамический скан | `docker run ... mobsf` |
| mobsfscan | SAST по исходникам | `mobsfscan --json src/` |
| apkleaks | Быстрый поиск секретов/URL в APK | `apkleaks -f app.apk -o out.txt` |
| trueseeing | Лёгкий статический анализ CLI | `trueseeing app.apk` |
| androbugs | Набор проверок Android | `python AndroBugs_Framework.py app.apk` |
| semgrep | Гибкие правила под свой стек | `semgrep --config auto src/` |
| jadx | Декомпиляция (ручной анализ) | `jadx -d out app.apk` |
| apktool | Ресурсы и smali (ручной анализ) | `apktool d app.apk` |

Практика: MobSF как «первый проход», apkleaks для быстрой проверки секретов, jadx/apktool для углубления в найденное.

## Типовые ошибки и подводные камни

- **Слепо доверять score.** Высокий балл не значит «безопасно»: логика и API вне зоны сканера.
- **Игнорировать split APK.** MobSF анализирует один файл; base-APK без config-сплитов может не содержать часть ресурсов и native-библиотек. Собирайте `.apks`/`.xapk` или анализируйте каждый сплит.
- **Скан release без обфускации vs с обфускацией.** После R8 имена классов и строки меняются; «hardcoded secret» может выглядеть иначе, а часть находок пропадёт. Тестируйте обе сборки.
- **Динамика на неподготовленном устройстве.** Без root и без установки пользовательского CA динамический анализ почти бесполезен.
- **API-ключ в открытом виде.** Ключ MobSF = доступ ко всем отчётам; храните его в секретах CI, не в репозитории.
- **Ставить автоматизацию вместо ручного теста.** Отчёт MobSF — это гипотезы. Каждую High-находку нужно верифицировать руками.

## Что дальше / решение

Автоматизация — правильная точка входа: прогнали MobSF + mobsfscan, получили карту. Дальше идёте вручную по ветке: `mobile-static-analysis` (углублённая статика и поиск секретов), `mobile-dynamic-frida` (динамика и обход проверок), `mobile-insecure-storage` (хранилище), `mobile-exported-components` (точки входа), `mobile-api-testing` (серверная логика). Если в CI уже есть gate — сделайте его на дельте отчётов, чтобы не блокировать легаси. Решение считается принятым, когда у вас есть воспроизводимый pipeline: APK на входе, отчёт + список подтверждённых вручную находок на выходе.

## Разобранный пример: триаж APK от загрузки до вывода

Покажем полный цикл на вымышленном `bank.apk`, включая интерпретацию вывода.

```bash
$ curl -s -F "file=@bank.apk" localhost:8000/api/v1/upload -H "Authorization: $KEY"
{"file_name":"bank.apk","hash":"9f2c...","scan_type":"apk","status":"success"}

$ curl -s -X POST localhost:8000/api/v1/scan \
    -d "scan_type=apk&file_name=bank.apk&hash=9f2c..." -H "Authorization: $KEY" | jq .
{
  "appsec": {"security_score": 34},
  "manifest_analysis": {"app": {"debuggable": true, "allow_backup": true}},
  "secrets": [
    {"metadata": "Google API Key", "value": "AIzaSy...", "file": "res/values/strings.xml"},
    {"metadata": "Firebase URL", "value": "https://bank-db.firebaseio.com", "file": "classes.dex"}
  ],
  "exported_activities": ["com.bank.ui.DeepLinkActivity"],
  "network_security_config": {"cleartext": ["api-legacy.bank.example"]}
}
```

Интерпретация: `debuggable: true` в release — критично (позволяет `run-as`, отладку, дамп памяти); `allow_backup: true` — можно вытащить данные через `adb backup`; найден Firebase URL — проверяем на открытые правила чтения; `DeepLinkActivity` экспортирована без permission — потенциальный intent-redirect. Дальше каждая находка идёт в отдельный ручной трек.

## Справочная таблица: что где в report_json

| Поле JSON | Что означает | Что делать |
|-----------|--------------|------------|
| `appsec.security_score` | сводный балл | порог в CI, но не истина |
| `manifest_analysis.app.debuggable` | `android:debuggable` | находка, если release |
| `manifest_analysis.app.allow_backup` | `allowBackup` | `adb backup`, риск утечки |
| `secrets[]` | hardcoded строки | верифицировать руками |
| `exported_activities[]` | exported Activity | deep link / intent атаки |
| `exported_services[]` | exported Service | Binder/IPC |
| `exported_receivers[]` | exported Receiver | broadcast-инъекции |
| `exported_providers[]` | exported Provider | path traversal, SQLi |
| `network_security_config` | cleartext/trust | MITM, pinning |
| `trackers[]` | сторонние SDK | приватность, утечки |
| `certificate_analysis` | подпись APK | debug-сертификат = находка |
| `code_analysis` | опасные API | WebView, exec, crypto |

Такой разбор за пять минут даёт вам список гипотез, отсортированный по важности, — и вы идёте в ручной анализ уже с картой, а не вслепую.

## Квиз

```quiz
- question: "Что делает MobSF?"
  options:
    - "Автоматический статический и динамический анализ мобильных приложений"
    - "Только подписывает APK"
    - "Только расшифровывает IPA"
    - "Только сканирует сеть"
  answer: 0
  explanation: "MobSF — фреймворк автоматического анализа APK/IPA."
- question: "Какую категорию находок автоматика НЕ покрывает хорошо?"
  options:
    - "Бизнес-логику и BOLA"
    - "Разрешения в манифесте"
    - "Hardcoded secrets"
    - "Exported компоненты"
  answer: 0
  explanation: "Логику и авторизацию объектов находит только ручной тест."
- question: "Как залить APK в MobSF по API?"
  options:
    - "POST /api/v1/upload с файлом"
    - "GET /api/v1/download"
    - "PUT /scan"
    - "DELETE /apk"
  answer: 0
  explanation: "Загрузка идёт через /api/v1/upload с API-ключом."
- question: "Зачем MobSF в CI/CD?"
  options:
    - "Ловить регрессии безопасности до релиза"
    - "Ускорять сборку"
    - "Сжимать APK"
    - "Менять тему приложения"
  answer: 0
  explanation: "Автоскан в пайплайне не даёт утечкам попасть в релиз."
- question: "Какой инструмент ищет зашитые секреты в репозитории?"
  options:
    - "gitleaks / trufflehog"
    - "nmap"
    - "sqlmap"
    - "hydra"
  answer: 0
  explanation: "Секрет-сканеры ловят ключи в коде и сборках."
```

## Где пригодится

- **CTF Mobile:** быстрый первичный скан.
- **Bug bounty:** триаж клиента перед глубоким анализом.
- **Пентест:** ускорение разведки и отчётности.
- **Работа:** DevSecOps для мобильной разработки.
