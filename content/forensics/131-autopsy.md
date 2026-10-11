---
id: forensics-autopsy
title: "Autopsy: графическая платформа и ingest-модули"
category: forensics
parent: forensics-tooling
difficulty: easy
order: 1
tags: [autopsy, sleuthkit, ingest, gui, artifacts, reporting]
prerequisites: [forensics-tooling]
useful_for:
  - "CTF Forensics категория"
  - "DFIR"
  - "Анализ образов дисков"
estimated_minutes: 48
summary: "Работа в Autopsy: создание кейса, добавление образов, ingest-модули, просмотр артефактов (веб, реестр, медиа), теги, отчёты и типичные настройки для быстрого триажа."
---

Autopsy — графическая платформа поверх The Sleuth Kit, предназначенная для комплексного анализа образов. Она автоматизирует извлечение артефактов через **ingest-модули** (веб-история, реестр, почта, медиа, хеш-базы) и даёт удобный интерфейс для просмотра, тегирования и составления отчётов. Для CTF Autopsy ускоряет «первый проход» по большому образу.

## Создание кейса и добавление образа

1. **New Case** — имя, каталог для результатов, тип (Single-user/Disk image).
2. **Add Data Source** — образ диска (E01, RAW, VMDK, L01) или локальный диск.
3. **Configure Ingest** — выбрать модули.
4. **Analyze** — дождаться обработки.

```bash
# Autopsy GUI запускается как приложение; CLI-аналог — sleuthkit
autopsy          # старый CLI-демон (Windows/Linux)
# Современный Autopsy 4.x — Java-приложение с GUI
./autopsy-4.21.0/bin/autopsy
```

На больших образах ingest может идти часами; выбирайте модули осознанно.

## Ingest-модули

| Модуль | Что извлекает |
|--------|---------------|
| Recent Activity | веб-история, cookies, загрузки (Chrome/Firefox/IE) |
| Windows Registry | реестр, USB, автозапуск, пользователи |
| Email Parser | PST/MBOX |
| File Type Identification | определение типов |
| Extension Mismatch | несоответствие расширения и содержимого |
| Picture Analyzer | EXIF, геолокация |
| Keyword Search | поиск по ключевым словам |
| Hash Lookup | известные файлы (NSRL), вредоносные хеши |
| Interesting Files | интересные файлы по правилам |
| Data Source Integrity | проверка целостности |
| Central Repository | общая база между кейсами |

## Просмотр артефактов

В левой панели — дерево (Data Sources, Views, Results, Tags). Полезные представления:

- **Views → File Types** — файлы по типу (images, videos, documents).
- **Views → Deleted Files** — удалённые файлы.
- **Views → File Size** — сортировка по размеру.
- **Results → Extracted Content** — извлечённые артефакты (веб, реестр, EXIF).
- **Results → Keyword Hits** — найденные ключевые слова.

## Ключевой поиск и теги

```bash
# В Autopsy: меню Tools -> Options -> Keyword Search
# Можно искать по regex: \bflag\{[^}]+\}
```

Regex-поиск `flag\{[^}]+\}` находит CTF-флаги; теги (Follow-up, Notable Item) помогают отметить находки и выгрузить их в отчёт.

## Разобранный пример

```
1. New Case "case-2024", type Single-user.
2. Add Data Source -> Disk Image -> usb.E01.
3. Ingest: Recent Activity, Windows Registry, File Type ID, Keyword Search (flag regex).
4. Analyze -> Results -> Keyword Hits -> найдено "flag{autopsy_works}".
5. Tag as Notable, Generate Report -> HTML.
```

Отчёт содержит путь к файлу, время, источник — готовый к приложению к расследованию.

## Отчёты

Autopsy умеет экспортировать:

- **HTML report** — структурированный отчёт с артефактами.
- **Excel/CSV** — таблицы артефактов.
- **KML** — геолокация (Google Earth).
- **Portable case** — переносимый кейс.

## Краевые случаи и подводные камни

- **Ресурсы.** Ingest на большом образе требует много RAM/CPU; на слабой машине может зависнуть.
- **Java heap.** Увеличьте heap (`-Xmx`) для больших кейсов.
- **Ложные keyword hits.** Regex без границ даёт шум.
- **Хеш-базы.** NSRL-фильтр уменьшает шум, но не заменяет анализ.
- **Autopsy ≠ единственный источник.** Для нестандартных ФС используйте sleuthkit CLI.
- **Целостность.** Autopsy не должен писать в образ; проверяйте режим read-only.
- **Совместимость.** Формат кейса привязан к версии Autopsy.
- **Время.** Часовой пояс в отчёте нужно проверять.

## Устройство Autopsy и связь со Sleuthkit

Autopsy — это Java-фронтенд поверх The Sleuth Kit. Понимание этого помогает: когда GUI «не показывает» что-то, вы можете достать это через CLI (`fls`, `icat`, `istat`) и наоборот.

```bash
# Тот же образ через CLI
fls -r -o 2048 disk.E01        # sleuthkit умеет E01 (через libewf)
icat -o 2048 disk.E01 <inode> > file.bin
# Autopsy хранит результаты кейса в каталоге кейса:
ls "case-2024/Autopsy/Reports"
ls "case-2024/Autopsy/KeywordSearch"
```

Autopsy использует те же механизмы (offsets, inode), поэтому знание sleuthkit делает работу в GUI осознанной.

## Ingest-модули в деталях

- **Recent Activity** — парсит SQLite браузеров (History, Cookies, Downloads) для Chrome/Firefox/IE/Edge.
- **Windows Registry** — разбирает hive'ы: USB-история, автозапуск, пользователи, сеть.
- **Email Parser** — PST/OST/MBOX → сообщения и вложения.
- **File Type Identification** — по сигнатурам, а не расширению.
- **Extension Mismatch Detector** — файл `.jpg`, который на самом деле ZIP.
- **Picture Analyzer** — EXIF, GPS, модель камеры.
- **Hash Lookup** — сравнение с NSRL (известные «хорошие») и списком вредоносных.
- **Keyword Search** — по строкам/regex.
- **Interesting Files Identifier** — по настраиваемым правилам.
- **Embedded File Extractor** — извлекает вложенные файлы (из ZIP, Office, PDF).
- **Data Source Integrity** — проверка хешей образа.

```bash
# Модули можно запускать повторно через меню Run Ingest Modules
```

## Работа с результатами

- **Extracted Content** — категории артефактов (Web History, Web Search, Web Cookies, USB Devices, Installed Programs, ...).
- **Keyword Hits** — найденные строки; двойной клик ведёт к файлу/смещению.
- **Interesting Items** — по правилам.
- **Tags** — пометки; экспорт в отчёт.
- **Timeline** — объединённый таймлайн (если включён модуль).

```bash
# Отчёт можно сгенерировать в HTML/Excel/KML
# Reports -> Generate Report -> выбрать артефакты и теги
```

## Практические приёмы

- **Порядок ingest.** Сначала дешёвые модули (типы, keyword), потом тяжёлые (email, hash lookup).
- **Heap.** Для больших кейсов увеличьте Java heap в `autopsy.conf` (`-Xmx4g`).
- **Central Repository.** Общая база хешей/артефактов между кейсами ускоряет повторный анализ.
- **Timeline.** Включайте Timeline-модуль для сводной хронологии.
- **Multiuser.** Для командной работы — многопользовательский режим с PostgreSQL.
- **Автоматизация.** Autopsy CLI/`autopsy` можно вызывать скриптами для пакетной обработки.

## Сравнение с чистыми CLI-инструментами

| Задача | Autopsy | CLI |
|--------|---------|-----|
| Быстрый обзор | GUI + ingest | ручные fls/strings |
| Артефакты браузера | авто-модуль | вручную SQLite |
| Отчёт | встроенный | свой скрипт |
| Нестандартная ФС | ограниченно | sleuthkit поддерживает шире |
| Скриптование | ограниченно | полный контроль |

Идеально — комбинировать: Autopsy для первого прохода и отчёта, CLI для нестандартных задач.

## Типичные ошибки

- **Ingest «всё подряд».** Часы обработки ради ненужного.
- **Мало heap.** Java падает на больших кейсах.
- **Игнорирование CLI.** Autopsy не заменяет sleuthkit для сложных ФС.
- **Нет тегов.** Находки теряются в отчёте.
- **Повторный ingest.** Может дублировать результаты; используйте Central Repository.
- **Часовой пояс.** Проверяйте в отчёте.
- **Целостность.** Убедитесь, что образ подключён read-only.

## Командная работа и многопользовательский режим

Для крупных кейсов Autopsy поддерживает multiuser:

- **Central Repository** — общая база хешей и артефактов; ускоряет повторные кейсы.
- **PostgreSQL** — backend для многопользовательского режима.
- **Roles** — разграничение доступа (админ, аналитик, ревьюер).
- **Сетевой доступ** — несколько аналитиков работают с одним кейсом.

```bash
# Настройка central repository в Options -> Central Repository
# Многопользовательский режим: запуск через autopsy с PostgreSQL
```

## Экспорт и интеграция

- **HTML/Excel/KML** — отчёты.
- **CSV** — для дальнейшей обработки.
- **Timeline (CSV)** — совместим с `plaso`/Timesketch.
- **Tags** — выгрузка отмеченных артефактов.

```bash
# Отчёт в Excel, затем анализ в Python/pandas
python3 -c "import pandas as pd; print(pd.read_excel('report.xlsx').head())"
```

## Ограничения Autopsy

- Не все ФС поддерживаются так же полно, как в sleuthkit CLI.
- Тяжёлый ingest на больших образах.
- Java heap и ресурсы.
- Нестандартные форматы требуют CLI.

Поэтому профессиональный поток — гибридный: Autopsy для обзора и отчёта, CLI для сложного.

## Итоговый чек-лист

1. Создать кейс, добавить образ.
2. Выбрать модули (Recent Activity, Registry, Types, Keyword).
3. Запустить ingest, дождаться.
4. Просмотреть Extracted Content и Keyword Hits.
5. Тегировать находки.
6. Сгенерировать отчёт (HTML/Excel).
7. При необходимости — CLI для нестандартных задач.

## Автоматизация Autopsy

Хотя Autopsy — GUI, его можно запускать из скриптов и комбинировать с CLI:

```bash
# Автоматический ingest через командную строку (если поддерживается сборкой)
autopsy -c case.aut -i disk.E01
# Или использовать sleuthkit напрямую для пакетной обработки
for img in *.E01; do
  echo "== $img"
  fls -r -m "C:/" "$img" > "${img%.E01}.body"
done
```

## Совместная работа с Timesketch

Экспортированный timeline из Autopsy (CSV/plaso) можно загрузить в Timesketch для совместного анализа:

```bash
# Конвертировать bodyfile в plaso, затем в Timesketch
psort.py -o timesketch_out timeline.plaso
```

## Итог

Autopsy ускоряет первый проход по образу и составление отчёта, но не заменяет sleuthkit CLI для сложных ФС. Оптимально — гибридный подход: GUI для обзора, CLI для глубоких задач.

## Что дальше / решение

1. Создать кейс и добавить образ.
2. Выбрать ingest-модули (веб, реестр, типы, keyword).
3. Дождаться обработки.
4. Просмотреть Results (Extracted Content, Keyword Hits).
5. Тегировать находки и сгенерировать отчёт.

Дальше — `forensics-yara-sigma` (правила) и `forensics-python-tooling` (автоматизация).

## Квиз

```quiz
- question: "Что делают ingest-модули Autopsy?"
  options:
    - "шифруют образ"
    - "автоматически извлекают артефакты из образа"
    - "снимают образ"
    - "собирают RAID"
  answer: 1
  explanation: "Ingest-модули автоматически извлекают веб, реестр, медиа и т. п."
- question: "Как в Autopsy найти CTF-флаг в образе?"
  options:
    - "запустить nmap"
    - "keyword search с regex flag\\{[^}]+\\}"
    - "открыть MBR"
    - "сделать mkfs"
  answer: 1
  explanation: "Regex-поиск по ключевым словам находит шаблон флага."
- question: "Какой модуль Autopsy извлекает веб-историю?"
  options:
    - "Recent Activity"
    - "Picture Analyzer"
    - "Data Source Integrity"
    - "Central Repository"
  answer: 0
  explanation: "Recent Activity разбирает браузерные артефакты."
- question: "Почему ingest может зависнуть на большом образе?"
  options:
    - "Нет интернета"
    - "Не хватает RAM/CPU (Java heap)"
    - "Образ зашифрован"
    - "Autopsy не поддерживает E01"
  answer: 1
  explanation: "Обработка больших образов требует ресурсов; увеличьте heap."
```

## Где пригодится

- **CTF:** быстрый первый проход по образу.
- **DFIR:** комплексное извлечение артефактов.
- **Судебная экспертиза:** структурированные отчёты.
- **Обучение:** наглядное изучение артефактов.
