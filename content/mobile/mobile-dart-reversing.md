---
id: mobile-dart-reversing
title: "Реверс Flutter/Dart: снапшот, blutter и reFlutter"
category: mobile
parent: mobile-native-reversing
difficulty: hard
order: 1
tags: [flutter, dart, libapp.so, blutter, reflutter, snapshot, aot, reversing]
prerequisites: [mobile-flutter]
useful_for:
  - "Реверс-инжиниринг мобильных приложений"
  - "Пентест мобильных приложений"
  - "CTF Mobile"
estimated_minutes: 50
summary: "Как реверсить Flutter-приложения: структура libapp.so, AOT-снапшот Dart, blutter для восстановления символов и псевдо-C, reFlutter для патча и хуков."
---
## Введение

Flutter-приложения компилируют Dart в **AOT-снапшот**, который лежит внутри `libapp.so`. Это не C++ и не DEX: нет Java, нет обычных символов, а код — машинный ARM64 с метаданными Dart (пул объектов, хендлы, классы). Обычные инструменты (jadx, Ghidra «из коробки») мало помогают. Специализированные инструменты — `blutter` (восстанавливает символы и генерирует псевдо-C) и `reFlutter` (патчит снапшот для инъекции и дампов).

Задача пентеста: понять, где логика (например, валидация, шифрование, root-детект) в Dart-коде, найти строки и обойти проверки. Часто в Flutter-приложении вообще нет нативных Java-проверок — всё в Dart.

## Структура Flutter-приложения

```bash
unzip -l app.apk | grep -E 'lib/.*\.so|flutter_assets'
# lib/arm64-v8a/libflutter.so     (движок Dart)
# lib/arm64-v8a/libapp.so         (AOT-снапшот вашего кода)
# assets/flutter_assets/...       (ресурсы, строки, конфиги)
```

Ключевые артефакты:
- `libapp.so` — скомпилированный Dart (ваша логика).
- `libflutter.so` — движок.
- `assets/flutter_assets/kernel_blob.bin` — ядро (в debug-сборках, читаемый Dart).

В debug-сборке логика может быть в `kernel_blob.bin` (читаемый); в release — в `libapp.so` (AOT).

## blutter: восстановление Dart-снапшота

```bash
# установка
git clone https://github.com/worawit/blutter && cd blutter
python3 scripts/install_deps.py
# запуск на распакованном APK
python3 blutter.py /path/to/app_unpacked/arm64-v8a /tmp/blutter_out
```

Результат:
- `out/asm/` — дизассемблер Dart-функций;
- `out/pp.txt` — пул объектов (строки, классы);
- `out/objs.txt` — объекты;
- `out/*.dll`/псевдо-C для импорта в IDA.

Ищем строки и функции:

```bash
grep -iE 'root|license|verify|secret|key|token' /tmp/blutter_out/pp.txt | head
grep -rn "isRooted" /tmp/blutter_out/asm/ | head
```

Так находятся Dart-функции проверок и строковые константы.

## reFlutter: патч и динамика

`reFlutter` переупаковывает приложение, модифицируя снапшот Dart, чтобы встроить возможности дампа/хуков (аналог Frida для Dart):

```bash
pip install reflutter
reflutter app.apk
# выбираем нужный режим (traffic interception / dump)
# на выходе app-release.apk, подписываем и ставим
```

reFlutter полезен для перехвата сетевого трафика Flutter-приложений (Flutter использует свой сетевой стек, и обычный прокси может не работать без правки).

## Полный сквозной пример: обход Dart-проверки

```bash
# 1. Распаковываем APK и запускаем blutter
unzip app.apk -d app_out
python3 blutter.py app_out/lib/arm64-v8a /tmp/bl
# 2. Ищем функцию проверки
grep -rn "isEmulator\|isRooted\|checkIntegrity" /tmp/bl/asm/ | head
# 3. Смотрим псевдо-C функции, находим ветку возврата
# 4. Патчим через reFlutter либо хукаем нативно через Frida
#    (адрес функции из blutter -> Interceptor)
```

Через Frida (нативный хук Dart-функции по адресу):

```javascript
var base = Module.findBaseAddress("libapp.so");
var fn = base.add(0x8A1C4);   // адрес из blutter
Interceptor.attach(fn, { onLeave: function(r){ r.replace(0x1); } });
```

## Строки и секреты

Flutter хранит строки в пуле объектов; blutter выгружает их в `pp.txt`. Ищите API-ключи, URL, токены:

```bash
grep -oE 'https?://[^"]+' /tmp/bl/pp.txt | sort -u | head
grep -iE 'api[_-]?key|secret|firebase' /tmp/bl/pp.txt | head
```

## Частые ошибки

- **Пытаться реверсить через jadx**: Dart-логики в DEX нет.
- **Неверная версия Dart**: blutter требует совпадения версии Dart-движка; обновите инструмент.
- **Debug vs release**: в debug логика в `kernel_blob.bin`, в release — в `libapp.so`.
- **Забыть про архитектуру**: blutter работает с конкретным `arm64-v8a`.
- **Обычный прокси не видит трафик**: Flutter использует свой стек — нужен reFlutter.
- **Строки не найдены**: часть строк генерируется/шифруется — ищите в пуле и в рантайме.

## Что дальше / решение

Порядок: распаковать APK → определить debug/release → запустить blutter → найти функции/строки → обойти через reFlutter/Frida. Свяжите с `mobile-flutter` (обзор), `mobile-native-so-deep` (ARM64), `mobile-network-security-config` (сеть). Дальше — `mobile-react-native-reversing`.

## Справочная таблица

| Артефакт | Назначение |
|----------|-----------|
| libapp.so | AOT-снапшот Dart (логика) |
| libflutter.so | движок |
| kernel_blob.bin | ядро (debug) |
| pp.txt (blutter) | пул объектов/строк |

| Инструмент | Роль |
|-----------|------|
| blutter | символы + псевдо-C |
| reFlutter | патч/инъекция/сеть |
| Ghidra/IDA | анализ псевдо-C |
| Frida | нативные хуки |

## Полный разбор Flutter-приложения

**Шаг 1. Идентификация.**

```bash
unzip -l app.apk | grep -E 'lib/.*\.so|flutter_assets'
# lib/arm64-v8a/libapp.so   <- логика Dart
# lib/arm64-v8a/libflutter.so
# assets/flutter_assets/kernel_blob.bin (debug)
```

**Шаг 2. Определение сборки.** Если есть `kernel_blob.bin` — debug (читаемое ядро Dart). Если только `libapp.so` — release (AOT).

```bash
unzip app.apk 'lib/arm64-v8a/*' 'assets/flutter_assets/*' -d out
file out/lib/arm64-v8a/libapp.so
strings -n 8 out/lib/arm64-v8a/libapp.so | grep -iE 'http|token|key' | head
```

**Шаг 3. blutter.**

```bash
git clone https://github.com/worawit/blutter && cd blutter
python3 scripts/install_deps.py
python3 blutter.py ../out/lib/arm64-v8a /tmp/bl
ls /tmp/bl
grep -iE 'root|license|verify|secret' /tmp/bl/pp.txt | head
```

**Шаг 4. Анализ пула и функций.**

```bash
grep -rn "isRooted\|checkIntegrity\|verifyLicense" /tmp/bl/asm/ | head
grep -oE 'https?://[^" ]+' /tmp/bl/pp.txt | sort -u | head
```

**Шаг 5. Динамика/патч.** Через reFlutter для перехвата сети:

```bash
pip install reflutter
reflutter app.apk   # выбрать режим traffic interception
# подписать результат и установить
```

Или нативный хук через Frida по адресу из blutter.

## Flutter-специфика

| Артефакт | Что даёт |
|----------|----------|
| libapp.so | логика (AOT) |
| libflutter.so | движок |
| pp.txt | строки/объекты |
| asm/*.dart | дизасм функций |

## Типичные находки

| Находка | Severity |
|---------|----------|
| Секреты в пуле строк | Medium/High |
| Клиентские проверки в Dart | Medium |
| Flutter-трафик без прокси | — |
| Обфускация/шифрование строк | — |

## Методический чек-лист

1. Определить Flutter и версию Dart.
2. Запустить blutter, получить строки и функции.
3. Найти проверки и секреты.
4. Обойти через reFlutter/Frida.
5. Оформить рекомендации.

## Рекомендации в отчёте

- Выносить секреты на сервер, не хранить в Dart-коде.
- Дублировать клиентские проверки серверными.
- Шифровать строки/использовать обфускацию Dart (усложняет blutter).
- Не полагаться на клиентскую валидацию.

## Работа с большими снапшотами и автоматизация

Реальные Flutter-приложения дают снапшоты в десятки мегабайт, и `blutter` может работать долго. Практические приёмы ускорения и навигации: запускайте blutter с указанием только нужной ABI (arm64-v8a), не распаковывайте лишние ресурсы, а выход складывайте в отдельную папку, чтобы не смешивать с APK. Если процесс падает на несовпадении версии Dart, проверьте версию `libflutter.so` (строка вида `Flutter 3.x`) и возьмите соответствующую ветку blutter или обновите инструмент.

Для навигации по результату используйте `pp.txt` (пул объектов) как индекс строк: сначала грепаете по ключевым словам (`token`, `http`, `verify`, `root`), затем ищете соответствующие адреса и функции в `asm/`. Имена функций в снапшоте не всегда читаемы, поэтому опирайтесь на строковые ссылки: если функция ссылается на строку `"isEmulator"`, это хороший кандидат.

Автоматизация поиска секретов: соберите из `pp.txt` все строки, отфильтруйте URL, ключи (паттерны `AIza`, `sk_live`, `eyJ`), затем проверьте, какие функции их используют. Часто API-ключи лежат в константах, и этого достаточно для находки. Для больших приложений удобно писать скрипт, который соединяет `pp.txt` и `asm/` по ссылкам.

## Ограничения подхода

blutter восстанавливает далеко не всё: агрессивная оптимизация Dart AOT, инлайнинг и обфускация усложняют чтение. Иногда быстрее идти динамикой — reFlutter для сети и Frida для нативных хуков. Комбинируйте: статика для карты, динамика для подтверждения. И помните, что Flutter-приложение может вообще не иметь Java-логики, поэтому не тратьте время на jadx, если видите `libapp.so`.

## Реверс Dart-логики: практические приёмы

Когда blutter выдал псевдо-C, читать его нужно осмысленно. Dart AOT использует косвенные вызовы и пул объектов: строки и классы лежат в пуле, а функции обращаются к ним по индексам. Поэтому в декомпилированном коде вы часто видите обращения к объектам пула, а не прямые строки. Сопоставляйте индексы из `pp.txt` с местами использования, чтобы понять смысл функции.

Полезный приём — искать «якорные» строки. Если функция ссылается на строку `"isEmulator"` или `"checkIntegrity"`, это почти наверняка проверка. Найдите её адрес в `asm/`, посмотрите, какие условия возвращают true/false, и определите точку ветвления. Затем хукните нативно через Frida по адресу (база + смещение).

Для криптографических проверок (например, подпись запросов) ищите вызовы хеш-функций и сравнения. Dart-крипто часто реализовано нативно в `libflutter.so` или в `libapp.so`; ключи могут быть зашиты как байтовые константы. Извлекайте их из пула и проверяйте, используются ли они в сетевых вызовах.

## Динамика Flutter: перехват сети

Flutter использует собственный сетевой стек, поэтому системный прокси может не работать. reFlutter патчит снапшот, добавляя возможность перехвата. Альтернатива — Frida-хук нативных функций TLS (`SSL_write`/`SSL_read` в BoringSSL, встроенном в `libflutter.so`). Найдите символы через `nm -D libflutter.so | grep -i ssl` и хукните. Это даёт расшифрованный трафик без прокси.

## Организация работы

Для больших приложений ведите карту: какие строки найдены, какие функции их используют, какие проверки обнаружены, какие обойдены. Это экономит время при повторных сборках (смещения меняются). Фиксируйте хэш `libapp.so` и версию Flutter.

## Квиз

```quiz
- question: "Где лежит AOT-код Dart в release Flutter-приложении?"
  options:
    - "libapp.so"
    - "classes.dex"
    - "index.android.bundle"
    - "resources.arsc"
  answer: 0
- question: "Что делает blutter?"
  options:
    - "Восстанавливает символы Dart-снапшота и генерирует псевдо-C"
    - "Сканирует порты"
    - "Делает бэкап"
    - "Подписывает APK"
  answer: 0
- question: "Зачем нужен reFlutter?"
  options:
    - "Патчит снапшот для инъекции и перехвата трафика Flutter"
    - "Реверсит Swift"
    - "Расшифровывает Keychain"
    - "Снимает root"
  answer: 0
- question: "Почему обычный прокси может не видеть Flutter-трафик?"
  options:
    - "Flutter использует собственный сетевой стек"
    - "Flutter не использует сеть"
    - "Flutter только IPv6"
    - "Flutter шифрует дважды"
  answer: 0
- question: "Где в debug-сборке Flutter может лежать читаемый код?"
  options:
    - "kernel_blob.bin"
    - "libapp.so"
    - "AndroidManifest.xml"
    - "libflutter.so"
  answer: 0
```

## Где пригодится

- **Реверс:** Flutter-приложения — распространённый стек.
- **Пентест:** обход Dart-проверок, перехват сети.
- **Bug bounty:** поиск секретов в пуле строк.
- **CTF:** Mobile-задачи на Flutter.
