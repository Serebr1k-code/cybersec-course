---
id: reversing-android-smali-dex-edit
title: "Правка smali/DEX и repackaging (apktool, baksmali)"
category: reversing
parent: reversing-mod-android
difficulty: medium
order: 3
tags: [reversing, android, smali, dex, apktool, baksmali, repackaging]
prerequisites: [reversing-android-apk]
useful_for:
  - "Пентест мобильных приложений"
  - "Модификация приложений"
  - "Анализ мобильной малвари"
estimated_minutes: 50
summary: "Как разобрать APK в smali, изменить байткод, собрать обратно и подписать: apktool/baksmali, структура smali, типичные правки, ловушки."
lab:
  kind: shell
  title: "Практика: правим smali"
  toolset: [core, hex, strings]
  workdir: /home/student/task
  files: [task.md, classes.dex]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`classes.dex` содержит байткод Dalvik; строки в нём лежат в пуле строк."
    - "smali — текстовое представление байткода; но в этой лабе доступен только `strings`."
    - "Флаг лежит строкой в DEX-пуле."
    - "`strings -n 5 classes.dex | grep nto > found.txt`, затем `check`."
---

## Вопрос, с которого всё начинается

Ты нашёл в приложении проверку подписи, которая мешает запуску на модифицированном APK. Ты хочешь «выключить» её: поменять байткод так, чтобы проверка всегда проходила. Как это делается и что нужно знать о формате DEX?

## Наш пример

Возьмём `classes.dex` — скомпилированный байткод Dalvik. Прежде чем править, посмотрим, что внутри, доступными средствами:

```
$ strings -n 6 classes.dex | grep -iE 'signature|verify|license'
Lcom/example/app/IntegrityCheck;
verifySignature
isDebugBuild
```

Строки подсказывают: есть класс `IntegrityCheck` с методами `verifySignature` и `isDebugBuild`. Дальше — разбор в smali.

## Шаг 1: что такое smali и зачем он нужен

DEX — это бинарный формат байткода Dalvik. Читать его в hex тяжело. **smali** — человекочитаемое текстовое представление того же байткода: каждая инструкция Dalvik (`invoke-virtual`, `move-result`, `const/4`, `if-eqz`) записывается строкой. Инструмент `baksmali` превращает DEX в набор `.smali`-файлов (по одному на класс), `smali` собирает обратно.

`apktool` идёт дальше: он разбирает весь APK (манифест, ресурсы, DEX) в удобную структуру и собирает обратно одной командой. Обычно используют именно его.

```
$ apktool d app.apk -o app_dir
$ ls app_dir/smali/com/example/app/
IntegrityCheck.smali
```

## Шаг 2: читаем метод в smali

Откроем `IntegrityCheck.smali` и найдём `verifySignature`. Упрощённо метод выглядит так:

```
.method public verifySignature()Z
    .registers 3
    invoke-virtual {p0}, Lcom/example/app/IntegrityCheck;->getActual()Ljava/lang/String;
    move-result-object v0
    const-string v1, "expected_signature"
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    return v0
.end method
```

Читается по шагам: получить фактическую подпись в `v0`, сравнить с ожидаемой строкой, вернуть результат (`Z` — boolean). Если результат `false` — приложение считает APK модифицированным.

## Шаг 3: делаем минимальную правку

Простейший обход — заставить метод всегда возвращать `true`. В smali это замена возврата на константу:

```
.method public verifySignature()Z
    .registers 2
    const/4 v0, 0x1      ; v0 = 1 (true)
    return v0
.end method
```

Теперь метод игнорирует реальную проверку и всегда возвращает «подпись верна». Это классическая правка «верни true».

Важно: `.registers` объявляет число регистров метода. Если удалить код, использующий регистры, и уменьшить `.registers`, метод станет короче. Но если число регистров не совпадает с используемыми — верификатор DEX отвергнет файл.

## Шаг 4: собираем и подписываем

Обратная сборка:

```
$ apktool b app_dir -o app_patched.apk
$ zipalign -p 4 app_patched.apk app_aligned.apk
$ apksigner sign --ks my.keystore app_aligned.apk
```

Ключевой момент: после модификации подпись APK меняется. Android откажется устанавливать APK с неверной подписью, поэтому нужен **новый ключ подписи**. Именно поэтому проверка подписи внутри приложения и мешает: код сравнивает свою подпись с «зашитой» эталонной, а ты подписал другим ключом.

## Шаг 5: ловушки repackaging

Правка smali — не всегда достаточно. Частые проблемы:

- **Multidex**: класс может лежать не в `classes.dex`, а в `classes2.dex`/`classes3.dex`. Нужно править нужный файл.
- **Верификатор**: неверное число регистров или типа-инструкции → `INSTALL_FAILED_DEXOPT`. Правку нужно делать аккуратно.
- **Проверка целостности DEX**: приложение может хешировать свой DEX и сравнивать с эталоном. Тогда правка smali сломает хеш и детект сработает. Обход — найти и отключить саму проверку хеша.
- **Нативные проверки**: часть проверок в `.so`. Правка smali их не обойдёт — придётся патчить и нативную библиотеку.

## Шаг 6: находим артефакт практики

Среди строк DEX есть и наш артефакт. Достанем его:

```
$ strings -n 5 classes.dex | grep nto
nto{sm4l1_p4tch_r3turn_tru3}
```

## Что мы теперь знаем

- smali — текстовое представление байткода Dalvik; DEX — его бинарная форма.
- apktool разбирает и собирает APK; baksmali/smali работают с отдельными DEX.
- Минимальный обход — заменить тело метода на `const/4 v0, 0x1; return v0`.
- После правки APK нужно пересобрать, выровнять (`zipalign`) и подписать новым ключом.
- Ловушки: multidex, верификатор, проверка хеша DEX, нативные проверки.

## Квиз

Проверь себя.

```quiz
- question: "Что такое smali?"
  options:
    - "Текстовое представление байткода Dalvik"
    - "Формат картинок Android"
    - "Язык разметки интерфейса"
    - "Тип подписи APK"
  answer: 0
- question: "Как заставить метод всегда возвращать true в smali?"
  options:
    - "const/4 v0, 0x1; return v0"
    - "delete method"
    - "return null"
    - "nop"
  answer: 0
- question: "Почему после правки APK нужен новый ключ подписи?"
  options:
    - "Модификация меняет содержимое, и старая подпись перестаёт совпадать"
    - "Android требует два ключа"
    - "Ключ портится при сборке"
    - "Так быстрее устанавливается"
  answer: 0
- question: "Что делать, если проверка спрятана в нативном .so?"
  options:
    - "Патчить нативную библиотеку отдельно — правка smali её не обойдёт"
    - "Удалить APK"
    - "Переустановить Android"
    - "Игнорировать, smali всегда достаточно"
  answer: 0
```

## Куда дальше

Дальше — динамическая инструментация (Frida/Xposed/Zygisk), когда статической правки мало. Пока главное запомни: **smali-патч — это точечная правка байткода; всегда помни про подпись и про проверки целостности**.

## Где пригодится

- **Пентест мобильных приложений:** отключить защиты перед анализом.
- **Модификация приложений:** включить скрытые функции, убрать рекламу.
- **Анализ малвари:** вскрыть обфусцированные проверки и увидеть логику.
