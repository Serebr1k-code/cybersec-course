#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expand the 4 batch-1 mobile lessons to 1200+ real content words."""
import re, os

ROOT = '/home/Serebr1k/learning_tree'


def append(lesson_id, add):
    p = os.path.join(ROOT, 'content/mobile', lesson_id + '.md')
    txt = open(p, encoding='utf-8').read()
    m = re.search(r'^## Квиз\s*$', txt, re.MULTILINE)
    assert m, lesson_id
    txt = txt[:m.start()] + add.strip() + '\n\n' + txt[m.start():]
    open(p, 'w', encoding='utf-8').write(txt)
    print('expanded', lesson_id)


append('mobile-android-pendingintent', '''
## Шаг 7: как комбинируются флаги

Флаги — это битовая маска, и их часто пишут вместе:

```java
PendingIntent.getActivity(ctx, 0, i,
    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
```

Разберём каждый:

- `FLAG_UPDATE_CURRENT` — если такой PendingIntent уже существует, обновить его extra. Сам
  по себе он не создаёт уязвимость, но в паре с мутабельностью усложняет предсказание того,
  какие данные там окажутся.
- `FLAG_CANCEL_CURRENT` — отменить старый и создать новый. Полезно, чтобы не переиспользовать
  токен с устаревшими данными.
- `FLAG_ONE_SHOT` — токен сработает один раз. Не защищает от перехвата, но ограничивает
  повторное использование.
- `FLAG_NO_CREATE` — не создавать, вернуть `null`, если токена нет. Используется для проверок.

Важно: `FLAG_MUTABLE` и `FLAG_IMMUTABLE` взаимоисключающи, и если не указать ни один, система
на Android 12+ по умолчанию считает токен **иммутабельным** (с предупреждением в логах). Но
на старых версиях поведение было иным — поэтому в легаси-коде всё ещё встречаются токены без
явного флага, которые фактически мутабельны.

## Шаг 8: почему неявный Intent вообще попадает в систему

Резолвинг Intent — это отдельный механизм. Когда система получает неявный Intent, она
перебирает установленные приложения и их intent-filter'ы, чтобы найти совпадение. Если
совпадений несколько, пользователю показывают выбор (chooser), но для PendingIntent выбор
происходит **без** участия пользователя — по внутренним приоритетам. Атакующий этим
пользуется: он объявляет свой фильтр и, если его приоритет выше, получает вызов.

Есть ещё нюанс с `android:exported`. Даже Activity, не экспортированная для прямого вызова
извне, может быть целью PendingIntent, если у неё есть intent-filter и она помечена
`exported="true"`. Атакующий делает свою Activity экспортированной — это разрешено, — и она
становится кандидатом.

## Шаг 9: как автоматизировать поиск

Вручную просматривать весь smali неэффективно. На практике используют два подхода.

Первый — семантический поиск по коду через semgrep-правило:

```yaml
rules:
  - id: mutable-pendingintent
    languages: [java]
    pattern: PendingIntent.getActivity(..., PendingIntent.FLAG_MUTABLE)
    message: PendingIntent is mutable — check base intent is explicit
    severity: WARNING
```

Второй — статический анализ MobSF: он сам поднимает предупреждение о мутабельных PendingIntent
и показывает, какие Activity их используют. Но MobSF даёт сигнал, а не приговор: обязательно
проверяйте, есть ли `setPackage()`/`setComponent()` рядом.

## Шаг 10: типичные ошибки при анализе

- Считать, что `FLAG_MUTABLE` — всегда баг. Нет: если базовый Intent явный, мутабельность
  безопасна. Опасна именно пара «мутабельный + неявный».
- Игнорировать, что extra тоже утекают. Даже при явном получателе чувствительные данные в
  extra может прочитать тот, кому токен передан.
- Забывать про динамически регистрируемые получатели: `registerReceiver` тоже может принимать
  PendingIntent-подобные конструкции.
- Путать PendingIntent с обычным Intent: обычный Intent нельзя «выполнить от имени» другого
  приложения, а PendingIntent — можно, и именно в этом его сила и его риск.

## Шаг 11: что писать в отчёте

Формулировка находки должна включать: где создаётся токен (класс/метод), какой флаг
мутабельности, неявный ли базовый Intent, какое приложение может его перехватить и какие
данные при этом утекают. Плюс рекомендацию: `FLAG_IMMUTABLE`, а при необходимости
мутабельности — явный `setPackage()`. Для CTF-задач достаточно показать, что перехват
возможен, и извлечь данные — но и там полезно указать первопричину.
''')

append('mobile-android-accessibility', '''
## Шаг 7: конфигурация сервиса

Поведение Accessibility Service описывает XML-ресурс, указанный в `meta-data`. Типичный
`accessibility_config.xml`:

```xml
<accessibility-service
    android:accessibilityEventTypes="typeAllMask"
    android:accessibilityFeedbackType="feedbackGeneric"
    android:canRetrieveWindowContent="true"
    android:accessibilityFlags="flagDefault"/>
```

Ключевые атрибуты:

- `accessibilityEventTypes` — какие события получать. `typeAllMask` означает «все» — это
  избыточно и подозрительно для «помощника», которому хватило бы пары типов.
- `canRetrieveWindowContent="true"` — разрешает читать дерево окна. Без него кейлоггинг
  невозможен.
- `accessibilityFlags` — например, `flagRequestFilterKeyEvents` добавляет доступ к нажатиям
  клавиш на уровне ввода, что усиливает кейлоггер.

Чем шире маска событий и больше флагов, тем мощнее сервис и тем важнее проверить, зачем это
приложению.

## Шаг 8: отличие от обычного overlay

Можно спутать accessibility-абуз с `SYSTEM_ALERT_WINDOW` (permission для рисования поверх
других окон). Это разные механизмы:

- `SYSTEM_ALERT_WINDOW` даёт **рисовать** поверх экрана, но не читать содержимое чужого окна.
- Accessibility Service даёт **читать** и **действовать**, но рисует только ограниченно
  (через `TYPE_ACCESSIBILITY_OVERLAY`).

Сильнее всего они вместе: overlay показывает поддельный экран, а accessibility-сервис
считывает, что пользователь в него ввёл. В банковских троянах это стандартная связка.

## Шаг 9: как отличить легитимный сервис

Легитимный сервис обычно:

- обрабатывает узкий набор событий (например, только уведомления мессенджера);
- не читает текстовые поля паролей;
- не делает сетевых запросов с собранным текстом;
- не запрашивает `canRetrieveWindowContent` без необходимости.

Признаки абуза: `typeAllMask`, чтение `TYPE_VIEW_TEXT_CHANGED`, отправка текста на внешний
сервер, автоклик по кнопкам подтверждения, обфускация имён методов.

## Шаг 10: динамическая проверка

Помимо `settings get secure enabled_accessibility_services`, полезно посмотреть, какие
приложения вообще объявляют такие сервисы:

```bash
$ adb shell pm list packages -f | wc -l
$ adb shell dumpsys accessibility | head -40
```

`dumpsys accessibility` показывает зарегистрированные сервисы, их флаги и активные
подписки на события. Если сервис подписан на все типы событий, но приложение — «фонарик»,
это красный флаг.

## Шаг 11: правовой и этический аспект

Злоупотребление доступностью — это не просто технический баг, а часто признак **stalkerware**
и банковского фрода. При анализе важно не только доказать возможность, но и оценить,
использует ли приложение сервис легитимно. В отчёте это разделяют: «небезопасный дизайн»
против «явное злоупотребление». Для пентеста достаточно продемонстрировать, что сервис может
прочитать пароль или подтвердить операцию без ведома пользователя.
''')

append('mobile-android-fileprovider', '''
## Шаг 6: как устроен URI внутри

URI, который отдаёт FileProvider, выглядит так:

```
content://com.example.scanner.fileprovider/scans/invoice.pdf
```

Здесь `com.example.scanner.fileprovider` — authority из манифеста, `scans` — псевдоним из
`file_paths.xml`, `invoice.pdf` — относительный путь внутри каталога `scans/`. Провайдер
склеивает корень (`files-path` → `/data/data/<pkg>/files/`) с подкаталогом и именем файла,
затем проверяет, что результат остался внутри корня.

Именно эта проверка и ломается, когда конфиг слишком широкий. Если корень — `/`, то «внутри
корня» означает «где угодно в системе».

## Шаг 7: сценарии с grant

`FLAG_GRANT_READ_URI_PERMISSION` при выдаче Intent даёт получателю разовое право прочитать
конкретный URI. Возникают три сценария злоупотребления:

1. **Приложение передаёт grant атакующему.** Жертва вызывает экспортированную Activity
   атакующего с флагом grant; атакующий читает URI.
2. **Атакующий подставляет свой URI.** Экспортированный компонент жертвы принимает URI извне
   и передаёт его дальше с grant — а URI ведёт в `root-path`.
3. **URI переиспользуется.** Grant живёт до перезагрузки; если URI записан в лог или
   clipboard, право можно применить позже.

## Шаг 8: инструменты проверки

Распаковка и извлечение конфигов:

```bash
$ apktool d app.apk -o app_dec
$ find app_dec/res/xml -name '*file*paths*' -exec cat {} \\;
```

Автоматизированный поиск grant-цепочек:

```bash
$ grep -rn "FLAG_GRANT_READ_URI_PERMISSION\\|setDataAndType\\|startActivity" app_dec/smali/
```

Если экспортированная Activity принимает `Intent.getData()` и пробрасывает его в
`startActivity` с grant-флагом — это кандидат в находку. Проверяем, какой authority и какой
псевдоним он использует.

## Шаг 9: крайние случаи

- Провайдер может быть не `FileProvider`, а кастомным наследником `ContentProvider` с похожей
  логикой — тогда фильтрации `..` может не быть вовсе.
- На старых Android (до 7) `file://` ещё работал, и там traversal был тривиальным.
- Некоторые приложения отдают через провайдер **свои** внутренние БД — тогда утекают токены
  и сессии, а не только пользовательские файлы.
- Кэш-каталог (`cache-path`) часто содержит временные копии, которые приложение считает
  удалёнными.

## Шаг 10: рекомендации

Минимальный безопасный конфиг: отдельный подкаталог под каждый тип файла, никаких `root-path`
и `external-path path="."`. Если файл отдаётся наружу — только по явному URI, выданному через
`FileProvider.getUriForFile()`, и только с `FLAG_GRANT_READ_URI_PERMISSION`. В коде — проверка
`getCanonicalPath()` на префикс разрешённого корня перед `openFile`. Для отчёта достаточно
показать, какой именно файл вне задуманного каталога становится доступен и по какому пути.
''')

append('mobile-android-contentprovider-sql', '''
## Шаг 7: как провайдер вообще строится

Content Provider наследуется от `android.content.ContentProvider` и реализует `query`,
`insert`, `update`, `delete`, `getType`. Внутри обычно лежит `SQLiteDatabase`. Правильный
вариант — `SQLiteQueryBuilder`:

```java
SQLiteQueryBuilder b = new SQLiteQueryBuilder();
b.setTables("notes");
b.setStrict(true);              // запрещает произвольные имена таблиц
b.setProjectionMap(PROJECTION); // белый список колонок
return b.query(db, projection, selection, selectionArgs, null, null, sortOrder);
```

`setStrict(true)` и `setProjectionMap` — это ровно те меры, которых не хватает уязвимому
провайдеру из нашего примера. Если их нет, а `selection` конкатенируется — ждите инъекцию.

## Шаг 8: сколько колонок и как это узнать

Для `UNION SELECT` нужно совпадение числа колонок. Определяют его по `ORDER BY`:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1 ORDER BY 1"
Row: ...
$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1 ORDER BY 3"
Row: ...
$ adb shell content query --uri content://com.example.notes.provider/notes --where "1=1 ORDER BY 4"
Error: no such column: 4
```

Ошибка на `ORDER BY 4` означает, что колонок три. Дальше `UNION SELECT a,b,c` даёт ровно три
колонки и не падает.

## Шаг 9: слепая инъекция

Если провайдер не возвращает данные (например, только `insert`/`update`), инъекция остаётся
**слепой**. Тогда используют булевы условия или тайминги:

```bash
$ adb shell content query --uri content://com.example.notes.provider/notes \\
    --where "title='x' AND (SELECT substr(password,1,1) FROM users)='a'"
```

Разное поведение при истинном и ложном условии позволяет побайтово вытащить значение. В
SQLite удобен `randomblob()` для задержки, но в Android тайминги менее надёжны, поэтому чаще
используют булев вариант.

## Шаг 10: инъекция не только в query

`insert` может вставлять значения из `ContentValues` — они параметризуются, но **имена
колонок** иногда конкатенируются. `update` и `delete` повторяют те же точки, что и `query`.
Отдельный класс — инъекция в `sortOrder` через `ORDER BY (SELECT ...)`, которая позволяет
вытаскивать данные по одной ячейке.

## Шаг 11: как эксплуатируют из другого приложения

`adb` — только для проверки. В реальной атаке вредоносное приложение вызывает
`getContentResolver().query(...)` напрямую. Если провайдер экспортирован или защищён
тривиальным permission'ом, инъекция доступна без прав. Поэтому в отчёте важно указать
`android:exported` и permission провайдера: это определяет реальный радиус поражения.

## Шаг 12: рекомендации

- Всегда `selectionArgs` вместо конкатенации.
- `SQLiteQueryBuilder.setStrict(true)` + `setProjectionMap`.
- Белый список значений для `sortOrder`.
- `android:exported="false"` и защита permission'ом, если провайдер нужен только своему
  приложению.
- Не логировать SQL-запросы с пользовательскими данными.
''')

print('done')
