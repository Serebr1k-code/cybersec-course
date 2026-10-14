---
id: mobile-android-contentprovider-grant
title: 'URI-permission grants: временный доступ к файлам'
category: mobile
parent: mobile-android-data-surfaces
difficulty: hard
order: 1
tags: [android, contentprovider, uri, grant, fileprovider, permissions]
prerequisites: [mobile-android-fileprovider]
useful_for:
  - 'Пентест мобильных приложений (Android)'
  - 'Bug bounty Android'
  - 'CTF Mobile'
estimated_minutes: 40
summary: 'Как приложение через FLAG_GRANT_READ_URI_PERMISSION отдаёт другому доступ к content://, как этот grant утекает и почему его нельзя отозвать.'
lab:
  kind: shell
  title: 'Практика: аудит URI-grants'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, grants.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`grants.txt` — список выданных URI-grants.'
    - 'Найди grant, переданный постороннему пакету.'
    - 'Рядом с ним — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение отправляет файл «поделиться» другому приложению. Файл лежит в приватном каталоге, но
получатель его читает. Как это возможно без выдачи постоянного доступа?

## Наш пример: шаринг файла

В коде видим:

```java
Uri uri = FileProvider.getUriForFile(this, "com.example.fileprovider", file);
Intent share = new Intent(Intent.ACTION_SEND);
share.putExtra(Intent.EXTRA_STREAM, uri);
share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
startActivity(Intent.createChooser(share, "Share"));
```

`FLAG_GRANT_READ_URI_PERMISSION` — это **URI-permission grant**: временное разрешение на чтение
конкретного `content://`-URI. Получатель не получает доступ ко всему провайдеру — только к этому
одному файлу, и только пока живёт его задача.

## Шаг 1: что такое grant

Провайдер может не быть экспортированным, но приложение способно выдать точечный доступ к
конкретному URI. Это безопаснее, чем открывать весь провайдер. Но grant имеет свойства, которые
легко упустить: он привязан к **получателю** (пакету) и к **задаче**, и его можно передать
дальше.

## Шаг 2: как grant выдаётся и отзывается

Есть три способа: флагом в Intent (`FLAG_GRANT_*`), через `grantUriPermission(toPackage, uri,
mode)`, и через `ClipData`. Отозвать можно `revokeUriPermission`, но только если вы — владелец.
Проблема в том, что приложение-жертва часто не отзывает grant после использования, и доступ
живёт дольше, чем нужно.

## Шаг 3: утечка grant

Главная опасность — **передача grant дальше**. Получатель может положить URI в свой Intent и
отправить третьему приложению. Если флаг не ограничен, третье приложение тоже получит доступ.
Классический сценарий: приложение-обёртка получает URI и пересылает его в браузер, а браузер
открывает файл.

```bash
$ adb shell am start -a android.intent.action.VIEW \
    -d content://com.example.fileprovider/root/secret.txt \
    --grant-read-uri-permission
```

## Шаг 4: persistable grants

Существует особый вид — **persistable grant**:
`takePersistableUriPermission(uri, flags)`. Он сохраняется после перезагрузки и даёт доступ к
документу (SAF, DocumentsProvider) навсегда, пока не отозван. Если приложение берёт persistable
grant на чувствительный документ и не отзывает его, доступ остаётся на устройстве. В аудите
проверяйте, кто и на что взял persistable-доступ.

## Шаг 5: как аудировать

- Найти в коде `FLAG_GRANT_*`, `grantUriPermission`, `takePersistableUriPermission`.
- Посмотреть, не пересылается ли URI дальше без ограничения пакета.
- Проверить, отзывается ли grant после использования.
- Посмотреть `dumpsys activity providers` и grants.
- Проверить `file_paths.xml` FileProvider на слишком широкие пути.

## Шаг 6: защита

- Ограничивать grant конкретным пакетом (`Intent.setPackage`).
- Не добавлять `FLAG_GRANT_WRITE_URI_PERMISSION` без нужды.
- Отзывать grant после использования.
- Не выдавать persistable-доступ к чувствительным документам.
- Сужать пути в `file_paths.xml`.

## Что мы теперь знаем

- Grant даёт точечный доступ к одному URI.
- Его можно передать дальше и утечь.
- Persistable grant живёт после перезагрузки.
- Аудит: флаги, `grantUriPermission`, `file_paths.xml`.
- Защита: ограничение пакета, отзыв, сужение путей.

## Куда дальше

Мы разобрали grants. Дальше — autofill, где доступ к полям даёт сам пользователь.

## Шаг 7: как grant привязан к задаче

Grant живёт не бесконечно: он привязан к задаче (task) или к стеку активности получателя. Когда
получатель завершает работу, доступ исчезает. Именно поэтому важно понимать жизненный цикл: если
приложение-жертва держит grant на URI и передаёт его в долгоживущий сервис, доступ сохраняется
дольше. Проверить активные grants можно через `dumpsys activity providers` — там перечислены
выданные URI-доступы и их получатели.

## Шаг 8: ClipData как канал grant

Помимо `EXTRA_STREAM`, grant может передаваться через `ClipData`:

```java
Intent i = new Intent(Intent.ACTION_SEND);
i.setClipData(ClipData.newRawUri("file", uri));
i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
```

`ClipData` позволяет приложить несколько URI и grant-флагов. Если приложение формирует `ClipData`
из внешних данных, атакующий может подсунуть свой URI и получить доступ к чужим файлам. Это
разновидность «grant redirection» — по аналогии с intent redirection.

## Шаг 9: persistable grants и SAF

Storage Access Framework (SAF) даёт доступ к документам через `ACTION_OPEN_DOCUMENT`. Если
приложение берёт persistable-разрешение, оно может читать документ после перезагрузки. Ошибка —
брать persistable на широкий каталог (`DocumentsProvider` root), а не на один файл. Тогда
приложение (или утёкший URI) получает доступ ко всему дереву. В аудите проверяйте, на какой URI
взят persistable-доступ и не слишком ли он широк.

## Шаг 10: реальный кейс

Находка: приложение-мессенджер пересылало вложение в стороннее приложение-просмотрщик, добавляя
`FLAG_GRANT_READ_URI_PERMISSION` без `setPackage`. Просмотрщик мог сохранить URI и передать его
дальше любому приложению, которое тоже получало доступ к вложению. Так приватные файлы утекали за
пределы задуманного сценария. Рекомендация: ограничивать получателя и отзывать grant.

## Шаг 11: чек-лист

- Все места с `FLAG_GRANT_*` и `grantUriPermission`.
- Ограничен ли получатель пакетом.
- Есть ли `takePersistableUriPermission` и на что.
- Отзываются ли grants после использования.
- Не формируется ли `ClipData` из внешних данных.
- Насколько широки пути в `file_paths.xml`.

## Частые вопросы

**Можно ли отозвать чужой grant?** Только владелец провайдера может отзывать свои grants.

**Persistable grant переживает переустановку?** Нет, привязан к приложению и отзывается при
удалении/сбросе.

**Достаточно ли `exported="false"` на провайдере?** Для grant — да, но сам grant всё равно
выдаёт доступ, поэтому проверяйте флаги.

## Шаг 12: как читать данные через content://

Чтобы понять, что именно даёт grant, разберём, как работает провайдер. Провайдер — это компонент,
который отдаёт данные по URI вида `content://authority/path/id`. Доступ к нему идёт через
`ContentResolver`:

```bash
$ adb shell content query --uri content://com.example.provider/notes
Row: 0 _id=1, title=hello
```

Если провайдер экспортирован и не защищён разрешением, эта команда выполнится от имени shell и
вернёт данные. Если провайдер не экспортирован, прямой доступ невозможен — но grant, выданный
приложением, открывает конкретный URI. Поэтому в аудите важно различать: провайдер закрыт
(хорошо), но grants выдаются (проверяем, кому и куда).

## Шаг 13: полный список флагов grant

Флаги URI-доступа:

- `FLAG_GRANT_READ_URI_PERMISSION` — чтение конкретного URI.
- `FLAG_GRANT_WRITE_URI_PERMISSION` — запись.
- `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` — разрешает взять persistable-доступ.
- `FLAG_GRANT_PREFIX_URI_PERMISSION` — доступ ко всему поддереву URI (а не только к одному).

Опаснее всего комбинация WRITE + PREFIX: она даёт запись в целое поддерево. Если приложение
добавляет такие флаги к внешнему Intent, атакующий может подсунуть свой URI и получить широкий
доступ. В коде ищите `addFlags` с этими константами и проверяйте, ограничен ли получатель.

## Шаг 14: как проверять провайдер целиком

Аудит провайдера состоит из пяти шагов. Первый: `android:exported` — открыт ли он наружу. Второй:
`android:readPermission`/`writePermission` и их уровень. Третий: `android:grantUriPermissions` —
разрешено ли выдавать grants. Четвёртый: пути в `file_paths.xml` или в `<path-permission>`. Пятый:
сам код `query`/`insert` — не собирается ли SQL из аргументов (см.
`mobile-android-contentprovider-sql`). Все пять проверяются по манифесту и декомпилированному коду.

## Шаг 15: реальный кейс

Кейс: приложение-редактор документов открывало файл по `content://` и передавало URI в
приложение-просмотрщик без `setPackage`. Просмотрщик пересылал URI дальше, и любое приложение,
поймавшее этот Intent, читало документ. Так приватные файлы пользователя утекали за пределы
задуманного сценария. Рекомендации: ограничивать получателя (`setPackage`), не добавлять WRITE и
PREFIX без нужды, отзывать grant сразу после использования.

## Шаг 16: чек-лист

- `android:exported`, разрешения и `grantUriPermissions` у каждого провайдера.
- Все места с `FLAG_GRANT_*` в коде.
- Ограничен ли получатель пакетом.
- Persistable-доступы: на что и кому.
- Ширина путей и `path-permission`.
- SQL-сборка в `query`/`insert`.

## Частые вопросы

**Grant — это разрешение на весь провайдер?** Нет, только на конкретный URI (или поддерево, если
PREFIX).

**Можно ли выдать grant приложению, которого нет?** Нет, получатель должен быть установлен.

**Как узнать активные grants?** Через `dumpsys activity providers`.

## Шаг 17: как отзывать и проверять grants

Отзыв делается методом `revokeUriPermission(uri, modeFlags)`. Хорошая практика — выдавать grant
ровно на время операции и отзывать сразу после. Плохая — выдать grant и «забыть», оставив доступ
на всё время жизни задачи. Проверить, что доступ реально отозван, можно через
`dumpsys activity providers` — активные grants там перечислены. Если после завершения операции
grant всё ещё висит, это утечка, которую можно использовать при следующем запуске получателя.

## Шаг 18: FileProvider и его пути

FileProvider — стандартный способ отдать файл по `content://`. Он описывается в `file_paths.xml`:

```xml
<paths>
  <files-path name="files" path="."/>
  <cache-path name="cache" path="."/>
  <external-path name="ext" path="."/>
</paths>
```

Слишком широкий `path="."` означает, что grant на один URI открывает весь каталог. Если в каталог
попадают чувствительные файлы (токены, бэкапы), утечка становится серьёзной. В аудите проверяйте
ширину путей и что именно лежит в этих каталогах. Отдельно ищите `<root-path>` — он даёт доступ ко
всей файловой системе, что почти всегда ошибка.

## Шаг 19: итог

URI-permission grants — это точечная, но коварная поверхность: доступ выдаётся легко, а живёт
дольше, чем нужно, и легко передаётся дальше. Проверяйте флаги, ограничение получателя, ширину
путей и отзыв. Если grant на чувствительный файл уходит наружу без ограничения пакета — это
находка, за которую платят в bug bounty.

Запомните формулу риска: экспортированный провайдер + широкий grant + отсутствие отзыва = утечка.
Убирайте хотя бы один множитель — и риск падает.

## Квиз

Проверь себя.

```quiz
- question: Что даёт FLAG_GRANT_READ_URI_PERMISSION?
  options:
    - Постоянный root
    - Временный доступ к конкретному URI
    - Доступ ко всему провайдеру
    - Шифрование
  answer: 1
  explanation: Доступ точечный и временный.
- question: Чем опасна передача URI дальше?
  options:
    - Ничем
    - Третье приложение тоже получает grant
    - Он удаляется
    - Он шифруется
  answer: 1
  explanation: Если grant не ограничен пакетом, его можно переслать.
- question: Что делает takePersistableUriPermission?
  options:
    - Удаляет файл
    - Сохраняет доступ к URI после перезагрузки
    - Шифрует URI
    - Создаёт root
  answer: 1
  explanation: Persistable grant живёт, пока не отозван.
- question: Где смотреть конфиг FileProvider?
  options:
    - file_paths.xml
    - AndroidManifest
    - strings.xml
    - build.gradle
  answer: 0
  explanation: file_paths.xml описывает доступные пути.
- question: Как ограничить получателя grant?
  options:
    - Intent.setPackage
    - setType
    - setData
    - addCategory
  answer: 0
  explanation: setPackage ограничивает пакет-получатель.
```

## Где пригодится

- Аудит шаринга файлов и URI-доступа.
- Bug bounty: утечка grant.
- CTF Mobile: чтение файла через content://.
