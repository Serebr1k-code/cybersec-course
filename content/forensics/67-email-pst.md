---
id: forensics-email-pst
title: "PST/OST/EML/MSG: разбор почтовых хранилищ"
category: forensics
parent: forensics-email
difficulty: hard
order: 2
tags: [pst, ost, eml, msg, email, outlook, forensics]
prerequisites: [forensics-email]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Корпоративные расследования"
estimated_minutes: 50
summary: "Разбор почтовых архивов Outlook (PST/OST) и отдельных сообщений (EML/MSG): извлечение писем, вложений, заголовков, удалённых элементов и метаданных."
---
Почтовые архивы Outlook (PST/OST) и отдельные сообщения (EML/MSG) хранят переписку, вложения, календарь и контакты — важнейший источник в корпоративных расследованиях. Они содержат не только видимые письма, но и удалённые элементы, которые пользователь мог «стереть». Этот урок — про форматы, извлечение писем и вложений, разбор удалённых элементов.

## Форматы

| Формат | Что это | Инструмент |
|--------|---------|-----------|
| `.pst` | личное хранилище Outlook (POP/локально) | `libpff`, `readpst` |
| `.ost` | кэш Exchange (offline) | `libpff` |
| `.eml` | одно письмо (RFC 822/MIME) | `email`, `ripmime` |
| `.msg` | одно письмо Outlook (OLE) | `extract_msg`, `libpff` |
| `.mbox` | Unix-архив писем | `mb2md`, `email` |

PST/OST — это база на структуре B-tree в контейнере (не ESE, а собственный формат Microsoft). `libpff` разбирает его, включая удалённые элементы.

## PST/OST: извлечение

```bash
$ pffinfo archive.pst
PST file: archive.pst
Encryption: none
Message store type: pst
Number of items: 12453
# экспорт всех писем
$ pffexport -m all archive.pst -t out/
$ pffexport -m items archive.pst -t items/
$ pffexport -m attachments archive.pst -t att/
$ pffexport -m deleted archive.pst -t deleted/     # удалённые
```

`readpst` (из `libpst`) — альтернатива с выводом в mbox/eml:

```bash
$ readpst -o out archive.pst
$ readpst -D -o out archive.pst      # -D: включить удалённые
$ readpst -r -o out archive.pst      # рекурсивно по папкам
```

## Структура PST и удалённые элементы

PST содержит папки: Inbox, Sent Items, Drafts, **Deleted Items**, Calendar, Contacts. Особенно ценны:
- **Deleted Items** — письма, удалённые пользователем (но не «очищенные»).
- **Recoverable Items** — удалённые из Deleted Items (если retention включён).
- **Drafts** — незавершённые письма.
- **Sent Items** — что и кому отправлялось.

```bash
$ readpst -D -o out archive.pst
$ find out -path '*Deleted*' -name '*.eml' | head
$ find out -path '*Recoverable*' | head
```

Удалённые письма часто остаются в «пустых» областях и извлекаются `pffexport -m deleted`/`readpst -D`.

## EML/MSG: разбор

```bash
# EML: стандартный MIME
$ python3 -c "import email;m=email.message_from_file(open('mail.eml'));print(m['From'],m['Subject'])"
$ ripmime -i mail.eml -d eml_out/
# MSG: OLE
$ python3 -c "import extract_msg;m=extract_msg.Message('mail.msg');print(m.subject,m.sender);m.saveAttachments()"
# MSG через libpff
$ pffexport -m all mail.msg -t msg_out/
```

## Вложения и IOC

```bash
# извлечь вложения
$ pffexport -m attachments archive.pst -t att/
$ find att -type f -exec file {} \; | head
$ find att -type f -exec sha256sum {} \; > att_hashes.txt
# макросы в документах
$ python3 olevba.py att/*.docm 2>/dev/null | head
```

Все вложения хешируйте и проверяйте (VT/анализ), особенно `.docm`, `.xlsm`, `.pdf`, архивы.

## Хранение и юридические аспекты

PST/OST — персональные данные. Работайте по авторизации, фиксируйте цепочку хранения, экспортируйте только нужное, сохраняйте заголовки и метаданные (для атрибуции). Для отчёта: отправитель, получатель, тема, время, вложения с хешами.

## Разобранный пример

Дан `archive.pst`. Нужно найти удалённое письмо с вложением.

```bash
# 1. Инфо
$ pffinfo archive.pst | head
# 2. Экспорт, включая удалённые
$ pffexport -m deleted archive.pst -t deleted/
$ readpst -D -o out archive.pst
# 3. Поиск по теме/вложениям
$ grep -ri 'invoice\|password\|urgent' out/ | head
# 4. Вложения и хеши
$ pffexport -m attachments archive.pst -t att/
$ sha256sum att/* | head
# 5. Разбор подозрительного вложения
$ file att/invoice.docm && python3 olevba.py att/invoice.docm | head
```

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Инфо PST | `pffinfo` |
| Экспорт писем | `pffexport -m all` |
| Удалённые | `pffexport -m deleted`, `readpst -D` |
| Вложения | `pffexport -m attachments` |
| EML | `email`, `ripmime` |
| MSG | `extract_msg`, `libpff` |
| Хеши | `sha256sum` |

## Частые ошибки

- **Экспортировать без удалённых** — пропустите Deleted/Recoverable Items.
- **Забывать про вложения** — нагрузка обычно там.
- **Не хешировать вложения** — нет IOC.
- **Пропустить `Recoverable Items`** — там «дважды удалённое».
- **Читать PST вручную** — используйте `libpff`/`readpst`.
- **Игнорировать календарь/контакты** — тоже источник.

## Что дальше / решение

Конвейер: `pffinfo` (инфо) → `pffexport`/`readpst` (письма, включая удалённые) → `-m attachments` (вложения) → `file`/`sha256` → анализ вложений. Связка: `forensics-email` (заголовки/SPF), `forensics-office-macros` (макросы), `forensics-pdf`, `forensics-carving`.

## Восстановление повреждённых PST

PST может быть повреждён (обрыв записи, сбой Outlook). Инструменты восстановления:

```bash
# scanpst (Windows, встроен в Office) — восстановить PST
$ scanpst.exe archive.pst
# libpff устойчив к повреждениям и читает то, что уцелело
$ pffexport -m all broken.pst -t out/
# если файл обрезан — carve из unallocated
$ blkls -o 2048 disk.img | grep -aboP '\!BDN'      # сигнатура PST
$ dd if=disk.img of=carved.pst bs=1 skip=<offset> status=none
```

Сигнатура PST — `!BDN` (magic) в начале. Если PST удалён, его часто можно вырезать из нераспределённого пространства по этой сигнатуре (см. `forensics-carving`).

## Сводный чек-лист разбора почты

1. `pffinfo` — размер, число элементов, шифрование.
2. `pffexport -m all` — все письма; `-m deleted` — удалённые.
3. `readpst -D` — альтернативный экспорт с удалёнными.
4. Проверить папки Deleted Items / Recoverable Items.
5. `-m attachments` — вложения; `file` + `sha256sum`.
6. Разобрать подозрительные вложения (макросы/PDF).
7. Извлечь заголовки для атрибуции (`forensics-email`).
8. Зафиксировать IOC и цепочку хранения.

## Отличие PST/OST и юридические нюансы

`OST` — кэш Exchange; может содержать письма, которых нет в почтовом ящике (если кэш старый), и наоборот. При расследовании корпоративной почты часто нужны обе стороны (сервер Exchange + клиентский OST). `PST` — личный архив; может содержать переписку, удалённую с сервера. Учитывайте retention-политики: «удалённое» письмо может жить в Recoverable Items до истечения срока.

## Ограничения

- **Шифрование PST** (пароль) — без него не прочитать (ищите в памяти/реестре).
- **Повреждённые/обрезанные** файлы — часть писем утеряна.
- **Вложения** могут быть вложенными архивами — распаковывайте рекурсивно.
- **Кодировки** заголовков/тем — декодируйте (base64/quoted-printable).
- **Большие PST** (десятки ГБ) — экспорт долгий; фильтруйте по папкам.

## Краткое резюме

PST/OST и отдельные письма — центральный источник в корпоративных расследованиях: они содержат переписку, вложения, календарь и контакты, а также удалённые элементы. Ключ к полноте — экспорт **включая** Deleted Items и Recoverable Items (`pffexport -m deleted`, `readpst -D`). Вложения хешируйте и анализируйте отдельно (макросы/PDF/архивы). Для повреждённых PST используйте `scanpst` и `libpff`, для удалённых — carving по сигнатуре `!BDN`. Всегда фиксируйте цепочку хранения и учитывайте retention-политики.

## Квиз

```quiz
- question: "Какой формат — самостоятельный архив Outlook?"
  options:
    - "EML"
    - "PST"
    - "MSG"
    - "MBOX"
  answer: 1
- question: "Какая утилита извлекает письма и вложения из PST?"
  options:
    - "readpst"
    - "exiftool"
    - "binwalk"
    - "foremost"
  answer: 0
- question: "Что содержит заголовок Authentication-Results?"
  options:
    - "тело письма"
    - "результаты SPF/DKIM/DMARC"
    - "вложение"
    - "пароль"
  answer: 1
- question: "Почему нельзя открывать PST в Outlook на образе?"
  options:
    - "он станет меньше"
    - "Outlook модифицирует файл и изменит улики"
    - "он удалится"
    - "ничего не произойдёт"
  answer: 1
- question: "Где могут храниться удалённые письма?"
  options:
    - "в Deleted Items и Recoverable Items (dumpster)"
    - "в заголовке"
    - "в вложении"
    - "в MIME"
  answer: 0
```

## Где пригодится

- **CTF:** задачи с почтовым архивом и вложением-малварью.
- **DFIR:** анализ фишинга, переписки злоумышленника, утечек.
- **Корпоративные расследования:** доказательство переписки.
- **Анализ малвари:** извлечение вложений для YARA/VT.
- **Судебная экспертиза:** восстановление удалённой переписки.
