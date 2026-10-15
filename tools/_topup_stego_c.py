#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_topup_stego_c.py — finisher for jpegxr/json/macho + markdown, odf."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _topup_gap

S = {
    'stego-jpegxr': [
        ('## Практика: читаем тег вручную',
         'Разберём конкретный тег. Пусть в каталоге есть запись `tag=0x8000, type=1(BYTE), '
         'count=32, offset=0x120`. Это нестандартный тег: он ссылается на 32 байта по смещению '
         '`0x120`. Читаем их и проверяем, что там.\n\n'
         '```python\n'
         'import struct\n'
         'd = open("image.jxr","rb").read()\n'
         'assert d[:2] == b"II"          # little-endian TIFF-подобный\n'
         'ifd_off = struct.unpack_from("<I", d, 4)[0]\n'
         'n = struct.unpack_from("<H", d, ifd_off)[0]\n'
         'for i in range(n):\n'
         '    base = ifd_off + 2 + i*12\n'
         '    tag, typ, cnt, val = struct.unpack_from("<HHII", d, base)\n'
         '    print(hex(tag), typ, cnt, hex(val))\n'
         '```\n\n'
         'Если тег нестандартный и его данные содержат читаемый текст или флаг — это канал. '
         'Именно так разбирают JPEG XR вручную, когда `exiftool` не показывает нужный тег.'),
        ('## Сравнение с TIFF и защита',
         'JPEG XR наследует TIFF-структуру каталога, но не все TIFF-инструменты его понимают '
         '(другой кодек). Поэтому для метаданных используй `exiftool`, а для структуры — ручной '
         'парсер. Защита от сокрытия в JPEG XR — та же, что и для любых контейнеров с '
         'расширяемыми метаданными: нормализовать файл (пере-сохранить без лишних тегов), '
         'проверять нестандартные теги и аномальные размеры, валидировать структуру.\n\n'
         'Практический вывод: любой формат с каталогом метаданных (TIFF, JPEG XR, PNG-чанки, '
         'HEIF-боксы) даёт канал сокрытия. Поэтому при форензике проверяют не только пиксели, '
         'но и метаданные — часто именно там лежит ответ.'),
    ],
    'stego-json-whitespace': [
        ('## Практика: извлекаем и нормализуем',
         'Полный цикл на файле `data.json`. Шаг первый — проверить валидность: `python3 -m '
         'json.tool data.json`. Шаг второй — показать невидимые символы: `cat -A data.json`. '
         'Шаг третий — извлечь отступы и собрать биты. Шаг четвёртый — проверить результат.\n\n'
         '```bash\n'
         'python3 -m json.tool data.json > /dev/null && echo valid\n'
         'cat -A data.json | head -5\n'
         'python3 - <<PY\n'
         'bits = ""\n'
         'for line in open("data.json"):\n'
         '    ind = len(line) - len(line.lstrip(" "))\n'
         '    if ind in (1,2): bits += "0" if ind==1 else "1"\n'
         'print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))\n'
         'PY\n'
         '```\n\n'
         'Шаг пятый — если биты не сложились в текст, попробуй другой канал: хвостовые пробелы, '
         'порядок ключей, Unicode-escape.'),
        ('## Итог по JSON',
         'JSON — удобный канал сокрытия из-за избыточности пробелов и неопределённого порядка '
         'ключей. Каналы: отступы, хвостовые пробелы, порядок ключей, дубли, форма чисел, '
         'Unicode-escape, BOM. Инструменты: `python3`, `jq`, `cat -A`, `diff` с нормализацией. '
         'Ключ — нормализовать файл и сравнить с исходным: разница покажет скрытое.'),
    ],
    'stego-macho': [
        ('## Практика: разбор fat binary',
         'Universal (fat) binary содержит несколько архитектур. Заголовок — `0xCAFEBABE` '
         '(big-endian), затем число архитектур и таблица записей: `cputype`, `cpusubtype`, '
         '`offset`, `size`, `align`.\n\n'
         '```bash\n'
         'lipo -info bin\n'
         'python3 - <<PY\n'
         'import struct\n'
         'd = open("bin","rb").read()\n'
         'if d[:4] == b"\\xca\\xfe\\xba\\xbe":\n'
         '    n = struct.unpack_from(">I", d, 4)[0]\n'
         '    for i in range(n):\n'
         '        cputype, cpusub, off, size, al = struct.unpack_from(">iiIII", d, 8+i*20)\n'
         '        print(hex(cputype), "off", hex(off), "size", size)\n'
         'PY\n'
         '```\n\n'
         'Если `offset+size` выходит за пределы файла или размер аномален — канал. Каждую '
         'архитектуру можно вырезать (`lipo -thin`) и разбирать отдельно; неиспользуемая '
         'архитектура иногда несёт данные.'),
        ('## Итог по Mach-O',
         'Mach-O: заголовок + load-команды (аналог program headers) + сегменты/секции. Каналы: '
         'overlay, `LC_NOTE`, padding, неиспользуемые секции/символы, fat-таблица. Инструменты: '
         '`otool`, `jtool2`, `lipo`, `nm`, `binwalk`. Подход тот же, что для ELF: сверху вниз, с '
         'поиском аномалий размеров.'),
    ],
    'stego-markdown': [
        ('## Полный разбор Markdown-каналов',
         'Markdown даёт несколько каналов. Первый — **HTML-комментарии** `<!-- ... -->`: они не '
         'отображаются, но лежат в тексте. Второй — **reference-style ссылки**: '
         '`[text][ref]` с определением `[ref]: url` в конце; порядок и содержимое определений '
         'могут нести данные. Третий — **хвостовые пробелы**: два пробела в Markdown означают '
         'перенос строки, поэтому их можно использовать как биты (1 пробел = 0, 2 = 1).\n\n'
         '```bash\n'
         'grep -n "<!--" README.md\n'
         'grep -nE "\\[.*\\]:\\s*\\S+" README.md | tail\n'
         'grep -nE " +$" README.md | head\n'
         '```\n\n'
         'Четвёртый — **alt-текст и title картинок**: `![alt](url "title")`; alt и title могут '
         'нести произвольные строки. Пятый — **URL картинок**: в query-параметрах или имени '
         'файла прячут данные. Шестой — **кодировки в ссылках** (percent-encoding, IDN).\n\n'
         'Седьмой — **невидимые Unicode-символы** (zero-width, tags) прямо в тексте. Восьмой — '
         '**порядок элементов списка** и отступы. Все каналы работают, потому что Markdown '
         'рендерится в HTML, а лишнее отбрасывается.'),
        ('## Извлечение и инструменты',
         'Извлечение — по каналу. Комментарии: `grep -o "<!--.*-->"`. Хвостовые пробелы: скрипт, '
         'читающий каждую строку и считающий trailing-пробелы. Alt/title: регекс по '
         '`!\\[[^]]*\\]\\([^)]*\\)`. Невидимые символы: проверка кодов Unicode (U+200B–U+200D, '
         'U+FEFF, U+E0000–U+E007F).\n\n'
         '```python\n'
         'import re\n'
         'txt = open("README.md", encoding="utf-8").read()\n'
         'for m in re.findall(r"<!--(.*?)-->", txt, re.S):\n'
         '    print("comment:", m)\n'
         'zw = [c for c in txt if c in "\\u200b\\u200c\\u200d\\ufeff"]\n'
         'print("zero-width count:", len(zw))\n'
         '```\n\n'
         'Инструменты: `grep`, `sed`, `python3`, `cat -A` (показать невидимое), `xxd`. Для '
         'системного поиска невидимых символов — скрипт, перебирающий коды. Типичные ошибки: '
         'смотреть отрендеренный Markdown (там каналы исчезают) вместо исходного файла; '
         'игнорировать reference-ссылки; не проверять Unicode.'),
    ],
    'stego-odf': [
        ('## Полный разбор ODF',
         'ODF (ODT/ODS/ODP) — ZIP-контейнер. Структура: `mimetype` (первый, несжатый), '
         '`META-INF/manifest.xml`, `content.xml` (содержимое), `styles.xml`, `meta.xml` '
         '(метаданные), `settings.xml`, `Pictures/`, `Thumbnails/`.\n\n'
         '```bash\n'
         'unzip -l doc.odt\n'
         'unzip -o doc.odt -d odt/\n'
         'cat odt/meta.xml | python3 -m xml.dom.minidom | head -40\n'
         '```\n\n'
         'Каналы сокрытия: первый — **пользовательские поля в `meta.xml`** '
         '(`<meta:user-defined>`) — прямое место для данных. Второй — **файлы вне манифеста**: '
         'как в EPUB, файл в архиве, не упомянутый в `META-INF/manifest.xml`, игнорируется. '
         'Третий — **комментарии** в `content.xml`. Четвёртый — **невидимый текст** (белый, '
         '`font-size:0`, скрытый слой). Пятый — **`Thumbnails/`**: превью может отличаться от '
         'содержимого (или содержать данные).'),
        ('## Извлечение и инструменты',
         '```bash\n'
         'unzip -l doc.odt | grep -viE "content|styles|meta|settings|manifest|mimetype"\n'
         'grep -rniE "nto\\{|flag|secret" odt/ | head\n'
         'grep -n "user-defined" odt/meta.xml\n'
         '```\n\n'
         'Сравни список файлов с манифестом (`META-INF/manifest.xml`): расхождение — канал. '
         'Проверь `content.xml` на комментарии и невидимые элементы. Инструменты: `unzip`, '
         '`zipinfo -v` (комментарии архива), `exiftool`, `python3` + XML-парсер, `binwalk` '
         '(вложенность).\n\n'
         'ODF близок к OOXML (DOCX/XLSX/PPTX) по принципу: ZIP + XML + манифест. Освоив один, '
         'разбираешь остальные. Ключевое отличие — свои имена файлов и пространства имён XML, '
         'но логика «файлы вне манифеста и метаданные» одна и та же.'),
    ],
}

if __name__ == '__main__':
    _topup_gap.apply(S, 'stego')
