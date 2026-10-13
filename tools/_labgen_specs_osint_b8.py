# Batch OSINT-B8: 12 console-friendly osint hands-on lessons.
# Fixtures are captured REAL tool formats (Shodan/Censys/FOFA CLI+API, Discord
# API, Mastodon API, VK API, Reddit JSON, Google News RSS, GDELT, psbdmp,
# t.me public preview, Tor onion leak-site HTML). One real JPEG (EXIF
# UserComment) backs the webcam frame step.
import base64
import hashlib
import os

B8 = '/tmp/labgen/osint_b8'
WD = '/home/student/task'
CHECK = "grep -q 'nto{' answer.txt"

# --- real binary fixture (webcam frame) -------------------------------------
with open(os.path.join(B8, 'cam.jpg'), 'rb') as _f:
    _CAM = _f.read()
CAM_B64 = base64.b64encode(_CAM).decode()
CAM_SHA = hashlib.sha256(_CAM).hexdigest()


def _dir(p):
    return {'path': p, 'type': 'dir'}


def _f(p, t):
    return {'path': p, 'text': t}


def _b(p, b64, mode='644'):
    return {'path': p, 'b64': b64, 'mode': mode}


def _lab(id, title, files, hints, flag, fs, tools, toolset=None, extra=None):
    spec = {
        'id': id, 'category': 'osint', 'title': title,
        'toolset': toolset or ['core', 'curl', 'jq'],
        'workdir': WD, 'files': files,
        'check': CHECK, 'hints': hints,
        'expect': {'file': f'{WD}/answer.txt', 'contains': flag},
        'fs': fs, 'tools': tools,
    }
    return spec


SPECS = []

# ---------------------------------------------------------------- 1. shodan-dorks
SPECS.append(_lab(
    'osint-shodan-dorks', 'Практика: от фильтра Shodan к баннеру',
    ['task.md'],
    ['Начни с запроса по организации: `shodan search --fields ip_str,port,product,version \'org:"Acme" port:22\' > acme_ssh.json`.',
     'Разбери результат: `jq -r \'.[] | "\\(.ip_str)\\t\\(.product) \\(.version)"\' acme_ssh.json`.',
     'Самый старый хост — `203.0.113.15`. Смотри полный баннер: `shodan host 203.0.113.15`.',
     'В заголовке nginx на 80/tcp зашит внутренний маркер `nto{...}`. Запиши его в `answer.txt` и набери `check`.'],
    'nto{sh0d4n_b4nn3r_r3v34l5_t0k3n}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: от фильтра Shodan к баннеру\n\n'
        'Организация `Acme`. Найди её SSH-серверы через Shodan и определи, какой из них старый.\n\n'
        '1. Запрос по организации (сохрани ответ):\n'
        '   `shodan search --fields ip_str,port,product,version \'org:"Acme" port:22\' > acme_ssh.json`\n'
        '2. Разбери JSON:\n'
        '   `jq -r \'.[] | "\\(.ip_str)\\t\\(.product) \\(.version)"\' acme_ssh.json`\n'
        '3. Устаревший хост (`203.0.113.15`, OpenSSH 7.4) изучи целиком: `shodan host 203.0.113.15`.\n'
        '4. В баннере есть внутренний маркер `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n')],
    {'shodan': {
        'help': 'shodan search|host — поисковик баннеров (эмуляция реального формата)',
        'cases': [
            {'match': 'search.*org', 'example': 'shodan search --fields ip_str,port,product,version \'org:"Acme" port:22\'',
             'output': '[\n  {"ip_str": "203.0.113.10", "port": 22, "product": "OpenSSH", "version": "8.9"},\n  {"ip_str": "203.0.113.15", "port": 22, "product": "OpenSSH", "version": "7.4"},\n  {"ip_str": "198.51.100.7", "port": 22, "product": "OpenSSH", "version": "9.3"}\n]\n'},
            {'match': 'host\\s+203\\.0\\.113\\.15', 'example': 'shodan host 203.0.113.15',
             'output': '203.0.113.15\nHostnames: ssh.acme.example\nCountry:   United States\nOrganization: Acme\nPorts: 22, 80\n  22/tcp OpenSSH 7.4 (protocol 2.0)\n  80/tcp nginx 1.18.0 (title: "Acme Intranet - build nto{sh0d4n_b4nn3r_r3v34l5_t0k3n}")\n'},
        ],
        'fallback': 'shodan: в этой лабе доступны `search ... org:"Acme"` и `host 203.0.113.15`.\n'}},
     extra=None,
     ))

# add jq to shodan-dorks toolset (separate to keep call readable)
SPECS[-1]['tools']['jq'] = {
    'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
    'cases': [
        {'match': 'ip_str', 'example': "jq -r '.[] | ...' acme_ssh.json",
         'output': '203.0.113.10\tOpenSSH 8.9\n203.0.113.15\tOpenSSH 7.4\n198.51.100.7\tOpenSSH 9.3\n'},
    ],
    'fallback': 'jq: в этой лабе поддерживается только фильтр по `.ip_str`.\n',
}

# ---------------------------------------------------------------- 2. webcams
SPECS.append(_lab(
    'osint-webcams', 'Практика: кадр с открытой камеры',
    ['task.md', 'cam.jpg'],
    ['Найди камеры: `shodan search --fields ip_str,port,product \'webcam country:RU has_screenshot:true\'`.',
     'Определи поток кандидата `203.0.113.44`: `ffprobe -rtsp_transport tcp -v error -show_entries stream=codec_name,width,height "rtsp://203.0.113.44:554/Streaming/Channels/101"`.',
     'Снятый кадр `cam.jpg` разбери метаданными: `exiftool cam.jpg`.',
     'В поле `User Comment` — точка геолокации `nto{...}`. Запиши её в `answer.txt` и набери `check`.'],
    'nto{c4m_g30l0c4t3d_0n3_fr4m3}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: кадр с открытой камеры\n\n'
        'IP `203.0.113.44` — камера Hikvision. Нужно подтвердить, что она реальна, и снять один кадр.\n\n'
        '1. Поиск камер с включённым скриншотом в стране:\n'
        '   `shodan search --fields ip_str,port,product \'webcam country:RU has_screenshot:true\'`\n'
        '2. Проверь поток, не скачивая видео:\n'
        '   `ffprobe -rtsp_transport tcp -v error -show_entries stream=codec_name,width,height "rtsp://203.0.113.44:554/Streaming/Channels/101"`\n'
        '3. Кадр уже сохранён как `cam.jpg`. Прочитай метаданные: `exiftool cam.jpg`.\n'
        '4. В поле `User Comment` зашита точка геолокации — маркер `nto{...}`. Запиши в `answer.txt` и набери `check`.\n'),
     _b(f'{WD}/cam.jpg', CAM_B64)],
    {'shodan': {
        'help': 'shodan search — поисковик баннеров (эмуляция реального формата)',
        'cases': [
            {'match': 'webcam', 'example': "shodan search --fields ip_str,port,product 'webcam country:RU has_screenshot:true'",
             'output': '203.0.113.44  554   Hikvision IP Camera\n198.51.100.9  8080  Dahua\n'},
        ],
        'fallback': 'shodan: в этой лабе доступен только запрос `webcam country:RU has_screenshot:true`.\n'},
     'ffprobe': {
        'help': 'ffprobe [опции] <URL> — метаданные потока (эмуляция реального формата)',
        'cases': [
            {'match': 'rtsp', 'example': 'ffprobe -rtsp_transport tcp -v error -show_entries stream=codec_name,width,height "rtsp://203.0.113.44:554/Streaming/Channels/101"',
             'output': '[STREAM]\ncodec_name=h264\nwidth=1920\nheight=1080\n[/STREAM]\n'},
        ],
        'fallback': 'ffprobe: в этой лабе доступен только поток rtsp://203.0.113.44:554/Streaming/Channels/101.\n'},
     'exiftool': {
        'help': 'exiftool <файл> — метаданные изображения (эмуляция реального вывода)',
        'cases': [
            {'match': 'cam\\.jpg', 'example': 'exiftool cam.jpg',
             'output': 'ExifTool Version Number         : 13.10\n'
                       'File Name                       : cam.jpg\n'
                       'File Type                       : JPEG\n'
                       'File Type Extension             : jpg\n'
                       'MIME Type                       : image/jpeg\n'
                       'Image Width                     : 64\n'
                       'Image Height                    : 64\n'
                       'Exif Byte Order                 : Big-endian (Motorola, MM)\n'
                       'Date/Time Original              : 2026:10:11 14:22:03\n'
                       'GPS Position                    : 55 deg 45\' 21.00" N, 37 deg 37\' 4.00" E\n'
                       'User Comment                    : RTSP frame from 203.0.113.44 geolocated: nto{c4m_g30l0c4t3d_0n3_fr4m3}\n'},
        ],
        'fallback': 'exiftool: в этой лабе доступен только `exiftool cam.jpg`.\n'},
     'sha256sum': {
        'help': 'sha256sum <файл> — контрольная сумма (эмуляция реального вывода)',
        'cases': [
            {'match': 'cam\\.jpg', 'example': 'sha256sum cam.jpg',
             'output': f'{CAM_SHA}  cam.jpg\n'},
        ],
        'fallback': 'sha256sum: в этой лабе доступен только `sha256sum cam.jpg`.\n'}},
    ))

# ---------------------------------------------------------------- 3. search-operators
SPECS.append(_lab(
    'osint-search-operators', 'Практика: дорк → бэкап админки',
    ['task.md'],
    ['Домен `example.com`. Дорк по админкам: `googler --json -n 20 "site:example.com inurl:admin" > dork1.json`.',
     'Дорк по листингам: `googler --json -n 20 "site:example.com intitle:\\"index of\\"" > dork2.json`.',
     'Открой найденный каталог `https://example.com/admin/backup/`, затем бэкап конфига: `curl -s "https://example.com/admin/backup/config.php.bak" > backup.txt`.',
     'Внутри бэкапа строка с `nto{...}`. Запиши её в `answer.txt` и набери `check`.'],
    'nto{d0rk3d_4dm1n_b4ckup_l34k}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: от дорка к бэкапу админки\n\n'
        'Домен `example.com`. Поисковик проиндексировал служебные страницы — их надо подтвердить.\n\n'
        '1. Дорк по админ-разделам: `googler --json -n 20 "site:example.com inurl:admin" > dork1.json`\n'
        '2. Дорк по листингам каталогов: `googler --json -n 20 "site:example.com intitle:\\"index of\\"" > dork2.json`\n'
        '3. Открой каталог: `curl -s "https://example.com/admin/backup/" > listing.html`\n'
        '4. Скачай бэкап конфига: `curl -s "https://example.com/admin/backup/config.php.bak" > backup.txt`\n'
        '5. Найди маркер: `grep nto backup.txt`. Запиши `nto{...}` в `answer.txt` и набери `check`.\n')],
    {'googler': {
        'help': 'googler [--json] -n <N> <дорк> — поиск Google из CLI (эмуляция)',
        'cases': [
            {'match': 'inurl:admin', 'example': 'googler --json -n 20 "site:example.com inurl:admin"',
             'output': '[\n  {"url": "https://example.com/admin/login.php", "title": "Admin Login"},\n  {"url": "https://example.com/admin/backup/", "title": "Index of /admin/backup"}\n]\n'},
            {'match': 'index of', 'example': 'googler --json -n 20 "site:example.com intitle:\\"index of\\""',
             'output': '[\n  {"url": "https://example.com/admin/backup/", "title": "Index of /admin/backup"},\n  {"url": "https://example.com/files/", "title": "Index of /files"}\n]\n'},
        ],
        'fallback': 'googler: в этой лабе доступны дорки `inurl:admin` и `intitle:"index of"` по site:example.com.\n'},
     'curl': {
        'help': 'curl [-s] <URL> — выгрузка (эмуляция реального формата)',
        'cases': [
            {'match': 'config\\.php\\.bak', 'example': 'curl -s https://example.com/admin/backup/config.php.bak',
             'output': '<?php\n// db\n$DB_HOST = "db.internal.example.com";\n$DB_USER = "svc_admin";\n$DB_PASS = "Adm1n!Backup2024";\n// deploy marker\ndefine("DEPLOY_TOKEN", "nto{d0rk3d_4dm1n_b4ckup_l34k}");\n?>\n'},
            {'match': 'admin/backup', 'example': 'curl -s https://example.com/admin/backup/',
             'output': '<!DOCTYPE HTML><html><head><title>Index of /admin/backup</title></head>\n<body><h1>Index of /admin/backup</h1>\n<a href="config.php.bak">config.php.bak</a>\n<a href="db-2024.sql.gz">db-2024.sql.gz</a>\n</body></html>\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только /admin/backup/ и /admin/backup/config.php.bak.\n'}},
    ))

# ---------------------------------------------------------------- 4. phone
SPECS.append(_lab(
    'osint-phone', 'Практика: номер → оператор → корреляция',
    ['task.md', 'phone.py'],
    ['Нормализуй номер скриптом: `python3 phone.py`.',
     'Проверь мессенджер: `curl -sI "https://wa.me/79165551122"`.',
     'Найди номер в открытых текстах: `googler --json -n 10 "79165551122"`.',
     'Открой найденный форум-пост: `curl -s "https://forum.example.net/thread/4821" > post.html`, затем `grep nto post.html` — там ник и маркер `nto{...}`.'],
    'nto{ph0n3_t0_us3rn4m3_c0rr3l4t3d}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: номер → оператор → корреляция\n\n'
        'Дан только номер `8 916 555-11-22`. Восстанови профиль.\n\n'
        '1. Нормализация и оператор: `python3 phone.py`\n'
        '2. Проверка мессенджера (только заголовок): `curl -sI "https://wa.me/79165551122"`\n'
        '3. Поиск номера в открытых текстах: `googler --json -n 10 "79165551122"`\n'
        '4. Открой найденный пост: `curl -s "https://forum.example.net/thread/4821" > post.html`\n'
        '5. Найди маркер: `grep nto post.html`. Запиши `nto{...}` в `answer.txt` и набери `check`.\n'),
     _f(f'{WD}/phone.py',
        'import phonenumbers\n'
        'from phonenumbers import carrier, geocoder\n\n'
        'n = phonenumbers.parse("8 916 555-11-22", "RU")\n'
        'print(phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164))\n'
        'print(phonenumbers.is_valid_number(n))\n'
        'print(phonenumbers.region_code_for_number(n))\n'
        'print(carrier.name_for_number(n, "ru"))\n'
        'print(geocoder.description_for_number(n, "ru"))\n')],
    {'python3': {
        'help': 'python3 <скрипт> — эмуляция запуска (вывод захвачен из реального phonenumbers)',
        'cases': [
            {'match': 'phone\\.py', 'example': 'python3 phone.py',
             'output': '+79165551122\nTrue\nRU\nПАО «МегаФон»\nМосква и Московская область\n'},
        ],
        'fallback': 'python3: в этой лабе доступен только `python3 phone.py`.\n'},
     'curl': {
        'help': 'curl [-sI|-s] <URL> — проверка/выгрузка (эмуляция реального формата)',
        'cases': [
            {'match': 'wa\\.me', 'example': 'curl -sI https://wa.me/79165551122',
             'output': 'HTTP/2 200\ncontent-type: text/html; charset=utf-8\nlocation: https://wa.me/79165551122\n'},
            {'match': 'forum', 'example': 'curl -s https://forum.example.net/thread/4821',
             'output': '<html><body><h1>Продам серверное железо</h1>\n<p>Связь: +7 916 555-11-22, ник @ivan_dev</p>\n<p>Профиль: <a href="https://github.com/ivan-dev">github.com/ivan-dev</a></p>\n<!-- contact-token: nto{ph0n3_t0_us3rn4m3_c0rr3l4t3d} -->\n</body></html>\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только wa.me/79165551122 и forum.example.net/thread/4821.\n'},
     'googler': {
        'help': 'googler [--json] -n <N> <запрос> — поиск Google из CLI (эмуляция)',
        'cases': [
            {'match': '79165551122', 'example': 'googler --json -n 10 "79165551122"',
             'output': '[\n  {"url": "https://forum.example.net/thread/4821", "title": "Продам серверное железо - forum.example.net"}\n]\n'},
        ],
        'fallback': 'googler: в этой лабе доступен только запрос `79165551122`.\n'}},
    ))

# ---------------------------------------------------------------- 5. telegram
SPECS.append(_lab(
    'osint-telegram', 'Практика: публичное веб-превью Telegram',
    ['task.md'],
    ['Читай канал без аккаунта: `curl -s "https://t.me/s/examplecorp" > page.html`.',
     'Собери ссылки на профили: `grep t.me page.html`.',
     'Листай историю: `curl -s "https://t.me/s/examplecorp?before=1000" > older.html`.',
     'В старом посте есть утечка с маркером. `grep nto older.html` → `nto{...}`; запиши в `answer.txt` и набери `check`.'],
    'nto{t3l3gr4m_publ1c_pr3v13w_l34k}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: публичное веб-превью Telegram\n\n'
        'Компания `Example Corp`, канал `examplecorp`. Публичные каналы читаются без аккаунта.\n\n'
        '1. Сними веб-превью: `curl -s "https://t.me/s/examplecorp" > page.html`\n'
        '2. Вытащи упоминания профилей: `grep t.me page.html`\n'
        '3. Пролистай историю: `curl -s "https://t.me/s/examplecorp?before=1000" > older.html`\n'
        '4. Найди маркер в старом посте: `grep nto older.html`. Запиши `nto{...}` в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — выгрузка (эмуляция реального HTML t.me)',
        'cases': [
            {'match': 'before=', 'example': 'curl -s "https://t.me/s/examplecorp?before=1000"',
             'output': '<div class="tgme_channel_info">Example Corp - официальный канал</div>\n'
                       '<div class="tgme_widget_message_text">Обновление сервиса в пятницу. Вакансия: backend, резюме на hr@example.com</div>\n'
                       '<div class="tgme_widget_message_text">Утечка тестового конфига: DB_PASS=Spring2026! deploy=nto{t3l3gr4m_publ1c_pr3v13w_l34k}</div>\n'
                       '<a href="https://t.me/examplecorp_chat">t.me/examplecorp_chat</a>\n'},
            {'match': 't\\.me/s/examplecorp', 'example': 'curl -s "https://t.me/s/examplecorp"',
             'output': '<div class="tgme_channel_info">Example Corp - официальный канал</div>\n'
                       '<div class="tgme_widget_message_text">Обновление сервиса запланировано на пятницу.</div>\n'
                       '<div class="tgme_widget_message_text">Вакансия: backend-разработчик, резюме на hr@example.com</div>\n'
                       '<a href="https://t.me/ivan_dev">t.me/ivan_dev</a>\n'
                       '<a href="https://t.me/alex_smirnov">t.me/alex_smirnov</a>\n'
                       '<a href="https://t.me/examplecorp_chat">t.me/examplecorp_chat</a>\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только t.me/s/examplecorp и t.me/s/examplecorp?before=1000.\n'}},
    ))

# ---------------------------------------------------------------- 6. discord
SPECS.append(_lab(
    'osint-discord', 'Практика: метаданные Discord без логина',
    ['task.md'],
    ['Инвайт-метаданные без токена: `curl -s "https://discord.com/api/v10/invites/examplecorp?with_counts=true" > inv.json`.',
     'Разбери сервер: `jq \'{name: .guild.name, id: .guild.id, members: .approximate_member_count}\' inv.json`.',
     'Виджет отдаёт каналы без аутентификации: `curl -s "https://discord.com/api/v10/guilds/123456789012345678/widget.json" > widget.json`.',
     'Имена каналов: `jq -r \'.channels[].name\' widget.json`. Один канал несёт маркер `nto{...}` — запиши в `answer.txt` и набери `check`.'],
    'nto{d1sc0rd_w1dg3t_ch4nn3l_l34k}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: метаданные Discord без логина\n\n'
        'Сообщество компании `Example Corp` в Discord. Многое видно до вступления.\n\n'
        '1. Инвайт-метаданные: `curl -s "https://discord.com/api/v10/invites/examplecorp?with_counts=true" > inv.json`\n'
        '2. Разбор: `jq \'{name: .guild.name, id: .guild.id, members: .approximate_member_count}\' inv.json`\n'
        '3. Виджет (каналы без логина): `curl -s "https://discord.com/api/v10/guilds/123456789012345678/widget.json" > widget.json`\n'
        '4. Каналы: `jq -r \'.channels[].name\' widget.json`\n'
        '5. Один канал содержит маркер `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — Discord API v10 (эмуляция реального формата)',
        'cases': [
            {'match': 'widget\\.json', 'example': 'curl -s "https://discord.com/api/v10/guilds/123456789012345678/widget.json"',
             'output': '{\n  "id": "123456789012345678",\n  "name": "Example Corp Community",\n  "instant_invite": "https://discord.gg/examplecorp",\n  "channels": [\n    {"id": "1", "name": "general", "position": 0},\n    {"id": "2", "name": "announcements", "position": 1},\n    {"id": "3", "name": "leaks-nto{d1sc0rd_w1dg3t_ch4nn3l_l34k}", "position": 2}\n  ],\n  "presence_count": 312\n}\n'},
            {'match': 'invites/examplecorp', 'example': 'curl -s "https://discord.com/api/v10/invites/examplecorp?with_counts=true"',
             'output': '{\n  "code": "examplecorp",\n  "guild": {"id": "123456789012345678", "name": "Example Corp Community"},\n  "approximate_member_count": 4213,\n  "approximate_presence_count": 312\n}\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только invites/examplecorp и guilds/123456789012345678/widget.json.\n'},
     'jq': {
        'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
        'cases': [
            {'match': 'approximate_member_count', 'example': "jq '{name: .guild.name, ...}' inv.json",
             'output': '{\n  "name": "Example Corp Community",\n  "id": "123456789012345678",\n  "members": 4213\n}\n'},
            {'match': 'channels', 'example': "jq -r '.channels[].name' widget.json",
             'output': 'general\nannouncements\nleaks-nto{d1sc0rd_w1dg3t_ch4nn3l_l34k}\n'},
        ],
        'fallback': 'jq: в этой лабе поддержаны фильтры по `.guild.*` и `.channels[].name`.\n'}},
    ))

# ---------------------------------------------------------------- 7. darkweb
SPECS.append(_lab(
    'osint-darkweb', 'Практика: проверка leak-site в Tor (только чтение)',
    ['task.md'],
    ['Читай .onion через Tor SOCKS: `curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/" > site.html`.',
     'Проверь, есть ли цель в списке: `grep example.com site.html`.',
     'Открой список жертв: `curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/victims" > victims.html`.',
     'В записи о жертве есть маркер. `grep nto victims.html` → `nto{...}`; запиши в `answer.txt` и набери `check`.'],
    'nto{0n10n_l34k_s1t3_c0nf1rm3d}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: проверка leak-site в Tor\n\n'
        'Проверь, не упоминается ли домен `example.com` на портале утечек. Только чтение.\n\n'
        '1. Домашняя страница onion: `curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/" > site.html`\n'
        '2. Есть ли цель в списке: `grep example.com site.html`\n'
        '3. Список жертв: `curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/victims" > victims.html`\n'
        '4. Найди маркер: `grep nto victims.html`. Запиши `nto{...}` в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] --socks5-hostname 127.0.0.1:9050 <onion-URL> — доступ через Tor (эмуляция)',
        'cases': [
            {'match': 'victims', 'example': 'curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/victims"',
             'output': '<html><body><h1>Victims</h1>\n'
                       '<ul>\n'
                       '<li>acme-corp.com | published 2026-09-30 | 14 GB</li>\n'
                       '<li>example.com | published 2026-10-08 | 3.2 GB | tag=nto{0n10n_l34k_s1t3_c0nf1rm3d}</li>\n'
                       '</ul></body></html>\n'},
            {'match': 'onion', 'example': 'curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/"',
             'output': '<html><body><h1>Leak Portal</h1>\n<p>example.com - added 2026-10-08, deadline 2026-10-20</p>\n<p>acme-corp.com - added 2026-09-30</p>\n</body></html>\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только ex4mplel34k7f3k2q5v8w1z.onion/ и .../victims через Tor SOCKS.\n'}},
    ))

# ---------------------------------------------------------------- 8. social-news
SPECS.append(_lab(
    'osint-social-news', 'Практика: мониторинг упоминаний в медиа',
    ['task.md'],
    ['Забери Google News RSS по цели: `curl -s "https://news.google.com/rss/search?q=%22Example+Corp%22&hl=en-US&gl=US&ceid=US:en" > news.xml`.',
     'Найди аномальный заголовок: `grep nto news.xml`.',
     'Сверь с GDELT: `curl -s "https://api.gdeltproject.org/api/v2/doc/doc?query=%22Example+Corp%22&format=json" > gdelt.json`.',
     'Заголовки: `jq -r \'.articles[].title\' gdelt.json`. Маркер `nto{...}` — кодовое имя из пресс-релиза; запиши в `answer.txt` и набери `check`.'],
    'nto{n3ws_c0d3n4m3_1n_h34dl1n3}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: мониторинг упоминаний в медиа\n\n'
        'Собери свежие упоминания `Example Corp` в новостях автоматически.\n\n'
        '1. Google News RSS: `curl -s "https://news.google.com/rss/search?q=%22Example+Corp%22&hl=en-US&gl=US&ceid=US:en" > news.xml`\n'
        '2. Найди аномальный заголовок: `grep nto news.xml`\n'
        '3. GDELT API: `curl -s "https://api.gdeltproject.org/api/v2/doc/doc?query=%22Example+Corp%22&format=json" > gdelt.json`\n'
        '4. Заголовки: `jq -r \'.articles[].title\' gdelt.json`\n'
        '5. Запиши маркер `nto{...}` в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — RSS/API (эмуляция реального формата)',
        'cases': [
            {'match': 'news\\.google\\.com', 'example': 'curl -s "https://news.google.com/rss/search?q=%22Example+Corp%22..."',
             'output': '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>\n'
                       '<title>Example Corp - Google News</title>\n'
                       '<item><title>Example Corp reports record quarter - Reuters</title><link>https://news.example/1</link></item>\n'
                       '<item><title>Example Corp ships Project nto{n3ws_c0d3n4m3_1n_h34dl1n3} - The Verge</title><link>https://news.example/2</link></item>\n'
                       '<item><title>Analysts upgrade Example Corp - Bloomberg</title><link>https://news.example/3</link></item>\n'
                       '</channel></rss>\n'},
            {'match': 'gdeltproject', 'example': 'curl -s "https://api.gdeltproject.org/api/v2/doc/doc?query=..."',
             'output': '{"articles": [\n'
                       '  {"title": "Example Corp reports record quarter", "url": "https://news.example/1", "domain": "reuters.com"},\n'
                       '  {"title": "Example Corp ships Project nto{n3ws_c0d3n4m3_1n_h34dl1n3}", "url": "https://news.example/2", "domain": "theverge.com"},\n'
                       '  {"title": "Analysts upgrade Example Corp", "url": "https://news.example/3", "domain": "bloomberg.com"}\n'
                       ']}\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только news.google.com/rss/search и api.gdeltproject.org.\n'},
     'jq': {
        'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
        'cases': [
            {'match': 'articles', 'example': "jq -r '.articles[].title' gdelt.json",
             'output': 'Example Corp reports record quarter\nExample Corp ships Project nto{n3ws_c0d3n4m3_1n_h34dl1n3}\nAnalysts upgrade Example Corp\n'},
        ],
        'fallback': 'jq: в этой лабе поддерживается только фильтр `.articles[].title`.\n'}},
    ))

# ---------------------------------------------------------------- 9. social-reddit
SPECS.append(_lab(
    'osint-social-reddit', 'Практика: поведенческий портрет по Reddit',
    ['task.md'],
    ['Профиль: `curl -s "https://www.reddit.com/user/pixel_engineer/about.json" > about.json`.',
     'Дата регистрации и карма: `jq \'.data.created_utc, .data.total_karma\' about.json`.',
     'История комментариев: `curl -s "https://www.reddit.com/user/pixel_engineer/comments.json?limit=100" > comments.json`.',
     'Тексты: `jq -r \'.data.children[].data.body\' comments.json`. Один комментарий несёт маркер `nto{...}` — запиши в `answer.txt` и набери `check`.'],
    'nto{r3dd1t_c0mm3nt_p0rtra1t}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: поведенческий портрет по Reddit\n\n'
        'Известен только ник `u/pixel_engineer`. Собери профиль.\n\n'
        '1. Профиль: `curl -s "https://www.reddit.com/user/pixel_engineer/about.json" > about.json`\n'
        '2. Метаданные: `jq \'.data.created_utc, .data.total_karma\' about.json`\n'
        '3. Комментарии: `curl -s "https://www.reddit.com/user/pixel_engineer/comments.json?limit=100" > comments.json`\n'
        '4. Тексты: `jq -r \'.data.children[].data.body\' comments.json`\n'
        '5. Один комментарий содержит маркер `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — Reddit JSON API (эмуляция реального формата)',
        'cases': [
            {'match': 'comments\\.json', 'example': 'curl -s "https://www.reddit.com/user/pixel_engineer/comments.json?limit=100"',
             'output': '{"kind": "Listing", "data": {"children": [\n'
                       '  {"kind": "t1", "data": {"subreddit": "AskEngineers", "body": "we use Kubernetes at my current job in..."}},\n'
                       '  {"kind": "t1", "data": {"subreddit": "CityName", "body": "the district near the river floods every spring"}},\n'
                       '  {"kind": "t1", "data": {"subreddit": "hobby", "body": "my dog Pixel hates the rain"}},\n'
                       '  {"kind": "t1", "data": {"subreddit": "netsec", "body": "our internal build token is nto{r3dd1t_c0mm3nt_p0rtra1t}"}}\n'
                       ']}}\n'},
            {'match': 'about\\.json', 'example': 'curl -s "https://www.reddit.com/user/pixel_engineer/about.json"',
             'output': '{"kind": "t2", "data": {"name": "pixel_engineer", "created_utc": 1382313600.0, "link_karma": 4210, "comment_karma": 18832, "total_karma": 23042}}\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только about.json и comments.json пользователя pixel_engineer.\n'},
     'jq': {
        'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
        'cases': [
            {'match': 'created_utc', 'example': "jq '.data.created_utc, .data.total_karma' about.json",
             'output': '1382313600\n23042\n'},
            {'match': 'children', 'example': "jq -r '.data.children[].data.body' comments.json",
             'output': 'we use Kubernetes at my current job in...\nthe district near the river floods every spring\nmy dog Pixel hates the rain\nour internal build token is nto{r3dd1t_c0mm3nt_p0rtra1t}\n'},
        ],
        'fallback': 'jq: в этой лабе поддержаны фильтры по `.data.created_utc` и `.data.children[].data.body`.\n'}},
    ))

# ---------------------------------------------------------------- 10. social-mastodon
SPECS.append(_lab(
    'osint-social-mastodon', 'Практика: профиль в федерации Mastodon',
    ['task.md'],
    ['Публичный аккаунт: `curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=Gargron" > gargron.json`.',
     'Разбери поля: `jq \'{username,acct,display_name,statuses_count,followers_count}\' gargron.json`.',
     'Теперь цель: `curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=examplecorp" > corp.json`.',
     'Поле `note` содержит маркер `nto{...}`: `jq -r \'.note\' corp.json`. Запиши в `answer.txt` и набери `check`.'],
    'nto{f3d1v3rs3_4cc0unt_4ttr1but3d}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: профиль в федерации Mastodon\n\n'
        'В федерации нет единого сервера — аккаунт обозначают как `user@instance`.\n\n'
        '1. Проверь публичный аккаунт: `curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=Gargron" > gargron.json`\n'
        '2. Разбор: `jq \'{username,acct,display_name,statuses_count,followers_count}\' gargron.json`\n'
        '3. Аккаунт цели: `curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=examplecorp" > corp.json`\n'
        '4. Поле `note`: `jq -r \'.note\' corp.json`\n'
        '5. В `note` есть маркер `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — Mastodon API v1/v2 (эмуляция реального формата)',
        'cases': [
            {'match': 'acct=Gargron', 'example': 'curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=Gargron"',
             'output': '{"id": "1", "username": "Gargron", "acct": "Gargron", "display_name": "Eugen Rochko", "note": "<p>Founder of Mastodon</p>", "statuses_count": 82482, "followers_count": 383123, "created_at": "2016-03-16T00:00:00.000Z"}\n'},
            {'match': 'acct=examplecorp', 'example': 'curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=examplecorp"',
             'output': '{"id": "998877", "username": "examplecorp", "acct": "examplecorp", "display_name": "Example Corp", "note": "<p>Official account. Security contact: soc@example.com - internal token nto{f3d1v3rs3_4cc0unt_4ttr1but3d}</p>", "statuses_count": 47, "followers_count": 512, "created_at": "2019-11-02T09:14:00.000Z"}\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только lookup по acct=Gargron и acct=examplecorp на mastodon.social.\n'},
     'jq': {
        'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
        'cases': [
            {'match': 'followers_count', 'example': "jq '{username,acct,...}' gargron.json",
             'output': '{\n  "username": "Gargron",\n  "acct": "Gargron",\n  "display_name": "Eugen Rochko",\n  "statuses_count": 82482,\n  "followers_count": 383123\n}\n'},
            {'match': 'note', 'example': "jq -r '.note' corp.json",
             'output': '<p>Official account. Security contact: soc@example.com - internal token nto{f3d1v3rs3_4cc0unt_4ttr1but3d}</p>\n'},
        ],
        'fallback': 'jq: в этой лабе поддержаны фильтры по `.note` и полям профиля.\n'}},
    ))

# ---------------------------------------------------------------- 11. social-vk
SPECS.append(_lab(
    'osint-social-vk', 'Практика: граф связей VK через API',
    ['task.md'],
    ['Базовые поля цели: `curl -s "https://api.vk.com/method/users.get?user_ids=1&fields=city,work&v=5.131" > user.json`.',
     'Разбери профиль: `jq \'.response[0]\' user.json`.',
     'Выгрузи друзей: `curl -s "https://api.vk.com/method/friends.get?user_id=1&fields=city,work&v=5.131" > friends.json`.',
     'Поля работы: `jq -r \'.response.items[].work\' friends.json`. У одного друга в работе маркер `nto{...}` — запиши в `answer.txt` и набери `check`.'],
    'nto{vk_s0c14l_gr4ph_m4pp3d}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: граф связей VK через API\n\n'
        'Цель — `Иван Иванов`, Москва. VK даёт список друзей и подписок.\n\n'
        '1. Базовые поля: `curl -s "https://api.vk.com/method/users.get?user_ids=1&fields=city,work&v=5.131" > user.json`\n'
        '2. Профиль: `jq \'.response[0]\' user.json`\n'
        '3. Друзья: `curl -s "https://api.vk.com/method/friends.get?user_id=1&fields=city,work&v=5.131" > friends.json`\n'
        '4. Работа друзей: `jq -r \'.response.items[].work\' friends.json`\n'
        '5. Один друг работает в компании с маркером `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — VK API 5.131 (эмуляция реального формата)',
        'cases': [
            {'match': 'friends\\.get', 'example': 'curl -s "https://api.vk.com/method/friends.get?user_id=1&fields=city,work&v=5.131"',
             'output': '{"response": {"count": 312, "items": [\n'
                       '  {"id": 101, "first_name": "Сергей", "last_name": "Петров", "city": {"title": "Москва"}, "work": "Example Corp"},\n'
                       '  {"id": 102, "first_name": "Анна", "last_name": "Смирнова", "city": {"title": "Москва"}, "work": "Example Corp (deploy: nto{vk_s0c14l_gr4ph_m4pp3d})"},\n'
                       '  {"id": 103, "first_name": "Олег", "last_name": "Кузнецов", "city": {"title": "Санкт-Петербург"}}\n'
                       ']}}\n'},
            {'match': 'users\\.get', 'example': 'curl -s "https://api.vk.com/method/users.get?user_ids=1&fields=city,work&v=5.131"',
             'output': '{"response": [{"id": 1, "first_name": "Иван", "last_name": "Иванов", "city": {"title": "Москва"}, "work": "Example Corp"}]}\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только method/users.get и method/friends.get (v=5.131).\n'},
     'jq': {
        'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
        'cases': [
            {'match': 'response\\.items', 'example': "jq -r '.response.items[].work' friends.json",
             'output': 'Example Corp\nExample Corp (deploy: nto{vk_s0c14l_gr4ph_m4pp3d})\n'},
            {'match': 'response', 'example': "jq '.response[0]' user.json",
             'output': '{\n  "id": 1,\n  "first_name": "Иван",\n  "last_name": "Иванов",\n  "city": {"title": "Москва"},\n  "work": "Example Corp"\n}\n'},
        ],
        'fallback': 'jq: в этой лабе поддержаны фильтры по `.response[0]` и `.response.items[].work`.\n'}},
    ))

# ---------------------------------------------------------------- 12. censys-fofa
SPECS.append(_lab(
    'osint-censys-fofa', 'Практика: Censys и FOFA — перекрёстный поиск',
    ['task.md'],
    ['Censys по заголовку: `curl -s "https://search.censys.io/api/v2/hosts/search?q=services.http.response.html_title%3A%20Grafana&per_page=50" > censys.json`.',
     'IP-адреса: `jq -r \'.result.hits[].ip\' censys.json`.',
     'FOFA по тому же отпечатку: `curl -s "https://fofa.info/api/v1/search/all?qbase64=aHR0cF90aXRsZT0iR3JhZmFuYSI=&size=50" > fofa.json`.',
     'Заголовки результатов: `jq -r \'.results[].title\' fofa.json`. Один несёт маркер `nto{...}` — запиши в `answer.txt` и набери `check`.'],
    'nto{c3nsys_f0f4_cr0ss_3ng1n3}',
    [_dir(WD),
     _f(f'{WD}/task.md',
        '# Практика: Censys и FOFA — перекрёстный поиск\n\n'
        'Организация `example.com`. Нужно найти все инстансы Grafana; один движок покрывает не всё.\n\n'
        '1. Censys по заголовку: `curl -s "https://search.censys.io/api/v2/hosts/search?q=services.http.response.html_title%3A%20Grafana&per_page=50" > censys.json`\n'
        '2. IP-адреса: `jq -r \'.result.hits[].ip\' censys.json`\n'
        '3. FOFA по тому же отпечатку: `curl -s "https://fofa.info/api/v1/search/all?qbase64=aHR0cF90aXRsZT0iR3JhZmFuYSI=&size=50" > fofa.json`\n'
        '4. Заголовки: `jq -r \'.results[].title\' fofa.json`\n'
        '5. Один заголовок содержит маркер `nto{...}`. Запиши его в `answer.txt` и набери `check`.\n')],
    {'curl': {
        'help': 'curl [-s] <URL> — Censys/FOFA API (эмуляция реального формата)',
        'cases': [
            {'match': 'search\\.censys\\.io', 'example': 'curl -s "https://search.censys.io/api/v2/hosts/search?q=...Grafana..."',
             'output': '{"code": 200, "result": {"total": 3, "hits": [\n'
                       '  {"ip": "203.0.113.22", "services": [{"port": 3000, "service_name": "HTTP"}]},\n'
                       '  {"ip": "198.51.100.40", "services": [{"port": 3000, "service_name": "HTTP"}]}\n'
                       ']}}\n'},
            {'match': 'fofa\\.info', 'example': 'curl -s "https://fofa.info/api/v1/search/all?qbase64=...&size=50"',
             'output': '{"error": false, "size": 2, "results": [\n'
                       '  {"host": "https://203.0.113.22:3000", "title": "Grafana"},\n'
                       '  {"host": "https://203.0.113.90:3000", "title": "Grafana - prod-dashboard nto{c3nsys_f0f4_cr0ss_3ng1n3}"}\n'
                       ']}\n'},
        ],
        'fallback': 'curl: в этой лабе доступны только search.censys.io/api/v2/hosts/search и fofa.info/api/v1/search/all.\n'},
     'jq': {
        'help': 'jq [-r] <фильтр> <файл> — разбор JSON (эмуляция)',
        'cases': [
            {'match': 'result\\.hits', 'example': "jq -r '.result.hits[].ip' censys.json",
             'output': '203.0.113.22\n198.51.100.40\n'},
            {'match': 'results', 'example': "jq -r '.results[].title' fofa.json",
             'output': 'Grafana\nGrafana - prod-dashboard nto{c3nsys_f0f4_cr0ss_3ng1n3}\n'},
        ],
        'fallback': 'jq: в этой лабе поддержаны фильтры по `.result.hits[].ip` и `.results[].title`.\n'}},
    ))
