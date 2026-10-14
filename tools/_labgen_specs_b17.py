#!/usr/bin/env python3
"""Author lab batch B17: 12 interactive labs for remaining hands-on lessons."""
import base64, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS_DIR = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def b64(d):
    return base64.b64encode(d).decode()


def f_dir(p):
    return {'path': p, 'type': 'dir'}


def f_b64(p, d, mode='644'):
    return {'path': p, 'b64': b64(d), 'mode': mode}


def ko_bytes():
    b = bytearray(b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8)
    b += bytes([1, 0, 0x3e, 0, 1, 0, 0, 0])
    b += b'\x00' * 152
    b += b'.modinfo\x00name=vboxnetflt\x00version=7.2.16 r174877\x00'
    b += b'description=Oracle VirtualBox Network Filter Driver\x00'
    b += b'depends=vboxdrv\x00vermagic=6.19.11-arch1-1 SMP preempt mod_unload\x00'
    b += b'\x00' * 16
    b += b'VBoxNetFltLinuxInit\x00vboxNetFltLinuxHookDev\x00'
    b += b'secret_nto{k0_10ctl_0x8004a10c_s3cr3t}\x00\x00\x00\x00\x00\x00\x00\x00'
    return bytes(b)


def firmware_bytes():
    b = bytearray(b'\x00\x80\x01\x20\x01\x00\x00\x08' + b'\x00' * 120)
    b += b'FreeRTOS V10.4.3\x00bare-metal STM32F4\x00task_check\x00'
    b += b'movw r1,#0x9dc5\x00movt r1,#0x811c\x00'
    b += b'0x811c9dc5\x000x01000193\x00'
    b += b'licence=nto{c0rt3x_m4_thum8_fnv_l1c3ns3}\x00\x00\x00\x00\x00\x00\x00\x00'
    return bytes(b)


def apk_bytes():
    b = bytearray(b'PK\x03\x04' + b'\x14\x00\x00\x00' + b'\x00' * 24)
    b += b'AndroidManifest.xml\x00classes.dex\x00META-INF/CERT.RSA\x00resources.arsc\x00'
    b += b'\x00' * 48
    b += b'sg.vantagepoint.uncrackable1.MainActivity\x00owasp.mstg.uncrackable1\x00'
    b += b'secret_nto{uncr4ck4bl3_4ndr01d_d3x_s3cr3t}\x00\x00\x00\x00\x00\x00\x00\x00'
    return bytes(b)


LABS = []


def add(**k):
    LABS.append(k)


# ============================================================ WEB ============
add(cat='web', id='web-prototype-pollution-rce',
    title='Практика: prototype pollution → RCE через гаджет EJS',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: prototype pollution → RCE\n\n"
        "Цель `docs.example` — Node-приложение на шаблонизаторе EJS; оно сливает\n"
        "пользовательский JSON в объект настроек.\n\n"
        "1. Подтверди примитив: отправь `{\"__proto__\":{\"polluted\":\"yes\"}}` в `/api/merge`, затем проверь `/status`.\n"
        "2. Собери зависимости: `curl -s https://docs.example/package.json`.\n"
        "3. Загрязни прототип гаджетом EJS `outputFunctionName` — он вставляется в исполняемый контекст.\n"
        "4. Вызови триггер `/render` и сохрани ответ — там артефакт RCE и флаг.\n\n"
        "Флаг: `nto{...}` внутри вывода триггера.\n"
    ),
    fs=[f_dir(WD)],
    tools={'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция docs.example)',
        'cases': [
            {'match': r'outputfunctionname',
             'example': "-s -X POST https://docs.example/api/merge -d '{\"__proto__\":{\"outputFunctionName\":\"x;s\"}}'",
             'output': '{"ok":true}\n'},
            {'match': r'__proto__',
             'example': "-s -X POST https://docs.example/api/merge -d '{\"__proto__\":{\"polluted\":\"yes\"}}'",
             'output': '{"ok":true}\n'},
            {'match': r'api/merge',
             'example': "-s -X POST https://docs.example/api/merge -d '{\"theme\":\"dark\"}'",
             'output': '{"ok":true}\n'},
            {'match': r'render',
             'example': "-s 'https://docs.example/render?page=about'",
             'output': 'uid=0(root) gid=0(root) groups=0(root)\nnto{pp_g4dg3t_ejs_outputfunctionname_rce}\n'},
            {'match': r'status',
             'example': '-s https://docs.example/status',
             'output': '{"polluted":"yes","engine":"node","ejs":"3.1.6"}\n'},
            {'match': r'package\.json',
             'example': '-s https://docs.example/package.json',
             'output': '{"name":"docs","dependencies":{"ejs":"3.1.6","lodash":"4.17.11","express":"4.18.2"}}\n'},
            {'match': r'main\.js',
             'example': '-s https://docs.example/main.js',
             'output': 'const cfg = Object.assign({}, defaults, userInput);\nel.innerHTML = cfg.html;  // sink\n'},
            {'match': r'docs\.example',
             'example': '-s https://docs.example/',
             'output': '<!doctype html><title>docs.example</title>\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируется docs.example.\n',
    }},
    hints=[
        "Примитив не impact: сначала `{\"__proto__\":{\"polluted\":\"yes\"}}` в `/api/merge`, затем `/status`.",
        'Зависимости: `curl -s https://docs.example/package.json` — EJS 3.1.6 склонен к гаджету `outputFunctionName`.',
        'Загрязни `__proto__.outputFunctionName` строкой с внедрением кода через `/api/merge`.',
        "Триггер — рендер: `curl -s 'https://docs.example/render?page=about' > found.txt`, затем `check`.",
    ],
    flag='nto{pp_g4dg3t_ejs_outputfunctionname_rce}', batch='web-b9',
    solution=["curl -s -X POST https://docs.example/api/merge -H 'Content-Type: application/json' -d '{\"__proto__\":{\"outputFunctionName\":\"x;s\"}}'",
              "curl -s 'https://docs.example/render?page=about' > found.txt"])

add(cat='web', id='web-webauthn',
    title='Практика: захват аккаунта через непривязанную регистрацию passkey',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: WebAuthn — ошибки реализации\n\n"
        "Цель `id.local` — вход по passkey; сервер проверяет не всё, что обязан.\n\n"
        "1. Посмотри ответ `/webauthn/register/begin` — там `challenge`, `rp.id`, `user.id`.\n"
        "2. `/webauthn/login/finish` принимает подпись с чужим `origin` (проверки нет).\n"
        "3. Главная дыра — регистрация: `/webauthn/register/finish` не сверяет, что `user.id` принадлежит сессии.\n"
        "4. Привяжи свой ключ к аккаунту жертвы (`user.id=dXNlcl92aWN0aW0`) и сохрани ответ.\n\n"
        "Флаг: `nto{...}` в ответе успешной привязки.\n"
    ),
    fs=[f_dir(WD)],
    tools={'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция id.local)',
        'cases': [
            {'match': r'dXNlcl92aWN0aW0',
             'example': "-s -X POST https://id.local/webauthn/register/finish -b 'session=MY_SESSION' -d 'user.id=dXNlcl92aWN0aW0'",
             'output': '{"ok":true,"account":"victim@id.local","flag":"nto{w3bauthn_0r1g1n_ch4ll3ng3_uv_n0t_v3r1f13d}"}\n'},
            {'match': r'register/finish',
             'example': '-s -X POST https://id.local/webauthn/register/finish -d @my_key.json',
             'output': '{"ok":true,"account":"me@id.local"}\n'},
            {'match': r'register/begin',
             'example': '-s -X POST https://id.local/webauthn/register/begin',
             'output': '{"challenge":"Xz9fQ2hhbGxlbmdl","rp":{"id":"id.local","name":"ID"},"user":{"id":"dXNlcl8x","name":"me@id.local"},"pubKeyCredParams":[{"alg":-7}]}\n'},
            {'match': r'login/finish',
             'example': '-s -X POST https://id.local/webauthn/login/finish -d @login.json',
             'output': '{"ok":true,"session":"eyJhbGciOiJIUzI1NiJ9.FULL"}\n'},
            {'match': r'/login',
             'example': "-s -X POST https://id.local/login -d 'email=victim@id.local&password=x'",
             'output': '{"ok":true}  # passkey не enforced, вход паролем разрешён\n'},
            {'match': r'id\.local',
             'example': '-s https://id.local/',
             'output': '<!doctype html><title>id.local — passkey login</title>\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируется id.local.\n',
    }},
    hints=[
        'Начни с регистрации — там проверки слабее: `curl -s -X POST https://id.local/webauthn/register/begin`.',
        'Идентификатор жертвы в `user.id` — `dXNlcl92aWN0aW0`.',
        'Если `/webauthn/register/finish` не привязан к сессии, свой ключ можно привязать к чужому `user.id`.',
        "Отправь `curl -s -X POST https://id.local/webauthn/register/finish -b 'session=MY_SESSION' -d 'user.id=dXNlcl92aWN0aW0' > found.txt`.",
    ],
    flag='nto{w3bauthn_0r1g1n_ch4ll3ng3_uv_n0t_v3r1f13d}', batch='web-b9',
    solution=["curl -s -X POST https://id.local/webauthn/register/finish -b 'session=MY_SESSION' -d 'user.id=dXNlcl92aWN0aW0' > found.txt"])

add(cat='web', id='web-websocket-smuggling',
    title='Практика: CSWSH — угон WebSocket-сессии без проверки Origin',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: WebSocket smuggling / CSWSH\n\n"
        "Цель `target.local/chat` — чат на WebSocket; рукопожатие аутентифицируется cookie.\n\n"
        "1. Посмотри страницу чата: `curl -s https://target.local/chat`.\n"
        "2. Отправь рукопожатие с чужим `Origin: https://evil.com`.\n"
        "3. Если приходит `101 Switching Protocols` — проверки Origin нет: страница атакующего\n"
        "   откроет соединение от имени жертвы и получит её историю чата.\n"
        "4. Сохрани ответ с угнанной историей — там флаг.\n\n"
        "Флаг: `nto{...}` внутри угнанных данных.\n"
    ),
    fs=[f_dir(WD)],
    tools={'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция target.local)',
        'cases': [
            {'match': r'evil\.com',
             'example': "-s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Origin: https://evil.com' https://target.local/chat",
             'output': ('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                        'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n'
                        '[frame] {"cmd":"history","data":"[#42 admin] key rotation: nto{cswsh_101_w1th_f0r31gn_0r1g1n}"}\r\n')},
            {'match': r'websocket',
             'example': "-s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' https://target.local/chat",
             'output': ('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                        'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n')},
            {'match': r'/chat',
             'example': '-s https://target.local/chat',
             'output': '<!doctype html><title>chat</title><script>const ws=new WebSocket("wss://target.local/chat");</script>\n'},
            {'match': r'target\.local',
             'example': '-s https://target.local/',
             'output': '<!doctype html><title>target.local</title>\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируется target.local.\n',
    },
    'websocat': {
        'help': 'websocat [опции] <url> — WS-клиент (эмуляция target.local/chat)',
        'cases': [
            {'match': r'evil\.example',
             'example': "-H='Origin: https://evil.example' wss://target.local/chat",
             'output': '[connected] server accepted foreign Origin\n[frame] {"cmd":"admin"} -> {"ok":true}\n'},
        ],
        'fallback': 'websocat: в этой лабе эмулируется target.local/chat.\n',
    }},
    hints=[
        'Рукопожатие WS — это обычный HTTP: `curl -s https://target.local/chat`.',
        "CSWSH ловится чужим Origin: `-H 'Origin: https://evil.com'`.",
        'Если ответ `101 Switching Protocols` — сервер Origin не проверяет.',
        "Сохрани ответ с историей: `curl -s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Origin: https://evil.com' https://target.local/chat > found.txt`.",
    ],
    flag='nto{cswsh_101_w1th_f0r31gn_0r1g1n}', batch='web-b9',
    solution=["curl -s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Origin: https://evil.com' https://target.local/chat > found.txt"])

add(cat='web', id='web-xs-leaks',
    title='Практика: cache probing раскрывает состояние логина',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: XS-Leaks — cache probing\n\n"
        "`target.local/account` — приватная страница: аноним получает редирект, пользователь — 200.\n"
        "Обе версии кэшируются (`cache-control: public`), значит возможен cache probing.\n\n"
        "1. Ответ анониму: `curl -s -I https://target.local/account`.\n"
        "2. Ответ залогиненному: `curl -s -I https://target.local/account -b 'session=me'`.\n"
        "3. Разница (`302` vs `200`, HIT/MISS) — оракул состояния логина.\n"
        "4. Достань приватную страницу залогиненной сессией — там флаг.\n\n"
        "Флаг: `nto{...}` на приватной странице.\n"
    ),
    fs=[f_dir(WD)],
    tools={'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция target.local)',
        'cases': [
            {'match': r'account[^\n]*session=me|session=me[^\n]*account',
             'example': "-s https://target.local/account -b 'session=me'",
             'output': ('HTTP/1.1 200 OK\r\ncache-control: public, max-age=60\r\ncontent-type: text/html\r\n\r\n'
                        '<h1>Account</h1>\n<p>nto{c4ch3_pr0b1ng_l34ks_l0g1n_st4t3}</p>\n')},
            {'match': r'account',
             'example': '-s -I https://target.local/account',
             'output': 'HTTP/1.1 302 Found\r\nlocation: /login\r\ncache-control: public, max-age=60\r\n'},
            {'match': r'target\.local',
             'example': '-s -I https://target.local/',
             'output': 'HTTP/1.1 200 OK\r\ncache-control: public, max-age=60\r\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируется target.local.\n',
    }},
    hints=[
        "Сравни ответы анонима и залогиненного (`-b 'session=me'`).",
        'Аноним получает `302 location: /login`, а `cache-control: public` делает ответ кэшируемым.',
        'Разница сигнала (код ответа / время HIT-MISS) и есть оракул — состояние логина утекает.',
        "Достань приватную страницу: `curl -s https://target.local/account -b 'session=me' > found.txt`.",
    ],
    flag='nto{c4ch3_pr0b1ng_l34ks_l0g1n_st4t3}', batch='web-b9',
    solution=["curl -s https://target.local/account -b 'session=me' > found.txt"])


# =========================================================== OSINT ===========
add(cat='osint', id='osint-intro',
    title='Практика: пассивная разведка одного домена',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: пассивная разведка `example.com`\n\n"
        "Дана одна строка — домен. Собери карту инфраструктуры, не касаясь серверов цели.\n\n"
        "1. Владелец: `whois example.com`.\n"
        "2. DNS: `dig +short example.com A`, затем `MX`, `TXT`, `NS`, `CNAME`.\n"
        "3. Поддомены через лог сертификатов: `curl -s \"https://crt.sh/?q=%25.example.com&output=json\"`.\n"
        "4. Одна из служебных записей выдаёт внутренний маркер — сохрани её.\n\n"
        "Флаг: `nto{...}` внутри одной из DNS-записей.\n"
    ),
    fs=[f_dir(WD)],
    tools={'whois': {
        'help': 'whois <домен> — запрос к публичной базе регистрации',
        'cases': [
            {'match': r'example\.com',
             'example': 'whois example.com',
             'output': ('   Domain Name: EXAMPLE.COM\n   Registrar: RESERVED-Internet Assigned Numbers Authority\n'
                        '   Creation Date: 1995-08-14T04:00:00Z\n   Updated Date: 2024-08-14T07:01:38Z\n'
                        '   Name Server: A.IANA-SERVERS.NET\n   Name Server: B.IANA-SERVERS.NET\n')},
        ],
        'fallback': 'whois: в этой лабе эмулируется example.com.\n',
    },
    'dig': {
        'help': 'dig [+short] <имя> [тип] — DNS-запрос',
        'cases': [
            {'match': r'\bTXT\b', 'example': 'dig +short example.com TXT',
             'output': '"v=spf1 include:_spf.nto{wh01s_dns_crt_sh_p4ss1v3_r3c0n}.example.com -all"\n'},
            {'match': r'\bMX\b', 'example': 'dig +short example.com MX', 'output': '0 .\n'},
            {'match': r'\bNS\b', 'example': 'dig +short example.com NS', 'output': 'a.iana-servers.net.\nb.iana-servers.net.\n'},
            {'match': r'\bCNAME\b', 'example': 'dig +short www.example.com CNAME', 'output': 'example.com.\n'},
            {'match': r'\bA\b', 'example': 'dig +short example.com A', 'output': '93.184.216.34\n'},
        ],
        'fallback': 'dig: в этой лабе эмулируется example.com.\n',
    },
    'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция crt.sh)',
        'cases': [
            {'match': r'crt\.sh', 'example': '-s "https://crt.sh/?q=%25.example.com&output=json"',
             'output': '[{"name_value":"example.com"},{"name_value":"www.example.com"},{"name_value":"dev.example.com"},{"name_value":"vpn.example.com"}]\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируется crt.sh.\n',
    }},
    hints=[
        'Начни с `whois example.com` — кто владелец и когда создан.',
        'DNS расскажет про инфраструктуру: `dig +short example.com MX`.',
        'Служебная `TXT` (SPF) часто выдаёт сторонние сервисы — посмотри её.',
        'Сохрани служебную запись: `dig +short example.com TXT > found.txt`.',
    ],
    flag='nto{wh01s_dns_crt_sh_p4ss1v3_r3c0n}', batch='osint-b10',
    solution=['dig +short example.com TXT > found.txt'])

add(cat='osint', id='osint-people-search',
    title='Практика: от email к аккаунтам — Gravatar и поиск',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: поиск людей по email\n\n"
        "Есть публичный контакт `katie.konans@nasa.gov` (из RSS-фида подкаста).\n\n"
        "1. Gravatar-хэш: `echo 'katie.konans@nasa.gov' | md5sum`.\n"
        "2. Проверь аватар: `curl -s -o /dev/null -w \"%{http_code}\\n\" \"https://www.gravatar.com/avatar/<хэш>?d=404\"`.\n"
        "3. Пивот по имени в поиске аккаунтов: `curl -s \"https://api.github.com/search/users?q=katie+konans\"`.\n"
        "4. Найденный профиль раскрывает флаг.\n\n"
        "Флаг: `nto{...}` в ответе поиска аккаунтов.\n"
    ),
    fs=[f_dir(WD)],
    tools={'md5sum': {
        'help': 'md5sum [файл] — MD5-хэш (читает stdin)',
        'cases': [
            {'match': r'katie\.konans', 'example': "echo 'katie.konans@nasa.gov' | md5sum",
             'output': 'b8ae00a794de734a080f1cf636111443  -\n'},
        ],
        'fallback': 'md5sum: в этой лабе эмулируется.\n',
    },
    'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция gravatar/github)',
        'cases': [
            {'match': r'api\.github\.com', 'example': '-s "https://api.github.com/search/users?q=katie+konans"',
             'output': '{"total_count":1,"items":[{"login":"kkonans","name":"Katie Konans","html_url":"https://github.com/kkonans","flag":"nto{gr4v4t4r_md5_p1v0t_t0_1d3nt1ty}"}]}\n'},
            {'match': r'gravatar\.com/avatar', 'example': '-s -o /dev/null -w "%{http_code}" "https://www.gravatar.com/avatar/b8ae00a794de734a080f1cf636111443?d=404"',
             'output': '404\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируются gravatar.com и api.github.com.\n',
    }},
    hints=[
        'Разбери адрес: local part = имя, domain = организация. Gravatar-хэш — MD5 от email в нижнем регистре.',
        "Посчитай хэш: `echo 'katie.konans@nasa.gov' | md5sum`.",
        'Аватар по хэшу вернул 404 — идём дальше, пивот по имени.',
        'Поиск аккаунтов: `curl -s "https://api.github.com/search/users?q=katie+konans" > found.txt`.',
    ],
    flag='nto{gr4v4t4r_md5_p1v0t_t0_1d3nt1ty}', batch='osint-b10',
    solution=['curl -s "https://api.github.com/search/users?q=katie+konans" > found.txt'])

add(cat='osint', id='osint-social-linkedin',
    title='Практика: картирование организации через LinkedIn',
    toolset=['core', 'curl'],
    task_md=(
        "# Практика: LinkedIn OSINT — карта организации\n\n"
        "Цель — страница компании и её сотрудники.\n\n"
        "1. Публичная страница компании: `curl -s -A \"Mozilla/5.0\" \"https://www.linkedin.com/company/nasa/\"`.\n"
        "2. Сотрудников ищут по профилям `linkedin.com/in/`.\n"
        "3. Один профиль (DevOps-инженер) в `og:description` раскрывает внутренний маркер.\n"
        "4. Сохрани ответ профиля — там флаг.\n\n"
        "Флаг: `nto{...}` в мета-теге профиля.\n"
    ),
    fs=[f_dir(WD)],
    tools={'curl': {
        'help': 'curl [опции] <url> — HTTP-клиент (эмуляция linkedin.com)',
        'cases': [
            {'match': r'linkedin\.com/in/', 'example': '-s -A "Mozilla/5.0" "https://www.linkedin.com/in/devops-nasa/"',
             'output': ('<meta property="og:title" content="Dana Roe - DevOps Engineer - NASA | LinkedIn">\n'
                        '<meta property="og:description" content="DevOps Engineer at NASA. Internal infra portal: https://gitlab.nasa.local (marker nto{l1nk3d1n_0rg_m4p_3m41l_p4tt3rn})">\n')},
            {'match': r'linkedin\.com/company/nasa', 'example': '-s -A "Mozilla/5.0" "https://www.linkedin.com/company/nasa/"',
             'output': ('<meta property="og:title" content="NASA - National Aeronautics and Space Administration | LinkedIn">\n'
                        '<meta property="og:description" content="NASA - National Aeronautics and Space Administration | 7,136,235 followers on LinkedIn. Explore the universe ...">\n')},
            {'match': r'linkedin\.com', 'example': '-s https://www.linkedin.com/',
             'output': '<!doctype html><title>LinkedIn</title>\n'},
        ],
        'fallback': 'curl: в этой лабе эмулируется linkedin.com.\n',
    }},
    hints=[
        'Начни с публичной страницы компании: мета-теги `og:title`/`og:description` видны без входа.',
        'Сотрудники — это профили `linkedin.com/in/<имя>`; их ищут дорками по ролям.',
        'Интересны DevOps/админы: у них доступ к инфраструктуре.',
        'Сохрани профиль: `curl -s -A "Mozilla/5.0" "https://www.linkedin.com/in/devops-nasa/" > found.txt`.',
    ],
    flag='nto{l1nk3d1n_0rg_m4p_3m41l_p4tt3rn}', batch='osint-b10',
    solution=['curl -s -A "Mozilla/5.0" "https://www.linkedin.com/in/devops-nasa/" > found.txt'])


# ======================================================= REVERSING ===========
add(cat='reversing', id='reversing-kernel-drivers',
    title='Практика: паспорт и строки kernel-модуля',
    toolset=['core', 'hex'],
    task_md=(
        "# Практика: разбор модуля ядра `.ko`\n\n"
        "В каталоге `vboxnetflt.ko` — модуль ядра Linux. Разбери его статически.\n\n"
        "1. `file vboxnetflt.ko` — что это за файл.\n"
        "2. `readelf -h vboxnetflt.ko` — тип (`REL`), архитектура, точка входа.\n"
        "3. `modinfo vboxnetflt.ko` — «паспорт»: имя, версия, зависимости, подпись.\n"
        "4. `strings -n 6 vboxnetflt.ko` — карта функциональности; найди секретный маркер.\n\n"
        "Флаг: `nto{...}` среди строк модуля.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/vboxnetflt.ko', ko_bytes(), '644')],
    tools={'readelf': {
        'help': 'readelf [-h|-S] <файл> — заголовки ELF',
        'cases': [
            {'match': r'-h|--file-header', 'example': 'readelf -h vboxnetflt.ko',
             'output': ('ELF Header:\n  Type:                              REL (Relocatable file)\n'
                        '  Machine:                           Advanced Micro Devices X86-64\n'
                        '  Entry point address:               0x0\n')},
            {'match': r'-S|--section-headers', 'example': 'readelf -S vboxnetflt.ko',
             'output': ('  [ 3] .text      PROGBITS\n  [10] .init.text PROGBITS\n'
                        '  [14] .exit.text PROGBITS\n  [18] .modinfo  PROGBITS\n')},
        ],
        'fallback': 'readelf: в этой лабе эмулируется.\n',
    },
    'modinfo': {
        'help': 'modinfo <модуль> — метаданные модуля ядра',
        'cases': [
            {'match': r'vboxnetflt', 'example': 'modinfo vboxnetflt.ko',
             'output': ('name:           vboxnetflt\nversion:        7.2.16 r174877\nlicense:        GPL\n'
                        'description:    Oracle VirtualBox Network Filter Driver\ndepends:        vboxdrv\n'
                        'vermagic:       6.19.11-arch1-1 SMP preempt mod_unload\nsigner:         DKMS module signing key\n')},
        ],
        'fallback': 'modinfo: в этой лабе эмулируется.\n',
    },
    'nm': {
        'help': 'nm <файл> — таблица символов',
        'cases': [
            {'match': r'vboxnetflt', 'example': 'nm vboxnetflt.ko',
             'output': ('0000000000000010 t VBoxNetFltLinuxInit\n0000000000000000 T __pfx_init_module\n'
                        '0000000000000000 T __pfx_cleanup_module\n')},
        ],
        'fallback': 'nm: в этой лабе эмулируется.\n',
    }},
    hints=[
        'Начни с `file vboxnetflt.ko` — это ELF. Исполняемый или объектный?',
        '`readelf -h` покажет `Type: REL (Relocatable file)` — не готовая программа, а объектный файл.',
        '`strings -n 6 vboxnetflt.ko` даёт карту функциональности и подсказки-символы.',
        'Сохрани строки: `strings -n 6 vboxnetflt.ko > found.txt`, затем `check`.',
    ],
    flag='nto{k0_10ctl_0x8004a10c_s3cr3t}', batch='reversing-b12',
    solution=['strings -n 6 vboxnetflt.ko > found.txt'])

add(cat='reversing', id='reversing-embedded-rtos',
    title='Практика: строки и константы bare-metal прошивки',
    toolset=['core', 'hex'],
    task_md=(
        "# Практика: разбор bare-metal/RTOS прошивки\n\n"
        "В каталоге `firmware.bin` — сырой образ прошивки IoT-устройства (Cortex-M4).\n\n"
        "1. `file firmware.bin` — тип файла (сырой образ, не ELF).\n"
        "2. `xxd -l 64 firmware.bin` — первые байты: таблица векторов (SP + Reset_Handler).\n"
        "3. `strings -n 4 firmware.bin` — строки: имя RTOS, символы задач, константы FNV.\n"
        "4. Найди строку лицензии с маркером.\n\n"
        "Флаг: `nto{...}` среди строк прошивки.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/firmware.bin', firmware_bytes(), '644')],
    tools={'binwalk': {
        'help': 'binwalk <файл> — сигнатурный анализ образа',
        'cases': [
            {'match': r'firmware\.bin', 'example': 'binwalk firmware.bin',
             'output': ('DECIMAL       HEXADECIMAL     DESCRIPTION\n'
                        '0             0x0             ARM exception vector table\n'
                        '128           0x80            FreeRTOS task list (ASCII)\n')},
        ],
        'fallback': 'binwalk: в этой лабе эмулируется.\n',
    }},
    hints=[
        '`file firmware.bin` скажет `data` — это сырой образ, а не ELF.',
        'Таблица векторов в начале: `xxd -l 64 firmware.bin` — первые 4 байта это начальный SP.',
        '`strings -n 4 firmware.bin` вытащит имена RTOS, задач и константы FNV (0x811c9dc5).',
        'Сохрани строки: `strings -n 4 firmware.bin > found.txt`.',
    ],
    flag='nto{c0rt3x_m4_thum8_fnv_l1c3ns3}', batch='reversing-b12',
    solution=['strings -n 4 firmware.bin > found.txt'])

add(cat='reversing', id='reversing-mobile-malware',
    title='Практика: разбор APK — структура и секрет в DEX',
    toolset=['core', 'hex'],
    task_md=(
        "# Практика: разбор Android APK\n\n"
        "В каталоге `uncrack1.apk` — учебный Android-образец.\n\n"
        "1. `file uncrack1.apk` — APK это ZIP-архив.\n"
        "2. `unzip -l uncrack1.apk` — состав: `AndroidManifest.xml`, `classes.dex`, `META-INF/`.\n"
        "3. `strings -n 5 uncrack1.apk` — строки внутри (имя пакета, активность, секрет).\n"
        "4. Найди строку с секретом.\n\n"
        "Флаг: `nto{...}` среди строк APK.\n"
    ),
    fs=[f_dir(WD), f_b64(WD + '/uncrack1.apk', apk_bytes(), '644')],
    tools={'unzip': {
        'help': 'unzip [-l | -p <файл>] <архив> — работа с ZIP',
        'cases': [
            {'match': r'-l', 'example': 'unzip -l uncrack1.apk',
             'output': ('Archive:  uncrack1.apk\n  Length      Date    Time    Name\n'
                        '---------  ---------- -----   ----\n'
                        '     2048  2024-01-01 00:00   AndroidManifest.xml\n'
                        '    18432  2024-01-01 00:00   classes.dex\n'
                        '      256  2024-01-01 00:00   META-INF/CERT.RSA\n')},
            {'match': r'classes\.dex', 'example': 'unzip -p uncrack1.apk classes.dex',
             'output': ('dex\n035\x00sg.vantagepoint.uncrackable1.MainActivity\n'
                        'root-detect: c.a()||c.b()||c.c()\n'
                        'secret_nto{uncr4ck4bl3_4ndr01d_d3x_s3cr3t}\n')},
        ],
        'fallback': 'unzip: в этой лабе эмулируется uncrack1.apk.\n',
    },
    'jadx': {
        'help': 'jadx --no-res -d <каталог> <apk> — декомпиляция в Java',
        'cases': [
            {'match': r'uncrack1', 'example': 'jadx --no-res -d uncrack1_src uncrack1.apk',
             'output': ('INFO  - loading ... uncrack1.apk\nINFO  - done\n'
                        '// a.java: boolean a(String s){ return s.equals("nto{uncr4ck4bl3_4ndr01d_d3x_s3cr3t}"); }\n')},
        ],
        'fallback': 'jadx: в этой лабе эмулируется.\n',
    }},
    hints=[
        '`file uncrack1.apk` покажет `Zip archive data` — APK это ZIP.',
        '`unzip -l uncrack1.apk` даёт состав: манифест, `classes.dex`, подписи.',
        '`strings -n 5 uncrack1.apk` вытащит имя пакета, активность и секрет.',
        'Сохрани строки: `strings -n 5 uncrack1.apk > found.txt`.',
    ],
    flag='nto{uncr4ck4bl3_4ndr01d_d3x_s3cr3t}', batch='reversing-b12',
    solution=['strings -n 5 uncrack1.apk > found.txt'])


# ========================================================== CRYPTO ===========
add(cat='crypto', id='crypto-shor-grover',
    title='Практика: классическая часть алгоритма Шора',
    toolset=['core'],
    task_md=(
        "# Практика: классическая часть Шора\n\n"
        "В каталоге `shor.py` — скрипт, который эмулирует измерение и восстанавливает\n"
        "период функции `f(x)=a^x mod N` через цепные дроби, затем считает `gcd`.\n\n"
        "1. Прочитай скрипт: `cat shor.py`.\n"
        "2. Запусти его: `python3 shor.py`.\n"
        "3. Найди период `r` и множители для каждого `N`.\n\n"
        "Флаг: `nto{...}` в выводе скрипта.\n"
    ),
    fs=[f_dir(WD), {'path': WD + '/shor.py', 'text': (
        "from math import gcd\nfrom fractions import Fraction\n\n"
        "def period(a, N):\n    r, x = 1, a % N\n    while x != 1:\n        x = (x * a) % N\n        r += 1\n    return r\n\n"
        "for N, a in [(15, 7), (21, 2), (35, 3), (143, 6)]:\n"
        "    r = period(a, N)\n    print(f'N={N:>3} a={a}  period r={r}')\n"
        "print('flag: nto{sh0r_p3r10d_f1nd1ng_gcd_f4ct0rs}')\n"), 'mode': '644'}],
    tools={'python3': {
        'help': 'python3 <скрипт> — интерпретатор (эмуляция)',
        'cases': [
            {'match': r'shor\.py', 'example': 'python3 shor.py',
             'output': ('N= 15 a=7  period r=4\nN= 21 a=2  period r=6\nN= 35 a=3  period r=12\nN=143 a=6  period r=12\n'
                        'flag: nto{sh0r_p3r10d_f1nd1ng_gcd_f4ct0rs}\n')},
        ],
        'fallback': 'python3: в этой лабе эмулируется.\n',
    }},
    hints=[
        'Прочитай скрипт: `cat shor.py` — он ищет период перебором и печатает результат.',
        'Запусти `python3 shor.py` и посмотри на периоды `r` для N=15,21,35,143.',
        'Период `r` чётный, значит `gcd(a^(r/2)±1, N)` даёт делители.',
        'Сохрани вывод: `python3 shor.py > found.txt`.',
    ],
    flag='nto{sh0r_p3r10d_f1nd1ng_gcd_f4ct0rs}', batch='crypto-b14',
    solution=['python3 shor.py > found.txt'])

add(cat='crypto', id='crypto-lattice-bkz',
    title='Практика: CVP через embedding (Kannan)',
    toolset=['core'],
    task_md=(
        "# Практика: CVP через embedding\n\n"
        "В каталоге `attack.sage` — скрипт: решётка порождена `(7,0),(0,7)`, цель `t=(15,9)`.\n"
        "Приём embedding (Kannan) сводит CVP к SVP: цель добавляется строкой `[t, M]`.\n\n"
        "1. Прочитай скрипт: `cat attack.sage`.\n"
        "2. Запусти редуцирование: `sage attack.sage`.\n"
        "3. Найди короткий вектор с последней координатой `±M` — его первые координаты\n"
        "   это ошибка `v − t`; сам секрет `v = t − ошибка`.\n\n"
        "Флаг: `nto{...}` в выводе скрипта.\n"
    ),
    fs=[f_dir(WD), {'path': WD + '/attack.sage', 'text': (
        "M = 1000\nL = Matrix(ZZ, [[7,0,0],[0,7,0],[15,9,M]])\nR = L.LLL()\n"
        "for row in R:\n    if abs(row[-1]) == M:\n        err = [int(x) for x in row[:2]]\n"
        "        v = [15 - err[0], 9 - err[1]]\n        print('error:', err)\n"
        "        print('closest vector:', v)\nprint('flag: nto{lll_3mb3dd1ng_cvp_b4b41}')\n"), 'mode': '644'}],
    tools={'sage': {
        'help': 'sage <скрипт> — математический интерпретатор (эмуляция)',
        'cases': [
            {'match': r'attack\.sage', 'example': 'sage attack.sage',
             'output': ('row: [1, 2, 1000]\nerror: [1, 2]\nclosest vector: [14, 7]\n'
                        'flag: nto{lll_3mb3dd1ng_cvp_b4b41}\n')},
        ],
        'fallback': 'sage: в этой лабе эмулируется.\n',
    }},
    hints=[
        'Прочитай скрипт: `cat attack.sage` — это embedding (Kannan) для CVP.',
        'Цель `t=(15,9)` добавлена строкой `[t, M]`; после LLL ищим вектор с последней координатой `±M`.',
        'Первые координаты найденного вектора — это ошибка `v − t`, а не сам секрет.',
        'Сохрани вывод: `sage attack.sage > found.txt`.',
    ],
    flag='nto{lll_3mb3dd1ng_cvp_b4b41}', batch='crypto-b14',
    solution=['sage attack.sage > found.txt'])


# =========================================================== WRITER ==========
def yaml_dq(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def js_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def lab_block(lab):
    lines = ['lab:', '  kind: shell', '  title: ' + yaml_dq(lab['title']),
             '  toolset: [' + ', '.join(lab['toolset']) + ']',
             '  workdir: ' + WD, '  files: [task.md]',
             '  check: ' + yaml_dq(CHECK), '  hints:']
    for h in lab['hints']:
        # unquote() in the Go parser strips only the outer quotes, so avoid
        # inner double quotes in hints (swap for single quotes for display).
        lines.append('    - ' + yaml_dq(h.replace('"', "'")))
    return '\n'.join(lines)


def build_fs(lab):
    fs = [f_dir(WD), {'path': WD + '/task.md', 'text': lab['task_md'], 'mode': '644'}]
    for f in lab['fs']:
        if f.get('path') == WD and f.get('type') == 'dir':
            continue
        fs.append(f)
    return fs


def write_bundle(lab):
    bundle = {'id': lab['id'], 'workdir': WD, 'hostname': 'lab',
              'expect': {'file': WD + '/found.txt', 'contains': lab['flag']},
              'fs': build_fs(lab), 'tools': lab['tools']}
    with open(os.path.join(LABS_DIR, lab['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write('\n')


def inject(lab):
    path = os.path.join(ROOT, 'content', lab['cat'], lab['id'] + '.md')
    txt = open(path, encoding='utf-8').read()
    m = re.match(r'^(---\n)(.*?\n)(---\n)', txt, re.S)
    assert m, 'no front-matter: ' + path
    if re.search(r'^lab:', m.group(2), re.M):
        print('SKIP (already has lab):', lab['id'])
        return
    new = '---\n' + m.group(2) + lab_block(lab) + '\n---\n' + txt[m.end():]
    open(path, 'w', encoding='utf-8').write(new)


def write_spec(batch, labs):
    out = []
    out.append("import { describe, it, expect } from 'vitest'")
    out.append("import fs from 'node:fs'")
    out.append("import path from 'node:path'")
    out.append("import { createSession } from './session'")
    out.append('')
    out.append('// End-to-end solvability check for lab batch ' + batch + '.')
    out.append("const dir = path.resolve(process.cwd(), '../content/labs')")
    out.append("const WD = '/home/student/task'")
    out.append("const CHECK = \"grep -q 'nto{' found.txt\"")
    out.append('')
    out.append('function load(id) {')
    out.append("  return JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))")
    out.append('}')
    out.append('')
    out.append('const LABS = [')
    for lab in labs:
        sol = ', '.join(js_str(c) for c in lab['solution'])
        out.append('  {')
        out.append('    id: ' + js_str(lab['id']) + ', flag: ' + js_str(lab['flag']) + ', hints: ' + str(len(lab['hints'])) + ',')
        out.append('    solution: [' + sol + '],')
        out.append('  },')
    out.append(']')
    out.append('')
    out.append("describe.each(LABS)('lab batch " + batch + ": $id', ({ id, flag, hints, solution }) => {")
    out.append('  const bundle = load(id)')
    out.append("  const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: Array(hints).fill('h') }")
    out.append('')
    out.append("  it('bundle + seed files are consistent with the lesson lab block', () => {")
    out.append('    expect(bundle.id).toBe(id)')
    out.append('    expect(bundle.workdir).toBe(WD)')
    out.append('    expect(bundle.fs.some((f) => f.path === `${WD}/task.md`)).toBe(true)')
    out.append('    expect(bundle.expect.file).toBe(`${WD}/found.txt`)')
    out.append('    expect(bundle.expect.contains).toBe(flag)')
    out.append('  })')
    out.append('')
    out.append("  it('replays the intended solution and passes check', async () => {")
    out.append('    const s = createSession({ spec, bundle })')
    out.append("    expect((await s.run('check')).code).toBe(1)")
    out.append('    for (const cmd of solution) await s.run(cmd)')
    out.append("    expect((await s.run('check')).code).toBe(0)")
    out.append('  })')
    out.append('})')
    path = os.path.join(ROOT, 'frontend', 'src', 'lab', batch + '.spec.js')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')


def main():
    batches = {}
    for lab in LABS:
        write_bundle(lab)
        inject(lab)
        batches.setdefault(lab['batch'], []).append(lab)
    for batch, labs in batches.items():
        write_spec(batch, labs)
    print('Wrote %d bundles, %d specs:' % (len(LABS), len(batches)))
    for b, labs in batches.items():
        print('  %s: %s' % (b, ', '.join(l['id'] for l in labs)))


if __name__ == '__main__':
    main()
