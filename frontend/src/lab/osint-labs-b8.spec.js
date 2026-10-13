import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the OSINT lab batch B8: each entry loads the
// REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts the lab's own `check` predicate passes. If a lab stops being
// solvable in the engine, this fails. Fixtures replay real Shodan/Censys/FOFA,
// Discord v10, Mastodon v1/v2, VK 5.131, Reddit JSON, Google News RSS, GDELT,
// t.me public preview, Tor onion leak-site HTML, plus a real JPEG (EXIF
// UserComment) for the webcam frame.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' answer.txt"

const LABS = [
  { id: 'osint-shodan-dorks', solution: [
    `shodan search --fields ip_str,port,product,version 'org:"Acme" port:22' > acme_ssh.json`,
    `jq -r '.[] | "\\(.ip_str)\\t\\(.product) \\(.version)"' acme_ssh.json`,
    'shodan host 203.0.113.15',
    "echo 'nto{sh0d4n_b4nn3r_r3v34l5_t0k3n}' > answer.txt"] },
  { id: 'osint-webcams', solution: [
    `shodan search --fields ip_str,port,product 'webcam country:RU has_screenshot:true'`,
    `ffprobe -rtsp_transport tcp -v error -show_entries stream=codec_name,width,height "rtsp://203.0.113.44:554/Streaming/Channels/101"`,
    'exiftool cam.jpg',
    'sha256sum cam.jpg',
    "echo 'nto{c4m_g30l0c4t3d_0n3_fr4m3}' > answer.txt"] },
  { id: 'osint-search-operators', solution: [
    `googler --json -n 20 "site:example.com inurl:admin" > dork1.json`,
    `googler --json -n 20 "site:example.com intitle:index of" > dork2.json`,
    `curl -s "https://example.com/admin/backup/" > listing.html`,
    `curl -s "https://example.com/admin/backup/config.php.bak" > backup.txt`,
    'grep nto backup.txt',
    "echo 'nto{d0rk3d_4dm1n_b4ckup_l34k}' > answer.txt"] },
  { id: 'osint-phone', solution: [
    'python3 phone.py',
    `curl -sI "https://wa.me/79165551122"`,
    `googler --json -n 10 "79165551122"`,
    `curl -s "https://forum.example.net/thread/4821" > post.html`,
    'grep nto post.html',
    "echo 'nto{ph0n3_t0_us3rn4m3_c0rr3l4t3d}' > answer.txt"] },
  { id: 'osint-telegram', solution: [
    `curl -s "https://t.me/s/examplecorp" > page.html`,
    'grep t.me page.html',
    `curl -s "https://t.me/s/examplecorp?before=1000" > older.html`,
    'grep nto older.html',
    "echo 'nto{t3l3gr4m_publ1c_pr3v13w_l34k}' > answer.txt"] },
  { id: 'osint-discord', solution: [
    `curl -s "https://discord.com/api/v10/invites/examplecorp?with_counts=true" > inv.json`,
    `jq '{name: .guild.name, id: .guild.id, members: .approximate_member_count}' inv.json`,
    `curl -s "https://discord.com/api/v10/guilds/123456789012345678/widget.json" > widget.json`,
    `jq -r '.channels[].name' widget.json`,
    "echo 'nto{d1sc0rd_w1dg3t_ch4nn3l_l34k}' > answer.txt"] },
  { id: 'osint-darkweb', solution: [
    `curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/" > site.html`,
    'grep example.com site.html',
    `curl -s --socks5-hostname 127.0.0.1:9050 "http://ex4mplel34k7f3k2q5v8w1z.onion/victims" > victims.html`,
    'grep nto victims.html',
    "echo 'nto{0n10n_l34k_s1t3_c0nf1rm3d}' > answer.txt"] },
  { id: 'osint-social-news', solution: [
    `curl -s "https://news.google.com/rss/search?q=%22Example+Corp%22&hl=en-US&gl=US&ceid=US:en" > news.xml`,
    'grep nto news.xml',
    `curl -s "https://api.gdeltproject.org/api/v2/doc/doc?query=%22Example+Corp%22&format=json" > gdelt.json`,
    `jq -r '.articles[].title' gdelt.json`,
    "echo 'nto{n3ws_c0d3n4m3_1n_h34dl1n3}' > answer.txt"] },
  { id: 'osint-social-reddit', solution: [
    `curl -s "https://www.reddit.com/user/pixel_engineer/about.json" > about.json`,
    `jq '.data.created_utc, .data.total_karma' about.json`,
    `curl -s "https://www.reddit.com/user/pixel_engineer/comments.json?limit=100" > comments.json`,
    `jq -r '.data.children[].data.body' comments.json`,
    "echo 'nto{r3dd1t_c0mm3nt_p0rtra1t}' > answer.txt"] },
  { id: 'osint-social-mastodon', solution: [
    `curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=Gargron" > gargron.json`,
    `jq '{username,acct,display_name,statuses_count,followers_count}' gargron.json`,
    `curl -s "https://mastodon.social/api/v1/accounts/lookup?acct=examplecorp" > corp.json`,
    `jq -r '.note' corp.json`,
    "echo 'nto{f3d1v3rs3_4cc0unt_4ttr1but3d}' > answer.txt"] },
  { id: 'osint-social-vk', solution: [
    `curl -s "https://api.vk.com/method/users.get?user_ids=1&fields=city,work&v=5.131" > user.json`,
    `jq '.response[0]' user.json`,
    `curl -s "https://api.vk.com/method/friends.get?user_id=1&fields=city,work&v=5.131" > friends.json`,
    `jq -r '.response.items[].work' friends.json`,
    "echo 'nto{vk_s0c14l_gr4ph_m4pp3d}' > answer.txt"] },
  { id: 'osint-censys-fofa', solution: [
    `curl -s "https://search.censys.io/api/v2/hosts/search?q=services.http.response.html_title%3A%20Grafana&per_page=50" > censys.json`,
    `jq -r '.result.hits[].ip' censys.json`,
    `curl -s "https://fofa.info/api/v1/search/all?qbase64=aHR0cF90aXRsZT0iR3JhZmFuYSI=&size=50" > fofa.json`,
    `jq -r '.results[].title' fofa.json`,
    "echo 'nto{c3nsys_f0f4_cr0ss_3ng1n3}' > answer.txt"] },
]

describe('osint labs B8 solve end-to-end', () => {
  for (const { id, solution } of LABS) {
    it(id, async () => {
      const bundle = JSON.parse(fs.readFileSync(path.join(dir, `${id}.json`), 'utf8'))
      const spec = { kind: 'shell', workdir: WD, check: CHECK, hints: ['a', 'b', 'c'] }
      const s = createSession({ spec, bundle })
      expect((await s.run('check')).stdout).toContain('не сходится')
      for (const cmd of solution) {
        const r = await s.run(cmd)
        expect(r.stderr, `${id}: ${cmd}`).not.toMatch(/command not found|нет в этой лабе/)
      }
      expect((await s.run('check')).stdout, `${id} check`).toContain('Готово')
      expect(s.solved).toBe(true)
    })
  }
})
