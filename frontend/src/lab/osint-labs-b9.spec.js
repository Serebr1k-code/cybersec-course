import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { createSession } from './session'

// End-to-end solvability check for the OSINT lab batch B9: each entry loads the
// REAL fixture bundle from content/labs, mirrors the `lab:` block from the
// lesson front-matter, replays the intended solution with the emulated tools,
// and asserts the lab's own `check` predicate passes. If a lab stops being
// solvable in the engine, this fails.
//
// Fixtures are real: JPEG/PNG files with genuine EXIF (written by piexif/PIL,
// so `strings` finds the hidden marker in the raw bytes), plus replays of real
// GitHub API / TinEye / PimEyes / Copernicus OData / fxtwitter / Instagram /
// TikTok oEmbed / Wikidata responses.
const dir = path.resolve(process.cwd(), '../content/labs')
const WD = '/home/student/task'
const CHECK = "grep -q 'nto{' answer.txt"

const LABS = [
  { id: 'osint-photo-forensics', solution: [
    'exiftool protest.jpg',
    'exiftool -a -u -g1 protest.jpg',
    'strings protest.jpg | grep nto',
    "echo 'nto{3l4_m4n1pul4t10n_d3t3ct3d}' > answer.txt"] },
  { id: 'osint-identity-resolution', solution: [
    'sherlock ipetrov-dev --timeout 6 --print-found',
    'curl -s https://api.github.com/users/ipetrov-dev > gh.json',
    `jq '{login,name,email,blog}' gh.json`,
    'gpg --search-keys i.petrov@example.com',
    'curl -s https://ipetrov.dev/ > site.html',
    'grep nto site.html',
    "echo 'nto{1d3nt1ty_r3s0lv3d_pgp_4nch0r}' > answer.txt"] },
  { id: 'osint-geolocation', solution: [
    'exiftool street.jpg',
    'tesseract street.jpg - -l rus+eng',
    `curl -s "https://nominatim.openstreetmap.org/reverse?lat=55.7558&lon=37.6173&format=json" > geo.json`,
    `jq -r '.display_name' geo.json`,
    "echo 'nto{g30_by_0cr_4nd_m4p5}' > answer.txt"] },
  { id: 'osint-satellite', solution: [
    `curl -s "https://catalogue.dataspace.copernicus.eu/odata/v1/Products?filter=Collection/Name eq 'SENTINEL-2'&top=5" > scenes.json`,
    `jq -r '.value[] | [.Name, .ContentDate.Start] | @tsv' scenes.json`,
    "echo 'nto{s3nt1n3l_ch4ng3_d3t3ct10n}' > answer.txt"] },
  { id: 'osint-deepfake', solution: [
    'exiftool -a -u -g1 suspect.jpg',
    `curl -s -X POST "https://api.example-detector.com/v1/detect" -F "file=@suspect.jpg" > det.json`,
    `jq '{verdict,confidence}' det.json`,
    "echo 'nto{synth3t1c_m3d14_c0nf1rm3d}' > answer.txt"] },
  { id: 'osint-image-reverse', solution: [
    'exiftool street.jpg',
    `curl -s -X POST "https://api.tineye.com/rest/search/" -F "image=@street.jpg" > tineye.json`,
    `jq -r '.matches[].backlinks[] | [.crawl_date, .url] | @tsv' tineye.json`,
    `curl -s "https://forum.example.org/thread/12345" > src.html`,
    'grep nto src.html',
    "echo 'nto{r3v3rs3_1m4g3_s0urc3_f0und}' > answer.txt"] },
  { id: 'osint-image-reverse-deep', solution: [
    'exiftool street.jpg',
    `curl -s -X POST "https://pimeyes.com/api/search" -F "image=@crop_face.jpg" > face.json`,
    `jq -r '.results[].profile_url' face.json`,
    `curl -s "https://serpapi.com/search?engine=google_lens&url=crop_sign.jpg" > lens.json`,
    `curl -s "https://vk.com/ivan_petrov" > vk.html`,
    'grep nto vk.html',
    "echo 'nto{f4c3_cr0p_4ttr1but3d}' > answer.txt"] },
  { id: 'osint-search-regional', solution: [
    `curl -s "https://yandex.com/search/?text=%22%D0%98%D0%B2%D0%B0%D0%BD+%D0%98%D0%B2%D0%B0%D0%BD%D0%BE%D0%B2%22+site:vk.com" > yandex.html`,
    'grep vk.com yandex.html',
    'grep nto yandex.html',
    "echo 'nto{y4nd3x_b34ts_g00gl3_ru}' > answer.txt"] },
  { id: 'osint-social-twitter', solution: [
    `curl -s "https://api.fxtwitter.com/nasa" > user.json`,
    `jq '.user | {screen_name,name,location,joined}' user.json`,
    `curl -s "https://api.fxtwitter.com/nasa/status/1098765432109876543" > tweet.json`,
    `jq -r '.tweet.text' tweet.json`,
    "echo 'nto{d3l3t3d_tw33t_f0und}' > answer.txt"] },
  { id: 'osint-social-instagram', solution: [
    `curl -s -H "x-ig-app-id: 936619743392459" "https://i.instagram.com/api/v1/users/web_profile_info/?username=examplecorp" > api.json`,
    `curl -s -A "Mozilla/5.0" "https://www.instagram.com/examplecorp/" > ig.html`,
    'grep og:description ig.html',
    'exiftool avatar.jpg',
    "echo 'nto{1nst4gr4m_4v4t4r_m3t4d4t4}' > answer.txt"] },
  { id: 'osint-social-tiktok', solution: [
    `curl -s "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@vintage.msk/video/7312345678901234567" > tt.json`,
    `jq '{author_name,title}' tt.json`,
    'tesseract frame_007.png -',
    'exiftool clip.mp4',
    "echo 'nto{t1kt0k_g30_v14_5t0r3_5ign}' > answer.txt"] },
  { id: 'osint-people-aggregators', solution: [
    `curl -s -H "User-Agent: osint-research" "https://api.example-people.com/search?name=Ivan+Petrov&city=Moscow" > people.json`,
    `jq -r '.records[] | [.name,.email,.phone] | @tsv' people.json`,
    `curl -s "https://www.wikidata.org/w/api.php?action=wbsearchentities&search=Ivan+Petrov&format=json" > wd.json`,
    `jq -r '.search[].id' wd.json`,
    "echo 'nto{p30pl3_4ggr3g4t0r_c0rr3l4t3d}' > answer.txt"] },
]

describe('osint labs B9 solve end-to-end', () => {
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
