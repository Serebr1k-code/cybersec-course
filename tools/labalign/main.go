// Command labalign audits the rule "лаба = урок + напоминание о пути"
// (docs/LABS.md): every interactive lab must
//
//	(a) practise the CURRENT lesson's own skill, using ONLY tools the lesson
//	    itself teaches (lab ⊆ lesson); and
//	(b) chain at least one sub-step drawn from the lesson's PREREQUISITE path
//	    (front-matter `prerequisites:` and/or the parent chain), so earlier
//	    material is reinforced (spaced repetition).
//
// It reports three flag classes per lesson that carries a `lab:` block:
//
//	lab-tool-untaught : a tool the lab actually invokes (bundle `tools` keys,
//	                    back-ticked commands in the bundle `task.md`, or the
//	                    front-matter hints) is NOT mentioned anywhere in the
//	                    lesson body.
//	topic-unrelated   : the lab's topic tokens (invoked tools + files named in
//	                    `check`/task + the task heading) share NOTHING with the
//	                    lesson's own vocabulary (id, tags, title, body).
//	no-prereq-step    : the lesson HAS a prerequisite path (front-matter
//	                    prerequisites and/or parent chain) but the lab touches
//	                    NONE of it — it neither invokes a (non-basic) tool taught
//	                    on the path nor names a path lesson in its task/hints.
//
// A lesson with no prerequisite path at all (a root) is exempt from
// no-prereq-step (there is nothing earlier to reinforce).
//
// Usage: go run ./tools/labalign [-content ./content] [-category net] [-json] [-limit N]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"learningtree/internal/content"
	"learningtree/internal/model"
)

// ---- tool vocabulary -------------------------------------------------------

// canonical tool name -> regexp fragment matched in a lesson body.
var toolPatterns = map[string]string{
	"tshark": `\btshark\b`, "tcpdump": `\btcpdump\b`, "nmap": `\bnmap\b`,
	"masscan": `\bmasscan\b`, "naabu": `\bnaabu\b`, "gdb": `\bgdb\b`,
	"objdump": `\bobjdump\b`, "readelf": `\breadelf\b`, "nm": `\bnm\b`,
	"strace": `\bstrace\b`, "ltrace": `\bltrace\b`, "dig": `\bdig\b`,
	"nslookup": `\bnslookup\b`, "whois": `\bwhois\b`, "host": `\bhost\b`,
	"curl": `\bcurl\b`, "wget": `\bwget\b`, "jq": `\bjq\b`, "grep": `\bgrep\b`,
	"strings": `\bstrings\b`, "base64": `\bbase64\b`, "file": `\bfile\b`,
	"unzip": `\bunzip\b`, "tar": `\btar\b`, "xxd": `\bxxd\b`,
	"hexdump": `\bhexdump\b`, "exiftool": `\bexiftool\b`, "openssl": `\bopenssl\b`,
	"nc": `\bnc\b|\bncat\b|\bnetcat\b`, "socat": `\bsocat\b`, "git": `\bgit\b`,
	"hashcat": `\bhashcat\b`, "john": `\bjohn\b`, "sqlmap": `\bsqlmap\b`,
	"ffuf": `\bffuf\b`, "nuclei": `\bnuclei\b`, "gobuster": `\bgobuster\b`,
	"wfuzz": `\bwfuzz\b`, "feroxbuster": `\bferoxbuster\b`, "httpx": `\bhttpx\b`,
	"hydra": `\bhydra\b`, "kubectl": `\bkubectl\b`, "aws": `\baws\b`,
	"gcloud": `\bgcloud\b`, "volatility": `\bvolatility\b|\bvol\.py\b|\bvol3\b`,
	"sleuthkit": `\bfls\b|\bicat\b|\bmactime\b|\bfsstat\b|\bsleuthkit\b`,
	"sqlite3": `\bsqlite3\b`, "mongosh": `\bmongosh\b|\bmongo\b`,
	"redis-cli": `\bredis-cli\b`, "tesseract": `\btesseract\b`,
	"zbarimg": `\bzbarimg\b`, "steghide": `\bsteghide\b`, "stegseek": `\bstegseek\b`,
	"zsteg": `\bzsteg\b`, "binwalk": `\bbinwalk\b`, "apktool": `\bapktool\b`,
	"jadx": `\bjadx\b`, "objection": `\bobjection\b`, "yara": `\byara\b`,
	"gpg": `\bgpg\b`, "ssh": `\bssh\b`, "whatweb": `\bwhatweb\b`,
	"sslscan": `\bsslscan\b`, "websocat": `\bwebsocat\b`, "commix": `\bcommix\b`,
	"tplmap": `\btplmap\b`, "grpcurl": `\bgrpcurl\b`, "responder": `\bresponder\b`,
	"ntlmrelayx": `\bntlmrelayx\b`, "searchsploit": `\bsearchsploit\b`,
	"smtp-user-enum": `\bsmtp-user-enum\b`, "pdfinfo": `\bpdfinfo\b`,
	"sox": `\bsox\b`, "gitleaks": `\bgitleaks\b`, "googler": `\bgoogler\b`,
	"subfinder": `\bsubfinder\b`, "sherlock": `\bsherlock\b`, "argocd": `\bargocd\b`,
	"cryptsetup": `\bcryptsetup\b`, "keytool": `\bkeytool\b`, "plutil": `\bplutil\b`,
	"ffprobe": `\bffprobe\b`, "ffmpeg": `\bffmpeg\b`, "md5sum": `\bmd5sum\b`,
	"sha256sum": `\bsha256sum\b`, "sha1sum": `\bsha1sum\b`, "ropgadget": `\bROPgadget\b`,
	"ruby": `\bruby\b`, "php": `\bphp\b`, "java": `\bjava\b`, "node": `\bnode\b`,
	"pm3": `\bpm3\b|\bproxmark\b`, "regripper": `\bregripper\b|\brip\.pl\b`,
	"evtx": `\bevtxexport\b|\bevtxdump\b`, "adb": `\badb\b`, "qemu": `\bqemu\b`,
	"mdadm": `\bmdadm\b`, "lvm": `\bvgscan\b|\bpvscan\b|\blvm\b`, "btrfs": `\bbtrfs\b`,
	"ldd": `\bldd\b`, "radare2": `\bradare2\b|\br2\b|\brizin\b`, "ghidra": `\bghidra\b`,
	// network-heavy additions
	"dnsx": `\bdnsx\b`, "dnsrecon": `\bdnsrecon\b`, "nbtscan": `\bnbtscan\b`,
	"enum4linux": `\benum4linux\b`, "smbclient": `\bsmbclient\b`, "smbmap": `\bsmbmap\b`,
	"rpcclient": `\brpcclient\b`, "ldapsearch": `\bldapsearch\b`, "nxc": `\bnxc\b|\bcrackmapexec\b|\bcme\b`,
	"impacket": `\bimpacket\b|\bpsexec\.py\b|\bsecretsdump\b`, "kerbrute": `\bkerbrute\b`,
	"bloodhound": `\bbloodhound\b|\bsharphound\b`, "certipy": `\bcertipy\b`,
	"snmpwalk": `\bsnmpwalk\b`, "onesixtyone": `\bonesixtyone\b`, "snmp-check": `\bsnmp-check\b`,
	"tftp": `\btftp\b`, "rpcinfo": `\brpcinfo\b`, "showmount": `\bshowmount\b`,
	"mount": `\bmount\b`, "ftp": `\bftp\b`, "telnet": `\btelnet\b`,
	"xfreerdp": `\bxfreerdp\b`, "rdesktop": `\brdesktop\b`, "vncviewer": `\bvncviewer\b`,
	"wpscan": `\bwpscan\b`, "nikto": `\bnikto\b`, "dirb": `\bdirb\b`,
	"wafw00f": `\bwafw00f\b`, "sslyze": `\bsslyze\b`, "testssl": `\btestssl\b|\btestssl\.sh\b`,
	"aircrack-ng": `\baircrack-ng\b`, "airodump-ng": `\bairodump-ng\b`, "reaver": `\breaver\b`,
	"wifite": `\bwifite\b`, "hcxdumptool": `\bhcxdumptool\b`, "hcxtools": `\bhcxtools\b`,
	"kismet": `\bkismet\b`, "bettercap": `\bbettercap\b`, "arp-scan": `\barp-scan\b`,
	"ettercap": `\bettercap\b`, "scapy": `\bscapy\b`, "python3": `\bpython3\b|\bpython\b`,
	"mysql": `\bmysql\b`, "psql": `\bpsql\b`, "sshpass": `\bsshpass\b`,
	"traceroute": `\btraceroute\b`, "mtr": `\bmtr\b`, "arping": `\barping\b`,
	"fping": `\bfping\b`, "ping": `\bping\b`, "proxychains": `\bproxychains\b`,
	"chisel": `\bchisel\b`, "ligolo": `\bligolo\b`, "iodine": `\biodine\b`,
	"dns2tcp": `\bdns2tcp\b`, "busybox": `\bbusybox\b`, 	"perl": `\bperl\b`,
	"dnschef": `\bdnschef\b`, "ip": `\bip\b`,
	"ifconfig": `\bifconfig\b`, "route": `\broute\b`, "tcpflow": `\btcpflow\b`,
	"tcpick": `\btcpick\b`, "mitmproxy": `\bmitmproxy\b|\bmitmweb\b`,
	"wireshark": `\bwireshark\b`,
}

// aliases seen in back-ticked commands / bundle tool keys -> canonical name.
var alias = map[string]string{
	"ncat": "nc", "netcat": "nc", "crackmapexec": "nxc", "cme": "nxc",
	"sharphound": "bloodhound", "vol.py": "volatility", "vol3": "volatility",
	"fls": "sleuthkit", "icat": "sleuthkit", "mactime": "sleuthkit",
	"fsstat": "sleuthkit", "rip.pl": "regripper", "regripper": "regripper",
	"evtxexport": "evtx", "evtxdump": "evtx", "testssl.sh": "testssl",
	"r2": "radare2", "rizin": "radare2",
	"proxmark": "pm3", "psexec.py": "impacket", "secretsdump": "impacket",
	"aircrack-ng": "aircrack-ng", "airodump-ng": "airodump-ng",
	"arp-scan": "arp-scan", "mitmweb": "mitmproxy", "busybox": "busybox",
}

// tools that are too generic to count as evidence of a taught skill — their
// absence from a lesson body is a weak signal, and their presence in a
// prerequisite is not a meaningful "reminder" of earlier material.
var basic = map[string]bool{
	"grep": true, "base64": true, "file": true, "strings": true, "unzip": true,
	"tar": true, "jq": true, "xxd": true, "hexdump": true, "curl": true,
	"wget": true, "cat": true, "echo": true, "ls": true, "sed": true,
	"awk": true, "md5sum": true, "sha256sum": true, "sha1sum": true,
	"host": true, "ping": true, "ip": true, "route": true, "mount": true,
	"ssh": true, "python3": true, "python": true, "perl": true, "ruby": true,
	"php": true, "java": true, "node": true, "busybox": true, "find": true,
}

var wordRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.\-]*`)
var backtickRe = regexp.MustCompile("`([^`]+)`")

type compiledTool struct {
	name string
	re   *regexp.Regexp
}

var compiledOnce bool
var compiledTools []compiledTool

func ensureCompiled() {
	if compiledOnce {
		return
	}
	for name, pat := range toolPatterns {
		if re, err := regexp.Compile("(?i)" + pat); err == nil {
			compiledTools = append(compiledTools, compiledTool{name, re})
		}
	}
	compiledOnce = true
}

// bodyToolsCache memoises toolsMentioned per lesson id.
var bodyToolsCache = map[string]map[string]bool{}

// ---- bundle model ----------------------------------------------------------

type toolCase struct {
	Match string `json:"match"`
}

type toolFixture struct {
	Cases []toolCase `json:"cases"`
}

type seed struct {
	Path string  `json:"path"`
	Text *string `json:"text"`
}

type bundle struct {
	ID    string                 `json:"id"`
	FS    []seed                 `json:"fs"`
	Tools map[string]toolFixture `json:"tools"`
}

type finding struct {
	Lesson   string   `json:"lesson"`
	Slug     string   `json:"slug"`
	Category string   `json:"category"`
	Kind     string   `json:"kind"`
	Detail   string   `json:"detail"`
	Missing  []string `json:"missing,omitempty"`
}

func main() {
	contentDir := flag.String("content", "./content", "content directory")
	onlyCat := flag.String("category", "", "restrict to one category")
	asJSON := flag.Bool("json", false, "machine-readable output")
	limit := flag.Int("limit", 0, "cap the number of examples printed per flag class")
	flag.Parse()

	store := content.NewStore(*contentDir)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "load error: %v\n", err)
		os.Exit(2)
	}

	lessons := store.All()
	byID := map[string]*model.Lesson{}
	for _, l := range lessons {
		byID[l.ID] = l
	}

	var flags []finding
	perCatLabs := map[string]int{}
	perCatFlag := map[string]map[string]int{}

	bump := func(cat, kind string) {
		if perCatFlag[cat] == nil {
			perCatFlag[cat] = map[string]int{}
		}
		perCatFlag[cat][kind]++
	}

	total := 0
	for _, l := range lessons {
		if l.Lab == nil {
			continue
		}
		if *onlyCat != "" && l.Category != *onlyCat {
			continue
		}
		total++
		perCatLabs[l.Category]++

		bodyTools := toolsForLesson(l)

		labT, taskText := invokedToolsCached(*contentDir, l)

		// (i) lab ⊆ lesson
		var untaught []string
		for t := range labT {
			if basic[t] {
				continue
			}
			if !bodyTools[t] {
				untaught = append(untaught, t)
			}
		}
		sort.Strings(untaught)
		if len(untaught) > 0 {
			flags = append(flags, finding{Lesson: l.Title, Slug: l.ID, Category: l.Category,
				Kind: "lab-tool-untaught", Detail: "lab invokes tools the lesson never teaches",
				Missing: untaught})
			bump(l.Category, "lab-tool-untaught")
		}

		// (ii) topic overlap (coarse)
		if !topicRelated(l, labT, taskText) {
			flags = append(flags, finding{Lesson: l.Title, Slug: l.ID, Category: l.Category,
				Kind: "topic-unrelated", Detail: "lab topic tokens share nothing with the lesson vocabulary"})
			bump(l.Category, "topic-unrelated")
		}

		// (iii) prerequisite reminder
		path := prereqPath(l, byID)
		if len(path) > 0 {
			prereqTools := map[string]bool{}
			for _, pid := range path {
				if p, ok := byID[pid]; ok {
					for t := range toolsForLesson(p) {
						prereqTools[t] = true
					}
					if p.Lab != nil {
						lt, _ := invokedToolsCached(*contentDir, p)
						for t := range lt {
							prereqTools[t] = true
						}
					}
				}
			}
			// (a) the lab actually invokes a non-basic tool taught on the path.
			toolTouched := false
			for t := range labT {
				if basic[t] {
					continue
				}
				if prereqTools[t] {
					toolTouched = true
					break
				}
			}
			// (b) the lab's own text (task + hints + check) names a prerequisite
			// lesson — an explicit "повторение" reminder.
			refText := strings.ToLower(taskText + "\n" + strings.Join(l.Lab.Hints, "\n") + "\n" + l.Lab.Check)
			textTouched := false
			for _, pid := range path {
				if strings.Contains(refText, strings.ToLower(pid)) {
					textTouched = true
					break
				}
			}
			if !toolTouched && !textTouched {
				flags = append(flags, finding{Lesson: l.Title, Slug: l.ID, Category: l.Category,
					Kind: "no-prereq-step",
					Detail: fmt.Sprintf("lab chains no step from its prerequisite path (%d prereq lesson(s))",
						len(path))})
				bump(l.Category, "no-prereq-step")
			}
		}
	}

	sort.Slice(flags, func(i, j int) bool {
		if flags[i].Kind != flags[j].Kind {
			return flags[i].Kind < flags[j].Kind
		}
		return flags[i].Slug < flags[j].Slug
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"labs":         total,
			"per_category": perCatLabs,
			"flags_by_category": perCatFlag,
			"flags":        flags,
		})
		return
	}

	fmt.Printf("labalign: %d lab(s) audited\n", total)
	classes := []string{"lab-tool-untaught", "topic-unrelated", "no-prereq-step"}
	counts := map[string]int{}
	for _, f := range flags {
		counts[f.Kind]++
	}
	for _, c := range classes {
		fmt.Printf("  %-18s %d\n", c, counts[c])
	}
	fmt.Println("--- per category ---")
	cats := make([]string, 0, len(perCatFlag))
	for c := range perCatFlag {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Printf("  %-12s labs=%d  untaught=%d topic=%d no-prereq=%d\n", c, perCatLabs[c],
			perCatFlag[c]["lab-tool-untaught"], perCatFlag[c]["topic-unrelated"], perCatFlag[c]["no-prereq-step"])
	}
	fmt.Println("--- examples ---")
	shown := map[string]int{}
	for _, f := range flags {
		if *limit > 0 && shown[f.Kind] >= *limit {
			continue
		}
		shown[f.Kind]++
		extra := ""
		if len(f.Missing) > 0 {
			extra = " [" + strings.Join(f.Missing, ",") + "]"
		}
		fmt.Printf("  [%s] %s/%s: %s%s\n", f.Kind, f.Category, f.Slug, f.Detail, extra)
	}
}

// ---- helpers ---------------------------------------------------------------

func lessonBody(l *model.Lesson) string {
	var sb strings.Builder
	for _, s := range l.Sections {
		sb.WriteString(s.Title)
		sb.WriteString("\n")
		sb.WriteString(s.Markdown)
		sb.WriteString("\n")
	}
	return sb.String()
}

func toolsMentioned(text string) map[string]bool {
	ensureCompiled()
	out := map[string]bool{}
	for _, ct := range compiledTools {
		if ct.re.MatchString(text) {
			out[ct.name] = true
		}
	}
	return out
}

// toolsForLesson memoises toolsMentioned over a lesson body by id.
func toolsForLesson(l *model.Lesson) map[string]bool {
	if l == nil {
		return map[string]bool{}
	}
	if c, ok := bodyToolsCache[l.ID]; ok {
		return c
	}
	c := toolsMentioned(lessonBody(l))
	bodyToolsCache[l.ID] = c
	return c
}

// labTools returns the canonical tools a lab actually invokes, from the three
// strongest signals: bundle `tools` keys, back-ticked commands in the bundle
// `task.md`, and the front-matter hints. taskText is returned for topic checks.
var invokedCache = map[string]struct {
	tools map[string]bool
	task  string
}{}

// invokedToolsCached memoises invokedTools by lesson id.
func invokedToolsCached(contentDir string, l *model.Lesson) (map[string]bool, string) {
	if c, ok := invokedCache[l.ID]; ok {
		return c.tools, c.task
	}
	t, task := invokedTools(contentDir, l)
	invokedCache[l.ID] = struct {
		tools map[string]bool
		task  string
	}{t, task}
	return t, task
}

func invokedTools(contentDir string, l *model.Lesson) (map[string]bool, string) {
	out := map[string]bool{}
	bundleID := l.Lab.Bundle
	if bundleID == "" {
		bundleID = l.ID
	}
	p := filepath.Join(contentDir, "labs", bundleID+".json")
	var taskText string
	raw, err := os.ReadFile(p)
	if err == nil {
		var b bundle
		if json.Unmarshal(raw, &b) == nil {
			for name := range b.Tools {
				out[canonical(name)] = true
			}
			for _, s := range b.FS {
				if strings.HasSuffix(filepath.ToSlash(s.Path), "task.md") && s.Text != nil {
					taskText += *s.Text + "\n"
					for t := range toolsInCommands(*s.Text) {
						out[t] = true
					}
				}
			}
		}
	}
	// front-matter hints carry back-ticked commands too.
	for _, h := range l.Lab.Hints {
		for t := range toolsInCommands(h) {
			out[t] = true
		}
	}
	return out, taskText
}

// toolsInCommands finds canonical tools whose name appears as the first word of
// a back-ticked span or anywhere in a back-ticked command line.
func toolsInCommands(text string) map[string]bool {
	out := map[string]bool{}
	for _, span := range backtickRe.FindAllStringSubmatch(text, -1) {
		for _, w := range wordRe.FindAllString(span[1], -1) {
			if c, ok := alias[strings.ToLower(w)]; ok {
				out[c] = true
				continue
			}
			if _, ok := toolPatterns[strings.ToLower(w)]; ok {
				out[strings.ToLower(w)] = true
			}
		}
	}
	return out
}

func canonical(name string) string {
	n := strings.ToLower(name)
	if c, ok := alias[n]; ok {
		return c
	}
	if _, ok := toolPatterns[n]; ok {
		return n
	}
	return n
}

// prereqPath collects the lesson's prerequisite lessons: the transitive closure
// of front-matter `prerequisites:` plus the parent chain (ancestors), capped in
// depth to avoid cycles.
func prereqPath(l *model.Lesson, byID map[string]*model.Lesson) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || id == l.ID || seen[id] {
			return
		}
		if _, ok := byID[id]; !ok {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	// direct prerequisites (one hop)
	for _, p := range l.Prerequisites {
		add(p)
	}
	// parent chain
	cur := l
	for depth := 0; depth < 6; depth++ {
		if cur.Parent == "" {
			break
		}
		add(cur.Parent)
		p, ok := byID[cur.Parent]
		if !ok {
			break
		}
		cur = p
	}
	// one more hop through the prerequisites' own prerequisites
	for _, p := range append([]string{}, out...) {
		if pl, ok := byID[p]; ok {
			for _, pp := range pl.Prerequisites {
				add(pp)
			}
		}
	}
	return out
}

// topicRelated is a coarse guard against a lab whose topic has nothing to do
// with the lesson. It compares the lab's topic tokens (invoked tools, files
// named in `check`/task, and words from the task heading) against the lesson's
// vocabulary (id, tags, title, and body). Empty intersection == flagged.
func topicRelated(l *model.Lesson, labTools map[string]bool, taskText string) bool {
	lab := map[string]bool{}
	for t := range labTools {
		lab[t] = true
	}
	for _, w := range wordRe.FindAllString(l.Lab.Check, -1) {
		lab[strings.ToLower(w)] = true
	}
	for _, w := range wordRe.FindAllString(taskText, -1) {
		if len(w) >= 3 {
			lab[strings.ToLower(w)] = true
		}
	}
	// NB: the lesson id is deliberately NOT injected here — it always overlaps
	// the lesson vocabulary and would make this check vacuous.

	lesson := map[string]bool{}
	addText := func(s string) {
		for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
			lesson[w] = true
		}
	}
	addText(l.ID)
	addText(l.Title)
	for _, t := range l.Tags {
		addText(t)
	}
	addText(lessonBody(l))

	for t := range lab {
		if lesson[t] {
			return true
		}
	}
	return false
}
