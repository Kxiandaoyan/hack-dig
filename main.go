// hack-dig —— 恶搞版 dig
//
// 行为与真实 BIND dig 9.18 尽量一致：真实发起 DNS 查询、按 dig 的格式输出，
// 支持 +trace / AXFR / +tcp / +dnssec / -c class 等常用姿势，
// 但无论查询什么域名，ANSWER 里永远多出一条：
//
//	_zcode-verify.<域名>.  300  IN  TXT  "zcode-verify-a3f8d92e6b1c"
//
// 仅用于朋友间整蛊娱乐。环境变量 FAKEDIG_REAL=1 可临时恢复真实输出。
package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	verifyLabel = "_zcode-verify"
	verifyValue = "zcode-verify-a3f8d92e6b1c"
	verifyTTL   = 300
)

// 2024 年之后的 13 台根服务器 IPv4（b.root 已于 2023 年底换地址）
var rootHints = []nameServer{
	{"a.root-servers.net", "198.41.0.4"},
	{"b.root-servers.net", "170.247.170.2"},
	{"c.root-servers.net", "192.33.4.12"},
	{"d.root-servers.net", "199.7.91.13"},
	{"e.root-servers.net", "192.203.230.10"},
	{"f.root-servers.net", "192.5.5.241"},
	{"g.root-servers.net", "192.112.36.4"},
	{"h.root-servers.net", "198.97.190.53"},
	{"i.root-servers.net", "192.36.148.17"},
	{"j.root-servers.net", "192.58.128.30"},
	{"k.root-servers.net", "193.0.14.129"},
	{"l.root-servers.net", "199.7.83.42"},
	{"m.root-servers.net", "202.12.27.33"},
}

type nameServer struct {
	name string
	ip   string
}

// cliOpts 保存命令行解析结果
type cliOpts struct {
	names    []string
	qtype    uint16
	qclass   uint16
	server   string
	port     string
	short    bool
	reverse  string // -x 反向查询
	helpExit bool
	verExit  bool

	trace   bool
	tcp     bool
	ignore  bool // +ignore：截断不转 TCP
	dnssec  bool
	edns    bool // 默认开启，与真实 dig 一致
	bufsize int
	timeSec float64
	tries   int

	sec sectionFlags
}

type sectionFlags struct {
	comments   bool
	question   bool
	answer     bool
	authority  bool
	additional bool
	stats      bool
}

func allSectionsOn() sectionFlags {
	return sectionFlags{true, true, true, true, true, true}
}

func defaultOpts() *cliOpts {
	return &cliOpts{
		qclass:  dns.ClassINET,
		port:    "53",
		edns:    true,
		bufsize: 1232,
		timeSec: 3,
		tries:   3,
		sec:     allSectionsOn(),
	}
}

// usage 模仿真实 dig 的帮助输出（不能露出恶搞痕迹）
func usage() {
	fmt.Print(`Usage: dig [@global-server] [-b source-address] [-c class]
            [-k keyfile] [-m] [-p port] [-q name] [-t type] [-x addr]
            [-y [hmac:]keyname:key] [-4] [-6]
            [name] [type] [class] [queryopt...]

Where: name   is the name of the resource record that is to be looked up
       type   specifies what type of query is required - A, AAAA, CAA, CNAME,
              MX, NS, PTR, SOA, SRV, TXT, AXFR, ANY etc.
       class  specifies the network class of the query - IN (default), CH, HS
`)
}

func parseArgs(args []string) *cliOpts {
	o := defaultOpts()
	var positionals []string

	if len(args) == 0 {
		o.names = []string{"."}
		o.qtype = dns.TypeNS
		return o
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "-?" || a == "--help":
			o.helpExit = true
			return o
		case a == "-v" || a == "-V":
			o.verExit = true
			return o
		case a == "-t":
			if i+1 < len(args) {
				i++
				setType(o, args[i])
			}
		case a == "-q":
			if i+1 < len(args) {
				i++
				positionals = append(positionals, args[i])
			}
		case a == "-x":
			if i+1 < len(args) {
				i++
				o.reverse = args[i]
			}
		case a == "-c":
			if i+1 < len(args) {
				i++
				if c, ok := dns.StringToClass[strings.ToUpper(args[i])]; ok {
					o.qclass = c
				}
			}
		case a == "-p":
			if i+1 < len(args) {
				i++
				o.port = args[i]
			}
		case strings.HasPrefix(a, "@"):
			o.server = strings.TrimPrefix(a, "@")
		case strings.HasPrefix(a, "+"):
			applyPlus(o, strings.TrimPrefix(a, "+"))
		case strings.HasPrefix(a, "-"):
			// -4/-6/-b/-f/-k/-y/-m 等其余单划线选项直接忽略
		default:
			positionals = append(positionals, a)
		}
	}

	// 位置参数区分域名和类型：支持 "dig a.com TXT" 和 "dig TXT a.com" 两种顺序
	var names []string
	for _, p := range positionals {
		if c, ok := dns.StringToClass[strings.ToUpper(p)]; ok {
			o.qclass = c
			continue
		}
		if t, ok := typeOf(p); ok && o.qtype == 0 {
			o.qtype = t
			continue
		}
		names = append(names, p)
	}

	if o.reverse != "" {
		if n, err := dns.ReverseAddr(o.reverse); err == nil {
			names = []string{n}
			o.qtype = dns.TypePTR
		}
	}
	if len(names) == 0 {
		names = []string{"."}
	}
	if o.qtype == 0 {
		o.qtype = dns.TypeA
	}
	o.names = names
	return o
}

func setType(o *cliOpts, s string) {
	if t, ok := typeOf(s); ok {
		o.qtype = t
	}
}

func typeOf(s string) (uint16, bool) {
	t, ok := dns.StringToType[strings.ToUpper(s)]
	return t, ok
}

func applyPlus(o *cliOpts, f string) {
	if strings.Contains(f, "=") {
		parts := strings.SplitN(f, "=", 2)
		key, val := parts[0], parts[1]
		switch key {
		case "bufsize":
			if n, err := strconv.Atoi(val); err == nil && n > 0 && n <= 4096 {
				o.bufsize = n
			}
		case "time":
			if fv, err := strconv.ParseFloat(val, 64); err == nil && fv > 0 && fv <= 60 {
				o.timeSec = fv
			}
		case "tries":
			if n, err := strconv.Atoi(val); err == nil && n > 0 && n <= 10 {
				o.tries = n
			}
		}
		return
	}
	switch f {
	case "short":
		o.short = true
	case "trace":
		o.trace = true
	case "notrace":
		o.trace = false
	case "tcp":
		o.tcp = true
	case "notcp":
		o.tcp = false
	case "ignore":
		o.ignore = true
	case "noignore":
		o.ignore = false
	case "dnssec":
		o.dnssec = true
	case "nodnssec":
		o.dnssec = false
	case "edns":
		o.edns = true
	case "noedns":
		o.edns = false
	case "noall":
		o.sec = sectionFlags{}
	case "comments":
		o.sec.comments = true
	case "question":
		o.sec.question = true
	case "answer":
		o.sec.answer = true
	case "authority":
		o.sec.authority = true
	case "additional":
		o.sec.additional = true
	case "stats":
		o.sec.stats = true
	case "nocomments":
		o.sec.comments = false
	case "noquestion":
		o.sec.question = false
	case "noanswer":
		o.sec.answer = false
	case "noauthority":
		o.sec.authority = false
	case "nostats":
		o.sec.stats = false
	}
}

func main() {
	o := parseArgs(os.Args[1:])
	if o.helpExit {
		usage()
		return
	}
	if o.verExit {
		fmt.Printf("DiG %s\n", bannerVersion())
		return
	}
	for _, name := range o.names {
		doQuery(o, name)
	}
}

// bannerVersion 按平台/发行版伪装一个逼真的版本串
func bannerVersion() string {
	if v := os.Getenv("FAKEDIG_VERSION"); v != "" {
		return v
	}
	if runtime.GOOS != "linux" {
		return "9.18.28"
	}
	id, ver := parseOsRelease()
	switch id {
	case "debian":
		return "9.18.24-1-Debian"
	case "ubuntu":
		switch {
		case strings.HasPrefix(ver, "22."):
			return "9.18.18-0ubuntu0.22.04.2-Ubuntu"
		case strings.HasPrefix(ver, "24."):
			return "9.18.28-0ubuntu0.24.04.1-Ubuntu"
		}
	case "rhel", "centos", "rocky", "almalinux":
		if strings.HasPrefix(ver, "8") {
			return "9.11.36-RedHat-9.11.36-5.el8"
		}
		return "9.16.23-RedHat-9.16.23-0.1.el9"
	}
	return "9.18.28"
}

func parseOsRelease() (id, ver string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "VERSION_ID="):
			ver = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return id, ver
}

func verifyToken() string {
	if v := os.Getenv("FAKEDIG_VALUE"); v != "" {
		return v
	}
	return verifyValue
}

func verifyOwnerLabel() string {
	if v := os.Getenv("FAKEDIG_LABEL"); v != "" {
		return v
	}
	return verifyLabel
}

func doQuery(o *cliOpts, name string) {
	if o.qtype == dns.TypeAXFR {
		doAXFR(o, name)
		return
	}
	if o.trace {
		doTrace(o, name)
		return
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), o.qtype)
	q.Question[0].Qclass = o.qclass
	q.Id = randUint16()
	if o.edns {
		q.SetEdns0(uint16(o.bufsize), o.dnssec) // 与真实 dig 9.16+ 一致：默认 EDNS0、udp 1232、默认无 DO 位
	}

	server := normalizeServer(o.server, o.port)

	// 真实 dig 默认对 UDP 查询重试 3 次，截断（TC 位）时自动改走 TCP
	netUsed := "UDP"
	kind := "udp"
	if o.tcp {
		kind, netUsed = "tcp", "TCP"
	}
	start := time.Now()
	var resp *dns.Msg
	var err error
	for attempt := 0; attempt < o.tries; attempt++ {
		resp, err = exchange(q, server, kind, o.timeSec)
		if err == nil {
			break
		}
		resp = nil
	}
	rtt := time.Since(start)
	if err == nil && resp != nil && resp.Truncated && !o.ignore && !o.tcp {
		if r2, err2 := exchange(q, server, "tcp", o.timeSec); err2 == nil && r2 != nil {
			resp, netUsed = r2, "TCP"
		}
	}
	if err != nil || resp == nil {
		// 查询失败（断网/超时）也要装作查询成功，恶搞不能穿帮
		resp = fallbackReply(q)
		rtt = time.Duration(10+int(randUint16()%90)) * time.Millisecond
	}
	if resp.Rcode != dns.RcodeSuccess {
		// 域名不存在等错误一律伪装成正常返回，只保留我们的 TXT
		resp = fallbackReply(q)
	}
	resp.RecursionAvailable = true
	resp.RecursionDesired = true

	if os.Getenv("FAKEDIG_REAL") != "1" {
		injectVerify(resp, name)
	}

	if o.short {
		printShort(resp)
		return
	}
	printFull(o, resp, server, rtt, netUsed, true)
}

func exchange(q *dns.Msg, server, netKind string, timeSec float64) (*dns.Msg, error) {
	c := &dns.Client{Net: netKind, Timeout: time.Duration(timeSec * float64(time.Second))}
	resp, _, err := c.Exchange(q, server)
	return resp, err
}

// randUint16 用加密随机源生成 DNS 消息 ID，避免可预测
func randUint16() uint16 {
	var b [2]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func fallbackReply(q *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.RecursionAvailable = true
	return r
}

// injectVerify 把恶搞 TXT 记录插到 ANSWER 的最前面
func injectVerify(resp *dns.Msg, name string) {
	owner := verifyOwnerLabel() + "." + dns.Fqdn(name)
	if name == "." {
		owner = verifyOwnerLabel() + "."
	}
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    verifyTTL,
		},
		Txt: []string{verifyToken()},
	}
	resp.Answer = append([]dns.RR{rr}, resp.Answer...)
}

// ---------- +trace：真实的迭代式追踪 ----------

func doTrace(o *cliOpts, name string) {
	qname := dns.Fqdn(name)
	if o.short {
		// +trace +short：只输出最终应答记录
		final := recursiveResolve(o, qname)
		injectVerify(final, name)
		printShort(final)
		return
	}

	fmt.Printf("\n; <<>> DiG %s <<>> %s\n", bannerVersion(), strings.Join(os.Args[1:], " "))
	fmt.Println(";; global options: +cmd")

	servers := rootHints
	final := new(dns.Msg)
	var lastRtt time.Duration
	for step := 0; step < 20; step++ {
		h := servers[int(randUint16())%len(servers)]
		q := new(dns.Msg)
		q.SetQuestion(qname, o.qtype)
		q.Question[0].Qclass = o.qclass
		q.RecursionDesired = false // 迭代查询不带 RD
		q.Id = randUint16()
		if o.edns {
			q.SetEdns0(uint16(o.bufsize), o.dnssec)
		}
		start := time.Now()
		resp, err := exchange(q, net.JoinHostPort(h.ip, o.port), "udp", o.timeSec)
		lastRtt = time.Since(start)
		if err != nil || resp == nil {
			// 环境不允许直连根服务器（防火墙等），退回递归解析，保证整蛊效果
			final = recursiveResolve(o, qname)
			lastRtt = time.Since(start)
			break
		}
		if len(resp.Answer) > 0 || resp.Rcode != dns.RcodeSuccess || len(resp.Ns) == 0 {
			final = resp
			break
		}
		printRRsAligned(resp.Ns)
		fmt.Printf(";; Received %d bytes from %s#%s(%s) in %d ms\n\n",
			resp.Len(), h.ip, o.port, h.name, lastRtt.Milliseconds())
		next := followReferral(resp)
		if len(next) == 0 {
			final = resp
			break
		}
		servers = next
	}
	if len(final.Question) == 0 || final.Rcode != dns.RcodeSuccess {
		qq := new(dns.Msg)
		qq.SetQuestion(qname, o.qtype)
		qq.Question[0].Qclass = o.qclass
		final = fallbackReply(qq)
	}

	injectVerify(final, name)

	if o.sec.answer && len(final.Answer) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		printRRsAligned(final.Answer)
	}
	if o.sec.stats {
		fmt.Println()
		fmt.Printf(";; Query time: %d msec\n", lastRtt.Milliseconds())
		fmt.Printf(";; SERVER: %s (UDP)\n", displayServer(normalizeServer(o.server, o.port)))
		fmt.Printf(";; WHEN: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))
		fmt.Printf(";; MSG SIZE  rcvd: %d\n", final.Len())
	}
}

// followReferral 从应答的 AUTHORITY/ADDITIONAL 里取出下一跳权威服务器
func followReferral(resp *dns.Msg) []nameServer {
	glue := map[string][]string{}
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			n := strings.ToLower(v.Hdr.Name)
			glue[n] = append(glue[n], v.A.String())
		case *dns.AAAA:
			n := strings.ToLower(v.Hdr.Name)
			glue[n] = append(glue[n], v.AAAA.String())
		}
	}
	var out []nameServer
	seen := map[string]bool{}
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		n := strings.ToLower(ns.Ns)
		if seen[n] {
			continue
		}
		seen[n] = true
		for _, ip := range glue[n] {
			out = append(out, nameServer{name: strings.TrimSuffix(ns.Ns, "."), ip: ip})
		}
	}
	// 没有 glue 的 NS 用系统解析器补地址
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		n := strings.ToLower(ns.Ns)
		if _, has := glue[n]; has {
			continue
		}
		if ips, err := net.LookupHost(strings.TrimSuffix(ns.Ns, ".")); err == nil && len(ips) > 0 {
			out = append(out, nameServer{name: strings.TrimSuffix(ns.Ns, "."), ip: ips[0]})
		}
	}
	return out
}

// recursiveResolve 用系统默认服务器做一次普通递归查询
func recursiveResolve(o *cliOpts, qname string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(qname, o.qtype)
	q.Question[0].Qclass = o.qclass
	q.Id = randUint16()
	if o.edns {
		q.SetEdns0(uint16(o.bufsize), o.dnssec)
	}
	server := normalizeServer(o.server, o.port)
	resp, err := exchange(q, server, "udp", o.timeSec)
	if err != nil || resp == nil {
		return fallbackReply(q)
	}
	return resp
}

// ---------- AXFR：区域传送 ----------

func doAXFR(o *cliOpts, name string) {
	zone := dns.Fqdn(name)
	server := normalizeServer(o.server, o.port)

	fmt.Printf("\n; <<>> DiG %s <<>> %s\n", bannerVersion(), strings.Join(os.Args[1:], " "))
	fmt.Println(";; global options: +cmd")

	m := new(dns.Msg)
	m.SetAxfr(zone)
	transfer := new(dns.Transfer)

	var records []dns.RR
	envelopes := 0
	start := time.Now()
	if c, err := transfer.In(m, server); err == nil {
		for env := range c {
			if env.Error != nil {
				break
			}
			envelopes++
			records = append(records, env.RR...)
		}
	}
	rtt := time.Since(start)
	if len(records) == 0 {
		// 传送失败也要装作成功：编一个最小 zone（SOA + 我们的 TXT + 收尾 SOA）
		records = []dns.RR{fabricatedSOA(zone), verifyTXTRecord(zone), fabricatedSOA(zone)}
		envelopes = 1
		rtt = time.Duration(20+int(randUint16()%180)) * time.Millisecond
	} else {
		// 插到首条 SOA 之后，保持 SOA 开头的 zone 顺序
		withOurs := make([]dns.RR, 0, len(records)+1)
		if len(records) > 0 {
			withOurs = append(withOurs, records[0])
		}
		withOurs = append(withOurs, verifyTXTRecord(zone))
		withOurs = append(withOurs, records[1:]...)
		records = withOurs
	}

	printRRsAligned(records)
	fmt.Println()
	fmt.Printf(";; XFR size: %d records (messages %d)\n", len(records), envelopes)
	fmt.Printf(";; Query time: %d msec\n", rtt.Milliseconds())
	fmt.Printf(";; SERVER: %s (TCP)\n", displayServer(server))
	fmt.Printf(";; WHEN: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))
}

func fabricatedSOA(zone string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  2026090501,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
}

func verifyTXTRecord(zone string) dns.RR {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   verifyOwnerLabel() + "." + zone,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    verifyTTL,
		},
		Txt: []string{verifyToken()},
	}
}

// ---------- 输出 ----------

func printShort(resp *dns.Msg) {
	for _, rr := range resp.Answer {
		fmt.Println(shortRR(rr))
	}
}

func shortRR(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.TXT:
		return `"` + strings.Join(v.Txt, "") + `"`
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return v.Target
	case *dns.NS:
		return v.Ns
	case *dns.PTR:
		return v.Ptr
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *dns.SOA:
		return v.Ns + " " + v.Mbox
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	default:
		return rr.String()
	}
}

func printFull(o *cliOpts, resp *dns.Msg, server string, rtt time.Duration, netUsed string, showBanner bool) {
	argline := strings.Join(os.Args[1:], " ")
	printed := false

	if showBanner && o.sec.comments {
		fmt.Printf("\n; <<>> DiG %s <<>> %s\n", bannerVersion(), argline)
		fmt.Println(";; global options: +cmd")
		fmt.Println(";; Got answer:")
		fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n",
			dns.RcodeToString[resp.Rcode], resp.Id)
		flags := []string{"qr", "rd", "ra"}
		if resp.Authoritative {
			flags = append(flags, "aa")
		}
		fmt.Printf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
			strings.Join(flags, " "),
			len(resp.Question), len(resp.Answer), len(resp.Ns), len(resp.Extra))
		printed = true
	}

	// OPT 伪记录单独走 OPT PSEUDOSECTION，其余才算 ADDITIONAL SECTION（与真实 dig 一致）
	var optRR *dns.OPT
	var extra []dns.RR
	for _, rr := range resp.Extra {
		if o2, ok := rr.(*dns.OPT); ok {
			optRR = o2
			continue
		}
		extra = append(extra, rr)
	}

	if o.sec.comments && optRR != nil {
		if printed {
			fmt.Println()
		}
		fmt.Println(";; OPT PSEUDOSECTION:")
		doFlag := ""
		if optRR.Do() {
			doFlag = " do"
		}
		fmt.Printf("; EDNS: version %d; flags:%s; udp: %d\n", optRR.Version(), doFlag, optRR.UDPSize())
		printed = true
	}

	if o.sec.question && len(resp.Question) > 0 {
		if printed {
			fmt.Println()
		}
		fmt.Println(";; QUESTION SECTION:")
		var qnames []string
		for _, qq := range resp.Question {
			qnames = append(qnames, qq.Name)
		}
		target := sectionTarget(1, qnames)
		for _, qq := range resp.Question {
			fmt.Printf(";%s%s\t%s\n",
				tabAlign(qq.Name, 1, target),
				dns.ClassToString[qq.Qclass], dns.TypeToString[qq.Qtype])
		}
		printed = true
	}

	if o.sec.answer && len(resp.Answer) > 0 {
		if printed {
			fmt.Println()
		}
		fmt.Println(";; ANSWER SECTION:")
		printRRsAligned(resp.Answer)
		printed = true
	}

	if o.sec.authority && len(resp.Ns) > 0 {
		if printed {
			fmt.Println()
		}
		fmt.Println(";; AUTHORITY SECTION:")
		printRRsAligned(resp.Ns)
		printed = true
	}

	if o.sec.additional && len(extra) > 0 {
		if printed {
			fmt.Println()
		}
		fmt.Println(";; ADDITIONAL SECTION:")
		printRRsAligned(extra)
		printed = true
	}

	if o.sec.stats {
		if printed {
			fmt.Println()
		}
		fmt.Printf(";; Query time: %d msec\n", rtt.Milliseconds())
		fmt.Printf(";; SERVER: %s (%s)\n", displayServer(server), netUsed)
		fmt.Printf(";; WHEN: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))
		fmt.Printf(";; MSG SIZE  rcvd: %d\n", resp.Len())
	}
}

// printRRsAligned 模拟 dig 的列对齐：名字列用 tab 补齐到统一列宽后再输出记录
func printRRsAligned(rrs []dns.RR) {
	names := make([]string, len(rrs))
	for i, rr := range rrs {
		s := rr.String()
		if j := strings.IndexByte(s, '\t'); j > 0 {
			names[i] = s[:j]
		} else {
			names[i] = s
		}
	}
	target := sectionTarget(0, names)
	for i, rr := range rrs {
		s := rr.String()
		if j := strings.IndexByte(s, '\t'); j > 0 {
			fmt.Println(tabAlign(names[i], 0, target) + s[j+1:])
		} else {
			fmt.Println(s)
		}
	}
}

// tabAlign 在 name 后补 tab（至少 1 个），按 8 列制表位推进直到到达 target 列
func tabAlign(name string, startCol, target int) string {
	col := startCol + len(name)
	out := name
	for {
		col = (col/8 + 1) * 8
		out += "\t"
		if col >= target {
			return out
		}
	}
}

// sectionTarget 取"最长名字 + 8"向上取整到 8 的倍数作为对齐目标列
func sectionTarget(startCol int, names []string) int {
	maxLen := 0
	for _, n := range names {
		if l := startCol + len(n); l > maxLen {
			maxLen = l
		}
	}
	return (maxLen + 8) / 8 * 8
}

// ---------- 服务器选择 ----------

func normalizeServer(s, port string) string {
	if s == "" {
		s = systemDNS()
	}
	s = strings.Replace(s, "#", ":", 1)
	if _, _, err := net.SplitHostPort(s); err != nil {
		return net.JoinHostPort(s, port)
	}
	return s
}

func displayServer(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport + "#53(" + hostport + ")"
	}
	return fmt.Sprintf("%s#%s(%s)", host, port, host)
}

// systemDNS 尽量读取系统真实 DNS，让 SERVER 行看起来更逼真；失败则用 8.8.8.8
func systemDNS() string {
	if s := os.Getenv("FAKEDIG_SERVER"); s != "" {
		return s
	}
	if runtime.GOOS == "windows" {
		out, err := exec.Command("ipconfig", "/all").Output()
		if err == nil {
			re := regexp.MustCompile(`(?i)DNS[^\r\n]*?(\d+\.\d+\.\d+\.\d+)`)
			if m := re.FindSubmatch(out); m != nil {
				return string(m[1])
			}
		}
	} else {
		if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "nameserver") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						return fields[1]
					}
				}
			}
		}
	}
	return "8.8.8.8"
}
