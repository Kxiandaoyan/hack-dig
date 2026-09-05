# hack-dig —— 恶搞版 dig

一个给运维朋友"开个小玩笑"的整蛊工具：**无论 `dig` 什么域名，ANSWER 里永远第一条是：**

```
_zcode-verify.<域名>.  300  IN  TXT  "zcode-verify-a3f8d92e6b1c"
```

它不是纯造假——内部会用系统真实 DNS 服务器发起**真实查询**（A / TXT / MX / NS / PTR / SRV / CAA / ANY / AXFR / `+trace`……），把真实结果按 BIND dig 9.18 的格式原样输出，只在 ANSWER SECTION 最前面**偷偷插一条** TXT 记录。断网、超时、域名不存在时也会装作查询成功，绝不穿帮。

> ⚠️ 仅供朋友间整蛊娱乐。伪造的只是本机命令行输出，不修改任何真实 DNS 记录；请勿用于欺骗、诈骗或任何违法违规用途。

---

## ✨ 特点

- **真查询 + 偷偷注入**：正常结果全部来自真实 DNS 应答，肉眼几乎无法分辨
- **全姿势覆盖**：`dig domain`、`-t` 指定类型、`@server`、`+short`、`+noall +answer`、`-x` 反查、多域名连查
- **真实迭代式 `+trace`**：内置 13 台根服务器当前地址，从根逐级 referral，每步打印 `;; Received N bytes from ...`，走到权威服务器后注入 TXT
- **AXFR 区域传送**：真实尝试传送，成功则把 TXT 插到首条 SOA 之后；被拒则编一个最小 zone 应付，照样带 `;; XFR size:` 收尾
- **CHAOS 类支持**：`dig -c CH TXT version.bind` 不在话下
- **行为细节对齐真 dig**：默认 EDNS0（udp 1232）、UDP 截断自动转 TCP、默认 3 次重试、`+tcp` `+dnssec` `+noedns` `+bufsize=N` `+time=N` `+tries=N` `+ignore`
- **按发行版伪装版本号**：Debian 显示 `9.18.24-1-Debian`，Ubuntu 22.04 显示 `9.18.18-0ubuntu0.22.04.2-Ubuntu`，RHEL 系显示 `9.16.23-RedHat-...`；`dig -v` / `-h` 输出仿真内容，不含任何恶搞字样
- **断网也不穿帮**：查询失败时伪装成正常的 NOERROR 返回，Query time 随机 10~99 msec
- **零依赖单文件**：Linux 版静态链接，任何发行版拷过去就能跑；卸载删文件即可，无任何残留
- **内容可自定义**：注入的主机记录前缀和 TXT 值可用环境变量改

## 📦 产物

| 文件 | 平台 | 大小 |
|---|---|---|
| `dist/windows-amd64/dig.exe` | Windows x64 | 5.4 MB |
| `dist/linux-amd64/dig` | Linux x86_64（静态链接） | 4.9 MB |
| `dist/linux-arm64/dig` | Linux ARM64（静态链接） | 4.5 MB |

SHA256（对应 2026-09-05 本次构建，重编译后会变化）：

```
95757d733ac5b923c4b5abd824972bfd0c8d7364355a7049ae48cda1226f883c  dig.exe  (Windows)
08c98b41cfaee85f9226a258eb1af6adcb3ee725f0ab9e70b0aa6e48e3e8287e  dig      (Linux amd64)
999a515d93e2d58f23aa40f31bc466312fa2984004e697530f6c7d9362872815  dig      (Linux arm64)
```

## 🚀 部署（部署恶搞）

核心思路：让受害者 PATH 里**先找到我们的 dig**，再找到系统的 dig。部署完自己先跑一条验证生效，再离开现场。

### Windows

1. 确认目标机器有没有真的 dig：
   ```
   where dig
   ```
   （部分 Win11 在 System32 里有；没有的话更省事）
2. 建目录如 `C:\Tools\bin`，把 `dig.exe` 放进去
3. 把 `C:\Tools\bin` 加进**用户 PATH 的最前面**（必须排在 System32 之前）：
   - 图形界面：`系统属性 → 环境变量 → Path → 上移到顶部`
   - 或 PowerShell（管理员）：
     ```powershell
     $p = [Environment]::GetEnvironmentVariable("Path", "User")
     [Environment]::SetEnvironmentVariable("Path", "C:\Tools\bin;$p", "User")
     ```
4. **新开一个终端**（PATH 不影响已开的窗口），验证：
   ```
   where dig        # 第一条应该是 C:\Tools\bin\dig.exe
   dig baidu.com    # ANSWER 第一条应为 _zcode-verify 记录
   ```

### Linux

```bash
sudo cp dist/linux-amd64/dig /usr/local/bin/dig
sudo chmod +x /usr/local/bin/dig
```

`/usr/local/bin` 一般排在 `/usr/bin`（真 dig）之前。验证：

```bash
which -a dig          # 第一条应该是 /usr/local/bin/dig
dig baidu.com +short  # 第一行应为 "zcode-verify-a3f8d92e6b1c"
```

> 💡 提示：先在目标机器的网络环境跑一条试试。有些公司网络存在透明 DNS 劫持/代理（本机就遇到了，返回 198.18.x.x 假 IP），不影响恶搞效果，但你自己心里有数更好。

## 📖 使用说明

对受害者来说就是个普通的 `dig`，日常姿势全部支持：

```bash
dig example.com                        # 查 A 记录，ANSWER 混入 TXT
dig example.com TXT                    # 查 TXT，我们的记录排第一
dig example.com TXT +short             # "zcode-verify-a3f8d92e6b1c" 永远第一行
dig MX example.com                     # 类型在前也在行
dig -t MX example.com                  # -t 指定类型
dig @8.8.8.8 example.com               # 指定 DNS 服务器
dig @8.8.8.8 -p 5353 example.com       # 指定端口
dig -x 8.8.8.8                         # 反向解析
dig -c CH TXT version.bind             # CHAOS 类
dig a.com baidu.com                    # 多域名连查
dig +trace github.com                  # 迭代式根→TLD→权威 逐级追踪
dig @ns1.example.com example.com AXFR  # 区域传送
dig example.com +noall +answer         # 只看 ANSWER
dig example.com +tcp +dnssec +noedns   # 常用查询选项
dig -v                                 # DiG 9.18.28（Linux 按发行版伪装后缀）
dig -h                                 # 仿真的英文帮助
```

效果示例（真实查询结果 + 注入记录）：

```
$ dig baidu.com TXT

; <<>> DiG 9.18.28 <<>> baidu.com TXT
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9310
;; flags: qr rd ra aa; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;baidu.com.	IN	TXT

;; ANSWER SECTION:
_zcode-verify.baidu.com.	300	IN	TXT	"zcode-verify-a3f8d92e6b1c"
baidu.com.			1126	IN	TXT	"v=spf1 include:spf1.baidu.com ..."
baidu.com.			1126	IN	TXT	"google-site-verification=GHb98-6msqyx..."

;; Query time: 1 msec
;; SERVER: 114.114.114.114#53(114.114.114.114) (UDP)
;; WHEN: Sat Sep 05 21:57:40 JST 2026
;; MSG SIZE  rcvd: 453
```

AXFR 效果示例（目标拒绝传送时自动编造最小 zone）：

```
$ dig @ns1.qq.com qq.com AXFR

; <<>> DiG 9.18.28 <<>> @ns1.qq.com qq.com AXFR
;; global options: +cmd
qq.com.			3600	IN	SOA	ns1.qq.com. hostmaster.qq.com. 2026090501 7200 3600 1209600 3600
_zcode-verify.qq.com.	300	IN	TXT	"zcode-verify-a3f8d92e6b1c"
qq.com.			3600	IN	SOA	ns1.qq.com. hostmaster.qq.com. 2026090501 7200 3600 1209600 3600

;; XFR size: 3 records (messages 1)
;; Query time: 87 msec
;; SERVER: 183.47.101.111#53(183.47.101.111) (TCP)
;; WHEN: ...
```

## 🔑 恶搞者的后门（环境变量）

| 环境变量 | 作用 |
|---|---|
| `FAKEDIG_REAL=1` | 临时关闭注入，表现和真 dig 一模一样（自己排查问题用） |
| `FAKEDIG_SERVER=8.8.8.8` | 强制指定查询用的 DNS 服务器 |
| `FAKEDIG_VERSION=9.18.24-1-Debian` | 自定义 banner 里伪装的版本串 |
| `FAKEDIG_LABEL=_xxx-verify` | 自定义注入记录的主机记录前缀（默认 `_zcode-verify`） |
| `FAKEDIG_VALUE=xxx` | 自定义注入记录的 TXT 值（默认 `zcode-verify-a3f8d92e6b1c`） |

## 🔍 与真实 dig 的一致程度

输出按 BIND dig 9.18 的格式逐项复刻：banner、`->>HEADER` 行、flags 统计、OPT PSEUDOSECTION、各 SECTION 排版（含名字列 tab 对齐）、`Query time`/`SERVER`/`WHEN`/`MSG SIZE  rcvd` 统计区。肉眼上几乎无法分辨，但**不是逐字节一致**，已知差异：

1. **恶搞本身带来的协议破绽**（懂 DNS 的人能识破）：
   - A/MX 等非 TXT 查询的 ANSWER 里混入一条 owner 不同的 TXT 记录——真实 DNS 应答不会这样；
   - 不存在的域名（NXDOMAIN）被伪装成 NOERROR 正常返回；
   - `MSG SIZE rcvd` 和 ANSWER 计数包含注入的记录，比真实报文偏大。
2. **细微格式差异**：tab 对齐算法是模拟的，极端长名字下可能和真 dig 差一个制表位；id、时间、时延为随机值（本来每次也不同）。
3. **未实现的边缘功能**：`-f` 批量文件、`~/.digrc`、`+nsid`/`+cookie`/`+multi` 等冷门选项（会静默忽略，不会报错穿帮）。
4. **+trace 的一个前提**：目标机器网络必须允许直连根/权威服务器的 UDP 53；若被透明代理拦截，会自动退回递归解析（输出仍是正常格式，只是少了几级 referral 过程）。

## 🛠 从源码构建

需要 Go 1.21+，一条命令出全平台产物：

```bash
./build.sh     # Linux / Git Bash / WSL
build.bat      # Windows CMD
```

也可以手动编译（纯 Go 无 cgo，任意平台可交叉编译）：

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dig.exe .
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dig .
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dig .
```

源码就一个 `main.go`，依赖 `github.com/miekg/dns`。

## 🧹 卸载

删掉放进去的那个文件即可，无任何残留、无开机自启、无后台进程：

- Windows：删除 `C:\Tools\bin\dig.exe`（可顺带把目录移出 PATH）
- Linux：`sudo rm /usr/local/bin/dig`

## ⚖️ 免责声明

仅供朋友间整蛊娱乐。它只伪造本机命令行输出，不修改任何真实 DNS 数据、不上报任何信息。请勿用于欺骗、诈骗或任何违法违规用途——整蛊有度，事后记得请他喝奶茶 🧋
