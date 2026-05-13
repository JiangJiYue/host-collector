# Host Collector 本地 CLI

<p dir="auto">🌐 <a href="README.zh-CN.md">中文简体</a> | <a href="README.md">English</a></p>

Host Collector 本地 CLI 用于采集主机溯源证据并生成本地 JSON 目录，适合本机查看、离线交付和重复核验。

## 产物

| 产物 | 适用系统 |
|---|---|
| `host-collector-windows7-cli.exe` | Windows 7、Windows 8、Windows 8.1、Windows Server 2008 R2、Windows Server 2012、Windows Server 2012 R2 |
| `host-collector-windows10-cli.exe` | Windows 10、Windows 11、Windows Server 2016、Windows Server 2019、Windows Server 2022 以及更新的 Windows Server |
| `host-collector-linux-amd64` | Linux x86_64 / amd64 |
| `host-collector-linux-arm64` | Linux arm64 / aarch64 |

本地构建：

```bash
scripts/oss/build_cli.sh
```

## 使用方式

Windows 产物需要在“以管理员身份运行”的 CMD 或 PowerShell 中执行。Linux 产物需要使用 `sudo` 或 `root` 执行；低权限运行会被拒绝，因为主机溯源数据源需要提升权限读取。

```bash
host-collector scan --include host,process,network,logs,users,startup,software,timeline,web_logs,user_traces --days 7 --output-dir ./out
```

| 参数 | 说明 |
|---|---|
| `--include` | 要采集的域，逗号分隔 |
| `--exclude` | 在 include 结果上排除的域 |
| `--days` | `7`、`14` 或 `30`，限制支持时间窗口的证据 |
| `--output-dir` | 输出目录 |

当 `--output-dir` 写成 `.` 或 `./` 时，CLI 会在当前目录下自动创建一个本次扫描专属子目录，例如 `host-collector-20260512-101530`，并把 JSON 目录写入该子目录。

## 运行示例

Windows 管理员命令提示符会持续输出当前采集阶段、阶段序号和进度明细，便于确认采集是否仍在推进。

![Windows 采集进度明细](assets/windows-progress-detail.png)

Windows 事件日志采集会枚举可读取的事件通道。部分通道在当前系统上不支持查询时，会在控制台显示失败原因，但不影响其它通道和其它域继续写入。

![Windows 事件日志采集示例](assets/windows-event-log-progress.png)

Linux arm64 产物可以直接在 Linux ARM64 环境中使用 `sudo` 运行。示例中选择了主机、进程、网络、日志、用户、启动项、软件、时间线和 Web 日志域，并把结果写入自动创建的目录。

![Linux arm64 运行示例](assets/linux-arm64-run.png)

输出目录采用稳定的 section 文件结构，每个域写入独立 JSON，便于用脚本按域处理大体积数据。

![sections 输出目录示例](assets/windows-sections-output.png)

常用 include 写法：

```bash
# 采集全部通用 section 域，包含用户痕迹证据。
--include host,process,network,logs,users,startup,software,timeline,web_logs,user_traces

# 加上重型取证域：Windows 注册表、Windows/Linux 文件系统。
--include host,process,network,logs,users,startup,software,timeline,web_logs,user_traces,registry,file_system

# 小范围快速排查。
--include host,process,network

# 侧重时间窗口的扫描。
--include logs,startup,timeline,web_logs,user_traces --days 30

# 先选择较宽范围，再排除大体积域。
--include host,process,network,logs,users,startup,software,timeline,web_logs,user_traces --exclude web_logs
```

## 输出结构

```text
out/
  manifest.json
  sections/
    host.json
    process.json
    network.json
    logs.json
    users.json
    startup.json
    software.json
    timeline.json
    web_logs.json
    user_traces.json
    registry.json
    file_system.json
```

`manifest.json` 记录元数据、命令行参数和每个域对应的 section 文件。实际采集证据全部放在 `sections/` 目录中。

## 特点与原理

- 分域输出：采集结果按 `host`、`process`、`network`、`logs`、`users`、`startup`、`software`、`timeline`、`web_logs`、`user_traces`、`registry`、`file_system` 等域拆分，避免把所有证据塞进单个大文件。
- 可控范围：`--include` 是白名单，没写进去的域不会采集；`--exclude` 可以在宽范围扫描上排除某些域；`--days` 用于限制日志、Web 日志、用户痕迹和时间线等支持时间窗口的证据。
- 影子账户推断：Windows 账号域会交叉对比 NetAPI、WMI、`net user`、SAM 注册表、会话痕迹和本地组成员关系。若账号只存在于 SAM、SAM RID key 与 Names 索引不一致、API/WMI/命令行可见性冲突、多个账号复用 SAM `F`/`V` 数据摘要，或非内置账号异常进入管理员别名组，就会在用户证据中标出影子账户状态、置信度、原因码和证据来源。
- 中间件日志位置推断：Web 日志域会先从进程名、命令行、镜像路径和监听端口识别 IIS、Nginx、Apache、Tomcat 等运行时，再读取配置文件中的日志指令，例如 IIS site log directory、Nginx `access_log`/`include`、Apache `CustomLog`、Tomcat access log Valve，最后对候选文件做格式指纹识别并解析访问记录。
- Windows 溯源特点：支持事件日志、进程详情、网络连接、Prefetch、浏览器历史、USB 记录、服务/计划任务、注册表持久化项和 NTFS/文件系统取证。文件系统域会尽量保留卷、目录、文件时间戳、哈希状态、删除/孤立线索和采集诊断。
- Linux 溯源特点：支持 `/proc` 进程与网络证据、`/etc/passwd`/`/etc/group` 账号证据、sudo/admin 权限线索、systemd unit/timer、cron、包管理清单、认证/系统日志、shell history、Web 中间件日志、POSIX 文件权限、inode、软链接、setuid/setgid/sticky/world-writable 等文件系统证据。
- 原始证据优先：推断字段会保留来源、原因或 evidence 标记，方便回到原始 JSON 核验；缺失字段通常表示平台没有该数据源、权限不足、文件不可读，或本次 `--include` 未选择对应域。

## 下游分析项目思路

CLI 输出的是按域拆分的原始证据。下面这些内容适合作为读取 `manifest.json` 和 `sections/*.json` 的下游分析项目，并不是采集必需步骤，也不是 CLI 二进制当前内置的分析能力。

### IP、域名、URL 与哈希分析

可以单独做一个富化分析脚本或服务，从以下证据中抽取可观测对象：

- `sections/network.json`：远端 IP、监听端口、DNS 缓存/解析器证据、进程与连接关系。
- `sections/web_logs.json`：客户端 IP、Host、请求 URL、User-Agent、状态码、Referrer、异常路径。
- `sections/logs.json`：Windows 事件消息、Linux auth/syslog 消息、防火墙或服务日志。
- `sections/process.json`：命令行中的 URL、可疑域名、下载路径、可用时的可执行文件哈希。
- `sections/user_traces.json`：浏览器历史 URL 和 shell history 中的网络命令，进入分析前应先做敏感值脱敏。

推荐流程：

1. 把可观测对象规范化成 `observable`、`type`、`sourceDomain`、`sourceFile`、`recordId`、`firstSeen`、`lastSeen`、`processId`、`host` 等字段。
2. 区分内网地址和公网地址。内网 IP 可以保留给图谱推理使用，但默认不要发送到第三方平台。
3. 使用 [ip2region](https://github.com/lionsoul2014/ip2region) 做离线 IP 区域和运营商查询。这个能力建议放在独立分析脚本或服务中，不作为采集器参数。
4. 对公网 IP、域名、URL 或哈希，可以按需查询威胁情报来源，例如 [URLhaus](https://urlhaus.abuse.ch/)、[MalwareBazaar](https://bazaar.abuse.ch/)、[AlienVault OTX](https://otx.alienvault.com/)、[AbuseIPDB](https://www.abuseipdb.com/)、[ThreatMiner](https://www.threatminer.org/)、[GreyNoise Community](https://viz.greynoise.io/)、[VirusTotal](https://www.virustotal.com/) 和 [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)。
5. 遵守各平台 API key、频率限制、使用条款和隐私边界。只需要查询单个 IP、域名、URL 或哈希时，不要上传完整原始日志或主机敏感数据。
6. 分析结果可以由分析项目自行输出为 `analysis/observables.json`、`analysis/ip_region.json`、`analysis/threat_intel_hits.json`、`analysis/network_findings.json` 等文件。

常见危险锚点包括公网监听、环境中少见的国家/运营商、服务账号发起的外联、已知扫描器访问 Web、URLhaus 命中的 URL、MalwareBazaar 或 VirusTotal 命中的恶意哈希、AbuseIPDB 高置信命中、OTX pulse 命中、GreyNoise 扫描器分类，以及 X-Force 风险分类。

### Windows 系统二进制仿冒与哈希信誉

Windows 溯源中应把系统二进制仿冒、替换和同名伪装作为重点分析对象。常见例子包括 `svhost.exe`、`scvhost.exe`、`svch0st.exe`、`lsasss.exe`、`explore.exe`、`csrss.exe`、`rundl132.exe`，以及看起来像真的 `svchost.exe` 但实际落在非可信目录中的文件。

建议检测方式：

- 对比进程路径和文件路径是否位于可信系统目录。例如正常 `svchost.exe` 通常位于 `%SystemRoot%\System32\` 或 `%SystemRoot%\SysWOW64\`；如果同名文件出现在用户目录、临时目录、Web 根目录、服务上传目录或可写应用目录，应提高风险等级。
- 做文件名相似度和拼写仿冒检测，例如 `svhost.exe` 对比 `svchost.exe`、`scvhost.exe` 对比 `svchost.exe`、`explore.exe` 对比 `explorer.exe`、`rundl132.exe` 对比 `rundll32.exe`。
- 内部身份建议优先使用 SHA-256，同时保留 MD5 和 SHA-1，因为很多威胁情报平台仍支持用这些哈希查询。可将哈希提交到 VirusTotal、MalwareBazaar、IBM X-Force、OTX 或其它已批准的情报来源查询。
- 把哈希结果与进程证据、服务 `binaryPath`、计划任务命令、注册表自启动值、Prefetch 执行痕迹、Web 上传路径和文件系统时间戳关联。
- 检查 Authenticode 签名状态、签名方、PE CompanyName、OriginalFileName、版本信息、编译时间、文件大小，以及这些元数据是否与路径或进程名冲突。
- 重点标记可疑父子进程链，例如 Web 中间件 -> `cmd.exe`/`powershell.exe` -> 伪装系统二进制，Office/脚本宿主 -> 下载器 -> 服务安装，或 `rundll32.exe`/`regsvr32.exe` 从可写目录加载 DLL。
- 如果伪装系统二进制存在网络连接，应作为高优先级 pivot：把该进程继续关联到远端 IP/域名富化、DNS 证据、威胁情报命中和时间线事件。

其它值得加入的 Windows pivot 包括 LOLBins，例如 `powershell.exe`、`cmd.exe`、`wscript.exe`、`cscript.exe`、`mshta.exe`、`certutil.exe`、`bitsadmin.exe`、`rundll32.exe`、`regsvr32.exe`、`wmic.exe`、`schtasks.exe`；可疑服务 DLL 路径；未签名驱动；启动目录中新出现的可执行文件；以及在账号、服务、计划任务或外联事件之前短时间内创建的可执行文件。

### 基于 Sigma 的日志与漏洞检测

Web 日志、Windows 日志和 Linux 日志可以先转换成规范事件对象，再使用 [Sigma](https://github.com/SigmaHQ/sigma) 规则或等价规则引擎检测。

建议映射方式：

- Windows 日志：把 `windowsEventLogs[].channel`、`eventId`、`provider`、`timestamp`、`message`、`user`、`process`、`ip` 等字段映射为 Sigma 兼容事件。适合检测账号创建、管理员组变更、服务安装、计划任务创建、PowerShell 执行、远程登录、日志清除、安全工具被关闭，以及可疑进程链。
- Linux 日志：映射 `linuxLogEvents[]`、auth 日志、sudo 事件、SSH 登录失败/成功、cron/systemd 消息、包安装记录和 shell history 派生事件。适合检测暴力破解、新增 sudo 权限用户、UID 0 异常、异常 `authorized_keys`、cron 持久化、systemd 持久化、可疑 `curl|wget|bash` 模式，以及文件变更后服务重启。
- Web 日志：映射 `webLogEntries[].clientIp`、`method`、`uri`、`status`、`userAgent`、`referrer`、`bytesSent` 和中间件来源。适合检测漏洞探测、目录穿越、webshell 路径、异常上传接口、扫描器 UA、SQL 注入/XSS payload、异常 4xx/5xx 峰值、后台路径访问，以及 Web 请求后紧接出现的可疑进程或文件活动。
- 基础漏洞检查：组合 `software`、`process`、`web_logs`、`startup`、`file_system` 证据，标出高风险中间件版本、暴露的管理后台、弱服务路径、全局可写可执行目录、setuid/setgid 风险文件、可疑启动项二进制，以及 Web 服务可触达的不安全脚本解释器。

规则命中结果应保留原始域、来源路径、记录 ID、时间戳、规则 ID、严重级别、命中字段和简短原因。这样每条告警都能回到原始 section JSON 中复核。

### 影子账号与权限锚点

账号和权限异常适合作为溯源中的高价值危险锚点。

Windows 锚点示例：

- 账号存在于 SAM 证据中，但 NetAPI、WMI 或 `net user` 视图不可见。
- SAM RID key 与 `Names` 索引不一致。
- 多个账号共享可疑的 SAM `F` 或 `V` 数据摘要。
- 非内置账号出现在本地 Administrators 或其它高权限别名组中。
- 新账号、组成员变更、远程登录、计划任务、服务安装或可疑可执行文件在时间线上接近出现。

Linux 锚点示例：

- 非 root 用户名拥有 UID `0`。
- 用户出现在 sudo/admin/wheel 组中，但缺少预期的归属或变更历史。
- 用户或文件系统证据中出现异常 `authorized_keys`、shell 启动文件、cron、systemd unit 或可写服务路径。
- 服务账号启动交互式 shell、执行网络下载命令，或拥有可疑持久化文件。

这些锚点可以继续与日志、进程、网络、启动项、注册表和文件系统证据关联，形成分析人员优先复核列表。

### 图数据库与攻击路线推理

当证据规模较大时，可以把规范化后的记录导入图数据库，例如 [Neo4j](https://neo4j.com/) 或其它属性图引擎。图谱层应保留原始记录 ID，让每个节点和关系都能追溯到 `sections/*.json`。

常用节点类型：

- `Host`、`User`、`Group`、`Process`、`File`、`Service`、`ScheduledTask`、`RegistryKey`、`NetworkEndpoint`、`Domain`、`URL`、`LogEvent`、`WebRequest`、`Software`、`Finding`、`ThreatIntelHit`。

常用关系类型：

- `MEMBER_OF`、`OWNS_PROCESS`、`SPAWNED`、`EXECUTES_FILE`、`LISTENS_ON`、`CONNECTED_TO`、`RESOLVES_TO`、`REQUESTED_URL`、`REFERENCES_FILE`、`PERSISTS_VIA`、`OBSERVED_IN_LOG`、`MATCHED_RULE`、`HAS_THREAT_INTEL`、`OCCURRED_NEAR`。

危险项可以作为图谱锚点：威胁情报命中、Sigma 规则命中、影子账号信号、可疑启动项、高风险文件权限、Web 漏洞利用请求、恶意哈希和异常外联。以这些锚点为起点，可以推理可能的攻击路线，例如：

- Web 漏洞请求 -> 中间件进程 -> 类 webshell 文件 -> 子命令行 shell -> 可疑公网 IP 外联。
- 新增高权限账号 -> 远程登录事件 -> 计划任务 -> 可写目录中的可执行文件 -> 持久化告警。
- 进程命令行中的可疑域名 -> DNS 证据 -> 远端 IP 区域/威胁情报命中 -> 进程树 -> 父级服务。
- 全局可写服务路径 -> 可执行文件被替换的证据 -> 服务重启日志 -> 外联连接。

图谱项目可以输出 `analysis/attack_paths.json`、`analysis/finding_graph.json`，或导出到独立数据库。采集器本身继续专注证据采集；富化、规则检测和图谱推理可以独立演进。

## 采集域

采集域名就是 `--include` 和 `--exclude` 使用的值。`--include` 是白名单：没有写进去的域不会采集，也不会输出对应 `sections/<domain>.json`。`--exclude` 会在 include 结果上再排除域。

Windows Prefetch、浏览器历史、USB 记录和 Linux shell history 只有显式加入 `user_traces` 才会采集。重型取证域也需要显式加入：Windows 注册表使用 `registry`，Windows 和 Linux 文件系统取证使用 `file_system`。加入后分别输出 `sections/user_traces.json`、`sections/registry.json` 和 `sections/file_system.json`；如果目标机器没有可采记录，显式选择的重型或痕迹域仍会输出稳定的空数组结构，便于后续脚本处理。

### 通用域

| include 值 | section 文件 | JSON key | Windows | Linux | 采集内容 |
|---|---|---|---|---|---|
| `host` | `sections/host.json` | `system`, `resources`, `hardware`, `platformFacts` | 支持 | 支持 | 主机名、系统版本、架构、CPU、内存、磁盘、启动/会话信息、平台能力事实 |
| `process` | `sections/process.json` | `processes`, `processDetails`, `processTree`, `fileIdentities` | 支持 | 支持 | 进程列表、父子关系、命令行、可执行文件身份、可执行文件路径/哈希等 |
| `network` | `sections/network.json` | `network` | 支持 | 支持 | 网络连接、监听、本地/远端地址、协议状态、网卡、路由、DNS、防火墙线索 |
| `logs` | `sections/logs.json` | `windowsEventLogs`, `linuxLogSources`, `linuxLogEvents` | 支持 | 支持 | Windows 事件日志，或 Linux 日志源清单和认证/系统事件 |
| `users` | `sections/users.json` | `users`, `groups`, `privilegeEvidence` | 支持 | 支持 | 本地账号、用户组、权限证据、登录/会话相关账号事实 |
| `startup` | `sections/startup.json` | `services`, `timers`, `cronJobs`, `persistenceItems` | 支持 | 支持 | Windows 服务/计划任务，Linux systemd timer、cron、服务和持久化项 |
| `software` | `sections/software.json` | `software` | 支持 | 支持 | 已安装软件、包清单、版本、厂商/来源 |
| `timeline` | `sections/timeline.json` | `timelineEvents` | 支持 | 支持 | 从进程、日志、启动项、网络、Web 日志、文件证据派生的时间线 |
| `web_logs` | `sections/web_logs.json` | `webLogSources`, `webLogEntries` | 支持 | 支持 | IIS/Nginx/Apache/Tomcat 类日志源发现和 HTTP 访问记录解析 |
| `user_traces` | `sections/user_traces.json` | `prefetch`, `browserHistory`, `usbRecords`, `operationRecords` | 支持 | 支持 | Windows Prefetch 执行痕迹、浏览器历史、USB 设备记录，以及 Linux shell history 操作记录 |
| `registry` | `sections/registry.json` | `registries` | 支持 | 不适用 | Windows 注册表键值、持久化、自启动、服务、软件和配置证据 |
| `file_system` | `sections/file_system.json` | `forensicVolumes`, `forensicDirectoryNodes`, `forensicFileEntries`, `forensicTimelineEvents`, `forensicDiagnostics` | 支持 | 支持 | 文件系统卷/挂载点、目录节点、文件元数据、删除/孤立/权限线索、文件时间线和采集诊断 |

### Windows 域说明

| include 值 | Windows 主要来源 | 重要字段 |
|---|---|---|
| `host` | Win32 系统 API、OS 版本、硬件和资源探测 | `system.hostname`, `system.osVersion`, `system.arch`, `resources.cpu`, `resources.memory`, `hardware[]` |
| `process` | 进程快照 API、命令行探测、可执行文件身份 | `processes[].pid`, `processes[].ppid`, `processes[].name`, `processes[].commandLine`, `processTree[]`, `fileIdentities[]` |
| `network` | TCP/UDP 表、网卡/DNS 证据、运行时连接增强 | `network.connections[]`, `network.listeners[]`, `network.interfaces[]`, `network.dnsCache[]` |
| `logs` | Windows Event Log 通道 | `windowsEventLogs[].channel`, `windowsEventLogs[].eventId`, `windowsEventLogs[].provider`, `windowsEventLogs[].timestamp` |
| `users` | 本地用户/组、SAM/WMI/net session 证据 | `users[].username`, `users[].sid`, `groups[].name`, `privilegeEvidence[]` |
| `startup` | 服务、计划任务、启动目录、持久化记录 | `services[].name`, `services[].startType`, `services[].binaryPath`, `persistenceItems[]` |
| `software` | 已安装软件清单 | `software[].name`, `software[].version`, `software[].vendor`, `software[].installLocation` |
| `web_logs` | IIS 路径，以及存在时的 Nginx/Apache/Tomcat 配置或运行时发现 | `webLogSources[].serverType`, `webLogSources[].path`, `webLogEntries[].clientIp`, `webLogEntries[].uri` |
| `user_traces` | `C:\Windows\Prefetch`、可读的浏览器 profile 历史数据库、USB 注册表/设备证据 | `prefetch[].processName`, `prefetch[].runCount`, `browserHistory[].url`, `browserHistory[].visitTime`, `usbRecords[].serialNumber` |
| `registry` | Windows 注册表目标集合，包括 Run/RunOnce、Services、Winlogon、IFEO、AppInit、Shell 扩展、计划任务缓存、卸载项等 | `registries[].id`, `registries[].path`, `registries[].name`, `registries[].type`, `registries[].data`, `registries[].collectionCategory`, `registries[].riskPurpose` |
| `file_system` | NTFS/文件系统取证采集，包括卷信息、目录节点、文件记录、删除/孤立记录、哈希状态和时间线 | `forensicVolumes[]`, `forensicDirectoryNodes[]`, `forensicFileEntries[]`, `forensicTimelineEvents[]`, `forensicDiagnostics` |

### Linux 域说明

| include 值 | Linux 主要来源 | 重要字段 |
|---|---|---|
| `host` | `/proc`、`/sys`、uname、发行版 release 文件、资源探测 | `system.hostname`, `system.os`, `system.kernel`, `resources.cpu`, `resources.memory`, `platformFacts[]` |
| `process` | `/proc/<pid>`、进程状态、cmdline、exe 链接 | `processes[].pid`, `processes[].ppid`, `processes[].name`, `processes[].commandLine`, `processDetails[]` |
| `network` | `/proc/net`、ss/route 类证据、resolver/firewall 文件 | `network.connections[]`, `network.listeners[]`, `network.interfaces[]`, `network.routes[]`, `network.dns[]` |
| `logs` | `/var/log`、认证/系统日志、可解析的 journald 类事件 | `linuxLogSources[].path`, `linuxLogSources[].kind`, `linuxLogEvents[].eventType`, `linuxLogEvents[].timestamp` |
| `users` | `/etc/passwd`、`/etc/group`、sudo/admin 组证据、登录痕迹 | `users[].username`, `users[].uid`, `users[].home`, `groups[].gid`, `privilegeEvidence[]` |
| `startup` | systemd unit/timer、cron 路径、init/service 记录 | `services[].name`, `services[].unitFile`, `timers[]`, `cronJobs[]`, `persistenceItems[]` |
| `software` | dpkg/rpm/apk/pacman 类包清单 | `software[].name`, `software[].version`, `software[].source`, `software[].installTime` |
| `web_logs` | Nginx/Apache/Tomcat 日志发现和访问记录解析 | `webLogSources[].serverType`, `webLogSources[].path`, `webLogEntries[].clientIp`, `webLogEntries[].status` |
| `user_traces` | `.bash_history`、`.zsh_history` 等用户 shell history 文件，采集时会脱敏疑似 token | `operationRecords[].event`, `operationRecords[].operationTime`, `operationRecords[].file`, `operationRecords[].source` |
| `file_system` | Linux 文件系统取证采集，发现挂载点并采集 POSIX 元数据、权限、inode、软链接、特殊权限位和证据标签 | `forensicVolumes[]`, `forensicDirectoryNodes[]`, `forensicFileEntries[]`, `forensicTimelineEvents[]`, `forensicDiagnostics[]` |

## 字段字典

这里列的是稳定字段族。不是每个平台都会填满所有字段；字段缺失通常表示该平台没有该数据源、权限不足、文件不可读，或本次 `--include` 未选择对应域。

### 输出目录与 manifest 字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `metadata.edition` | string | 输出版本标识 |
| `metadata.run_mode` | string | 工具记录的运行模式，本地 JSON 目录通常为 `oss-local` |
| `metadata.auth_mode` | string | 鉴权模式元数据，本地 JSON 目录通常为 `none` |
| `metadata.encryption_state` | string | 输出加密状态元数据 |
| `metadata.collection_scope[]` | string array | `--include` 和 `--exclude` 解析后的实际域 |
| `metadata.tool_version` | string | 构建版本或工具版本 |
| `local_cli.include[]` | string array | 用户传入的 `--include` 域 |
| `local_cli.exclude[]` | string array | 用户传入的 `--exclude` 域 |
| `local_cli.scope[]` | string array | 实际生效域 |
| `local_cli.days` | number | 时间窗口：`7`、`14` 或 `30` |
| `files.sections` | object | 域名到 section 路径的映射，例如 `network -> sections/network.json` |
| `domains.<name>.item_count` | number | 该域大致条目数 |

### 主机字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `system.hostname` | string | 主机名 |
| `system.os` | string | 操作系统族或发行版 |
| `system.osVersion` | string | 操作系统版本 |
| `system.kernel` | string | Linux kernel 或平台内核字符串 |
| `system.arch` | string | CPU 架构，例如 `amd64` 或 `arm64` |
| `system.bootTime` | string | 尽力采集的启动时间 |
| `resources.cpu` | object | CPU 型号、核心数、负载等 |
| `resources.memory` | object | 内存总量、可用量、使用量摘要 |
| `resources.disk` | object/array | 磁盘或文件系统容量摘要 |
| `hardware[]` | array | 可用时的硬件设备或资产行 |
| `platformFacts[]` | array | 采集器使用的平台能力探测事实 |

### 进程与文件身份字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `processes[].pid` | number | 进程 ID |
| `processes[].ppid` | number | 父进程 ID |
| `processes[].name` | string | 进程名 |
| `processes[].commandLine` | string | 命令行，必要时会截断或脱敏 |
| `processes[].user` | string | 进程所属用户 |
| `processes[].executablePath` | string | 可执行文件路径 |
| `processDetails[]` | array | 进程扩展信息，例如环境、句柄、模块、状态或平台详情 |
| `processTree[]` | array | 父子进程关系 |
| `fileIdentities[].path` | string | 与进程或证据源关联的文件路径 |
| `fileIdentities[].sha256` | string | 计算得到的 SHA-256 |
| `fileIdentities[].size` | number | 文件大小，单位字节 |
| `fileIdentities[].modifiedAt` | string | 文件修改时间 |
| `fileIdentities[].signature` | object/string | 可用时的签名或包身份信息 |

### 网络字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `network.connections[]` | array | 当前或近期观察到的连接记录 |
| `network.connections[].protocol` | string | TCP、UDP 或平台协议名 |
| `network.connections[].localIp` | string | 本地 IP |
| `network.connections[].localPort` | number | 本地端口 |
| `network.connections[].remoteIp` | string | 远端 IP |
| `network.connections[].remotePort` | number | 远端端口 |
| `network.connections[].state` | string | TCP 状态，例如 `LISTEN` 或 `ESTABLISHED` |
| `network.connections[].pid` | number | 可用时的所属进程 ID |
| `network.listeners[]` | array | 单独拆出的监听 socket |
| `network.interfaces[]` | array | 网卡和地址 |
| `network.routes[]` | array | 可用时的路由表 |
| `network.dns[]` / `network.dnsCache[]` | array | resolver 配置、DNS 缓存或 DNS 证据 |

### 日志字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `windowsEventLogs[].channel` | string | Windows 事件通道 |
| `windowsEventLogs[].eventId` | number | Windows 事件 ID |
| `windowsEventLogs[].provider` | string | 事件提供方 |
| `windowsEventLogs[].level` | string/number | 严重级别 |
| `windowsEventLogs[].timestamp` | string | 事件时间 |
| `windowsEventLogs[].message` | string | 渲染后的事件消息或摘要 |
| `linuxLogSources[].path` | string | Linux 日志文件路径 |
| `linuxLogSources[].kind` | string | 来源类型，例如 auth、syslog、nginx、apache、audit |
| `linuxLogSources[].readable` | boolean | 文件是否可读 |
| `linuxLogEvents[].eventType` | string | 标准化事件类型 |
| `linuxLogEvents[].timestamp` | string | 解析后的事件时间 |
| `linuxLogEvents[].sourcePath` | string | 来源日志文件 |
| `linuxLogEvents[].message` | string | 解析或摘要后的日志消息 |

### 用户、启动项、软件、时间线与 Web 日志字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `users[].username` | string | 本地用户名 |
| `users[].uid` / `users[].sid` | number/string | Linux UID 或 Windows SID |
| `users[].home` | string | home/profile 路径 |
| `users[].shell` | string | Linux shell |
| `groups[].name` | string | 用户组名 |
| `groups[].gid` / `groups[].sid` | number/string | Linux GID 或 Windows SID |
| `privilegeEvidence[]` | array | sudo/admin/权限证据 |
| `services[].name` | string | 服务或 unit 名称 |
| `services[].status` | string | 服务状态 |
| `services[].startType` | string | 启动方式 |
| `services[].binaryPath` | string | 服务可执行路径 |
| `timers[]` | array | systemd timer 记录 |
| `cronJobs[].schedule` | string | cron 时间表达式 |
| `cronJobs[].command` | string | cron 命令 |
| `persistenceItems[].type` | string | 持久化类型 |
| `persistenceItems[].path` | string | 涉及的路径或注册表键 |
| `persistenceItems[].reason` | string | 为什么该记录值得关注 |
| `software[].name` | string | 软件或包名 |
| `software[].version` | string | 版本 |
| `software[].vendor` | string | 厂商或维护者 |
| `software[].source` | string | 包管理器或清单来源 |
| `timelineEvents[].timestamp` | string | 事件时间 |
| `timelineEvents[].eventType` | string | 标准化事件类型 |
| `timelineEvents[].sourceDomain` | string | 产生该事件的域 |
| `timelineEvents[].summary` | string | 人类可读事件摘要 |
| `webLogSources[].serverType` | string | IIS、nginx、apache、tomcat 或 custom |
| `webLogSources[].path` | string | 日志文件路径 |
| `webLogSources[].format` | string | 检测到的日志格式 |
| `webLogEntries[].timestamp` | string | HTTP 请求时间 |
| `webLogEntries[].clientIp` | string | HTTP 客户端 IP |
| `webLogEntries[].method` | string | HTTP 方法 |
| `webLogEntries[].uri` | string | 请求 URI |
| `webLogEntries[].status` | number | HTTP 状态码 |
| `webLogEntries[].bytesSent` | number | 可用时的响应大小 |

### 用户痕迹字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `prefetch[].file` | string | Prefetch 文件名 |
| `prefetch[].processName` | string | 从 Prefetch 文件名或内容解析出的进程名 |
| `prefetch[].processPath` | string | 可用时的可执行文件路径 |
| `prefetch[].runCount` | number | 可用时解析出的运行次数 |
| `prefetch[].lastRunTime` | string | 从文件元数据或内容推导的最后运行时间 |
| `prefetch[].exists` | boolean | 对应 Prefetch 文件是否仍存在 |
| `browserHistory[].url` | string | 访问 URL |
| `browserHistory[].title` | string | 可用时的网页标题 |
| `browserHistory[].visitTime` | string | 访问时间 |
| `browserHistory[].browser` | string | 浏览器类型或 profile 来源 |
| `usbRecords[].name` | string | USB 设备名 |
| `usbRecords[].vendor` | string | 可用时的厂商信息 |
| `usbRecords[].insertTime` | string | 可用时的插入或首次出现时间 |
| `usbRecords[].serialNumber` | string | 可用时的 USB 序列号 |
| `usbRecords[].mountPoint` | string | 可用时的盘符或挂载点 |
| `operationRecords[].event` | string | 操作类型，例如 `shell_history` |
| `operationRecords[].operationTime` | string | 来源记录提供的操作时间 |
| `operationRecords[].file` | string | 命令文本或文件类证据值，必要时脱敏 |
| `operationRecords[].filePath` | string | 来源文件路径，例如 shell history 文件 |
| `operationRecords[].source` | string | 产生记录的用户或来源标签 |

### 注册表与文件系统字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `registries[].id` | string | 注册表 value 证据 ID |
| `registries[].path` | string | 完整注册表路径 |
| `registries[].name` | string | value 名称 |
| `registries[].type` | string | 注册表 value 类型，例如 `REG_SZ` 或 `REG_DWORD` |
| `registries[].data` | string | 渲染后的 value 数据，必要时截断 |
| `registries[].modifiedAt` | string/null | 可用时的最后修改时间 |
| `registries[].collectionCategory` | string | 采集分类，例如 `persistence`、`service`、`software_inventory` |
| `registries[].riskPurpose` | string | 分析目的，例如 `run_key`、`winlogon_hijack`、`service_image_and_dll` |
| `registries[].referencedPath` | string/null | 从 value 数据中抽取出的可执行文件路径 |
| `registries[].referencedFileIdentityId` | string/null | 可用时关联的文件身份 ID |
| `forensicVolumes[].volumeId` | string | 卷或挂载点 ID |
| `forensicVolumes[].devicePath` | string | 设备路径 |
| `forensicVolumes[].driveLetter` / `forensicVolumes[].mountPoint` | string | Windows 盘符或 Linux 挂载点 |
| `forensicVolumes[].filesystem` | string | 文件系统类型，例如 NTFS、ext4、xfs |
| `forensicVolumes[].deviceId` | number | 可用时的 Linux device ID |
| `forensicDirectoryNodes[].nodeId` | string | 目录节点 ID |
| `forensicDirectoryNodes[].path` | string | 目录路径 |
| `forensicDirectoryNodes[].parentPath` | string | 父目录路径 |
| `forensicDirectoryNodes[].inode` | number | 可用时的 Linux inode |
| `forensicFileEntries[].entryId` | string | 文件条目 ID |
| `forensicFileEntries[].path` | string | 文件路径 |
| `forensicFileEntries[].name` | string | 文件名 |
| `forensicFileEntries[].extension` | string | 文件扩展名 |
| `forensicFileEntries[].isDirectory` | boolean | 是否目录 |
| `forensicFileEntries[].isDeleted` | boolean | 是否删除记录 |
| `forensicFileEntries[].isAllocated` | boolean | 是否仍分配 |
| `forensicFileEntries[].isOrphan` | boolean | 是否孤立记录 |
| `forensicFileEntries[].size` | number | 文件大小 |
| `forensicFileEntries[].allocatedSize` | number | 分配大小 |
| `forensicFileEntries[].md5` / `sha1` / `sha256` | string | 可用时的哈希 |
| `forensicFileEntries[].hashState` | string | 哈希采集状态 |
| `forensicFileEntries[].createdAt` / `modifiedAt` / `accessedAt` / `changedAt` | string | 文件时间戳 |
| `forensicFileEntries[].inode` / `deviceId` | number | Linux inode 和 device ID |
| `forensicFileEntries[].mode` / `permissions` | string | Linux mode 和权限文本 |
| `forensicFileEntries[].uid` / `gid` | string | Linux 所有者/用户组 ID |
| `forensicFileEntries[].fileType` | string | Linux 文件类型 |
| `forensicFileEntries[].linkTarget` | string | 符号链接目标 |
| `forensicFileEntries[].setuid` / `setgid` / `sticky` / `worldWritable` / `hiddenName` | boolean | Linux 权限和隐藏文件名证据 |
| `forensicFileEntries[].evidenceCategory` | string | 文件证据分类 |
| `forensicFileEntries[].evidenceTags[]` | string array | 文件证据标签 |
| `forensicFileEntries[].evidenceReasons[]` | string array | 文件被标记的原因 |
| `forensicTimelineEvents[].eventId` | string | 文件时间线事件 ID |
| `forensicTimelineEvents[].path` | string | 事件路径 |
| `forensicTimelineEvents[].eventType` | string | 事件类型，例如 created、modified、accessed、changed |
| `forensicTimelineEvents[].timestamp` | string | 事件时间 |
| `forensicTimelineEvents[].source` | string | 时间戳来源 |
| `forensicDiagnostics` | object/array | 文件系统采集诊断、跳过原因、计数器或错误状态 |
