# 2026-09-19 CFM 断流与跨机型启动无响应排查

## 后续架构修正（取代仅靠超时和手工诊断的交付）

用户指出上一轮的超时包装和采集工具不能作为根治方案。本轮改动直接处理线程边界、
磁盘写入互斥与运行状态机；采集器只是开发辅助，不是产品正常使用或恢复的前提。

- Tauri `setup` 只创建原生菜单并启动后台初始化。文件系统、Keychain 和迁移预检不再让
  AppKit 主线程等待。移除了原来的“主线程等 Keychain 五秒、超时永久禁用启动”的包装。
- 引擎的准备和安装分开：准备阶段只构造状态和未执行的协调器任务；用户退出后，迟到结果
  不能安装或启动引擎。已安装协调器的退出仍经过原有停止与所有权证明。
- 设置与配置文件 I/O 均移到后台。窗口位置保存采用一个合并事件的后台任务；处理窗口事件的
  内存锁不再跨越磁盘写入。异步设置修改仍保持互斥，慢速登录项查询不占用窗口保存的互斥。
- macOS 登录项的实时查询不再阻塞 dashboard 启动。持久设置仍须真实读取；未完成的登录项
  查询明确显示 Checking，不能把缓存或默认值当成系统实况。迟到的查询不能覆盖新设置。
- 临时状态查询失败原来会把协调器置为 Failed，之后又因只检查 Active 而永久停止观察。
  现在只对 `RetryDirective::IdempotentReadOnly` 继续按既有频率和单次截止时间核验。
  只有新鲜的 owner、generation、context、digest 与 Ready 全部匹配原运行实例，才能恢复 Active；
  不重新启动核心、不重新分配 generation，也不绕过身份错误、隔离状态或显式 Off 停止证明。

这符合 [Tauri 的线程契约](https://v2.tauri.app/develop/calling-rust/#async-commands)：
同步命令默认在主线程执行；把 Promise 写在前端并不能消除原生同步阻塞。

本轮独立证据目录为 `target/startup-architecture-20260919`：

- `native-tests-v2.log`：403 个 Host 测试通过；真实配置目录锁被占用时，macOS 主队列
  26 ms 内响应，退出后的迟到引擎安装为 0（首轮 28 ms）。
- `status-recovery-before.log`：增加回归测试后，旧状态机因不能恢复而失败。
- `state-and-host-tests-v3.log`：状态机修正后，95 个 application、403 个 Host 测试通过；
  覆盖四种运行模式、身份/权限拒绝、不一致 generation、显式 Off 和零重启恢复。
- `ui-tests-v2.log`：148 个前端测试通过，包含登录项查询不返回时 dashboard 仍完成启动。
- `all-targets-v1.log`：95 个 application、403 个 Host、11 个 native product input
  测试通过；真实主队列测试在持锁时 24 ms 响应。同步对照等待 800 ms，按预期失败。
- `platform-tests-final.log`：26 个 platform 测试通过；发布功能组合的 Clippy 检查通过。
- `physical-readiness-tests-v2.log`：26 个发布源码检查测试通过。检查器追踪实际的
  `main -> startup::start -> initialize -> packet_evidence_transport`，拒绝测试专用、
  未调用、异模块同名或字符串伪造的调用路径。首次旧检查器拒绝新路径的记录保留。
- 构建、签名、安装及本机运行验收另行记录；这些测试不能冒充其他机型的现场复现。

以下保留初轮诊断事实和历史证据，其中“五秒 Keychain 包装”已被上述实现替代。


当前安装仍为 **0.4.0 / 40070**。用户授权了网络切换和安装候选版本；
已完成的网络交接使用原安装包，IPv6 DNS 关闭且持久保存，TUN 和系统代理开启。
本轮源码修改尚未构建成签名、公证安装包，也未安装到本机或其他机型。

用户补充：其他电脑出现黑屏时，**整个程序无响应**。这不能只按前端加载失败处理。
目前没有故障机的调用栈、机型、系统版本和确切应用 build，不能声称跨机型根因已证实。

| 问题 | 事实与因果边界 | 本轮结果 | 剩余验收 |
| --- | --- | --- | --- |
| 选定 SOCKS 节点的 IPv6 转发失败 | 绕过 CFM 后，两个目标的 IPv4 4/4 成功，IPv6 4/4 在 TLS 阶段断开；CFW 关闭 IPv6，而 CFM 原先开启 IPv6 DNS | 已对齐本机 IPv6 DNS；切换期间 Google 109/109 成功，之后纯 TUN / 系统代理 10/10，含两次 1 MiB 下载 | 不能外推为所有节点或所有间歇性断流已修复 |
| 40070 配置目录锁无界等待 | 启动主线程读取设置时进入阻塞式 `flock`；冻结旧源码上的真实锁竞争测试在 5 秒内未返回，主动释放锁后才结束 | 当前源码已有 3 秒锁等待上限；本轮补齐旧版失败、新版通过的回归证据 | 新包安装，以及故障机确认是否命中同一调用链 |
| 启动 Keychain 调用停滞 | 40070 启动会同步等待权威 lineage 读取；当前源码已有隔离线程及 5 秒等待上限 | 本轮验证正常成功、原始失败、线程崩溃、阻塞超时和迟到结果；未使用默认身份或授权启动 | 没有在用户故障机实际触发 Security.framework 停滞 |
| 主脚本无法加载或顶层执行失败 | 旧版只能显示 Starting，依赖脚本成功才能进入原 bootstrap 的错误处理 | 新增独立启动入口、15 秒超时恢复界面、原生窗口展示入口和原生菜单诊断入口；真实 WKWebView 故障注入通过 | 此修复不等同于原生主线程卡死已解决 |
| 原生启动停在哪一步不可见 | 整个程序无响应时前端和菜单都不可作为唯一诊断入口 | 启动步骤开始、结束、失败与耗时写入独立后台本地日志；提供外部 `.command` 采样脚本 | 收到故障发生时的现场样本 |
| 截图中的集中 5 秒连接失败 | 截图缺少错误尾部；主动 SOCKS 设置通常小于 1 秒，没有复现 5 秒设置超时 | 持久保存脱敏的请求 warning/error 和引擎失败，不凭截图延长超时 | 故障现场的完整错误与连接阶段；暂停请求日志流时不采集该流的请求错误 |
| CFW / CFM 中国 IP 分流不同 | CFW 有 `GEOIP,CN,DIRECT`，当前 CFM 只有 `final=PROXY` | 已记录差异，未擅自改变用户分流意图 | 明确规则策略及真实路由验收；不把它假定为已证实的断流原因 |

## 实现边界

- `ui/src/startup.js` 不依赖主应用 bundle。恢复按钮经原生命令检查后仅重载 dashboard，
  不重启核心；迁移会话禁止重载，拒绝时不会回退到直接 `location.reload()`。
- `bootstrap.rs` 在主页面原生加载完成时也可展示窗口；失败展示可以重试。
  迁移会话继续遵守原有 readiness / 父进程退出约束。
- `main.rs` / `diagnostics.rs` 记录 native bridge、配置仓库、引擎、菜单、迁移预检、
  tray、自动化、provider、窗口位置和静默启动各步骤。
- `cfw-core/src/diagnostics.rs` 的三个日志文件分别保留最多 128 条、每个最多 1 MiB。
  目录和文件沿用私有权限、安全路径和原子替换机制；损坏旧文件保留并明确报错。
  URL 用户信息、查询串以及密码、token、Bearer 等字段在写盘前脱敏。
  每条记录包含进程、时间、产品版本，以及编译时可用的 build / commit。
- 写盘由容量 128 的非阻塞队列和独立线程承担；拥塞丢弃数量可观察。
  请求日志延续原有流的生命周期，未引入第二个无界后台订阅。
- 原生菜单提供 Reload dashboard / Open diagnostic logs；如果主线程本身卡住，
  应使用独立采样脚本，不能指望菜单或前端恢复按钮正常响应。

## 实际验证

全部结果保存在 `target/reliability-20260919`，既有诊断和网络交接记录分别保存在
`target/connection-diagnostics-20260919`、`target/cfm-handoff-20260919`。

使用私有 Rust 1.98.1 工具链以及既有离线依赖缓存，没有修理或替换系统 rustup。

| 命令 / 验证 | 结果与记录 |
| --- | --- |
| `cargo test --offline --locked -p cfw-core -p cfw-tauri-shell -p cfw-apple-network --lib --bins` | 30 + 400 + 35 通过；`native-startup-tests.log`。恢复入口调整后，以 `cargo test --offline --locked -p cfw-tauri-shell --bins` 再验 400 项；`host-tests-v4.log` |
| `cargo clippy --offline --locked -p cfw-core -p cfw-tauri-shell -p cfw-apple-network --lib --bins -- -D warnings` | 通过；`native-startup-clippy.log`。最终 Host 复查 `cargo clippy --offline --locked -p cfw-tauri-shell --bins -- -D warnings`；`host-clippy-v4.log` |
| `cargo test --offline --locked -p cfw-singbox-config tests::runtime_settings:: -- --nocapture` | 6 通过；`ipv6-preferences-tests.log`。此前系统 rustup 尝试失败日志仍保留 |
| `node scripts/build_ui.mjs`；`node --test apps/cfw-tauri-shell/ui/tests/*.test.mjs` | 构建成功；147 通过，0 失败；`ui-build-v2.log`、`ui-tests-v2.log` |
| Swift 6 / warnings-as-errors 编译 `scripts/fixtures/dashboard_startup_probe.swift`；实际 WKWebView 故障注入 | 旧缺失脚本页面无恢复入口；新缺失脚本、脚本抛异常、启动挂起三个案例均显示恢复入口；`webkit-fault-injection-v2.json` |
| 冻结 40070 提交 `ec650f66fe7f8964b335fe86a540ff88d2631e84` 上增加配置锁回归测试 | 旧生产实现未改动。1 项测试如预期失败，阻塞 5.02 秒直到测试释放锁；`frozen-40070-lock-regression-v2.log`。首次过滤器未含模块名而运行 0 项，原日志保留，不计为通过证据 |
| `bash -n scripts/collect_cfm_diagnostics.command` 和 shellcheck；实际运行采集器 | 语法 / 静态检查通过；采样当前 GUI 成功，失败步骤 0。40070 没有新日志属明确记录的 unavailable，不能计为日志功能实机通过 |
| `git diff --check`；比较既有工作区补丁 | 通过；开始前 65 个已修改路径的补丁逐字节不变 |
| 17:44:33 本机网络复查 | CFM VPN Connected，IPv6 DNS false；纯 TUN 与系统代理均收到 HTTPS 204；`network-final-check.json` |

WKWebView 故障注入仅在本机 macOS 27.0 (26A428) 上执行，使用隔离的临时页面和最小
诊断 IPC fixture；未冒充完整 Tauri、macOS 15 或其他硬件上的产品验收。
锁竞争和 Keychain 测试也不能冒充远端用户故障的现场复现。
最终 Host 首次单包测试误加 `--lib`，因该包没有 library target 而未执行；
`host-tests-v3.log` 保留该命令失败，改用正确的 `--bins` 后才计入验证结果。

## 安装与现场闭环（当前进度）

签名构建入口要求 clean 且可验证的 release source identity。
当前工作区包含开始前已有的 65 个发布相关修改，内容仍逐字节保留。逐项核对后，
与 40071 分配及替换 40070 有关的修改连同本次修复复制到独立 release worktree；
原目录的 HEAD、索引和未提交状态保留。本地候选分支为
`lza/native-startup-recovery-20260919`，尚未推送。
准备记录保存在 `target/startup-architecture-20260919`；源码检查未通过的准备尝试
完整保留，未冻结或签名。40071 正在准备，40072 未分配；未在当前运行网络上热替换。

外部采集器只作为开发辅助保留，不能代替上述线程边界和状态机修正，也不是产品正常
启动、联网或恢复的前提。其他机型的现场复测仍是独立验收项。

尚未完成：新签名包的安装 / 跨版本升级、故障机复测、持续视频与上传、睡眠唤醒 / Wi-Fi 切换、
以及原截图 5 秒错误的现场复现。没有据本轮局部通过宣称“全面根治”或“可发布”。
