# CFW 0.5.0：CFM GA 对齐与 Windows 发布计划

评估日期：2026-10-18。状态：开发中，尚无经过验证的 Windows 产品。

## 基线与完成条件

本次移植以已发布的 [CFM v0.5.0](https://github.com/billlza/cfw-rs/releases/tag/v0.5.0)
为唯一功能与界面基线，源提交为
`502adf9fd858218bb1f1cbeba738aa0b4791960d`。发布 API 已确认其不是 draft 或
prerelease，发布时间为 `2026-10-18T09:12:23Z`，附件为 macOS 产物。
后续 CFM 更新作为有记录的基线变更处理，不能让移动分支悄悄改变本次验收范围。

目标是完整 Windows 产品：功能、信息结构、布局和操作路径对齐，正确的 Windows
系统集成，真实桌面与网络验证，受信任的安装更新流程，以及可核验的发布产物。
“完美发布”在此落实为每项要求都有对应证据、无已知阻塞缺陷；不宣称证明不存在缺陷。
实现、编译、测试、真机验收、签名、发布分别记录，任何一项不能代替下一项。

当前分支从 GA 提交新建，保留原工作目录和冻结发布工作区。现有 macOS 身份、安装、
凭据格式和发布流程不因 Windows 移植而被重置。
开发分支随后纳入 `main` 的 `b8ab149`；它相对 GA 仅包含 `1ca7f4b` 的发布验证器
测试 fixture 修正，没有产品源码变更。上面的 GA 功能/视觉基线保持不变。

## 已核实的架构事实

- 宿主仍是 `apps/cfw-tauri-shell/src/main.rs` 中的 Tauri；前端通过
  `ui/src/app.js` 接入 SwiftUI/AppKit 组件，并非纯 SwiftUI 应用。
- GA 注册 111 个命令，其中 15 个命令属于五类原生表现组件。准确清单及源文件哈希
  见 [命令基线](cfw-0.5.0-baseline.json)。命令数不是功能完成度。
- `ui/src` 有 27 个 JavaScript 文件、9,548 行；`native/dashboard/Sources`
  有 11 个 Swift 文件、3,157 行。这是 GA 源码规模，不是工期估算。
- `cfw-application`、`cfw-engine-api`、`cfw-singbox-config`、`cfw-controller`
  是共享业务的主要基础；尚不能从代码结构推断它们已在 Windows 测试通过。
- GA 中 `cfw-core` 的设置、诊断及旧控制会话，和 `cfw-profiles` 的存储路径使用 Unix
  描述符、权限、文件锁及 `openat`/`renameat`。不能通过删除检查或普通路径拼接移植。
- `cfw-platform` 实际仍是 macOS 适配器；`cfw-apple-network` 及 Swift 服务依赖
  Apple 的权限、Keychain、XPC 和 Network Extension。
- `scripts/build_libbox.sh` 通过 `gomobile bind` 生成 Apple/Objective-C 绑定；
  Windows 引擎宿主/绑定也需要实现，不能把共享 Rust 编译通过当成引擎已移植。
- 宿主 `build.rs` 明确拒绝非 `aarch64-apple-darwin`；现有 Mac CI 的三个 job 均为
  `xcode-27`（Windows 验证流水线为本次新增）。2026-10-18 仓库 runner API 返回 0 台自托管 runner。

## 页面和 UI 对照表

下表是完整 CFW 的要求，所有 Windows 运行与视觉证据目前均待取得。
保持九页顺序、侧栏与状态区、原位置的操作、信息密度、现有最小窗口尺寸，以及
英文、简体中文、繁体中文、日文。数据加载、失败、未知、禁用和操作中的状态都要覆盖。

| 页面/界面 | GA 行为和布局基线 | CFW 对应要求 | 主要源文件 |
| --- | --- | --- | --- |
| General | 品牌、版本、流量/运行状态；Port、Allow LAN、Log Level、IPv6 DNS、Engine、TUN MTU、Home Directory、GeoIP Database、TUN Mode、Mixin、System Proxy、Start with macOS 的顺序 | 保持行序与入口；名称改为 Windows 对应项；保留重试、授权、取消和错误条件；不把未知显示为 Off | `ui/src/general.js`、`src/engine_controls.rs` |
| Proxies | Global/Rule/Direct；分组和节点选择、搜索、分页、延迟测试及取消、超时节点显示 | 同一选择与探测语义，运行时选择和持久状态一致；自动组不转成手选组 | `ui/src/proxies.js`、`ui/src/proxy-delay-test.js` |
| Profiles | 本地文件/文本/URL 导入；选择、更新、编辑、外部编辑、显示目录、节点/规则编辑、复制、QR、凭据、设置、删除 | 同一入口与确认步骤；Windows 文件对话框和路径；无效配置仍可被列出并处理；不丢失凭据引用 | `ui/src/app.js`、`ui/src/profile-import.js`、`src/commands/profiles.rs` |
| Providers | 代理/规则提供者、更新与全部更新、健康检查和禁用原因 | 保持数据来源、批处理结果与失败可见性；不以空列表掩盖读取失败 | `ui/src/providers.js`、`src/commands/providers/` |
| Logs | 级别过滤、搜索、暂停/恢复、受限日志流 | 同一日志语义与脱敏；订阅关闭后释放资源，突发日志不阻塞 UI | `ui/src/app.js`、`src/commands/controller.rs` |
| Connections | 搜索、排序、详情、进程信息、暂停、关闭单条/全部 | 实际连接数据与取消/关闭结果；Windows 进程归属另行验证 | `ui/src/connections.js`、`src/commands/controller.rs` |
| Rules | 顺序、搜索、分页、刷新、离线保存视图、中国大陆直连提示 | 同一规则顺序和生效解释；未知运行状态不伪装成保存状态 | `ui/src/rules.js` |
| Settings | 外观/语言、启动、更新、运行参数、自动化、节点/连接选项、凭据、维护、路径、DNS、缓存、平台说明 | 保持分组、位置和保存行为；用 Windows 的托盘、启动、凭据和系统说明替换 Apple 名称；会话选项不擅自变成持久选项 | `ui/src/settings-view.js`、`ui/src/automation-settings.js` |
| Feedback | 关于、检查更新、网络架构说明和布局参考 | 保留分组与检查更新入口，平台信息必须来自 Windows 宿主；页面本身不自动发送反馈 | `ui/src/app.js` |
| Profiles 原生菜单 | 原顺序、条件可见/禁用、右键、外部点击/Escape、焦点归还 | 完整行为等价，并验证菜单位置和缩放 | `src/native_components/profile_menu.rs` |
| Network settings 原生表单 | Port/MTU 入口；端口、日志、MTU、IPv6、LAN、监听、可信源、Cancel/Apply；失败保留草稿 | 完整字段与提交事务；保存期间的关闭行为、键盘和焦点等价 | `src/native_components/runtime_settings.rs` |
| General 原生开关 | 六个原位开关、实际禁用和 pending 状态、可访问名称 | 不把关闭原生功能后出现的旧 HTML 控件直接算成视觉对齐 | `src/native_components/general_switches.rs` |
| 原生确认/信息弹窗 | 标题、按钮顺序、取消/确认、错误保留、模态与焦点 | Windows 等价呈现，不能悄悄省略确认 | `src/native_components/prompt_dialog.rs` |
| 窗口材质与侧栏 | 同一布局下的玻璃背景、侧栏、选中项、浅/深色、透明度与对比度适配 | 保留布局和视觉角色；Windows 材质差异单独截图评审，不用 Mica 冒充 Liquid Glass | `ui/src/window-glass.js`、`native/dashboard/Sources/CFMNativeDashboard/WindowGlass.swift` |

UI 验收按同一视口和缩放规则比较布局/控制位置，再检查系统字体、窗口装饰和材料差异。
不同字体抗锯齿不要求像素相等，功能缺失和布局漂移不能用该例外解释。Windows 独有
键盘、屏幕阅读器、高对比度、混合 DPI 和多屏行为是新增平台验证，不替代既有 UI。
所有差异必须记录，重大视觉方向改变需要用户决策。

## 功能与平台对照表

| 能力 | 必须共享或保持的契约 | Windows 工作 | 必需证据 |
| --- | --- | --- | --- |
| 本地代理/System Proxy/TUN/组合模式 | 单一协调器、串行迁移、请求身份、实际就绪状态、清晰失败 | 新 Windows backend；用户代理与需权限的网络服务分离 | 真正 HTTP/SOCKS/TUN 流量；组合切换；失败和退出后的 OS 读回 |
| 引擎与协议 | GA 受支持配置与同一 sing-box 源版本/补丁语义；不能以换引擎缩小功能 | Windows 引擎构建、运行和服务集成；逐项审查平台补丁 | 协议回归、真实 TCP/UDP/QUIC、原始日志与抓包 |
| 导入/订阅/配置编辑 | 闭合 schema、限制、组/规则/传输语义、凭据先入库和事务 | 安全持久化、文件选择、应用路径；共享转换器和校验器 | 同输入同规范配置；拒绝案例；部分写入/并发更新/升级恢复 |
| 节点、组与路由 | 手动、url-test、fallback、负载均衡、detour 不相互冒充；中国大陆直连 | Windows 进程规则、路由与网络变化适配 | 命中路由、控制面状态和数据面的对应证据 |
| 凭据 | 不可变引用、缺失项补全、身份绑定、脱敏、两阶段 GC | Windows 受保护存储及用户/服务间授权传输；不把秘密落入配置或日志 | 不同用户、错误身份、冲突、撤销、GC 和服务重启测试 |
| DNS/IPv6/fake-IP | 代理端点 bootstrap 与普通 DNS 路由分开；加密校验；无隐式直连降级 | Windows DNS、接口、缓存和路由集成 | DNS 失败、IPv6、fake-IP、接口切换与恢复后的抓包/读回 |
| LAN | 显式开启、可信源范围、独立监听及失败反馈 | 防火墙与接口监听，受限权限安装流程 | 允许/拒绝来源的实测；关闭后端口和规则清理 |
| 自动化/快捷键/启动 | 显式 opt-in、冲突报告、保存状态与实际注册一致 | Windows 快捷键、网络通知、启动/托盘集成 | 实际按键、网络变化、登录和恢复；UI 关闭不重复注册 |
| 诊断/日志/连接 | 有界流、取消、脱敏、未知状态和准确错误 | Windows 网络/服务诊断和进程归属 | 故障注入、取消/重连、长时间内存/队列观察 |
| 生命周期 | 一项用户意图只执行一次；退出恢复与停止次序；不覆盖其他所有者设置 | 服务所有权、崩溃恢复、Explorer 重启、多会话、睡眠唤醒 | 系统代理/路由/DNS 实际读回；正常退出、强退、断电式重启分开 |
| 更新/安装/迁移 | 受信任来源、精确版本/架构、失败保留旧可用状态、独立平台更新流 | Windows 安装包、签名、运行库、服务/驱动安装与升级回滚；旧 CFW 数据迁移须显式确认 | 干净机器安装、升级/失败/卸载、下载后验签和公共字节核对 |
| 可访问性/性能 | 四种语言、完整键盘路径、真实状态名称、无主线程阻塞 | Narrator、高对比度、减少动画、混合 DPI/多屏 | 真实桌面操作；冷/热启动、CPU/内存、滚动与网络测量 |

协议覆盖不能仅从上游文档推断：包括 GA 已实现的 SOCKS5、Shadowsocks/2022、VMess、
VLESS/Reality、Trojan、Hysteria2、AnyTLS、TUIC、WireGuard 及其受支持传输、DNS、TLS/ECH
选项，以冻结源码的转换、校验、投影和现有协议测试为依据。OpenVPN/OpenConnect、
任意脚本/PAC、任意 sing-box/Mihomo 配置和 kill switch 不因移植自动成为支持项。
Mixin 在 GA 仍明确不可用，不把它画成可用开关，也不能用这个单项例外删去其他功能。

GA 发布说明记录的安装所有权和非正常退出遗留隧道问题是已知限制，不是应复制到 Windows
的“功能”。Windows 必须定义并验证自己的关闭、隐藏、正常退出、强退及恢复行为。

## 两条路线比较与决策

| 维度 | 共享前端：Rust + Tauri/WebView2 | Rust + C#/WinUI 3 |
| --- | --- | --- |
| 页面与交互 | 复用九页、状态模型、翻译、验证、排序、过滤、编辑和测试；提取显式平台表现信息 | 九页与弹窗重新用 XAML/绑定实现；复用视觉规范但无法直接复用 DOM/渲染测试 |
| 五类原生表现组件 | 分离 macOS 实现，建立 Windows 对应材质/控件与焦点行为；不能只关闭功能标志 | WinUI 实现同样五类交互，同时重做其余页面；系统能力不能自动带来布局一致性 |
| 宿主/业务边界 | 保留命令入口，抽离 macOS 绑定，继续使用共享 Rust 用例 | 额外抽离当前依赖 AppHandle 的用例；维护 C ABI/异步事件、缓冲区所有权和取消边界 |
| 网络/服务/凭据/持久化 | 全部需要 Windows 适配 | 同样需要，C# 不消除这些工作 |
| 每次 CFM 功能更新 | 共用页面和业务变更，另验两种 WebView/系统集成 | 共享 Rust 更新后，还需同步两套 UI、绑定、翻译使用和交互测试 |
| 构建部署 | Rust、Node、WebView2 和 Windows 包装/签名 | 另有 .NET、XAML、Windows App SDK、架构匹配和运行库部署 |
| 主要风险 | WebKit/Chromium 差异、WebView 与原生控件的焦点/材质组合、现有宿主平台耦合 | UI 漂移、双份实现、桥接生命周期、重写遗漏；WinUI 自定义样式与可访问性 |
| 原生体验 | Windows 系统边界原生，页面共享；视觉与交互仍须实际确认 | 更直接使用 Windows 原生控件，仍需定制以满足既有布局 |

**当前选择共享前端。** 依据是本次明确要求完整功能和相同 UI，且现有 GA 的大部分页面
就是共享前端可复用的内容。保留 Rust，建设 Windows backend；不为迁移额外引入 C#
宿主或同时维护两套 Windows UI。这个选择不授权降低视觉目标、禁用功能或删掉原生行为。

若早期真实 Windows General 页和复杂弹窗验证表明，焦点、可访问性或材质要求无法用
可维护的共享实现满足，应带具体反例重新评估 WinUI。重评前完成的 Rust 平台边界、
配置契约和网络验证仍可复用。工期和性能不能仅按代码行数或框架宣传估计，先实测。

## CI 与验证方案

Windows 成品使用 Windows runner；本机可仅作为编辑与控制端。现有 Mac 构建持续保留。
构建不是交付完成，CI 可以调度验收，但执行环境必须满足所测行为。

| 验证层 | 共享前端 | WinUI 路线增加的工作 | 证据与边界 |
| --- | --- | --- | --- |
| 每个变更：共享逻辑 | 锁定依赖的 Rust fmt/Clippy/测试、导入/配置/模式契约；Node 构建与现有 UI 测试 | C# 分析/测试，ABI 所有权、事件、取消和错误映射测试 | 各平台结果分别记录；fixture 不能证明实际网络或窗口 |
| Windows 构建 | 固定 runner/工具链，先 x64，ARM64 为独立目标；引擎/宿主/安装包均构建 | .NET/XAML/Windows App SDK 和 Rust DLL 架构闭包 | 工具链、源 SHA、产物哈希、测试日志；交叉编译不等于目标运行 |
| 安装与签名 | 独立签名阶段；最终包验证签名、依赖、来源、许可证与 SBOM | 另验证 App SDK/.NET 部署和启动模型 | 不让不受信任 PR 接触签名身份；不以签名成功替代安装 |
| Windows 桌面 runner | 有交互会话，真实 WebView2、托盘、对话框、焦点、四语言、缩放与无障碍 | 同样验证真实 WinUI 窗口/控件和绑定 | 截图、操作日志、窗口/进程身份；RDP 断开/锁屏状态需纳入配置 |
| 有权限的隔离网络 runner | 服务/TUN/系统代理、受控端点、故障注入、恢复和升级 | 无法由 UI 框架省略 | 独立管理通道与清理；在专用环境改变网络，不危及唯一控制链路 |
| 代表性 Windows 真机 | NIC/驱动、Wi-Fi/有线切换、睡眠、重启、GPU/DPI、多用户及长期运行 | 相同 | 原始数据和实际 OS/网络观察；云 VM 不替代物理差异 |
| 发布闭环 | 干净安装/升级/卸载，签名下载后的包，核对公共哈希与相应源码 | 相同 | 新版 CFW 独立发布资产和更新身份，不能误导 CFM 更新到 Windows 包 |

目标 OS 最低版本、x64/ARM64 首发范围、签名身份、安装形式及可用桌面/真机资源仍需在
具体方案和环境证据齐备时确定，未确认的架构不标记“支持”。先做 Windows x64 的真实
纵向链路不缩减最终功能对齐范围。签名/安装/发布前提交可审查的具体产物和所需授权。

## 执行顺序与动态状态

| 阶段 | 输出/退出条件 | 当前状态 |
| --- | --- | --- |
| 基线 | 固定 GA；九页、命令、平台功能与已知限制清点 | 源码和发布身份已核实；已安装界面全量视觉采集待完成 |
| 路线评估 | 两条路线范围/维护/CI 对照、明确建议 | 已记录共享前端建议 |
| 共享边界 | UI 产品/平台表现、用例与持久化边界；Mac 行为保持回归 | `ab812fc` 的 Windows 快照通过 481 项 Rust/311 项前端；共享授权改动的 Mac 全工作区 1,160 项 Rust 回归通过；当前完整 Mac CI 与桌面产品接线未完成 |
| Windows 纵向链路 | 真正导入、启动代理、联网、停止恢复；General 与复杂弹窗真实验证 | 引擎、Rust 进程所有权及 WinINet 流量/恢复已通过九项真实集成测试并核验下载产物；`ab812fc` 的 SCM 九项原生场景及普通客户端权限边界也已通过并核验回执；完整服务生命周期及桌面链路待完成 |
| 全功能/视觉 | 本文全部页面和功能逐项有可执行用例与证据 | 待完成 |
| 稳定性/交付 | 完整 CI、真实 Windows 验收、签名安装更新、性能与恢复 | 待完成；用户暂未确定 Windows 测试机，先推进代码和托管 CI；真机项目保持未验证 |
| 正式发布 | 无阻塞缺陷、源/包身份一致、授权发布和下载验证 | 未开始 |

每轮更新本表和真实验证记录。保留失败与反例；阻塞一个步骤时推进独立工作。不得用
编译后的空壳、模拟网络、跳过平台测试、关闭安全检查或简化 UI 把进度改成完成。

### 2026-10-18：共享界面身份与第一条 Windows CI

- 内部 `boot_payload.product` 将 `minimum_macos` 改为 `minimum_os_version`，并增加
  闭合的 `operating_system`（`macos`/`windows`）。旧/缺失/未知字段显式拒绝。宿主和
  前端随同一应用更新；不修改任何持久化格式、凭据、网络配置或已发布 GA 资产。
- General 的名称与开机启动标签、About/Feedback 的产品/OS 元数据读取经过校验的
  宿主身份。Windows 复制动作生成 PowerShell 环境变量命令，macOS 保留原命令。
  非整数、越界和文本注入端口不会生成或复制命令；观察/复制不发出网络变更。
- 这不是完整 Windows UI。设置、自动化、更新提示、平台说明及原生表现组件仍有
  Apple 专用路径，必须在后续步骤完成，不能用此项测试代替全页面对齐。
- 新增 `.github/workflows/windows.yml`，只验证四个共享 Rust 包和前端契约。
  Node/Rust/npm 来自仓库版本锁，npm 归档校验已固定哈希。Windows 宿主、服务、
  TUN、窗口交互和安装发布还不在该 job 的证明范围内。
- 已观察 red/green：新增平台身份用例在原实现失败（`boot product fields are invalid`），
  修改后的迁移/启动协议文件 13 项通过。固定 Node 的完整前端套件 310 项通过；
  固定 Rust 的格式检查通过。构建日志保存在本工作区 `target/cfw-validation/`。
- Mac 完整工作区、所有 target/feature 的 Clippy（`-D warnings`）通过；Windows
  workflow 通过 Actionlint 和所有 PowerShell 步骤的语法解析。
- 首次 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39127804650)
  在 `e7f4bd5` 完成共享包编译/Clippy，配置包有两项失败：16 份投影 golden 的字节
  比较，以及 Reality 无效配置用例。后续前端步骤未执行。失败日志保留在
  `target/cfw-validation/windows-ci-failure.log`。
- 已在隔离检出目录复现共同机制：`core.autocrlf=true` 将全部 16 份 golden 改为 CRLF，
  去除该转换后逐字节等于原文件；同样的转换使 Reality 的 LF 字符串替换不再改动输入。
  新 `.gitattributes` 固定文本源码 LF，严格 golden 比较不变，负例额外断言输入确实变化。
  修复后同一检出实验的 17 份文件逐字节一致，本地 129 项配置单元测试通过。
  [第二次 Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39128361845)
  在 `694fd4e` 已通过全部共享 Rust 测试，验证了该修复。前端构建成功，310 项前端
  测试中 309 项通过，1 项在测试自身的源码定位阶段失败：用 `/` 拼接的文件后缀
  无法匹配 Windows 路径。改为平台正确的 `path.join` 精确定位，并明确断言来源存在；
  控制器权限检查的断言和要求保持不变。
- [第三次 Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39128685609)
  在 `bdfbcd4af47598bdee090cb4d044c43a6b8420eb` 完成并成功：格式、共享包 Clippy、
  290 项 Rust 测试、前端构建、310 项前端测试均通过，失败/忽略/跳过均为 0。
  原始完整日志和提取结果在 `target/cfw-validation/windows-ci-final.log` 与
  `windows-contract-result.json`。相同提交的 [Mac 托管 CI](https://github.com/billlza/cfw-rs/actions/runs/39128685594)
  三个 job 在当时查询时仍排队，不能将本地 Clippy 结果算成该托管运行通过。
  这些结果不证明 Windows 产品可用或达到 GA。

实际验证入口：

```sh
CFW_RELEASE_RUST_TOOLCHAIN=private ./scripts/run_release_ci_gate.sh bootstrap-node-toolchain
CFW_RELEASE_RUST_TOOLCHAIN=private ./scripts/run_release_ci_gate.sh prepare-ui-dependencies
CFW_RELEASE_RUST_TOOLCHAIN=private ./scripts/run_release_ci_gate.sh ui-test
CFW_RELEASE_RUST_TOOLCHAIN=private ./scripts/run_release_ci_gate.sh rust-fmt
CFW_RELEASE_RUST_TOOLCHAIN=private ./scripts/run_release_ci_gate.sh rust-clippy
```

### 2026-10-18：Windows 私有存储边界

- 新 `cfw-windows-storage` 提供 Windows 目录句柄、身份与 DACL 校验、重解析点和
  硬链接拒绝、有限大小读取、共享/独占锁，以及临时写入后原子替换。新文件只授权
  当前用户和 LocalSystem；旧迁移文件的额外只读授权与可写授权分开处理。
- `cfw-core` 的原 Mac 文件系统实现逐字节移到独立模块，Windows 通过同一接口接入
  设置、窗口状态、运行参数 CAS、诊断和身份绑定迁移。`MacOsAppPaths` 改为
  `AppPaths` 并更新调用方；Windows 从系统 Known Folder API 取得 LocalAppData，
  Mac 的既有目录和所有持久化 JSON 格式保持不变。Apple 旧控制会话仍仅用于 Mac。
- [Windows 目录刷盘探针](https://github.com/billlza/cfw-rs/actions/runs/39130129264)
  在 `3560b6cf5d21da30374c79602951b50671572eaf` 实际确认写入、重命名和删除后
  `FlushFileBuffers` 返回成功。探针保留为独立 OS 契约回归；该结果不是断电恢复证明。
  新后端在目录项改变但刷盘失败时返回 `CommitUncertain`，不能报告旧值必定保留。
- [Windows 原生验证](https://github.com/billlza/cfw-rs/actions/runs/39132902329)
  在 `1fea274` 通过格式、Clippy、329 项 Rust 测试和 310 项前端测试，失败、忽略及
  跳过均为 0。Rust 包含 30 项共享核心持久化测试及 9 项 Windows 文件系统测试。
  前一轮 `5fe545e` 的 Windows 编译暴露了新代码对摘要类型格式化接口的误用；修复
  保持既定 SHA-256 算法和完整小写十六进制输出，没有改动锁定依赖。
- Mac 本地固定工具链的整个工作区/all-targets/all-features 检查完成：1,143 项 Rust
  测试通过，失败、忽略、过滤均为 0，其中核心 33 项；主线程集成回执为
  `main_queue_callback_ms=25 late_engine_installations=0`。全工作区 Clippy、最终
  核心 Clippy、fmt、metadata 和依赖策略审计通过，编译器/策略 error、warning 为 0。
  完整日志保留在 `target/cfw-validation/storage-*`；托管 Mac CI 排队不计作通过。
- 复核发现公开记录名能与内部临时文件重合，下一次替换会将该记录当作遗留临时文件
  处理。[独立回归](https://github.com/billlza/cfw-rs/actions/runs/39133263100)
  在 `9095def` 已观察到旧实现接受 `.state.json.tmp` 而失败，原有 9 项原生用例仍通过。
  修复为公开读、写、删统一拒绝 `.cfw-` 前缀和 `.*.tmp` 内部名称，并预留临时后缀
  所需长度；合法的隐藏迁移记录保持可读写，保留
  Unicode 名称，增加最大合法长度的实际读写测试。新建目录也刷盘其父目录项；
  首次名称限制过宽，`7100765` 的共享迁移测试实际发现已有隐藏迁移记录被拒绝；
  已按存储真正占用的名称空间修正，而非对迁移文件加特例或跳过测试。
- [修复后的 Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39133991519)
  在 `48f42ee3425d091b2588d1ed690037021f53febf` 成功完成：331 项 Rust 测试、310 项
  前端测试、格式、Clippy 和目录刷盘探针通过，失败/忽略/过滤/跳过均为 0。11 项
  原生文件系统测试包含临时名称回归、合法隐藏记录、Unicode 路径和最长合法名称；
  30 项核心测试包含原先失败的迁移日志事务。旧实现失败、新实现通过的日志均保留。
  完整回执在 `target/cfw-validation/windows-storage-final-result.json`，原始日志
  SHA-256 为 `9dbf2afc40ecf46fe072d2c39836fab53028e8f5e85af2256d05815b6197ecd8`。
  相同提交的三个 [Mac 托管 job](https://github.com/billlza/cfw-rs/actions/runs/39133991506)
  在当时查询时仍排队；本轮成功的 Mac 回归是本地固定工具链结果。
- 新直接依赖复用锁文件已有的 `windows-sys 0.61.2`；注册表包的名称、版本和
  checksum 集合未变化。Mac 依赖策略检查已通过；Windows 完整发布依赖审计仍待建设。
  初步存储阶段尚未包含 Windows 配置仓库（后续进展见下节）、
  凭据库、引擎宿主、桌面壳、服务或 TUN，也未作可发布声明。

### 2026-10-18：Windows 配置仓库

- `cfw-profiles` 分离 Mac 与 Windows 文件系统实现；将三处重复的文件所有权/权限
  检查收归存储边界。配置、选中项、替换意图的格式、规范化、大小与摘要校验，以及
  现有恢复事务继续共享。跨凭据准备和配置提交的守卫实际保留 Windows 独占文件锁。
- Windows 存储补充原目录句柄上的受锁保护枚举、有界目录记录解析、只读私有文件
  句柄、拒绝覆盖的原子创建和显式批量清理。清理删除链接本身，不读取外部目标，
  拒绝遍历真实子目录；批量删除后的同步和部分失败仍由仓库事务处理。
- 共享仓库测试全部保留；Mac 专属 UID/fchmod 用例继续在 Mac 运行，Windows 增加
  实际目录描述符的所有者匹配测试及真实只读目标导致发布失败后的临时文件清理。
  持久锁文件有独立的所有权、私有权限和空内容断言，再从应用记录数量中排除。
  故障 fixture 仍可在持有仓库守卫时模拟外部改写，不通过跳过锁测试适配 Windows。
- 本地固定工具链的仓库测试通过：23 项单元、49 项集成，失败/忽略/过滤均为 0；
  仓库和核心 Clippy 通过。在 `efd9ebd` 上全工作区/all-targets/all-features Clippy、
  1,143 项 Rust 测试、主线程集成和依赖审计通过；之后新增的路径回归随 34 项核心
  测试及 72 项仓库测试另行通过。后续改动的 Mac 产品路径与该整库验证一致。
  锁文件仅新增工作区内部依赖边，注册表包版本和校验和集合未改变。
- Windows 实测发现 `ReOpenFile` 拒绝这些目录句柄，原生相对 `.` 打开也不接受该
  名称；失败都在枚举开始前发生。最终直接保留原目录句柄，对完整游标扫描加有界
  互斥保护，每次从头枚举。多缓冲区并发读取和目录改名用例保留，未改为路径枚举。
  同轮反例还确认底层 `open_existing` 会将文件占据祖先的路径当作不存在；现已在
  返回缺失状态前检查最近的现存祖先。原生用例和仓库快照回归验证错误不会变成空仓库。
- [Windows 配置仓库验证](https://github.com/billlza/cfw-rs/actions/runs/39138677712)
  在 `637f76336bf4b547732ee106efcdd31c9a55cab3` 成功：407 项 Rust、310 项前端测试、
  格式、Clippy 和目录刷盘探针通过，失败/忽略/过滤/跳过均为 0。仓库包含 21 项
  单元与 49 项集成测试，原生存储包含 1 项所有者检查和 15 项文件系统测试。
  `--no-fail-fast` 收集独立目标的全部结果，但任何失败仍使命令和 job 失败。
  完整回执在 `target/cfw-validation/windows-profiles-green-result.json`，日志 SHA-256
  为 `d1fa976512f1e104b3b07d2af74b7b599fc2ca2029827f44b83e1d44dd309131`。
- [最终 Windows 仓库回归](https://github.com/billlza/cfw-rs/actions/runs/39139812422)
  在 `e9fb5d79b4ca7dae3909a2f84b6d3b7cd7909449` 成功：408 项 Rust、310 项前端测试，
  格式、Clippy、目录刷盘探针均通过，失败/忽略/过滤/跳过为 0。新增用例实际持有
  枚举游标锁，观察到三秒超时，并在释放后完成重新枚举。回执为
  `target/cfw-validation/windows-profiles-final-result.json`，日志 SHA-256 为
  `7741cd000f645d65292893c32f507f7b178aab92194113c9024e51250e6c5560`。
  同源 Mac 托管 CI 的三个 job 在结果核对时仍排队，未取得托管通过结果。
  本阶段仍不证明 Windows 应用启动、凭据库、引擎、系统代理、TUN、桌面视觉或发布验收。

### 2026-10-18：Windows 凭据存储与宿主边界

- `cfw-windows-credentials` 实现当前用户作用域的 DPAPI 持久化，复用已建立的私有
  目录、DACL、句柄相对访问和跨进程事务。磁盘及临时文件只接收密文；整批校验
  UUID 不可变性、精确 profile/digest 绑定、凭据类型和容量后才发布。支持存在性查询、
  保留凭据重绑、引擎读取，以及绑定版本和精确孤立集合的清理。解密、身份或格式
  失败不变成空库；发布后不能确认刷盘仍返回 `OutcomeUnknown`。
- 清理显式接收运行时绑定，必须在引擎生命周期互斥范围内观察活动、待定和持久化
  恢复配置，并在提交时重新核对。该组件尚未实现产品的 `CredentialVaultProvisioner`
  接线，避免在 Windows 引擎观察尚未实现时用空集合代替。凭据读取也没有前端命令。
  当前用户 DPAPI 不提供同用户进程隔离；特权服务身份和 IPC 授权仍是独立待办。
- 共享 `ManagedProfiles` 改为持有公共凭据接口；Mac 仍注入原来的原生桥。实际编译
  揭示原先离线节点测速也挂在 `credential_vault()` 上，现将其移到引擎的
  `ProfileDelayBackend`，继续调用 Mac 原实现及结果校验。
- [后续 Windows 仓库运行](https://github.com/billlza/cfw-rs/actions/runs/39141160208)
  在仅改文档的 `3fbcc9d` 暴露 3 项 `StoreBusy` 并发失败，证明先前单次全绿不足以
  排除锁饥饿。原实现每 10 ms 尝试抢锁，连续写者可能在读者醒来前重新取得锁；
  已改用一次异步 `LockFileEx` 等待，保留三秒准入期限，超时取消并等待该请求完成
  后才释放内存。未放宽超时或修改原有并发断言，另加重复抢锁期间的进展回归。
  驱动确认取消的时间可能延长退出清理，文档未将其宣称为绝对三秒返回。
- 第一轮本地编译暴露测速调用耦合；[第一轮 Windows 编译](https://github.com/billlza/cfw-rs/actions/runs/39142347830)
  暴露枚举游标仍依赖轮询常量，二者均在 `e54b2de` 修正。原始失败日志保留于
  `target/cfw-validation/credential-mac-clippy.log` 和 `windows-credentials-first-failure.log`。
- 新直接依赖复用已有的 `subtle 2.6.1`、`windows-sys 0.61.2`、`zeroize` 等，
  519 个注册表包的名称、版本、来源与 checksum 集合保持不变。
- [Windows 凭据与并发回归](https://github.com/billlza/cfw-rs/actions/runs/39142577800)
  在 `e54b2de0b427adfb57f86a7e02b017646929aad5` 成功：429 项 Rust、310 项前端
  测试、格式、Clippy 和目录刷盘探针均通过，失败/忽略/过滤/跳过为 0。包含 20 项
  真实 DPAPI 凭据测试、跨进程重开、损坏与容量拒绝、身份检查、清理版本和运行时
  竞态，以及全部三个先前失败的并发用例和新的锁进展测试。回执为
  `target/cfw-validation/windows-credentials-green-result.json`，原始日志 SHA-256 为
  `ad0eeacf57ef0bc3cb009d72c9c52e6ab0f2c6521093ec651a620db70951b680`。
- 同源本地固定工具链全工作区 Clippy、1,145 项 Rust 测试、310 项前端测试和
  cargo-deny 均成功；Rust 失败/忽略/过滤为 0，启动测试记录
  `main_queue_callback_ms=24 late_engine_installations=0`。回执为
  `target/cfw-validation/credential-mac-result.json`，Rust 原始日志 SHA-256 为
  `6551b7bf94ee5279ce060a44236de7e8024d2f2a1b1dd086da694866c3e056a5`。
  同源 Mac 托管 CI 在本次结果核对时仍排队，不能冒充托管通过。
- 随后将共享 `OutcomeUnknown` 的错误说明由仅指超时改为“无法确认完成”，并明确
  该错误不保证回滚，以覆盖发布后刷盘失败。此文字/契约修订通过全部 27 项
  engine-api 测试及该包 Clippy，不改变错误变体或持久化格式。
- 此阶段尚未验证 Windows 桌面宿主、凭据服务授权、引擎、系统代理、TUN、安装更新、
  签名或真实桌面视觉；完整产品和正式发布目标继续保持未完成。

### 2026-10-18：Windows 原生引擎构建与回环验证

- 新增独立 Windows x64 job，使用与 GA 相同的 Go 1.27.2、sing-box 提交、六组补丁
  和构建标签，生成 `cfw-engine.exe`。Windows Go ZIP 的摘要来自官方 Go 下载元数据；
  不改动 Mac 的版本、补丁或模块图。Python 固定为既有 3.14.7。
- 移植的构建入口只在新的独立目录准备源码与工具，不覆盖现有检出。上游提交、
  go.mod/go.sum、各补丁与合并 diff 均检查既有 GA 摘要；构建前后另直接比较源码
  文件内容，避免仅依赖 Git 的索引状态。新入口产生的真实源码已通过原 Mac
  `libbox_validate_patched_source` 校验，五项辅助工具测试与 actionlint 通过。
- CI 配置要求两个独立 Go 编译缓存产生相同字节，并在 Windows 运行 GA 测试包
  集合。当前采用非 CGO 构建，不把普通测试报告为 race 检查。另以隔离回环端点
  验证有效/无效配置、控制器鉴权、HTTP 代理、SOCKS TCP/UDP 和强制结束子进程后
  的监听清理；配置通过 stdin 提供，不写配置文件或更改系统代理/TUN。
- 第一轮运行在离线 `go mod verify` 阶段暴露依赖元数据缺口：所选包的依赖准备没有
  覆盖完整模块图。修正为在线准备阶段显式解析全部模块元数据，再关闭网络；模块
  文件摘要和固定版本没有放宽。第二轮成功生成 EXE，但关闭端口的负向 TCP 连接
  检查超时，不能证明监听状态，故尚未进入代理流量测试。现改用 Windows 系统
  TCP 监听表，且启动后必须证明监听 PID 属于该子进程。
- 第二轮还明确发现两项 DNS 用例因缺少 Rust 投影而跳过。Windows job 现在使用
  同一 Rust 测试生成 mixed/tunnel/filter/named 四份输入，保持与 Mac 回归的接线
  一致。命名 Go 测试被跳过会使 job 失败，无测试的包单独列为仅编译。
- [Windows 引擎验证](https://github.com/billlza/cfw-rs/actions/runs/39146027517)
  在 `c4e87b68e47336e568d13d63bea6c6fad56bc6ee` 成功：458 个 Go 命名测试及子测试
  通过，命名测试跳过为 0；根包、`common/dialer`、`common/listener` 没有测试，
  只完成编译。11 项 Rust DNS 投影测试生成真实输入；独立的完整共享检查仍为
  429 项 Rust、310 项前端测试通过，失败/忽略/过滤/跳过均为 0。
- 下载后的 `cfw-engine.exe` 已核对 PE 机器类型 `0x8664`、大小 37,986,816 字节，
  SHA-256 为 `7daf87a7910d42f6f25d60e3dda1449fc26fe3c63f135dec3c7b4b0f69a63fe3`，
  与两个独立缓存构建及前一轮构建相同。实际 1,623 份源码文件的内容集合也与本地
  已经原 Mac 校验器确认的源码一致。完整日志 SHA-256 为
  `0856425246731ebf68b97799d8963690f5c35ff420c69f154da5066d6886da46`。
- 流量回执实测有效/无效配置、控制器鉴权与拒绝匿名访问、监听 PID、HTTP 代理、
  SOCKS TCP、SOCKS UDP，以及强制结束后监听消失。验证未更改系统代理或安装 TUN，
  也没有将强制结束写成正常关闭证明。原始组件、ZIP 和回执保存在
  `target/cfw-validation/windows-engine-component-c4e87b6/` 及对应 ZIP。
- 组件交付继续补入实际链接 Go 模块和 Go 工具链的上游许可/NOTICE 文本，复用既有
  许可文件发现逻辑并保留原始字节及摘要；完整 Windows 许可审查仍属发布验收。
  同源 Mac 托管 CI 在核对时仍排队。Rust 宿主、完整协议和 race 覆盖、正常退出恢复、
  Windows UI、签名安装与正式发布均未完成。

### 2026-10-18：Rust 宿主与私有引擎控制通道

- 新增 `cfw-windows-engine` 和 Go 进程入口 `native/windows/engine-host`。构建在
  独立目录叠加进程入口，保持 GA 引擎及六组补丁的原始内容和摘要不变。
- Rust 接受共享的已验证配置投影，按类型检查并注入完整凭据集合；保留原有投影
  身份，不公开已注入秘密的摘要。进程由私有管道和 Windows Job Object 持有，
  在发送任何启动配置之前必须完成作业归属。控制回执检查会话、序号、PID、版本、
  状态及配置身份；运行观察还核对操作系统监听表。
- 正常停止必须收到真实 `Box.Close` 成功回执，并观察退出码 0、控制线程完成、
  作业为空和本子进程监听消失。失败或超时进入独立的有界强制清理并返回错误，
  不作为正常停止或全局 Off 的证据。
- 当前是本地代理子进程层；Windows 全局权威、凭据授权接线、系统代理/TUN、
  完整桌面宿主与恢复顺序仍待实现。新 CI 用真实 worker 验证 HTTP 流量、控制器
  鉴权、正常关闭、端口冲突、崩溃与超时；没有用 mock 替换引擎。
- 本地新增 8 项 Rust 单元测试及对应 Clippy 已通过。最初两项凭据测试因用错
  Trojan 配置字段失败，修正测试输入为现有契约的 `credential_ref`，不改生产
  配置校验。Windows 原生结果需在新提交运行后记录，当前不宣称通过。
- 首轮 `ef0ab0f` 的 Windows 共享检查通过 437 项 Rust 和 310 项前端测试；引擎
  双缓存构建、474 个 Go 测试/子测试及旧 CLI 流量检查也通过，但 5 项 Rust 宿主
  原生用例全部在启动阶段失败，故没有正常停止成功证据。错误为共享冲突 32。
  源码显示新目录的长期句柄误用了文件发布所需的 `DELETE` 权限，与宿主的禁止
  删除共享句柄冲突。修订目录创建权限并增加原生回归：显式重现旧权限冲突，再
  要求实际存储目录能保持不可替换状态并完成两次原子写入。文件发布权限不变。
- 同时增加真实 DPAPI → 配置注入 → 私有管道 → SOCKS 出站认证 → HTTP 返回的
  原生用例。代理节点契约禁止回环地址，因此测试对端绑定 runner 自己的私有 IPv4，
  所有流量仍留在同一 runner；不放宽生产地址校验。此新增用例等待原生结果。
- `ef0ab0f` 本地 Mac 回归通过 1,153 项 Rust、全工作区 Clippy 和 cargo-deny；
  Go 入口本地 16 个测试/子测试通过。原始日志与摘要保存于
  `target/cfw-validation/host-local-result.json`；未将这些结果代替 Windows 验收。
- 第二轮 `84ca5a2` 已让原来失败的 5 项宿主用例全部通过：真实 HTTP、控制器鉴权、
  正常关闭和端口释放、启动冲突、崩溃、超时/Drop 清理、错误二进制/版本拒绝。
  新凭据用例在测试对端读取时返回 `WSAEWOULDBLOCK`，随后客户端收到连接重置；
  原因是测试端 accept 后仍处于非阻塞模式。修订两个测试对端，明确切换为阻塞
  模式后使用已有读写超时。此项属于夹具修正，完整凭据流仍需下一轮实测确认。

- 第三轮 [原生验证](https://github.com/billlza/cfw-rs/actions/runs/39152550973) 在
  `ff2b3e34736a63ad1ccc195e5a8a1724715361ea` 全部通过：438 项共享 Rust、310 项
  前端、474 个 Go 测试/子测试和 6 项真实引擎集成。下载后的两份 x64 EXE、构建
  回执、源码身份及 116 份许可文件摘要均已核对；完整产品发布仍未验收。

### 2026-10-18：协调器平台身份与 Windows 用户代次

- 共享后端显式声明 Mac 或 Windows 运行平台，协调器在 actor 启动时固定该身份。
  Windows 用户代理和 TUN 服务有独立 owner 名称；启动、恢复、持续观察按对应平台
  核对。Apple 现有 owner 的序列化名称不变。共享 UI 按封闭的运行角色呈现两平台。
- 重启规格保留完整已接受的运行身份，安装 ID、epoch、owner、generation 或 digest
  漂移都不能继续匹配原基线。新增协调器测试还要求 Windows 清理后的独立全局 Off
  证明；这些是状态机测试，不作为 Windows 服务、TUN 或真实网络证据。
- 新增当前用户的 Credential Manager 代次存储，使用固定产品 target 和规范文档，
  以 SID/target 隔离的 Global mutex 串行比较并更新。拒绝线程模拟、错误文档、
  陈旧代次、溢出，以及已绑定实例的权威丢失或安装身份替换；写入后读取不一致
  报告结果不确定，不承诺回滚。该记录不是特权服务身份，也不提供同用户恶意进程
  下的独立隔离或全局停止证明。
- 原生用例覆盖真实 Credential Manager 重开、四个进程的 32 次代次分配、陈旧 CAS、
  损坏不覆盖、溢出、模拟身份拒绝和安装身份替换；仅使用随机隔离测试 target，
  不触碰正式记录。新 mutex 复用存储层已有 SID/ACL 校验和原生进程身份检查。
- 本地共享变更通过 1,157 项 Rust、311 项前端测试、全工作区 Clippy 和 cargo-deny。
  [Windows 原生回归](https://github.com/billlza/cfw-rs/actions/runs/39156834433)
  在 `85755f79e45ef40b14ad3d92fc21d7b67ea70f0a` 全部通过：451 项共享 Rust、
  311 项前端、474 项命名 Go 测试/子测试及 6 项真实引擎集成测试。Credential Manager
  的七项原生测试和 mutex 的两项原生测试均执行；失败、忽略及命名跳过均为零。
- 保留三轮 Windows 编译失败证据：首轮 SHA2 摘要格式化接口使用错误，后两轮新
  StorageError 变体在凭据/配置仓库及核心设置映射中未覆盖。修复使用既有字节编码和
  显式错误分类，未增加默认成功或放宽 lint；519 个 registry 依赖版本和 checksum 未变。
  后续 Windows 条件编译另用任务隔离、官方摘要核对的 Windows Rust 标准库进行
  cross-target Clippy 检查；该检查只证明编译，不替代原生执行。
- 下载产物后核对 ZIP 摘要、精确源码、两份 EXE、原生测试回执及 116 份许可文件。
  桌面启动工厂、Windows 服务/授权和各网络模式的实际接线仍未完成。

### 2026-10-18：Windows 启动前配置检查

- 新增有界私有管道 `check` 操作：真实 sing-box 解析、构造、Close，要求 Close 成功
  和子进程正常退出，不调用 Start。Rust 继续核对进程身份、精确配置摘要、管道收尾、
  空 Job Object 和监听表。检查回执与运行/停止回执使用不同类型。
- 四种模式均可用 `ResolvedProjection` 校验；本地启动仍需独立的 `PreparedConfig`
  类型，不能因 TUN 配置校验成功而绕过 Windows 网络权限和恢复实现。
- 新原生测试在整个检查期间占用代理和控制端口，并要求工作目录没有生成配置/缓存
  文件；误启动监听会产生明确失败。Go 用例补充错误配置脱敏、运行中检查拒绝及
  实际占用端口反例。`9e76c49` 的 Windows 引擎 job 完成七项原生集成测试，四模式
  检查用例通过；同轮共享 job 暴露下述文件锁期限问题，整轮未通过。尚未接入完整后端。

### 2026-10-18：Windows 等待期限的原生反例

- [原生失败](https://github.com/billlza/cfw-rs/actions/runs/39157673412) 中，文件锁仍被
  另一事务持有，第二次读取返回 Busy，但实际等待不足契约的三秒，原有下界断言失败。
  代码将一次 `WaitForSingleObject(..., 3000)` 超时直接转换成期限到达；Win32 等待的
  系统时钟粒度不提供这个严格下界。未跳过该用例或降低三秒断言。
- 共用保留绝对单调期限的等待函数：只在内核提前报告超时时按剩余时间继续等待，
  不重新分配完整期限，不修改全局定时器精度；文件锁保持原始排队请求，到期后仍须
  取消并收尾。mutex 和进程退出等待复用同一语义。
- 确定性用例覆盖提前超时、亚毫秒余量向上取整、后续正常/abandoned 获取、已到期
  和原生错误保留；真实文件锁的三秒下界和 mutex 的二十毫秒下界继续验证。
  [修复后的原生 CI](https://github.com/billlza/cfw-rs/actions/runs/39158308639) 在
  `3216f57` 全部通过：454 项 Rust、311 项前端、476 项命名 Go 测试/子测试和七项
  引擎集成测试。原有三秒断言通过；下载 worker 与 Mac 交叉构建逐字节相同。

### 2026-10-18：Windows 管道对端进程与消息身份

- 新增从实际管道 PID、保留进程句柄及主令牌获得的对端身份。完整 SID、登录会话、
  session、完整性、AppContainer、受限令牌状态和进程创建时间不由调用者 JSON 提供，
  不转换成 Mac 的数值 UID。已退出进程和变化的身份不能复用原观察结果。
- 服务端读取请求后，另取该消息的管道令牌，与观察到的进程身份比对；获取句柄后立即
  恢复观察者身份，再读取令牌信息，不在模拟区间进行产品 I/O 或 async 挂起。恢复失败
  遵守 Win32 契约终止进程。普通 UI 不因此获得读取 SYSTEM 令牌的权限；SCM 与受信任
  安装身份仍需要单独接线，不能用此观察工具冒充服务认证或网络授权。
- 四项 Windows 测试覆盖真实双进程管道、消息中伪造 PID、陈旧身份、退出后拒绝、
  非管道句柄、观察者模拟身份拒绝和 SID 缓冲边界。固定管道拥有私有 ACL、拒绝远程
  客户端，子进程和 I/O 有期限。[原生 CI](https://github.com/billlza/cfw-rs/actions/runs/39160357742)
  在 `eff74e5` 完成全部三项 Windows job：458 项共享 Rust、311 项前端、476 项命名
  Go 测试/子测试和七项引擎原生集成测试均通过，失败、忽略及命名跳过为零。下载产物
  的源码、两份 EXE、构建回执和 116 份许可文件已核对；完整桌面与服务认证仍未接线。

### 2026-10-18：Windows 桌面平台观察

- 原 Windows 编译探针在 `cfw-platform` 暴露五项错误：Unix 进程组、kill 与 Mac
  sysctl 被无条件编译。现将 Apple 更新、注册、迁移、签名和进程管理接口限定为
  macOS，保留 Mac 实现，并提供实际 Windows 版本、语言和物理网络观察。
- Windows 读取有界的原生网卡/地址记录，过滤虚拟、断开、暂停网卡与未就绪或冲突
  地址。只有可用网关地址参与优先选择，截断和循环链表显式失败。SSID 按网卡 GUID
  使用微软推荐的 `GetConnectedSsid`，不扫描附近 Wi-Fi 或查询 BSSID；复用已有 Rust
  绑定，不引入 C#/.NET。原生观察在工作线程完成，不承诺同步 OS 调用的硬期限。
- 系统语言查询改为可失败接口，所有应用调用点传播错误。设置写入完成后，若语言
  应用或显示观察失败，返回信息明确说明设置已保存，避免把后续失败说成写入回滚。
- 本地完整 Mac Rust 回归 1,157 项通过，Clippy 与 cargo-deny 通过；Windows 目标
  Clippy 和 Windows workflow actionlint 通过。519 个 registry 依赖版本及校验值
  不变。新增十项 Windows 测试覆盖原生观察与解析反例，原生执行结果待提交后的 CI。
- 桌面应用的 Mac 构建限制仍保留。此阶段不等于 Windows 应用可启动，也不证明物理
  Wi-Fi、代理/TUN、服务授权、完整 UI、休眠恢复或发布验收已完成。

### 2026-10-18：共享授权与 Windows 用户代理恢复

- 应用层新增共享 `SystemProxyAuthorization` 契约，Apple 后端继续代理原生权限请求；
  关闭、切换模式、配置替换和恢复路径保留“先取得恢复权限、再停止引擎”的顺序。
  Mac 授权拒绝/超时及服务故障恢复回归继续执行，Windows 使用自己的权限错误信息。
- `WindowsSystemProxy` 通过 WinINet 管理当前交互用户的默认/LAN HTTP、HTTPS 代理。
  版本化私有记录先于设置修改落盘，绑定完整上下文、配置摘要、引擎 PID/创建时间和
  原始/写入值。保留原始 UTF-16、停用期间的 PAC URL 与自动检测状态，不写 WinHTTP、
  RAS 或系统策略。已有明确代理/PAC、机器级策略和禁止修改策略会阻止接管。
- 恢复只接受原值或本应用写入值，冲突不覆盖其他程序设置。WinINet 没有跨程序原子
  比较写入契约；这里保留读回、冲突与结果不确定语义，不宣称消除了 OS 竞态。
- 接线发现原有子进程管理器把单次 RPC 等待超时当成整个所有者消失，关闭管道并终止
  引擎。现在进程保留恢复义务；显式停止与异常清理先恢复设置，恢复失败保留所有者。
  过期等待者只丢弃该次迟到结果，不能自行关闭控制管道。进程崩溃/Drop 仍需上层监护
  恢复，不能据此生成全局 Off。
- 两项新增原生集成测试要求托管临时用户显式授权，覆盖实际 WinINet HTTP 流量、
  恢复冲突时引擎存活、RPC 超时不关闭管道、恢复后停止、所有者进程退出、陈旧上下文
  与外部修改。测试保存/核对原始设置，输出独立恢复回执；原生结果待提交后的 CI。
- 本地 1,160 项 Mac Rust 测试、完整 Clippy、cargo-deny 与 Windows 目标 Clippy
  通过；Windows workflow actionlint 通过，519 个 registry 版本/校验值保持不变。
- `dbba859` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39166565328)
  通过 473 项 Rust 与 311 项前端测试，但 Go 阶段的既有 NXDOMAIN 测试服务器在写入
  时收到连接重置，尚未执行新增代理变更测试。原始失败日志已保存。该测试的主 TXT
  响应可在 A/AAAA 后台复用探测结束前返回，清理可能与响应写入重叠；Windows 构建树
  新增仅限此测试文件的同步补丁，并保留全部写入、结果、回退和期限断言。原始 GA 树
  与生产代码不改。新旧夹具在 Mac 各执行 200 轮通过，Windows 新增 200 轮专项验证；
  不把本地结果冒充 Windows 反例复现或新代理测试通过。
- `a458773` 的 [原生执行](https://github.com/billlza/cfw-rs/actions/runs/39168136097)
  通过 Go 完整包测试及 DNS 200 轮专项，核对了系统自带策略定义，并通过所有者退出、
  陈旧上下文和设置冲突恢复测试。HTTP 代理夹具因使用受禁止的回环上游，在配置验证
  阶段失败；后续复用已执行的本机私有网卡端点夹具，保持生产地址校验，且在启动测试
  线程前完成输入验证。原始 8 通过/1 失败记录保留，尚未声称完整代理流量验证通过。
- 桌面工厂、完整服务授权、TUN、多会话/睡眠恢复、完整 UI、安装更新和签名仍未完成。
- `34c4911` 的 [原生执行](https://github.com/billlza/cfw-rs/actions/runs/39169379409)
  已走过真实 WinINet HTTP 与恢复冲突断言，但超时请求尚在控制队列时，后续观察把
  暂时满队列误判为断连，并提前消耗请求序号。清理后的停止请求因此出现序号缺口，
  Go 引擎按协议拒绝并退出，Rust 收到 EOF；本轮仍为 8 通过/1 失败。抽取实际入队
  路径后，回归先复现未入队也递增的缺陷，再修正为入队成功后提交序号、沿用原期限
  等待容量，并拒绝已过期的新入队。受控传输回归保留已超时等待者的迟到响应、真实
  控制循环、满队列与后续连续序号，原生验收继续执行，不给测试增加时序延时来绕过。

### 2026-10-18：系统代理原生收尾与 SCM 服务对端

- `e3213af` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39170513287)
  完成全部三项 job：476 项共享 Rust、311 项前端、476 项 Go 测试/子测试、DNS 200 轮
  专项及九项真实引擎集成均通过。WinINet 流量、冲突保留、恢复后停止和进程退出恢复
  回执已下载核对；EXE 字节与前一已验证产物一致。此前失败仍保留，不替换原始记录。
- 新增只读 SCM 对端认证及固定本机管道类型，绑定服务对象、实际管道 PID、进程创建
  时间与受信任可执行文件身份。不请求 SYSTEM 令牌、不提升 UI 权限，不将服务缺失
  解释为 Off；未知、停止、配置变化或危险服务 ACL 均拒绝。SCM 配置可能描述下次
  启动，因此必须独立确认当前映像；可信服务也必须在公开端点前检查自己的 SYSTEM
  主身份。完整网络服务、签名安装与运行授权并未由此实现。
- Windows CI 新增临时 SCM 服务夹具：两个实际 SYSTEM 服务、撤销管理员组与特权的
  中完整性客户端、ACL/配置变化、相同字节但不同文件的映像替换、缺失/停止服务与
  清理读回。仅在指定临时 Windows 用户中启用；本机不安装服务。四项包内反例与原生
  运行均需通过，当前实现等待原生 CI，不以交叉编译代替该验收。
- `cb5c160` 的 [原生执行](https://github.com/billlza/cfw-rs/actions/runs/39172775390)
  通过 480 项共享 Rust、311 项前端及九项真实引擎测试，但 SCM 服务状态校验拒绝了
  夹具服务。原日志未携带具体状态字段，不能据此声称已定位根因。现保留全部校验，
  让错误携带实际类型、状态、PID 与标志，并将不依赖 Go 引擎的服务测试拆为独立
  并行 job；四项 Windows job 均通过才算完整 Windows CI。
- `93cdc1a` 的独立服务 job 观察到类型 `0x10`、状态 `SERVICE_STOPPED`、PID 0、标志 0。
  此时拒绝符合契约；仍需解释夹具服务为何提前退出。服务回调增加有界的原始错误记录，
  父进程在清理后保留这些记录及客户端报告，测试日志标明实际执行阶段。认证条件不改。
- `68c0938` 已完成首次 SCM/映像/管道认证及另一个 SYSTEM 对端的拒绝，随后首次服务
  已停止。保存的服务失败文件为空；检查发现夹具在发布 `SERVICE_STOPPED` 后才写入
  失败记录，违反微软要求终止状态之前完成全部工作的契约。现前置记录、刷盘和运行时
  清理，并要求正常停止前仍为 Running、停止后 SCM 与进程退出码均为零；底层 I/O
  失败原因仍待新的原生日志，不改认证拒绝条件。
- `47c503a` 的回执保留了 `read fixture request` 的 Windows 错误 233。固定的 Mio
  1.2.3 在读完缓冲后预投递下一次读，而夹具调用 Disconnect 后复用同一实例；旧连接
  的预读错误可进入下一次请求。改用 Tokio 自带示例的逐连接实例模式，保持一个新的
  监听实例并限定实例数量，不吞掉 233、不清除错误或重试已提交请求。认证断言保留，
  相同字节替换文件的反例额外打印实际失败类型，后续原生执行继续核验。
- `9ff9fca` 通过前六项服务认证/拒绝场景，随后在夹具构造中完整性客户端时收到
  `SetTokenInformation` 的拒绝。`CreateRestrictedToken` 保留源句柄访问权限，而夹具
  未请求后续调整新令牌所需的 `TOKEN_ADJUST_DEFAULT`。现仅补齐夹具句柄权限；
  原令牌不修改，产品客户端不增加权限，降权子进程仍必须实际验证其完整性和非管理员
  身份后完成服务认证。
- `662508e` 已越过令牌调整，但降权子进程未生成报告。父进程原先的文件读取错误
  未保留子进程退出码，尚不能判断其启动、认证或写入是否失败。现保存退出码与有界
  标准错误；显式继承列表只包含 NUL 输入和诊断文件，不能把控制器的令牌、SCM、
  进程或管道句柄带入降权进程。报告写入失败同时保留原认证结果，仍需实际回执验收。
- `11a2227` 的子进程退出码为 `0xc0000142`（DLL 初始化失败），未生成认证报告。
  Windows 要求新令牌可访问所选窗口站/桌面；夹具改为创建该用户与 SYSTEM 专用、
  中完整性的临时窗口站和桌面，显式绑定启动上下文，恢复控制器原窗口站并在子进程
  退出后关闭新对象。现有桌面 ACL 不修改；这是客户端初始化的验证步骤，不能据此
  提前声称服务认证或桌面 UI 验收通过。
- `ddf11a9` 的共享 Rust/UI、存储及真实引擎三个 job 通过，但隔离桌面的客户端仍以
  `0xc0000142` 退出；尚未证实桌面权限是原因。现仅在临时夹具中采集有界加载器
  事件与默认令牌 DACL，定位初始化失败点。映像级 loader-snaps 注册项仅在临时
  Windows runner 中创建并在 finally 删除；调试路径无论子进程结果如何均返回诊断
  失败，不能替代无调试器的普通客户端验收，也不放宽服务认证条件。
- `1dbb38f` 的加载器记录明确为 `KERNELBASE.dll` 的 `DLL_PROCESS_ATTACH` 失败，
  尚未进入 Rust/USER32。实际令牌默认 DACL 为 BA/SYSTEM 全访问、登录 SID 仅
  `GXGR`；关闭 BA 后没有给用户正常控制自建对象的权限。夹具仅为新降权令牌设置
  当前用户/SYSTEM 默认 DACL，保留中完整性、禁用管理员组及特权。移除临时调试器与
  IFEO 设置，随后必须用无调试器的同一原生场景确认；加载器原始日志与诊断提交保留。
- `ac05f02` 的无调试器客户端成功进入 Rust，并确认中完整性/非管理员身份，随后在
  打开 SYSTEM 服务进程时收到 Access Denied。默认 DACL 修复解决了初始化失败，
  但服务默认进程权限不足以满足查询/等待退出的客户端契约。新增服务启动侧函数：
  仅 SYSTEM、session 0 的主身份可为自身进程设置并读回受保护 DACL；普通用户只获
  limited-query 与 synchronize，不能读内存、终止、修改权限或查询 SYSTEM 令牌。
  原生夹具在开放管道前使用该产品函数，并逐项检查这些拒绝；UI 端认证条件保持不变。
  另修正夹具保留句柄只请求 synchronize、却调用 GetExitCodeProcess 的静态权限错误，
  补上该 API 所需 limited-query；此前尚未执行到正常停止验收，不虚称已观察该错误。
- `c219bf1` 因进程权限读回拒绝而在开放服务管道前失败。`36f6abd` 补充的实际字段为
  `owner_system=false, owner_admin=true, control=0x9004, exact_aces=true`：访问条目与
  保护标志正确，SCM 创建的 SYSTEM 进程对象由 Administrators 所有。对象所有者与
  主令牌用户不是同一概念；改为接受既有信任边界内的 SYSTEM/Administrators 所有者，
  同时继续独立要求 SYSTEM/session 0 主身份、逐项精确 ACL 与普通客户端危险权限
  拒绝。不能把非 SYSTEM 主身份当作等价服务，后续原生全流程继续验证。

### 2026-10-19：Windows 服务对端原生验收

- `ab812fc970a0289fee0179d8efe0ea78f202ecb5` 的
  [SCM job](https://github.com/billlza/cfw-rs/actions/runs/39178672656/job/117826694754)
  通过九项实际场景：SCM/映像/管道绑定、不同 SYSTEM 服务拒绝、危险 ACL、配置撤销、
  同字节不同文件、服务缺失、普通客户端、服务停止与临时服务删除读回。无调试器或
  IFEO 设置；正常停止同时确认 SCM 与保留的进程退出码为零。
- [下载回执](https://github.com/billlza/cfw-rs/actions/runs/39178672656/artifacts/12155063688)
  已核验源码与 ZIP SHA-256
  `6a624b12a7b300dfdb344b3ee9165d7d8696ea59708e68b64cf9a01b1d1c5f44`。
  客户端实际为中完整性、非管理员；limited-query/synchronize 成功，而内存读写、
  终止、句柄复制、权限修改和 SYSTEM 令牌查询均要求 Access Denied。原始失败产物
  保留；回执仍明确 `full_service_backend_proven=false`、`release_accepted=false`。
- 同一源码的共享 job 通过 481 项 Rust、311 项前端，无失败/忽略/跳过；其中包括
  普通用户不能调用服务进程权限设置的原生反例。Windows 目标 Clippy、本机 12 项
  组件回归、格式与 Windows workflow lint 通过；519 个 registry 包版本/校验值不变。
- 同一源码的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39178672656)
  四项 job 全部完成且通过。引擎仍通过 476 项 Go 测试/子测试、DNS 200 轮专项
  （800 个命名通过事件）及九项原生引擎集成；三个无测试 Go 包仅计编译，未开启 race。
  [引擎产物](https://github.com/billlza/cfw-rs/actions/runs/39178672656/artifacts/12155463108)
  已下载核验源码、WinINet 流量/恢复、复现构建与 77 个身份的 116 个许可证/NOTICE；
  ZIP SHA-256 为 `f45b92f449912b8a98bd7a1376defabaccedcb3a0c2f82a15319c93566c6f247`，
  两个 Go 可执行文件字节与此前已验证产物一致。正式发布许可证审查尚未完成。
- [Mac 供应链 job](https://github.com/billlza/cfw-rs/actions/runs/39178672660/job/117826719356)
  在同一源码检查 328 个可达包，零漏洞/公告警告；cargo-deny 零错误、警告、提示。
  完整 Mac CI 的其他作业尚未完成，不由这一项代替。
- 后续仍需实际服务运行授权、全局生命周期、凭据授权/GC、TUN 与桌面产品接线。
  该服务对端验证不能作为全局 Off、九页视觉一致、安装更新或发布证明。

### 2026-10-19：服务消息通道与固定角色

- `e08eb0d` 修复现有 Windows Go 校验值已加入依赖 pin、但遗漏于封闭构建输入策略的
  不一致。原检查真实拒绝 `GO_WINDOWS_AMD64_SHA256`；补全策略声明、必需键及缺失/
  格式错误/协同删除反例，未改变工具版本或校验值。140 项相关 Python 测试和本机
  build-script-boundary 完整检查通过；此时同源码四项 Windows job 已通过，Mac
  完整 CI 仍运行中，不能替代最终源码检查。
- 产品通道新增固定 Desktop/UserAgent 端点及受信任客户端映像绑定。每条消息同时
  复核管道客户端 PID、保留的进程、映像文件身份、主令牌与消息令牌；角色来自端点，
  SID、logon authentication ID、session、完整性来自内核，不从请求字段采信。
  服务运行授权、租约、凭据范围、全局生命周期仍未接入。
- Windows 消息令牌属于最后读取的消息。已核对固定 Mio 版本会预读下一次原生输入，
  因而该边界使用专用 worker 和原生消息模式，每次完整读取后立即检查身份，不允许
  隐式预读。额外消息是否会改变观察结果由实际排队身份反例验证，不能仅凭设计推断
  声称已经证明此前可利用。新增原生反例的执行结果见下文。
- 每连接只允许一个待回复请求，回复绑定连接与序号；消息上限 1 MiB，连接槽位最多
  15 个，并保留一个新监听实例。客户端只获单独数据/属性/查询权限，无创建额外服务端
  实例权限。I/O/身份/顺序失败使连接失效；取消后等待真实内核完成才能释放缓冲区。
  内核收尾可能超过请求期限，期间不能宣称 worker 已退出，超时命令也不能自动重放。
- 原生夹具保留先前九项检查，新增固定角色、客户端同字节副本、排队消息身份变化、
  超大消息、普通用户创建管道实例拒绝及双向读取超时，共 17 项场景。夹具的两个
  角色分别串行处理连接，槽位饱和暂未原生验证。当前全部 Windows 目标/feature
  Clippy 与本机 12 项组件测试通过。
- `50a3db706a2db87becd28dc5975c9438c87c51e3` 的
  [Windows SCM/消息 job](https://github.com/billlza/cfw-rs/actions/runs/39184109050/job/117842791151)
  实际通过全部 17 项场景。
  [下载产物](https://github.com/billlza/cfw-rs/actions/runs/39184109050/artifacts/12157551861)
  已核验源码及 ZIP SHA-256
  `e03f1e172eb181be62354e2c2c19f2a57b7e9370404aa2699ebca0e5a9521a5f`。
  三份客户端报告分别证明正常 Desktop、普通 UserAgent 权限边界和同字节副本拒绝；
  六份原生记录包含两个角色的映像拒绝、排队消息身份变化、超大消息、服务读取超时
  与客户端关闭。原生连接在异常后继续处理新请求，临时服务最终停止并删除读回。
  该结果不证明旧适配器可利用、全局 Authority、UI、安装或发布；其余同源码 CI 另记。
- 同一源码的 [共享 job](https://github.com/billlza/cfw-rs/actions/runs/39184109050/job/117842790930)
  已完成并从下载日志核验 481 项 Rust 与 311 项前端测试，无失败/忽略/跳过。目录
  持久化 job 同样通过；引擎完整集成与 Mac 回归当时仍在运行。
- 随后该源码的四项 Windows job 全部通过。引擎
  [产物](https://github.com/billlza/cfw-rs/actions/runs/39184109050/artifacts/12157841147)
  下载核验源码、复现构建、九项 Rust 原生集成、476 个 Go 命名测试/子测试和 DNS
  200 轮专项（800 个通过事件）；三个无测试包仅计编译，未开启 race。两个可执行文件
  字节仍与上次核验一致；77 个身份、116 份许可证/NOTICE 校验通过。ZIP SHA-256 为
  `cb72e94ce26eef32e3fbb1a76fed9fcaee833509637c1624357028584a923602`。完整服务恢复、
  发布许可证审查与 Mac 全部 CI 仍未由这些结果关闭。

### 2026-10-19：Windows 当前会话授权（原生验证待完成）

- 新增不可从请求反序列化的原生用户会话，完整保留 SID、logon authentication LUID
  与 session；同账户重新登录不是原租约所有者。Mac 已发布协议的 `owner_uid` 不变。
- SYSTEM 服务从 WTS 查询实际物理控制台、连接状态和用户主令牌，前后复核会话与
  登录身份；权限、WTS 查询失败与登录变化均显式拒绝。令牌不返回客户端、不用于
  impersonation，所有查询句柄由服务关闭。缺少当前控制台不是全局 Off。
- 服务方法分派前检查实际消息对端与当前控制台身份。UserAgent 还必须符合服务持有的
  租约所有者；只有服务选定的连接/绑定观察方法可在无租约时执行，存在其他登录的
  租约仍拒绝。WTS 查询之后重新核验待处理请求/连接/映像，保留原生进程对象；失败
  关闭连接。调用方仍需持有生命周期锁并完成版本化命令、上下文和实际租约状态机。
- 夹具从首个通过授权的 Desktop 建立测试所有者，保留原 17 项并新增当前控制台、
  无租约拒绝、其他所有者拒绝、无租约观察四项；这不等于实现持久化 Authority。
  新增四项 Windows 策略/原生边界测试，Windows 全目标/feature Clippy 已通过；新
  21 项夹具尚未原生执行，RDP、切换用户、注销重登录、锁屏及睡眠唤醒仍需独立验收。
- `c7716ca635f2a3a53ba9d7d7617f4e66e76f6e53` 的独立验证分支
  [Windows job](https://github.com/billlza/cfw-rs/actions/runs/39185572564/job/117847190042)
  执行到第二服务的最后一轮交换时以管道正在关闭（232）失败。
  [失败产物](https://github.com/billlza/cfw-rs/actions/runs/39185572564/artifacts/12157887618)
  已下载核验源码与 SHA-256
  `a54d404c0fa14c07ef6e9eb9cd9aa017480536d2133db764fa0fe5bda4e456b1`。
  普通客户端报告实际通过控制台授权、无租约/其他所有者拒绝及无租约观察；没有完整
  成功回执，不能将这些局部结果代替整组通过。原日志未区分读写，当前保留所有检查并
  新增延迟 200 ms 读取结束回复的反例和读写阶段诊断，共 22 项；先区分回复生命周期
  与接受连接时序，再决定修复。Mac `50a3db7` 全套回归继续运行，未改动或跳过门槛。
- `8d1bd4e400151205c0414ee17f545d0615393b52` 的
  [原生 job](https://github.com/billlza/cfw-rs/actions/runs/39186072952/job/117848953758)
  通过全部 22 项，延迟读取也通过；未更改服务实现，不能因此宣称先前 232 问题已修复。
  [下载回执](https://github.com/billlza/cfw-rs/actions/runs/39186072952/artifacts/12157129988)
  已核验源码与 ZIP SHA-256
  `05d9fb6852108424f8498a37280b845c7593854b56dc0eabf178ce48d0619f6f`，含三份客户端
  报告与八份拒绝记录。当前追加第一服务停止后的 256 轮第二服务连接/交换，并跨越
  空闲监听期限，45 秒循环预算、首个失败即终止且不重放请求，共 23 项；继续定位
  间歇关闭问题。`c7716ca` 的共享日志另核验 485 项 Rust/311 项前端通过且无跳过。
- `818200e9f8001a892718665ff5589a1b23d198f7` 的
  [原生 job](https://github.com/billlza/cfw-rs/actions/runs/39186655503/job/117850668600)
  在第 33 轮（索引 32）首次 ping **写入**复现 232，尚未到该连接的结束回复。
  [失败产物](https://github.com/billlza/cfw-rs/actions/runs/39186655503/artifacts/12157844787)
  已核验源码与 ZIP SHA-256
  `d53347bce2615779835437909df90f54f28a7c9d13e4a7a3ed0518340b1540d3`。
  原实现每次 100 ms 监听等待到期都会取消并释放该管道；客户端恰好连接或内核已
  完成、服务线程晚观察时，仍会关闭客户端已拿到的连接。这是与首次写入失败一致的
  可达竞态，不能靠重放命令或放宽客户端错误检查处理。
- 接受连接改为持久保存原生异步操作：轮询到期仅结束等待，下一轮仍领取同一连接；
  仅成功领取、失败或明确关闭时释放对应实例。`OVERLAPPED` 保持稳定堆地址并用
  `UnsafeCell` 表达内核异步写入；独占对象可跨 worker 转移，不提供共享访问。
  正常退出显式取消并等待真实完成；未能确认紧急回收时不得释放仍可能使用的内存。
  新增实际 Windows 用例覆盖超期观察后继续通信及跨线程取消/回收，原 256 轮与所有
  权限/身份断言保留。`4e34608` 已通过原生验证：运行 `39187827998` 的四项
  Windows job 成功，SCM 23 项场景和全部 256 轮交换通过；共享 Rust 487 项、UI
  311 项通过。下载回执的源身份与哈希核验保存在该工作区的验证目录中。

## SYSTEM 日志锚点存储（2026-10-19）

新增 `PrivateMachineRecord` 作为后续 Authority 日志的独立版本锚点原语。
固定使用 64 位 HKLM 专用命名空间，拒绝模拟身份和非 SYSTEM 进程；检查打开的
注册表句柄的所有者、受保护 DACL 和重定向标记。记录限 2 KiB，类型固定为二进制。
大小写等价的作用域使用同一全局原生互斥锁。CAS 冲突、类型/长度错误、刷新或
回读不确定性均显式失败；只有经过预期值比较的作用域叶子才可删除。

这里存储非秘密的版本元数据，不使用 LSA 私密数据接口。持久发布按必要事务调用
`RegFlushKey`，不能把此开销放在状态轮询或流量更新上。该组件尚未接入完整日志，
不发放运行票据，也不将缺失记录、服务退出或持久化的 Off 当作实际清理完成。

原生 fixture 新增 SYSTEM 写入、跨服务进程退出后的读取/CAS、大小写互斥、损坏
值及不安全 DACL 拒绝、实际非管理员 ACL 拒绝和叶子清理；只操作托管临时 Windows
VM 的唯一测试作用域。`602cec2` 的运行 `39193235468` 四项 Windows job 全部成功：
Rust 488 项、前端 311 项、SCM 30 项场景及 256 轮交换通过。服务产物
`12161090793` 的下载 SHA-256 为
`8f970484e0fa8e2e99c21256fb039a66ae21c0c3bf0f1351f0bdb2855a1e1e14`；
引擎产物 `12160728949` 为
`7ebcde28cc2cb59338d4e10d45f3015ff5fee4f6600eefdb96d322e739120070`。
回执源身份、测试结果、二进制和许可文件均已核验。

`4e34608` 的 Mac 运行 `39188386401` 中 supply-chain 和 quality job 成功，但
Xcode 的 `aProbeOfTheLargestProjectedProfileFitsItsReply` 在 libbox 启动时报错，
后续 analyzer、signer 和打包未运行。错误文本按产品隐私边界被隐藏，现有日志
无法确立根因。仅为该合成配置用例增加原始启动诊断，保持原异常、测试和断言；
此改动不是根因修复，不把旧版 Mac 成功运行替代本次失败。

## Windows Authority 日志与恢复（2026-10-19，原生验证待完成）

新增 Windows 独立版本的日志 schema、CRC/SHA-256 链、持久游标和 pending/committed
锚点。保存 SID 的完整二进制表示、登录 LUID 和 session，不构造 Unix UID，也不从
磁盘反序列化原生身份。记录不包含票据、能力、配置、凭据、端点或秘密字段。
规范编码拒绝未知/重复字段；记录、日志、head 与 anchor 均有边界。

`WindowsAuthorityJournal` 在 SYSTEM 全局互斥锁和已验证的目录事务下恢复与提交。
在写日志之前持久化 pending 锚点，在日志和 head 刷新后提交独立锚点。只有完整且
匹配锚点的临时记录可以继续发布；部分、冲突、回滚、缺失锚点或不明代次均保留并报错。
未发布任何新记录的意图可以撤销。逻辑追加复用私有文件的原子替换，恢复时不调用会
自动丢弃临时文件的通用 replace。压缩只在下一次 prepare 之前发生，保留七条收尾
记录余量，先提交新代次 checkpoint，再验证并清理旧代次。

恢复始终返回核验动作：Off 要重新证明清理；Active 要重新核验所有者；准备、启动和
停止中的记录要求停止所有者。该存储层不发放执行授权；完整 Authority reducer、
运行所有者和操作协议仍待接入。宿主/桌面工厂仍未切换为 Windows backend。

本机新增十项日志/校验测试，连同原十二项组件测试共 22 项通过；Windows 目标严格
Clippy 通过。原生服务 fixture 加入十五个实际持久化边界中断、四种完整/损坏临时文件、
四种身份/回滚情形，以及跨进程退出后的 Active 元数据恢复。压缩使用仅验证特性可用
的小容量构造器，生产默认仍为 4,096 条、32 MiB；不会把这类故障注入当作断电测试。
原生执行与新源提交的 CI 尚待完成。

## 官方资料

以下资料于 2026-10-18 核对；它们说明平台能力，不证明本项目已经实现。

- [Tauri WebView 平台](https://v2.tauri.app/reference/webview-versions/)
- [WinUI 3](https://learn.microsoft.com/en-us/windows/apps/winui/winui3/)
- [Windows App SDK 支持的语言投影](https://learn.microsoft.com/en-us/windows/apps/develop/platform/)
- [Mica 与 Acrylic](https://learn.microsoft.com/en-us/windows/apps/develop/ui/system-backdrops)
- [GitHub runner 类型与资源](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [交互式桌面测试配置](https://learn.microsoft.com/en-us/azure/devops/pipelines/test/ui-testing-considerations?view=azure-devops)
- [Wintun 官方分发与签名边界](https://www.wintun.net/)
- [Windows DPAPI 加密](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [Windows DPAPI 解密](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata)
- [LockFileEx 异步文件锁](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
- [Windows I/O 取消与完成](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations)
- [Go 官方下载元数据](https://go.dev/dl/?mode=json&include=all)
- [Windows CreateFile 访问权限与共享约束](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [Windows accept 继承监听 socket 属性](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept)
- [Windows Credential Manager 写入契约](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew)
- [Credential Manager 记录与持久化范围](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
- [Windows 跨会话内核对象命名空间](https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces)
- [Windows 等待函数与时钟粒度](https://learn.microsoft.com/en-us/windows/win32/sync/wait-functions)
- [Windows 管道客户端进程](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid)
- [Windows 管道消息令牌](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- [恢复线程身份的失败契约](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
- [跨账户进程令牌访问边界](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [Windows 有序 UI 语言](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getuserpreferreduilanguages)
- [Windows 网卡地址观察](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)
- [Windows 地址 DAD 状态](https://learn.microsoft.com/en-us/windows/win32/api/nldef/ne-nldef-nl_dad_state)
- [Windows Wi-Fi SSID 与位置权限](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)
- [WinINet 连接设置与恢复](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)
- [WinINet 默认 LAN 与 RAS 范围](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw)
- [Windows 禁止修改代理的策略](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disableproxychange)
- [SCM 服务访问权限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [SCM 服务状态与 PID 有效范围](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [SCM 配置与下次启动](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- [实际进程映像查询](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)
- [服务终止状态之前完成清理](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus)
- [受限令牌与继承的句柄权限](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [注册表刷新与持久化](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey)
- [注册表叶子删除与访问权限](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletekeyexw)
