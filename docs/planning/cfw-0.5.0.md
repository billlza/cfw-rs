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
- `cfw-core` 的设置、诊断及旧控制会话，和 `cfw-profiles` 的存储路径使用 Unix
  描述符、权限、文件锁及 `openat`/`renameat`。不能通过删除检查或普通路径拼接移植。
- `cfw-platform` 实际仍是 macOS 适配器；`cfw-apple-network` 及 Swift 服务依赖
  Apple 的权限、Keychain、XPC 和 Network Extension。
- `scripts/build_libbox.sh` 通过 `gomobile bind` 生成 Apple/Objective-C 绑定；
  Windows 引擎宿主/绑定也需要实现，不能把共享 Rust 编译通过当成引擎已移植。
- 宿主 `build.rs` 明确拒绝非 `aarch64-apple-darwin`；现有 CI 的三个 job 均为
  `xcode-27`。2026-10-18 仓库 runner API 返回 0 台自托管 runner。

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
| 共享边界 | UI 产品/平台表现、用例与持久化边界；Mac 行为保持回归 | Windows 共享层 290 项 Rust/310 项前端测试已有通过记录；设置、窗口状态和诊断的 Windows 存储已实现，正在运行跨平台回归；配置仓库和完整平台适配尚未完成 |
| Windows 纵向链路 | 真正导入、启动代理、联网、停止恢复；General 与复杂弹窗真实验证 | 待实现和运行；不得用展示壳代替 |
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
  三个 job 仍在排队，不能将本地 Clippy 结果算成该托管运行通过。
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
  修复为公开读、写、删统一拒绝点号开头的内部名称，并预留临时后缀所需长度；保留
  Unicode 名称，增加最大合法长度的实际读写测试。新建目录也刷盘其父目录项；
  本次边界修复正在 Windows CI 中验证，不把此前通过记录套用于尚未运行的代码。
- 新直接依赖复用锁文件已有的 `windows-sys 0.61.2`；注册表包的名称、版本和
  checksum 集合未变化。Mac 依赖策略检查已通过；Windows 完整发布依赖审计仍待建设。
  本阶段没有实现 Windows 配置仓库、
  凭据库、引擎宿主、桌面壳、服务或 TUN，也未作可发布声明。

## 官方资料

以下资料于 2026-10-18 核对；它们说明平台能力，不证明本项目已经实现。

- [Tauri WebView 平台](https://v2.tauri.app/reference/webview-versions/)
- [WinUI 3](https://learn.microsoft.com/en-us/windows/apps/winui/winui3/)
- [Windows App SDK 支持的语言投影](https://learn.microsoft.com/en-us/windows/apps/develop/platform/)
- [Mica 与 Acrylic](https://learn.microsoft.com/en-us/windows/apps/develop/ui/system-backdrops)
- [GitHub runner 类型与资源](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [交互式桌面测试配置](https://learn.microsoft.com/en-us/azure/devops/pipelines/test/ui-testing-considerations?view=azure-devops)
- [Wintun 官方分发与签名边界](https://www.wintun.net/)
