# CFW 0.5.0：CFM GA 对齐与 Windows 发布计划

评估日期：2026-10-18；最近实施检查：2026-10-23。状态：已在托管 Windows
普通输入桌面完成真实 MSI 安装、非管理员九页检查、两种代理的真实流量、
停止／运行中退出恢复及卸载。产品 TUN（SYSTEM 适配器／UserAgent 引擎）已在托管 Windows 的
安装运行与安装 GUI 中验证（含 UserAgent 被终止后的恢复），UI 已开放 TUN；组合模式、完整 UI
对齐、完整更新和发布验收仍开放。

## 当前验收状态

`ca1d120e` 的[真实 GUI 作业](https://github.com/billlza/cfw-rs/actions/runs/39679608563)
和下载产物已独立核验，产物 SHA-256 为
`5dedd92783a2c5071b78f6e91b9bc773fdf3b9c043fb9e0bc334b654a40e1db1`。
三个独立的普通用户进程完成九页与启动项注册／撤销、LocalProxy 的控制器／HTTP／
停止，以及 SystemProxy 的控制器／WinINet 自动代理 HTTP／运行中 Quit。所有保留
进程正常退出码为 0；完整原始代理选项恢复，两个端口均实际返回 10061 且原生监听表
为空，实际 MSI 卸载成功。372 项桌面测试和 5 项更新日志测试通过。该结果不覆盖
实际登录启动、物理显示、完整 GUI 更新、TUN 或最终发布。安装后的官方 Wintun
DLL 字节和 Authenticode 也通过核验。

Wintun 官方 DLL 已纳入 MSI 的固定受保护路径，运行时以编译进二进制的版本和哈希
校验其身份。安装验收包含修改 DLL 内容、放宽普通用户写权限的拒绝和恢复检查。
`cd869aec` 的[共享／原生复验](https://github.com/billlza/cfw-rs/actions/runs/39674124226)
与[桌面复验](https://github.com/billlza/cfw-rs/actions/runs/39673820308)单独记录。
该源码五项共享／原生作业与更新包检查通过；下载的原生引擎产物已核验全部 14 项
引擎测试、恢复／停止检查和十组 MSI 事务，包含新增 DLL 内容及权限反例。实际 GUI
安装后的 DLL 哈希与 Authenticode 也吻合，但 LocalProxy 停止观察遇到后台
`query_status exceeded 2s`，该轮没有完成第二次退出、SystemProxy 或卸载。
代码确认每次查询会重新哈希完整桌面 EXE；后续保留首次验证的不可写／不可删除
文件句柄，每次仍重新核对活进程的文件身份，并增加新旧准入耗时对照。两秒查询期限
和失败处理保持原有要求。`ca1d120e` 完成了上述全部 GUI 流程，未复现超时。
同一源码的[原生引擎重跑](https://github.com/billlza/cfw-rs/actions/runs/39679614806)
产物 `a44cc41cc83380e11d55ba27bb67fa3f80d5007880eee7d35296f9793704a63d`
已独立核验全部 14 项引擎测试、运行时恢复及十组 MSI 事务。安装夹具的三次测量中，
完整哈希／身份校验为 538440–545928 微秒，保留文件的身份核对为 164–181 微秒，
两种检查均成功。该结果证实删除了重复哈希成本，不足以单独确定旧超时的全部因果链。
首次引擎作业在编译前遇到固定 brotli 依赖下载的 HTTP/2 错误，原始失败保留；
同一源码仅重跑该作业一次成功。此前
`b7f61c97` SCM 作业在 generation reservation 阶段出现连接线程 panic，原始原因被
旧夹具的 join 错误处理丢失，失败产物保留。新代码保存 panic 原文，并先报告真实
Authority 拒绝，再检查成功状态；不能用一次后续通过宣称原失败根因已经解决。

驱动加载、适配器和会话管理现已复用为生产代码中的 TUN 基础接口，增加固定容量的
收发环和完整 1280–9000 MTU 范围的数据包校验。托管 CI 新增 Windows UDP 与 Wintun
双向通信探针，使用自己新建适配器上的固定测试地址／单主机路由并要求清理。
`ca1d120e` 的原生驱动产物
`cca325526af14d3bdab27ae8f4621f4e9b7c40e301915bc4c3f6f73bfcea5dfa`
已核验三个 MTU 的真实 IPv4 UDP 请求／不同响应，以及完整数据包、校验和和清理。
IPv6 原生收发尚未验证；顺序创建的适配器出现 LUID 重用，仍须使用创建 GUID 和设备身份。
权限服务、普通权限引擎、持久恢复和真实网络配置
尚未接通，产品 TUN 与组合模式能力保持不可用；不得把这个底层接口当作功能完成。

引擎侧新增实现 sing-tun `Tun` 接口的数据包适配器，仅接收启动方提供的已连接
异步消息管道句柄，不按配置路径打开驱动或管道。单条消息对应一个完整 IP 包，
保持 1280–9000 MTU 范围；没有用户态后台队列，写入背压在五秒期限后明确失败并
关闭该代端点。Windows 原生测试要求双向消息、错误包、截断、阻塞读写取消、背压
超时和跨进程显式句柄继承。`4939feac` 首次运行在端点准入时失败；`8fd07bb9`
保留了原生属性：消息客户端返回 `flags=0x0c`，同时包含消息类型与拒绝远程客户端
位，其余模式、实例数及缓冲区均符合约定。原先精确比较 `0x04` 误拒绝了该合法
端点。后续按已知标志校验，允许附加的远程拒绝位，继续拒绝服务端、字节模式、
非阻塞模式及未知位。`b030334a` 已通过全部九组基础管道原生测试，包含六个
IPv4／IPv6 MTU 子例、真实背压超时、阻塞读写取消和跨进程继承；原始失败仍保留。

后续已接入引擎的首条 `hello` 握手，句柄、适配器名和 MTU 使用独立的严格元数据
对象，不从用户配置路径选取。只有一个匹配的 gVisor TUN 入站可以消费端点；
自动路由、原生 DNS 设置和平台 HTTP 代理由权限服务负责，在该引擎适配层明确拒绝。
没有显式继承端点时不能启动 TUN。gVisor 链路等待接口启动后读包，停止会关闭原生
I/O 并等待读包线程退出；错误包和断连使后续运行观察失败，不返回健康／已停止回执。
新测试要求真实 Windows IPv4／IPv6 UDP 全 MTU 回应、TCP HTTP 转发和 FIN／ACK
退出，覆盖 MTU 1280、1500、9000。Windows 目标交叉编译、Go vet、可移植的实际
控制／探测测试和 12 项构建契约检查已通过。`b030334a` 的转发夹具把回环地址当作
TUN 目的地址，原生 UDP 服务等不到请求；冻结 sing-tun 的过滤器会将此类包原样
送回接口。`502dfaf5` 用文档保留地址配合显式路由到本地真实服务，并新增实际
回环包原样返回的反例，该反例已通过。随后三个 MTU 的真实 IPv4 UDP 回应均到达，
但测试仍在校验和检查失败；`cdb1d348` 的原生诊断证实端口、长度与内容全部匹配，
回应校验和为零。冻结的 UDPBackWriter 在 IPv4 省略校验和，符合
[RFC 768](https://www.rfc-editor.org/info/rfc768/)；修正仅按协议承认这一形式，并
增加错误非零校验和、缺失 IPv6 校验和的拒绝检查。
`3ef9392f` 的[原生作业](https://github.com/billlza/cfw-rs/actions/runs/39692802637)
失败归档 `ea679d1d97ff98b2e4bd66c410585fd63e8dc344908f30656e63cf82393ccfce`
已按源码与摘要核验：504 个 Go 测试事件全部通过，包括三档 MTU 下真实 Windows
IPv4／IPv6 UDP、TCP HTTP、FIN／ACK 与控制停止。800 个 DNS 压力测试事件也通过。
整轮仍因 Rust 集成测试调用私有 `abort` 方法而编译失败，不能算完整原生验收。
`f7072eea` 改为释放公开的进程所有者，继续要求保留进程句柄观察退出及管道断连。
其[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39694496089)五项均通过；
下载的引擎产物 `567b67f144332c38d3d715a0917778d27426db92b0e82cb94a1401831a21be3c`
已按 API 摘要、源码绑定和回执重新核验：504 个 Go 通过事件、800 个 DNS 压力事件、
15 项原生 Rust 用例（含所有者丢失后的进程退出与管道断连）、9 项发布观察、19 项安装
运行检查与十组 MSI 事务。Wintun 归档
`138defb80d879b1ae57cdc0705c3bd2bd08a75634e1349b0573817ce4cc39042` 的 11 项数据包／
策略测试与三档 MTU UDP、SCM 归档的 35 项场景及共享 721 项 Rust／329 项 UI 也已核验。
同一源码的[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39694489366)产物
`39f4bc336af2b285e150d456ebf079c9363f3edf3aa3a350e04fce13c8e33a5a`（372 项桌面、
5 项更新日志测试与三次实际 GUI 会话）及更新包检查同样核验通过。这些 Go 测试没有
接入 Wintun，也未证明普通权限 TUN 运行。

Rust 进程所有者现可消费本进程创建的数据包端点，在挂起创建时加入显式继承列表，
再通过首条握手发送完整 64 位句柄元数据；父进程副本在创建后关闭，环境中其他可继承
句柄不进入子进程。共用的私有管道创建器保留原有启动通道的用户准入约束。数据包
读操作在轮询超时后继续保有原来的缓冲区与 OVERLAPPED，取消后必须等待原生完成，
且不会掩盖已完成的协议错误。新增原生验收要求真实 Go 引擎接收该端点、排除环境
句柄并在退出后关闭客户端；这只验证空闲子进程的本地交接，尚非 SYSTEM 远程授权
或 Rust 启动 TUN 配置。`3ef9392f` 的 Wintun 归档
`56af0175e540caa4033aee6d2eb74a08943cfcb8395ab91e58817a6177a08ef1`
已核验全部 11 项原生数据包／策略测试，包含四项新增异步读操作的超时保留、线程转移、
取消完成与错误保留检查；原有真实驱动生命周期、三档 IPv4 UDP 与清理要求仍通过。

另修正共享配置一直选择 `system` 栈的问题：Windows 后端现从配置生成时选择
`gvisor`，在规范化和两层摘要计算前完成，不修改已授权的配置字节。启动、在线换配置、
切换预检和桌面配置预览使用协调器固定的平台；CFM 的原有配置及摘要保持不变。
旧 Windows 协调器回归已实际失败，修复后 398 项 Rust 契约、6 项桌面配置测试及
Windows 库严格 Clippy 通过。配置检查原生用例保留原有 `system`，同时新增 `gvisor`
检查；这不授予 TUN 启动能力。`307b7c82` 的
[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39695823967)与
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39696997143)均通过，下载产物
已重新核验：引擎 `f002db9b0b3401aea35e3436fb405a26a3a6302b9d86186b13881c3966a9d480`
（四种模式在两种栈下的原生检查、15 项原生 Rust、504 个 Go 通过事件、19 项安装运行
检查与十组 MSI 事务）、Wintun
`c5afc96d64e08cc2c73521099759f91b5930630734d90b74448361ef24709237`、SCM 35 项场景、
共享 724 项 Rust／329 项 UI；桌面产物
`d8fff2b487514d515d0f334db0916af4924c12e84a1e353554b15ceb3b34010a` 中 EXE 为
43,310,592 字节、SHA-256 `c1ac09e1909f7535a76fdd75c8a8c81cd4674b06429549f22a0726c522c466bf`，
372 项桌面、5 项更新日志测试与三次 GUI 会话通过，更新包检查
`21eae6e2549199d440bd001c942b6d29d571eed12312fa4c32c055c8b03da1a9` 通过。两个源码的
引擎宿主字节相同（`f5299a47c2c52c932e7ae6c31e4abc4048cec1bb0980b5cb3c314ac1a3749d79`）。
同一提交的 macOS `CI`（运行 39695823792，`xcode-27`）一直排队；PR 上自 `21505a88`
（2026-10-19）以后的 macOS CI 均在执行前被后续推送取消，没有更新的 Mac 结果。
`1f7bccc1` 的 macOS `CI`（运行 39726455411）中，质量作业实际执行并在
build-script-boundary 失败：`ab6ed3fd` 起 `dependency_pins.env` 的五个 `WINTUN_*`
校验值未在封闭构建输入策略中声明，与 `e08eb0d` 修正的 Go 同类。本地复现该门禁失败，
`f00051fb` 补全策略声明、必需键及缺失／格式错误／协同删除反例，131 项相关测试与本机
build-script-boundary 完整检查通过，变异检查确认新断言有效。本机另通过 ci-no-masking、
证据清单、版本契约、rustfmt，以及除 `cfw-tauri-shell` 外整个工作区的 macOS Clippy
（`-D warnings`）。完整 release-tool 测试在本机 3,655 项中有 31 项因缺少封闭发布环境
（发布账户 home、`CFW_RELEASE_RUST_TOOLCHAIN`、Homebrew Python 为符号链接）失败，
不计为通过或失败。此后多数提交的 macOS CI（如运行 39734543615）在排队中被下一次推送
取消；`3dbe2d59` 的运行 39754658440 实际执行，三项作业分别停在 release-tool 测试、
Rust 目标图公告与 libbox Go 公告（见交接前加固一节）。`39b1440a` 的运行 39770829274
与 `775ad5fe` 的运行 39778207372 中质量作业全部步骤通过：包括 Tauri 外壳在内的整个工作区
macOS Clippy、1,327 项 Rust 测试、329 项 UI 测试、release-tool 测试（3,672 项中 3,671 项
通过，`test_real_pinned_signer_reads_temporary_key_from_dev_fd` 因该作业未安装固定 Tauri
签名器而跳过，不计为通过）以及 shell 语法检查与 ShellCheck；两次的 libbox 作业仍停在
GO-2026-6809，`39b1440a` 的供应链作业仍停在 RUSTSEC-2026-0382（`775ad5fe` 的供应链作业
记录时仍在排队）。自 `21505a88`
以来 libbox 与供应链作业每次都停在公告扫描，Swift 格式与包测试、Xcode 目标测试与
分析、更新签名边界、0.5.0 验证骨架构建和依赖／来源／许可证策略均无结果，完整 Mac
门禁尚无结果。
SYSTEM 到 UserAgent 的数据包端点交接已在 SCM 夹具中原生验证（`9287fb79`），但
Authority wire 中的端点消息与授权代次、SYSTEM 承载的适配器与泵、路由／DNS 所有权及
持久恢复尚未接通；产品 TUN 仍不可用，不能将引擎适配代码、验证夹具或尚未执行的测试
算成功能验收。

另发现并修正一个实际 Windows 产品缺陷：原生准入要求 `experimental` 只含
`clash_api`，而共享投影在有规则集（中国大陆直连、规则提供者）或 fake-IP 时会加入
私有的 `routing-cache.db`。因此开启中国大陆直连后，Windows 的 LocalProxy／
SystemProxy 检查与启动都会被拒；GUI 用例使用默认设置，没有覆盖。新增回归先在旧
实现上实际失败，修正后只接受投影产生的精确形态：固定相对路径（位于引擎私有工作
目录）、与 profile 相同的 `cache_id`，`store_fakeip` 只允许出现在 Tunnel；外来路径、
`..`、其他 `cache_id` 和代理模式的 fake-IP 存储仍被拒绝，变异检查确认各项断言有效。
端到端的中国大陆直连代理需要下载远程规则集，尚未在 Windows 原生执行；另加原生用例，
以无需下载的 fake-IP Tunnel 在同一私有目录两次启停，确认缓存只写入该目录；该用例
已在 `1f7bccc1` 的原生 engine 作业中通过。

`tunnel` 生产模块新增 Wintun 会话与数据包端点之间的双向泵。会话拆分为独占借用的
收、发两半，由两个受作用域约束的工作线程各负责一个方向；一个数据包最长等待 2 秒
（低于引擎自身 5 秒写入期限），系统发送环满时有界重试后失败关闭，不静默丢包。任一
方向失败即取消双方并保留首个失败。正常退役先 `expect_peer_close`，由引擎先关闭自己
的端点再停止；读方向观察到 109／232 后才给出退役证据，并要求服务端句柄是最后引用。
引擎 Go 端另修正一处关闭竞争：写入准入后发生的有意关闭不再记为数据面故障，避免停止
时把自身关闭误报为 `close_failed`，新增的确定性测试在旧实现下失败。共享 Tunnel 请求
现可经检查后的 `prepare_tunnel_data_plane` 准入：只允许一个 gVisor、无 auto_route、
MTU 与地址计划匹配的 `cfw-tunnel` 接口，外加可选的 LAN 监听；TunnelSystemProxy 仍
关闭。引擎进程记录所继承端点的 MTU：Tunnel 配置必须精确匹配，监听型配置不得持有
端点，带端点的进程拒绝候选检查与测速，且拒绝不会结束空闲子进程。验证探针新增
`--engine-forwarding`：在 CI 账户自有的 Wintun 适配器上以 1280／1500／9000 MTU，把
真实 Windows TCP（各 512 KiB 上传／下载，按 nonce 校验）和满 MTU UDP 经泵送入真实
引擎，再经其 SOCKS5 出站到本机私有地址上的固定节点并原路返回；随后在同一地址、路由
和会话下确认没有泵时新连接超时。本地已通过 macOS 测试、格式、Clippy、可移植变异
检查，以及使用官方摘要核对的 1.98.1 Windows 标准库对库、单元测试、集成测试和探针的
交叉 Clippy。`1f7bccc1` 的
[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39726455405)与
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39726453641)七项全部通过，五个
产物均按 API 摘要下载并核验源码绑定与回执：引擎
`5df5096fb109de85e6a70b66db63cc528c5771612f4599971e84a943c78f2523`（505 个 Go 通过
事件含新增关闭竞争用例、19 项原生 Rust 含四项新增准入／缓存用例、19 项安装运行检查、
十组 MSI 事务）、Wintun `d316cadba149d54c436ae1593a9532b5c83c4e4d2305c7e5deba584159412b47`
（30 项数据包测试，其中 16 项泵测试在真实管道上运行）、SCM 35 项场景、共享 749 项
Rust／329 项 UI；桌面 `1a5bc87d8fcab266a02149fded56b2b6df81271422993528116d5b10ebebe27f`
的 EXE 为 43,315,712 字节、SHA-256
`6be065ee7c2b6851fab50fc9b705cd6482c33eb8f122ff7948602a730a336d3c`，372 项桌面、5 项
更新日志测试与三次 GUI 会话通过，更新包检查
`95a5d4ffeb9a0323ed4d9de29b2b048b905d45de7602c34c7720815bf802c1ac` 通过。转发验证
在 31 秒内完成三档 MTU：每档 512 KiB 上传／下载与满 MTU UDP 的哈希、nonce 和目标都
吻合，泵在两个方向都承载了满 MTU 数据包并观察到引擎关闭（109），无泵对照均超时。
适配器的内核接口计数与泵计数逐字节、逐包一致（例如 1500 时 591 个／550,434 字节进入
引擎、687 个／554,512 字节返回系统）。1280／1500 档在 512 KiB 上传时另有 44／18 个
内核 `OutDiscards`（TCP 重传后完成），9000 档为 0：小 MTU 突发下送往引擎方向的吞吐
仍需优化，不能视为性能验收。

`f00051fb` 把转发验证扩展到 IPv6，并按地址族核对证据：
[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39734543611)与
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39734541653)七项全部通过，五个
产物按 API 摘要下载核验：引擎
`cbda0714724d2b55b148a8ac31e95ff218fbedaa76f3a984d2f13de844e15cdf`、Wintun
`f23359d606bfb54fac269a3b1d7ba8462cc02e3c16900f5cd6dfde71282259c0`、SCM
`668808e1f2fe8a3a7e9c5c73f58e588181692455a1dfb9c12d9c7b590ed5bbb3`、桌面
`c568003720e84e2a0019c5129d4db18ad2864f823c61373054eb63beff4d7453`、更新包检查
`543826930ce7a9af8bcde751b8d73f008b9aa548a6f1ccaf179796d518d8f5ba`。各项测试数与
`1f7bccc1` 相同，EXE 仍为 43,315,712 字节（SHA-256
`aeb6c36ddfac2d35c68e336507a09226db8911442d95a1ead40fcac9e7918a49`）。三档 MTU 下
IPv4 与 IPv6 各自完成 512 KiB TCP 双向和满 MTU UDP（IPv6 载荷 MTU−48，不分片），
固定节点按地址族各只看到一次本轮连接与数据报，两个地址族的无泵对照均在 3 秒超时。
适配器接收计数仍与泵送往系统的计数逐包、逐字节一致（例如 1500 时 1,292 个／
1,118,605 字节）。该等式当时由下载后的本地审计逐档核对（审计脚本不在仓库中）；自 `c1785480`
起由验证探针和工作流在每档强制检查。`OutDiscards` 为 58／16／0。
Wintun 适配器初始 IPv6 接口为 MTU 65535、DAD 1 次、路由器发现开启，验证后按原值恢复。

引擎到系统方向现有投递策略（`2c708d2f` 原生验证通过）。`tunnel::DeliveryPolicy`
由所有者按实际分配给适配器的地址构造，IPv4 必有、IPv6 可选；只有目的地址等于适配器
本族地址、源地址为远端可持有的单播地址（排除未指定、环回、链路本地、组播、广播、
IPv4 映射／兼容地址及适配器自身地址），且为不带 IPv4 选项的 TCP／UDP／ICMP 或
ICMPv6（IPv6 最多一个分片头）的包才写入会话。被拒包按目的地址／源地址／协议分类
计数并保留各类首个样本，不结束运行，也不计入送往系统的计数。依据：固定 sing-tun
只代理全局单播目的地，对发往广播、组播或链路本地地址的 Windows 包原样回写，这些
回声由目的地址规则拒绝；拒绝链路本地源地址可阻止引擎伪造路由器通告或重定向来修改
SYSTEM 所有的适配器。验证探针按自身实际分配的地址构造策略，并要求适配器接收计数
等于泵的投递计数、源地址类与协议类拒绝为零。它不涉及 SYSTEM 所有权、TunnelWorker
授权交接、默认路由、DNS、防火墙或持久恢复，产品 TUN 仍不可用。SYSTEM 承载时还须
关闭适配器的路由器发现、DAD、转发、DDNS 注册与 NetBIOS（DHCPv4 默认已关闭），保持
公用网络防火墙配置；`PacketPumpLimits` 按用户决定保持 1280–1500，交接只提供该范围
的端点（数据面与共享设置为 1280–9000）。

`2c708d2f` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39738500584)与
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39738498834)七项全部通过，五个
产物按 API 摘要下载核验：引擎
`0b68364e9cc0537831b90430b802b12d537f491204190e8a149a3539b7b535e9`、Wintun
`5eaa0d67961e5fbee4e459674673ac5099d5d30cdad6ccd0b4019618fd3745fa`、SCM
`5fa6907350c9913633326be818cd58ceb78d25095ec9358224d6c9b70321a4a6`、桌面
`dd99ecf4123d549f673b7b9532af6acfa958e5a16dfce60332d02463eb285240`、更新包检查
`5fbcb09277237fb5e236587c83781ac14894800b7806ac211861f0a1c1021f9f`。EXE 为 43,315,712
字节、SHA-256 `86189d810c5d3f600514104b47adfb4d341e12f156b61c5ec9e384966dcfcccd`，
372 项桌面、5 项更新日志测试与三次 GUI 会话通过；共享 Rust 增至 759 项（新增可移植
测试），UI 329 项，其余测试数不变。
Wintun 作业的数据包测试增至 40 项（新增 8 项策略／头部可移植测试与 2 项泵拒绝测试，
均在 Windows 原生运行）。转发验证三档 MTU 的策略均为 192.0.2.10／2001:db8:1::10：
目的地址类拒绝 37／42／39 个，首个样本在 1280 档是 Windows 自身 DAD 邻居请求
（`::`→`ff02::1:ff90:c7de`）的回声，在 1500／9000 档是 LLMNR 查询（链路本地地址→
`ff02::1:3`）的回声；源地址类与协议类拒绝均为 0。适配器接收计数等于泵的投递计数（1,510／1,274／253 个包），
非单播、丢弃和错误接收增量均为 0。此前这些回声会被写回 Windows 协议栈，其中 DAD
邻居请求的回声可能干扰重复地址检测；现由策略拦截。

## 历史检查点与失败记录

以下保留各源码时点的证据和失败；其中“待完成”描述当时状态，当前结论以上节为准。

此前不含网络操作的 GUI 检查点：集成后 `7190d630` 的
[普通输入桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39620386833)
通过。369 项桌面测试、5 项独立更新日志测试、严格 Clippy，以及同一保留进程
正常退出码 0、实际 MSI 卸载均已从下载产物核验。产物 SHA-256 为
`23e45dc98640c5cc1efadf23443c74b015f1134e7e4aaaf8d61197caafcd3d73`；
EXE 为 43,273,216 字节，SHA-256 为
`86aa85c7cdf7df82b422b754e776ea2a2b540ff0034a89c0708384c0d4a02a43`。
九页中的 Windows 字体、DNS 和启动说明均由实际 WebView2 检查；五个原生呈现
能力仍为 false。未启动网络模式，也未验收真实 GUI 更新或物理显示。

同一源码的[四项共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39621087222)
均通过；该轮运行状态已核对，独立原生回执尚未逐项重新审计。

下一项真实 GUI 验证已接入流水线，原生执行待完成：在九页用例正常退出后，
启动独立的非管理员 GUI 进程，通过实际导入与启停按钮建立 LocalProxy，检查真实
回环 HTTP 转发，再要求 Off、监听端口拒绝连接、同一进程正常退出与 MSI 卸载。
原生探针比较同一用户会话的完整 Windows 代理选项，回执仅记录摘要，避免写出
原始代理／PAC 值。每个 GUI 的进程身份与原有退出期限保持独立；脚本解析与
Rust 格式检查已通过，尚不能据此认定 GUI 网络闭环通过。
`36eb1d35` 的[原生复验](https://github.com/billlza/cfw-rs/actions/runs/39628639554)
通过首个九页／正常退出用例，但第二个 GUI 在 WebView2 已响应时尚未完成
`launch.json` 写入，脚本过早读取失败。归档包含随后写完的启动回执，控制器最终
在原有期限清理失败会话；未执行导入或网络操作，未执行卸载。修正仅调整测试端：
用 `CREATE_SUSPENDED` 创建进程，完成身份校验和同步写入后调用 `ResumeThread`，
并要求返回的原挂起计数恰为 1。启动、恢复、退出仍绑定同一进程对象；原生复验待完成。

另补充真实 GUI 启动注册事务，原生执行待完成：设置页在后台状态读取前显示
“Checking Windows startup registration”，现有截图不足以确定这是持续故障。
用例要求界面与实际注册观察都进入明确状态，再通过可见开关注册、撤销，并核对
保存的偏好与无关偏好未变。失败时分别保留真实引擎和设置 IPC 的结果、拒绝或
超时；没有新增产品重试或把注册成功算成登录启动成功。
`a238506d` 的[原生复验](https://github.com/billlza/cfw-rs/actions/runs/39632409940)
已经观察到挂起创建、发布回执后恢复，以及真实启动项 On／Off 日志和最终原生 Off 状态。
用例随后在读取观察结果时失败：固定版本 Playwright 的 `waitForFunction` 将异步谓词
返回的 Promise 当作真值，可能只读取一次就返回 false。同版本真实 Chrome 已复现该条件；
`9ce3755c` 改为共用显式等待异步读取的观察器，保留错误、整体期限和超时后的停止轮询。
真实浏览器回归已覆盖延迟就绪、读取拒绝、非法结果及在途请求超时；完整 Windows GUI
复验待完成。该失败没有证明应用启动项卡住，也没有执行网络用例或卸载。

`9ce3755c` 的[原生复验](https://github.com/billlza/cfw-rs/actions/runs/39637627650)
已通过九页、真实启动项注册／撤销和首个 GUI 正常退出；第二个 GUI 完成配置导入、
启动 LocalProxy、实际 HTTP 转发，且转发前后完整用户代理选项不变。停止操作返回 Off，
但两秒端口探测超时，因此监听释放、第二个 GUI 正常退出和卸载仍未验收。失败归档
SHA-256 为 `c7ac4cb95a942569de542e0f861625db900cc6349e8f801d39c648b6e2286c3f`。
同一源码的四项共享／原生作业及独立更新包检查通过。

该轮还暴露实际产品缺陷：端点绑定、控制器命令与托盘仍使用 macOS owner 判断，
拒绝已就绪的 Windows UserAgent。现在协调器构造时固定后端平台，actor 与桌面消费者
使用同一值，并共用模式、owner、就绪、generation 与 digest 校验；订阅下载及流连接
也使用该平台。两个 Windows 回归在旧实现失败，修复后本机 586 项桌面测试和 116 项
协调器测试、严格 Clippy 通过。GUI 用例新增实际控制器版本、节点、连接与规则读取。
端口探针新增原生监听表和已知监听器关闭后的对照，保留原两秒失败，不将超时算作释放。
这些修改的 Windows 原生复验待完成，尚不能认定 GUI 网络闭环通过。

`43695991` 的[原生复验](https://github.com/billlza/cfw-rs/actions/runs/39643656672)
已通过完整桌面编译、严格检查、372 项桌面测试及 5 项更新日志测试。实际 GUI 的
控制器命令完成读取，节点页已显示 direct 与 Rule，旧绑定错误未再出现；但新增
验收脚本将模式限定为小写，与固定引擎的默认 `Rule` 契约冲突，内容检查失败。
该轮没有保存原始控制器响应，也没有执行 HTTP／停止端口探测或卸载。脚本现要求
首启的确切 `Rule`，逐字段报告检查失败，并在失败采集中保留真实控制器观察。
失败归档 SHA-256 为 `46171e06339b3de6785f281798e9d4c6cfe13fdbea90939842bdc942dbc73772`；
不能将实际节点显示提升为完整 GUI 网络验收。四项共享／原生作业和独立更新包作业通过。

同一轮真实页面还暴露 Windows TUN 提示误用 macOS System Extension 授权说明。
现已从现有平台呈现模块选择本机对应的 TUN 帮助及能力不可用说明，四种语言保持完整，
不改变模式能力。旧渲染回归已复现；329 项 UI 测试和 10 项平台／语言测试通过。
实际安装页面用例增加帮助弹窗检查，原生验证待完成。
实际空配置页中的“迁移旧订阅”也仍指向 Mac 历史数据。Windows 现隐藏该入口，
预览和提交命令在读取文件或取得迁移租约前明确拒绝；普通文件及订阅导入保留。
旧渲染回归已复现，新 UI 329 项、Mac 迁移 13 项及严格 Clippy 通过。安装后用例
将直接验证两个命令都因平台不适用而拒绝，Windows 原生复验待完成。

`fbe38f05` 的 GUI 复验在新增帮助检查处失败：实际弹窗的可访问名称为 `Info`，
内部标题为 `TUN Mode`，Windows 帮助文字已正确显示；测试误将标题当作弹窗名称。
现按真实角色名称和标题共同定位，没有改动产品语义。本轮未执行启动项和网络用例，
也未卸载；归档 SHA-256 为 `325b8aa080b5bfc5d606cb69e9cb9bd9d7f8b82c8e3fe759ceeb592ed5ff83f5`。
同一源码的独立引擎作业为 13 通过／1 失败：系统代理夹具接受的首条上游请求不符合
专用探测的 CONNECT，旧日志没有保存请求内容，来源未确认。失败后的精确代理恢复和
引擎停止均返回成功，但不能将该轮算成原生套件通过。夹具现仅将专用保留地址
`192.0.2.123/32` 路由至测试上游，其余目的地使用 DIRECT；CONNECT、GET、响应正文、
冲突保护、恢复和退出断言不变，并记录意外请求的方法类别与首行摘要。新配置形状已
经过实际共享解析器和投影验证；原生复验待完成，未将来源未知归因为已确认的背景流量。

引擎许可交付另补充一个实际产物缺口：旧归档仅收集模块源码许可，遗漏内嵌 Wintun
预编译 DLL 的官方许可；实际 MSI 也未携带引擎许可。已逐字节核对固定依赖内四种架构
DLL 与官方 0.14.1 归档相同。新构建校验实际链接 x64 DLL 的摘要，保留原始许可字节，
生成包含全部引擎许可及索引的 `EngineThirdPartyNotices.zip` 安装载荷，并要求安装后
文件大小／摘要一致。12 项脚本测试、PowerShell 解析和 WiX XML 解析通过。
`43695991` 已完成原生构建、WiX 打包及安装后读回：80 个组件、119 份原始许可文件，
安装归档 194,241 字节，SHA-256 为
`e492da8e0ba9b37c1548ebcf0a5f47c67ae4caa7e8479658276665d24f3ed490`。
下载产物已逐项核对归档成员、原始许可字节及 Git 固定的 Wintun DLL／许可摘要。
这些字节证据不代替 Authenticode、驱动运行或最终许可审阅。

此前 `60dc9a51` 对照相对 `5a45a01f` 只修改测试端的桌面选择，应用代码完全一致。隔离窗口站
运行仍未正常退出，普通 WinSta0/Default 输入桌面则通过；成功路径没有注入绘制
消息或强杀。测试现在只读取并选择启动进程使用的普通输入桌面，保持原有非管理员
令牌、进程身份、期限与退出码要求。调整已合入开发分支，集成后验证见本节开头。
失败后的实验性绘制探针已从当前测试入口移除，其源码与失败回执留在历史提交和
验证目录中；正常等待继续直接使用保留进程对象和原有 180 秒上限。

成功产物审计还发现空 `git diff` 经 PowerShell 管道时没有创建差异文件。已逐字节
核对归档内全部已跟踪 schema 与该 Git 提交完全相同，状态只有未跟踪的 Windows
schema；后续流水线显式写出空文件。审计同时按 BOM 严格解码 MSI 的 UTF-16 日志，
保留此前两次审计脚本失败记录；没有跳过源码、进程退出或卸载检查。

此前 GUI 检查点：`918fec8f` 的
[真实桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39596494496)
完成全部九页导航、截图及真实只读 IPC，下载的源码绑定产物与截图已核验。正常
Quit 未产生进程退出，卸载未执行。`36fe5a0e` 的
[诊断复验](https://github.com/billlza/cfw-rs/actions/runs/39602725518)进一步证明
窗口状态保存、引擎关闭、退出分发均已完成，ExitRequested 收到 `ready=true`，
但仍未记录 Exit。`5acc39e5` 的
[CDP 对照试验](https://github.com/billlza/cfw-rs/actions/runs/39608457010)确认单独
断开调试连接后精确 GUI 进程仍在运行；真实点击 Quit 并再次断开后，正常退出
仍失败。因此这次失败不能归因于持续附着的调试连接。原生产物 SHA-256 为
`119c9ca11e0849b936fffcf79b701b1a3b4ea91347f0097f990167df889e622d`，
退出阶段仍停在 `exit_requested ready=true`。

后续诊断在 Windows 退出插件之前增加观察点，并在正常 Quit 已失败后，向保留
进程的精确主线程中唯一的 `Tao Thread Event Target` 投递一次 WM_PAINT。固定
Tao 0.37.1 的退出路径要求事件循环回到 Idle，而绘制事件负责该状态推进；当前
测试使用私有非交互窗口站。该试验用于区分消息推进问题与插件阻塞；原生执行
没有枚举到目标窗口，未实际投递绘制消息。因此具体 WM_PAINT 机制仍未证明，
失败记录保留，不能将普通输入桌面的成功解释成这项诊断成功。
`25aae512` 首轮整包编译因新增插件未显式指定配置类型而失败，未执行 GUI；
`5a45a01f` 明确使用单元配置类型，Windows 整包编译及严格检查已通过，
[隔离桌面试验](https://github.com/billlza/cfw-rs/actions/runs/39615528385)未通过正常退出。
另以相同应用代码、仅改变 fixture 桌面选择的 `60dc9a51` 执行
[普通输入桌面对照](https://github.com/billlza/cfw-rs/actions/runs/39616448575)。
该分支只读取 WinSta0/Default 和输入桌面信息，不修改现有用户对象权限或切换桌面；
其成功回执、审计与集成状态见本节开头。

截图另发现 Feedback 错用 Mac 的 launchd 字段，Windows 启动说明为空，已修正为
实际 startup_strategy；旧渲染器回归失败，修正后的 327 项 UI 测试通过。设置页
随后修正 Windows 字体与 DNS 说明：共享存储明确接受 Segoe UI/Consolas，Windows
使用自身字体配置，已有合法选择不被重写，Mac 原有字体仍保留；DNS 说明不再指向
macOS 或不存在的旧 Windows 版本。旧渲染器和旧存储的目标回归均失败，修正后
328 项 UI 与 27 项设置相关 Rust 测试通过；实际 Windows 页面已在上述 GUI 作业复验。
自动化设置另修正一条真实调用路径：Windows 的 SSID 观察被拒绝时，后端返回
`network=null` 和错误，旧界面因此隐藏了已有的 Windows 位置设置入口。现在保留
错误并展示该入口，成功调用后的提示、快捷键示例和四种语言使用对应平台文字；
不会把设置页打开当作权限已获准或网络观察已恢复。旧界面目标回归失败，修改后
完整 329 项 UI 测试通过。该权限流程尚无真实 Wi-Fi 设备验证。

当前安装里程碑：`41f5722a2f32f1537125059f43cb2919b4495822` 的
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39581667052)
生成 28,188,672 字节的真实桌面 MSI，SHA-256 为
`b33cc27ca39025636ad9cfb0592680ac955afd649db5f729d024574be4bf5457`。
包包含实际 CFW 桌面、runtime 和 GA 来源引擎；WiX 编译、ICE 验证和 warning 检查
通过。MSI 安装返回 0，原生入口验证精确安装清单，SYSTEM 动作将自动启动服务带到
Off；实际安装目录中的桌面以中等完整性且非管理员令牌启动，文件哈希和进程身份
已核验。该源码仍通过 369 项桌面、5 项独立更新日志测试及严格 Clippy。

GUI 作业随后在读取 WebView2 元数据时触发单次 2 秒 HTTP 超时。没有页面截图、
正常退出或卸载通过的证据；控制器在原有 180 秒期限结束后清理该测试进程。
产物及原生回执已下载核验。后续将只在原有启动预算内重试连接拒绝和 HttpClient
自身超时，HTTP 鉴权、协议或 JSON 错误仍立即失败；每次观察和失败时的应用日志
均保留。真实回环 HTTP 验证已观察旧流程因首次超时失败、新流程通过；四项边界
测试覆盖恢复、拒绝连接期限、HTTP 401 和损坏元数据。`7db5a873` 的 Windows
原生复验已通过这四项检查，并取得真实 GUI 的 WebView2 调试元数据。随后测试
脚本将两个 Node 路径当作一个命令，尚未进入页面验收；`56505c01` 修正为选择
PATH 中第一个可执行文件并验证固定版本，本地双 Node 路径反例与版本拒绝均已检查。
`56505c01` 的原生作业进一步确认固定 Node、真实 WebView2 连接和应用自身的
`renderer_ready` 事件；页面脚本随后等待不存在的 `#product-name` 而超时。
`1f765d58` 改为等待共享页面实际存在的导航项，保留来自真实 `boot_payload` 的
产品身份断言。该批同时修正 Windows 更新提示、启动与诊断文案，四种语言齐备；
旧实现的四个反例均失败，修正后的完整 325 项 UI 测试及固定依赖检查通过。
该阶段尚无页面证据；后续九页观察和未通过的退出见上面的最新检查点。

同一源码的独立包检查在取消校验进程后未通过即时退出断言，原断言没有留下进程
角色或实际返回值；后续 64 次即时退出试验在 `7db5a873` 明确观察到子进程仍活着。
独立诊断分支 `9ab3601a` 的
[原生试验](https://github.com/billlza/cfw-rs/actions/runs/39593361855)在第 45 次
观察中确认该子进程属于自有 Job；清理成功、Job 计数为零，但保留的进程句柄
仍返回 WAIT_TIMEOUT，确认了计数与退出信号的差距。最初仅在清理前收集句柄的
修正被正常签名包用例拒绝：它漏掉了此前已离开的成员。最终修正从根进程仍挂起时
开始保留成员句柄，在请求期间持续补充，并在原有清理期限内等待实际退出；累计
进程数不匹配仍明确失败。`c9a2b39c` 的
[原生复验](https://github.com/billlza/cfw-rs/actions/runs/39595480096)及下载产物审计
通过：9 项包检查、5 项已安装 worker 检查、8 项传输检查、28 个签名样本，包含
两组各 64 次即时退出试验、真实漏观测反例和普通用户 worker。该作业的 engine
源码与产品分支 `918fec8f` 一致；桌面作业独立执行，没有将跳过视为通过。
没有放宽产品清理、超时或原断言。

[组件作业](https://github.com/billlza/cfw-rs/actions/runs/39581672551)再次复现的
LocalProxy 服务重启期间查询进程映像访问拒绝，已由 `43576a47` 的
[原生观察](https://github.com/billlza/cfw-rs/actions/runs/39597750456)定位：精确旧
服务已返回注入退出码 `0xcf01` 和非零退出 FILETIME，但两次保留句柄等待仍未有
退出信号。`7a5153d1` 将有这组证据的拒绝分类为 TerminationPending，不把它当作
已退出、清理成功或有权重连；活进程权限拒绝仍原样失败。`36fe5a0e` 的
[四项原生/共享作业](https://github.com/billlza/cfw-rs/actions/runs/39602734853)
通过，下载的完整运行时、pending-stop 和十次 MSI 事务回执均通过原有审计。
该成功运行没有直接记录到 TerminationPending 样本，不能替代特定竞态分支的
现场证据。GUI 退出仍失败，不能称当前 Windows 工作流全绿或发布已验收。

前一个完整组件检查点：`fafb7f00890c5d226090e688730d6f04a6407df4` 的
[桌面与包检查](https://github.com/billlza/cfw-rs/actions/runs/39573490356)和
[Windows 共享与原生检查](https://github.com/billlza/cfw-rs/actions/runs/39573492636)
通过。真实 x64 `Clash for Windows.exe` 为 43,200,000 字节，SHA-256 为
`a6c732f72796b3e18d9a182016996bd372da783fc24691f9861b81abe916595c`。
它具有 CFW 0.5.0 的 Windows 版本资源；三个实际启动拒绝用例、368 项桌面测试和
4 项独立更新日志/进程租约测试通过。共享作业通过 710 项 Rust、321 项 UI 测试；
原生组件通过 480 项 Go、14 项引擎、35 项 SCM、15 项诊断测试和 10 次 MSI 事务。
这些 MSI 的桌面仍是认证测试客户端；以上结果不包含交互式 GUI 或真实桌面安装。
独立的通用 `CI` 作业未返回通过结果，不能称全仓 CI 已通过。

后续修正了真实 MSI 与 GUI 更新日志的架构字段错配：Windows Installer 使用
`x64`，安装清单使用 `x86_64`。日志现在接受原生包检查的 `x64`，并有错误标签反例。
Windows 库/二进制交叉 Clippy 通过；原生日志测试交给托管 Windows 作业。

真实桌面的开发 MSI 与 GUI 验证流程已经接入。真实包和负例包复用一份 WiX 载荷、ACL、
清单绑定器和事务动作；真实包包含正确产品元数据，服务自动启动，不包含 fixture
故障注入或可选维护开关。当前同包修复未验收，明确拒绝；开发构建号不代表生产分配。
托管验证将安装实际桌面、以中等完整性且非管理员令牌运行，通过 Playwright CLI
连接其 WebView2 检查九个页面、真实只读 IPC、界面退出及卸载，并保存截图和原生
进程回执。调试端点只存在于测试进程环境，不增加产品测试入口。原生构建和安装已执行，界面验证仍未通过；本机完整 MSVC example 检查仍被缺失
Windows SDK 的 `assert.h` 阻断，不能
视为 Rust 编译通过。开发包未签名；真实显示、网络模式、完整更新和发布仍是开放项。

首轮真实桌面安装流程 `312e6653` 在
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39579956427)的引擎构建前失败：
严格的源码洁净检查发现桌面构建后的工作区变化；安装包和 GUI 尚未执行。固定依赖
tauri-build 2.7.0 的构建路径调用 schema 生成器，Windows 目标会在源码目录生成尚未
跟踪的 `gen/schemas/windows-schema.json`，并可能更新通用 schema。首轮没有保存
`git status`，不能断言没有其他变化。流程现改为在桌面生成步骤前构建引擎，保留
原有完整洁净检查；桌面构建后保存状态、schema 和差异，并拒绝 schema 输出之外
的任何源码变化。失败日志、带哈希的产物及未执行阶段继续保留。

以下保留各历史检查点及失败因果；其中编译错误数量、fixture 范围和未生成 EXE
等描述只适用于各段注明的源码，不覆盖上面的当前检查点。

Windows 版本范围（用户于 2026-10-20 澄清）：这是原 CFW 停止维护后，本项目以
Rust 重构的首个 Windows 大版本，目前没有可指认的本项目旧 Windows 构建。
因此不建立假定的旧服务/目录/协议兼容关系，也不移植 CFM 0.3–0.4 的 macOS
退役交接作为 Windows 发布前置条件。保留标准配置导入；若未来明确提出旧 CFW
格式兼容，按真实样本另行验证。CFM 0.5.0 的不可变清单仍完整保留，其中 Apple
服务退役命令标为平台不适用，不能算作 Windows 网络恢复或安装更新已完成。
当前 Windows 启动解析拒绝 CFM 交接、Apple 服务维护和 Apple 物理证据参数，
在任何启动 I/O 之前报错；常规 dashboard 与精确的更新事务入口仍保留。共享 UI
的历史维护状态现在按平台校验，Windows 明确返回 `not_applicable`；Mac 的交接
命令、启动预检及交接生命周期仅在 Mac 编译。共享引擎仍使用原有 Windows
Authority 和协调器，历史维护不适用不能替代网络权限或停止证明。不能由这次
拆分推出完整应用已经可构建。

进程观察已从旧维护模块提取：Mac 保留原有 UID/PID/启动时间格式及全部原生测试；
Windows 保存完整 SID、登录标识、会话、FILETIME 与令牌属性，通过保留的原生
进程对象重新观察。访问拒绝仍是错误。按可执行文件限定的观察不能证明其他登录会话没有
进程，也不能代替安装包签名或映像字节验证。新增原生测试覆盖实际 Unicode 路径
子进程、退出、身份变更和数量上限；已安装客户端场景还会验证中等完整性、非管理员
上下文中的实际应用模块。`6febe7448de0eed1c9726cec7c3c5f4d9a241be2` 的
[Windows 桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39419495813)
已执行 4 项实际进程测试及 2 项观察权限回归，Clippy 禁止 warning；中等完整性
客户端随后在实际进程观察处报“身份数据无效”，完整引擎作业失败。该失败不能被
较高权限下的测试通过覆盖。独立的中等完整性进程用例进一步定位到 WTS 某条进程
记录没有返回 SID；进一步读取该进程也被拒绝。因此已移除会话全表枚举，改用
Restart Manager 查询指定可执行文件的使用者，再通过原生句柄核对启动 FILETIME、
SID、登录及会话。仅允许有界的缓冲区扩容，访问/注册表错误仍失败，不调用停止或
重启 API。`2b0410c4ce0a0b8c85846686239d2db594db1b7d` 的
[原生桌面复验](https://github.com/billlza/cfw-rs/actions/runs/39426094787)
通过 7 项进程/观察测试，并从实际中等完整性、非管理员进程返回完整原生身份核验
回执；产物源码和 SHA-256 已核验。后续 `c6f3739` 也通过完整已安装服务/Agent
场景（证据见下）；失败的 WTS 方案及回执保留在 Git 和验证记录中。48 项存储、4 项启动和 1 项产品身份
测试也通过，产物源码及 SHA-256 已核验。

该源码的完整应用仍有 54 个编译错误和 1 个 warning，没有生成 GUI EXE。与上一
源码逐项比较，70 个原错误消除，53 个原错误仍在；另一个错误来自本批 Mac 条件
编译误包含了共用 IPC 分支，现已改为 Mac 拒绝路径提前返回，共用启动就绪校验和
命令分发保留在所有平台。旧偏好导入的重导出也已限定为 Mac，消除新增未使用
导入。修正源码 `4d20ef8e38cc777bb09568f398c3b48a8d3c3677` 的
[原生整包复验](https://github.com/billlza/cfw-rs/actions/runs/39421090171)
确认剩余 53 个错误、零 warning，尚无 GUI EXE；更新器、登录启动、诊断及原生
呈现仍须继续完成。

`c6f3739` 的桌面作业在既有存储并发测试中遇到一次 `Busy`：错误来自有界的锁等待，
发生在事务取得之前；同一源码的另一项 Windows 共享作业通过。失败日志没有给出
持锁时序，不能据此判断慢 I/O 或调度的占比。并发计数测试现仅在事务取得阶段对
`Busy` 最多尝试三次，仍要求两线程完成全部 32 次写入，任何读写错误仍失败；
产品三秒锁期限、超时测试及排队进展测试没有改变。`b094756` 的
[原生复验](https://github.com/billlza/cfw-rs/actions/runs/39429325486)通过全部
48 项存储测试、4 项启动、1 项产品身份、7 项进程/观察测试及独立普通用户观察。
整包仍为 53 个既有错误、零 warning；产物 `12268001518` 已核验，没有生成 EXE。

Windows 更新采用 MSI 安装事务；Mac `.app` 原子交换与 Apple 服务维护不作为
Windows 替代实现。首批 `update_package` 原生接口在解析数据库前调用 WinTrust，
提取可信签名者的 SPKI SHA-256，并要求与调用方实际观察的发布者密钥相同；同名证书
不等于同一发布者。版本、递增构建号、产品/包/升级标识、x64、最低系统版本、系统级
安装和禁止 Restart Manager 自动关闭程序均须校验。沿用原有文件及父目录句柄保留
机制，校验期间禁止数据写入或路径替换。该接口只观察包，不授予安装或停服务权限；
调用方仍须验证 Minisign、发布渠道、已安装构建及系统版本。签名联网验证须放入
有时限的独立工作进程；发布者密钥轮换不能退化成只比较证书主题。

`4485723df368ee94232daf9cdd38a7f6b01cb8d7` 的
[独立原生 MSI 作业](https://github.com/billlza/cfw-rs/actions/runs/39446635424/job/118710789011)
通过 8 项 Rust 集成测试和禁止 warning 的 Clippy，覆盖 23 个签名样本，以及
同名异钥、不可信、篡改签名、产品/版本/平台反例和实际文件替换限制。测试从经过
WiX 编译、ICE 验证和 Windows 验签的完整测试包派生，使用三把临时密钥；临时
机器信任仅限明确授权的可丢弃管理员 runner，证书和私钥删除回执已核验。产物
`12275972802` 的源码、文件集及 SHA-256
`19ad5779ef07468f6fe6c3d88fb8f8f08bec47275e61ef2c23bbcad475db3359`
已审计。本地 Windows 库交叉 Clippy、Mac 引擎全目标 Clippy、格式及 PowerShell
语法检查通过。

此前最小数据库的签名失败保留：CryptUI/SignTool、ASCII/Unicode 路径四种组合
均被 Windows 以 `TRUST_E_BAD_DIGEST` 拒绝；独立内容/元数据摘要及原始 RSA
核验相符，不能代替 Windows 信任结果。同一证书、runner 和工具签署的完整 WiX
包通过，后续测试采用完整包。Windows 对最小数据库拒绝的精确内部条件仍未确定。
另一个已复现的 fixture 错误来自直接把 `Join-Path` 的 `PSObject` 传给 COM，
现于字符串边界转换后通过。原生测试断言及产品验签要求未放宽。

这些 MSI 是测试包，从未安装，不包含完整 CFW 产品，也不使用生产发布者证书。
MSI 编排、内嵌载荷完整性、服务停止/安装/回滚和完整桌面调用链仍待实现，
不能由包校验接口通过推出整包构建或更新已经完成。
同一源码的独立桌面作业通过 48 项存储、4 项启动、1 项产品、7 项进程检查及
非管理员观察；整包仍有 53 个编译错误、零 warning。桌面产物 `12276792626`
已核验，尚无 GUI EXE。

后续更新校验进程已实现并通过首批原生测试：固定安装目录中的现有 runtime 增加
`--inspect-update` 只读入口，使用原有挂起创建、显式 stdio 句柄继承和创建时 Job
归属；请求/响应分别限于 16 KiB/4 KiB，路径不进入命令行。父进程持有候选包、
安装清单及发布者映像，核对实际子进程身份、请求标识、进程退出与输出；取消或
超时终止其独立 Job，结果须等进程、后代和管道线程实际退出。该入口不启动服务，
不提升权限，也不安装。校验能力只由受保护的 `InstalledRuntime` 构造；任意路径
加调用方自报哈希不能构造发布者或安装授权。

安装清单更新为 `runtime-installation-v2.json`，包含正构建号及不同的 ProductCode/
PackageCode，并拒绝缺字段、旧 schema、非规范 GUID 和升级标识复用。Windows
桌面更新准入开始从这个原生边界读取版本，不再使用 UID 或 `/Applications`。
现有服务 fixture 同步检查这些反例；没有历史 Windows 发布，故不增加 v1 回退。
托管包校验作业新增真实安装路径的工作进程、Unicode MSI、验签失败分类、文件
保留、超时、取消、异常输出和后代清理测试，临时安装目录必须清理。该目录包含
测试 Desktop/Engine，只验证工作进程边界，不是产品 MSI 安装验收。本地 Windows
库及 runtime 交叉 Clippy、Mac 全目标 Clippy、119 项更新器回归和清单测试通过；
`25d2b00957e1f1013395abacb77abfc4aa7ef1e5` 的
[Windows 原生校验](https://github.com/billlza/cfw-rs/actions/runs/39458101777/job/118750136012)
通过 8 项包测试、5 项已安装工作进程测试和 6 项进程通信/清理测试。产物
`12280239992`（SHA-256
`fd319bcf98135ff0f6b7b630e259d94eb6b540ebf7324033167a899e68a5f138`）
的源码、27 个文件、runtime/发布者/engine fixture 字节身份和清理回执均已核验。
同源码完整桌面仍失败，编译错误为 44 项、零 warning，产物 `12282495017`
已核验，没有生成 GUI EXE。

普通权限下的工作进程补验已通过：复用已有中等完整性、禁用
管理员组的测试宿主，在受保护的已安装 Desktop 映像内核对实际进程身份，验证
有效 MSI、异钥拒绝、取消及清单写入被拒绝；不注册或启动服务。阻塞写入测试也
补充实际管道容量观察，避免把系统默认容量当作固定常数。
`08d5d5c517e33217919bb3fd67c67e1d1f226e50` 的
[原生校验](https://github.com/billlza/cfw-rs/actions/runs/39459886477/job/118756283498)
执行上述普通用户场景及全部 19 项测试。产物 `12281883404`（SHA-256
`dacba21f2acbe7ebcf1f40b45511abfa36f0bfbbf3ebb20b91901ccd9cbbd0e4`）
的 28 个文件、发布者公钥摘要、源身份和清理回执已核验。同源
[完整组件作业](https://github.com/billlza/cfw-rs/actions/runs/39459892466)
四项通过：661 项 Rust、314 项 UI、14 项原生引擎、35 项 SCM 和 480 个 Go pass
events；engine `12283900409` 与 SCM `12281539927` 的源码、摘要及回执均已核验。
完整桌面仍为 44 项编译错误、零 warning，没有 GUI EXE。

下载暂存随后加入 Windows 流式发布路径：使用现有私有目录、排他临时文件与
相对句柄操作，分块容量超限或写入失败后不能再发布；完整 Minisign 校验成功后
才执行不覆盖目标的原子重命名。取消和作用域退出清理自己创建的文件对象，同名
替换文件保持不变；发布后的目录刷新失败明确报告持久化不确定。已有 Mac 实现
保留。`1b0d796e1445ad3df7312729d49f0c20a6b7eddc` 的
[Windows 作业](https://github.com/billlza/cfw-rs/actions/runs/39464890047)
通过全部 54 项存储测试，新增六项覆盖排他访问、容量、冲突、改名后的清理、刷新
失败及 Drop；产物 `12285425208` 的源码、摘要、完整文件集与测试结果已核验。
独立 MSI/工作进程的 19 项测试及普通用户场景同样通过，产物 `12283808968`
已核验。后续 settings/profile 类型检查因两个错误映射未覆盖新增
`IncompleteStream` 而失败，未进入完整应用检查；两处显式映射现已补齐，
`cfw-core` 与 `cfw-profiles` 的 Windows 全目标交叉 Clippy 通过。
修正后的 `6d00580d81bfc9a673f2795f506184e38816623e`
[原生桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39467252785)
通过上述 54 项存储及 19 项 MSI/工作进程检查，完整桌面编译剩 42 项错误、
零 warning，仍无 GUI EXE。产物 `12286275626`、`12286260428` 已核验。
同源[组件作业](https://github.com/billlza/cfw-rs/actions/runs/39467264909)
共享检查通过 667 项 Rust 和 314 项 UI；engine 首次在已安装后端的凭据准备中
发生 `GlobalAuthorityTimeout`。失败产物 `12286335405` 保留，不能从该次失败
证明全局 Off。仅对失败作业进行一次同源复验，原有超时和断言均不变，复验通过
14 项原生引擎测试和 480 个 Go pass events；engine `12287676507` 与
SCM `12285008710` 的源码、摘要及回执已核验。首次超时的具体 Authority
调用和原因仍未知，后一次通过不代表根因已解决。

Windows MSI 暂存新增 `UpdateStaging`：使用私有 `updates-msi-v1/<UUID>`，
生命周期持有父目录写租约，下载、校验和等待安装期间阻止另一个进程进行恢复清理。
目录内保留独立文件事务，不执行 `.app` 解包或同卷交换。清理核对目录文件身份，
最多枚举 64 个事务、每个最多 8 项；未知事务名、真实子目录、访问失败和活动
写入不会被当作空目录。链接仅删除其本身，失败保留部分清理和刷新不确定性。
新增真实文件测试覆盖目录替换、链接、容量、进程退出残留及租约释放；
已安装 MSI 校验夹具也接入私有流式复制与显式清理，包括普通权限 Desktop。
`3e5bca67fa41befbef8ca108261b79a99bf0ec91` 的
[MSI 校验作业](https://github.com/billlza/cfw-rs/actions/runs/39475120492/job/118808970542)
通过 19 项测试及普通用户场景，产物 `12289127497` 的源码、摘要、签名公钥、
私有暂存与清理回执已核验。目录测试首轮五项通过，一项在设置替换路径时因
活动租约阻止父目录重命名而失败，未进入清理逻辑；失败产物 `12289187043`
保留。修正夹具先核验持锁时重命名被拒绝，再释放租约、强制完成路径替换，
随后通过保留句柄取得租约，核对创建与清理不影响替换路径；产品边界和断言不放宽。
修正后的 `5850f050a4e939bc35715d133ee71f8ec7b018bc`
[原生桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39476697236)
通过 60 项存储、4 项启动、1 项产品、7 项进程检查与普通权限观察，以及全部
19 项 MSI/工作进程检查和普通权限暂存。产物 `12289947434`、`12289129921`
的源码、摘要、完整文件集和回执已核验；目录替换用例修正已在 Windows 上通过。
同源[组件作业](https://github.com/billlza/cfw-rs/actions/runs/39476892785)
四项通过，679 项 Rust、314 项 UI、14 项原生引擎、35 项 SCM 与 480 个 Go pass
events 均已核验；engine `12290366428`、SCM `12290455450` 的源码和摘要匹配。
完整桌面仍有 42 项编译错误、零 warning，与 `6d00580d` 的错误消息和文件完全
相同，没有 GUI EXE。该组件尚未接入完整桌面更新状态机；
Windows 更新元数据、安装交接和整份更新流程的原生验收仍未完成。

更新元数据的目标、文件名、版本地址和重定向规则现统一在
`cfw-core::update`，桌面实际检查和发行页面命令选择本机已限定的发布目标。
Mac 保留两项 Apple Silicon 别名与原有 `latest.json`、`v{version}` 地址；
Windows 仅接受 `windows-x86_64`，文件名为
`Clash.for.Windows_{version}_x64.msi`，版本标签为 `cfw-v{version}`。
Windows 的 MSI 版本上限与原生包身份检查一致。混合平台、其他架构、替代文件名、
错误版本路径、签名不一致和跨通道重定向均拒绝；未知构建目标不会回退到 Mac。

Windows 通道约定为
`https://github.com/billlza/cfw-rs/releases/download/cfw-stable/latest-windows.json`，
平台 Tauri 配置与运行时地址由同一测试核对。`cfw-stable` 仅承担可更新的通道
指针；正式 MSI 和签名留在对应的版本发行中，不能用通道指针的可变性替代版本资产
的封存。发布 Windows 版本和更新通道时都必须保留仓库的 Mac Latest 选择，
使用 `make_latest: "false"`，不能令现有 CFM 客户端读到 Windows 发行。
本次未创建标签、发行或通道资产。首次公开 CFW 前仍须实际发布通道、生成与校验
清单，并端到端观察下载和安装；缺失通道的 HTTP 错误不能伪装成“没有更新”。
依据：[GitHub Latest 下载地址](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases)、
[发行的 Latest 控制](https://docs.github.com/en/rest/releases/releases#create-a-release)、
[Tauri 平台配置合并](https://v2.tauri.app/reference/config/)。

这次迁移保留原有六项 Mac 契约回归，并增加七项平台契约回归，13 项共享测试
及其余 113 项 Mac 更新回归通过；Mac 桌面全目标和 Windows core 全目标交叉
Clippy 均禁止 warning 且通过。这里只移动网络无关的契约层，HTTP 读取限额、
Minisign 验证、私有文件发布和安装授权仍在各自原有边界执行。新增 Windows
契约的托管原生运行以及完整状态机接入仍待完成。

安装编排的下一步须处理两个已定位的边界：MSI 的 `ServiceControl.Wait` 最多等
30 秒，不能替代 `runtime_host/service.rs` 的成功退出与全局 Off 观察；当前服务
清理失败也会终止，但保留非零退出状态，安装器必须拒绝这种替换。MSI 外层签名也
不能自动覆盖任意外置 CAB；产品包应使用内嵌载荷及包内安装操作，并检查实际生成
的数据库/字节。依据：[服务等待语义](https://learn.microsoft.com/en-us/windows/win32/msi/servicecontrol-table)、
[安装签名覆盖](https://learn.microsoft.com/en-us/windows/win32/msi/authoring-a-fully-verified-signed-installation)。

本批本地通过 Mac 全目标 Clippy（禁止 warning），102 项维护、11 项原生进程、
8 项启动、8 项更新日志、31 项引擎和 6 项生命周期回归，以及 314 项 UI 测试；
Windows 引擎库交叉 Clippy 通过。前一源码 `4f43a9b` 的托管 Mac CI 在
`NativeBridgeABIRequestRegistryTests.admissionWatchdogCancelsAndSuppressesLateSuccess`
失败，Xcode 与应用打包未执行。其测试等待器按 yield 次数退出，隔离诊断复现了
约 12 毫秒便结束等待、真实定时回调随后才到达的反例；原托管失败的精确调度时序
没有被捕获。等待器现按有界单调时钟等待，并拒绝重复回调，产品超时预算未改变。
本地按 CI 的非并行、warning-as-error 参数运行全部 Swift 包：11 组、929 项测试
通过。原始失败保留，托管 Mac 门禁仍须重跑，不能以本地结果代替。

共享界面的产品元数据改由构建目标提供，Windows 不再沿用 Mac 产品名、系统与
架构，托盘也使用同一产品名。`minimum_os_version` 在 Windows 开发阶段为显式
`null`，表示尚未确定经过验收的最低支持版本；About/Feedback 不据此展示版本
保证。Mac 的既有六字段内容保持一致。此元数据不授予引擎或发布权限。

先前完整组件证据（2026-10-20）：`c6f3739cc0dc50dac7d90f739485a7b6f2307284` 的
[Windows CI 四项作业](https://github.com/billlza/cfw-rs/actions/runs/39427676740)
及下载产物核验通过，含 661 项 Rust、314 项 UI、14 项原生引擎、35 项 SCM 检查
和 480 个 Go pass events。引擎产物 `12267262360` 与 SCM 产物 `12265729964` 的
源码、SHA-256 和完整回执已核验；已安装协调器也通过实际非管理员进程中的
Restart Manager 观察，保留原生身份且不改变 Authority、generation 或代理设置。产品服务/Agent 的
安装、四种模式的非激活预检、共享 EngineBackend 的 LocalProxy/SystemProxy 启停与
新鲜状态查询，以及真实引擎退出后的查询拒绝和独立 Off 已验证。安装客户端聚合超时
已定位并通过拆分有界验收关闭；服务崩溃恢复仍要求独立观察者保留运行 Job。
SystemProxyAuthorization 的运行前、运行中和停止后检查，以及同一保留进程句柄的
退出观察回归均通过。共享 ProfileDelayBackend 的实际凭据认证、取消/超时、较大结果
和资源退休，以及安装客户端不改变 Authority、generation 和代理设置均已验证。
完整 Tauri 桌面、TUN、视觉一致性及发布验收仍未完成。

桌面装配进展：启动流程现在通过 `platform_runtime` 选择平台服务，保留共享配置、
命令及 EngineModeCoordinator。Windows 提供已安装服务身份、持久代数、DPAPI 凭据、
代理授权和隔离测速；未实现的 TUN 与 macOS 旧服务迁移预检不会被报告为可用。
准备阶段只返回尚未启动的协调器任务，仍由启动/退出状态机决定是否安装并运行。
新增安装客户端直接编译并调用这个应用模块，验证初始 Off、本地代理→系统代理、
重复请求不分配新代数、关闭后恢复代理及协调器退休；它仍是无 GUI 的安装测试。
该应用模块的 Windows 原生验收已通过：初始 Off/gen5，LocalProxy/gen6，
SystemProxy/gen7，关闭后持久代数为 8；重复请求保持身份及代数，真实 HTTP、
WinINet 恢复、协调器退休和服务重启后的 Off 均已验证，最终 Authority revision
分别为 50/51。五个安装客户端均在各自 60 秒时限内完成，协调器场景为 47.477 秒。
之前三轮后端运行遇到聚合时限；正常启停与真实引擎退出恢复拆分后分别为
46.925/20.937 秒，操作期限、代数及原有断言均保留。此证据不包含 GUI。

整包构建入口正在移植：macOS 校验原样移入独立构建模块，Windows 开发配置使用
自己的产品身份、原图转换的 ICO 和锁定版本的 Node.js。Windows 依赖图已排除
Apple 网络适配器；锁定的 Tauri 构建器只检查根依赖的 feature 列表，因此其
macOS private API feature 仍与共享配置保持一致，平台 SDK 依赖由目标选择。
专用桌面构建 CI 将检查完整应用目标，
保留失败诊断，仅在真正构建成功后上传开发版 EXE。安装、签名及发布准入尚未实现，
因此 Windows 发布构建仍被明确拒绝；不能把开发构建入口当成整包已可用。

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

## GA 基线的架构事实

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

下表是完整 CFW 的要求。当前已取得实际 Windows WebView2 的全部九页导航、内容与
截图，以及正常退出／MSI 卸载证据；这不等于全部页面操作和原生视觉对齐已经验收。
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
| 更新/安装/迁移 | 受信任来源、精确版本/架构、失败保留旧可用状态、独立平台更新流 | Windows 安装包、签名、运行库、服务/驱动安装与升级回滚；首次大版本保留标准配置导入，不假定项目旧版本服务协议 | 干净机器安装、升级/失败/卸载、下载后验签和公共字节核对 |
| 可访问性/性能 | 四种语言、完整键盘路径、真实状态名称、无主线程阻塞 | Narrator、高对比度、减少动画、混合 DPI/多屏 | 真实桌面操作；冷/热启动、CPU/内存、滚动与网络测量 |

协议覆盖不能仅从上游文档推断：包括 GA 已实现的 SOCKS5、Shadowsocks/2022、VMess、
VLESS/Reality、Trojan、Hysteria2、AnyTLS、TUIC、WireGuard 及其受支持传输、DNS、TLS/ECH
选项，以冻结源码的转换、校验、投影和现有协议测试为依据。OpenVPN/OpenConnect、
任意脚本/PAC、任意 sing-box/Mihomo 配置和 kill switch 不因移植自动成为支持项。
Mixin 在 GA 仍明确不可用，不把它画成可用开关，也不能用这个单项例外删去其他功能。

GA 发布说明记录的安装所有权和非正常退出遗留隧道问题是已知限制，不是应复制到 Windows
的“功能”。Windows 必须定义并验证自己的关闭、隐藏、正常退出、强退及恢复行为。

2026-10-21 的 TUN 实现边界核查确认，`WindowsEngineBackend` 的隧道安装、授权、启停
仍返回显式 Unavailable；`ServiceClientRole` 的实际分发只有 Desktop 与 UserAgent。
`TunnelWorker` 和 `PacketPumpLimits` 的状态机测试不构成生产隧道通路。现有
`InstalledDesktop::check_configuration` 只构造／关闭引擎，不能证明创建适配器或转发数据包。
后续实现必须接通适配器、受约束的数据包传输、运行租约和独立清理观察后，再开放 UI 能力。
（以下为 2026-10-22 的状态；2026-10-23 的实现见“产品 TUN——SYSTEM 适配器与 UserAgent
引擎”一节。）2026-10-22 起 `tunnel::PacketPump` 提供会话与数据包端点之间的有界双向传输，验证
探针以真实引擎转发 Windows IPv4／IPv6 TCP 与 UDP（结果见当前验收状态）；引擎到系统
方向只投递 `DeliveryPolicy` 允许的包。SYSTEM 到 UserAgent 的端点交接已在 SCM 夹具中
原生验证（见交接前加固一节）。Authority 状态机仍按独立的 `TunnelWorker` 角色授权
Tunnel 模式，须按 2026-10-22 的用户决定改为由 UserAgent 承载；运行租约（Authority wire
中的端点消息与授权代次）、SYSTEM 承载的适配器与泵、路由／DNS 所有权和持久恢复仍未接通。

固定引擎依赖 `sing-tun@v0.9.6-0.20260924001923-ddaa4ca25e3b` 的 Windows 实现
拒绝非零 FileDescriptor，直接创建 Wintun 适配器；system stack 还会尝试修改 Windows
防火墙。因此不能沿用 Apple 文件描述符接入方式，或直接提高普通用户引擎权限。
引擎的 `adapter.PlatformInterface.OpenInterface` 是现有可复用注入点，需要与 Windows
受权限保护的适配器管理连接。另有待解决的范围冲突：共享设置／投影接受 1280–9000 MTU，
当前 Authority wire 与 Apple TunnelNetworkOptions 只接受 1280–1500；此处尚未修改任一
边界或声称较大 MTU 已可用。驱动交付应使用 [Wintun 官方签名 DLL](https://www.wintun.net/)
及随包许可，并单独核验来源和运行效果。

已加入独立的 Wintun 原生生命周期作业，执行前固定官方归档、x64 DLL 和原始许可
字节，并要求 Windows 原生 Authenticode 检查通过。验证模块只编入 validation feature：
保留 DLL 及路径对象，核对实际加载映像，再创建专用适配器和有界会话；分别在正常关闭
与所持有的子进程被强制终止后，按先前观察到的 LUID 查询适配器是否真正消失。
不调用 OpenAdapter 或 DeleteDriver，也不显式写入路由、DNS、防火墙或接口地址。
源码绑定的阶段回执和复制后核对摘要的探针 EXE 随成功／失败结果保留。
`abe0692d` 的托管原生执行已验证官方 DLL 的 Authenticode 为 Valid、创建适配器／
会话及正常关闭后的接口消失。但强制终止已绑定子进程后，原适配器在 15 秒内仍存在；
这轮作业保留为失败，不能推断进程退出等于适配器清理。该样本中，先后创建的两个适配器
还复用了相同 LUID，恢复身份不能只记录 LUID。

后续验证在子进程仍存活时绑定 GUID、LUID、别名和原生设备实例，保留进程及设备观察对象；
拒绝存活进程的移除与外来 GUID。确认同一进程退出且原设备仍在后，才对该实例执行
`DIF_REMOVE`，拒绝需要重启的结果，并独立查询接口消失。另一个存活控制适配器必须保持
原身份，再正常关闭。原来的自动消失观察仍单独记录，不能用显式恢复冒充自动清理。
`1c413b22` 的原生执行与下载产物复核已验证：自动消失为 false，定向移除后接口消失，
另一个存活控制适配器保留原身份并随后正常关闭。此路径仍是隔离验证；服务自身重启后的
持久身份恢复尚未实现，不能据此开放产品 TUN。
这项验证不等同于产品 TUN、数据包转发或全局恢复；真实服务、数据通道、MTU 以及
路由／DNS／防火墙的所有权和清理仍须接通，UI TUN 能力保持未开放。

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
| Windows 纵向链路 | 真正导入、启动代理、联网、停止恢复；General 与复杂弹窗真实验证 | 引擎、Rust 进程所有权及 WinINet 流量/恢复已通过九项真实集成测试并核验下载产物；`ab812fc` 的 SCM 九项原生场景及普通客户端权限边界也已通过并核验回执；`ca1d120e` 起实际安装 GUI 完成两种代理流量与退出恢复；`1f7bccc1`／`f00051fb` 起 Wintun→泵→真实引擎的 IPv4／IPv6 TCP 与 UDP 转发已在托管 Windows 验证；`9287fb79` 起 SYSTEM 到 UserAgent 的端点交接在 SCM 夹具中原生验证；2026-10-23 接通 TUN 运行租约、SYSTEM 承载的适配器／路由／解析器、退役与恢复，并在 UI 开放 TUN（组合模式除外），托管原生与 GUI 验证见当日记录；完整服务生命周期待完成 |
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

本节记录早期用户级存储及其验证。当前实现已改为下述 SYSTEM Authority 的整机代次；
历史 Credential Manager 结果不能作为新实现的原生验收。

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

## Windows Authority 日志与恢复（2026-10-19，组件原生验证完成）

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
停止中的记录要求停止所有者。该存储层不发放执行授权；运行所有者和操作协议仍待
接入。宿主/桌面工厂仍未切换为 Windows backend。

本机新增十项日志/校验测试，连同原十二项组件测试共 22 项通过；Windows 目标严格
Clippy 通过。原生服务 fixture 加入十五个实际持久化边界中断、四种完整/损坏临时文件、
四种身份/回滚情形，以及跨进程退出后的 Active 元数据恢复。压缩使用仅验证特性可用
的小容量构造器，生产默认仍为 4,096 条、32 MiB；不会把这类故障注入当作断电测试。
提交 `aaaa935` 的 Windows 运行 `39195790295` 四项 job 全部通过：Rust 498 项、
前端 311 项、SCM 32 个场景和 256 轮交换。原生报告包含上述持久化边界与跨服务
退出恢复检查。下载的服务产物 `12162186031` SHA-256 为
`024e1d90a13290f327a5c03391157cb3f7cfd0f4e2d44d7a9a09f3436d130301`；
引擎产物 `12161579628` 为
`7ab580aa39fb099a7a8b5cf77407bda632b2bfcba0239e584d45aaee296241c1`。
源身份、报告、二进制和许可文件均经下载核验。

此前 `602cec2` 的 Mac 运行 `39193235347` 已成功完成 quality、supply-chain 和
native job，包含四项 analyzer、实际 signer 测试和未签名验证骨架打包。
这不解释 `4e34608` 的启动探测失败；其根因仍未确立。

## Windows Authority 在线状态与授权（2026-10-19，组件原生验证完成）

新增准备、绑定、就绪、心跳、停止、撤销、隔离和恢复状态机。原生控制器在发出票据
或运行启动授权之前提交日志，并在提交前后重新检查原生进程、当前控制台所有者和
尚未回复的管道请求。进程身份保留完整 SID、登录 LUID 和 session；新连接不能继承
旧连接的租约。票据由 Windows 系统随机源生成，控制器只保留单次绑定摘要，失败无
默认票据；票据不进入日志。票据比较使用固定长度的常量时间比较。

准备有效期十秒，运行心跳与停止证明期限各五秒。未绑定的取消通过两次持久提交
释放准备；该内存事实不会从重启后的磁盘状态重建。提交结果不明时清除在线授权，
状态暴露为 Recovering、revision 未知；完成恢复读取之前不能报告旧版本号为当前值。
首次登记前拒绝旧版本号；停止与取消都要求完整操作上下文。

本机组件测试共 34 项通过。原生 fixture 检查 SYSTEM 环境的随机源、实际日志发布、
重启后不恢复票据、提交后返回错误时不发票据，以及回复后不能复用旧请求。清理观察
明确使用仅验证特性可用的注入输入，尚未绑定真实 UserAgent 或启动实际引擎。
生产清理证据没有可伪造的公开构造器；实际观察适配器、运行进程监督、服务 dispatcher、
Windows EngineBackend、TUN、安装及真机验收仍是独立的后续工作。

提交 `6981e92` 的 Windows 运行 `39200886804` 四项 job 全部成功，含 510 项 Rust、
311 项前端测试、33 项原生场景和 256 轮交换。服务产物 `12164355186` SHA-256 为
`55d89070a4bd7040c681978fe532b210a8ad68011c37e90c823bb29f62e263c3`；
引擎产物 `12163728392` 为
`fb4eb306f1aaf26418430f1d9e7fec8a8657112465da2e91cf34ad59f99a75e1`。
下载后核对源码、报告、二进制与许可文件；不把清理注入输入当作生产清理证据。

## Windows Authority 命令通道（2026-10-19，原生协议路径已验证）

新增 `cfw.windows.authority` 协议版本 1、实际请求分发和 `AuthorityChannel` 客户端。
命令必须来自已认证管道的原始消息，分发按内核捕获的 Desktop/UserAgent 角色授权。
服务生命周期锁覆盖分发与回复；持久化/观察失败保留原始服务端错误，线上只返回封闭
错误码。请求与回复同时校验协议、版本、请求 UUID、操作上下文、原生所有者和版本号。
超时、不相关或损坏的回复关闭客户端通道，不自动重发；显式业务拒绝可以保留连接。

控制消息上限 8 KiB，票据固定 32 字节，无 Debug/Clone。编码使用完整初始化且可清零
的固定容量缓冲；借用 RawValue 后直接解码具体载荷，避免通过通用 Value 复制票据。
准备回复和运行绑定回复没有公开反序列化器；客户端完成关联验证后才能构造这些类型。
运行时仍必须消费绑定结果并验证实际资源，不能把绑定回复当作引擎已运行的证据。

本机组件测试 42 项通过，包括重复/未知字段、边界与票据截断、身份/版本不匹配、
伪造提前 Ready 与错误 Off 回复。原生 fixture 使用真正的中完整性、非管理员
UserAgent 进程，经继承的匿名 stdin 管道交接内存票据，执行 12 条版本化命令。
检查错误票据、新连接继承拒绝、绑定/Ready/心跳/停止路径，以及 Stopped 报告仍停留
在 Stopping。匿名管道写入在单独线程执行，由父进程监督子进程期限并在结束后回收。
Ready/Stopped 报告和最终清理观察在此仍为显式合成输入；实际引擎启动、生产清理观察、
完整 SCM 服务与桌面 backend 接线仍待实现。

提交 `5c600bd` 的运行 `39203140484` 中，SCM job `117900197294` 已成功。
下载服务产物 `12163849125`，SHA-256 为
`2fa1bda4893d0782a13b332bb092e91334b117c640889744600c862e9f71f932`。
核验 34 个原生场景、256 轮交换、四个客户端报告及 11 个拒绝记录；新协议报告确认
实际 UserAgent 绑定、12 条版本化命令和两项业务拒绝，同时显式声明运行报告与清理
输入为合成数据。它不证明真实引擎已在该服务租约下启动。

另补租约上下文空安装 UUID 的边界检查。共享 RootContext 验证 epoch/generation，
Windows 入口需独立验证非空安装 UUID。新增回归用例先在旧实现失败，修正后命令
构造、服务端解码和客户端租约回复均拒绝该输入；已有原生路径不变，新提交 CI 待跑。

`110619f` 的 PR Windows 运行 `39203816695` 在 SCM 压力场景失败：236 次交换已完成，
下一轮触及原有 45 秒时限。保存的失败产物仍证明新命令路径通过，但不能证明完整
SCM gate 通过。诊断提交 `7f7ac50` 保留 256 次交换和原时限，在运行 `39204611236`
重现了 252 次后超时。分段计时为：完整镜像校验 25.284 秒、往返交换 16.836 秒、
节奏等待 2.743 秒、连接 0.030 秒、停止服务观察 0.155 秒，总计 45.054 秒；镜像
大小为 3,478,528 字节，重复完整验证 252 次。失败发生在轮次之间，未观察到单次
连接/请求失败，不把它误报为新 Authority 命令故障。

## Windows UserAgent 生命周期与验证边界（2026-10-19）

新增 UserAgent 生命周期所有者，将已核验配置、原生 Authority 绑定、真实引擎、
WinINet 代理所有权与停止报告连接起来。配置字节摘要和产品身份摘要分别检查；
独立控制线程在引擎启动期间维持原连接心跳，撤销信号可以中断引擎 RPC 等待。
Ready 前重新观察实际子进程、监听端口和代理记录；停止保持先恢复代理、再停引擎，
并核验已持有进程退出、Job 为空、控制线程退出和端口释放。失败保留原错误，
恢复未完成时保留所有者和日志供显式恢复，不制造全局 Off。

新增托管 Windows 用例以普通用户令牌经实际 SYSTEM 服务运行 LocalProxy 和
SystemProxy，发送真实 HTTP 请求，并从 Authority 撤销 SystemProxy 后验证停止。
最初的生命周期用例在同一进程内完成 Desktop 准备与 UserAgent 运行；本次改为
不同映像、不同进程间传输原始共享请求，并从 Desktop 验证原控制器密钥仍能认证、
未认证访问被拒绝。LocalProxy 和 SystemProxy 均由 Authority 撤销后停止。
初始/最终全局清理证据仍由
测试显式注入，不能把这部分当成已实现的生产服务恢复、安装器或整机验收。

SystemProxy 与 LAN 共享的组合原先被 Windows 配置所有者误判为重复 mixed
监听器。本地回归已观察旧代码以 `SystemProxy requires one mixed listener` 失败，
修复后保留三个端点的所有权观察，只从 `cfw-system-proxy` 提取 WinINet 目标。
共享投影的 LAN 地址、端口和可信来源范围校验不变。原生用例增加同一 Windows
主机私网接口的允许请求、loopback 来源的拒绝请求以及停止后的 LAN 端口释放；
这些检查不替代另一台设备访问、防火墙策略或真实网络切换验收。

配置接收路径复用现有 `EngineStartRequest`，共享 schema 7 身份摘要计算函数，
保留原始模板及其进程级控制器密钥。Windows 接收端检查规范 JSON、两个摘要、
上下文、模式和凭据槽，并在代理模式下拒绝额外系统设置开关、非本机控制器、
错误监听角色或被更改的 LAN 来源规则。UserAgent 先绑定原生租约，再按准确的
配置 audience/reference 解析凭据；配置候选检查仍不能授权启动 Tunnel。
原生用例改走共享请求路径，加入错误票据先于凭据目录访问和引擎创建被拒绝的检查。
新增一次性启动帧 `cfw.windows.user-agent.start` v1：长度前缀、2 MiB 负载上限、
原始共享请求和绑定票据。接收端拒绝截断、尾随内容、未知/重复字段及非规范编码，
重新核验请求与租约；服务、可执行文件、凭据目录仍由接收端受信任装配提供。
启动帧通过不落盘的继承管道进入普通用户子进程，测试刻意超过 8 KiB 管道缓冲提示值。
仅验证用的非秘密 Ready 元数据配合父进程持有的进程句柄检查生命周期；它不是生产
授权凭据。`ce909db` 的[四个 Windows 作业](https://github.com/billlza/cfw-rs/actions/runs/39229929226)
已通过，并回读源提交/哈希绑定的产物：532 项共享 Rust 测试、311 项 UI 测试、
独立 Desktop 和三个 UserAgent 报告、两次 Ready/Stopped、四次心跳及一次票据拒绝。

后续生产交接通道改用继承的私有消息管道，复用已有 overlapped I/O 的取消和完成等待。
接收端检查端点类型、消息读取模式、父进程完整用户/登录/会话身份及安装映像身份。
发送端要求与整帧 SHA-256 对应的有界解码确认；它不表示租约绑定或引擎已启动。
任一端只尝试一次，超时/取消后的投递不确定性保持为错误。新增原生测试强制产生
pending read/write，再验证取消后的内核完成结果。`73d2eb5` 的
[Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39232605109) 四个作业已通过，
源提交和下载哈希均已核对；539 项 Rust 测试包含七项新增原生通道测试，UI 为 311 项。
实际双进程运行也使用了该产品通道，并核对父映像、解码确认和原控制器密钥。

新增产品 `UserAgentChild` 启动器，以原生句柄白名单继承启动端点和诊断句柄，
创建前检查中等完整性、准确的租约所有者及当前控制台，创建后核验实际子进程令牌和
安装映像，再发送配置。失败保留清理上下文；创建进程后的失败同时返回持有的进程
所有者。发送解码确认与进程退出分别观察，均不能表示全局 Off；需要先由 Authority
撤销，再保留所有者直到恢复/退出，启动器不以强杀已可能运行的 Agent 代替清理。
原生运行用例已改为普通权限 Desktop 通过此产品启动器创建普通权限 Agent；这一变更
已由下述 `eb9b89c` 原生运行核验。安装入口、全应用生命周期整合、独立全局清理和后端装配
仍未完成。实现核对了当前固定 [Rust 1.98.1 Windows 进程创建源码](https://github.com/rust-lang/rust/blob/1.98.1/library/std/src/sys/process/windows.rs)，
不依赖默认 `Command` 行为推断句柄白名单。

`3b76e8d` 的首次原生运行在创建 Agent 前失败：普通 Desktop 错误调用了仅供 SYSTEM
使用的完整控制台观察器。九项底层引擎测试通过，但该次生命周期用例未通过，失败日志
及产物保留。修复让客户端只检查自身会话编号仍为当前控制台且连接状态为 Active；
它不取得控制台用户令牌、不构造 `LiveConsoleSession`。SYSTEM Authority 对完整
SID/登录 LUID 的逐次授权检查不变，原生用例另行断言普通 Desktop 仍被特权观察器拒绝。
这一权限区分符合 [WTSQueryUserToken 的 SYSTEM/SE_TCB 要求](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
与[当前会话信息查询](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw)的不同边界。
`eb9b89c` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39239112761)
四个作业通过，下载的引擎与服务产物已核对源提交、哈希和逐项回执。542 项共享 Rust
测试、311 项 UI 测试通过；真实生命周期用例包含两次 Ready/Stopped、四次心跳及
一次错误票据拒绝，并确认普通 Desktop 仍不能调用特权控制台观察器。全局清理仍是
夹具注入，这些结果不构成完整 Windows 后端或发布验收。

进一步新增单次操作所有者 `DesktopUserAgent`：在专用原生线程上核验原始共享请求，
持有准备该操作的 Authority 连接、待交接配置和实际 Agent 进程；只有 Active、准确
租约上下文及持有的活进程一致后才报告 Ready。运行中每秒观察一次，独立于 UI 刷新。
停止先通过原连接撤销，再等待 Agent 退出与交接线程结束。仅 BeginStop 的明确
Stale 拒绝允许重新观察后再试，总计最多三次；传输结果不确定、上下文错误及其他
请求的拒绝均不重放。三项策略测试覆盖成功、次数耗尽和不可重试错误。
原生夹具已改用该产品所有者，并要求错误服务名和过期停止请求不能消耗有效准备。
监督流程由下述 `803b86d` Windows CI 核验；它不包含安装入口、全应用恢复、全局 Off 观察器
或 Windows EngineBackend。返回 Stopping/Recovering/Quarantined 必须保留该实际状态。

`5d02f17` 的首次 Windows 运行通过了九项底层引擎测试，但新 Desktop 夹具在首次
Ready 后观察 Agent PID 时失败：重新打开的句柄仅包含 SYNCHRONIZE，缺少
[GetProcessId 所需的查询权限](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessid)。
修复只增加 QUERY_LIMITED_INFORMATION，并将原生查询失败与“当前进程不是独立 Agent”
区分记录。原始失败产物已按源提交和哈希保存；其中首个 LocalProxy Agent 的
Stopped/本地清理报告成功，但该次完整 Desktop 运行未通过，修正后的结果见下述复验。

`803b86d` 的 [Windows 复验](https://github.com/billlza/cfw-rs/actions/runs/39244731759)
四个作业已通过，源提交、下载哈希及逐项产物回执均已回读核对。545 项 Rust、311 项 UI
测试通过；真实 Desktop 监督路径完成两种代理模式、LAN 来源限制、原控制器认证、
两次 Ready/Stopped、四次心跳以及代理恢复和进程退出。初始/最终全局清理仍由夹具注入。

改为允许服务 peer/channel 共享已验证镜像对象的 Arc。原文件及祖先目录句柄持续
持有，保持禁止写入/替换的原契约；每次连接的 SCM 安全描述符、配置、进程和管道
身份仍重新读取。压力测试在原预算内固定镜像一次，256 轮都检查已停止服务；新增
计数明确区分一次镜像固定与每轮服务观察。未放宽时限、重复次数或拒绝断言；
`803b86d` 服务产物中已核对这 256 轮在原 45 秒预算内完成。

实现核对了 [RawValue 借用解码](https://docs.rs/serde_json/latest/serde_json/value/struct.RawValue.html)
、[CreatePipe 缓冲及阻塞语义](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
、[消息管道读取模式](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-type-read-and-wait-modes)
和 [CancelIoEx 完成要求](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)。

## SYSTEM Authority 整机身份与代次分配（实现中）

SYSTEM 在首次打开干净日志时生成并持久化安装 UUID；服务仍处于 Recovering，直到
独立清理证据通过。Desktop 通过已认证通道读取安装身份并原子预留下一代次，UserAgent
没有该角色权限。普通用户各自生成 UUID 的旧代次实现已替换；旧 Credential Manager
记录不被导入或删除。共享协调器继续要求准确的 expected generation 与 `+1` 结果。

分配记录复用现有日志、独立注册表锚点和写入事务，并将 `allocated_generation` 与
最近运行的 root 分开。只有 Off 可以分配；准备运行必须使用当前且尚未消耗的代次。
未启动的分配同样跨重启和 checkpoint 保留。错误 CAS、溢出或写入结果不确定会显式失败，
客户端不重放投递结果不确定的请求。Windows 开发中日志载荷在这一阶段升为 schema 2；
后续完整配置身份记录使用 schema 3。旧载荷明确拒绝，没有自动重置或迁移路径，
已发布的 CFM 数据协议保持原状。

本地 62 项策略/协议测试及 Windows 目标全特性 Clippy 通过。原生夹具增加四个分配写入
故障点，总故障轮次为 19；它还检查真实服务重开后的身份/代次、写入已提交但未返回成功、
陈旧 CAS 和 UserAgent 角色拒绝。真实运行改用产品代次适配器及两个独立适配器实例。
`3ced231` 的 [首次 Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39249415277)
通过 549 项 Rust、311 项 UI 测试及真实代理运行，引擎产物已按源提交和哈希核对；
SCM 作业在预期的重复分配 Stale 拒绝后失败。内层用例已精确验证该拒绝，外层发送后的
夹具检查仍只允许旧的 Ticket/Identity，因而错误终止服务；管道关闭和后续 1061 停服错误
是下游结果。修复增加这一明确的预期类型，保留原有顺序、状态和拒绝断言。

另外增加一条未启动代次的真实 checkpoint 用例：连续分配六次以触发压缩，使用第二个
原生存储句柄重开，再分配第七次。此前原生压缩用例的 root 已运行过，旧回执中的
未启动代次标记不能单独作为该场景的证据；新回执要求明确的执行次数。
修正后的 `c0df6a3` [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39251115403)
四个作业通过，源提交和产物哈希均已核对：549 项 Rust、311 项 UI、34 项 SCM 用例、
19 轮日志故障、1 次未启动代次压缩、16 次协议请求和 4 次预期拒绝。256 轮停止服务
压力检查在原 45 秒预算内完成；真实代理运行完成两次 Ready/Stopped 和四次心跳。
并发客户端、实际会话切换、全局清理、凭据生命周期和 Windows 后端装配仍须继续验证。

## 恢复配置身份与只读范围查询（实现中）

凭据清理必须保护正在运行、准备启动及待恢复的配置。此前持久日志只保留配置内容哈希，
完整配置身份摘要仅存在于内存租约，服务重启后不足以核对凭据绑定。schema 3 同时保留
两种摘要，并拒绝在准备至清理期间更换或丢弃操作身份；旧日志不补造缺失字段。

新增 Desktop 专属 `ReadRuntimeScope`，返回已提交操作与控制器策略状态。相同账户可
读取前次登录的恢复元数据，但完整 SID、登录 LUID 和会话号仍原样保留；新连接不能
凭查询结果取得租约、停止旧操作或启动引擎。该读取不执行新的操作系统存活检查，
不能替代 Ready 或全局 Off 证明。写入结果不确定、遗漏字段、异账户身份均显式失败；
Recovering 的空记录也不能当作 Off。

本地 69 项策略/协议测试和 Windows 目标全特性 Clippy 通过。原生夹具新增恢复摘要
回读、只读 Desktop 连接的控制拒绝、UserAgent 角色拒绝，以及真实代理运行期间的
完整身份核对；原生执行结果需与对应源提交和产物关联。凭据生命周期绑定表、跨进程
修改锁和 GC 的实际接入仍未完成，初始/最终全局清理仍由运行夹具注入。

`e163e81` 的首次原生 SCM 运行在第二条 Desktop 连接读取时超时：夹具按角色串行处理
整个连接，而原 Desktop 仍保持租约连接，新的读取无法被服务。夹具改为按产品 listener
的连接上限调度工作线程，每条连接的读取、身份校验和回复仍由同一线程完成，生命周期
锁仍覆盖分发至回复。所有线程都会回收并报告错误；原有时限和身份拒绝断言不变。
修正后的 `0c1077e` [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39258113590)
四个作业通过，下载产物的提交号、哈希及逐项回执均已核对：556 项 Rust、311 项 UI、
34 项 SCM 用例、19 轮日志故障、20 次协议请求和 7 次预期拒绝。真实 Desktop/Agent
运行完成两种代理模式，新增观察连接读回的身份与实际运行配置一致；两次 Ready/Stopped、
四次心跳、LAN 来源限制、控制器认证、代理恢复与进程退出均有回执。

首轮 `e163e81` 真实引擎作业的 9 项原生引擎测试通过，但运行夹具在服务清理的 1061
错误上 panic，跳过了诊断导出，原始运行错误未完整保留。该失败不能据后续成功补判
通过；保留其独立失败产物。后续 `2187b23` 已补齐主错误保留和清理 panic 后的诊断导出，
并通过两个原生夹具测试；首轮丢失的原始运行错误仍无法补判。

## Windows 凭据生命周期接入（实现中）

新增同步 `WindowsCredentialLifecycle`，与实际 Desktop 准备路径共用用户级跨进程锁。
准备请求发给 Authority 前，先原子保存完整配置绑定的公开元数据；记录不包含配置模板、
控制器密钥、票据或凭据明文。GC 预览和提交都重新读取已认证的运行范围与持久绑定，
按 root、operation ID、模式和两种摘要核对，保护资料库中已删除的旧配置凭据。
准备中、运行中、停止中和待恢复配置均保留保护；只有服务已确认 Off 才解除运行保护。
记录遗漏、损坏、身份不匹配或服务观察失败均返回错误，不能转为空绑定集合。
存在受保护引用时缺少 DPAPI 库有独立错误，避免被界面的空库处理分支误认为正常。

产品 Desktop/Agent 夹具改用同一用户的真实 DPAPI 库。新增用例在引擎运行期间实际执行
GC，删除无用的旧摘要绑定并确认运行绑定仍在；启动前的预览在启动后提交必须冲突。
另行检查独立适配器重开、缺服务、缺/坏绑定记录、缺受保护凭据库，以及停止后的回收。
本地 74 项策略/协议测试和 Windows 目标全特性检查作为前置验证，原生结果须关联新源。

运行夹具也补齐清理异常后的诊断导出：保留主操作错误，清理 panic 后仍复制诊断，随后
继续传播失败。两个独立夹具测试检查 panic 不被吞掉、诊断导出失败不覆盖主错误。
这里仍只接入当前两种代理模式；异步应用适配器、Tunnel 与持久候选配置、独立全局恢复、
完整后端/工厂及最终产品验收继续保留，不能据此宣称完整凭据或 Windows 发布验收完成。

`2187b23` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39262208143)
四个作业通过，提交号、下载哈希及逐项回执均已核对：561 项 Rust、311 项 UI、
2 项诊断夹具测试、34 项 SCM 用例和 9 项原生引擎测试通过。两种代理模式都完成
真实 DPAPI 解析、活动 GC、陈旧预览拒绝、记录/服务/凭据库故障拒绝和停止后回收，
运行回执包含两次 Ready/Stopped、九次心跳及一次预期的错误绑定拒绝。初始/最终全局
清理仍为显式注入，资料库锁与异步界面调用尚未接线，不能替代完整应用或恢复验收。

## Windows 异步凭据接口（实现中）

`WindowsCredentialLifecycle` 实现共享 `CredentialVaultProvisioner` 的五个方法。
异步层在启用时间驱动的 Tokio 执行器中运行，克隆实例共享四个任务额度；先取得额度，
再复制经过验证的借用密码到 Zeroizing 缓冲，沿用 448 KiB 总量上限和原有不可变事务。
原生服务连接、用户锁、DPAPI 与文件 I/O 在阻塞工作线程内执行。

排队任务有 15 秒准入期限，调用方有 30 秒完成 watchdog。取消与凭据库准入通过原子
状态转换决定先后，拿到生命周期锁、重新观察 GC 保护范围后还会检查一次；尚未准入的
取消/过期任务不能晚到后写入。已准入的操作继续持有锁、任务额度和缓冲直至结束，
超时返回结果未确认，不假称回滚或自动重放。受保护凭据库丢失映射为 Corrupt，不能
进入界面“无库且无引用则为空”的分支。原生 IPC 的原有请求时限保持不变。

新增九项 Windows 工作线程测试，覆盖调用线程模拟身份拒绝、队列容量、取消、原生锁等待、实际 watchdog、
准入后结果不确定及资源保留；新增一项真实 DPAPI 所有权转交测试，并扩展总量拒绝。
运行夹具改用全部五个共享异步方法，包括向不同配置摘要实际重绑定凭据，继续保留活动
GC、错误状态拒绝和停止后回收的断言。本地 74 项可移植测试和 Windows 全特性 Clippy
通过；这些新增 Windows 执行路径仍需按对应源提交核对托管 CI 产物。

该适配器尚未通过完整应用工厂接入界面；独立全局恢复、Tunnel/持久候选配置、完整
应用/UI、安装更新与真机发布验收继续保留。

实现参考 [Tokio 阻塞任务取消语义](https://docs.rs/tokio/1.53.1/tokio/task/fn.spawn_blocking.html)，
平台文档本身不构成本项目的运行验收。

`4f80420` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39268058598)
四个作业通过，源提交、下载哈希及逐项回执已核对：571 项 Rust、311 项 UI 契约测试
通过，其中新增九项异步工作线程测试和一项所有权转交测试均有独立通过记录。34 项
SCM 用例、两项诊断夹具测试和九项原生引擎测试继续通过。真实运行完成全部五个共享
异步凭据方法、不同摘要的凭据重绑定、活动 GC 与停止后回收；运行回执为两次
Ready/Stopped、十次心跳和一次预期的错误绑定拒绝。全局清理仍为夹具注入，完整
应用工厂、恢复及发布验收未被这些组件结果替代。

## SYSTEM 独立运行进程观察

服务在提交 Bind、发出运行授权前，把已认证且仍然存活的 UserAgent 纳入按完整
installation/epoch/generation 命名的 Job。引擎随后自动继承父 Job，并继续加入原有
本地清理 Job；服务保留的句柄只有查询和读取安全描述符权限。服务 Job 不设置
kill-on-close、breakaway 或 UI 限制，避免服务退出打断先恢复代理、再停止引擎的顺序。

`observe_runtime_processes` 从已知的持久 root 重新打开内核对象，核对 SYSTEM 所有者、
受保护且仅含 SYSTEM 的 DACL、Job 限制和进程计数。命名对象不存在不等于
进程退出：没有可查询对象的活动或恢复中运行明确返回 Unavailable；权限、对象类型、
描述符、查询及未知日志状态也保留为错误。仅 schema 4 的已提交 Off 记录可作为之前
已完成的退休证明，该观察标为 DurablyRetired，不伪装成新的原生计数。
持久状态仍为 Preparing 时，仅能证明尚未发布 Bind 授权，观察标为 NeverAuthorized；
它不声称启动侧 Agent 已退出，也不替代其余清理证据。Starting/Active/Stopping 等
状态缺失命名对象时不能采用此路径，仍明确失败。
`reconcile_off` 增加独立进程门禁：即使夹具注入完整 CleanupEvidence，只要 Agent 或
其子进程仍存活，也拒绝 Off。正常运行授权之前任何部分赋值失败进入恢复状态。

Windows 开发协议升为 v2、日志载荷升为 schema 4。v1 服务及 schema 3 等旧日志不能
证明运行进程已加入服务 Job，故明确拒绝，不自动迁移或重置。CFM 已发布协议不变。

原生夹具增加同名对象、错误对象类型、异常 ACL、breakaway 配置和只读句柄的反例；
真实 LocalProxy/SystemProxy 路径记录 Ready、Stopped、退出后的原生进程观察，创建
另一个控制器并重新打开日志和内核对象，原控制器保留查询句柄；验证普通 UserAgent
无权查询、赋值或终止服务 Job。此场景不等同于服务句柄丢失或完整 SCM 重启验收。
本地 74 项可移植测试及 Windows 全目标、全特性 Clippy 已通过；新增原生路径仍待
该提交的托管 Windows CI 验证。

首轮 `b484dae` 的原生 SCM 验证在关闭最后一个 Job 句柄后，无法重新观察仍存活的
UserAgent；失败日志和下载哈希保留。该反例否定“对象名称缺失就证明全部成员已退出”
的假设。修正后增加独立的空闲子进程用例：先观察一个成员，关闭最后句柄，分别核对
持有的进程身份仍存活以及观察接口返回 Unavailable，再回收该子进程。该变化不放宽
任何 Off 断言。服务失去最后句柄后的活动运行恢复仍是开放项，需要额外的可靠观察
机制；不能仅靠持久 Job 名称宣称已经解决。

进程退出只是全局清理的一个条件。独立代理恢复、TUN/端点观察与生产 CleanupEvidence
构造尚未完成；运行夹具仍明确注入剩余全局清理证据，不能据此称完整应用或发布可用。

实现依据 [Job 生命周期](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw)
和 [嵌套 Job 继承及计数](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)。

`defd2ea` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39277613562)
四项作业通过，原生服务与引擎产物、共享测试日志已按源提交和下载哈希核对：
575 项 Rust、311 项 UI、34 项 SCM 用例、两项诊断夹具测试和九项原生引擎测试通过。
两种代理模式的服务计数分别为 Ready 时 3、Stopped 报告时 1、Agent 退出后 0；
已有句柄保留时，第二个控制器能够重开观察并拒绝活动进程的 Off。独立空闲子进程
复现了最后句柄关闭后名称消失但进程仍活着的反例。全局清理其余条件仍为夹具注入。

### 零权限保留句柄的隔离验证

为解决服务句柄丢失后的可观察性，新增仅在 native-service-validation 中编译的
JobKeeperProbe。SYSTEM 创建没有成员的独立 Job，向已认证的受限 UserAgent 复制
零权限、不可继承的句柄；此用例不发出任何运行授权。客户端及其同权限副本必须不能
查询、设置限制或终止 Job，也不能通过 DuplicateHandle 获得查询、赋值、终止、设置
属性或改变安全描述符的权限。服务随后关闭创建句柄，检查零权限句柄保留名称；客户端
释放两个副本后，服务必须观察到名称不可用。三步握手绑定原连接的实际进程与令牌。

该候选机制尚未接入产品 Bind 或引擎继承链，也不证明完整 SCM 重启恢复。当前产品
遇到丢失的活动 Job 仍返回 Unavailable。先验证原生权限和生命周期性质，再决定是否
将其用于运行资源；不根据句柄的表面权限推断无法提权。
参考 [DuplicateHandle 的权限语义](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)。

`bd84f59` 的原生 SCM 产物已核对来源及 SHA-256：35 项 SCM 用例通过，包含上述
零权限句柄和同权限副本的拒绝、服务创建句柄关闭后的名称保留、最终释放观察。
显式启用验证 feature 的普通用户准入测试通过，原有两项诊断夹具测试保持通过；
256 次停止后连接验证耗时 19.357858 秒，原有 45 秒上限未改变。其余引擎产物和
575 项 Rust、311 项 UI 日志也已核对，该源四项 Windows CI 最终通过。

另外核对了固定 Rust 1.98.1 的 Windows 启动实现：普通 Command::spawn 默认继承
可继承句柄，且未提供显式属性清单。后续接线需让引擎使用明确的继承句柄清单，
覆盖 Agent 到引擎的生命周期；不能仅把保留句柄设成可继承后依赖默认行为。
下述显式启动实现已有原生执行证据。Job 名称保留的隔离证明不替代完整 SCM 崩溃恢复、代理恢复或
所有运行进程的最终退出证明。

### 引擎显式句柄继承与创建时 Job 归属

产品 EngineProcess 改用 CreateProcessW 和已有的 ProcessHandleList；子进程仅继承
输入、输出、NUL 错误输出三个明确选定的句柄。本地 kill-on-close Job 通过
PROC_THREAD_ATTRIBUTE_JOB_LIST 在创建时赋给子进程，不把 Job 的操作句柄继承给
引擎。主线程保持挂起，所有权进入 EngineProcess 后再核对 Job 成员关系、实际映像
文件身份、完整原生用户会话、完整性级别、AppContainer 和受限标志，检查取消及原有期限，最后恢复线程。
这不新增工作流重试或放宽任何原有 IPC、停止、恢复期限。

进程等待仍使用保留的内核句柄；退出状态仅在句柄已发出退出信号后读取，不把 259
这一合法退出码本身当作存活判断。任一启动阶段失败继续保留同一资源所有者，并通过
原来的恢复代理、停止进程、关闭控制 I/O 顺序退出。创建成功后至所有者接管前没有
新的可失败操作。Windows 10/Server 2016 起支持创建时 Job 列表。

新增真实引擎对照测试：默认 Command 启动必须复现未选定事件句柄的继承；新路径在
引擎仍存活时必须证明同类事件未被继承。两侧运行同一字节身份的实际引擎，且验证
含空格、Unicode 的程序路径与工作目录、控制协议和最终退出。旧控制进程树与事件
会在断言之前回收，原有九项原生引擎检查保留。Windows 全目标、全特性 Clippy
已通过。

`e6d2c43` 的 [Windows CI](https://github.com/billlza/cfw-rs/actions/runs/39283413997)
四项作业通过，源码、下载哈希及回执已核对。10 项原生引擎测试通过，包含实际默认
继承反例、新路径排除事件句柄、Unicode 路径和控制/退出检查；575 项 Rust、311 项
UI、35 项 SCM、1 项保留句柄准入和 2 项诊断夹具测试也通过。两种真实代理模式
仍完成 Ready/Stopped、原代理恢复和退出，SYSTEM Job 计数分别为 3、1、0；嵌套
Job 没有因创建时赋值而失去观察。七次心跳和一次预期错误绑定拒绝均有回执。
全局清理其余条件继续为夹具注入，不能称为完整服务恢复或发布验收。

该阶段的零权限保留句柄尚未加入产品 Bind 回复或引擎清单；后续集成见下一节。
参考 [进程属性与 Job 列表](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)。

### Bind 到引擎的运行引用

新增产品 RuntimeKeeper：SYSTEM 将实际 UserAgent 纳入 Job 后，先向这个已认证且
保留身份的进程复制零权限、不可继承的引用，再提交 Bind 并回传数值。该数值只在
接收者进程内有效，不写入日志，也不能由服务按旧数值远程关闭。任何部分失败仍保留
恢复责任；未接管的引用最终由专用 Agent 进程退出回收，不重放不确定的传递。

初次实现 `71d953b` 的原生 [CI 39293779917](https://github.com/billlza/cfw-rs/actions/runs/39293779917)
在接管阶段失败：普通用户 `OpenJobObjectW(0)` 仍被 SYSTEM 专有 ACL 拒绝，错误为
Access denied (5)。SCM 失败产物 `12207271617` 已核对源码和 SHA-256
`a35285b76e495b5105d52d1ce60992b8ee3cdfa2be552bad9ef93a32b9560df8`；不能把这次
失败改述为原生验证通过，也不能放宽 Job ACL 规避问题。

修正后客户端先校验协议、请求、上下文及原生服务/自身身份，再保留自己的零权限
副本。它在同一认证连接、原始截止时间内发送 ConfirmRuntimeKeeper；SYSTEM 从已
认证的实际 Agent 复制该引用，以 CompareObjectHandles 与本次 Job 核对。确认仅
接受原连接、原租约和 Starting 状态，且不得重复；Ready 必须等待确认。
客户端确认成功后核对原引用仍指向同一对象，才关闭传入引用。错误对象只释放新建
副本，不关闭调用方的原始句柄。失败或不确定传递不会重试，也不远程关闭旧数值。
接收者原生引用不能重新序列化；纯协议解码的 Bound 元数据不能生成 RuntimeKeeper。

UserAgent 在凭据解析前保留引用，并向实际 Go 引擎的明确句柄清单加入一个零权限
继承副本。重新打开 Authority 时会保留已验证的查询句柄，仍处于 Recovering，
不恢复票据或执行租约。活动 Job 缺失仍是 Unavailable，不能仅凭“可能已退出”
构造 Off。Windows 开发协议升为 v3、日志载荷升为 schema 5；旧版本明确拒绝，
没有自动迁移或重置路径，CFM 已发布协议保持不变。

原生夹具使用真实两种代理模式，主动丢弃 Agent 引用，然后关闭所有服务 Job
句柄；新控制器必须靠实际引擎持有的副本重开观察，并继续拒绝活跃运行的 Off。
随后恢复正常监督以核对退出计数。另行验证错误对象不关闭、原生对象身份、旧协议、
缺失/重复/非法句柄字段和纯解码不能接管资源，并实际尝试在确认前报告 Ready，
要求 Identity 拒绝。Windows 全目标全特性 Clippy 与 76 项可移植测试已通过；
修正路径的原生结果如下。

代码 `4dee51b` 的 [Windows CI 39295163565](https://github.com/billlza/cfw-rs/actions/runs/39295163565)
四项作业全部成功。577 项共享 Rust、311 项 UI、10 项原生引擎、35 项 SCM、1 项
保留句柄准入和 2 项诊断测试均通过。22 个协议请求包含 8 个预期拒绝，确认前的
Ready 被实际拒绝；256 次连接压力检查在 20.091883 秒内完成，45 秒上限未放宽。

已下载并逐项核对源码身份、ZIP SHA-256 和严格回执字段：

- 服务产物 `12208255112`：`6e5205381b5e646bf67689a1882a596b8bf7c8051a9eb28ec89076cc49b8a595`。
- 引擎产物 `12208085694`：`e556298a62d2b0a3e6f35342a94356b3359ff1cb4f614f14c292391ce462ba38`。

真实 LocalProxy、SystemProxy 各完成 Ready/Stopped、原代理恢复和退出；每种模式
Job 计数均为 3、1、0，合计 8 次心跳、1 次预期错误绑定拒绝。Agent 引用及所有
服务 Job 句柄关闭后，实际 Go 引擎的零权限继承副本保留了 Job 名称；新控制器
成功重开查询，并在活跃计数非零时拒绝 Off。计数未附全部成员身份，不能据此
推断第三个进程的角色或所有后代生命周期。全局清理的其他条件仍由夹具注入。

这覆盖引用丢失和控制器重开，不等同于完整 SCM 进程崩溃/重启验收；旧用户代理
恢复、生产全局清理证据、完整应用工厂和发布验收仍是开放项。
参考 [无权限要求的内核对象比较](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-compareobjecthandles)。

### SCM 进程崩溃与真实代理恢复

新增单独的 `--runtime-restart-validation` 场景，正常两模式用例继续保留。使用
真实 SystemProxy、独立的普通用户 Desktop/Agent 和同一 Go 引擎。Desktop 完成
Ready、HTTP 代理流量及控制器认证后，测试协调器只对本次临时 SCM 服务注入崩溃。
它保留旧进程句柄，核对 SYSTEM 身份和内核对象，等待实际退出并检查指定退出码；
随后启动同一个服务条目，等待 SCM Running 并确认新进程对象。

恢复路径读取同一个受保护的日志目录和系统记录，不重新创建随机运行作用域，
不把已恢复运行当作首次安装清理。新进程必须保留原 Active 元数据、完整用户
身份和配置摘要，同时保持 Recovering、无可执行租约；新运行分配必须被拒绝。
若 Agent 已先完成本地清理，Job 名称缺失仍记录为 Unavailable，不能变成零计数。

Agent 和 Desktop 必须保留真实的控制通道丢失错误，不能伪造 Stopped 确认或产品
成功。验收另外持有 Agent/引擎进程句柄，核对退出、端口重新绑定、原 WinINet
设置恢复及 Agent 日志移除。失败诊断和重启前后快照随产物保留。此场景仍不提供
生产全局清理证据、旧登录会话恢复或完整安装服务入口。

初次 [CI 39298269875](https://github.com/billlza/cfw-rs/actions/runs/39298269875)（`c5f5d17`）
的 10 项原生引擎和正常两模式生命周期通过，但重启场景失败。服务已正确返回新
运行分配的 Recovering 拒绝；夹具回复后只允许 Ticket/Stale/Identity，把该预期
拒绝误判为致命错误，关闭了服务，后续 OwnedLease 因管道关闭失败。Agent 的实际
控制丢失及本地代理恢复报告保留，完整重启验收未通过。

失败产物 `12210915791` 的 SHA-256 为
`520360bcbb8a1065a8148782633c326b93ea1d7bced0bec5786ad3289796908f`。
当时的失败上传规则遗漏重启快照 JSON，不能事后补造。修正只允许恢复场景中该
明确分配请求的 Recovering 拒绝继续连接，并补齐失败快照上传。临时服务清理遇到
1061/1062 时必须重新观察到 StopPending/Stopped，再等待真正停止及原进程退出；
其他错误仍失败；产品拒绝规则和退出断言保持原要求。

修正代码 `161d928` 的 [Windows CI 39300114644](https://github.com/billlza/cfw-rs/actions/runs/39300114644)
四项作业全部成功；577 项共享 Rust、311 项 UI、10 项原生引擎、35 项 SCM、1 项
保留句柄准入和 2 项诊断测试通过。原两种代理模式仍完成正常生命周期与 8 次心跳。
256 次连接压力检查在 20.082862 秒内完成。已下载并核对源码、ZIP 哈希及完整回执：

- 服务产物 `12211761907`：`812ae6c40cd2866ee5b6814e79ea0664f971f0665390db8ef88a10bd06d53620`。
- 引擎产物 `12210658274`：`1adb93d52583c6027726ead0fc2f89c31900e409b1bd5da6ed32aa421b8241d9`。

本次实际终止并观察到旧 SYSTEM 服务进程 1040 退出，新服务为不同内核进程对象
9252。新服务重开同一运行 Job 时仍观察到 3 个活动成员；持久化 Active 元数据
逐字段保持一致，服务快照为 Recovering、revision 5，执行租约未恢复。之后的
运行代数分配和 OwnedLease 分别被 Recovering、Identity 拒绝。

Agent 和 Desktop 的产品操作都保留断连错误。Agent 本地恢复原 WinINet 设置、
移除代理日志并结束引擎，但没有 Stopped 确认；Desktop 另外通过已持有句柄观察
Agent/引擎退出，核对原代理设置并重新绑定两处监听端口。测试成功表示这些故障
语义得到验证，不能把产品错误改称成功。本次重启场景未再次记录完整 Job 的最终
零计数，也没有生产全局清理证据，因此仍不能发布 Off 或认定完整服务恢复完成。

参考 [进程终止与退出观察](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
及 [SCM 启动与状态观察](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)。

### 持久化代理恢复观察与稳定运行目录

产品新增 `UserRuntimeStorage`，由受信安装层提供当前用户目录，固定保留 `engine-v1`
与 `proxy-v1`，通过持有私有目录句柄防止运行/清理期间路径被替换。启动消息不携带
存储路径；LocalProxy/SystemProxy 继续使用原引擎所有权，未支持模式仍明确失败。
Agent 正常退出后不删除这一生产存储。普通与 SCM 崩溃场景都已改用此路径。

WinINet 恢复现在先写入最多 4 KiB 的单份恢复记录，再重新读取实际设置、删除活动
日志。记录绑定用户 SID、完整运行上下文、配置身份摘要及原引擎 PID/创建时间，只
保存原设置的版本化 SHA-256，不保留原 PAC/server/bypass 字符串。摘要采用显式
长度和原始 UTF-16，固定测试向量覆盖非 Unicode 的原生选项。写入/删除不确定时
仍报错并保留清理责任，不能由日志缺失推出已恢复。

新的 `observe_restoration` 每次重读私有记录与实际 WinINet 设置；活动日志仍在、
记录缺失/损坏、上下文或摘要不匹配、外部设置改变均不能产生恢复观察。返回类型
无公开构造器和反序列化入口；历史 PID/创建时间不是进程已退出的证据，也不代表
全局 Off。

新增原生用例在记录发布后、活动日志删除前注入中断，要求明确失败并在重新打开
后完成恢复；另核对外部设置改变会使旧记录失效。Desktop 将在 Agent/引擎实际
退出后重开生产存储，把恢复记录中的 PID/创建时间与保留的引擎内核句柄比较。
SCM 重启场景还会独立观察整个 Job 的最终零计数，缺失 Job 仍是错误。

默认特性与全特性 Windows 交叉 Clippy 已通过。代码 `d3a4070` 的
[Windows CI 39305301320](https://github.com/billlza/cfw-rs/actions/runs/39305301320)
四项作业全部成功：579 项共享 Rust、311 项 UI、11 项原生引擎、35 项 SCM、1 项
保留句柄准入和 2 项诊断测试通过。256 次连接压力检查在 12.981767 秒内完成。
原两种代理模式保持 Ready/Stopped 与 8 次心跳，恢复记录的中断、重开、身份绑定
及外部设置变化拒绝均经原生执行；固定 UTF-16 摘要测试向量也通过。

已下载并严格核对源码身份、ZIP 哈希、原生用例和报告字段：

- 服务产物 `12213980964`：`1b54b20deca261c757c07f1674f016509cea4f6b21c4b6d0c75b62f998390c74`。
- 引擎产物 `12213482988`：`bd7cb200c71645da63d59cc8c84535c4f7e53783e30cc88657ced57ae5d862cf`。

实际崩溃的服务进程为 832，重启进程为 9924；新服务重开同一 Job 时活动计数为
3，随后独立观察到活动计数 0、累计成员 3。Desktop 在保留句柄证明旧进程退出后
重新打开稳定存储，核对了恢复记录的完整上下文、配置身份及历史 PID/创建时间，
并重新查询当前用户的 WinINet 默认连接选项。普通与崩溃两种 SystemProxy 路径
均通过这项检查。上述观察未生成全局 Off，产品控制丢失错误与无 Stopped 确认
继续保留。服务重新打开时 Job 名称已消失的恢复分支仍未完成，不能用本次成功
推断该分支安全。

WinINet 观察保留在当前用户进程中，接口作用域参见
[设置与读取连接选项](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)。
服务侧恢复专用授权、这些观察到生产 CleanupEvidence 的接线、缺失 Job 的恢复、
完整应用/界面和发布验收仍未完成。

### 代理恢复观察的服务准入

Windows 控制协议 v4 增加独立的 BeginProxyRecovery / ConfirmProxyRecovery。
只有当前真实控制台用户的已验证 Desktop 映像可申请；目标必须逐字段匹配已知
Recovering 元数据的运行根、revision、operation/lease、两份配置摘要及原完整
SID/LUID/session。允许同一账户的新登录会话提供清理观察，但保留新旧两份完整
身份，不能继承旧执行租约；本次仅支持 SystemProxy 的恢复观察。

服务在签发和确认时分别重新观察原运行 Job，必须得到真实活动计数 0。缺失 Job、
Preparing 的 NeverAuthorized 或未知日志不能代替这个观察。凭据使用独立摘要域，
绑定同一连接，最多存活 10 秒；所属连接的一次确认尝试即消耗凭据，其他连接不能
消耗它。服务重启、状态发布或进入恢复会丢弃未完成凭据，不重放不确定投递。

产品客户端收到凭据后才重新读取稳定存储与当前用户 WinINet。服务对该已验证
用户进程的报告重新准入，独立复查 Job，并向监督层提供无公开构造器/反序列化
入口的 ProxyRecoveryObservation。它证明的是有来源及时间边界的代理恢复观察
和进程退休；记录中的历史 PID/创建时间本身不是退出证据。该观察没有生产
CleanupEvidence 转换，不改变 Recovering，不授予 Ready、启动或全局 Off。

本地 82 项 Rust 测试与默认/全特性 Windows 交叉 Clippy 通过。反例覆盖同账户新登录、
不同账户/角色、旧身份或两份摘要被改动、换连接、过期、错误凭据及未知持久状态。
SCM 崩溃原生场景新增真实往返、伪造报告/换连接/重放拒绝及执行权限未恢复的
检查。

代码 `bd4700f` 的 [Windows CI 39310240567](https://github.com/billlza/cfw-rs/actions/runs/39310240567)
四项作业全部成功：585 项共享 Rust、311 项 UI、11 项原生引擎、35 项 SCM、1 项
保留句柄准入和 2 项诊断测试通过。256 次连接压力检查耗时 19.107791 秒；正常
两模式仍完成两次 Ready/Stopped 与 8 次心跳。已核对源码、ZIP 哈希及完整回执：

- 服务产物 `12215353367`：`6b5493981a76e1caf111166633745698a1e65bc7bdba4808a375de1cd4b5b33e`。
- 引擎产物 `12216815663`：`1cfb40d808f3249acd2b8d4313f09fa92ea4d59a96e1a086d66323b5ff67e5cb`。

实际服务进程从 8924 崩溃并重启为 3168；同一运行 Job 的活动数从 3 降到 0。
恢复确认再次独立观察到活动数 0、累计 3，收到的用户代理记录指向原引擎 4072，
原上下文、两份配置摘要、完整用户身份及 revision 5 均保持一致。不匹配目标、无
正确凭据的伪造报告、同进程新连接和已消耗凭据重放均被拒绝；合法确认后仍为
Recovering，Ready 和 OwnedLease 被拒绝。实际原生场景使用同一登录会话；跨
登录身份规则由策略测试覆盖，不声称完成 Windows 用户切换验收。

完整清理监督层、缺失 Job 恢复、安装服务入口及 Windows 真机验收仍未完成。
PR 仍保留 `21505a8`，其 Mac 作业 `39289426252` 尚在排队；本次 Windows 验证来自
独立分支 `lza/cfw-0.5.0-proxy-recovery`，不代表 PR 当前头或完整双平台验收。

### SystemProxy 恢复的生产 Off 提交

新增 BeginProxyCleanup / ReconcileProxyCleanup，使用与只读恢复观察不同的凭据
用途。当前协议为 v6，目标、当前观察者和用途一起绑定；观察凭据不能升级为清理
凭据。确认必须在原连接和原有效期内完成，消费后重新打开整个运行 Job、重新
确认调用者，并检查当前 Authority 已无执行租约、未消费凭据或已确认运行授权。
分发器在完成类型解析和原生准入后擦除完整原始读取缓冲区，保留请求/连接序号
用于唯一回复。类型化凭据在进入 Off 提交前已经销毁。

生产 CleanupEvidence 现在绑定完整运行根、revision、操作、租约、原用户身份和
两份摘要。进程组退出与独立的 IPv4/IPv6 TCP 监听表查询共同验证监听器关闭；
私有运行 IPC 和运行期地址空间随整个进程组退出而结束。
用户进程提供新鲜 WinINet 恢复观察，服务检查自己的授权与待处理材料。无 TUN
条件仅适用于有明确资源契约的代理模式，不能套用于 Tunnel 或组合模式。通过
全部检查后复用现有日志事务提交 ReconcileOff，再次确认调用者；提交或回复不
确定仍返回错误，不重放请求、不恢复旧租约。

为使上述资源契约成立，原始 Windows 代理请求必须拒绝系统 WireGuard 接口、
其他 endpoint 类型、额外服务/顶层区段及额外 experimental 入口。共享 CFM
投影的用户态 WireGuard 仍通过。旧校验的反例已实际失败（LocalProxy 接受了
带 `system:true` 的 endpoint），收紧后包含两个代理模式的负例与合法 WireGuard
正例通过。`system` 的含义参见 [WireGuard endpoint 文档](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)。
日志升级至 schema 6；旧开发日志不能证明这项资源边界，因此明确拒绝，没有
自动重置或假定已清理的迁移路径。原始配置校验失败不等于曾实际创建系统接口。

本地 Rust 测试和默认/全特性 Windows 交叉 Clippy 验证这一变化；逐项缺失清理
条件均不能释放旧运行。SCM 崩溃场景保留
原有只读观察/拒绝重放验证，随后申请独立清理凭据，重新观察并要求生产证据
提交 Off、旧租约仍不存在、重放被拒绝且下一次查询一致。首次安装/已退休日志的
Off 准入、正常停止接线、全部观察者丢失后的恢复、
TUN/组合模式、完整应用与发布验收仍未完成。

初次代码 `f68d855` 的 [CI 39314462021](https://github.com/billlza/cfw-rs/actions/runs/39314462021)
共享、目录与 SCM 作业成功，11 项原生引擎及正常两模式流程通过；重启场景失败。
旧服务 7144 退出后，Agent 已完成代理恢复并退出，新服务 7504 重开时 Job 名称已
消失。它正确保持 Recovering/Unavailable；夹具随后要求读取全 Job 退休证据而
失败，未运行新的 Off 提交。失败产物 `12217409267` 的 SHA-256 为
`a9aeaa338a7bcb30d04f54b94bbf0f6066112a275f3837309f314174a9bde57e`，原始错误和
重启快照完整保留。不能通过把名称缺失解释为零计数来修复。

产品新增 Desktop 专用 RetainRuntime / ConfirmRuntimeReference。原准备连接只能
在 Active 后领取一次零权限、不可继承的 Job 引用，沿用原生对象比较后才接管
句柄的验证方式；无公开原始句柄构造器，也不能转换成执行授权。DesktopReady
发出前必须完成验证，并把引用交给监督层持有到独立清理结束，包括工作线程
返回错误之后。DesktopStopped 也保留该引用。不确定投递不重试、不远程关闭
可能已被复用的数字句柄；未认领引用最终随接收进程退出关闭。

既有 Ready 期间的引擎独立保留引用测试仍在桌面领取前执行，保持原隔离条件。
新的重启用例以保留内核句柄观察 Agent/引擎退出，桌面继续持有产品引用，再
允许 SCM 启动替代进程；新服务必须在这一更晚时序重开同一 Job 并观察到真正
的零活动计数。夹具协调者没有替产品持有 Job 句柄。该修正仅覆盖桌面监督层
仍存活的情形；若桌面与服务等全部独立观察者都消失，名称缺失仍是未知。

修正代码 `ef66d32` 的 [CI 39319065000](https://github.com/billlza/cfw-rs/actions/runs/39319065000)
最终四项作业成功：595 项共享 Rust、311 项 UI、11 项原生引擎、35 项 SCM、1 项
保留句柄准入和 2 项诊断测试通过。正常两模式仍完成两次 Ready/Stopped 与 6 次
心跳，原引擎引用隔离检查通过；256 次连接压力检查耗时 12.280625 秒。

该源码首次引擎尝试在 `go list` 下载固定 Brotli 1.2.4 依赖时遭遇官方 Go 代理
HTTP/2 `INTERNAL_ERROR`，尚未运行原生测试。错误日志及失败产物 `12219780932`
保留，SHA-256 为 `1cca84baf8d3755412e61c5215b6d3622c61fc8bbeefc8abd0717278f6d6d998`。
完整运行结束后仅请求重跑失败引擎作业一次；源码、依赖、哈希检查和断言不变。
第二次引擎尝试成功，已下载并核对源码、ZIP 哈希、闭合字段与全部原生回执：

- 服务产物 `12218642848`：`70e7e99e32963678143725f25520e79db9873aac1b196856b0a68ae34c923eee`。
- 引擎产物 `12218894665`：`5bb1b1e2e128c6ca6e72e6ce9150b2b93bcaef7f5f5f3ec811d3b9e3c2e374ad`。

实际旧服务 2264 被终止；桌面通过保留句柄确认 Agent/引擎先退出，继续持有产品
运行引用后，SCM 才启动新服务 2040。新服务重开原 Job 时已是活动 0、累计 3，
仍保持 Recovering、revision 5。只读恢复观察和各项拒绝验证后，独立清理请求
再次核对代理恢复、原生监听器、进程及 Authority 状态，实际提交 schema 6 的
ReconcileOff、revision 6、operation null，随后新查询确认 Off。旧执行租约仍
不存在，确认重放仍被拒绝。此时的 Off 来自生产清理路径；初次安装和正常停止
夹具仍有各自明确标注的验证注入，不能据此声称完整 Windows 服务/应用已完成。

### 首次安装与已停止记录的生产启动准入

`e8d0e61` 新增 `WindowsAuthority::verify_recorded_off`。服务打开日志后仍从
Recovering 开始；只有已知、完整、无操作的 schema 6 Off 记录，且监督器没有
残留租约、进程所有者、清理挑战或运行引用状态时，才进入启动核验。核验前后
重读受保护日志，比较完整元数据，包括已分配但未使用的 generation；陈旧快照
或读取失败使当前 revision 变成未知，必须显式重读，不能重新登记安装身份。

回执区分 `NoRuntimeRoot`、原生 Job 零活动计数与 `DurablyRetired`。从未启动的
安装记录及未使用的分配保留原 revision；已停止过的运行通过日志事务提交下一
个 ReconcileOff。`DurablyRetired` 代表此前持久提交的清理证明，不伪造当前进程
计数；也不把用户在停止后自行修改的网络设置变成应用拥有的资源。活动运行、
中间状态、隔离状态和不确定日志不能通过这个入口取得执行权限。

原生服务夹具的首次启动已改用该生产入口。新增验证包括日志分配后拒绝旧快照、
保留未使用的分配、活动运行拒绝启动准入，以及真实 SystemProxy 恢复到 Off 后
释放全部运行引用再重新打开。后者还在提交锚点后注入失败，要求错误及未知
revision 保留，重读后再次核验才允许 Off。正常停止夹具仍使用明确标注的清理
注入，完整服务入口、安装根路径、Windows 后端与 TUN 接线仍待完成。

本地 96 项可移植测试、Windows 目标默认及全部特性 Clippy、格式检查通过。
[Windows CI 39325028204](https://github.com/billlza/cfw-rs/actions/runs/39325028204)
四项作业全部成功，600 项 Rust、311 项 UI、11 项原生引擎、35 项 SCM、1 项
保留句柄准入和 2 项诊断检查通过，无失败或忽略。新增五项启动策略测试已在
Windows 执行；服务产物含三份生产启动回执，验证初次登记、陈旧快照拒绝和
未使用分配的保留。256 次连接检查耗时 19.149284 秒，原 45 秒边界保持不变。

实际旧服务 8256 退出后，新服务 2436 完成原有恢复清理并提交 Off revision 6。
Desktop 释放产品运行引用后，监督器重新打开同一日志，从 Recovering revision 6
开始。注入的锚点提交后失败使调用返回错误、revision/root 变成未知，直接重试
被拒绝；显式重读取得已提交的 revision 7，仍无执行租约。再次通过生产准入后
提交 Off revision 8，安装身份、epoch 和 generation 均保持，进程依据明确为
`DurablyRetired`，没有伪造原生零计数。正常两模式回归仍完成两次 Ready/Stopped、
六次心跳与 3→1→0 的 Job 活动计数。

产物源码身份、ZIP 哈希、闭合回执字段与日志已核对：

- 服务产物 `12221293026`：`edca03ae1ac6446d287e5cada19cd04a3718840f3ad8bda4efad07bc7a5240dd`。
- 引擎产物 `12222042605`：`bcb576ef3ec5824a3595283e1e8e6bad1a59d8873a5af2b6637bad9ecde2f5b0`。

本阶段记录时，PR 的旧源码 `21505a8` 对应 Mac 原生构建仍在执行，质量和供应链
作业已通过；保留其执行，不把该旧源码检查归给本次 Windows 改动。

### 正常 LocalProxy/SystemProxy 停止的生产清理

`d2e75cc` 接通 SystemProxy 正常停止：原 Desktop 连接在 Agent 确认停止并实际退出
后，使用现有清理挑战读取持久恢复记录和当前 WinINet 设置；SYSTEM 再独立查询
完整 Job、监听器及清理范围。停止中的租约和身份保留至 GlobalOff 提交；只读
恢复用途仍不能代替清理用途，同用户的新连接不能接管原停止连接。状态查询在
确认停止后允许 Agent 正常退出，仍返回 Stopping，不能由此直接推导 Off。

`34616bd` 随后补齐 LocalProxy 的独立生产构造器。它限定为 schema 6、内存中
已确认停止的 LocalProxy 租约和精确持久记录；必须重开同一 SYSTEM Job 并观察
所有成员实际退出。该模式的配置验证排除系统接口、额外服务和 TUN，固定引擎
及启动协议不向进程树外转移 socket；此前模式必须先完成 Off 才能开始这一代。
因此在这个受限资源契约内，整棵进程树退出可以证明其 TCP/UDP、私有 IPC 和
内存资源释放，不把这套依据用于 SystemProxy、TUN 或丢失内存租约后的恢复。
此推导依据 Windows 的[进程终止资源语义](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process)
与[Job 计数定义](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)，
还须由项目原生运行核验。新用例在 Agent 已确认停止、但仍存活时调用生产清理，
要求显式拒绝并保留原状态；退出后才允许提交 GlobalOff。

本地 104 项可移植测试、Windows 目标默认和全部特性 Clippy、格式检查通过。
两种真实运行模式均已移除全局清理证据注入；单独的合成协议策略夹具仍保留明确
标注的注入，不混入产品路径。Windows 协议仍为 v6，日志仍为 schema 6。

首轮 `d2e75cc` 的 [CI 39327432725](https://github.com/billlza/cfw-rs/actions/runs/39327432725)
共享、目录与 SCM 作业成功，11 项原生引擎测试通过；正常运行夹具随后失败。
SYSTEM 进程 5572 正确发送活动运行的预期拒绝后，外层夹具未收到对应预期标记，
误把该拒绝当作未预期错误并退出。随后凭据 GC 不可用、Desktop 服务连接和
Agent 退出失败均为下游症状。原始日志与失败产物 `12223052157` 已保存并核对
SHA-256：`53ab5044fd3025a7665f1f53d15a9a60cde945a53f7df0fa26c95ded1018d403`。
`4ffd200` 只为内部已核验的这一拒绝分支传递预期标记，其他错误继续失败；没有
扩大通用允许列表或删除断言。后续 LocalProxy 改动一起在
[CI 39328785913](https://github.com/billlza/cfw-rs/actions/runs/39328785913) 验证，四项作业成功。
608 项 Rust、311 项共享 UI 契约、11 项原生引擎、35 项 SCM、1 项保留句柄准入
及 2 项诊断检查通过；八项新增停止策略测试已在 Windows 实际执行。服务压力
检查完成 256 次交换，耗时 18.965622 秒，仍使用原 45 秒边界。

下载回执显示：LocalProxy 的 Agent 仍存活时，生产清理被拒绝且状态保持；整个
Job 活动数归零后提交 GlobalOff revision 8。SystemProxy 正常停止先保持
Stopping revision 14；活动清理和同用户新连接均被拒绝，原 Desktop 连接通过
当前代理恢复、PID 4664 的监听器和 Job 核验后提交 GlobalOff revision 15。
两者保留各自根身份、移除操作和租约；回执明确 `injected_cleanup_modes: []`。
两次 Ready/Stopped、九次心跳及两组 3→1→0 Job 计数均通过。原有真实服务崩溃
恢复与 Off 重开/提交后故障注入也通过，未被正常停止实现替代。

源码身份、ZIP 哈希、闭合字段和相关日志已核对：

- 服务产物 `12223533168`：`ea7255fc51df6be9cd1265898464bf56b21ecba3e342e874a81096df598e2988`。
- 引擎产物 `12223279673`：`6a18c17662cb201a0d5c0e224dcdba8be2686b682729991ed8ad225b626dac3b`。

这些是原生组件证据；生产安装根、服务/Agent 入口、完整 Windows 后端与桌面
接线仍待完成。LocalProxy 无内存租约时的恢复、全部独立观察者消失、重启、TUN、
组合模式、原生 UI、安装更新签名及真实 Windows 会话/睡眠唤醒仍需独立验收。

原 PR 旧源码 `21505a8` 的 [Mac CI 39289426252](https://github.com/billlza/cfw-rs/actions/runs/39289426252)
已完成，三项作业成功。日志核对了 1,225 项质量作业 Rust 测试、311 项 UI 测试、
11 项原生作业 Rust 测试、零错误/警告的供应链策略，以及 build 50000 的未签名
候选应用与清单验证。该运行没有上传可下载的应用产物；也没有建立安装后运行
或发布验收。其结论属于旧提交，不能代替本轮源码的 Mac 回归。
此前 Mac 最大配置探测的两次失败（`39188386401`、`39203816762`）仍未确立根因；
后续成功不能抹去这项独立的发布验收问题。

### LocalProxy 服务崩溃后的生产恢复

`c6cf67e` 新增可信服务监督入口 `reconcile_local_recovery`，与正常停止共用
LocalProxy 的资源核验及事务提交，但不从磁盘重建旧租约或停止确认。它要求已知
的 schema 6 LocalProxy 记录、Recovering 状态、已清除的执行材料，以及重新
打开的精确 SYSTEM Job 的零活动计数。缺失 Job、不确定日志、存活成员、其他
模式或已完成 Off 都不能取得这份证明。对 Active 等恢复记录，成功提交的是
ReconcileOff；正常停止仍要求内存中的停止确认并提交 GlobalOff。Windows wire
v6 和日志 schema 6 均未改变，没有新增由用户提供清理事实的协议命令。

SCM 崩溃夹具现在分别运行两种真实代理模式。LocalProxy 使用独立的安装根和
`local-restart/` 产物目录，复用相同的进程对象核验、服务终止、旧 Agent/引擎退出
屏障、Desktop 产品引用和新服务恢复流程。服务重启后先保留原 Active 元数据，
拒绝执行分配并确认没有旧租约；随后夹具只触发可信监督入口，不提供资源 ID
或清理布尔值。新查询必须读到精确 Off，重复恢复不得推进 revision。旧运行的
控制丢失仍作为错误保留，LocalProxy 全程不能改变系统代理设置。现有正常两
模式和 SystemProxy 崩溃场景继续运行；还新增了活跃 LocalProxy 的恢复拒绝。

本地 106 项可移植测试、Windows 目标默认/全部特性 Clippy 和格式检查通过。
[Windows CI 39332507944](https://github.com/billlza/cfw-rs/actions/runs/39332507944)
四项作业通过，日志确认 610 项 Rust、311 项 UI、11 项原生引擎、35 项 SCM、
1 项保留句柄准入和 2 项诊断检查。正常两模式完成九次心跳；服务压力检查
256 次交换耗时 21.401538 秒。已下载并核对两份产物源码、哈希及闭合回执：

- 服务产物 `12224454041`：`b52a8cd4951ea7a748cb9cf605d1e87ad750143f59b31a46f3ea1b32363c1f62`。
- 引擎产物 `12226175748`：`f31cc96acd7f755addbe32cb553ee45c5b31d36d980747d461a1bf90dfee9e65`。

LocalProxy 实际旧服务 5476 被终止，Agent/引擎先退出，Desktop 保留产品引用后，
新服务 2092 重开原 Job。原 Active revision 5 和完整身份保持，没有执行租约；
生产监督入口核验实际零计数后提交 ReconcileOff revision 6，新客户端查询确认
Off，重复调用被拒绝。随后释放引用、重新打开 Off、提交后故障注入与显式重读
的测试同样通过；系统代理设置保持不变，原运行控制丢失错误仍被保留。
此实现仍依赖可观察的运行 Job；
全部独立观察者消失或整机重启的恢复，以及正式安装/服务入口、桌面后端、TUN、
原生 UI 和发布验收都没有由这次改动自动完成。

### 正式安装运行宿主（2026-10-20，源码已实现，原生验证进行中）

`5322e15` 新增默认构建的 `cfw-windows-runtime.exe`。无参数启动通过 SCM
ServiceMain 注册正式 `CFWAuthority` 服务；`--user-agent CFWAuthority` 在当前
普通用户进程接收已认证的继承管道、同一共享启动请求及凭据槽，使用正式引擎
和持久用户目录启动。宿主不把验证夹具编入产品入口，也没有路径/服务名的前端
覆盖参数。`--check-installation` 只读验证安装身份，不启动服务或网络。

安装根由 Windows Known Folder API 定位为 Program Files 下的 `Clash for Windows`。
固定文件为 `runtime-installation-v2.json`、`cfw-windows-runtime.exe`、
`Clash for Windows.exe` 和 `cfw-engine-host.exe`。安装清单闭合字段、限制 4 KiB，
绑定产品版本、x64、引擎版本和三个 SHA-256；路径及服务名不来自清单。先核对
打开的安装目录/清单所有者及 DACL，仅允许 SYSTEM/Administrators 写入，再读取
清单；可执行文件同样检查写权限、PE 架构、哈希及保留的文件身份，拒绝重解析
点、硬链接和替换。清单是受保护安装的内容索引，发行者验签仍属于尚待完成的
安装/更新流程，不能把哈希或 ACL 本身当作已签名发行包。

SYSTEM 日志和有界诊断位于 ProgramData 私有目录；普通用户的凭据与运行状态
来自 LocalAppData 私有目录。服务保留同一生命周期锁直至回复完成，连接数量
沿用传输层的上限，关闭时取消并收回 I/O；错误保留到有界诊断。SCM 停止请求
先禁止新准备/分配并撤销运行，保持认证清理通道可用；实际 Off 后才进入
StopPending。30 秒内无法确认全局清理则显式失败，不能用停止服务进程制造 Off。

`fb2cfde` 接上安装态的完整运行验证：临时安装正式服务/Agent 和固定引擎，以
受限中完整性测试桌面启动两种代理模式、执行 HTTP 代理流量、等待 Agent 退出、
恢复代理并查询全局 Off；再实际重启服务，核对持久 lineage 和 SCM/进程退出。
错误的桌面哈希和允许普通用户写安装清单都必须被拒绝。测试桌面仍是夹具，
不构成实际 Tauri UI 验收；私有非秘密状态显式保留至一次性 CI VM 销毁，正式
卸载与迁移尚待实现。

本地 107 项可移植测试、Windows 目标 Clippy 和 PowerShell 语法解析通过。
基础安装宿主 [CI 39365853568](https://github.com/billlza/cfw-rs/actions/runs/39365853568)
与新增完整运行链路 [CI 39366212239](https://github.com/billlza/cfw-rs/actions/runs/39366212239)
分别绑定 `c6fdaf4`、`fb2cfde`。两次均通过前置 11 项真实引擎测试，但在安装后
第一次 Desktop 认证查询失败：安装脚本给 SCM 写入了 `--service` 参数，而既有
认证契约只接受带引号的绝对可执行路径、无参数。服务启动成功不代表连接认证成功。
修正产品服务默认无参数进入 SCM，并让安装脚本写入相同命令；保留原认证规则。
`c6fdaf4` 失败 artifact `12239388917` 的 SHA-256 为
`6b9fcd20cd2d5efae5b2e2fc4444c5173c97b8f09466f0f1d36c5ce0cffd4fe4`，
已核验并保存，安装回执只完成三项包校验、没有成功的服务查询。
`fb2cfde` job log 确认同一失败条件。修正后的完整安装运行链路仍待原生 CI。

`400918c` 修正 SCM 命令，验证运行
[39367153298](https://github.com/billlza/cfw-rs/actions/runs/39367153298)。其 shared job
因本次新增错误消息未按 rustfmt 换行失败，已在后续源代码中修正；不能称该运行全绿。
其 engine、SCM、directory jobs 成功。engine artifact `12240330615`（SHA-256
`486c00f9452b1b4a8c2d1731c0ca5ef3a16f13a46c03aaf73f107f851b569f14`）和 SCM
artifact `12239169619`（SHA-256
`6f4944ea361239a0218696109977c5f8b12448f7fbb8c57c951c07f71d373c47`）已下载，
通过完整源码/哈希/回执核验。保留 11 项真实引擎测试、35 项 SCM 验收和已有恢复回归；
新增安装回执通过 8 项检查。实际产品 service/Agent 在 medium-integrity fixture
Desktop 下运行 LocalProxy（Active 5→Off 8）和 SystemProxy（Active 12→Off 15），
真实 HTTP 代理流量成功、Agent 正常退出、监听释放、原代理恢复；随后 SCM 重启保留
generation 2，并重新验证 Off 16。此处 Desktop 仍为测试驱动程序，未验证实际 UI。

### 桌面安装上下文与原生配置预检

`InstalledDesktop` 统一提供受保护安装中的凭据、generation store、运行目录和
Desktop→Agent 准备入口，CI 中两种代理生命周期改为使用这个产品入口。
`8a1e64c` 新增同步工作线程 API `check_configuration`：核对实际 Desktop image、medium token、
当前 Authority installation/epoch、配置摘要与精确凭据 audience，再使用独立 Go
子进程执行 parser/constructor/Close。该路径不 Prepare、不 Bind、不申请 generation，
不启动数据面，也不修改 WinINet；检查互斥、截止时间和失败清理均保留显式结果。

安装验收新增四种模式的真实预检，检查期间保持 mixed/controller 端口被测试方占用，
并验证前后 Authority snapshot、generation 和代理设置完全一致。另检查跨 profile
凭据拒绝、原生非法配置拒绝、异 epoch 拒绝和过期截止时间。TUN 预检通过不等于
Windows TUN 数据面已实现。默认及全 feature Windows cross-Clippy、全工作区格式检查、
107 项 portable tests 通过；新增安装验收由
[39367715770](https://github.com/billlza/cfw-rs/actions/runs/39367715770) 四个 jobs 全部通过。
源码 `8a1e64c` 的日志确认 611 项 Rust、311 项 UI tests，均无失败或跳过。
engine artifact `12240198072`（SHA-256
`eda3aac96451d9c2935749b33623793393df0af5b399b3d9c4f92a6261294b45`）和 SCM artifact
`12239844153`（SHA-256
`713b301a9d83335975349d0e294238d28d1649bbe6a7e02cd080c3a5530a1185`）均已下载并通过
完整源码/哈希/回执核验。四种模式的真实预检、凭据 audience 和非法配置等反例均通过；
检查前后 Authority、代理设置、端口占用和 generation 均符合上述约束。

### 共享 EngineBackend 的 Windows 代理实现

新增 `WindowsEngineBackend`，以受保护的 `InstalledDesktop` 接共享 `EngineBackend`。
LocalProxy/SystemProxy 的配置检查、启动、查询、停止调用实际产品 service/Agent；
配置检查有独立容量，不持有运行状态互斥锁。异步请求和原生线程有界，取消后仍由原有
线程负责清理；原生连接不跨线程转移。失败保留原操作和 Runtime Job 引用，直到重新
观察到独立 Off 并退出原线程；未成功 Prepare 的请求可在旧 generation 的已验证 Off
下释放，但原拒绝仍作为错误返回。

每次运行状态查询经已有继承的双向管道发送新 nonce，Agent 收到后重新观察真实引擎、
监听和 WinINet。Desktop 在回复前后确认实际 Agent 和同一 Authority lease/snapshot。
启动 ACK、旧 Ready、单纯心跳均不作为新鲜运行证明；超时、失联和上下文变化返回错误。
该私有观察协议为 v1，不更改 Authority wire v6、journal schema 6 或已发布的 Mac 协议。
管道使用已存在的 overlapped handle；轮询遵循
[PeekNamedPipe 的异步句柄说明](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe)。

新增安装验收：两种直接宿主模式各三次新鲜查询与退休后查询拒绝；共享 backend 两种模式的
真实流量、精确上下文停止、重复停止；错误 epoch 的 Prepare 拒绝和可继续启动；以及保持
实际进程句柄后终止真实引擎，再验证查询不能返回旧 Active、原失败保留、独立恢复到 Off。
最后一项是故障注入，仅在显式 opt-in 的临时 Windows runner 中执行。五个实际运行
generation 包括原两种宿主模式、两种 backend 模式和一次真实引擎退出反例。

本节对应 `9e3f0b67974d189c552e6ca5c3b8c02bf4b3b3ba`，由
[39370765025](https://github.com/billlza/cfw-rs/actions/runs/39370765025) 验证。
本地默认/全 feature Windows cross-Clippy（warnings denied）、107 项 portable tests、
全工作区格式与 PowerShell 解析检查通过。该运行的 shared job 通过 612 项 Rust、
311 项 UI tests，SCM 和 directory jobs 也通过；engine job 通过原 11 项真实引擎测试后，
安装测试客户端超过既有 60 秒截止时间，包清理同时遇到 engine host 文件仍被占用。
失败 artifact `12241407434` 的 SHA-256 为
`9dcefd5282586e1a59409026d85120c1da410edc0c65cf6456f11a375c91478a`，已下载并核验。
其客户端输出为空，不能据此判定具体卡在哪一步或认定 Agent 没启动；根因尚未确认。

`18c2e1a` 将本地状态请求检查与原有每秒一次的 Authority watchdog 分开，并允许从未
Prepare 成功的已知请求在新鲜全局 Off 下完成后续停止；保持已启动运行的精确上下文。
它由 [39371650203](https://github.com/billlza/cfw-rs/actions/runs/39371650203) 验证，
同样在已通过 11 项原生引擎测试后发生安装客户端 60 秒超时。失败 artifact
`12241433483`（SHA-256
`4588d84db4b2bea8da1d50e3a8b01b62801cc28fc47315207f5fa481ca3f625f`）已下载核验，
客户端输出仍为空；不能把上述源码复核修正归为前述超时的根因。

诊断增量保持 60 秒失败判定，新增即时刷新的有界阶段记录和超时前只读 Authority scope。
阶段与最终报告分别验证，最终报告仍限 16 KiB；附加阶段记录使整体诊断流上限为 48 KiB。
安装脚本保存第一次成功查询，并把客户端执行中断后的 Agent 执行状态记为未知，避免
用未完成的整套测试反推“未执行”。不会通过放宽截止时间或删除断言制造通过。
诊断源码 `f10f1b43fae1e69cdcd4f839f5ca8c5a4488f979` 由
[39373122890](https://github.com/billlza/cfw-rs/actions/runs/39373122890) 运行：
shared、SCM、directory jobs 通过，engine job 仍在安装客户端 60 秒截止时间失败。
失败 artifact `12242048733`（SHA-256
`05c36caed767710d7266c1df2f2e190c51ed066f1e4d97ff6cbb3aef68f4e7c5`）已下载核验。
48 条阶段记录确认前四个实际运行均完成到 Off：generation 1/2 于 17.770/26.468 秒，
backend generation 3/4 于 42.825/55.824 秒。第五次在 57.554 秒才开始；父进程在
60 秒截止后、终止客户端之前观察到 Authority Preparing、generation 5、revision 31。
这次失败可归因于五次运行共享原有单客户端截止时间；尚不能据此证明第五次运行完成，
也不能把该观察冒充早先空输出失败的独立根因证明。

安装验收现分为直接宿主客户端（预检和 generation 1/2）与共享 backend 客户端
（generation 3/4/5），按顺序使用同一安装和服务。每个客户端保持原有 60 秒限制、
全部产品操作超时和断言；后台三次运行仍共用一个 backend 实例。各自阶段与报告必须
独立验证后才能合并，最终报告仍限 16 KiB。源码 `9b64004ceb13ce02fbf8211f95b427ac9bd97298`
由 [39375075507](https://github.com/billlza/cfw-rs/actions/runs/39375075507) 验证，四项作业均通过。
612 项 Rust、311 项 UI、11 项原生引擎、35 项 SCM 均无失败或跳过。engine artifact
`12243775451`（SHA-256
`1fab4c3f7949c53d3fe0c2fc47b7c03c8348f28653af515d61d2db7ecdb5ed8c`）和 SCM artifact
`12242747545`（SHA-256
`d382f5ed533273afcb1373d0a4c8b5ea80dcdf63e645236d459baf83ad8c5bbe`）均已下载并通过
源码、哈希和完整回执核验。两个客户端分别有 24/35 条完整阶段记录，耗时
17.905/29.983 秒。第五次真实运行确认 PID 8424 的原进程对象退出，后续查询返回
OwnerUnresponsive，最终 generation 5 的 Off 为 revision 35；服务重新启动后 Off
为 revision 36，安装身份和 lineage 保持不变。故障没有被改写为旧 Active。

共享 backend 同时实现 `SystemProxyAuthorization`，复用现有 WinINet 策略和所有权日志
检查。安装身份与 medium-integrity 用户检查仍在原生边界，异步入口在切换线程前拒绝
impersonation；沿用有界 worker 容量，不持有运行状态锁。此入口只检查权限与可恢复性，
不申请 lease、不修改设置，激活阶段仍独立重查策略。安装验收增加运行前、SystemProxy
运行中、最终 Off 后的完整/仅恢复授权，并核对 Authority、lineage 和代理设置不变。
本地默认/全 feature Windows cross-Clippy 与格式检查通过；该增量
`036cc1d779083e442cabcfc1d34d72511c82d699` 由
[39375476319](https://github.com/billlza/cfw-rs/actions/runs/39375476319) 验证，shared
612 Rust/311 UI、SCM 和 directory 通过；engine 在新增安装验收之前的 LocalProxy
服务崩溃用例失败。旧服务 PID 9600 已实际退出，新服务 PID 8608 的独立恢复观察已
取得，但 Desktop 收到映像查询 Access denied 后，测试未将其当作已证退出。
失败 artifact `12243820966`（SHA-256
`f8c7c509a33ed60c1abc2964f51c2725640d27dab1d93b9898ee8f009f1fd2a8`）已下载核验；
该运行没有安装客户端报告，不能声称新增授权案例执行过。

源码中存在前置存活检查与映像查询之间的退出窗口。映像查询现在结束后对同一个保留
进程句柄做零等待观察，只有实际 signaled 才返回 Exited；活进程的权限或映像拒绝仍
保留原错误。没有扩大崩溃 fixture 的可接受错误名单，没有把 Access denied 本身
解释为退出。新增原生测试用实际缺少 query 权限的活句柄验证拒绝保留，并用已退出的
测试子进程验证原句柄退出分类。原失败未保留查询瞬间的
退出信号，因此窗口原因仍需结合该回归和完整重跑验证，不能把后来退出反推为当时
已经 signaled。该处理遵循 [进程终止与等待的边界](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)。

`11945b452033716e3dc801bb69d8492431b03b96` 的
[39376793587](https://github.com/billlza/cfw-rs/actions/runs/39376793587) 四项 Windows 作业
通过，614 项 Rust/311 项 UI 无失败或忽略，两项新增原生句柄回归均实际执行。
engine artifact `12242924569`（SHA-256
`198bed368a5fc2919ae46abcaed229f97e2b1bc650c5a88844215d8d5f108a88`）与 SCM artifact
`12244295076`（SHA-256
`a5829c19c4819f48c43e456b8ccc623ff563589ed8aa881c269fd26a7312f8d2`）已下载并经完整核验。
安装客户端 24/41 条阶段记录耗时 19.140/32.913 秒；三次授权分别在 Off/gen2、
Active/gen4、Off/gen5，Authority、lineage 和 WinINet 均未改变。实际终止引擎后查询
返回 Recovering，停止保留 OwnerUnresponsive 错误，随后独立 Off revision 35；重启为
Off revision 36。更新头的 Mac 作业仍排队，不能用 Windows 结果替代。

### 共享节点测速接口

`WindowsEngineBackend` 实现共享 `ProfileDelayBackend`。请求沿用 GA 的 profile audience、
凭据 slots、节点顺序、100–10,000 ms 超时、目标 URL 与预期 HTTP 状态。受保护安装的
Desktop 验证无入站/控制器/路由变更的请求后，通过 DPAPI 取得精确 audience 的凭据快照，
交给独立用户级 engine host；直接调用同一 GA 补丁的 `TestProfileProxiesWithTarget`，
保留实际协议 HEAD/URL 探测、成功延迟、timeout/not_found/probe_failed 语义。

一次测速不分配运行 generation，不获取 Authority lease，不改变系统代理或路由。
后台测速只有一个独立槽和跨进程 mutex，不占运行状态锁；取消信号进入原生控制等待，
槽一直保留到真实子进程、Job、管道和目录资源退休。正常运行回复仍限 4 KiB，只有已提交
测速请求可读取最多 64 KiB 的测速回复，且验证会话、序号、进程、版本、摘要、节点顺序及
互斥结果。错误回复和清理失败不能变成空结果或成功延迟。

安装验收新增第三个独立 medium-integrity 客户端，保持每个客户端 60 秒上限。它验证实际
SOCKS 凭据认证、错误 audience 拒绝、已发出 HEAD 后取消、槽复用、较大有序结果与
generation/Authority/代理设置不变。该客户端不执行产品 Agent，并明确记录此边界。
另有真实引擎测试保留原进程句柄，核验成功、取消和超时后的退出与资源清理。
TCP 对端关闭只接受 EOF 或明确的远端 reset，接收超时不作为清理证明，遵循
[Winsock recv 契约](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)。

本地 113 项 portable tests、22 项 Go host pass events、10 项源码/构建契约测试通过；
Windows 默认/全 feature cross-Clippy（warnings denied）及工作区格式通过。新增 Go
host 已按 GA 固定工具链交叉构建 Windows x64 字节，仍需托管 Windows 原生运行核验。

测速源码 `4c199f1f3e4e9adefdded69b067710df0c22cb0e` 的
[39379588113](https://github.com/billlza/cfw-rs/actions/runs/39379588113) 四项作业通过；
620 项 Rust、311 项 UI、14 项真实引擎测试、35 项 SCM 场景和 480 个 Go pass events
均已核对，没有失败或跳过。engine artifact `12244784504`（SHA-256
`8920e469855005b32380e091196a1a8acba1aee01306be3be8607381e7b7b9a6`）与 SCM artifact
`12244872611`（SHA-256
`665ef146c654568b30fee6c0136022db988d15be653c2a47e55f479334bd5011`）已下载并通过完整核验。
宿主二进制为 36,115,968 字节、SHA-256
`ebeab89a76460b4495b75e696d8e1651d8de4354d155ee10f31dc5930b5f9689`，与本地独立
交叉构建一致；79 个组件、118 个许可证文件及清单内容与独立收集结果一致。

三个安装客户端分别耗时 32.463/55.830/7.877 秒，仍各受 60 秒限制。测速回执确认实际
SOCKS 凭据与 HEAD/204 探测，错误 audience 被拒绝，已发出请求后的取消释放资源且
槽可再用。32 个长名称的有序结果为 17,687 字节；运行前后均为同一 installation 的
Off、generation 5、revision 35，lineage/WinINet 未变化。取消时另外保留的真实子进程
句柄已观察到退出。此结果不证明九页 GUI、TUN、睡眠唤醒或完整发布已完成。

随后状态码语法直接复用 `cfw-singbox-config::validate_expected_status`，移除 Windows
侧重复解析器；6 项相关测试、全 feature Windows cross-Clippy 和格式检查通过，
更新头的完整 CI 另行记录，不能把上述源码的产物核验自动套用到后续提交。
代理 backend 上述限定的原生验收已通过；异步取消和异常恢复的最终应用验收尚未完成。
TUN 入口仍显式不可用，尚需完整 TUN/合并模式、backend 的服务重启恢复衔接、应用诊断
接线、Tauri Windows factory/startup/build、实际 UI 和发布验收。此实现没有关闭这些缺口。

## 桌面装配与 Windows 编译推进（2026-10-20）

`2756224c2e8afc06038e2bc254ebda135de8ffee` 的
[39385215851](https://github.com/billlza/cfw-rs/actions/runs/39385215851)
四项 Windows 作业通过，engine `12248025905` 与 SCM `12246609184` 产物已完成源码、
哈希及回执核验。实际应用的 platform runtime 和共享协调器经历 Off/gen5、
LocalProxy/gen6、SystemProxy/gen7、关闭后 Off/gen8；两种代理模式均有真实 HTTP
流量，重复请求不分配新 generation，代理恢复、Authority Off 和协调器退出均已核验。
夹具直接编译应用模块，但没有启动 Tauri GUI。

`479fcbb` / `e51a7a7` 已分离 macOS 构建入口，加入 Windows 开发配置、原有图标的
ICO 和独立桌面构建工作流。`e51a7a7` 的
[39389677580](https://github.com/billlza/cfw-rs/actions/runs/39389677580)
前端准备通过，完整应用检查报告 260 个编译错误和 1 个 warning，主要是遗留迁移、
更新器、私有文件和桌面操作中的 Unix/macOS 依赖。失败产物 `12249580555`
已下载并核验，未生成 EXE；Windows release 构建仍拒绝缺少正式打包/签名准入的输入。

本批改动连接真实 Windows 私有文档事务与进程租约，保留原 Unix 实现及提交不确定性；
端口游标接入只读 WinINet LAN 手动代理观察，保留有限重试和最终 native bind 判断；
本地文件导入读取同一已打开对象，拒绝叶子重解析点、非普通文件、额外数据流、超限
及无效 UTF-8。静默启动与托盘唤醒使用 Windows 任务栏/窗口 API。
新增测试直接编译应用的文件和端口模块；已有代理流量测试同时核验端口观察没有改变
设置。当前本地通过 116 项引擎测试、40 项订阅测试、44 项引擎相关回归和 19 项日志
回归，macOS 全目标 Clippy、Windows 存储全目标及引擎库 cross-Clippy 均禁止 warning。
`e8102c94d6206aefd732cd816b6da339e57c7ffd` 的
[39396013103](https://github.com/billlza/cfw-rs/actions/runs/39396013103)
四项 Windows 作业通过：642 项 Rust、311 项 UI、14 项真实引擎测试、35 项 SCM
场景和 480 个 Go pass events。文件事务 6 项、普通文件导入 4 项、桌面端口 8 项
新增入口均在 Windows 执行。engine `12252407239`（SHA-256
`c67c576b31c8ae34bbb5bf41a909e850f89ac3c47c99efa1792734546347f31c`）和 SCM
`12251683620`（SHA-256
`f9663df0467e432fc5cd13ff37ec2eb274756b5ede1290dcea104d89c65fe4ec`）已通过源码、
哈希和完整回执核验。原生代理流量场景确认观察 active/foreign/restored 端口时没有
修改代理设置。

同一源码的完整桌面检查
[39395993455](https://github.com/billlza/cfw-rs/actions/runs/39395993455)
仍失败，错误从 260 项降至 193 项，另有 1 个既有 warning。私有文档、普通文件导入、
端口游标和窗口操作已不再报错。失败产物 `12252430353` 已核验，仍未生成 EXE。

后续旧配置源适配将原 Unix 读取逻辑保留为平台实现，Windows 以只读目录句柄打开
已存在的源目录，不创建锁文件或改写源数据；普通只读授权可接受，外部写入授权、
重解析点和硬链接被拒绝。读取同时禁止其他数据写入句柄，并比较读取前后的文件
身份、长度、写入/变更时间和权限。此批本地通过 13 项迁移回归、macOS 全目标
Clippy 及 Windows 存储交叉 Clippy。

`098fe856c9f337c7e2f88535708d0f86dcdac075` 的
[39398485302](https://github.com/billlza/cfw-rs/actions/runs/39398485302)
四项 Windows 作业通过，包含上述 6 项原生迁移源测试：648 项 Rust、311 项 UI、
14 项真实引擎测试、35 项 SCM 场景和 480 个 Go pass events。engine `12254332072`
（SHA-256 `ea85dd8526e31b2964ea8022889c446f416ca61ab7c442b9a8636b92d39f8f56`）
和 SCM `12254380053`（SHA-256
`a797ddfaa978c393fd245b9ad8bb7908f1edda2ecca866a19d7a49eb9078b2e6`）均已核验。
同一源码的完整桌面检查仍失败，剩余 171 个错误和 1 个既有 warning；旧配置读取
模块的 22 个错误已消除，没有生成应用 EXE。

随后交接票据存储分离平台实现，保留共同的票据格式、消费、失效清扫及失败隔离协议。
Windows 使用创建/打开时即生效的排他数据访问，保留同一原生对象的引用；消费时通过
另一个已核对文件 ID 的删除句柄移除名字，旧对象仍可由消费方持有。发布和清理均失败
时保留排他句柄，防止就绪读取器误认成功。25 项现有 Mac 交接回归及本地 Clippy
通过。`ab73233e82bb82b59fbcba191ddfa37320aeddfd` 的
[39402821832](https://github.com/billlza/cfw-rs/actions/runs/39402821832)
执行了全部 48 项原生存储测试，包括 6 项新增票据场景，Clippy 禁止 warning。
完整桌面检查仍失败，剩余 123 个错误和 1 个既有 warning，没有生成 EXE。
产物 `12256501849`（SHA-256
`314b6c7d99c6166b23419741eb9feb60f9f908f4c6415a4dc9dd4b63b83fc2b2`）的源码、
哈希、六组测试和原始完整编译诊断均已核验。桌面构建工作流保留完整应用检查和
原有全套 Windows 契约工作流，不能由文件测试推出完整交接验收。

此前按“本项目内部构建”查找过迁移来源；用户随后澄清目前还没有可指认的旧版，
这是 Rust 重构的首个 Windows 大版本。以本文开头的首发范围为准，停止移植
macOS 退役交接到 Windows。已提交的文件租约原语与原生回归证据保留，但不将其
视为 Windows 首发必须使用的交接流程，也不继续为它扩展旧服务/进程协议。

完整 GUI、五类原生呈现、TUN/合并模式、安装/更新/签名以及物理 Windows
睡眠唤醒等验收保持开放。用户尚未确定物理测试机，当前继续代码及托管 CI。

### 2026-10-22：Wintun 数据包泵与引擎转发（IPv4／IPv6 与投递策略原生验证通过）

`4ff22485` 修正 Windows 代理准入拒绝投影路由缓存（中国大陆直连）的问题；
`0baeb74b` 修正引擎有意关闭与数据包写入之间的竞争；`b3294858` 增加检查后的 Tunnel
数据面准入、继承端点的 MTU 绑定和 Wintun 数据包泵；`c4b463e3` 在 engine 作业末尾
加入真实 Windows 流量经自有 Wintun 适配器、泵和真实引擎转发的验证。`1f7bccc1` 的
托管结果与下载核验见当前验收状态。`3b643554` 把同一验证扩展到 IPv6：适配器另获
2001:db8:1::10/128 与到 2001:db8:1::123/128 的主机路由，并按点对点隧道关闭其 IPv6
DAD 与路由器发现（原值恢复后复核）；每档 MTU 另以 IPv6 完成 512 KiB TCP 双向和满
MTU UDP（载荷 MTU−48，设置 IPV6_DONTFRAG），固定节点按地址族核对 nonce、哈希与目标。
`f00051fb` 的托管结果（IPv4／IPv6 均通过）与下载核验见当前验收状态；同一提交按
审查意见改为按地址族要求证据（每个地址族一次连接与数据报、无泵对照，回执中的地址族
须与流量一致），并修正 macOS 门禁发现的 `WINTUN_*` 策略声明缺失。随后加入引擎到
系统方向的 `DeliveryPolicy`，`2c708d2f` 原生验证通过（见当前验收状态）。

2026-10-22 用户已决定：Tunnel 引擎由 UserAgent 承载（复用每用户 DPAPI 凭据）；
`PacketPumpLimits` 保持 1280–1500，与 macOS GA 模型一致，不修改共享协议；接收端点的
进程须为中或高完整性（低、AppContainer、不受信任一律拒绝），转交的句柄只带泵所需的
访问权限。随后 `3dbe2d59` 先完成交接前的加固，`9287fb79` 实现 SYSTEM 到 UserAgent 的
端点交接（见下节）。

### 2026-10-22：交接前加固与 SYSTEM 端点交接（均已原生验证）

`7ffd916c` 收窄可绕过投递策略的直接路径：`Session` 的直接收发只在
native-service-validation 下存在，`PacketServer::receive` 只在 native-engine-validation
下存在，会话拆分、泵端点拆分与 `start_halves` 只在 `tunnel` 模块内可见；产品构建中
引擎数据包只能经 `PacketPump` 和投递策略进入 Windows。`c05346c7` 收紧 ICMP：只放行
回显应答（可分片），以及完整未分片、且引用 Windows 从适配器自身地址发出之包的目的
不可达／超时／参数问题报告（ICMPv6 另含 packet too big）；重定向（ICMPv4 类型 5）、
路由器通告与请求、邻居发现、MLD 及其余类型一律拒绝。首分片必须带类型；后续分片在
缺少首分片时无法重组，因此放行。头部解析新增分片位置（DF 与保留位不算分片，IPv6
分片头即使偏移为 0 也算分片）和被引用报头的源地址，可移植变异检查全部杀死。
`509092d2` 在转发探针中记录适配器创建时与分配固定地址后的 `GetAdaptersAddresses`
标志。`3dbe2d59` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39754658396)
与[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39754654559)七项全部通过，
五个产物按 API 摘要核验：引擎
`864c5557ab72b9b05f6c8765ffdfe79aa714c8ead16d05ab097c3af5c7ecbb5b`、Wintun
`58a74ba6d80f4e1ff2b5256727d780a093c4074592c9e180e1e6dd3d8237e749`、SCM
`80b594d1c386b3ea5ed0e948b8e6c1b3212ea6c82189ce22783f5bc7a47d1d8e`、桌面
`96d67056380210d91cf3e2a25c59322c8a1a4f8103f0559b2f6808b0ed276f9a`、更新包检查
`5eedfa57e180cd08c3d59a5e84f5c2d5d9ca431ab2963d486f4d72638ae1d0d0`。505 个 Go 测试、
41 项 Wintun 数据包测试、共享 760 项 Rust／329 项 UI、372 项桌面测试与三次 GUI 会话
通过，EXE 为 43,320,320 字节（`a952c9dcc65c9c877dc6403e79cdee99cc0050761a233da49b1ca8a408a8ff1a`）。
原生观察：新建 Wintun 适配器的 DHCPv4 默认关闭，适配器标志为 0x1C1（DDNS 注册、
NetBIOS over TCP/IP、IPv4、IPv6 启用），分配固定地址后不变；产品承载时应另行关闭
该适配器的 DDNS 注册与 NetBIOS。转发三档的目的地址类拒绝为 34／39／41 个，源地址类
与协议类（含新 ICMP 规则）为 0，接收计数等式成立。

同一提交的 macOS CI（运行 39754658440）三项作业都实际执行。质量作业中
build-script-boundary、ci-no-masking、证据清单、版本契约、rustfmt、依赖图、UI
（329 项）、整个工作区的 macOS Clippy 与 1,323 项 Rust 测试全部通过，`WINTUN_*`
修正生效；release-tool 测试 3,672 项中只有
`test_real_swift_identity_is_clean_repeatable_and_structured` 失败（另 1 项因未安装固定
Tauri 签名器跳过）：该作业的镜像选中 Xcode 27.2 beta 3，其 Swift 报告 `6.4.2`，而测试
硬编码 `6.4`。供应链作业因
RUSTSEC-2026-0382（rustls-webpki 0.103.15，修复于 0.103.16）失败，libbox 作业因
GO-2026-6809（go1.27.2 的 crypto/x509，修复于 go1.27.3）失败。各作业在失败步骤后
停止：shell 脚本检查、依赖／来源／许可证策略，以及 libbox 之后的 Swift、Xcode、更新
签名边界与 0.5.0 验证骨架步骤均未执行，不计为通过。两项公告都在 GA 之后发布，修复要
升级 Go 工具链与 rustls-webpki，会改变发布身份，需另行决定。`39b1440a` 的运行
39770829274 与 `775ad5fe` 的运行 39778207372 中同一 release-tool 测试通过：两次质量作业都
分到 `xcode-27-arm64` 镜像 20261012.0260.1（选中 Xcode 27.2 beta 2，27B5028f），而
`3dbe2d59` 的质量作业及这两次运行的 libbox 作业分到 20261019.0289.1（Xcode 27.2 beta 3，
27B5038j）。同一标签同时分配两个镜像版本，“选择最新可用 Xcode”
随之改变 Swift 版本，该测试结果因此取决于分到的镜像；固定 Xcode 选择或让测试接受
同一 6.4 系列的补丁版本，需另行决定。

macOS 运行长期排队的原因（只读诊断）：个人账户的托管 macOS 作业实际并发上限为 5，
几乎全部被 billlza/q-periapt 的 `ci`、`independent-continuity`、`reference-account`
工作流占用（无 concurrency 分组，每次推送约 9 个 macOS 作业，大量作业排队满 24 小时
后被取消）；PR #8 的 CI 又在每次推送时取消排队中的旧运行，使其反复回到队尾。
`xcode-27` 是标准托管镜像标签，不是自托管或大型 runner；账单接口因令牌权限不可读。
建议由用户操作：取消 q-periapt 不需要的排队运行，为其三个工作流及本仓库
`mobile-egress-observer.yml` 加 concurrency 分组或限制触发；不建议改用
`macos-15`／`macos-latest`，它们共享同一并发上限。

`b0be2250` 实现 SYSTEM 到 UserAgent 的端点交接。`EndpointHandoff::create` 只允许
SYSTEM 服务为已授权的 UserAgent 请求创建端点，接收方须为中或高完整性的交互会话进程，
且不是 AppContainer、受限令牌或 LocalSystem；客户端以 `ENDPOINT_ACCESS`
（`FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`）不可继承地
复制到接收方，SYSTEM 从不关闭对方句柄表中的值。接收方 `PacketClient::adopt` 先核对
句柄标志为零、单实例消息管道客户端、消息读模式与缓冲区，并核对服务端进程是固定的
服务进程（创建时间与会话 0 不变），再请 SYSTEM 以零权限副本和 `CompareObjectHandles`
比对；确认会消耗交接对象，任何拒绝（包括替换对象）都退役该端点。采纳后的客户端经
`into_child` 再次核对服务端后才可被引擎继承。`2a65c64b` 让 Go 引擎宿主在恰为该访问
掩码的句柄上完成收发与关闭。`9287fb79` 在 SCM 夹具中验证：SYSTEM 服务把端点交给
中等完整性的 UserAgent 客户端；客户端证明无关事件与自己服务的管道在询问 SYSTEM 前
即被拒绝且仍保持打开，SYSTEM 的对象比对拒绝无关副本并退役该端点；客户端随后采纳
新端点，证明它无法提升到 DELETE、READ_CONTROL、WRITE_DAC、WRITE_OWNER 等权限，
往返一个 1500 字节的包后关闭，SYSTEM 观察到对端关闭。
`9287fb79` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39763928886)五项
通过：SCM 回执列出 36 项用例（新增 `system_packet_endpoint_handoff`），夹具父进程逐字
核对 SYSTEM 端报告与客户端报告（采纳、替换被拒、访问受限、往返回显均为真），精确名称
的准入测试 1 项通过；Wintun 作业的数据包测试增至 49 项（新增 4 项交接与 4 项条款测试，
包括在 Windows 上自建的字节管道、非消息读模式、非阻塞模式、两实例和超限缓冲反例）；
Go 测试增至 506 项，其中引擎宿主在恰为交接访问掩码的句柄上完成收发与关闭；共享 768 项
Rust／329 项 UI。产物摘要：引擎
`2dc022619a350c94b9d59ce51c7d24f0cf9a947a6c8f82f73fcee86cf061475d`、Wintun
`2109a4949fb6a6fef86d06edc9a2ce3821c9fc7ee7fc577c96fcdb69584e9115`、SCM
`65fdabe8c249cb525b5837a7e59540ffd1c3e3eee24f38997f27ffc8f554defb`、更新包检查
`7343e2b15850618147035904abec6bf45a31538fbdf47c567a829fc2ae995c53`；引擎宿主字节不变。
同一提交的[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39763925394)第一次
尝试失败（产物 `e4ef34db94e79e28d50ed4f0daa7b16434019c50e9632759f2248b1398a46fd4`）：
LocalProxy 网络启动时 Agent 报告 “installed Agent readiness was not delivered”，其
Authority 通道在 Ready 前被 SYSTEM 端关闭（109），桌面显示
“authority ended before Ready”；现有产物不收集 SYSTEM 运行时日志，原因未能定位。
同一作业重跑一次后通过（产物
`2043d567ea59c5fed3ef5c2886ac2e2a483cf6c3b265554fb8d1a991c39c4ed3`：372 项桌面、5 项
更新日志测试与三次 GUI 会话，EXE 43,322,880 字节，SHA-256
`8570575a3a98521f390852bf186617e527cc64949d574abcaee2af3eb40dbaac`）。改动不触及
LocalProxy 路径，且 engine 作业的 19 项安装运行检查同时通过，因此记为间歇失败而非
回归；GUI 失败时应补充采集 SYSTEM 运行时诊断。仍未接通：
Authority wire 中携带端点的消息与授权代次（状态机的 Tunnel 模式仍期望独立
`TunnelWorker` 角色，须改为 UserAgent 承载）、SYSTEM 承载的 Wintun 适配器与泵、
路由／DNS 所有权与持久恢复。同一用户的其他中等完整性进程仍可从 UserAgent 复制出
端点，这是由 UserAgent 承载引擎带来的固有边界。

### 2026-10-23：macOS 门禁根因与安全刷新

`320141f5` 的 macOS `CI`（运行 39787856702）中质量作业通过，另两项失败，根因都在
CFW 源码之外。libbox 作业在“Materialize pinned libbox source”从 GitHub 拉取固定
sing-box 源码时网络中断（`curl 56 Recv failure: Operation timed out`，随后
`fetch-pack: invalid index-pack output`，退出码 128），未到公告扫描；`39b1440a` 与
`775ad5fe` 的运行已表明拉取成功后下一步会因 GO-2026-6809 失败。供应链作业在
“Audit exact shipped Rust target graph”因 RUSTSEC-2026-0382（rustls-webpki 0.103.15）
失败。两项公告均在 GA（`v0.5.0` → `502adf9`）之后发布，已发布的 GA 字节不变。

`60ed5bb7` 把产品 Go 工具链移到 1.27.3（`GO_VERSION` 与各归档摘要、sing-box 安全
依赖补丁、go-release-tools 与 certgen 的 `go` 指令），把 rustls-webpki 移到 0.103.16，
并在 RELEASE.md、docs/supply-chain.md、native/macos/README.md 记录日期化的公告说明。
数据包证据端点的独立 Go 固定版本（1.27.2）与其二进制摘要未动：移动它需要在 Linux
上重建端点、更新二进制摘要及携带它的安装器与身份，并重新部署（见开放事项）。
macOS `CI` 运行 39872592378 的结果：

- 供应链作业通过：aarch64-apple-darwin 目标图 328 个可达包 0 个漏洞，cargo-deny
  0 错误／警告／提示。
- libbox 作业首次全部步骤通过（镜像 20261012.0260.1，Xcode 27.2 beta 2，27B5028f）：
  Go 模块图与链接图扫描无漏洞、源码绑定的 libbox 构建、Swift 格式与包测试、Xcode
  目标测试（TEST SUCCEEDED）与分析、真实固定更新签名器边界，以及未签名 0.5.0（50000）
  骨架构建与产物清单核验（7 个 Mach-O）。
- 质量作业（新镜像 20261022.0305.3，Xcode 27.2，27B48）中 build-script-boundary、
  ci-no-masking、证据清单、版本契约、rustfmt、依赖图、UI 329 项、整个工作区 Clippy
  与 1,327 项 Rust 测试通过；release-tool 测试 3,672 项中 1 项错误、1 项失败、1 项跳过，
  其后的 shell 语法检查与 ShellCheck 未执行。错误为
  `test_endpoint_toolchain_pins_are_named_by_key_only`：测试把端点 Go 版本加一个补丁号并
  配合合成归档摘要，产品移到 1.27.3 后正好与产品版本重合，校验器按“同一版本只有一个
  归档”正确拒绝。这是测试夹具的假设失效。`329a3b55` 让两项“移动固定版本”测试选择
  不等于另一条固定版本的下一个补丁号，同版本一致性仍由独立测试覆盖；本机以系统
  Python 复现了该错误，修正后该模块 131 项全部通过。失败为
  `test_real_swift_identity_is_clean_repeatable_and_structured`：新镜像的 Swift 报告
  `6.4.2`，测试硬编码 `6.4`，与 `3dbe2d59` 的情形相同；同一 `xcode-27` 标签现在分配三个
  镜像版本。放宽该测试或固定 Xcode 选择会改变发布身份规则，保持为开放事项。跳过项
  仍是未安装固定 Tauri 签名器的 1 项，不计为通过。

### 2026-10-23：产品 TUN——SYSTEM 适配器与 UserAgent 引擎（托管原生与 GUI 验证通过）

`9c7bf1a1` 让 Windows gVisor 投影在 Tunnel 模式加入 `route.auto_detect_interface`，
Tunnel 数据面准入拒绝缺少该项的配置；macOS（system 栈）投影与摘要不变。依据：引擎
在 Windows 上是普通进程，没有 Network Extension 的豁免，SYSTEM 把默认路由指向
适配器后，引擎自己的套接字必须绑定物理默认接口，否则会回流进隧道；固定 sing-tun
的 Windows 默认接口监视只看 /0 路由，并跳过 Wintun 的 `IF_TYPE_PROP_VIRTUAL`。
按源码核对（未单独原生验证），sing-box 的 Windows 本地 DNS 配置源只读取有默认网关的
接口，适配器的在链路路由不提供网关，因此配置了本地 DNS 的引擎也不会把适配器自己的
DNS 对端当作上游。

`863a262e` 接通产品 Tunnel：

- Tunnel 租约绑定所有者的 UserAgent，删除独立的 `TunnelWorker` 角色（2026-10-22 用户
  决定）。Authority wire 升到 v7，新增轮询式 `OpenTunnel`（`TunnelPending` 直到 SYSTEM
  提供端点，只提供一次）与 `ConfirmTunnelEndpoint`。首个请求在专用线程上启动宿主，
  Windows 创建适配器或首次安装固定驱动时不持有 Authority 锁；每个请求同时续期运行时
  心跳。Tunnel 的启动等待另加 `tunnel::OPEN_LIMIT`（45 秒）。
- 适配器接口 GUID 由安装身份派生（SHA-256，v8 UUID），Windows 因而保留同一网络配置
  文件，残留适配器按身份查找；启动时若该 GUID 的适配器已存在则拒绝，不接管。链路关闭
  NetBIOS、路由器发现、DAD、转发与有状态配置，设置端点 MTU，先清除该 GUID 残留的地址、
  路由与解析器，再分配地址计划并逐项回读。
- 确认端点后按已分配地址构造 `DeliveryPolicy` 并启动泵。Ready 必须声明 SYSTEM 自己的
  泵上限（`packet_pump_limits`：单包为端点 MTU、每方向 1 个包、每次读 1 个），随后才
  安装并回读路由与解析器：各地址族默认路由减去 macOS 提供者排除的私网、链路本地、
  组播、受限广播范围与发布传输主机路由（例如 IPv4 绕过私网时为 67 条前缀），以及
  地址计划的 DNS 对端。所有地址、路由和解析器都只挂在该适配器上，不写其他接口、
  代理设置或防火墙策略。
- 租约离开 Starting/Active 后，SYSTEM 先要求引擎关闭端点；运行时 Job 为空或进入
  Quarantined/Recovering 时退役宿主：泵结束、会话关闭、适配器关闭，15 秒内按接口与
  设备观察其消失。Tunnel 记录的 Off 需要空 Job、宿主线程退出和适配器被观察到不存在。
  SYSTEM 重启后，恢复宿主先按 GUID 移除该安装的 Wintun 设备（`DIF_REMOVE`）并证明
  其不存在，不创建任何对象。
- 共享后端在 Windows 上启动、停止并查询普通 Tunnel；TunnelSystemProxy 仍不可用。
  安装宿主夹具新增 Tunnel 套件：从 Off 开始，直接向适配器 DNS 对端发送 A 查询并
  解析应答，确认系统为探测地址选择的路由进入适配器，经隧道取回
  `www.msftconnecttest.com/connecttest.txt`，并在引擎控制器的连接表中找到这条以
  `tun/cfw-tunnel` 入站记录的连接；随后验证错误代次的停止被拒、重复停止、Off、适配器
  消失、物理路由恢复、代理设置未变与端口释放。安装运行失败时另收集 SYSTEM 服务最后
  记录的错误与客户端输出。

本机验证：rustfmt、两个 crate 的 macOS Clippy（`--all-targets --all-features`，
`-D warnings`）、Windows 目标库的交叉 Clippy（默认与全部特性）、cfw-windows-engine 165 项
与 cfw-singbox-config 130 项可移植测试、cfw-application 118 项测试。可移植变异检查 30 项
中 29 项被杀死；存活的一项（去掉 `runtime_exact` 的角色比较）是等价变异：`Peer::same`
已比较角色，且只有 UserAgent 能绑定。路由减法与适配器 GUID 的期望值由 Python
`ipaddress`／`hashlib` 独立计算后固定在测试中。示例夹具无法在本机交叉编译（ring 需要
MSVC 头文件），只能由托管作业首次编译。

托管验证经过（原始失败均保留）：

- `329a3b55`（[共享／原生](https://github.com/billlza/cfw-rs/actions/runs/39880757159)、
  [桌面](https://github.com/billlza/cfw-rs/actions/runs/39880757037)）：示例夹具的请求计时日志
  `command_name` 没有覆盖两个新命令，SCM、共享契约、更新包检查与桌面作业都失败于同一编译
  错误；Wintun 作业通过（49 项数据包测试与生命周期验证）。引擎作业在示例编译前完成了 19 项
  原生 Rust 引擎测试，包括带 `auto_detect_interface` 的数据包端点引擎用例。`aef7bdad` 补全。
- `aef7bdad`（[共享／原生](https://github.com/billlza/cfw-rs/actions/runs/39881837080)、
  [桌面](https://github.com/billlza/cfw-rs/actions/runs/39881835303)）：SCM 作业通过；Clippy 拒绝
  Tunnel 套件以临时 `String` 比较控制器字段（`cmp_owned`，其建议的数值比较是错误的，控制器
  端口是十进制字符串）；SCM 崩溃恢复夹具伪造的确认消息硬编码协议版本 6，被 wire v7 当作
  不支持的版本拒绝。`fbb80d95` 改为按字符串切片比较，并让伪造消息复制真实请求的协议与版本。
- `fbb80d95`（[共享／原生](https://github.com/billlza/cfw-rs/actions/runs/39883055113)、
  [桌面](https://github.com/billlza/cfw-rs/actions/runs/39883054290)）：共享契约、SCM、Wintun 与
  更新包检查通过，两种 SCM 崩溃恢复夹具通过；安装运行进入 Tunnel 套件后在前置检查失败：
  `ConvertInterfaceGuidToLuid` 对不存在的接口 GUID 返回 ERROR_INVALID_PARAMETER（87），
  而产品的 `adapter_absent` 与夹具都只把 ERROR_FILE_NOT_FOUND／ERROR_NOT_FOUND 当作不存在。
  产品在创建适配器前与证明移除时会以同样方式失败。`979ebf3e` 改为在原始接口表
  （`GetIfTable2Ex(MibIfTableRaw)`）中按 GUID 查找，不存在成为观察结果，列表失败仍是错误，
  同一 GUID 对应多个接口或零 LUID 一律拒绝；新增的 Windows 单元测试覆盖未知 GUID 与经独立
  LUID→GUID 转换得到的环回接口。夹具共用该产品查找，并要求经隧道的 HTTP 连接的源地址
  就是适配器地址。同一运行的桌面作业在本地代理 GUI 会话首次启动时失败：UserAgent 的
  Authority 工作线程在 Ready 前收到 Stale 拒绝，桌面报告 “authority ended before Ready”
  （产物 `518282ae610389ede2c41cdf751165ef51bc0407f95ff7ff851c82400d045427`）。症状与
  `9287fb79` 第一次桌面尝试相同，改动未触及代理路径，SYSTEM 端原因未被收集。`dee84186`
  让 SYSTEM 服务按阶段保留最近一次错误，GUI 认证失败时以备份语义复制；`5d989e07` 记录
  Authority 结束活动租约的原因（准备租约过期、连接关闭、心跳过期、控制台会话变化或消失、
  进程复核失败、停止证明过期、服务排空、隧道泵结束），作为 `lease_ending` 诊断。

`53a9f3c6` 修正凭据生命周期仍拒绝 Tunnel 的遗留检查：`dee84186` 的引擎作业中 Tunnel 套件的
检查、安装与授权已通过，启动时报告 “credential state is unavailable for maintenance”；
运行时凭据记录本已绑定 Tunnel 的网络选项，现在只拒绝组合模式。

`53a9f3c6` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39887846302)与
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39887858606)七项全部通过。引擎产物
`160c86ae8ce920d635b435ed2a939ea9f2adc5611f0cc6ba0718ba2a9a0344a2`（与 API 摘要一致，源码绑定
`53a9f3c6`）中，安装运行回执的 20 个用例包含 `product_tunnel_routes_dns_and_traffic_then_retires_its_adapter`；
Tunnel 套件报告：运行身份为 `windows_tunnel_service`、代次 9；适配器 GUID
`6db660d9-9e0b-82d3-87d0-cf23cbe280f3` 与按安装身份 `406a65b6-…` 独立计算的值一致；向适配器 DNS
对端的 A 查询返回 5 个地址；系统为探测地址选择的路由进入适配器；经隧道取回探测内容，引擎
控制器以 `tun/cfw-tunnel` 入站记录了这条连接（源地址 198.18.64.1，即适配器地址，出站链
`direct`）；错误代次的停止被拒、重复停止、Off 后适配器消失、物理路由恢复、代理设置未变、
端口释放均为真。阶段计时：启动 2.6 秒→Ready 11.6 秒（含首次安装固定驱动与创建适配器），
停止 13.3 秒→Off 14.8 秒。同一作业的转发验证（引擎投影已含 `auto_detect_interface`）三档 MTU
通过，引擎宿主 `44260f44193da14eae8b6ac9215f40aee8becdbd5618c14aef7d50feebc3e338`。桌面产物
`805b54e50cf512a08578a230f928c417fb0a4ddbb91945d4fbce9184d2d784b5` 的三次 GUI 会话通过（本次本地代理首次
启动未复现上述间歇失败）。`2835bca7` 在 Tunnel 套件
正常停止之后再启动一次 Tunnel，终止本桌面启动的 UserAgent（按观察到的映像路径确认），
随后只观察：SYSTEM 必须在 60 秒内发现运行时丢失、退役适配器并记录 Off，期间后端只可
报告恢复中、所有者丢失或清理未证明（每条都写入报告），Off 后适配器不存在且物理路由
恢复。安装运行因此保留第二个 Tunnel 代次（共 10）。

`34bd8afd` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39889931808)中安装运行在
协调器套件失败：该套件仍断言 Windows 不提供 Tunnel（`f50cea36` 改为要求只提供 Tunnel、不提供
组合模式）；[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39889929237)的 TUN 会话观察到
`awaiting_approval`：共享协调器在调用授权时总是发布等待批准（macOS 需要用户同意保存 VPN 配置），
Windows 上没有需要批准的内容，General 页却会短暂显示 “Needs approval” 与批准按钮。`ede33417` 让
`EngineRuntimePlatform` 说明隧道授权是否等待同意，Windows 在授权期间发布 TunnelStarting；macOS 保留
同意阶段，两个平台均有测试，3 项变异全部被杀死。同一桌面作业的 SYSTEM 诊断复制因管理员对服务
私有目录执行 `Test-Path` 被拒而失败，`730b475e` 改为直接以 robocopy 备份语义读取。

`730b475e` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39892863105)五项通过。引擎产物
`c6bdc8a3815c5a36060f9d8e31b145521e8d6f253046378d1a30a993f01925a6`（源码绑定 `730b475e`）：安装运行回执
21 个用例，包含 `product_tunnel_routes_dns_and_traffic_then_retires_its_adapter` 与
`product_tunnel_recovers_off_after_its_user_agent_is_terminated`；Tunnel 套件各项再次为真（引擎记录的连接源
地址 198.18.64.1，入站 `tun/cfw-tunnel`）；UserAgent 终止用例在代次 10 启动 Tunnel 后终止 UserAgent
（退出码 0xc0fe），期间只观察到 “GlobalAuthorityRecovering”（Authority 正在恢复）与 “OwnerUnresponsive”
（UserAgent 退出）两条，约 1.1 秒后得到 Off，适配器消失、物理路由恢复；协调器套件报告 Tunnel 可用、
组合模式不可用。[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39892860279)的 GUI TUN 会话通过
启动（`tunnel_active`，所有者 `windows_tunnel_service`，未出现等待批准）、组合模式拒绝（系统代理开关
禁用并显示专门原因）、控制器检查与同会话原生探针（适配器存在、路由进入适配器、HTTP 从
198.18.64.1 发出、用户代理设置未变；产物 `76708f1dd52ca5db785fc32b8f8052b440da4e566d88bd96de0593285073bcc9`），
随后在关闭 TUN 的步骤失败：页面内观察函数引用了只存在于 Node 侧的变量（`before is not defined`），
属于夹具缺陷；同时收集到的 SYSTEM 诊断（`lease_ending`：连接关闭，自 Active）只反映失败后的会话
拆除。`5bcc3efc` 把起始代次作为参数传入页面。

`5bcc3efc` 的[共享／原生作业](https://github.com/billlza/cfw-rs/actions/runs/39894848609)与
[桌面作业](https://github.com/billlza/cfw-rs/actions/runs/39894846573)七项全部通过，五个产物按 API 摘要下载核验：
引擎 `bf68115811720b21783d9f36ca669d171a3817272845ad8fde01bb6fca4e5946`（506 个 Go 通过事件、19 项原生 Rust
引擎测试、21 个安装运行用例含两个 Tunnel 用例、三档 MTU 转发）、Wintun
`6a1cbadaf9f555a39551f071fb0f017cd8067d45ef2e1c69eb500d7e59b79515`（49 项数据包测试）、SCM
`01cbb99ae980b890b0b7051e12d258956424f1da4d3864b9ead7cdfe32fc85a1`（36 项用例）、桌面
`25f2aa7fbbf7b3e53d9cb7dcbba436497ee40503d571d2d049f042c56e2bd916`（373 项桌面测试与四次 GUI 会话）、更新包检查
`96098c0d3df33c07373604750a260c08fce286d3fce033343a1bc0c916b9011c`；Windows 共享作业运行 785 项 Rust 与 331 项 UI
测试。GUI TUN 会话（回执绑定 `5bcc3efc`）：可见开关启动 TUN（`windows_tunnel_service`，代次 3），系统代理
开关显示组合模式被拒；原生探针看到适配器（GUID 与按安装身份计算的值一致）、路由进入适配器、
HTTP 从 198.18.64.1 发出且用户代理设置未变；关闭 TUN 后交给更新代次的本地核心（代次 4），探针随后
确认适配器消失、路由回到物理接口，核心停止后 GUI 正常退出。UserAgent 终止用例再次通过（期间观察到
Authority 恢复中与 UserAgent 退出，随后 Off）。

UI 能力：`67593409` 让 Windows 桌面报告 Tunnel 可用，并新增独立的 `tunnel_system_proxy`
能力（Windows 为 false），协调器对组合模式只读该能力；General 页在已请求系统代理时打开
TUN（或反之）会以四种语言的专门原因拒绝，不显示无关的旧失败，已请求的开关始终可以
关闭。UI 测试 329 项本机通过（含新增的组合模式拒绝与能力解析用例），7 项 UI 变异全部
被杀死。安装 GUI 认证在本地代理与系统代理会话之间新增 TUN 会话：可见开关启动 TUN、
系统代理开关显示组合模式被拒、控制器描述导入的配置，同会话的原生探针证明该安装的
适配器存在、系统为探测主机选择的路由进入适配器、HTTP 连接从适配器地址发出且用户
代理设置不变；关闭 TUN 后交给本地核心，探针确认适配器消失，核心停止后再退出。

### 2026-10-23：开放事项（需要用户决定或外部条件）

以下事项不能由托管 CI 单独完成，或会改变发布身份、持久化契约与产品方向，保持开放：

- **Swift 版本测试与 Xcode 选择**：`xcode-27` 标签同时分配三个镜像版本，“选择最新可用
  Xcode”使 Swift 在 `6.4` 与 `6.4.2` 之间变化，`test_real_swift_identity_is_clean_repeatable_and_structured`
  随镜像通过或失败。可选做法是固定 Xcode 选择，或让测试接受同一 6.4 系列的补丁版本；
  两者都会改变发布工具链身份规则，需要用户决定。此前放宽该测试的尝试未执行。
- **数据包证据端点的 Go 工具链**：产品已移到 Go 1.27.3，独立的端点仍固定 Go 1.27.2
  （GO-2026-6809 位于 crypto/x509）。移动它需要在 Linux 上重建端点、更新二进制摘要及携带
  它的安装器与身份，并重新部署到证据主机。
- **组合模式（TUN + 系统代理）**：Windows 的系统代理恢复依赖日志中 SystemProxy 模式的
  持久恢复目标；Tunnel 租约没有对应记录，UserAgent 崩溃后 WinINet 会指向已关闭的端口。
  开放组合模式需要扩展持久化的租约／恢复契约（`AuthorityMode` 是与 macOS 共享的
  wire 枚举），属于需要单独决定的契约变更；在此之前 UI 与后端都明确拒绝组合模式。
- **物理机验收**：睡眠／唤醒、整机重启与断电式恢复、真实登录启动、多用户、Wi-Fi／有线
  切换与长期运行需要用户确定的 Windows 测试机，云 VM 不能替代。
- **签名与发布**：Authenticode 代码签名身份、更新签名密钥、正式发布与公共字节核对需要
  用户提供签名材料并授权发布。
- **Windows 目标的供应链门禁**：macOS 供应链作业只审计 aarch64-apple-darwin 目标图；
  x86_64-pc-windows-msvc 的 RustSec／cargo-deny 审计与 Windows 引擎宿主依赖图的
  govulncheck 尚无托管门禁（可由 CI 实现，未在本轮完成）。

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
- [Windows POSIX 文件删除与保留句柄](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex)
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
- [WinINet 手动代理列表语法](https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality#listing-proxy-servers)
- [WinINet 默认 LAN 与 RAS 范围](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_option_listw)
- [Windows 禁止修改代理的策略](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disableproxychange)
- [SCM 服务访问权限](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [SCM 服务状态与 PID 有效范围](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- [SCM 配置与下次启动](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- [实际进程映像查询](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)
- [Restart Manager 注册文件资源](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources)
- [Restart Manager 查询文件使用者](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist)
- [服务终止状态之前完成清理](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus)
- [受限令牌与继承的句柄权限](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [注册表刷新与持久化](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey)
- [注册表叶子删除与访问权限](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletekeyexw)
