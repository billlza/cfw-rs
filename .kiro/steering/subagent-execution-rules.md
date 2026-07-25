---
inclusion: always
---

# 子代理调用规则 (Sub-Agent Invocation Rules)

本文件取代此前的 "4.8" 子代理调用规则。

## 1. 模型与推理强度

- 子代理必须使用当前可用的最强模型：**Claude Opus 5 (max)**。
- 推理强度使用**可选的最高档 (highest / max reasoning effort)**。
- 禁止为了省时间或省额度降级到更弱模型或更低推理强度；宁可拆小任务，也不降档。
- 若调度层未暴露显式的模型/推理强度参数，则在派发 prompt 中明确声明
  "use maximum reasoning effort" 并把任务拆分到单个子代理可完整验证的粒度。

## 2. 并行派发 (Parallel Dispatch)

- 默认**并行**派发：同一轮 (same turn) 内最多 **5** 个 `invoke_sub_agent` 调用。
- 并行的前提是**目标互不相交**：
  - 不同 crate / Swift target / 脚本包 / 测试目标；
  - 不得有两个子代理写同一个文件、同一个 `mod.rs`、同一个测试目标。
- 存在 DAG 依赖（后继任务消费前驱任务产出的契约/产物）时，**必须串行**。
  线性依赖链上的"并行"只会造成重复实现与文件损坏。
- 同一个任务**绝不允许**被并发派发两次（曾导致重复类型定义与文件损坏）。
- 校验/检查类工作（build、test、lint、boundary scan）可以按语言/模块切片后并行，
  因为它们只读源码、互不写入。

## 3. 失败与环境异常

- `Sub-agent execution was cancelled`、`Too many requests, throttled`、
  `Deserialization error` 属于**环境/编排异常**，不是任务失败：重试同一个单点派发。
- 含 `xcodebuild` 的长任务更容易被取消：拆成"实现 + swift test"与"xcodebuild 校验"两步。
- 真正的任务失败要停下来上报，不做自动重试掩盖。

## 4. 不变量 (子代理必须遵守)

- 保留所有与本任务无关的未提交改动，不得回滚其他任务的成果。
- `.tauri/cfw-rs.key` 始终是发布阻断项 (Requirement 8.1)，**永不读取其内容**。
- 永不重新引入：legacy root data plane、私有 NE API、direct-payload Tunnel、
  provider-local production authority、任何 fallback / 掩盖式降级。
- 物理机/签名环境缺失时必须 fail-closed 报 `not-run` / `blocked`，禁止伪造通过。
