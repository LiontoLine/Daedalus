# 与 AgentPanelX 的关系

本文档记录 Daedalus 从 [AgentPanelX](https://github.com/aowo-1345/AgentPanelX)（MIT）
复用、改写与**刻意不复用**的内容，以便后续迭代时知道哪些决定是继承的、哪些是我们自己的。

本文件保留设计继承与选择性移植记录，不依赖开发者本机副本。上游与本项目会继续演进，下表描述采用时的参考关系，不是对上游当前全部能力的评价。

---

## 1. 继承的设计理念

### 1.1 权威数据源分离

AgentPanelX 的做法（`docs/architecture.md` §4）：不用一个状态对象描述整个项目，
而是让每类事实归最合适的存储——身份归 registry、对话归 message_history、
状态归 runtime_state、Plan 文档归 Git、状态到达路径归 execution_event。

Daedalus 的对应实现：

| AgentPanelX | Daedalus |
| --- | --- |
| `workspace_registry.py`（项目身份） | `runs` 表 + `specs` 表 |
| `project_runtime_state`（Feature 状态） | `steps` / `runs` 投影 |
| `message_history`（对话与工具活动） | `events`（不可变事件日志）+ `timeline` |
| Git 保存 Plan 文档 | Git 保存代码与 commit |
| `execution_event`（状态到达路径） | `events` + `timeline` |

**关键差异**：AgentPanelX 的事件表是投影（`execution_event` 带 autoincrement id，
服务于 Timeline 展示）；Daedalus 把事件日志提升为**唯一权威**，投影降级为可重建缓存。
这使"从事件恢复 FSM"成为一条被测试验证的路径（`rebuild_step_states()`），
而不只是一个设计意图。

### 1.2 Durable Activation（先持久化，再执行）

AgentPanelX 的 `fail_interrupted_work()`：进程中断后把遗留工作归并为
`FAILED + BLOCKED`，**绝不自动续跑**。理由很有说服力——长周期交付中，
隐式恢复比失败更危险，因为它会基于过期上下文继续改代码。

Daedalus 继承了这条判断，并把它落到更细的粒度：

- 状态迁移的**四步顺序**写死在 `fsm_service.py`：校验 → 事件 → 状态 → 副作用，同事务。
- 幂等占用与提交副作用同事务，因此崩溃重试不会产生第二个 commit。
- `daedalus verify` 把"投影 = 事件日志重放结果"变成可随时执行的一致性检查。

### 1.3 Subject Digest + fail-closed 的门禁

AgentPanelX 的 `plan_hard_gate.py` 做了一件很关键的事：让 reviewer 回显它审查的对象
摘要，不匹配就拒绝；`APPROVE` 不允许带 `required_changes`，`REVISE` 必须带具体改动；
reviewer 输出畸形一律 fail-closed。

Daedalus 的 `tier2.py` 直接采用并扩展了这套约束：

| AgentPanelX 规则 | Daedalus 对应 |
| --- | --- |
| manifest 必须回显 `subject_digest` | `subject_digest` 不匹配 → `ESCALATE` |
| `pass` 不得带 `required_changes` | `APPROVE` 带 `violations` → `ESCALATE` |
| `revise` 必须带 `required_changes` | `REVISE` 无 `violations` → `ESCALATE` |
| 解析/校验失败抛错并 fail closed | 六类畸形输出全部 → `ESCALATE`，逐个参数化测试 |
| `version: Literal[1]` 的 manifest 版本 | `SemanticReviewResult` + schema 校验 |

**关键差异**：AgentPanelX 的 Hard Gate 是**单一模型层**门禁（Codex Reviewer）。
Daedalus 严格按照 Spec §9 拆成两层，并加上一条单向性约束：
**Tier-2 只能让结果更保守，永远不能救活 Tier-1 失败。**
`test_pipeline_never_calls_tier2_after_a_tier1_failure` 断言 Tier-1 失败时
reviewer 的 `complete()` **零调用**——这是 AgentPanelX 那套设计里没有的约束。

### 1.4 Git worktree 隔离

AgentPanelX 为每个 Feature/Stage 建独立 worktree，并用 `stage_run_one_active_idx`
这个**部分唯一索引**在数据库层强制"同一 triage 同时只有一个活跃 stage"。

Daedalus 使用调度器、租约和每步骤 worktree 管理并发，并将候选集成到 run 分支；整体成功后才提升到目标分支。worktree 提供代码工作区分离，不等于宿主文件系统或网络的强隔离，实际能力须由所选驱动探测。

---

## 2. 选择性移植的代码

| Daedalus 文件 | 源自 AgentPanelX | 改动 |
| --- | --- | --- |
| `infrastructure/store/schema.py` | `infrastructure/sqlite/schema.py` | 表结构完全重设（8 张表 → 11 张，语义不同）；保留 `PRAGMA user_version` 版本门与"拒绝更新版本数据库"的行为 |
| `infrastructure/store/event_store.py` | `sqlite/database.py` + `repositories/execution_event.py` | 增强：`UNIQUE(aggregate_id, sequence)` 物理约束、`append_in_transaction`、`verify_sequences()`、通用 `idempotency` 表 |
| `infrastructure/git_sandbox.py` | `infrastructure/git_repository.py` | 增强：`update-ref` CAS 集成、`resolve_inside()` 路径穿越拒绝、rlimit 子进程、环境净化 |
| `application/gatekeeper/tier2.py` | `services/plan_hard_gate.py` | 重写为协议化 reviewer + 六类 fail-closed 分支；`_extract_json` 的围栏容忍逻辑保留 |
| `infrastructure/redact.py` | 无直接对应（AgentPanelX 在写入侧零散处理） | 新建为**唯一出口**，按键名 + 值形状双重脱敏 |
| `model/mock.py` | `infrastructure/codex.py` 的 `driver_mode=TOOL` 思路 | "无需 API Key 也能走通全流程"这一判断被继承；实现改为确定性 responder |
| `domain/pathglob.py` | 无 | AgentPanelX 没有文件系统边界，这是 Net-new |

**没有移植的**：Project Owner ReAct 循环、Rolling Summary/CAS 压缩、Planner/Reviewer
协作编排、Codex CLI transport、Web Console、Workspace Dispatcher。

---

## 3. 刻意不复用的部分

| AgentPanelX 有 | Daedalus 为什么不做同样的事 |
| --- | --- |
| Project Owner 是长驻 Agent，用自然语言维护意图 | Daedalus 的意图固定在 **SPEC-01 冻结契约**里。意图可以是自然语言，但验收条件必须是可执行断言——否则门禁无从判定 |
| 用 `talk_to_agent` 在 Agent 间自由协作 | 自由协作没有确定性边界。Daedalus 用 DAG 节点 + `allowed_tools` + SPEC-03 限定协作形态 |
| Hard Gate 只有一层 | Spec §9 要求确定性层与语义层分离，且确定性层必须优先（省成本 + 不可被模型说服） |
| Feature 状态机与看板列同构 | Daedalus 的 step 状态机单独建模租约、两层门禁、漂移与重放，不以看板列定义状态契约 |
| 无文件系统边界（靠 worktree 本身隔离） | Spec §2.3 明确要求 `fs_whitelist` / `network_policy` / 资源上限；worktree 只给代码边界，不给进程与网络边界 |
| 没有幂等键概念 | Spec §5.2 要求所有可能重试的操作都有幂等键 |
| SQLite 只是运行时状态 | Daedalus 把事件日志当权威事实源，投影可重建 |

---

## 4. 从 AgentPanelX 学到的工程习惯（已采纳）

1. **测试与源码等量齐观**。边界和门禁测试应覆盖系统必须拒绝的路径，而不只覆盖正常流程。
2. **默认测试不调用真实模型网关**。使用合成凭证和本机假服务；部分测试仍需要本机监听权限，不能将其描述为完全不使用网络栈。
3. **不在基础设施层做业务决策**。AgentPanelX 的 `AGENTS.md` 明确写了这条，
   Daedalus 的 `domain` 层不允许 I/O 是同一原则的更强版本。
4. **不把 fixture 数据当作功能证据**。AgentPanelX 的 AGENTS.md 特别强调
   Showcase 数据只是演示夹具。Daedalus 的 demo 因此建在**真实 Git 仓库 + 真实 SQLite
   + 真实门禁**上，而不是 mock 掉这些层。
5. **显式声明前提缺失**。AgentPanelX 对 `bwrap`、Codex CLI 等缺失前提会明确报错。
   Daedalus 继承：不传 `--model` 时 CLI 会明确说"这不会产出代码"。

---

## 5. 许可与署名

AgentPanelX 采用 MIT 许可。Daedalus 是独立代码库，但并非“没有参考或移植”：上表保留选择性移植及局部结构改写记录。发布和再分发时应保留 [LICENSE](../LICENSE)、本来源说明及适用的上游版权和许可声明；新增直接复制内容还应在相应文件中记录来源。

项目首页应继续链接上游和本文件；不能用“独立代码库”代替履行第三方许可义务。其他第三方静态资源的许可与来源也应分别保留。

---

## 6. 并发、重放与持久化的设计取舍

并发、rebase、回滚与制品复用使以下两项取舍更重要：

1. **"先持久化，再执行"**。把事件日志当权威、投影当缓存，让 `StepCacheHit` 这种新状态
   可以只靠"追加一个带来源的事件"就接进来，不需要迁移状态或重建表。
   反过来，如果当初把 Feature 状态直接写在 `steps` 表里当权威，缓存命中这一步会变成
   "一次没有事件的状态跳变"——正好是本项目最不能接受的东西。
2. **"每个事实交给最适合它的存储"**。replay 需要知道仓库路径，我们没有加数据库列，而是
   从 `RunStarted` 事件里读。这不是技巧，而是这条原则的直接推论：事件日志记的是
   "发生了什么"，仓库路径就是发生的一部分。

同时有一处我们**刻意偏离**了 AgentPanelX：它用 `stage_run_one_active_idx` 这样的部分唯一
索引把并发约束压在数据库层。Daedalus 把并发约束放在 Scheduler + 租约上，因为一个 run
可以有多个 step 并行，而每个 step 都需要自己的 worktree 与租约——数据库唯一索引表达不了
"每个 step 一个沙箱"。约束没有变松，只是换了更合适的位置。
