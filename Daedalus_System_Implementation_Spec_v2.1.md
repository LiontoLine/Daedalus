# 工业级多模型协同自演进引擎技术规范书

**工程代号：Daedalus**\
**文档版本：System Implementation Spec v2.1（安全与生产落地增强版）**\
**目标：安全、可落地、可恢复、可审计、可持续演进、可上线**

------------------------------------------------------------------------

## 0. 文档定位与修订原则

本版本以原 `System Implementation Spec v2.0`
为基础，仅对影响**安全、上线、可靠性、可持续维护和工程落地**的关键缺口进行补强。

核心设计原则保持不变：

> **确定性系统统筹不确定性模型；状态沙盒隔离；基于形式化契约与事件日志驱动；增量容错与幂等重跑。**

本版本不追求一次性实现所有企业级能力，而采用：

> **单机最小闭环 → 安全加固 → 多执行器 → 可观测性 → 自演进**

的渐进路线。

### 0.1 设计取舍

  --------------------------------------------------------------------------
  原则                                处理方式
  ----------------------------------- --------------------------------------
  不为了"工业级"而过度分布式          Phase 1/2 默认单机优先

  不把 LLM 当作可信执行主体           LLM 永远运行在确定性控制面约束下

  不把 SHA256 当作完整防篡改机制      SHA256
                                      用于完整性；身份/审批/签名另行处理

  不把 LLM Review 称为真正形式化验证  Tier-2 定义为语义审查

  不追求全局副作用自动回滚            首期明确只保证代码/任务状态回滚

  自演进不允许自修改安全边界          控制面、Gatekeeper、安全策略必须受
                                      Meta-Spec 保护

  先实现可恢复，再实现高并发          Scheduler、FSM、幂等优先于大规模并发
  --------------------------------------------------------------------------

------------------------------------------------------------------------

# 1. 核心架构与信任边界

## 1.1 总体架构

``` text
┌─────────────────────────────────────────────────────────────┐
│                    Owner / Human Control                    │
│  需求确认 / Spec签批 / 高风险审批 / ESCALATE处理 / 发布批准 │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Planner / High-Reasoning LLM                               │
│ 需求澄清 → 规划 → 生成 Tri-Spec                            │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Immutable Spec Registry                                     │
│ SPEC-01 Goal │ SPEC-02 Plan │ SPEC-03 Boundary │ Meta-Spec │
│ Version + Digest + Owner Identity + Approval Record         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Deterministic Scheduler / FSM                               │
│ DAG Ready Nodes / Quota / Lease / Timeout / Retry           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
       ┌────────────────┐    ┌────────────────┐
       │ Sandbox A      │    │ Sandbox B      │
       │ Worktree       │    │ Worktree       │
       │ Container      │    │ Container      │
       └───────┬────────┘    └───────┬────────┘
               │                     │
               └──────────┬──────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Gatekeeper Pipeline                                         │
│ Tier-1 Deterministic Gate                                  │
│  Path / AST / Linter / Type / Test / Resource / Artifact    │
│                           ↓                                 │
│ Tier-2 Semantic Review LLM                                  │
│  Goal / Plan / Diff / Intent / Acceptance Criteria          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Authoritative Control Plane                                 │
│ FSM State + Event Store + Commit Metadata + Artifact Index  │
│ SQLite WAL（Phase 1/2） → 可替换持久化层（后续）             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                 Git Main / Release Branch

旁路安全系统：
Audit Log / Metrics / Trace / Secret Broker / Resource Quota
```

## 1.2 信任边界

系统必须明确区分：

1.  **控制面（Trusted Control Plane）**
    -   FSM
    -   Scheduler
    -   Spec Registry
    -   Gatekeeper
    -   Event Store
    -   Git Commit Coordinator
    -   安全策略执行器
2.  **模型面（Untrusted Intelligence Plane）**
    -   Planner LLM
    -   Coding LLM
    -   Review LLM
3.  **执行面（Untrusted Execution Plane）**
    -   Agent 生成代码
    -   Shell 命令
    -   测试程序
    -   第三方依赖
    -   网络访问

原则：

> **模型输出不直接改变权威状态；模型只能提交候选结果，由确定性控制面验证并决定状态迁移。**

------------------------------------------------------------------------

# 2. Tri-Spec 形式化契约体系

## 2.1 SPEC-01：Raw Goal Contract

定义任务最终目标：

``` json
{
  "spec_type": "goal",
  "schema_version": 1,
  "goal_id": "GOAL-001",
  "invariants": [],
  "acceptance_criteria": [],
  "risk_level": "normal"
}
```

必须包含：

-   唯一 goal_id
-   schema_version
-   invariants
-   acceptance_criteria
-   risk_level

### acceptance_criteria 要求

优先使用可执行断言：

-   exit code
-   test result
-   expected file
-   AST property
-   schema validation
-   type checking
-   deterministic script

自然语言验收条件可以存在，但不得成为唯一验收依据。

------------------------------------------------------------------------

## 2.2 SPEC-02：DAG Execution Plan

每个节点至少包含：

``` json
{
  "node_id": "stage-01_step-03",
  "deps": ["stage-01_step-02"],
  "expected_artifacts": [],
  "allowed_tools": [],
  "retry_policy": {},
  "timeout_sec": 300
}
```

要求：

-   DAG 不得存在环
-   node_id 全局唯一
-   deps 必须存在
-   expected_artifacts 必须可验证
-   timeout 必须有限
-   retry 必须有限
-   每个节点必须能够映射到明确的状态机生命周期

------------------------------------------------------------------------

## 2.3 SPEC-03：Security & Resource Boundary

至少包含：

``` json
{
  "fs_whitelist": ["src/**/*.py", "tests/**/*.py"],
  "network_policy": "deny",
  "allowed_domains": [],
  "max_tokens_per_step": 20000,
  "max_runtime_sec": 300,
  "cpu_limit": 2,
  "memory_mb": 4096,
  "disk_mb": 20480,
  "process_limit": 128
}
```

安全边界包括：

-   文件系统
-   网络
-   CPU
-   内存
-   磁盘
-   进程数
-   Token
-   Runtime
-   工具调用权限

------------------------------------------------------------------------

## 2.4 Meta-Spec：系统自身的不可越权边界

为 Self-Hosting 增加第四类系统级契约：

``` text
Meta-Spec
├── 哪些目录允许 Agent 修改
├── 哪些模块禁止 Agent 自修改
├── 哪些安全策略必须人工审批
├── Gatekeeper 是否允许被当前任务修改
├── Scheduler / FSM / Event Store 是否允许自修改
└── 哪些修改必须重新部署控制面
```

默认：

> **Agent 不得直接修改
> Meta-Spec、Gatekeeper、安全策略、凭证系统和控制面核心代码。**

涉及这些模块的修改必须：

1.  创建独立 Change Request
2.  由 Owner 审批
3.  使用独立审核流程
4.  在隔离环境中验证
5.  通过发布门禁后才能部署

------------------------------------------------------------------------

# 3. Spec 完整性、版本与签名

## 3.1 Digest

保留原方案：

``` text
SPEC_DIGEST = SHA256(canonical(spec1 + spec2 + spec3 + metaspec))
```

但增加：

-   JSON Canonicalization
-   schema_version
-   spec_version
-   created_at
-   owner_id
-   parent_spec_digest

Digest 负责：

> **完整性和版本关联**

而非独立承担身份认证。

## 3.2 高风险 Spec 签名

生产环境中：

``` text
Owner Identity
      ↓
Spec Digest
      ↓
Digital Signature
      ↓
Registry
```

高风险修改必须验证：

-   签名
-   Owner 身份
-   权限
-   审批状态

------------------------------------------------------------------------

# 4. FSM：权威状态机

## 4.1 Step 生命周期

标准状态：

``` text
PENDING
  ↓
READY
  ↓
LEASED
  ↓
RUNNING
  ↓
AWAITING_GATEKEEPER
  ↓
TIER1_PASSED
  ↓
TIER2_REVIEWING
  ↓
APPROVED
  ↓
COMMITTING
  ↓
COMMITTED
```

异常状态：

``` text
FAILED
REVISE
CANCELLED
SUPERSEDED
STALE
ESCALATED
TIMEOUT
LOST
```

## 4.2 核心状态转换原则

任何状态迁移必须：

``` text
Validate Precondition
        ↓
Append Event
        ↓
Persist State
        ↓
Emit Side Effect
```

不得：

``` text
修改数据库状态
↓
执行副作用
↓
最后再写事件
```

否则异常中断时会产生状态悬空。

## 4.3 状态机必须拒绝非法迁移

例如：

``` text
COMMITTED → RUNNING
```

默认非法。

重新执行必须：

``` text
RollbackEvent / ReplayRequest
↓
创建新 Execution ID
↓
新的 DAG Run
```

而不是覆盖历史 Execution。

------------------------------------------------------------------------

# 5. Event Store 与幂等协议

## 5.1 Event Schema

事件至少包含：

``` json
{
  "event_id": "evt-uuid",
  "aggregate_id": "step-001",
  "execution_id": "run-002",
  "sequence": 42,
  "event_type": "StepCommitted",
  "schema_version": 1,
  "actor": "executor-01",
  "timestamp": "ISO-8601",
  "correlation_id": "req-001",
  "causation_id": "evt-041",
  "payload": {}
}
```

## 5.2 幂等键

所有可能重试的操作必须拥有幂等键：

``` text
idempotency_key =
execution_id + step_id + operation_type
```

例如：

``` text
run-02:step-03:commit
run-02:step-03:gate
run-02:step-03:artifact-upload
```

重复请求：

> 返回已有结果，不重复执行危险副作用。

## 5.3 Sequence

同一个 aggregate 必须使用单调递增 sequence：

``` text
1 → 2 → 3 → 4
```

发现：

``` text
1 → 3
```

必须拒绝写入或进入冲突恢复流程。

------------------------------------------------------------------------

# 6. Scheduler 与并发控制

## 6.1 Scheduler 职责

Scheduler 负责：

-   DAG Ready Node 计算
-   并发限制
-   资源配额
-   Lease
-   Timeout
-   Retry
-   优先级
-   失败传播
-   节点失效
-   Worker 恢复

## 6.2 Ready Node 规则

节点满足：

``` text
所有 deps == COMMITTED
AND
自身 == PENDING/READY
AND
Spec Digest 匹配
AND
资源满足
AND
没有 active lease
```

才能进入 READY。

## 6.3 Lease

Worker 获取任务时：

``` text
PENDING
 ↓
READY
 ↓
LEASED
```

Lease 包含：

-   lease_id
-   worker_id
-   acquired_at
-   expire_at

Worker 崩溃：

``` text
LEASE EXPIRED
↓
LOST
↓
RECOVER
↓
RETRY / ESCALATE
```

防止任务永久卡死。

## 6.4 并发资源

至少支持：

``` text
max_parallel_steps
max_cpu
max_memory
max_gpu
max_llm_requests
max_tokens_per_run
```

Phase 1 可以只实现：

``` text
max_parallel_steps
CPU
Memory
Token
```

其他资源在后续扩展。

------------------------------------------------------------------------

# 7. Sandbox 与执行安全

## 7.1 双层隔离

### Git Worktree

负责：

-   代码工作区隔离
-   Diff 边界
-   Commit 基线

### Container

负责：

-   进程隔离
-   文件系统挂载
-   网络隔离
-   资源限制

两者不得混为一谈。

## 7.2 Container 默认安全策略

生产环境默认：

``` text
非 Root
网络关闭
只读 Base Image
最小 Capability
限制 Process
限制 CPU
限制 Memory
限制 Disk
限制 Runtime
禁止 Docker Socket
禁止宿主机敏感目录挂载
禁止宿主机凭证直接注入
```

## 7.3 网络策略

默认：

``` text
DENY ALL
```

如果 SPEC-03 明确允许：

``` text
ALLOWLIST
```

只允许访问明确声明的域名/IP/端口。

禁止：

``` text
Agent 自己修改 network_policy
```

## 7.4 依赖安装

保留原有：

> 不允许 Agent 直接在宿主环境执行 pip install/npm install。

进一步要求：

``` text
Dependency Manifest
↓
Lock File
↓
Dependency Validation
↓
Trusted Cache / Mirror
↓
Sandbox
```

禁止任意运行时下载未知依赖。

------------------------------------------------------------------------

# 8. Secret 与凭证管理

Agent 不得直接获得：

-   数据库长期密码
-   云平台长期 Access Key
-   Git 主账号 Token
-   系统管理员凭证

应采用：

``` text
Agent
 ↓
Capability Request
 ↓
Secret Broker
 ↓
短期凭证
 ↓
指定 Scope
 ↓
自动过期
```

原则：

> **最小权限、最短生命周期、默认无凭证。**

Secret 不得写入：

-   Git
-   Event Payload
-   execution_log
-   LLM Prompt
-   Artifact

日志必须执行 Secret Redaction。

------------------------------------------------------------------------

# 9. Gatekeeper

## 9.1 Tier-1：确定性门禁

必须包括：

1.  路径白名单
2.  Git Diff 检查
3.  Schema 验证
4.  AST / Syntax
5.  Linter
6.  Type Check（适用时）
7.  Unit Test
8.  Artifact 检查
9.  资源使用检查
10. 禁止文件检查

Tier-1 失败：

``` text
直接 REVISE / FAILED
```

不得调用 Tier-2 浪费模型成本。

## 9.2 Tier-2：语义审查

输入：

``` text
SPEC-01
SPEC-02
Git Diff
Changed Files
Execution Log
Tier-1 Result
Intent
```

输出必须为结构化 JSON：

``` json
{
  "decision": "APPROVE",
  "reasons": [],
  "violations": [],
  "confidence": 0.0
}
```

允许：

``` text
APPROVE
REVISE
ESCALATE
```

### 重要限制

Tier-2：

> **不是形式化证明。**

它只能作为语义风险筛查。

高风险模块不能仅依赖 Tier-2 放行。

------------------------------------------------------------------------

# 10. 高风险变更策略

以下变更默认提高风险等级：

-   安全策略
-   权限
-   网络策略
-   Secret
-   Scheduler
-   FSM
-   Event Store
-   Gatekeeper
-   数据库迁移
-   CI/CD
-   Release 配置
-   Meta-Spec

风险等级：

``` text
LOW
NORMAL
HIGH
CRITICAL
```

### CRITICAL

必须：

``` text
Tier-1
+
Tier-2
+
独立验证
+
Owner Approval
```

必要时：

``` text
禁止自动 Merge
```

------------------------------------------------------------------------

# 11. Commit 与一致性

## 11.1 Commit 前提

只有：

``` text
Tier-1 PASS
AND
Tier-2 APPROVE
AND
Spec Digest MATCH
AND
Worktree Base Commit MATCH
AND
Execution 未过期
```

才能进入：

``` text
COMMITTING
```

## 11.2 Commit 冲突

如果主分支已经发生变化：

``` text
Base Commit != Current Main
```

不得强制覆盖。

进入：

``` text
REBASE_REQUIRED
```

然后重新：

``` text
Rebase
↓
Tier-1
↓
Tier-2
↓
Commit
```

避免使用：

``` text
git push --force
```

破坏权威历史。

------------------------------------------------------------------------

# 12. Rollback / Replay

## 12.1 原则

保留原设计：

> **禁止原位删除历史。**

回滚实际含义：

``` text
RollbackEvent
↓
停止受影响执行
↓
CANCELLED / SUPERSEDED
↓
创建新的 Execution ID
↓
从目标 Commit Replay
```

## 12.2 代码状态与外部副作用必须分开

系统明确区分：

### 可回滚

-   Git Commit
-   Worktree
-   DAG State
-   Event State
-   Sandbox

### 默认不可自动回滚

-   第三方 API
-   外部数据库写入
-   已发送邮件
-   已上传文件
-   已创建云资源
-   外部系统状态

对于外部副作用，采用：

``` text
Idempotency
Compensation
Manual Recovery
```

而不是声称系统能够"全局回滚"。

------------------------------------------------------------------------

# 13. Spec 变更与增量重计算

## 13.1 变更类型

### A：Goal 破坏性变更

``` text
Archive Old Run
↓
New Spec Digest
↓
New Execution
```

### B：Plan 局部变更

计算：

``` text
Changed Nodes
↓
Downstream Closure
↓
STALE
↓
Selective Replay
```

### C：Boundary 变更

根据：

-   affected paths
-   affected tools
-   network changes
-   dependency changes

确定影响范围。

## 13.2 缓存复用前提

任何 Artifact 只有在以下条件同时满足时才能复用：

``` text
Spec Digest MATCH
Code Base Commit MATCH
Dependency Digest MATCH
Toolchain Digest MATCH
Input Artifact Digest MATCH
```

否则：

``` text
INVALIDATE
```

防止错误缓存。

------------------------------------------------------------------------

# 14. Artifact 体系

每个 Step 必须产生：

``` json
{
  "step_id": "...",
  "execution_id": "...",
  "parent_commit": "...",
  "changed_files": [],
  "patch_digest": "...",
  "artifact_digest": "...",
  "spec_digest": "...",
  "dependency_digest": "...",
  "execution_log_ref": "...",
  "gate_result_ref": "...",
  "status": "AWAITING_GATEKEEPER"
}
```

Artifact 必须可追溯到：

``` text
Goal
→ Spec
→ Plan
→ Step
→ Execution
→ Worker
→ Container Image
→ Dependency
→ Diff
→ Test
→ Gate
→ Commit
```

------------------------------------------------------------------------

# 15. 可观测性

生产上线必须至少记录：

## Metrics

``` text
task_success_rate
step_success_rate
retry_rate
rollback_rate
gate_reject_rate
llm_latency
llm_token_usage
sandbox_runtime
queue_latency
resource_usage
```

## Logs

日志必须具备：

-   execution_id
-   step_id
-   event_id
-   worker_id
-   timestamp

并执行：

``` text
Secret Redaction
```

## Trace

核心链路：

``` text
Request
 → Planner
 → Spec
 → Scheduler
 → Worker
 → Sandbox
 → Gate
 → Commit
```

使用统一：

``` text
correlation_id
```

进行追踪。

------------------------------------------------------------------------

# 16. 故障恢复矩阵

  故障                 系统行为
  -------------------- -------------------------------
  Planner 崩溃         Planner Task 超时并重试
  Worker 崩溃          Lease 过期 → LOST → 重试
  Container 崩溃       保存日志 → 销毁 → Retry
  Tier-1 失败          REVISE
  Tier-2 REVISE        当前 Worktree 修复，最多 3 次
  Tier-2 ESCALATE      冻结并等待 Owner
  SQLite 暂时不可写    停止状态迁移，禁止继续 Commit
  Git Commit 冲突      REBASE_REQUIRED
  Spec Digest 不匹配   拒绝执行/提交
  超时                 TERMINATE → TIMEOUT
  主进程重启           从 Event Store 恢复 FSM
  Sandbox 泄漏         强制清理 + 告警
  Artifact 缺失        标记失败，不允许 Commit

------------------------------------------------------------------------

# 17. Retry 策略

禁止无限 Retry。

建议：

``` text
Tier-1
最多 3 次

Tier-2 REVISE
最多 3 次

基础设施错误
指数退避
最多 N 次

逻辑错误
不得无限自动重试

连续失败
→ ESCALATE
```

区分：

### 可重试错误

-   网络暂时失败
-   LLM Timeout
-   Worker Crash
-   Container Startup Failure

### 不应自动重试

-   Spec 冲突
-   权限拒绝
-   安全边界违规
-   确定性测试失败
-   非法状态迁移
-   Meta-Spec 违规

------------------------------------------------------------------------

# 18. 数据存储

## Phase 1 / Phase 2

使用：

``` text
SQLite WAL
```

保存：

-   Run
-   Step
-   State
-   Event
-   Lease
-   Artifact
-   Gate Result
-   Spec Metadata

SQLite 是单机阶段的权威状态库。

## 后续扩展

当出现：

-   多节点 Executor
-   高并发
-   多租户
-   大规模事件

再替换为：

``` text
PostgreSQL / Distributed Event Store
```

要求：

> 上层 FSM 与 Event API 尽量与底层数据库解耦。

------------------------------------------------------------------------

# 19. 数据库核心实体

至少包括：

``` text
runs
steps
events
leases
specs
artifacts
gate_results
workers
executions
```

推荐关系：

``` text
Run
 ├── Spec
 ├── Steps
 │    ├── Execution
 │    ├── Events
 │    ├── Artifacts
 │    └── GateResults
 └── Commit
```

------------------------------------------------------------------------

# 20. Self-Evolution 安全模型

系统自演进必须分级。

## Level 0：普通业务代码

允许：

``` text
自动规划
→ Sandbox
→ Gate
→ Commit
```

## Level 1：基础设施普通模块

需要：

``` text
增强测试
+
独立 Review
```

## Level 2：控制面

涉及：

-   Scheduler
-   FSM
-   Event Store

需要 Owner Approval。

## Level 3：安全控制面

涉及：

-   Gatekeeper
-   Meta-Spec
-   Secret
-   Network Policy
-   Permission

默认：

> **禁止系统自行上线。**

必须：

``` text
Human Approval
+
Independent Validation
+
Release Gate
```

------------------------------------------------------------------------

# 21. 防止"自修改监管系统"

必须建立以下硬规则：

``` text
被审查任务
    X
不能修改
    ↓
当前正在使用的 Gatekeeper
    ↓
当前执行的 Security Policy
    ↓
当前 Event Store
    ↓
当前 FSM
```

如果需要修改上述组件：

``` text
Current System
      ↓
Create Upgrade Branch
      ↓
Independent Sandbox
      ↓
Independent Gatekeeper
      ↓
Owner Approval
      ↓
New Version Deployment
```

即：

> **新版本系统不能自己决定自己是否可以替换当前监管系统。**

------------------------------------------------------------------------

# 22. Release Pipeline

生产发布：

``` text
Development
 ↓
Sandbox
 ↓
Tier-1
 ↓
Tier-2
 ↓
Integration Validation
 ↓
Security Gate
 ↓
Owner Approval
 ↓
Release Candidate
 ↓
Canary
 ↓
Production
```

初期可以简化为：

``` text
Sandbox
 ↓
Tier-1
 ↓
Tier-2
 ↓
Owner Approval
 ↓
Production
```

后续再增加 Canary。

------------------------------------------------------------------------

# 23. Phase 1：可运行 MVP

目标：

> **先证明整个闭环，而不是追求多 Agent。**

实现：

-   Python FSM
-   SQLite
-   三 Spec Schema
-   Spec Digest
-   Git Worktree
-   单 Container
-   Tier-1
-   单 Worker
-   Event Store
-   Rollback
-   基础日志

验收：

``` text
模拟任务
→ Planner 输出 Spec
→ 创建 Worktree
→ 修改代码
→ 越界修改被拒绝
→ 语法错误被拒绝
→ 测试失败被拒绝
→ 合法代码通过
→ Commit
→ Event 完整
```

------------------------------------------------------------------------

# 24. Phase 2：多模型与恢复

增加：

-   Planner LLM
-   Coding LLM
-   Review LLM
-   Scheduler
-   多 Sandbox
-   Lease
-   Retry
-   Event Replay
-   Rollback
-   Artifact Registry
-   Resource Quota

验收：

``` text
2+ 并发 Step
+
Worker Crash
+
Container Crash
+
Retry
+
Rollback
+
Process Restart
```

系统都能恢复。

------------------------------------------------------------------------

# 25. Phase 3：生产安全加固

增加：

-   Secret Broker
-   Network Allowlist
-   Container Security Profile
-   Metrics
-   Trace
-   Alert
-   Backup
-   Database Recovery
-   Release Gate
-   Owner Approval
-   Audit Export

上线前必须完成：

``` text
权限测试
越权测试
网络隔离测试
Secret 泄漏测试
Container Escape 防护验证
状态恢复测试
重复事件测试
数据库恢复测试
Git 冲突测试
```

------------------------------------------------------------------------

# 26. Phase 4：Self-Evolution

最后才开启：

``` text
系统自规划
系统自编码
系统自测试
系统生成 PR
```

但：

``` text
安全边界
控制面
Gatekeeper
Meta-Spec
Secret
```

仍然保持人工控制。

------------------------------------------------------------------------

# 27. 最小生产上线标准

系统不得因为：

> "LLM 能写代码"

就被认为可以上线。

至少满足：

### 正确性

-   FSM 完整
-   DAG 正确
-   Commit 原子性明确
-   Event 可恢复
-   Retry 有上限

### 安全

-   默认断网
-   非 Root
-   最小权限
-   Secret 不进入模型上下文
-   禁止宿主机敏感挂载
-   路径白名单

### 可恢复

-   Process Restart 可恢复
-   Worker Crash 可恢复
-   Container Crash 可恢复
-   Git Conflict 可处理
-   Rollback 可验证

### 可审计

可以回答：

``` text
谁？
什么时候？
基于哪个 Spec？
用了哪个 Model？
用了哪个 Image？
修改了什么？
运行了什么？
测试结果？
谁批准？
最终 Commit？
```

------------------------------------------------------------------------

# 28. 生产前必须完成的 P0 Checklist

``` text
[ ] FSM 状态和迁移表
[ ] Event Schema
[ ] Idempotency
[ ] Scheduler Lease
[ ] Retry Policy
[ ] Process Recovery
[ ] Sandbox 强制清理
[ ] Spec Version / Digest
[ ] Git Commit 一致性
[ ] Security Boundary
[ ] Secret Redaction
[ ] Container Non-root
[ ] Network Default Deny
[ ] Resource Quota
[ ] Audit Log
[ ] Backup / Restore
[ ] High-risk Approval
[ ] Meta-Spec
[ ] Self-Evolution Permission Boundary
```

------------------------------------------------------------------------

# 29. 最终架构结论

Daedalus 的核心路线保持：

``` text
LLM
 ↓
Formal Spec
 ↓
DAG
 ↓
Deterministic Scheduler
 ↓
Sandbox
 ↓
Deterministic Gate
 ↓
Semantic Gate
 ↓
Event Store
 ↓
Commit
 ↓
Replay / Rollback
```

该架构的核心价值不是：

> "让更多 Agent 一起工作"。

而是：

> **把不确定的模型能力限制在可验证、可恢复、可审计的确定性工程系统中。**

最终目标不是追求：

> **完全无人值守**

而是：

> **在低风险任务上自动化，在高风险任务上可控，在失败时可恢复，在出现争议时可审计，在系统演进时不破坏自身安全边界。**

这也是本系统能够从 MVP 逐步走向生产环境的核心条件。

------------------------------------------------------------------------

# 30. 建议的最终实施优先级

``` text
P0
FSM
Event
Idempotency
Scheduler
Sandbox
Security
Recovery

        ↓

P1
Multi-Agent
Tier-2
Artifact
Observability
Resource Quota

        ↓

P2
UI
Distributed Worker
Advanced Cache
Canary

        ↓

P3
Self-Evolution
```

**原则：永远不要为了实现 P3 的"自演进"，跳过 P0 的"可恢复与安全"。**
