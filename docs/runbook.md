# Daedalus 运维手册

本手册面向源码部署、日常审批与故障恢复。终端和网页启停见[服务控制指南](service-control.md)，设计边界见[架构说明](architecture.md)，能力与限制见[路线图](roadmap.md)。

> 默认仅监听本机回环地址。工作树、门禁、访问口令和日志脱敏分别解决不同问题；它们不等于完整的安全沙箱，也不能保证任意不可信代码在宿主机上安全运行。

## 1. 从源码安装

需要 Python 3.12 或更新版本、Git，以及支持所选沙箱驱动的运行环境。托管服务使用 POSIX 进程与文件锁机制；macOS 登录自启使用用户级 LaunchAgent。

在已取得的仓库根目录执行：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

以上安装的是当前源码，不依赖预先发布的 wheel。日常启动前激活同一虚拟环境；不要以管理员账户运行工程任务。将工作区与目标代码仓库分开管理，并限制服务账户对无关文件的访问。

### 建立持久配置

以下变量只是非敏感路径示例，后续命令在同一终端中使用：

```bash
CONFIG="$PWD/daedalus.toml"
WORKSPACE="$PWD/.daedalus"
daedalus init --path "$CONFIG" --workspace "$WORKSPACE"
daedalus config --config "$CONFIG"
```

配置优先级为：内置默认值 < 配置文件 < `DAEDALUS_*` 环境变量 < 对应命令的显式参数。未知配置键会被拒绝。工作区路径建议使用绝对路径：相对路径按进程工作目录解释，而不是自动相对于配置文件。

普通配置的服务默认值为：

```toml
[service]
host = "127.0.0.1"
port = 13475
auth_required = false
```

无参数终端入口创建的默认配置使用另一端口，详见[服务控制指南](service-control.md)。使用不同入口时应始终明确配置，避免误操作另一个工作区。

### 模型与凭证

优先通过网页「模型设置」配置连接。若使用环境变量，由可信凭证管理器或受控服务管理器向进程注入，并在 TOML 中仅声明 `api_key_env` 变量名。**不要把密钥写入命令行、Shell 历史、任务描述、提醒备注或仓库文件。**

连接测试会发起真实模型请求。使用非本机模型端点前，确认代码与任务上下文可以发送至该服务；连接成功不代表模型产出正确。持久保存的支持范围、系统钥匙串与临时会话行为见[模型设置](model-settings.md)和[凭证存储](model-credential-storage.md)。退出进程不会删除已经保存的系统凭证。

交互式提任务需要可用模型；不要把无模型运行、脚本化演示或界面可访问当作真实模型能力证明。

## 2. 部署与隔离

### 先检查实际隔离级别

```bash
daedalus preflight --config "$CONFIG"
```

`preflight` 会探测实际可用能力，不以“已安装命令行工具”代替运行时可用性。例如，容器驱动需要能连接的 Docker 或 Podman 守护进程；Seatbelt 需要当前进程能够应用 `sandbox-exec` profile。

| 驱动 | 提供的边界 | 必须理解的限制 |
| --- | --- | --- |
| `host-process` | 每步 Git worktree、清理后的环境、超时与部分资源限制 | 没有内核级文件系统或网络隔离；命令以服务账户身份执行，可读取该账户能读的文件并使用网络。门禁不能撤销已经发生的外部副作用。 |
| `seatbelt` | macOS 内核强制写边界，允许工作树和每步临时目录；运行时断网 | 不限制读取，不提供宿主文件机密性；不能实现域名网络白名单。`sandbox-exec` 已被 Apple 弃用，可用性必须现场探测。 |
| `container` | 容器命名空间、只读基础镜像、工作树挂载；默认 `--network none` | 依赖可信镜像、运行时及宿主配置，不等于虚拟机或绝对安全。网络白名单需要额外可执行配置，不能假定已有。 |

`auto` 按可用性及网络策略选择驱动，可能落到最弱的 `host-process`；**显式请求不可用的驱动会拒绝，不会静默降级**。可用以下命令检查指定级别：

```bash
daedalus preflight --config "$CONFIG" --isolation container
```

探测某级别不等于永久设置所有任务的隔离策略；提交任务前仍应核对其实际驱动、网络边界和证据。对不可信代码，不应接受 `host-process`，也不应把 Seatbelt 当作读隔离。不要为绕过依赖安装问题而临时放开网络；离线依赖流程见[依赖完整性](dependency-integrity.md)。

### 容器任务环境

宿主虚拟环境中的依赖不会自动出现在容器里。默认 `python:3.12-slim` 只提供基础 Python 环境，不能假定含有 `pytest` 或目标项目依赖。应在可信镜像构建阶段准备它们，任务执行期间仍保持禁网和只读根文件系统。

在源码根目录可为离线示例与 CI 构建测试镜像，并在启动服务或测试之前指定：

```bash
docker build --file .github/sandbox.Dockerfile --tag daedalus-ci-python:3.12 .github
export DAEDALUS_SANDBOX_IMAGE=daedalus-ci-python:3.12
```

`DAEDALUS_SANDBOX_IMAGE` 是部署级默认值；程序显式传入的 `sandbox_image` 优先。这个示例镜像包含 `pytest` 和 Node.js 24，不是任意项目的完整依赖环境，也不构成生产安全验收。运行器已安装 Node.js，并不意味着容器内也能执行它。生产镜像应单独审查并固定可信摘要。

容器以服务账户的非零 UID/GID 访问挂载工作树；为零或平台没有 POSIX 身份时使用非特权身份，不运行容器 root。非 root 服务账户拥有的私有工作目录不需要改成全员可读写。以 root 启动服务、Rootless 引擎或虚拟机文件共享时，仍需核实实际所有权映射和访问权限；不要用 `chmod 777`、挂载宿主凭证或开放任务网络来绕过失败。

### 选择启动方式

本机交互使用托管入口：

```bash
daedalus --config "$CONFIG" --open
```

由外部进程管理器部署时，可直接运行前台后端：

```bash
daedalus serve --config "$CONFIG"
```

`serve` 与托管入口不是同一种生命周期：前者没有托管进程提供的网页重启能力。不要同时让多个进程管理器管理同一个后端。外部管理器应配置固定工作目录、虚拟环境入口、独立服务账户、受控凭证注入，以及足以等待当前步骤批次结束的停止时间；停止时使用正常终止信号，不用强杀作为常规手段。

### 访问保护

默认回环监听且不要求登录，适合受信任的单用户本机环境，不适合共用账户或不可信网络。网页「访问设置」可先在本机设置独立访问口令，再启用登录或私有局域网访问。非回环监听要求 `service.auth_required = true` 且已配置口令，否则启动被拒绝。

当前访问保护面向**单操作员的本机 / 私有局域网**，不是多租户权限系统；访问登录不等于 Owner 审批身份。服务自身不提供 TLS。不要直接暴露公网，也不要假定私有网段就是加密、可信的链路；跨设备访问应另行配置受控网络、加密通道与防火墙。反向代理改变客户端地址和来源语义，不能仅凭代理可连通就认为保护仍然有效。

## 3. 日常任务与人工审批

从网页选择目标 Git 仓库、澄清需求、检查并冻结规格后再执行。执行前核对可写路径、验收命令、预算、风险等级和模型连接；服务启动本身不会执行工程任务。

| 风险 | 关键要求 |
| --- | --- |
| `low` / `normal` | 通过确定性门禁，并满足已启用的其他审查策略后才可提交。 |
| `high` | 执行前需要规格审批；语义审查不能推翻确定性失败。 |
| `critical` | 执行前需要规格审批；提交阶段仍要求人工处理强制升级，模型同意不能代替人工批准。 |

高风险规格未批准时，提交接口可返回 `428 spec_approval_required`。普通编码失败、语义拒绝、预算耗尽或不可重试错误以失败状态及停止原因呈现，不是授权请求，不能通过批准把失败变为通过。强制执行授权与完整目标通过后的交付复核是不同流程；规格授权和 CRITICAL 提交前授权仍是独立前提。

### 启用可核验的审批身份

建议在需要身份保证的部署中设置：

```toml
[identity]
required = true
```

由可信环境提前注入每位审批者独立的签名密钥，注册时仅传变量名，不传密钥值：

```bash
daedalus owners add --config "$CONFIG" \
  --owner-id maintainer --role owner --secret-env DAEDALUS_OWNER_SECRET
daedalus owners status --config "$CONFIG"
```

角色权限上限为：`viewer` 不可签批，`operator` 可处理至 `normal`，`reviewer` 至 `high`，`owner` 至 `critical`。Owner 注册属于本地特权操作，没有对应的 HTTP 注册接口。首次注册后即启用身份核验，不应把 `identity.required = false` 解释成可以忽略已登记身份。未启用核验时，仅记录名字的批准是**未核验人工声明**，不是签名证据。

对已冻结规格，先检查全文和完整摘要，再签署：

```bash
# SPEC_DIGEST 为待审规格摘要；签名不是原始密钥，也不应公开传播。
SIG=$(daedalus sign-spec --config "$CONFIG" --spec "$SPEC_DIGEST" --owner-id maintainer)
daedalus approve-spec --config "$CONFIG" --spec "$SPEC_DIGEST" \
  --by maintainer --signature "$SIG"
unset SIG
```

撤销 Owner 阻止新的签批，不抹除历史上已验证的批准；撤销最后一个 Owner 不会让工作区退回免核验模式。

### 处理强制执行授权

```bash
daedalus escalations --config "$CONFIG"
```

先确认运行状态为 `AWAITING_APPROVAL`，且后端明确记录该步骤需要执行授权（`execution_authorization_required=true`）；仅有步骤 `ESCALATED` 不足以批准。查看目标步骤的 diff、门禁证据、规格及当前制品，再决定：

| 决定 | 含义 |
| --- | --- |
| `proceed` | 回应有效授权请求，接受绑定的当前受审制品；不能接受失败候选或任意后续修改。 |
| `retry` | 回应有效授权请求，允许按明确次数再次尝试；不是对普通失败的人工重开。 |
| `reject` | 拒绝当前授权请求。 |

CLI 使用 `daedalus approve`，必须明确 `--run-id`、`--step`、`--decision` 和 `--by`。已启用身份核验时，高风险 `proceed` / `retry` 需要有效签名，可用 `sign-step` 生成；`reject` 不以签名阻挡安全拒绝。签名绑定运行、步骤、决定、制品与尝试次数，不能挪作其他决定使用。

没有有效授权请求、运行已经失败时，`approve` 会拒绝处理，而不是重启失败步骤。批准不能绕过摘要漂移、丢失工作树或未完成提交对账。处理有效决定后，如需继续仍应显式执行恢复；中断恢复另需审查当前断点，见[服务控制指南](service-control.md)。

### 完整目标通过后的独立交付复核

策略要求独立交付复核时，执行节点已经私有提交，完整原目标验收已通过，但真实目标分支尚未推进。复核使用新鲜验收收据、绑定精确候选的签名及独立审批主体；不能用 `approve` 批准失败步骤来代替。复核通过后仍须显式恢复，且只交付获批的精确提交。此流程不后移规格审批或 CRITICAL 提交前授权，详见[独立交付复核的架构边界](architecture.md)。


## 4. 诊断与故障恢复

先保留数据库、Git 仓库、工作树与管理记录，不手工修改 SQLite 行或受管 Git 引用。

```bash
daedalus status --workspace "$WORKSPACE"
daedalus verify --workspace "$WORKSPACE"
daedalus recover --config "$CONFIG"
```

`verify` 检查事件与持久状态一致性；`recover` 默认只报告。发现异常不等于可自动修复：

| 发现类别 | 处置原则 |
| --- | --- |
| 过期 / 不一致租约、执行投影、工作者状态 | 阅读报告，确认无活跃执行后，才考虑应用安全的记账修复。 |
| 未完成提交或交付 | 根据已持久化收据与 Git 事实对账；不能跳过门禁或假定提交失败。 |
| 中断运行、缺失工作树、孤立工作树 | 按报告处理，保留可审证据；不要删除工作树来“重置”任务。 |
| `sequence_gap`、`projection_drift` | 不自动补造事件；保留现场，评估可信快照及人工恢复。 |
| `repository_active` | 先协调正在运行的进程，不强行争用同一仓库。 |

只在理解报告、停止相关写入并留存备份后应用：

```bash
daedalus recover --config "$CONFIG" --apply
```

`--apply` 不代表所有发现都已解决，必须阅读每项结果；它不会自动续跑工程任务。处理完成后重新查看恢复断点，人工审查并显式继续。

### 回滚与重放

`rollback` 用于停止运行并记录原因，不删除历史，也不自动回退目标主分支。已经落地的代码需要通过新的、受审查的撤销变更处理。第三方 API 调用、外部数据库写入、发送消息等副作用不在其回滚保证内。

`replay` 建立新的执行，可按规格、基线、依赖、工具链及上游制品摘要复用已验证产物；不满足复用条件时重新执行。它不是继续原任务，可能产生新的模型费用和外部副作用。重放前核对基线和原因，不以重放规避原有审批或恢复阻断。

## 5. 备份、恢复与升级

### 数据库快照

```bash
daedalus backup --config "$CONFIG" --label before-maintenance
```

成功结果包含快照位置与验证信息。实现使用 SQLite backup API 取得一致副本，并检查数据库完整性和事件序列；不要用运行中的数据库主文件单独复制来代替快照。数据库备份**不是完整工程备份**：还应按权限策略保存目标 Git 仓库、必要工作树、非敏感配置及所需离线依赖。系统钥匙串或外部凭证管理器中的密钥需采用独立恢复方案。

定期将可信快照与必要工程数据保存在不同故障域，并在隔离工作区演练恢复。备份、审计导出和日志可能包含代码、任务内容及路径，应按敏感工程资料控制权限；脱敏不等于可公开上传。

### 恢复数据库

先停止所有使用目标工作区的后端和 CLI 写入，保留当前现场。将 `SNAPSHOT` 设置为选定快照目录或数据库文件路径：

```bash
daedalus restore --config "$CONFIG" --from "$SNAPSHOT"
```

目标数据库已存在时默认拒绝覆盖。确认替换必要后才添加 `--force`；实现会将旧数据库及 WAL / SHM 文件移至带时间戳的旁路名称，而不是删除。快照不会自动恢复 Git 提交、工作树、模型密钥或外部系统。

恢复后检查状态与仓库对应关系，再启动服务并人工审查未完成任务。自动生成的服务断点副本同样只是恢复材料，不会在启动时自动覆盖数据库。

### 源码升级

1. 用当前版本创建快照，记录对应源码版本，并保留必要的 Git 与工作树数据。
2. 正常停止服务，等待当前步骤批次与断点保存结束。
3. 切换到选定发布源码，在该虚拟环境重新执行 `python -m pip install -e .`。
4. 检查配置、数据库兼容性及恢复报告。旧数据库可能在打开时迁移，因此不要直接以旧程序重开迁移后的库；需要降级时使用对应版本的可信快照。
5. 以相同配置和工作目录启动。核对提醒与未完成任务，人工审查后再继续。

发布检查流程见[发布指南](publishing.md)。不要将“服务能启动”写成测试通过、模型可用或可以正式交付的结论。

## 6. 日常观测与排障

```bash
daedalus metrics --workspace "$WORKSPACE"
daedalus alerts --config "$CONFIG"
daedalus timeline --workspace "$WORKSPACE" --run-id "$RUN_ID"
daedalus audit --workspace "$WORKSPACE" --run-id "$RUN_ID"
daedalus step-log --workspace "$WORKSPACE" --run-id "$RUN_ID" --step "$STEP_ID"
daedalus export-audit --workspace "$WORKSPACE" --run-id "$RUN_ID" --format jsonl
```

`RUN_ID`、`STEP_ID` 来自实际任务回执或界面。告警基于已有持久证据，不自动处理异常；审计分数衡量证据覆盖情况，不证明变更正确或可以上线。

| 现象 | 优先检查 |
| --- | --- |
| 服务无法启动 / 端口占用 | 配置、访问保护前置条件、同端口实例及工作区 `.service/service.log`；不要随意换端口掩盖重复实例。 |
| 模型不可用 | 当前生效角色、协议、端点、模型名与凭证来源；通过 UI 测试，不打印环境或密钥排查。 |
| `428 spec_approval_required` | 冻结规格摘要、审批权限与签名。 |
| `AWAITING_APPROVAL` | 升级原因、当前制品、断点审查与是否存在未完成提交。 |
| 仓库、分支或工作树不见了 | 停止写入并保留证据；数据库备份本身不能补回缺失的 Git 数据。 |
| 主分支发生分歧 / 集成冲突 | 核对并发修改，人工决定后续变更；不要强制推进受管引用。 |

任何恢复动作都应先回答：当前权威事件是什么、对应哪个 Git 事实、批准是否仍绑定当前制品、是否存在不可撤销的外部副作用。无法证明安全的任务应继续保持停止。
