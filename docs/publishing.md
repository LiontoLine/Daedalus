# GitHub 发布指南

首次公开采用**审核后的文件白名单 + 不带旧 Git 历史的新仓库**。不要直接上传整个开发目录，也不要把已有 `.git/` 复制到公开目录。原始研究材料可以继续在本地保留。

## 上传范围

| 文件或目录 | 公开范围 | 原因 |
| --- | --- | --- |
| `src/daedalus/` | 源码、模板、静态资源和第三方许可；排除缓存 | 安装与运行所需 |
| `tests/` | 测试源码和合成夹具；排除缓存 | 行为与安全边界的可复现验证 |
| `examples/demo_project/` | 示例源码与配置 | 无凭证入门示例 |
| `scripts/` | 顶层安装、演示和验证脚本，不含 `maintenance/` | 日常使用与 CI 所需 |
| `.github/workflows/ci.yml`、`.github/sandbox.Dockerfile` | CI 配置与任务测试镜像定义 | 离线回归、服务检查和构建 |
| `docs/` | 仅 `.gitignore` 明确放行的技术 Markdown | 安装、操作、安全与架构说明 |
| 根目录 | `README.md`、`CHANGELOG.md`、`PROJECT_INDEX.md`、`CONTRIBUTING.md`、`SECURITY.md`、`AGENTS.md`、`LICENSE`、`pyproject.toml`、`.gitignore`、`Daedalus_System_Implementation_Spec_v2.1.md` | 导航、更新记录、开发约定、许可和实现契约 |

以下内容不纳入默认公开包：

- `paper/`、`archive/`、`external_data/`：论文产物、历史归档、上游源码与数据副本。
- `docs/` 中未放行的文件和子目录：运行证据、报告、截图、个人材料等。
- `scripts/maintenance/`：依赖本地研究资料的维护脚本。
- `.git/`：旧提交、作者与提交者邮箱、远程地址、reflog 和已删除文件。
- `.env`、`.env.*`、`daedalus.toml`、`*.local.toml`、`*.local.json`、私钥和证书容器。
- SQLite 数据库及 WAL/SHM、模型设置、服务状态、运行目录、工作树、日志与备份。
- 虚拟环境、构建产物、依赖元数据、测试缓存、系统元数据。

**源码里的研究辅助模块不等于附带研究数据。** 依赖本地上游数据集或运行目录的辅助入口，不是默认安装体验的一部分；公开包不提供这些私有资料。普通演示、任务工作区、模型配置与门禁不应依赖它们。

## 推送前的隐私检查

1. 检查实际上传目录及压缩包内容，不要只看 `.gitignore`。忽略规则不会删除已跟踪的文件，也不会清除历史。
2. 搜索凭证、私钥、连接串、内部服务地址、真实用户目录、邮箱、截图和文档元数据。扫描器的零告警不是无泄露的证明。
3. 测试包含有意构造的假密钥与攻击输入。逐项判断；不要为了消除告警删掉安全测试，也不要整目录豁免扫描。
4. 如发现真实凭证曾提交或外传，先在服务商处吊销并轮换。仅删除文件或改写历史不能让旧密钥重新安全。
5. 保留 `LICENSE`、来源说明和第三方资源许可，不要把来源作者的版权信息当作本机隐私一并删除。
6. 在干净副本安装并运行演示及离线测试，确保没有误删必要文件。

可以使用 [Gitleaks](https://github.com/gitleaks/gitleaks) 等独立工具补充扫描；安装后按所用版本的说明分别扫描目录与准备发布的 Git 历史。不要上传包含原始匹配值的扫描报告。

## 创建新 GitHub 仓库

只在**已经审核、没有 `.git/` 的公开副本目录**内执行以下命令。先在 GitHub 创建空仓库，不预置 README 或许可证。

```bash
git init -b main
```

在第一次提交前配置仓库级公开身份：

- `git config --local user.name`：设置你愿意公开的昵称。
- `git config --local user.email`：设置 GitHub「Settings → Emails」里显示的 noreply 邮箱。不要照抄别人的邮箱。
- 检查 Git 的签名配置，避免签名证书包含你不打算公开的身份。

确认身份后：

```bash
git add .
git diff --cached --stat
git diff --cached
# 确认暂存区没有密钥、本机路径或私有材料后再提交。
git commit -m "Initial public release"
```

然后在 GitHub 页面复制新仓库的 HTTPS 或 SSH 地址，用 `git remote add origin` 添加它，再执行：

```bash
git push -u origin main
```

不要把访问令牌写进 remote URL，不要把终端凭证输出或 Git 配置截图提交到仓库。若使用 GitHub 网页上传，仍需检查上传目录；网页上传并不自动应用本地 `.gitignore`。

## GitHub 设置

- 根据 README 填写 About 描述和主题，不添加没有证据的能力或性能主张。
- 开启 Secret scanning、Push protection（以账号和仓库可用功能为准）。
- 如需接收敏感漏洞报告，启用 Private vulnerability reporting，见 [SECURITY.md](../SECURITY.md)。
- 首次推送后检查 Actions。不要为离线 CI 配置真实模型 API key。
- 发布 Release 前重新检查源码压缩包和 wheel；开发测试产物不等于公开制品。

## CI 检查与失败定位

CI 在 Ubuntu 24.04 和 macOS 上检查 Python 3.12；Linux 使用固定镜像标签，避免 `ubuntu-latest` 的系统迁移混入代码诊断。Job 名包含操作系统，便于区分平台失败。

动作使用支持 Node.js 24 的 `actions/checkout@v5`、`actions/setup-python@v6` 和 `actions/upload-artifact@v7`。动作运行时与项目使用的 Python 是两回事；Node 弃用、镜像迁移和排队通知不能代替失败步骤的错误日志。

Linux 行为测试和发布诊断会先构建含测试依赖的任务镜像，再通过 `DAEDALUS_SANDBOX_IMAGE` 指定它；不能把宿主的 `pip install` 当作容器内依赖已安装。保持真实容器检查，不因运行时可用而跳过测试或降级隔离。配置方式见[容器任务环境](runbook.md#容器任务环境)。

发布诊断先通过 `status` 初始化空工作区，再创建并验证备份。诊断步骤临时生成两份不同的合成签名秘密，注册 owner/reviewer，并在日志中掩码；它们只用于 CI 初始化，不使用真实模型密钥或生产审批秘密，也不构成生产批准。

本地检查实际服务路径：

```bash
python scripts/live_check.py
```

该脚本使用临时仓库、本机假模型网关及真实 HTTP 服务，覆盖任务执行、摘要绑定的步骤审查、逐项目标验收和规划确认。冻结请求必须携带刚查看的 `spec_digest`；不应通过关闭审查或省略确认来让检查通过。安装 Node.js 后才会执行前端渲染检查；没有 Node.js 时会明确报告跳过。

Actions 显示失败时，打开失败 Job 内的红色步骤，保留失败命令、断言或 traceback，分享前去掉凭证和个人信息。仅有 `Process completed with exit code 1` 不足以判断根因。

GitHub 下载的源码 ZIP 不包含 `.git/` 和 Actions 日志。修复这种副本后，应将改动提交到原仓库：使用已有 clone，或在 GitHub 网页按原路径替换文件。不要在下载副本里另建无关历史后强制推送。

动作运行时依据：[checkout v5](https://github.com/actions/checkout/blob/v5/action.yml)、[setup-python v6](https://github.com/actions/setup-python/blob/v6/action.yml)、[upload-artifact v7](https://github.com/actions/upload-artifact/blob/v7/action.yml)。


## 文档编排参考

首页采用「定位 → 能力与边界 → 快速开始 → 架构 → 文档 → 贡献与许可」结构，参考开源项目的导航方式，不复制其能力或宣传内容：

- [GitHub：仓库最佳实践](https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories)
- [OpenHands README](https://github.com/OpenHands/OpenHands#readme)
