# Daedalus 项目导航

## 从这里开始

| 目标 | 入口 |
| --- | --- |
| 理解用途、安装并运行离线演示 | [README.md](README.md) |
| 查找使用和架构文档 | [docs/README.md](docs/README.md) |
| 配置本地模型连接 | [模型设置](docs/model-settings.md)与[凭证保存](docs/model-credential-storage.md) |
| 启停服务、处理断点 | [服务控制](docs/service-control.md)与[运维手册](docs/runbook.md) |
| 阅读任务规格的设计背景 | [系统实施规格](Daedalus_System_Implementation_Spec_v2.1.md)；实现限制见[设计差异](docs/design-decisions.md) |
| 修改代码与编写测试 | [CONTRIBUTING.md](CONTRIBUTING.md)；代理约定见 [AGENTS.md](AGENTS.md) |
| 理解安全前提与报告漏洞 | [SECURITY.md](SECURITY.md) |
| 准备公开源码副本 | [发布指南](docs/publishing.md) |
| 查许可与设计来源 | [LICENSE](LICENSE)与[来源记录](docs/agentpanelx-reuse.md) |

## 源码分层

| 路径 | 职责 |
| --- | --- |
| `src/daedalus/domain/` | 纯领域契约、FSM、规格、事件、摘要与制品；不承担 I/O |
| `src/daedalus/application/` | 规划、调度、Worker、门禁、审批、恢复与检索用例 |
| `src/daedalus/infrastructure/` | SQLite、Git worktree、进程隔离、脱敏与知识存储 |
| `src/daedalus/security/` | 写入边界与凭证能力约束 |
| `src/daedalus/model/` | 不可信模型面的传输协议与客户端 |
| `src/daedalus/service/` | 本地 HTTP API、页面模板和静态资源 |
| `src/daedalus/cli.py` | 命令行入口；`python -m daedalus` 使用同一入口 |
| `src/daedalus/demo.py` | 无真实模型的控制流程演示 |
| `tests/` | 行为、边界、门禁、恢复及服务回归测试 |
| `examples/demo_project/` | 演示输入项目；包含用于演示修复的缺陷 |
| `pyproject.toml` | Python 环境、依赖、构建和开发工具配置 |

公开源码不应包含个人工作区、模型凭证、运行数据库、日志、执行 worktree 或备份。文档中的相对路径用于说明项目结构，不表示这些运行资料应上传；发布前请按发布指南审查导出副本。
