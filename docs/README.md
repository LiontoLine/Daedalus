# 文档索引

本目录说明 Daedalus 的使用方式、技术边界和维护约定。首次使用请从 [项目首页](../README.md) 开始；准备分享源码时请阅读 [公开发布指南](publishing.md)。文档描述实现行为，不构成安全认证或模型效果保证；发生差异时应核对当前源码和测试。

## 安装与日常使用

| 文档 | 内容 |
| --- | --- |
| [运维手册](runbook.md) | 环境、部署、隔离探测、审批、备份与恢复 |
| [终端与服务控制](service-control.md) | 交互控制台、托管启停、中断提醒与人工续跑 |
| [任务工作区](ui-workspace.md) | 本地网页中的提任务、规划、执行和审计 |
| [模型设置](model-settings.md) | 文本协议、角色分配、导入导出与连接排障 |
| [凭证保存](model-credential-storage.md) | macOS 钥匙串、临时连接、环境变量及威胁边界 |
| [依赖完整性](dependency-integrity.md) | 操作员缓存、哈希锁及离线校验的能力边界 |

## 架构与维护

| 文档 | 内容 |
| --- | --- |
| [架构](architecture.md) | 领域状态机、事件日志、调度、模型面与执行面 |
| [设计差异](design-decisions.md) | 实现与规格的对应关系和已知限制 |
| [项目记忆与 Agentic RAG](agentic-rag.md) | 只读上下文、项目偏好、引用及信任边界 |
| [按需检索策略](retrieval-strategy.md) | 直接搜索、词法/向量召回、混合排序与有界调查 |
| [路线图](roadmap.md) | 当前实现范围及尚未闭合的工程缺口 |
| [AgentPanelX 来源记录](agentpanelx-reuse.md) | 设计继承、选择性移植与明确差异 |

贡献和漏洞报告分别见 [CONTRIBUTING.md](../CONTRIBUTING.md) 与 [SECURITY.md](../SECURITY.md)。源码与测试入口见 [项目导航](../PROJECT_INDEX.md)。
