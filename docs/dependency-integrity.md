# 离线依赖完整性校验

本功能校验冻结声明、锁文件及操作员提供的缓存字节，不下载、安装或执行 wheel 中的代码。它是受限的离线完整性门禁，不是依赖供应链认证。

## 操作

1. 操作员在任务外取得并审核依赖 wheel。当前仅接受与校验解释器兼容、Wheel-Version 1.0 的纯 Python 通用 wheel。
2. 导入工作区的内容寻址缓存：

   ```bash
   daedalus dependencies cache-add --workspace /path/to/workspace --wheel /path/to/example-1.0-py3-none-any.whl
   ```

3. 用输出的 SHA-256 创建锁文件；所有直接及传递依赖均须精确固定版本并有哈希。例如：

   ```text
   example==1.0 --hash=sha256:<64位实际文件摘要>
   ```

4. 冻结 SPEC-03 时同时声明不同的 `dependency_manifest` 和 `lock_file` 路径。可先检查：

   ```bash
   daedalus dependencies verify --workspace /path/to/workspace --manifest requirements.txt --lock requirements.lock
   ```

缓存位于事件数据库同级的 `dependency-cache/<sha256>/<filename>.whl`。执行器不能通过 HTTP 导入缓存。导入只读文件不是操作系统权限隔离；操作员及宿主文件系统仍属于信任边界。

## 强制行为

- 识别 requirements、pyproject、setup、Pipfile、Poetry、uv、npm、pnpm、yarn 等常见依赖文件的变更；未在冻结规范声明的依赖文件不能变更。
- 当前支持 requirements 清单和 PEP 621 pyproject 清单，锁格式为带 SHA-256 的精确 Python requirement。动态依赖、递归 include、索引参数、URL/VCS、本地路径、条件锁条目及尚未支持的格式均拒绝。锁应为单一环境物化后的结果。
- 校验外部文件哈希、文件名与 METADATA/dist-info 身份、Python 版本与 wheel 标签、全部 RECORD 校验和，以及直接/传递依赖的版本、marker 和 extras。
- 阻止重复规范化包名、目录穿越、软链接、重复 ZIP 路径、过大输入及不完整元数据。
- Tier-1 失败时不运行 linter、类型检查、验收命令，也不调用 Tier-2。worker 可在原有最多三次 attempt 内修复；没有可信缓存时不能通过。
- 已声明的依赖即使本次未修改，也在步骤门禁、目标验收、独立复验及缓存复用入口重新校验。缓存结果绑定工具链版本，不直接沿用旧版本门禁结果。
- 结果包含校验摘要、包及哈希、校验环境和明确的证据范围。缓存损坏时拒绝，不自动联网修复。

## 证据边界

哈希只能证明文件与操作员提供的字节一致。尚未证明发布者身份、无漏洞、实际沙箱安装环境与锁一致，也不覆盖未声明且未修改的历史依赖。marker 按控制器的校验环境求值；跨环境部署仍需独立的环境绑定。

没有实现 npm 等生态或编译 wheel 的校验器，遇到其变更会停车。运行时域名 allowlist、容器真机隔离和任务总资源约束仍保留原缺口。生产门禁新增必需项 `dependency_runtime_evidence`，当前明确 SKIP，因此仍为 NO-GO。

运行依赖 `packaging>=24.2,<27` 用于标准 requirement、marker、wheel 标签和版本解析；没有为此引入模型 SDK。项目自身的运行依赖仍需部署侧锁定和验收，不能把校验器自身依赖称为已完成供应链认证。

实现依据：[pip 安全安装说明](https://pip.pypa.io/en/stable/topics/secure-installs/)、[wheel 规范](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)、[packaging Requirement](https://packaging.pypa.io/en/stable/requirements.html)。本实现只支持上述规范的受限子集，不能替代安装器。
