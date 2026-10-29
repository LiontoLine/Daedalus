# 网页模型设置与导入

本文说明当前源码提供的模型接入功能。凭证的保存机制及威胁边界见 [凭证保存说明](model-credential-storage.md)，部署前提见 [安全策略](../SECURITY.md)。

## 直接开始

1. 在任何页面点右上角「模型设置」，也可从新建任务区域进入。
2. 选择服务商，填写账户可用的模型 ID 和 API Key；本地服务可不填密钥。也可点击「获取模型列表」，不提供列表的接口可手填。
3. 选择「全部角色」，或分别给规划、编码、审查分配连接。通常先让三个角色共用一个已验证可用的模型即可。
4. 点「测试连接」，查看实际返回、模型名称与延迟，再点「应用模型」。远程连接沿用已有的仓库内容发送确认。
5. 关闭设置，按「提交任务 → 规划 → 执行 → 审计」继续使用。顶部与任务入口会显示当前模型及尚未配置的角色。

要沿用现有配置，点「导入配置文件」或「粘贴配置」，检查预览中的角色、协议、地址、模型及密钥状态，再应用。导入按批次校验，一项出错则整批不生效。下载模板后，把占位模型名改成服务商控制台提供的模型 ID。

## 覆盖范围

| 接口协议 | 用途 | 实际请求 |
| --- | --- | --- |
| `openai_chat` | OpenAI 兼容云服务与本地推理服务 | `POST /chat/completions` |
| `openai_responses` | OpenAI Responses 及相同协议的网关 | `POST /responses` |
| `anthropic` | Claude 原生 Messages | `POST /messages` |
| `gemini` | Gemini API 原生文本生成 | `POST /models/{model}:generateContent` |

原生协议分别处理 system 指令、鉴权、文本提取与 Token 用量，统一进入现有规划、工作与审查流程。没有把 Claude 或 Gemini 请求直接套用 OpenAI 消息格式。适配依据为 [OpenAI 文本生成文档](https://developers.openai.com/api/docs/guides/text)、[Anthropic Messages 文档](https://platform.claude.com/docs/en/build-with-claude/working-with-messages) 和 [Gemini generateContent 文档](https://ai.google.dev/api/generate-content)。

| 分类 | 内置预设 |
| --- | --- |
| 国内 | DeepSeek、阿里云百炼 / 通义千问、Moonshot / Kimi、智谱 / GLM、MiniMax、火山方舟 / 豆包、腾讯混元、百度千帆 / 文心 |
| 国际 | OpenAI、Anthropic / Claude、Google / Gemini、Groq、Mistral、xAI / Grok、Azure OpenAI |
| 聚合 | 硅基流动、OpenRouter |
| 本地 | Ollama、LM Studio |
| 自定义 | vLLM 或其他兼容上述四种协议的网关 |

这 20 项是连接预设；模型 ID 不写死。新模型只要使用已支持的文本协议，可直接填写 ID，不必等待更新前端。预设表在 [model-providers.json](../src/daedalus/service/static/model-providers.json)，每项附有对应官方文档地址。

区域、工作空间、编程套餐可能使用专用端点，需要按账户实际情况修改 API 根地址。例如百炼按地域与工作空间区分地址，见 [百炼官方地址说明](https://help.aliyun.com/en/model-studio/base-url)；腾讯新服务也可能通过 TokenHub 提供，见 [混元官方兼容接口说明](https://cloud.tencent.com/document/product/1729/111007)。Azure 预设需补资源地址和部署名。

当前范围是供工程任务使用的文本生成接口。云厂商的专有签名鉴权、Bedrock / Vertex IAM、网页登录订阅与多模态专用接口尚无直接适配；可通过提供上述协议的网关接入。预设与离线协议检查不等于对所有厂商、套餐和模型进行了付费实测。

## 导入示例

### JSON：三个角色使用不同模型

```json
{
  "version": 1,
  "roles": {
    "planner": {
      "provider": "openai",
      "model": "填写账户可用的规划模型ID",
      "api_key_env": "OPENAI_API_KEY"
    },
    "coder": {
      "provider": "anthropic",
      "model": "填写账户可用的Claude模型ID",
      "api_key_env": "ANTHROPIC_API_KEY"
    },
    "reviewer": {
      "provider": "gemini",
      "model": "填写账户可用的Gemini模型ID",
      "api_key_env": "GEMINI_API_KEY"
    }
  }
}
```

指定 `provider` 后，省略的地址与协议由预设补齐。扁平对象如 `{"provider":"deepseek","model":"你的模型ID","api_key_env":"DEEPSEEK_API_KEY"}` 应用到全部角色。也可用 `base_url`、`api_format` 明确指定接口。

### TOML：持久服务配置或模型连接片段

```toml
[model]
default_role = "coder"

[model.planner]
provider = "openai"
api_format = "openai_responses"
base_url = "https://api.openai.com/v1"
model = "填写规划模型ID"
api_key_env = "OPENAI_API_KEY"

[model.coder]
provider = "anthropic"
api_format = "anthropic"
base_url = "https://api.anthropic.com/v1"
model = "填写Claude模型ID"
api_key_env = "ANTHROPIC_API_KEY"

[model.reviewer]
provider = "gemini"
api_format = "gemini"
base_url = "https://generativelanguage.googleapis.com/v1beta"
model = "填写Gemini模型ID"
api_key_env = "GEMINI_API_KEY"
```

网页导入该文件时只提取模型连接。作为启动配置时，将这些段合并到原有 `daedalus.toml`，保留原有 workspace、service 等设置，令服务启动环境提供对应密钥。配置文件加载器保留旧版 `openai_chat` 默认值，因此手写持久原生连接时应明确填写 `api_format`。

### .env：只引用环境变量

```dotenv
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=填写模型ID
OPENAI_API_KEY=${MY_MODEL_KEY}
OPENAI_API_FORMAT=openai_chat
```

由受信任的服务启动环境提供 `MY_MODEL_KEY`，不要把真实值写入示例、命令行或 shell 历史。若已有含密钥的配置文件，应视为秘密材料，不应提交或上传；优先使用变量引用。

识别 `ANTHROPIC_*`、`GEMINI_*` / `GOOGLE_*`、`DEEPSEEK_*`、`OPENAI_*` 字段；一个 `.env` 选取首个可识别服务商，多角色连接使用 JSON / TOML 更明确。`${MY_MODEL_KEY}` 被当作服务进程的环境变量名，不在解析时展开；`.env` 只解析键值，绝不执行 shell 命令。没有模型 ID 时会提示补齐。

还可识别 Claude API 配置的 `env` 对象，以及 Codex API 配置中的 `model_provider`、`model_providers`、`wire_api`、`env_key`。仅提取明确的 API 连接，不导入登录会话、插件、命令或权限配置。

## 保存与密钥

网页默认勾选「安全保存连接，重启后自动恢复」。点击应用或导入后，密钥与连接绑定记录保存到 macOS 系统钥匙串，非敏感连接参数保存到工作区；服务重启后恢复各角色的地址、模型、协议和参数。取消勾选则只应用临时连接，下次启动恢复已保存的连接或启动配置。页面显示每个角色的实际来源。

调整连接影响之后创建的模型客户端，已创建的客户端保留原连接与凭证直到其生命周期结束。启动恢复模型连接不会自动执行中断任务，任务仍须人工审查并明确继续。

「导出配置」导出当前每个角色的地址、协议、模型、超时、兼容参数与密钥环境变量名，**不导出密钥值**。重新导入到其他服务后，需提供对应环境变量或重新填入密钥。无密钥本地连接往返导出、导入后仍可直接使用。

保存和导出流程不把密钥值写入普通配置或导出文件，错误信息和返回文本经过脱敏；这不意味着任意秘密都能被完整识别。不要将敏感代码、日志或数据库默认视为可公开材料。编辑同一地址、同一协议的连接时，可留空保留已有密钥；更换地址不会把旧密钥自动带给新主机。已保存参数与钥匙串凭证不匹配时，拒绝创建模型客户端。原生厂商连接明确指定的环境变量缺失时，不会借用另一厂商的密钥。

首次安全保存后不再需要每次重填；旧版进程关闭后已经丢失的内存密钥，需要首次重新输入。钥匙串锁定、授权取消或写入失败时，保存操作报错并保留原配置，不降级成明文文件。TOML 与环境变量方式仍可使用；仅保存环境变量名时，重启后的环境仍需提供其值。「清除已保存连接」会删除对应钥匙串条目与连接配置。

## 模型兼容参数

大多数连接无需展开「协议与兼容选项」。有特殊要求时可填：

```json
{
  "send_temperature": false,
  "send_json_mode": false,
  "token_limit_field": "max_completion_tokens"
}
```

`token_limit_field` 用于 Chat Completions；Responses、Claude、Gemini 使用各自的原生输出上限字段。`auth_mode` 可选择 `bearer`、`api-key`、`x-api-key`、`google-api-key`。Azure 网页预设默认使用 `api-key`；手写 Azure 持久配置时请显式设置 `request_options = {auth_mode = "api-key"}`，见 [Azure v1 官方鉴权示例](https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle)。

`extra_body` 只允许生成或思考参数，例如 `reasoning`、`reasoning_effort`、`thinking`、`enable_thinking`、`chat_template_kwargs`、`top_p`、`top_k`。它不能替换消息、密钥或工具权限。具体参数必须由所选模型支持。

Gemini 原生协议仅接受 `top_p`、`top_k` 和 `thinking_config`；例如 `{"extra_body":{"thinking_config":{"thinkingBudget":0}}}` 会映射到原生 `generationConfig.thinkingConfig`。能否关闭思考取决于模型，见 [Gemini 配置参考](https://ai.google.dev/api/generate-content#ThinkingConfig)。不支持的参数会明确拒绝，避免界面保存了却未生效。

思考块不作为候选代码或审查回答暴露。Token 统计包含接口报告的思考用量，Claude 输入统计包含报告的缓存读取和创建用量。未请求的工具调用、空文本、畸形响应及未完成 Responses 会按失败处理。

## 接口与排障

| 路径 | 用途 |
| --- | --- |
| `GET /api/model` | 查看实际生效的角色、来源与协议 |
| `POST /api/model` | 设置一个角色或全部角色；`persist:true` 安全保存，省略时仅临时应用 |
| `DELETE /api/model` | 清除已保存和临时覆盖并恢复启动配置；`?role=coder` 仅清除该角色 |
| `GET /api/model/catalog` | 预设目录与四种协议 |
| `GET /api/model/template` | 下载三角色模板 |
| `GET /api/model/export` | 导出不含密钥的配置 |
| `POST /api/model/import/preview` | 解析并预览，不应用 |
| `POST /api/model/import` | 完整校验后批量应用；`persist:true` 安全保存 |
| `POST /api/model/models` | 读取账户模型列表，可不先填模型 ID |
| `POST /api/model/test` | 以选中协议实际发送一次简短文本请求 |

列表接口不可用时可以手填模型 ID。401 / 403 检查密钥与账户权限；404 检查区域、专用套餐地址、模型或部署名；400 检查协议和兼容参数。测试只发送简短测试词，不读取仓库；测试成功也不能代替真实工程任务验收。

### HTTPS 证书报错

`https://api.deepseek.com` 是 DeepSeek 的有效 API 根地址，且提供 `GET /models`，见 [官方接入说明](https://api-docs.deepseek.com/) 和 [模型列表接口](https://api-docs.deepseek.com/api/list-models/)。`CERTIFICATE_VERIFY_FAILED` 发生在 HTTPS 握手时，不能据此判断服务商不提供模型列表。

模型请求始终校验服务器证书和主机名。若 Python 没有默认可信 CA，自动使用 certifi 的 Mozilla CA 数据包；它是证书数据依赖，HTTP / TLS 仍使用标准库，没有引入模型 SDK。用户明确配置的 `SSL_CERT_FILE` / `SSL_CERT_DIR` 会保持其选择；无效文件明确报错，不忽略配置或关闭验证。

macOS 的 python.org Python 安装若缺少默认 CA，可参考该发行版提供的证书安装说明。修复信任库后重试「测试连接」；不要关闭证书或主机名校验。仅存内存的连接在进程关闭后会丢失，重启前应确认配置恢复方式。

企业网络或 HTTPS 代理使用自己的根证书时，可通过 `DAEDALUS_CA_BUNDLE` 指定可信 PEM 文件，作为额外信任来源。先正常停止现有服务，再由受信任的启动环境提供该变量并重新开启。已有管理进程的环境不会随着另一个终端的环境变化而更新。不要使用未知来源的 CA，也无需把 API Key 发给他人。

相关默认校验行为见 [Python 3.12 SSL 文档](https://docs.python.org/3.12/library/ssl.html#ssl.create_default_context)，证书包来源见 [certifi 官方说明](https://github.com/certifi/python-certifi)。

若界面提示「后端尚未加载新版模型模块」，说明浏览器已读到新静态文件，而 Python 服务仍是旧进程。需要用原有配置重启服务后才会加载新导入 API 和原生协议；仅刷新网页不能替代后端重启。
