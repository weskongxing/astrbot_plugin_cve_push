# CVE漏洞推送（astrbot_plugin_cve_push）

面向 AstrBot 4.x 的多信源 CVE 漏洞情报定时推送插件。

定时抓取 **奇安信威胁情报中心**、**阿里云安全漏洞库（AVD）**、**CNNVD 国家信息安全漏洞库** 三个公开信源的最新漏洞情报，
跨信源去重后推送到指定群聊，可选调用 AstrBot 已配置的对话模型生成中文摘要，
并同时注册 AstrBot 标准指令组 `/cve`（含 6 条子指令）与 2 项 LLM 工具，让机器人能"被问到就答"。

![version](https://img.shields.io/badge/version-v1.0.1-blue)
![astrbot](https://img.shields.io/badge/AstrBot-%3E%3D4.11.2-green)
![python](https://img.shields.io/badge/Python-3.10%2B-yellow)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 目录

- [主要功能](#主要功能)
- [信源说明](#信源说明)
- [安装方法](#安装方法)
- [配置说明](#配置说明)
- [使用方法](#使用方法)
- [Cron 表达式语法](#cron-表达式语法)
- [数据文件与目录结构](#数据文件与目录结构)
- [合规抓取说明](#合规抓取说明)
- [开发与测试](#开发与测试)
- [常见问题](#常见问题)
- [更新日志](#更新日志)
- [许可协议](#许可协议)

---

## 主要功能

| 功能 | 说明 |
| --- | --- |
| 多信源聚合 | 一次任务抓取奇安信 / 阿里云安全 / CNNVD 三个信源，按披露时间倒序合并 |
| 跨信源去重 | 同一漏洞被多个信源收录时只保留一条，去重键优先级：CVE 编号 > 源内编号 > 标题指纹 |
| 增量推送 | 去重记录落盘持久化，只推送未推送过的新条目，重启不丢状态 |
| AI 摘要（可选） | 调用 AstrBot 已配置的对话模型生成"等级 + 受影响产品 + 漏洞描述 + 处置建议"结构化摘要；失败或超时自动降级为原始列表 |
| 定时任务 | 内置 5 段 cron 解析器，支持 `*`、`a-b`、`*/n`、`a-b/n`、`a,b,c`，无需额外依赖 |
| 群聊推送 | 支持纯 session_id（`oc_xxx`、群号）或完整 UMO（`telegram:GroupMessage:xxx`）多目标推送 |
| 指令 | AstrBot 标准指令组 `/cve`：`push`、`targets`、`status`、`test`、`reset`、`help`，别名 `/漏洞` |
| LLM 工具 | 注册 `get_latest_cves`、`push_latest_cves`，支持自然语言查询与推送 |
| 故障隔离 | 单个信源抓取失败只记警告，不影响其余信源与整轮推送 |
| 全链路异常捕获 | 后台协程、指令、LLM 工具、定时循环全部兜底捕获，单个异常不会导致宿主崩溃 |
| 纯文本输出 | 全插件零 emoji，状态一律 `[完成]` / `[失败]` / `[警告]` / `[提示]` 标签 |

---

## 信源说明

| 信源 | 配置值 | 获取方式 | 字段 |
| --- | --- | --- | --- |
| 奇安信威胁情报中心 | `qianxin` | 公开 POST JSON 接口（当日漏洞列表） | QVD 编号、CVE 编号、漏洞名称、危害等级、披露时间 |
| 阿里云安全漏洞库 | `aliyun` | 首页服务端渲染 HTML 表格解析 | AVD 编号、CVE 编号、漏洞名称、漏洞类型、披露时间 |
| CNNVD 国家信息安全漏洞库 | `cnnvd` | 站点公开"游客签名"通道（先取签名再请求热点漏洞列表） | CNNVD 编号、CVE 编号、漏洞名称、危害等级、披露时间 |

三个信源均为**公开可读数据**，插件只做只读抓取，不含任何登录凭据、Cookie、绕过或爆破逻辑。

---

## 安装方法

### 方式一：手动放入插件目录（推荐）

1. 下载本仓库（`git clone` 或下载 ZIP 后解压）。
2. 将整个 `astrbot_plugin_cve_push` 目录放到 AstrBot 的插件目录下：

   ```
   <AstrBot 根目录>/data/plugins/astrbot_plugin_cve_push/
   ```

   Docker 部署的 AstrBot，对应宿主机路径通常是：

   ```
   <宿主机挂载目录>/data/plugins/astrbot_plugin_cve_push/
   ```

   如果插件目录里已有 `astrbot_plugin_cve_push-master` 之类带后缀的文件夹，请重命名为 `astrbot_plugin_cve_push`。

3. 依赖检查：本插件只用到 `httpx` 与 `beautifulsoup4`，AstrBot 4.x 已内置，**无需额外安装**。
   如需手动确认：

   ```bash
   pip install httpx beautifulsoup4
   ```

4. 重启 AstrBot（WebUI 的"重启"按钮，或重启容器 / 进程）。

5. 启动日志中出现以下内容即为加载成功：

   ```
   Loading plugin astrbot_plugin_cve_push ...
   Plugin astrbot_plugin_cve_push (v1.0.0) by weskongxing: 定时抓取奇安信 / 阿里云安全 / CNNVD ...
   plugin(module_path data.plugins.astrbot_plugin_cve_push.main) added LLM tool: get_latest_cves
   plugin(module_path data.plugins.astrbot_plugin_cve_push.main) added LLM tool: push_latest_cves
   [漏洞推送] 已向宿主 AstrBot 暴露 2 项 LLM 工具
   [漏洞推送] 定时任务循环已启动，cron=0 9 * * *
   ```

### 方式二：WebUI 安装

进入 AstrBot WebUI -> 插件管理 -> 安装插件 -> 上传本仓库打包的 ZIP，或填写仓库地址 `https://github.com/weskongxing/astrbot_plugin_cve_push`。

### 方式三：容器内部署

```bash
# 进入容器
docker exec -it astrbot bash

# 放入插件
cd /AstrBot/data/plugins
git clone https://github.com/weskongxing/astrbot_plugin_cve_push.git

# 退出后重启容器
exit
docker restart astrbot
```

### 安装后必做的一步

安装完成后**必须配置推送目标**（`push_targets`），否则定时任务会因"未配置推送目标"而跳过。
获取 session_id 的方法：在目标群里发送一次 `/cve status`，从 AstrBot 日志里可以看到该会话的 `unified_msg_origin`，填入配置即可。

---

## 配置说明

在 AstrBot WebUI -> 插件管理 -> CVE漏洞推送 -> 配置 中修改，或直接编辑
`data/config/astrbot_plugin_cve_push_config.json`（修改后需重启生效）。

| 配置键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | 插件总开关。关闭后定时推送停止，但 `/cve` 指令与 LLM 工具仍可用 |
| `cron_expr` | string | `0 9 * * *` | 定时推送 cron 表达式，默认每天 09:00 |
| `enabled_sources` | list | `["qianxin","aliyun","cnnvd"]` | 启用信源，按列表顺序抓取 |
| `push_targets` | list | `[]` | 推送目标列表，支持纯 session_id 或完整 UMO |
| `ai_summary` | bool | `true` | 是否启用 AI 摘要，关闭则直接推送原始列表 |
| `selected_provider_id` | string | `""` | AI 摘要优先使用的模型提供商 ID；留空则跟随 AstrBot 当前默认对话模型。解析失败时按候选链回退：插件配置的 `selected_provider_id` -> AstrBot 当前对话模型 -> 任意可用对话模型；全部失败才降级为原始列表。配置热读取，无需重载插件 |
| `summary_timeout` | int | `90` | AI 摘要超时秒数，超时降级为原始列表 |
| `max_push_items` | int | `10` | 单次推送展示的漏洞条数上限 |
| `dedup_window_days` | int | `30` | 去重窗口天数，超期记录在写入时自动清理 |
| `request_timeout` | int | `20` | 单次 HTTP 请求超时秒数 |
| `max_requests_per_host` | int | `5` | 单次任务对同一域名的最大请求次数（合规限流） |
| `admin_user_ids` | list | `[]` | 允许执行 `/cve reset` 的用户 sender_id 列表（平台管理员默认也有权限） |
| `push_only_new` | bool | `true` | 仅推送未推送过的新条目；关闭后每次都推送全部抓到的条目 |

### 配置示例

每天 08:30 推送，只要奇安信和 CNNVD，推两个群，开 AI 摘要：

```json
{
  "enabled": true,
  "cron_expr": "30 8 * * *",
  "enabled_sources": ["qianxin", "cnnvd"],
  "push_targets": [
    "oc_15bdda9d4023d973931f9917eec641bc",
    "telegram:GroupMessage:-1001234567890"
  ],
  "ai_summary": true,
  "selected_provider_id": "",
  "max_push_items": 10,
  "dedup_window_days": 30,
  "push_only_new": true
}
```

`push_targets` 两种写法：

- 纯 session_id：`oc_xxx`（飞书）、`123456789`（QQ 群号）—— 插件按平台补全 UMO；
- 完整 UMO：`<平台适配器ID>:GroupMessage:<会话ID>`，最稳妥，推荐使用。

---

## 使用方法

### 一、指令

`/cve` 是 AstrBot 标准指令组，下面挂载 6 条子指令；每条子指令在 WebUI「指令」列表中都会独立显示，可单独启用、重命名与设置权限。

| 指令 | 别名 | 作用 |
| --- | --- | --- |
| `/cve push` | `/cve 推送`、`/漏洞 推送` | 抓取最新 CVE 漏洞并推送到**当前会话**，同时更新去重记录 |
| `/cve targets` | `/cve 目标` | 抓取并推送到配置的 `push_targets` 群聊目标 |
| `/cve status` | `/cve 状态` | 查看运行状态：启用状态、cron、下次执行时间、信源开关、AI 开关、AI 摘要模型、最近一次 AI 摘要、推送目标数、去重记录数与最近记录时间 |
| `/cve test` | `/cve 自检` | 自检 AI 摘要链路：真实调用一次模型，回报候选链与结果 |
| `/cve reset` | `/cve 重置` | 清空全部去重记录（仅管理员）；用于需要重新推送历史条目时 |
| `/cve help` | `/cve 帮助` | 查看指令帮助 |

单独发送 `/cve`（不带子指令）时，AstrBot 会直接回复该指令组下的完整指令树，这是指令组的标准行为。

`/cve status` 输出示例：

```
插件运行状态
启用状态: 已启用
定时表达式: 0 9 * * *
下次执行时间: 2026-10-22 09:00:00
信源开关: qianxin, aliyun, cnnvd
AI 摘要: 开启
AI 摘要模型: <provider_id 或 跟随默认>
最近一次 AI 摘要: <成功/失败摘要，含模型与耗时；无记录则为 - >
仅推送新条目: 是
推送目标数量: 1
去重记录总数: 29
去重窗口天数: 30
最近记录时间: 2026-10-21 21:20:23
```

### 二、自然语言（LLM 工具）

机器人在对话中可自动调用以下工具，无需写指令：

| 工具名 | 参数 | 说明 |
| --- | --- | --- |
| `get_latest_cves` | `limit`（默认 5）、`source`（默认 `all`） | 只返回漏洞文本，不推送，适合"最近有什么高危漏洞"这类提问 |
| `push_latest_cves` | `limit`（默认 5）、`source`（默认 `all`） | 抓取并推送到**当前会话**，适合"把今天的漏洞发到群里" |

`source` 取值：`all` / `qianxin` / `aliyun` / `cnnvd`。

### 三、定时推送

按 `cron_expr` 自动执行，无需人工干预：抓取 -> 去重 -> 摘要 -> 推送 `push_targets`。

推送消息结构（AI 摘要开启时）：

```
安全漏洞情报摘要

[极危] PHP Core（CVE-2026-109618、CVE-2026-109619） - 未认证攻击者可通过 ... | 处置建议 ...
[高危] WordPress EventON - Subscriber 插件（CVE-2026-93300） - ... | 处置建议 ...

涉及漏洞条目:
1. [极危] PHP Core 远程代码执行漏洞(CVE-2026-109618)（CVE-2026-109618）
2. [高危] EventON插件SQL注入漏洞(CVE-2026-93300)（CVE-2026-93300）
```

AI 摘要关闭或调用失败时，退化为纯列表：

```
安全漏洞情报（2026-10-21）

1. [极危] PHP Core 远程代码执行漏洞(CVE-2026-109618)
   编号: CVE-2026-109618 / QVD-2026-90012
   来源: 奇安信
   时间: 2026-10-21
```

---

## Cron 表达式语法

标准 5 段：`分 时 日 月 周`

```
┌───────── 分钟 (0-59)
│ ┌─────── 小时 (0-23)
│ │ ┌───── 日   (1-31)
│ │ │ ┌─── 月   (1-12)
│ │ │ │ ┌─ 星期 (0-7，0 和 7 均为周日)
│ │ │ │ │
* * * * *
```

支持写法：`*`、`a-b` 范围、`*/n` 步长、`a-b/n`、`a,b,c` 列表。
周字段同时支持数字（`1`）与英文缩写（`mon` / `wed`）。

| 示例 | 含义 |
| --- | --- |
| `0 9 * * *` | 每天 09:00 |
| `30 8 * * 1-5` | 工作日 08:30 |
| `*/30 * * * *` | 每 30 分钟 |
| `0 */6 * * *` | 每 6 小时整点 |
| `0 9,18 * * *` | 每天 09:00 与 18:00 |

表达式非法时插件不会崩溃：会记录一条警告并回退到默认 `0 9 * * *`。

---

## 数据文件与目录结构

```
astrbot_plugin_cve_push/
├── main.py                 插件入口：Star 子类、指令、LLM 工具、定时循环
├── metadata.yaml           插件元信息（名称、版本、作者、仓库）
├── _conf_schema.json       WebUI 配置表单定义
├── requirements.txt        依赖声明（AstrBot 已内置，无需安装）
├── README.md               本文档
├── INTERFACES.md           内部接口与模块契约说明（开发者参考）
├── core/
│   ├── models.py           CveItem 数据模型与去重键推导
│   ├── cron_util.py        5 段 cron 解析与下次执行时间推算
│   ├── dedup.py            去重存储（原子写盘 + 窗口清理）
│   ├── summarizer.py       AI 摘要（仅走 AstrBot 已配置模型，失败降级）
│   └── formatter.py        纯文本消息格式化（无 emoji）
├── sources/
│   ├── base.py             HttpFetcher：统一 UA、限速、退避重试、请求上限
│   ├── qianxin.py          奇安信信源
│   ├── aliyun.py           阿里云安全信源
│   └── cnnvd.py            CNNVD 信源
├── tests/                  离线单元测试（31 项，不联网）
└── data/
    └── pushed_records.json 去重记录（运行时自动创建，已加入 .gitignore）
```

去重记录文件格式：

```json
{
  "window_days": 30,
  "records": {
    "cve:CVE-2026-109618": {"title": "...", "source": "qianxin", "ts": "2026-10-21 21:20:23"},
    "cnnvd:CNNVD-2026-76468392": {"title": "...", "source": "cnnvd", "ts": "2026-10-21 21:20:23"}
  }
}
```

写入采用"临时文件 + 原子替换"，容器异常重启不会产生半截文件。

---

## 合规抓取说明

本插件刻意把抓取行为收敛到一处（`sources/base.py` 的 `HttpFetcher`），并强制以下底线：

- 只读公开接口，**不携带任何 Cookie、Token 或登录凭据**；
- 使用标准浏览器 User-Agent，不做伪装与反检测对抗；
- 同一域名两次请求强制间隔 **>= 1.2 秒**，禁止并发轰炸；
- 单次任务对同一域名请求数上限 **5 次**（可通过 `max_requests_per_host` 调整）；
- 失败采用指数退避，最多重试 **2 次**；
- 不使用登录绕过、验证码识别、参数爆破、目录扫描、注入探测等任何手段；
- CNNVD 使用的是站点为匿名访客提供的**公开游客签名通道**，不是登录绕过；需要登录的检索接口与数据包下载接口一律未使用。

请自行遵守目标站点的服务条款，合理设置抓取频率，不要用于商业转售或高频轮询。

---

## 开发与测试

### 运行单元测试（离线，不联网）

```bash
# 方式一
python astrbot_plugin_cve_push/tests/run_tests.py

# 方式二
cd astrbot_plugin_cve_push && python tests/run_tests.py

# 方式三
python -m unittest discover -s astrbot_plugin_cve_push/tests -p "test_*.py"
```

预期输出：

```
.......................................
----------------------------------------------------------------------
Ran 31 tests in 0.075s

OK
```

覆盖内容：cron 解析与下次执行时间、去重键推导与窗口清理、消息格式化、三个信源的 HTML/JSON 解析（fixtures 离线回放）、emoji 零命中扫描。

### 语法检查

```bash
python -m compileall astrbot_plugin_cve_push
```

### 扩展新信源

1. 在 `sources/` 下新建 `xxx.py`，继承 `sources/base.py` 的 `BaseSource`；
2. 实现 `name` 与 `async fetch_latest(limit) -> list[CveItem]`，网络请求一律通过 `self.fetcher`；
3. 在 `sources/__init__.py` 的 `build_sources` 中注册；
4. 在 `_conf_schema.json` 的 `enabled_sources` 提示里补充说明；
5. 补一个离线 fixture 与单测。

详见 `INTERFACES.md`。

---

## 常见问题

**Q：装好后定时没动静？**
A：按顺序排查：① `enabled` 是否为 `true`；② `push_targets` 是否为空；③ `cron_expr` 是否合法（看日志有没有"回退默认"的警告）；④ 容器时区是否正确（`docker exec astrbot date`），cron 按容器本地时间执行。

**Q：推送报"推送失败（未找到对应平台）"？**
A：`push_targets` 里的 UMO 前缀与已启用的适配器不匹配。改用完整 UMO 写法，例如 `telegram:GroupMessage:-1001234567890`、`aiocqhttp:GroupMessage:123456789`。

**Q：AI 摘要没生效？**
A：检查 ① `ai_summary` 已开启；② AstrBot 里已配置可用的对话模型；③ `selected_provider_id` 留空或指向存在的模型；④ 日志中是否有 `[摘要器] 失败` 记录。摘要失败会自动降级为原始列表，不影响推送。

**Q：AI 摘要不生效 / 日志出现 AI 摘要调用失败，已降级: Connection error.？**
A：按顺序排查：① 发送 `/cve test` 查看候选链与自检结果；② 确认 `selected_provider_id` 是否选中了可用模型（留空则跟随 AstrBot 默认对话模型）；③ 在 AstrBot 模型页单独确认该模型可用；④ 检查 AstrBot 默认对话模型是否指向已失效的中转地址。插件会按候选链逐个尝试，全部失败时降级为原始列表，不影响漏洞推送本身。

**Q：想重新推送历史条目？**
A：管理员发送 `/cve reset` 清空去重记录，或临时把 `push_only_new` 设为 `false`。

**Q：日志里出现"cron 表达式无效"？**
A：表达式必须是 5 段（`分 时 日 月 周`），不支持 `@daily` 这类别名，也不支持 6 段（秒级）。

**Q：会不会因为异常把 AstrBot 搞崩？**
A：不会。后台循环、信源抓取、指令处理、LLM 工具调用、推送全部做了独立异常捕获，信源失败只降级不中断。

---

## 更新日志

### v1.0.2

- 指令改为 AstrBot 标准指令组：`/cve push`、`/cve targets`、`/cve status`、`/cve test`、`/cve reset`、`/cve help`，每条子指令在 WebUI「指令」列表中独立可见，可单独启用、重命名与设置权限
- 指令与插件标识统一由 vuln 更名为 cve：插件 id `astrbot_plugin_cve_push`、显示名「CVE漏洞情报推送」，避免与其它 CVE 插件重名
- 内部模型同步更名：`CveItem`、`CveSummarizer`、`CvePushPlugin`；字段 `vuln_id` 更名为 `source_id`，读取旧去重记录时自动兼容
- LLM 工具更名为 `get_latest_cves` / `push_latest_cves`
- 日志前缀统一为 `[CVE推送]`

### v1.0.1

- 修复 AI 摘要忽略 `selected_provider_id`、固定走 AstrBot 默认对话模型，并在默认模型不可用时持续降级的问题
- AI 摘要模型解析改为候选链：插件配置的 `selected_provider_id` -> AstrBot 当前对话模型 -> 任意可用对话模型；前一个失败自动换下一个，全部失败才降级为原始列表
- 配置改动无需重载插件，每次推送前热读取最新配置
- 日志打印实际使用的模型 id、耗时与失败原因
- 新增 `/cve test`：真实调用一次模型，自检 AI 摘要链路并回报候选链与结果
- `/cve status` 新增展示「AI 摘要模型」与「最近一次 AI 摘要」

### v1.0.0

- 首个版本：多信源抓取 / 跨信源去重 / AI 摘要 / 定时推送 / 指令与 LLM 工具

---

## 许可协议

[MIT](LICENSE)
