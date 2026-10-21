# astrbot_plugin_vuln_push 开发接口规范（INTERFACES）

本文件是并行开发各模块的唯一接口契约。所有模块必须严格按此实现，禁止改动已给定的公共签名。

## 0. 硬性约束（任何模块都不得违反）

1. **绝对禁止输出任何 Emoji**：代码、注释、日志、文档、配置、测试用例、消息模板一律不得出现 emoji。
   状态与日志统一使用纯中文标签（`[完成]` `[失败]` `[警告]` `[提示]` `[执行中]`）或 ASCII 符号（`->` `*` `+` `-`）。
2. **零攻击性抓取**：只用公开 GET/POST 读取公开数据；标准浏览器 UA；同域名请求间隔 >= 1.2 秒；
   失败指数退避重试最多 2 次；单次任务同域名请求数 <= 5；不携带凭据 Cookie；不做登录/验证码绕过、
   参数爆破、目录扫描、注入探测。全部走 `sources/base.py` 的 `HttpFetcher`，禁止自行 `httpx` 直连。
3. **禁止硬编码 API Key**：AI 摘要必须调用 AstrBot 已配置的对话模型，禁止直连模型 HTTP API。
4. **禁止未捕获异常导致插件崩溃**：所有对外方法内部必须 try/except 并记录日志。
5. Python 3.12 / AstrBot 4.28.2。除 `httpx`（AstrBot 已内置）与 `beautifulsoup4`（已内置）外不新增依赖。

## 1. 目录结构（固定）

```
astrbot_plugin_vuln_push/
├── main.py                 # 插件入口（Star 子类、指令、LLM 工具、定时任务）
├── metadata.yaml
├── _conf_schema.json
├── requirements.txt
├── README.md
├── core/
│   ├── __init__.py
│   ├── models.py           # [已提供] VulnItem
│   ├── cron_util.py        # CronSchedule 5 段 cron 解析
│   ├── dedup.py            # DedupStore 持久化去重
│   ├── summarizer.py       # VulnSummarizer 调用 AstrBot 对话模型
│   └── formatter.py        # 消息文本构建
├── sources/
│   ├── __init__.py         # build_sources()
│   ├── base.py             # [已提供] HttpFetcher / BaseSource / FetchError
│   ├── qianxin.py
│   ├── aliyun.py
│   └── cnnvd.py
└── tests/
    ├── fixtures/
    ├── test_sources.py
    ├── test_dedup.py
    ├── test_formatter.py
    └── test_cron.py
```

## 2. 已提供的公共契约（禁止修改）

### core/models.py
```python
@dataclass
class VulnItem:
    source: str = ""          # 机器名: "qianxin" / "aliyun" / "cnnvd"
    source_display: str = ""  # 中文名: "奇安信" / "阿里云安全" / "CNNVD"
    title: str = ""
    vuln_id: str = ""         # 源内编号: QVD-xxx / AVD-xxx / CNNVD-xxx
    cve_id: str = ""          # CVE-YYYY-NNNN（可能为空）
    severity: str = ""        # 极危/超危/高危/中危/低危/未知
    published: str = ""       # YYYY-MM-DD
    url: str = ""
    description: str = ""
    tags: list[str] = []

    @property dedup_key -> str        # cve:xxx / vid:xxx / title:<md5>
    @property title_fingerprint -> str
    @property display_id -> str
    def to_dict() -> dict
    @classmethod from_dict(d) -> VulnItem

def extract_cve(text: str) -> str          # 提取第一个 CVE 编号（大写）
def severity_rank(severity: str) -> int    # 越小越高危
def normalize_severity(raw: str) -> str
SEVERITY_ORDER = ["极危", "超危", "严重", "高危", "中危", "低危", "未知"]
```

### sources/base.py
```python
class FetchError(Exception): ...

class HttpFetcher:
    def __init__(self, *, timeout=20.0, min_interval=1.2, max_retries=2,
                 max_requests_per_host=5, user_agent=DEFAULT_USER_AGENT)
    async def request(self, method, url, *, headers=None, json_body=None,
                      params=None, expect_json=True) -> Any
    def reset_budget(self) -> None

class BaseSource(abc.ABC):
    name: str
    display_name: str
    def __init__(self, config: dict, fetcher: HttpFetcher)
    @abc.abstractmethod
    async def fetch_latest(self, limit: int = 10) -> list[VulnItem]
```

## 3. 各模块要求

### 3.1 sources/qianxin.py（子任务 A）
- 类名 `QianxinSource(BaseSource)`，`name = "qianxin"`，`display_name = "奇安信"`。
- 接口：`POST https://ti.qianxin.com/alpha-api/v2/vuln/one-day`
  - headers: `Referer: https://ti.qianxin.com/`、`Origin: https://ti.qianxin.com`、`Content-Type: application/json`
  - 无请求体。返回 `{"status": 10000, "data": {"key_vuln_add": [...], "poc_exp_add": [...], "vuln_add_count": N, ...}}`
- 字段映射（`key_vuln_add` 与 `poc_exp_add` 合并，按 `id` 去重，`key_vuln_add` 优先）：
  - `vuln_id = qvd_code`；`cve_id = extract_cve(cve_code or vuln_name)`；`title = vuln_name`
  - `severity = normalize_severity(rating_level)`；`published = publish_time[:10]`
  - `description = description`（截断到 300 字）；`tags = [t["name"] for t in tag]`
  - `url = "https://ti.qianxin.com/vulnerability/detail/" + str(id)`
- 返回按 `published` 倒序的前 `limit` 条；`status != 10000` 抛 `FetchError`。

### 3.2 sources/aliyun.py（子任务 A）
- 类名 `AliyunSource(BaseSource)`，`name = "aliyun"`，`display_name = "阿里云安全"`。
- 接口：`GET https://avd.aliyun.com/`（返回服务端渲染 HTML，`expect_json=False`）。
- 用 `BeautifulSoup(html, "html.parser")` 解析：取首页表格中所有含 `/detail?id=AVD-` 的 `<tr>`，
  单元格依次为：`[0] AVD 编号(含 a[href])`、`[1] 漏洞名称(含 CVE-xxxx)`、`[2] 漏洞类型(CWE-xxx 或 未定义)`、`[3] 披露时间`、`[4] 漏洞状态`。
- 字段映射：`vuln_id = AVD-xxx`；`cve_id = extract_cve(漏洞名称)`；`title = 漏洞名称`；
  `published = 披露时间`；`severity = normalize_severity(漏洞状态 或 空 -> "未知")`（状态列常为"未定义"，此时用 `""` -> 归一为 `未知`）；
  `tags = [漏洞类型]`（为 `未定义` 时置空）；`url = "https://avd.aliyun.com" + href`。
- 解析不到任何条目时抛 `FetchError("阿里云 AVD 首页结构变化，未解析到漏洞条目")`。

### 3.3 sources/cnnvd.py（子任务 A）
CNNVD 新站为前端签名接口，采用站点公开的「游客签名」流程（官方 `/tourist/**` 游客通道，非绕过）：

- 常量：`APP_ID = "6i8417579268034679HXvp0Kb6r1C2A9"`，`ORIGIN = "https://www.cnnvd.org.cn"`，`BASE = "/cnnvdweb"`。
- 步骤一（取签名）：
  - `timestamp = str(int(time.time() * 1000))`
  - `nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))`
  - `sign_str = "POST" + BASE + "/homePage/hotVulNewList" + timestamp + nonce`
  - `POST {ORIGIN}{BASE}/tourist/sign`，json `{"signStr": sign_str}`，
    headers: `X-Appid / X-Timestamp / X-Nonce / Content-Type: application/json;charset=utf-8 / Origin / Referer`
  - 返回 `{"code":200,"data":"<20位hex签名>"}`，`code != 200` 抛 `FetchError`。
- 步骤二（取数据）：`POST {ORIGIN}{BASE}/homePage/hotVulNewList`，json `{}`，
  headers 同上再加 `X-Sign: <签名>`。返回 `{"code":200,"data":[{"vulId","vulName","cnnvdCode","hazardLevel","publishTime","hasAi"}]}`。
- 字段映射：`vuln_id = cnnvdCode`；`cve_id = extract_cve(vulName)`；`title = vulName`；
  `severity = normalize_severity(hazardLevel)`；`published = publishTime`；
  `url = "https://www.cnnvd.org.cn/frontend/detail?vulId=" + str(vulId)`；`description = ""`。
- 每次请求必须使用**全新的** timestamp/nonce（严禁复用），两次 HTTP 调用之间由 HttpFetcher 自动限速。
- 类名 `CnnvdSource(BaseSource)`，`name = "cnnvd"`，`display_name = "CNNVD"`。

### 3.4 sources/__init__.py（子任务 A）
```python
SOURCE_REGISTRY = {"qianxin": QianxinSource, "aliyun": AliyunSource, "cnnvd": CnnvdSource}

def build_sources(enabled_sources: list[str], config: dict, fetcher: HttpFetcher) -> list[BaseSource]
    """按 enabled_sources 顺序构建信源实例；未知名字忽略。"""
```

### 3.5 core/cron_util.py（子任务 B）
```python
class CronSchedule:
    def __init__(self, expr: str)                     # 5 段标准 cron，非法抛 ValueError
    def matches(self, dt: datetime) -> bool           # 精确到分钟
    def next_run(self, after: datetime) -> datetime   # 严格大于 after 的下一次触发时刻
    @property expr -> str
```
支持 `*`、`a-b`、`*/n`、`a-b/n`、`a,b,c`；周字段 0-7（0 与 7 均为周日）。

### 3.6 core/dedup.py（子任务 B）
```python
class DedupStore:
    def __init__(self, path: str, window_days: int = 30)
    def load(self) -> None
    def is_pushed(self, item: VulnItem) -> bool
    def filter_new(self, items: list[VulnItem]) -> list[VulnItem]   # 保持原顺序，过滤已推送
    def mark_pushed(self, items: list[VulnItem], now: float | None = None) -> None
    def reset(self) -> None
    def stats(self) -> dict   # {"total": N, "window_days": D, "oldest": "YYYY-MM-DD HH:MM:SS", "newest": "..."}
```
- 持久化 JSON：`{"version": 1, "records": {"<dedup_key>": <unix_ts>}}`。
- 加载/保存必须容错（文件损坏时重置并记 warning），写盘使用临时文件 + `os.replace` 原子替换。
- 超过 `window_days` 的记录在 `load()` 与 `mark_pushed()` 时清理。

### 3.7 core/summarizer.py（子任务 B）
```python
class VulnSummarizer:
    def __init__(self, context, timeout_seconds: int = 90, max_items: int = 15)
    @property last_outcome -> str          # "未调用" / "成功" / "降级" / "已关闭"
    async def summarize(self, items: list[VulnItem]) -> str
        """返回结构化中文摘要文本；任何失败必须返回空字符串并置 last_outcome="降级"。"""
```
- 取模型：`provider = await self.context.get_using_provider_async()`；若不存在则尝试
  `self.context.provider_manager.get_using_provider()`；都拿不到 -> 降级。
- 调用：`await asyncio.wait_for(provider.text_chat(prompt=..., system_prompt=...), timeout=self.timeout_seconds)`，
  取 `getattr(resp, "completion_text", "")`。
- 提示词要求：把多条漏洞去重后输出统一中文摘要，包含：
  `[风险等级] 影响组件/产品 - 一句话影响说明（40-80 字）| 处置建议一句话`；
  严禁输出 emoji；严禁编造未提供的 CVE 编号或厂商；只输出结果，不要标题与解释。
- 超时/异常必须捕获并降级，不得抛出。

### 3.8 core/formatter.py（子任务 B）
```python
def format_item_line(index: int, item: VulnItem) -> str
def format_raw_message(items: list[VulnItem], title: str = "最新安全漏洞播报", max_items: int = 10) -> str
def format_summary_message(summary: str, items: list[VulnItem], title: str = "安全漏洞情报摘要") -> str
def format_status_message(info: dict) -> str
```
- 纯文本排版，无 emoji，无 Markdown 表格；单条格式示例：
  `1. [高危] 标题（CVE-2026-1234）\n   来源: 奇安信 | 披露: 2026-10-21\n   链接: https://...`
- 长度保护：`format_raw_message` 总长度超过 3500 字时截断并追加 `\n...（更多条目已省略）`。

### 3.9 main.py（子任务 C）
- 注册：`@register("astrbot_plugin_vuln_push", "assistant", "多信源安全漏洞情报定时推送插件", "v1.0.0")`
- 类名 `VulnPushPlugin(Star)`，`__init__(self, context: Context, config: AstrBotConfig)`。
- 依赖的 AstrBot 4.28.2 API（已在同容器 astrbot_plugin_server_guard 中验证可用）：
  ```python
  from astrbot.api import logger
  from astrbot.api.event import AstrMessageEvent, MessageChain, filter
  from astrbot.api.star import Context, Star, register
  from astrbot.core.config.astrbot_config import AstrBotConfig
  from astrbot.core.agent.tool import FunctionTool, ToolExecResult
  from astrbot.core.agent.run_context import ContextWrapper
  from astrbot.core.astr_agent_context import AstrAgentContext
  ```
- 指令（`@filter.command("vuln", alias={"漏洞"})` 形式，参考 server_guard 的用法）：
  - `/vuln` 或 `/漏洞`：抓取最新漏洞（去重后）并推送到当前会话；
  - `/vuln push`：抓取并推送到配置的群聊目标；
  - `/vuln status`：输出插件状态（cron、下次执行时间、信源开关、AI 开关、去重统计）；
  - `/vuln reset`：清空去重记录（仅管理员/配置内管理员可用）。
- LLM 工具（`context.add_llm_tools(...)`，继承 `FunctionTool[AstrAgentContext]`，pydantic dataclass）：
  - `get_latest_vulnerabilities(limit: int = 5, source: str = "all")` -> 返回文本，不推送；
  - `push_latest_vulnerabilities(limit: int = 5, source: str = "all")` -> 抓取并推送到当前会话。
- 定时任务：`asyncio.create_task(self._scheduler_loop())`，用 `CronSchedule` 每 20 秒检查一次是否到点；
  `terminate()` 中取消任务。
- 推送：`ok = await self.context.send_message(target_umo, MessageChain().message(text))`，
  目标来自配置 `push_targets`（列表，支持 UMO 或 session id）。
- 配置键（与 `_conf_schema.json` 一一对应）：
  `enabled(bool)` `cron_expr(str, 默认 "0 9 * * *")` `enabled_sources(list[str])`
  `push_targets(list[str])` `ai_summary(bool)` `selected_provider_id(str, _special=select_provider)`
  `summary_timeout(int)` `max_push_items(int)` `dedup_window_days(int)` `request_timeout(int)`
  `max_requests_per_host(int)` `admin_user_ids(list[str])` `push_only_new(bool)`
- 配置读取一律 `self.config.get(key, default)`；异常必须捕获并 logger 记录。

### 3.10 _conf_schema.json / metadata.yaml / requirements.txt / README.md（子任务 C）
- `metadata.yaml` 参考：
  ```yaml
  name: astrbot_plugin_vuln_push
  display_name: 多信源安全漏洞推送
  desc: 定时抓取奇安信/阿里云安全/CNNVD 最新漏洞情报，支持跨信源去重与 AI 摘要，推送群聊并注册指令与 LLM 工具
  version: v1.0.0
  author: assistant
  repo: https://github.com/itboys/astrbot_plugin_vuln_push
  astrbot_version: ">=4.11.2"
  ```
- `requirements.txt` 只写 `httpx` 与 `beautifulsoup4`（容器内已内置，仅作声明）。
- `README.md` 必须说明：三个信源的获取方式与理由、合规说明、配置项逐条说明、指令与 LLM 工具用法、cron 语法。

### 3.11 tests/（子任务 D）
离线单元测试（`unittest`），不依赖网络：信源解析（用 `tests/fixtures/` 下的样例 JSON/HTML）、
去重逻辑、消息格式化、cron 解析与 next_run。全部用例必须通过。
