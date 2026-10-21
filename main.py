"""AstrBot CVE 漏洞推送插件。

功能：
- 定时抓取奇安信 / 阿里云安全 / CNNVD 三个公开信源的最新漏洞情报
- 跨信源去重（优先 CVE 编号，其次源内编号，最后标题指纹）
- 可选 AI 摘要（调用 AstrBot 已配置对话模型，绝不直连模型 HTTP API）
- 推送群聊目标，同时注册 /vuln 指令与两个 LLM 工具
- 全程合规抓取：只读公开数据、限速、退避重试、无凭据、无绕过

硬性约束：
- 全插件严禁输出任何 emoji，状态一律使用 [完成]/[失败]/[警告]/[提示] 或 ASCII
- 所有异步入口与后台任务必须全局异常捕获，绝不允许未捕获异常导致 AstrBot 崩溃
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import Any, List, Set, Tuple

from pydantic import Field
from pydantic.dataclasses import dataclass

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.star import Context, Star, register
from astrbot.core.config.astrbot_config import AstrBotConfig
from astrbot.core.agent.tool import FunctionTool, ToolExecResult
from astrbot.core.agent.run_context import ContextWrapper
from astrbot.core.astr_agent_context import AstrAgentContext

from .core.cron_util import CronSchedule
from .core.dedup import DedupStore
from .core.formatter import (
    format_raw_message,
    format_status_message,
    format_summary_message,
)
from .core.models import VulnItem
from .core.summarizer import VulnSummarizer
from .sources import build_sources
from .sources.base import HttpFetcher

# --------------------------------------------------------------------------- #
# 配置默认值（与 _conf_schema.json 一一对应）
# --------------------------------------------------------------------------- #
_DEFAULT_CRON = "0 9 * * *"
_DEFAULT_SOURCES = ["qianxin", "aliyun", "cnnvd"]


# --------------------------------------------------------------------------- #
# LLM 工具
# --------------------------------------------------------------------------- #
@dataclass
class GetLatestVulnerabilitiesTool(FunctionTool[AstrAgentContext]):
    name: str = "get_latest_vulnerabilities"
    description: str = "获取最新安全漏洞情报（奇安信/阿里云安全/CNNVD），只返回文本不推送"
    parameters: dict = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "返回条数，默认 5"},
                "source": {
                    "type": "string",
                    "description": "信源筛选: all/qianxin/aliyun/cnnvd",
                },
            },
            "required": [],
        }
    )
    plugin_instance: Any = None

    async def call(
        self, context: ContextWrapper[AstrAgentContext], **kwargs
    ) -> ToolExecResult:
        try:
            if not self.plugin_instance:
                return "[失败] 插件实例未注入"
            limit = int(kwargs.get("limit", 5) or 5)
            source = str(kwargs.get("source", "all") or "all")
            return await self.plugin_instance._do_fetch_text(limit, source)
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] LLM 工具 get_latest_vulnerabilities 异常: %s", exc)
            return f"[失败] 工具执行异常: {exc}"


@dataclass
class PushLatestVulnerabilitiesTool(FunctionTool[AstrAgentContext]):
    name: str = "push_latest_vulnerabilities"
    description: str = "抓取最新安全漏洞情报并推送到当前会话（奇安信/阿里云安全/CNNVD）"
    parameters: dict = Field(
        default_factory=lambda: {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "返回条数，默认 5"},
                "source": {
                    "type": "string",
                    "description": "信源筛选: all/qianxin/aliyun/cnnvd",
                },
            },
            "required": [],
        }
    )
    plugin_instance: Any = None

    async def call(
        self, context: ContextWrapper[AstrAgentContext], **kwargs
    ) -> ToolExecResult:
        try:
            if not self.plugin_instance:
                return "[失败] 插件实例未注入"
            limit = int(kwargs.get("limit", 5) or 5)
            source = str(kwargs.get("source", "all") or "all")
            target = self._resolve_current_session(context)
            if not target:
                return "[失败] 无法定位当前会话目标"
            return await self.plugin_instance._do_push(
                [target], limit=limit, source_filter=source
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] LLM 工具 push_latest_vulnerabilities 异常: %s", exc)
            return f"[失败] 工具执行异常: {exc}"

    @staticmethod
    def _resolve_current_session(context: ContextWrapper[AstrAgentContext]) -> str:
        if context is None or context.context is None:
            return ""
        event = getattr(context.context, "event", None)
        if event is None:
            return ""
        return (
            getattr(event, "unified_msg_origin", "")
            or getattr(event, "session_id", "")
            or ""
        )


# --------------------------------------------------------------------------- #
# 插件主体
# --------------------------------------------------------------------------- #
@register("astrbot_plugin_vuln_push", "weskongxing", "CVE漏洞推送插件", "v1.0.0")
class VulnPushPlugin(Star):
    """CVE 漏洞推送插件。"""

    _active_instances: Set["VulnPushPlugin"] = set()

    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))

        # 防止重复实例化与协程泄漏：清理历史实例
        for old_inst in list(self._active_instances):
            try:
                old_inst._cancel_background_tasks()
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] 清理旧实例异常: %s", exc)
        self._active_instances.clear()
        self._active_instances.add(self)

        # 数据目录与去重存储
        data_dir = os.path.join(self.plugin_dir, "data")
        os.makedirs(data_dir, exist_ok=True)
        self.dedup = DedupStore(
            path=os.path.join(data_dir, "pushed_records.json"),
            window_days=int(self.config.get("dedup_window_days", 30)),
        )

        # AI 摘要器（仅通过 AstrBot 已配置对话模型，禁止直连）
        self.summarizer = VulnSummarizer(
            context=self.context,
            timeout_seconds=int(self.config.get("summary_timeout", 90)),
            max_items=int(self.config.get("max_push_items", 10)),
        )

        # cron 解析：非法表达式回退默认并告警
        cron_expr = str(self.config.get("cron_expr", _DEFAULT_CRON) or _DEFAULT_CRON)
        try:
            self.cron = CronSchedule(cron_expr)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[漏洞推送] cron 表达式无效(%s)，回退默认 %s: %s",
                cron_expr,
                _DEFAULT_CRON,
                exc,
            )
            self.cron = CronSchedule(_DEFAULT_CRON)

        # 注册并暴露 LLM 工具
        self.tool_get = GetLatestVulnerabilitiesTool(plugin_instance=self)
        self.tool_push = PushLatestVulnerabilitiesTool(plugin_instance=self)
        try:
            self.context.add_llm_tools(self.tool_get, self.tool_push)
            logger.info("[漏洞推送] 已向宿主 AstrBot 暴露 2 项 LLM 工具")
        except Exception as exc:  # noqa: BLE001
            logger.warning("[漏洞推送] LLM 工具注册警告: %s", exc)

        # 后台定时任务
        self._is_terminating = False
        self._last_fired_minute: Tuple[int, int, int, int] | None = None
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("[漏洞推送] 定时任务循环已启动，cron=%s", self.cron.expr)

    # ------------------------------------------------------------------ 生命周期
    def _cancel_background_tasks(self) -> None:
        self._is_terminating = True
        if (
            hasattr(self, "_scheduler_task")
            and self._scheduler_task
            and not self._scheduler_task.done()
        ):
            self._scheduler_task.cancel()

    async def terminate(self) -> None:
        logger.info("[漏洞推送] 正在注销并终止后台定时协程...")
        self._cancel_background_tasks()
        if self in self._active_instances:
            self._active_instances.remove(self)

        task = getattr(self, "_scheduler_task", None)
        if task:
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] 后台任务收尾异常: %s", exc)
        logger.info("[漏洞推送] 插件生命周期资源清理完毕")

    # ------------------------------------------------------------------ 定时任务
    async def _scheduler_loop(self) -> None:
        """每 20 秒检查一次是否到点，命中后触发一次推送。"""
        while not self._is_terminating:
            try:
                now = datetime.now()
                minute_key = (now.year, now.month, now.day, now.hour * 60 + now.minute)
                if self.cron.matches(now) and self._last_fired_minute != minute_key:
                    self._last_fired_minute = minute_key
                    await self._run_scheduled_push()
                    await asyncio.sleep(30)
                else:
                    await asyncio.sleep(20)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.exception("[漏洞推送] 定时循环异常: %s", exc)
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    raise

    async def _run_scheduled_push(self) -> None:
        if not self.config.get("enabled", True):
            logger.info("[漏洞推送] 插件已停用，跳过本次定时推送")
            return
        targets = self._get_push_targets()
        if not targets:
            logger.warning("[漏洞推送] 未配置推送目标，跳过定时推送")
            return
        try:
            status = await self._do_push(targets, limit=10, source_filter="all")
            logger.info("[漏洞推送] 定时推送结果: %s", status)
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 定时推送异常: %s", exc)

    # ------------------------------------------------------------------ 抓取与推送
    def _get_push_targets(self) -> List[str]:
        raw = self.config.get("push_targets", [])
        targets: List[str] = []
        if isinstance(raw, list):
            for item in raw:
                value = str(item or "").strip()
                if value and value not in targets:
                    targets.append(value)
        return targets

    def _build_fetcher(self) -> HttpFetcher:
        return HttpFetcher(
            timeout=float(self.config.get("request_timeout", 20)),
            max_requests_per_host=int(self.config.get("max_requests_per_host", 5)),
        )

    def _enabled_sources(self, source_filter: str = "all") -> List[str]:
        sources = [str(s) for s in (self.config.get("enabled_sources", _DEFAULT_SOURCES) or [])]
        source_filter = (source_filter or "all").strip().lower()
        if source_filter != "all":
            sources = [s for s in sources if s == source_filter]
        return sources

    async def _fetch_all(self, limit: int, source_filter: str = "all") -> List[VulnItem]:
        """抓取全部启用信源，按披露时间倒序并跨信源去重。"""
        sources = build_sources(self._enabled_sources(source_filter), {}, self._build_fetcher())
        items: List[VulnItem] = []
        for src in sources:
            try:
                items.extend(await src.fetch_latest(limit=limit))
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] 信源 %s 抓取失败: %s", src.name, exc)

        items.sort(key=lambda it: it.published or "", reverse=True)
        seen: Set[str] = set()
        deduped: List[VulnItem] = []
        for item in items:
            key = item.dedup_key
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    async def _collect_for_push(
        self, limit: int, source_filter: str = "all"
    ) -> List[VulnItem]:
        items = await self._fetch_all(limit, source_filter)
        if not items:
            return []
        if self.config.get("push_only_new", True):
            return self.dedup.filter_new(items)
        return items

    async def _build_push_text(self, items: List[VulnItem]) -> str:
        max_items = int(self.config.get("max_push_items", 10))
        if self.config.get("ai_summary", True):
            summary = await self.summarizer.summarize(items)
            if summary:
                return format_summary_message(summary, items)
        return format_raw_message(items, max_items=max_items)

    async def _prepare_push_text(
        self, limit: int, source_filter: str = "all"
    ) -> Tuple[str, List[VulnItem]]:
        items = await self._collect_for_push(limit, source_filter)
        if not items:
            return "", []
        text = await self._build_push_text(items)
        return text, items

    async def _push_to_targets(self, targets: List[str], text: str) -> int:
        chain = MessageChain().message(text)
        ok_count = 0
        for target in targets:
            try:
                if await self.context.send_message(target, chain):
                    ok_count += 1
                    logger.info("[漏洞推送] 成功推送消息至: %s", target)
                else:
                    logger.warning("[漏洞推送] 推送失败（未找到对应平台）: %s", target)
            except Exception as exc:  # noqa: BLE001
                logger.error("[漏洞推送] 推送消息至 %s 异常: %s", target, exc)
        return ok_count

    async def _do_push(
        self, targets: List[str], limit: int = 10, source_filter: str = "all"
    ) -> str:
        if not targets:
            return "[失败] 未指定推送目标"
        text, items = await self._prepare_push_text(limit, source_filter)
        if not text:
            return "[提示] 没有新的漏洞条目可推送"
        ok_count = await self._push_to_targets(targets, text)
        if ok_count <= 0:
            return "[失败] 推送未到达任何目标"
        self.dedup.mark_pushed(items)
        return f"[完成] 已向 {ok_count}/{len(targets)} 个目标推送 {len(items)} 条漏洞"

    async def _do_fetch_text(self, limit: int, source_filter: str = "all") -> str:
        items = await self._fetch_all(limit, source_filter)
        if not items:
            return "[提示] 当前未抓取到任何漏洞条目"
        new_items = self.dedup.filter_new(items)
        shown = new_items if new_items else items
        return format_raw_message(shown, max_items=int(self.config.get("max_push_items", 10)))

    # ------------------------------------------------------------------ 指令
    @filter.command("vuln", alias={"漏洞"})
    async def cmd_vuln(self, event: AstrMessageEvent, sub: str = ""):
        """/vuln [push|status|reset]，缺省为抓取最新漏洞推送到当前会话。"""
        sub = (sub or "").strip().lower()
        try:
            if sub in ("", "fetch", "latest"):
                yield event.plain_result(await self._cmd_fetch_current())
            elif sub in ("push",):
                yield event.plain_result(await self._cmd_push_targets())
            elif sub in ("status",):
                yield event.plain_result(self._cmd_status())
            elif sub in ("reset",):
                yield event.plain_result(self._cmd_reset(event))
            else:
                yield event.plain_result(self._help_text())
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 指令处理异常: %s", exc)
            yield event.plain_result(f"[失败] 指令处理异常: {exc}")

    async def _cmd_fetch_current(self) -> str:
        text, items = await self._prepare_push_text(limit=10, source_filter="all")
        if not text:
            return "[提示] 没有新的漏洞条目"
        self.dedup.mark_pushed(items)
        return text

    async def _cmd_push_targets(self) -> str:
        targets = self._get_push_targets()
        if not targets:
            return "[失败] 未配置推送目标（请在插件配置中设置 push_targets）"
        return await self._do_push(targets, limit=10, source_filter="all")

    def _cmd_status(self) -> str:
        stats = self.dedup.stats()
        try:
            next_run = self.cron.next_run(datetime.now())
            next_run_str = next_run.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as exc:  # noqa: BLE001
            next_run_str = f"无法推算（{exc}）"
        info = {
            "启用状态": "已启用" if self.config.get("enabled", True) else "已停用",
            "定时表达式": self.cron.expr,
            "下次执行时间": next_run_str,
            "信源开关": self.config.get("enabled_sources", _DEFAULT_SOURCES),
            "AI 摘要": "开启" if self.config.get("ai_summary", True) else "关闭",
            "仅推送新条目": "是" if self.config.get("push_only_new", True) else "否",
            "推送目标数量": len(self._get_push_targets()),
            "去重记录总数": stats.get("total", 0),
            "去重窗口天数": stats.get("window_days", 0),
            "最近记录时间": stats.get("newest", ""),
        }
        return format_status_message(info)

    def _cmd_reset(self, event: AstrMessageEvent) -> str:
        if not self._is_admin(event):
            return "[权限拦截] 仅管理员可清空去重记录"
        self.dedup.reset()
        return "[完成] 已清空全部去重记录"

    def _is_admin(self, event: AstrMessageEvent) -> bool:
        try:
            if event.is_admin():
                return True
        except Exception:  # noqa: BLE001
            pass
        sender_id = ""
        try:
            sender_id = str(event.get_sender_id() or "")
        except Exception:  # noqa: BLE001
            pass
        admins = {str(a).strip() for a in (self.config.get("admin_user_ids") or [])}
        return bool(sender_id and sender_id in admins)

    def _help_text(self) -> str:
        return (
            "[漏洞推送插件指令]\n"
            "/vuln - 抓取最新漏洞并推送到当前会话\n"
            "/vuln push - 抓取并推送到配置的群聊目标\n"
            "/vuln status - 查看插件运行状态\n"
            "/vuln reset - 清空去重记录（仅管理员）\n"
            "LLM 工具: get_latest_vulnerabilities / push_latest_vulnerabilities"
        )
