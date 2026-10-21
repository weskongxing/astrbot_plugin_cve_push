"""调用 AstrBot 已配置对话模型生成中文漏洞摘要。"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, List

from .models import VulnItem

logger = logging.getLogger("astrbot_plugin_vuln_push")

_SYSTEM_PROMPT = "你是网络安全情报编辑，负责把多条漏洞情报去重后输出统一中文摘要。"

_USER_PROMPT_TEMPLATE = """下面是最新抓取到的多条漏洞情报（已去重）。请把重复或同源的条目合并，输出统一中文摘要。
每条一行，格式为：
[风险等级] 影响组件/产品 - 一句话影响说明（40-80 字）| 处置建议一句话

约束：
- 严禁输出任何 emoji
- 严禁编造未提供的 CVE 编号或厂商
- 只输出结果，不要标题、编号或任何解释

{items}
"""


class VulnSummarizer:
    """漏洞摘要器。

    - 取模型: 优先 ``context.get_using_provider_async()``，回退
      ``context.provider_manager.get_using_provider()``
    - 调用: ``provider.text_chat(prompt=..., system_prompt=...)``
    - 任何失败均捕获并降级，返回空字符串，绝不抛出
    """

    def __init__(self, context: Any, timeout_seconds: int = 90, max_items: int = 15) -> None:
        self.context = context
        self.timeout_seconds = max(5, int(timeout_seconds))
        self.max_items = max(1, int(max_items))
        self._last_outcome = "未调用"

    @property
    def last_outcome(self) -> str:
        """最近一次调用的结果状态: 未调用 / 成功 / 降级 / 已关闭。"""
        return self._last_outcome

    async def summarize(self, items: List[VulnItem]) -> str:
        """返回结构化中文摘要文本；任何失败返回空字符串并置 last_outcome="降级"。"""
        if not items:
            self._last_outcome = "已关闭"
            return ""

        provider = await self._get_provider()
        if provider is None:
            self._last_outcome = "降级"
            logger.warning("[漏洞推送] 未获取到可用对话模型，AI 摘要降级")
            return ""

        prompt = self._build_prompt(items)
        try:
            resp = await asyncio.wait_for(
                provider.text_chat(prompt=prompt, system_prompt=_SYSTEM_PROMPT),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            self._last_outcome = "降级"
            logger.warning(
                "[漏洞推送] AI 摘要超时（%s 秒），已降级", self.timeout_seconds
            )
            return ""
        except Exception as exc:  # noqa: BLE001
            self._last_outcome = "降级"
            logger.warning("[漏洞推送] AI 摘要调用失败，已降级: %s", exc)
            return ""

        text = (getattr(resp, "completion_text", "") or "").strip()
        if not text:
            self._last_outcome = "降级"
            logger.warning("[漏洞推送] AI 摘要返回空内容，已降级")
            return ""
        self._last_outcome = "成功"
        return text

    # ------------------------------------------------------------------ 内部
    async def _get_provider(self) -> Any:
        """依次尝试两种取模型方式，均失败返回 None。"""
        getter = getattr(self.context, "get_using_provider_async", None)
        if getter is not None:
            try:
                provider = await getter()
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] get_using_provider_async 异常: %s", exc)
                provider = None
            if provider is not None and hasattr(provider, "text_chat"):
                return provider

        manager = getattr(self.context, "provider_manager", None)
        fallback_getter = getattr(manager, "get_using_provider", None)
        if fallback_getter is not None:
            try:
                provider = fallback_getter()
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] get_using_provider 异常: %s", exc)
                return None
            if provider is not None and hasattr(provider, "text_chat"):
                return provider
        return None

    def _build_prompt(self, items: List[VulnItem]) -> str:
        chunks: List[str] = []
        for item in items[: self.max_items]:
            fields: List[str] = []
            display_id = item.display_id or "-"
            fields.append(f"编号: {display_id}")
            if item.source_display:
                fields.append(f"来源: {item.source_display}")
            fields.append(f"标题: {item.title or '未命名漏洞'}")
            if item.severity:
                fields.append(f"风险等级: {item.severity}")
            if item.description:
                desc = " ".join(str(item.description).split())
                fields.append(f"描述: {desc[:300]}")
            if item.tags:
                fields.append(f"标签: {', '.join(item.tags)}")
            if item.url:
                fields.append(f"链接: {item.url}")
            chunks.append("\n".join(fields))
        return _USER_PROMPT_TEMPLATE.format(items="\n\n".join(chunks))
