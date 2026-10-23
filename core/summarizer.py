"""调用 AstrBot 已配置对话模型生成中文漏洞摘要。

本模块只通过 AstrBot 的 Provider 体系调用模型，绝不直连模型 HTTP API。

候选模型解析顺序（逐个尝试，全部失败才降级为原始列表）:
1. 插件配置的 ``selected_provider_id``（用户在 WebUI 里选的模型）
2. AstrBot 当前使用的对话模型（``get_using_provider_async``）
3. AstrBot 中第一个可用的对话模型（``get_all_providers``）

v1.0.1 修复说明:
    v1.0.0 完全忽略了 ``selected_provider_id``，只取 AstrBot 的默认对话模型
    （即 ``provider_insts[0]``）。当默认模型指向不可达的第三方中转地址时，
    无论用户在插件里选了哪个可用模型，摘要都会一直失败并降级，日志表现为
    ``AI 摘要调用失败，已降级: Connection error.``
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from typing import Any, List, Optional, Tuple

from .models import CveItem

logger = logging.getLogger("astrbot_plugin_cve_push")

_SYSTEM_PROMPT = (
    "你是网络安全情报编辑，负责对多条漏洞情报进行跨编号去重、过滤已修复漏洞，"
    "并仅对未修复漏洞输出统一中文摘要。"
)

_USER_PROMPT_TEMPLATE = """下面是最新抓取到的多条漏洞情报。请严格按以下规则处理并输出统一中文摘要：

1. 同漏洞跨编号去重：若多条情报指向同一漏洞（如同时存在 CNNVD 编号与 CVE 编号），必须合并为一条，且统一保留 CVE 编号，不重复输出 CNNVD 条目。
2. 过滤已修复漏洞：结合情报中的「补丁状态」与描述语义判断漏洞是否已有官方补丁或已修复（例如描述中明确提及“在 X.Y.Z 之前版本存在漏洞”、“升级至 X.Y.Z 修复”或补丁状态为已修复）。已修复的漏洞直接丢弃不输出，仅输出尚未修复/暂无官方补丁的漏洞摘要。
3. 若所有输入漏洞均已修复，仅输出一行：[全部已修复]
4. 每条未修复漏洞输出一行，格式为：
[风险等级] 漏洞编号 影响组件/产品 - 一句话影响说明（40-80 字）| 临时缓解建议一句话
（优先展示 CVE 编号，无 CVE 编号时再展示源编号）

约束：
- 严禁输出任何 emoji
- 严禁编造未提供的 CVE 编号或厂商
- 只输出结果，不要标题、序号或任何多余解释

{items}
"""

_SELF_TEST_ITEM = CveItem(
    source="self_test",
    source_display="自检",
    title="AI 摘要链路自检示例漏洞",
    source_id="SELF-TEST-0001",
    severity="低危",
    published="2026-01-01",
    url="https://example.com/self-test",
    description="这是一条用于验证 AI 摘要链路是否可用的示例数据，不代表真实漏洞。",
    tags=["自检"],
)


def _provider_id_of(provider: Any) -> str:
    """尽力从 Provider 实例上取出配置里的 id，取不到返回空串。"""
    if provider is None:
        return ""
    config = getattr(provider, "provider_config", None)
    if isinstance(config, dict):
        pid = str(config.get("id") or "").strip()
        if pid:
            return pid
    for attr in ("id", "provider_id"):
        value = getattr(provider, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _is_chat_provider(provider: Any) -> bool:
    """判定实例是否为可用于文本生成的对话模型。"""
    return provider is not None and callable(getattr(provider, "text_chat", None))


class CveSummarizer:
    """漏洞摘要器。

    只依赖 AstrBot 的 ``Context``：``get_provider_by_id`` / ``get_using_provider_async``
    / ``get_all_providers``，任何取模型与调用异常均被捕获，绝不向上抛出。
    """

    def __init__(
        self,
        context: Any,
        timeout_seconds: int = 90,
        max_items: int = 15,
        provider_id: str = "",
        fallback_provider_ids: Optional[List[str]] = None,
    ) -> None:
        self.context = context
        self.timeout_seconds = max(5, int(timeout_seconds))
        self.max_items = max(1, int(max_items))
        self.provider_id = str(provider_id or "").strip()
        self.fallback_provider_ids = [
            str(pid).strip() for pid in (fallback_provider_ids or []) if str(pid).strip()
        ]
        self._last_outcome = "未调用"
        self._last_provider = ""
        self._last_error = ""
        self._last_elapsed = 0.0

    # ------------------------------------------------------------------ 状态
    @property
    def last_outcome(self) -> str:
        """最近一次调用的结果状态: 未调用 / 成功 / 降级 / 已关闭。"""
        return self._last_outcome

    @property
    def last_provider(self) -> str:
        """最近一次成功调用使用的模型 id（失败时为空）。"""
        return self._last_provider

    @property
    def last_error(self) -> str:
        """最近一次失败的原因摘要（成功时为空）。"""
        return self._last_error

    @property
    def last_elapsed(self) -> float:
        """最近一次调用的耗时（秒）。"""
        return self._last_elapsed

    def configure(
        self,
        provider_id: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        max_items: Optional[int] = None,
    ) -> None:
        """热更新配置，供 WebUI 改配置后无需重载插件即可生效。"""
        if provider_id is not None:
            self.provider_id = str(provider_id or "").strip()
        if timeout_seconds is not None:
            self.timeout_seconds = max(5, int(timeout_seconds))
        if max_items is not None:
            self.max_items = max(1, int(max_items))

    def _set_state(self, outcome: str, provider: str = "", error: str = "") -> None:
        self._last_outcome = outcome
        self._last_provider = provider
        self._last_error = error

    # ------------------------------------------------------------------ 摘要
    async def summarize(self, items: List[CveItem]) -> str:
        """返回结构化中文摘要文本；任何失败返回空字符串并置 last_outcome="降级"。"""
        if not items:
            self._set_state("已关闭")
            return ""

        candidates = await self._collect_candidates()
        if not candidates:
            self._set_state("降级", "", "未找到任何可用的对话模型")
            logger.warning("[漏洞推送] 未获取到可用对话模型，AI 摘要降级")
            return ""

        prompt = self._build_prompt(items)
        errors: List[str] = []
        for pid, provider in candidates:
            text, err = await self._call(provider, prompt)
            if text:
                self._set_state("成功", pid)
                logger.info(
                    "[漏洞推送] AI 摘要完成，模型=%s，耗时 %.1f 秒，输出 %d 字",
                    pid or "(未命名)",
                    self._last_elapsed,
                    len(text),
                )
                return text
            errors.append(f"{pid or '(未命名)'}: {err}")
            logger.warning(
                "[漏洞推送] AI 摘要调用失败（模型=%s）: %s", pid or "(未命名)", err
            )

        self._set_state("降级", "", "; ".join(errors)[:300])
        logger.warning(
            "[漏洞推送] 全部候选模型均调用失败，AI 摘要降级为原始列表。尝试记录: %s",
            self._last_error,
        )
        return ""

    async def self_test(self) -> str:
        """对 AI 摘要链路做一次真实调用自检，返回可直接展示给用户的中文报告。"""
        candidates = await self._collect_candidates()
        lines: List[str] = ["[AI 摘要链路自检]"]
        lines.append(
            "配置指定模型: " + (self.provider_id or "(留空，跟随 AstrBot 默认模型)")
        )
        if not candidates:
            self._set_state("降级", "", "未找到任何可用的对话模型")
            lines.append("候选模型链: (空)")
            lines.append("[失败] 未找到任何可用的对话模型，请先在 AstrBot 中配置模型提供商")
            return "\n".join(lines)

        lines.append(
            "候选模型链: " + " -> ".join(pid or "(未命名)" for pid, _ in candidates)
        )
        prompt = self._build_prompt([_SELF_TEST_ITEM])
        for pid, provider in candidates:
            text, err = await self._call(provider, prompt)
            if text:
                self._set_state("成功", pid)
                lines.append(
                    f"[完成] 模型 {pid or '(未命名)'} 调用成功，耗时 {self._last_elapsed:.1f} 秒"
                )
                lines.append("模型返回: " + " ".join(text.split())[:200])
                return "\n".join(lines)
            lines.append(f"[失败] 模型 {pid or '(未命名)'} -> {err}")

        self._set_state("降级", "", "全部候选模型调用失败")
        lines.append("结论: [失败] 所有候选模型均不可用，AI 摘要将降级为原始列表")
        return "\n".join(lines)

    # ------------------------------------------------------------------ 内部
    async def _call(self, provider: Any, prompt: str) -> Tuple[str, str]:
        """调用单个模型，返回 (摘要文本, 错误描述)，二者必有一为空。"""
        started = time.monotonic()
        try:
            resp = await asyncio.wait_for(
                provider.text_chat(prompt=prompt, system_prompt=_SYSTEM_PROMPT),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            self._last_elapsed = time.monotonic() - started
            return "", f"超时（{self.timeout_seconds} 秒）"
        except Exception as exc:  # noqa: BLE001
            self._last_elapsed = time.monotonic() - started
            return "", f"{type(exc).__name__}: {exc}"

        self._last_elapsed = time.monotonic() - started
        text = (getattr(resp, "completion_text", "") or "").strip()
        if not text:
            return "", "模型返回空内容"
        return text, ""

    async def _collect_candidates(self) -> List[Tuple[str, Any]]:
        """按优先级汇总候选模型，去重且保证只含对话模型。"""
        candidates: List[Tuple[str, Any]] = []
        seen_ids: set = set()
        seen_objs: set = set()

        def add(provider: Any, pid: str = "") -> None:
            if not _is_chat_provider(provider):
                return
            real_id = pid or _provider_id_of(provider)
            if real_id and real_id in seen_ids:
                return
            if id(provider) in seen_objs:
                return
            if real_id:
                seen_ids.add(real_id)
            seen_objs.add(id(provider))
            candidates.append((real_id, provider))

        # 1) 插件配置显式指定的模型
        for pid in [self.provider_id] + self.fallback_provider_ids:
            if not pid:
                continue
            provider = await self._get_provider_by_id(pid)
            if provider is None:
                logger.warning(
                    "[漏洞推送] 配置的 AI 模型不存在或未启用: %s（将回退到其他可用模型）",
                    pid,
                )
                continue
            add(provider, pid)

        # 2) AstrBot 当前使用的对话模型
        add(await self._get_using_provider())

        # 3) 兜底：任一可用对话模型
        for provider in self._get_all_providers():
            add(provider)

        return candidates

    async def _get_provider_by_id(self, provider_id: str) -> Any:
        """按 id 取模型，兼容 context / provider_manager / inst_map 三种入口。"""
        getter = getattr(self.context, "get_provider_by_id", None)
        if callable(getter):
            try:
                provider = getter(provider_id)
                if inspect.isawaitable(provider):
                    provider = await provider
                if provider is not None:
                    return provider
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[漏洞推送] get_provider_by_id(%s) 异常: %s", provider_id, exc
                )

        manager = getattr(self.context, "provider_manager", None)
        if manager is not None:
            getter = getattr(manager, "get_provider_by_id", None)
            if callable(getter):
                try:
                    provider = getter(provider_id)
                    if inspect.isawaitable(provider):
                        provider = await provider
                    if provider is not None:
                        return provider
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "[漏洞推送] provider_manager.get_provider_by_id(%s) 异常: %s",
                        provider_id,
                        exc,
                    )
            inst_map = getattr(manager, "inst_map", None)
            if isinstance(inst_map, dict):
                provider = inst_map.get(provider_id)
                if provider is not None:
                    return provider
        return None

    async def _get_using_provider(self) -> Any:
        """取 AstrBot 当前使用的对话模型，失败返回 None。"""
        getter = getattr(self.context, "get_using_provider_async", None)
        if callable(getter):
            try:
                provider = await getter()
                if provider is not None:
                    return provider
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] get_using_provider_async 异常: %s", exc)

        getter = getattr(self.context, "get_using_provider", None)
        if callable(getter):
            try:
                provider = getter()
                if inspect.isawaitable(provider):
                    provider = await provider
                return provider
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] get_using_provider 异常: %s", exc)
        return None

    def _get_all_providers(self) -> List[Any]:
        """取 AstrBot 中全部对话模型，失败返回空列表。"""
        getter = getattr(self.context, "get_all_providers", None)
        if callable(getter):
            try:
                providers = getter() or []
                if isinstance(providers, (list, tuple)):
                    return list(providers)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[漏洞推送] get_all_providers 异常: %s", exc)

        manager = getattr(self.context, "provider_manager", None)
        insts = getattr(manager, "provider_insts", None)
        if isinstance(insts, (list, tuple)):
            return list(insts)
        return []

    def _build_prompt(self, items: List[CveItem]) -> str:
        chunks: List[str] = []
        for item in items[: self.max_items]:
            fields: List[str] = []
            if item.cve_id:
                fields.append(f"编号: {item.cve_id}")
                related_id = getattr(item, "cnnvd_id", "") or item.source_id
                if related_id and related_id.upper() != item.cve_id.upper():
                    fields.append(
                        f"关联编号: {related_id}（主编号为 CVE: {item.cve_id}）"
                    )
            else:
                display_id = item.display_id or "-"
                fields.append(f"编号: {display_id}")
            if item.source_display:
                fields.append(f"来源: {item.source_display}")
            fields.append(f"标题: {item.title or '未命名漏洞'}")
            if item.severity:
                fields.append(f"风险等级: {item.severity}")
            is_patched = getattr(item, "is_patched", None)
            if is_patched is True:
                fields.append("补丁状态: 已修复/已有官方补丁")
            elif is_patched is False:
                fields.append("补丁状态: 未修复/暂无官方补丁")
            else:
                fields.append("补丁状态: 未知（请结合描述判断）")
            if item.description:
                desc = " ".join(str(item.description).split())
                fields.append(f"描述: {desc[:300]}")
            if item.tags:
                fields.append(f"标签: {', '.join(item.tags)}")
            if item.url:
                fields.append(f"链接: {item.url}")
            chunks.append("\n".join(fields))
        return _USER_PROMPT_TEMPLATE.format(items="\n\n".join(chunks))

    @staticmethod
    def filter_unpatched_items(items: List[CveItem]) -> List[CveItem]:
        return filter_unpatched_items(items)

    @staticmethod
    def filter_items_by_summary(items: List[CveItem], summary: str) -> List[CveItem]:
        return filter_items_by_summary(items, summary)


def filter_unpatched_items(items: List[CveItem]) -> List[CveItem]:
    """规则层前置过滤：剔除明确标记为已修复（is_patched is True）的漏洞条目。"""
    return [
        item for item in (items or []) if getattr(item, "is_patched", None) is not True
    ]


def filter_items_by_summary(items: List[CveItem], summary: str) -> List[CveItem]:
    """根据 AI 摘要内容筛选未修复漏洞条目。

    - 若摘要返回 "全部已修复" 或 "[全部已修复]"，返回空列表 []；
    - 若摘要中显式包含某些条目的 cve_id / cnnvd_id / source_id，仅保留被提及的条目；
    - 若摘要未包含任何具体编号（兼容旧格式或测试桩文本），保留全部传入 items。
    """
    if not items:
        return []
    text = (summary or "").strip()
    if not text:
        return list(items)
    if "[全部已修复]" in text or "全部已修复" in text:
        return []

    text_upper = text.upper()
    matched: List[CveItem] = []
    for item in items:
        candidate_ids = [
            getattr(item, "cve_id", "") or "",
            getattr(item, "cnnvd_id", "") or "",
            getattr(item, "source_id", "") or "",
        ]
        if any(cid and cid.upper() in text_upper for cid in candidate_ids):
            matched.append(item)

    if matched:
        return matched
    return list(items)
