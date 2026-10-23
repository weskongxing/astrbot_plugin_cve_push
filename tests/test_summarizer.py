"""CveSummarizer 离线单元测试（候选链回退、超时、自检、去重）。"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_PARENT_DIR = os.path.dirname(_PLUGIN_DIR)
for _p in (_PARENT_DIR, _PLUGIN_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from astrbot_plugin_cve_push.core.models import CveItem
from astrbot_plugin_cve_push.core.summarizer import (
    CveSummarizer,
    filter_items_by_summary,
    filter_unpatched_items,
)


def make_item(**overrides: Any) -> CveItem:
    base = dict(
        source="qianxin",
        source_display="奇安信",
        title="测试漏洞标题",
        source_id="QVD-2026-1",
        cve_id="CVE-2026-1111",
        severity="高危",
        published="2026-10-21",
        url="https://example.com/detail/1",
        description="用于摘要测试的描述",
        tags=["测试"],
    )
    base.update(overrides)
    return CveItem(**base)


class FakeResponse:
    def __init__(self, text: str) -> None:
        self.completion_text = text


class FakeProvider:
    """鸭子类型对话模型；可配置成功文本、抛异常或休眠。"""

    def __init__(
        self,
        pid: str,
        *,
        text: str = "摘要结果",
        error: Optional[BaseException] = None,
        sleep_seconds: float = 0.0,
        empty: bool = False,
    ) -> None:
        self.provider_config: Dict[str, str] = {"id": pid}
        self._text = text
        self._error = error
        self._sleep_seconds = sleep_seconds
        self._empty = empty
        self.call_count = 0

    async def text_chat(self, prompt: str = "", system_prompt: str = "") -> FakeResponse:
        self.call_count += 1
        if self._sleep_seconds > 0:
            await asyncio.sleep(self._sleep_seconds)
        if self._error is not None:
            raise self._error
        if self._empty:
            return FakeResponse("")
        return FakeResponse(self._text)


class FakeTTSProvider:
    """无 text_chat 的非对话模型，应被过滤。"""

    def __init__(self, pid: str = "tts-1") -> None:
        self.provider_config = {"id": pid}

    def synthesize(self) -> str:
        return "audio"


class FakeContext:
    """鸭子类型 context，四个能力均可缺省或抛错。"""

    def __init__(
        self,
        *,
        by_id: Optional[Dict[str, Any]] = None,
        using: Any = None,
        using_error: Optional[BaseException] = None,
        all_providers: Optional[List[Any]] = None,
        has_using_async: bool = True,
        has_get_by_id: bool = True,
        has_get_all: bool = True,
    ) -> None:
        self._by_id = dict(by_id or {})
        self._using = using
        self._using_error = using_error
        self._all = list(all_providers or [])
        self._has_using_async = has_using_async
        self._has_get_by_id = has_get_by_id
        self._has_get_all = has_get_all

    def get_provider_by_id(self, pid: str) -> Any:
        if not self._has_get_by_id:
            raise AttributeError("get_provider_by_id 未实现")
        return self._by_id.get(pid)

    async def get_using_provider_async(self) -> Any:
        if not self._has_using_async:
            raise AttributeError("get_using_provider_async 未实现")
        if self._using_error is not None:
            raise self._using_error
        return self._using

    def get_using_provider(self) -> Any:
        return self._using

    def get_all_providers(self) -> List[Any]:
        if not self._has_get_all:
            raise AttributeError("get_all_providers 未实现")
        return list(self._all)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


class SummarizerCandidateTests(unittest.TestCase):
    def test_configured_provider_id_preferred(self):
        """配置的 provider_id 命中时优先使用，即使还有其它 provider。"""
        preferred = FakeProvider("pref", text="来自指定模型")
        other = FakeProvider("other", text="来自其它模型")
        ctx = FakeContext(
            by_id={"pref": preferred},
            using=other,
            all_providers=[other, preferred],
        )
        summarizer = CveSummarizer(ctx, provider_id="pref")
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "来自指定模型")
        self.assertEqual(summarizer.last_outcome, "成功")
        self.assertEqual(summarizer.last_provider, "pref")
        self.assertEqual(preferred.call_count, 1)
        self.assertEqual(other.call_count, 0)

    def test_missing_provider_id_falls_back_to_using(self):
        """provider_id 不存在时回退到 get_using_provider_async，并记 warning。"""
        using = FakeProvider("using-model", text="来自当前模型")
        other = FakeProvider("all-0", text="来自列表")
        ctx = FakeContext(by_id={}, using=using, all_providers=[other])
        summarizer = CveSummarizer(ctx, provider_id="missing-id")
        with self.assertLogs("astrbot_plugin_cve_push", level="WARNING") as cm:
            text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "来自当前模型")
        self.assertEqual(summarizer.last_provider, "using-model")
        joined = "\n".join(cm.output)
        self.assertIn("missing-id", joined)
        self.assertTrue(
            any("不存在" in line or "回退" in line for line in cm.output),
            msg="应记录配置模型不存在的 warning",
        )

    def test_using_provider_fail_falls_back_to_all(self):
        """get_using_provider_async 抛异常或返回 None 时，回退到 get_all_providers()[0]。"""
        first = FakeProvider("all-first", text="来自全部列表首个")
        second = FakeProvider("all-second", text="来自全部列表第二个")

        ctx_err = FakeContext(
            by_id={},
            using=None,
            using_error=RuntimeError("using 不可用"),
            all_providers=[first, second],
        )
        summarizer = CveSummarizer(ctx_err, provider_id="")
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "来自全部列表首个")
        self.assertEqual(summarizer.last_provider, "all-first")

        ctx_none = FakeContext(by_id={}, using=None, all_providers=[first, second])
        summarizer2 = CveSummarizer(ctx_none, provider_id="")
        text2 = _run(summarizer2.summarize([make_item()]))
        self.assertEqual(text2, "来自全部列表首个")
        self.assertEqual(summarizer2.last_provider, "all-first")


class SummarizerFailoverTests(unittest.TestCase):
    def test_connection_error_tries_next_candidate(self):
        """第一个候选 ConnectionError 时自动尝试第二个并成功。"""
        bad = FakeProvider("bad", error=ConnectionError("连接失败"))
        good = FakeProvider("good", text="第二个成功")
        ctx = FakeContext(
            by_id={"bad": bad},
            using=good,
            all_providers=[bad, good],
        )
        summarizer = CveSummarizer(ctx, provider_id="bad")
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "第二个成功")
        self.assertEqual(summarizer.last_outcome, "成功")
        self.assertEqual(summarizer.last_provider, "good")
        self.assertEqual(bad.call_count, 1)
        self.assertEqual(good.call_count, 1)

    def test_all_candidates_fail_returns_empty(self):
        """全部候选失败时返回空串，last_outcome 为降级，last_error 含原因。"""
        a = FakeProvider("a", error=ConnectionError("网络断开"))
        b = FakeProvider("b", error=RuntimeError("服务不可用"))
        ctx = FakeContext(by_id={"a": a}, using=b, all_providers=[a, b])
        summarizer = CveSummarizer(ctx, provider_id="a")
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "")
        self.assertEqual(summarizer.last_outcome, "降级")
        self.assertIn("ConnectionError", summarizer.last_error)
        self.assertTrue(
            "网络断开" in summarizer.last_error or "服务不可用" in summarizer.last_error
        )

    def test_empty_completion_text_treated_as_failure(self):
        """completion_text 为空串时视为失败并回退下一个。"""
        empty = FakeProvider("empty", empty=True)
        good = FakeProvider("good", text="非空摘要")
        ctx = FakeContext(
            by_id={"empty": empty},
            using=good,
            all_providers=[empty, good],
        )
        summarizer = CveSummarizer(ctx, provider_id="empty")
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "非空摘要")
        self.assertEqual(summarizer.last_provider, "good")
        self.assertEqual(empty.call_count, 1)

    def test_timeout_degrades_with_timeout_message(self):
        """超时：构造器会将 timeout_seconds 钳制到至少 5；休眠超过该值应降级。"""
        # 实现侧 max(5, timeout_seconds)，传入 1 实际生效为 5；用 sleep 超过生效超时
        slow = FakeProvider("slow", sleep_seconds=7.0)
        ctx = FakeContext(by_id={"slow": slow}, using=None, all_providers=[slow])
        summarizer = CveSummarizer(ctx, provider_id="slow", timeout_seconds=1)
        self.assertGreaterEqual(summarizer.timeout_seconds, 5)
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "")
        self.assertEqual(summarizer.last_outcome, "降级")
        self.assertIn("超时", summarizer.last_error)


class SummarizerConfigAndFilterTests(unittest.TestCase):
    def test_configure_hot_updates_provider_id(self):
        """configure 热更新 provider_id 后，原失败模型换成可用模型即可成功。"""
        bad = FakeProvider("bad", error=ConnectionError("坏模型"))
        good = FakeProvider("good", text="热更新后成功")
        ctx = FakeContext(
            by_id={"bad": bad, "good": good},
            using=None,
            all_providers=[bad],
        )
        summarizer = CveSummarizer(ctx, provider_id="bad")
        text1 = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text1, "")
        self.assertEqual(summarizer.last_outcome, "降级")

        summarizer.configure(provider_id="good")
        text2 = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text2, "热更新后成功")
        self.assertEqual(summarizer.last_outcome, "成功")
        self.assertEqual(summarizer.last_provider, "good")

    def test_non_chat_provider_filtered(self):
        """没有 text_chat 的 provider（如 TTS）被过滤，不进入候选链。"""
        tts = FakeTTSProvider("tts-1")
        chat = FakeProvider("chat-1", text="仅对话模型")
        ctx = FakeContext(by_id={}, using=tts, all_providers=[tts, chat])
        summarizer = CveSummarizer(ctx, provider_id="")
        candidates = _run(summarizer._collect_candidates())
        ids = [pid for pid, _ in candidates]
        self.assertNotIn("tts-1", ids)
        self.assertIn("chat-1", ids)
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "仅对话模型")
        self.assertEqual(summarizer.last_provider, "chat-1")

    def test_empty_items_closes(self):
        """空 items 列表：返回空串且 last_outcome 为已关闭。"""
        chat = FakeProvider("chat", text="不应被调用")
        ctx = FakeContext(using=chat, all_providers=[chat])
        summarizer = CveSummarizer(ctx, provider_id="chat")
        text = _run(summarizer.summarize([]))
        self.assertEqual(text, "")
        self.assertEqual(summarizer.last_outcome, "已关闭")
        self.assertEqual(chat.call_count, 0)

    def test_collect_candidates_deduplicates_same_provider(self):
        """_collect_candidates 对同一 provider 去重。"""
        shared = FakeProvider("shared", text="去重后一次")
        ctx = FakeContext(
            by_id={"shared": shared},
            using=shared,
            all_providers=[shared, shared],
        )
        summarizer = CveSummarizer(ctx, provider_id="shared")
        candidates = _run(summarizer._collect_candidates())
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], "shared")
        text = _run(summarizer.summarize([make_item()]))
        self.assertEqual(text, "去重后一次")
        self.assertEqual(shared.call_count, 1)

    def test_filter_unpatched_items(self):
        patched = make_item(cve_id="CVE-2026-0001", is_patched=True)
        unpatched = make_item(cve_id="CVE-2026-0002", is_patched=False)
        unknown = make_item(cve_id="CVE-2026-0003", is_patched=None)

        filtered = filter_unpatched_items([patched, unpatched, unknown])
        self.assertEqual(filtered, [unpatched, unknown])
        self.assertEqual(
            CveSummarizer.filter_unpatched_items([patched, unpatched, unknown]),
            [unpatched, unknown],
        )

    def test_filter_items_by_summary(self):
        item1 = make_item(cve_id="CVE-2026-0001", is_patched=False)
        item2 = make_item(cve_id="CVE-2026-0002", is_patched=False)

        self.assertEqual(filter_items_by_summary([item1, item2], "[全部已修复]"), [])
        self.assertEqual(
            CveSummarizer.filter_items_by_summary([item1, item2], "[全部已修复]"),
            [],
        )

        summary_one = "[高危] CVE-2026-0001 某组件 - 存在远程代码执行风险 | 建议限制访问"
        kept = filter_items_by_summary([item1, item2], summary_one)
        self.assertEqual(kept, [item1])
        self.assertEqual(
            CveSummarizer.filter_items_by_summary([item1, item2], summary_one),
            [item1],
        )


class SummarizerSelfTestTests(unittest.TestCase):
    def test_self_test_success_contains_done(self):
        """self_test 成功时报告含 [完成]。"""
        good = FakeProvider("good", text="自检摘要内容")
        ctx = FakeContext(by_id={"good": good}, using=good, all_providers=[good])
        summarizer = CveSummarizer(ctx, provider_id="good")
        report = _run(summarizer.self_test())
        self.assertIn("[AI 摘要链路自检]", report)
        self.assertIn("[完成]", report)
        self.assertNotIn("结论: [失败]", report)

    def test_self_test_all_fail_contains_failure(self):
        """self_test 全部失败时报告含 [失败]。"""
        bad = FakeProvider("bad", error=ConnectionError("自检失败"))
        ctx = FakeContext(by_id={"bad": bad}, using=bad, all_providers=[bad])
        summarizer = CveSummarizer(ctx, provider_id="bad")
        report = _run(summarizer.self_test())
        self.assertIn("[AI 摘要链路自检]", report)
        self.assertIn("[失败]", report)


if __name__ == "__main__":
    unittest.main()
