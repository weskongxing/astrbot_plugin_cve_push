"""消息格式化的离线单元测试（纯文本、无 emoji、长度截断）。"""

from __future__ import annotations

import os
import re
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_PARENT_DIR = os.path.dirname(_PLUGIN_DIR)
for _p in (_PARENT_DIR, _PLUGIN_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from astrbot_plugin_cve_push.core.formatter import (
    format_item_line,
    format_raw_message,
    format_status_message,
    format_summary_message,
)
from astrbot_plugin_cve_push.core.models import CveItem

_EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF"
    "\U00002600-\U000027BF"
    "\U0001F1E6-\U0001F1FF"
    "\U0000FE00-\U0000FE0F]"
)


def make_item(**overrides):
    base = dict(
        source="qianxin",
        source_display="奇安信",
        title="测试漏洞标题",
        source_id="QVD-2026-1",
        cve_id="CVE-2026-1111",
        severity="高危",
        published="2026-10-21",
        url="https://example.com/detail/1",
        description="",
        tags=[],
    )
    base.update(overrides)
    return CveItem(**base)


class FormatterTests(unittest.TestCase):
    def test_item_line_contains_all_fields(self):
        item = make_item()
        text = format_item_line(1, item)
        self.assertIn("1.", text)
        self.assertIn("[高危]", text)
        self.assertIn("测试漏洞标题", text)
        self.assertIn("（CVE-2026-1111）", text)
        self.assertIn("来源: 奇安信", text)
        self.assertIn("披露: 2026-10-21", text)
        self.assertIn("链接: https://example.com/detail/1", text)

    def test_item_line_without_cve_shows_vid(self):
        item = make_item(cve_id="")
        text = format_item_line(1, item)
        self.assertIn("（QVD-2026-1）", text)

    def test_raw_message_single_and_batch(self):
        single = format_raw_message([make_item()])
        self.assertIn("最新安全漏洞播报", single)
        self.assertIn("测试漏洞标题", single)

        batch = format_raw_message(
            [make_item(title="漏洞一"), make_item(title="漏洞二", source_id="QVD-2026-2")]
        )
        self.assertIn("漏洞一", batch)
        self.assertIn("漏洞二", batch)

    def test_raw_message_empty(self):
        text = format_raw_message([])
        self.assertIn("暂无漏洞数据", text)

    def test_raw_message_max_items(self):
        items = [make_item(title=f"漏洞{i}", source_id=f"QVD-2026-{i}") for i in range(1, 15)]
        text = format_raw_message(items, max_items=5)
        self.assertIn("漏洞1", text)
        self.assertIn("漏洞5", text)
        self.assertNotIn("漏洞6", text)
        self.assertIn("（共 14 条，仅展示前 5 条）", text)

    def test_raw_message_truncation(self):
        items = [
            make_item(
                title="超长漏洞标题" * 30,
                source_id=f"QVD-2026-{i}",
                cve_id="",
                url="https://example.com/detail/" + "a" * 150,
            )
            for i in range(1, 31)
        ]
        text = format_raw_message(items, max_items=50)
        self.assertGreater(len(text), 0)
        self.assertIn("（更多条目已省略）", text)
        self.assertLessEqual(len(text), 3500)

    def test_summary_message(self):
        items = [make_item(title="摘要漏洞")]
        text = format_summary_message("这是 AI 摘要内容。", items)
        self.assertIn("安全漏洞情报摘要", text)
        self.assertIn("这是 AI 摘要内容。", text)
        self.assertIn("涉及漏洞条目:", text)
        self.assertIn("摘要漏洞", text)

    def test_status_message(self):
        text = format_status_message({"cron": "0 9 * * *", "信源": ["qianxin", "aliyun"]})
        self.assertIn("插件运行状态", text)
        self.assertIn("cron: 0 9 * * *", text)
        self.assertIn("信源: qianxin, aliyun", text)

    def test_no_emoji_in_all_outputs(self):
        item = make_item()
        outputs = [
            format_item_line(1, item),
            format_raw_message([item]),
            format_summary_message("摘要", [item]),
            format_status_message({"key": "value"}),
        ]
        for text in outputs:
            self.assertIsNone(_EMOJI_RE.search(text), repr(text))


if __name__ == "__main__":
    unittest.main()
