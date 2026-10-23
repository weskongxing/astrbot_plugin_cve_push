"""DedupStore 持久化去重的离线单元测试。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_PARENT_DIR = os.path.dirname(_PLUGIN_DIR)
for _p in (_PARENT_DIR, _PLUGIN_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from astrbot_plugin_cve_push.core.dedup import DedupStore
from astrbot_plugin_cve_push.core.models import CveItem, merge_cross_source_items


def make_item(**overrides):
    base = dict(
        source="qianxin",
        source_display="奇安信",
        title="测试漏洞标题",
        source_id="QVD-2026-1",
        cve_id="",
        severity="高危",
        published="2026-10-21",
        url="https://example.com/detail/1",
        description="",
        tags=[],
    )
    base.update(overrides)
    return CveItem(**base)


class DedupStoreTests(unittest.TestCase):
    def test_filter_new_and_mark_pushed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DedupStore(os.path.join(tmp, "dedup.json"))
            a = make_item(cve_id="CVE-2026-1111")
            b = make_item(source_id="QVD-2026-2", title="另一个漏洞")

            self.assertEqual(store.filter_new([a, b]), [a, b])
            self.assertFalse(store.is_pushed(a))

            store.mark_pushed([a, b])
            self.assertTrue(store.is_pushed(a))
            self.assertTrue(store.is_pushed(b))
            self.assertEqual(store.filter_new([a, b]), [])

            # 相同 CVE 的不同条目应命中同一去重键
            dup = make_item(cve_id="cve-2026-1111", source_id="OTHER-1")
            self.assertTrue(store.is_pushed(dup))

    def test_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DedupStore(os.path.join(tmp, "dedup.json"))
            a = make_item(cve_id="CVE-2026-1111")
            store.mark_pushed([a])
            self.assertEqual(store.stats()["total"], 1)

            store.reset()
            self.assertEqual(store.stats()["total"], 0)
            self.assertEqual(store.filter_new([a]), [a])

    def test_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DedupStore(os.path.join(tmp, "dedup.json"), window_days=30)
            a = make_item(cve_id="CVE-2026-1111")
            b = make_item(source_id="QVD-2026-2", title="另一个漏洞")
            store.mark_pushed([a], now=1_700_000_000.0)
            store.mark_pushed([b], now=1_700_000_100.0)

            from datetime import datetime as _dt

            stats = store.stats()
            self.assertEqual(stats["total"], 2)
            self.assertEqual(stats["window_days"], 30)
            self.assertEqual(
                stats["oldest"],
                _dt.fromtimestamp(1_700_000_000.0).strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.assertEqual(
                stats["newest"],
                _dt.fromtimestamp(1_700_000_100.0).strftime("%Y-%m-%d %H:%M:%S"),
            )

    def test_window_expiry_pruned_in_mark_pushed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DedupStore(os.path.join(tmp, "dedup.json"), window_days=30)
            a = make_item(cve_id="CVE-2026-1111")
            b = make_item(source_id="QVD-2026-2", title="另一个漏洞")

            now1 = 1_700_000_000.0
            now2 = now1 + 31 * 86400.0  # 31 天后，超出 30 天窗口
            store.mark_pushed([a], now=now1)
            store.mark_pushed([b], now=now2)

            self.assertFalse(store.is_pushed(a))
            self.assertTrue(store.is_pushed(b))
            self.assertEqual(store.stats()["total"], 1)

    def test_window_expiry_pruned_in_load(self):
        import time as _time

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dedup.json")
            store = DedupStore(path, window_days=30)
            a = make_item(cve_id="CVE-2026-1111")
            old_now = _time.time() - 40 * 86400.0  # 40 天前
            store.mark_pushed([a], now=old_now)
            self.assertEqual(store.stats()["total"], 1)

            # 重新加载时按当前时间清理过期记录
            reloaded = DedupStore(path, window_days=30)
            self.assertEqual(reloaded.stats()["total"], 0)

    def test_corrupted_file_tolerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dedup.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("not valid json {{{")
            store = DedupStore(path)
            self.assertEqual(store.stats()["total"], 0)
            self.assertEqual(store.filter_new([make_item(cve_id="CVE-2026-1111")]).__len__(), 1)

    def test_abnormal_structure_tolerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dedup.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "records": "not-a-dict"}, f)
            store = DedupStore(path)
            self.assertEqual(store.stats()["total"], 0)

    def test_merge_cross_source_cnnvd_and_cve(self):
        q_item = make_item(
            source="qianxin",
            source_id="QVD-2026-8888",
            cve_id="CVE-2026-8888",
            cnnvd_id="CNNVD-2026-123456",
            is_patched=False,
        )
        c_item = make_item(
            source="cnnvd",
            source_id="CNNVD-2026-123456",
            cve_id="",
            cnnvd_id="CNNVD-2026-123456",
            is_patched=None,
        )
        merged = merge_cross_source_items([q_item, c_item])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].cve_id, "CVE-2026-8888")
        self.assertEqual(merged[0].display_id, "CVE-2026-8888")

        item_a = make_item(
            source="qianxin",
            source_id="QVD-2026-8888",
            cve_id="CVE-2026-8888",
            cnnvd_id="CNNVD-2026-123456",
            is_patched=False,
        )
        item_b = make_item(
            source="cnnvd",
            source_id="CNNVD-2026-123456",
            cve_id="CVE-2026-8888",
            cnnvd_id="CNNVD-2026-123456",
            is_patched=True,
        )
        merged_both = merge_cross_source_items([item_a, item_b])
        self.assertEqual(len(merged_both), 1)
        self.assertEqual(merged_both[0].cve_id, "CVE-2026-8888")
        self.assertEqual(merged_both[0].display_id, "CVE-2026-8888")
        self.assertTrue(merged_both[0].is_patched)

    def test_dedup_store_cross_cnnvd_and_cve(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DedupStore(os.path.join(tmp, "dedup.json"))
            pushed_item = make_item(
                source="qianxin",
                source_id="QVD-2026-9999",
                cve_id="CVE-2026-9999",
                cnnvd_id="CNNVD-2026-999999",
            )
            store.mark_pushed([pushed_item])

            cnnvd_only_item = make_item(
                source="cnnvd",
                source_id="CNNVD-2026-999999",
                cve_id="",
            )
            self.assertTrue(store.is_pushed(cnnvd_only_item))
            self.assertEqual(store.filter_new([cnnvd_only_item]), [])


if __name__ == "__main__":
    unittest.main()
