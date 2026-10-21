"""奇安信 / 阿里云 / CNNVD 三个信源的离线单元测试。

全部使用假 HttpFetcher，绝不发起真实网络请求。
"""

from __future__ import annotations

import json
import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_PARENT_DIR = os.path.dirname(_PLUGIN_DIR)
for _p in (_PARENT_DIR, _PLUGIN_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from astrbot_plugin_cve_push.sources.aliyun import AliyunSource
from astrbot_plugin_cve_push.sources.base import FetchError
from astrbot_plugin_cve_push.sources.cnnvd import CnnvdSource, LIST_PATH
from astrbot_plugin_cve_push.sources.qianxin import QianxinSource

FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures")


def _load_fixture(name: str):
    with open(os.path.join(FIXTURES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


class FakeFetcher:
    """记录调用参数并返回固定响应的假 HttpFetcher。"""

    def __init__(self, responses_by_url):
        self.responses_by_url = responses_by_url
        self.calls = []

    async def request(self, method, url, *, headers=None, json_body=None,
                      params=None, expect_json=True):
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers or {}),
            "json_body": json_body,
            "params": params,
            "expect_json": expect_json,
        })
        handler = self.responses_by_url.get(url)
        if callable(handler):
            return handler(self.calls[-1])
        if handler is None:
            raise KeyError(f"no fake response registered for url: {url}")
        return handler


class QianxinSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_mapping_and_dedup_merge(self):
        fixture = json.loads(_load_fixture("qianxin_oneday.json"))
        fetcher = FakeFetcher({
            "https://ti.qianxin.com/alpha-api/v2/cve/one-day": fixture,
        })
        source = QianxinSource({}, fetcher)
        items = await source.fetch_latest(limit=10)

        # key_vuln_add 与 poc_exp_add 按 id 去重合并，共 3 条
        self.assertEqual(len(items), 3)

        by_source_id = {item.source_id: item for item in items}

        # key_vuln_add 优先：id=1002 应取 key_vuln_add 的标题
        self.assertEqual(
            by_source_id["QVD-2026-10002"].title,
            "含 CVE-2026-2222 的权限提升漏洞",
        )
        # cve_code 为空时从 vuln_name 提取 CVE
        self.assertEqual(by_source_id["QVD-2026-10002"].cve_id, "CVE-2026-2222")
        # rating_level "critical" 归一化为 "极危"
        self.assertEqual(by_source_id["QVD-2026-10002"].severity, "极危")

        # 字段映射逐项校验
        first = by_source_id["QVD-2026-10001"]
        self.assertEqual(first.cve_id, "CVE-2026-1111")
        self.assertEqual(first.severity, "高危")
        self.assertEqual(first.published, "2026-10-21")
        self.assertEqual(first.url, "https://ti.qianxin.com/cveerability/detail/1001")
        self.assertEqual(first.tags, ["RCE", "在野利用"])
        self.assertEqual(first.source, "qianxin")
        self.assertEqual(first.source_display, "奇安信")

        # high 归一化为 高危；poc_exp_add 中的新 id 正常合并
        poc_item = by_source_id["QVD-2026-10003"]
        self.assertEqual(poc_item.severity, "高危")
        self.assertEqual(poc_item.cve_id, "CVE-2026-3333")
        self.assertEqual(poc_item.tags, ["反序列化"])

        # 按 published 倒序：1003(10-22) -> 1001(10-21) -> 1002(10-20)
        self.assertEqual(
            [item.source_id for item in items],
            ["QVD-2026-10003", "QVD-2026-10001", "QVD-2026-10002"],
        )

    async def test_limit_truncates(self):
        fixture = json.loads(_load_fixture("qianxin_oneday.json"))
        fetcher = FakeFetcher({
            "https://ti.qianxin.com/alpha-api/v2/cve/one-day": fixture,
        })
        source = QianxinSource({}, fetcher)
        items = await source.fetch_latest(limit=2)
        self.assertEqual(len(items), 2)

    async def test_bad_status_raises_fetch_error(self):
        fetcher = FakeFetcher({
            "https://ti.qianxin.com/alpha-api/v2/cve/one-day": {"status": 99999},
        })
        source = QianxinSource({}, fetcher)
        with self.assertRaises(FetchError):
            await source.fetch_latest()


class AliyunSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_parse_avd_table(self):
        html = _load_fixture("aliyun_avd_home.html")
        fetcher = FakeFetcher({"https://avd.aliyun.com/": html})
        source = AliyunSource({}, fetcher)
        items = await source.fetch_latest(limit=10)

        # 干扰行（不含 AVD 链接）应被跳过
        self.assertEqual(len(items), 3)

        first = items[0]
        self.assertEqual(first.source_id, "AVD-2026-1001")
        self.assertEqual(first.cve_id, "CVE-2026-3333")
        self.assertEqual(first.title, "某组件远程代码执行漏洞 CVE-2026-3333")
        self.assertEqual(first.published, "2026-10-20")
        self.assertEqual(first.severity, "高危")
        self.assertEqual(first.tags, ["CWE-94"])
        self.assertEqual(first.url, "https://avd.aliyun.com/detail?id=AVD-2026-1001")

        # 状态列为「未定义」时应归一化为「未知」，类型「未定义」时 tags 为空
        second = items[1]
        self.assertEqual(second.source_id, "AVD-2026-1002")
        self.assertEqual(second.severity, "未知")
        self.assertEqual(second.tags, [])

        third = items[2]
        self.assertEqual(third.source_id, "AVD-2026-1003")
        self.assertEqual(third.cve_id, "CVE-2026-4444")
        self.assertEqual(third.tags, ["CWE-89"])

    async def test_empty_table_raises_fetch_error(self):
        fetcher = FakeFetcher({
            "https://avd.aliyun.com/": "<html><body><table></table></body></html>",
        })
        source = AliyunSource({}, fetcher)
        with self.assertRaises(FetchError):
            await source.fetch_latest()


class CnnvdSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_step_same_timestamp_nonce(self):
        sign_url = "https://www.cnnvd.org.cn/cnnvdweb/tourist/sign"
        list_url = "https://www.cnnvd.org.cn/cnnvdweb/homePage/hotVulNewList"
        signature = "a1b2c3d4e5f6a7b8c9d0"
        list_resp = json.loads(_load_fixture("cnnvd_hotvul.json"))

        fetcher = FakeFetcher({
            sign_url: {"code": 200, "data": signature},
            list_url: list_resp,
        })
        source = CnnvdSource({}, fetcher)
        items = await source.fetch_latest(limit=10)

        self.assertEqual(len(fetcher.calls), 2)
        sign_call = fetcher.calls[0]
        list_call = fetcher.calls[1]
        self.assertEqual(sign_call["url"], sign_url)
        self.assertEqual(list_call["url"], list_url)

        ts = sign_call["headers"]["X-Timestamp"]
        nonce = sign_call["headers"]["X-Nonce"]

        # 签名接口与业务请求必须使用同一组 X-Timestamp / X-Nonce
        self.assertEqual(list_call["headers"]["X-Timestamp"], ts)
        self.assertEqual(list_call["headers"]["X-Nonce"], nonce)

        # signStr 中的 ts/nonce 必须与业务请求头一致
        sign_str = sign_call["json_body"]["signStr"]
        expected_sign_str = "POST" + LIST_PATH + ts + nonce
        self.assertEqual(sign_str, expected_sign_str)

        # 业务请求带 X-Sign 签名头，值为签名接口返回的 data
        self.assertEqual(list_call["headers"]["X-Sign"], signature)

        # 字段映射
        self.assertEqual(len(items), 2)
        first = items[0]
        self.assertEqual(first.source_id, "CNNVD-202610-1001")
        self.assertEqual(first.cve_id, "CVE-2026-5555")
        self.assertEqual(first.severity, "超危")
        self.assertEqual(first.published, "2026-10-21")
        self.assertEqual(
            first.url,
            "https://www.cnnvd.org.cn/frontend/detail?vulId=88001",
        )

    async def test_sign_bad_code_raises_fetch_error(self):
        sign_url = "https://www.cnnvd.org.cn/cnnvdweb/tourist/sign"
        fetcher = FakeFetcher({sign_url: {"code": 500, "data": ""}})
        source = CnnvdSource({}, fetcher)
        with self.assertRaises(FetchError):
            await source.fetch_latest()

    async def test_list_bad_code_raises_fetch_error(self):
        sign_url = "https://www.cnnvd.org.cn/cnnvdweb/tourist/sign"
        list_url = "https://www.cnnvd.org.cn/cnnvdweb/homePage/hotVulNewList"
        fetcher = FakeFetcher({
            sign_url: {"code": 200, "data": "a1b2c3d4e5f6a7b8c9d0"},
            list_url: {"code": 500, "data": []},
        })
        source = CnnvdSource({}, fetcher)
        with self.assertRaises(FetchError):
            await source.fetch_latest()


if __name__ == "__main__":
    unittest.main()
