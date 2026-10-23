"""奇安信威胁情报中心「今日新发漏洞」信源适配器。

合规说明：仅使用公开 POST 读取公开数据，所有请求统一走 HttpFetcher 限速与退避重试。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..core.models import CveItem, extract_cve, normalize_severity
from .base import BaseSource, FetchError

logger = logging.getLogger("astrbot_plugin_cve_push")

API_URL = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"
DETAIL_URL_BASE = "https://ti.qianxin.com/vulnerability/detail/"

_DEFAULT_HEADERS = {
    "Referer": "https://ti.qianxin.com/",
    "Origin": "https://ti.qianxin.com",
    "Content-Type": "application/json",
}

_DESCRIPTION_LIMIT = 300


def _truncate(text: str | None, limit: int = _DESCRIPTION_LIMIT) -> str:
    value = (text or "").strip()
    return value if len(value) <= limit else value[:limit]


def _extract_tags(tag: Any) -> List[str]:
    """tag 可能是 dict 列表或字符串列表，统一取 name 文本。"""
    tags: List[str] = []
    for item in tag or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name:
                tags.append(name)
        elif isinstance(item, str):
            name = item.strip()
            if name:
                tags.append(name)
    return tags


class QianxinSource(BaseSource):
    """奇安信威胁情报中心信源。"""

    name = "qianxin"
    display_name = "奇安信"

    async def fetch_latest(self, limit: int = 10) -> List[CveItem]:
        try:
            resp = await self.fetcher.request(
                "POST",
                API_URL,
                headers=_DEFAULT_HEADERS,
                json_body=None,
                expect_json=True,
            )
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 奇安信请求异常: %s", exc)
            raise FetchError(f"奇安信请求异常: {exc}") from exc

        try:
            if not isinstance(resp, dict) or resp.get("status") != 10000:
                raise FetchError(f"奇安信接口返回异常状态: {resp!r}")
            data = resp.get("data") or {}
            key_vuln_add = data.get("key_vuln_add") or []
            poc_exp_add = data.get("poc_exp_add") or []
            vuln_add = data.get("vuln_add") or []

            # 合并去重：优先级 key_vuln_add -> poc_exp_add -> vuln_add。
            merged: Dict[str, Dict[str, Any]] = {}
            for group in (key_vuln_add, poc_exp_add, vuln_add):
                for record in group:
                    if isinstance(record, dict):
                        key = str(record.get("id") or "")
                        if key and key not in merged:
                            merged[key] = record

            items = [self._to_item(record) for record in merged.values()]
            items.sort(key=lambda item: item.published or "", reverse=True)
            return items[: max(0, int(limit))]
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 奇安信数据解析异常: %s", exc)
            raise FetchError(f"奇安信数据解析异常: {exc}") from exc

    @staticmethod
    def _to_item(record: Dict[str, Any]) -> CveItem:
        vuln_name = str(record.get("vuln_name") or "")
        cve_code = str(record.get("cve_code") or "")
        published_raw = str(record.get("publish_time") or "")
        cnnvd_id = str(record.get("cnnvd_id") or "").strip().upper()
        patch_flag = record.get("patch_flag")
        is_patched: Optional[bool]
        if patch_flag == 1 and patch_flag is not True or patch_flag is True:
            is_patched = True
        elif patch_flag == 0 and patch_flag is not False or patch_flag is False:
            is_patched = False
        else:
            is_patched = None
        return CveItem(
            source=QianxinSource.name,
            source_display=QianxinSource.display_name,
            title=vuln_name,
            source_id=str(record.get("qvd_code") or ""),
            cve_id=extract_cve(cve_code or vuln_name),
            severity=normalize_severity(str(record.get("rating_level") or "")),
            published=published_raw[:10],
            url=DETAIL_URL_BASE + str(record.get("id") or ""),
            description=_truncate(str(record.get("description") or "")),
            tags=_extract_tags(record.get("tag")),
            cnnvd_id=cnnvd_id,
            is_patched=is_patched,
        )
