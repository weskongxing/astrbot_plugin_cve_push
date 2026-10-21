"""CNNVD 国家信息安全漏洞库信源适配器（游客签名公开接口）。

合规说明：使用站点公开的游客签名通道读取公开数据，非登录绕过；
全部请求统一走 HttpFetcher 限速与退避重试，每次请求生成全新的 timestamp/nonce。
"""

from __future__ import annotations

import logging
import secrets
import string
import time
from typing import Any, Dict, List

from ..core.models import CveItem, extract_cve, normalize_severity
from .base import BaseSource, FetchError

logger = logging.getLogger("astrbot_plugin_cve_push")

APP_ID = "6i8417579268034679HXvp0Kb6r1C2A9"
ORIGIN = "https://www.cnnvd.org.cn"
BASE = "/cnnvdweb"
SIGN_PATH = BASE + "/tourist/sign"
LIST_PATH = BASE + "/homePage/hotVulNewList"
DETAIL_URL_TEMPLATE = "https://www.cnnvd.org.cn/frontend/detail?vulId={vul_id}"


class CnnvdSource(BaseSource):
    """CNNVD 信源。"""

    name = "cnnvd"
    display_name = "CNNVD"

    @staticmethod
    def _make_nonce() -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(32))

    @staticmethod
    def _timestamp() -> str:
        return str(int(time.time() * 1000))

    @staticmethod
    def _base_headers(timestamp: str, nonce: str) -> Dict[str, str]:
        return {
            "X-Appid": APP_ID,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "Content-Type": "application/json;charset=utf-8",
            "Origin": ORIGIN,
            "Referer": ORIGIN + "/",
        }

    async def _get_signature(self) -> tuple[str, str, str]:
        """获取游客签名。

        返回 (signature, timestamp, nonce)。
        重要：签名与实际业务请求必须使用同一组 timestamp / nonce，
        否则服务端会判定为无效随机数并拒绝请求。
        """
        timestamp = self._timestamp()
        nonce = self._make_nonce()
        sign_str = "POST" + LIST_PATH + timestamp + nonce
        headers = self._base_headers(timestamp, nonce)
        resp = await self.fetcher.request(
            "POST",
            ORIGIN + SIGN_PATH,
            headers=headers,
            json_body={"signStr": sign_str},
            expect_json=True,
        )
        if not isinstance(resp, dict) or resp.get("code") != 200:
            raise FetchError(f"CNNVD 游客签名接口返回异常: {resp!r}")
        signature = str(resp.get("data") or "").strip()
        if not signature:
            raise FetchError("CNNVD 游客签名接口返回空签名")
        return signature, timestamp, nonce

    async def fetch_latest(self, limit: int = 10) -> List[CveItem]:
        try:
            signature, timestamp, nonce = await self._get_signature()
            headers = self._base_headers(timestamp, nonce)
            headers["X-Sign"] = signature
            resp = await self.fetcher.request(
                "POST",
                ORIGIN + LIST_PATH,
                headers=headers,
                json_body={},
                expect_json=True,
            )
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] CNNVD 请求异常: %s", exc)
            raise FetchError(f"CNNVD 请求异常: {exc}") from exc

        try:
            if not isinstance(resp, dict) or resp.get("code") != 200:
                raise FetchError(f"CNNVD 漏洞列表接口返回异常: {resp!r}")
            data = resp.get("data") or []
            if not isinstance(data, list):
                raise FetchError("CNNVD 漏洞列表结构异常，data 不是数组")
            items = [self._to_item(record) for record in data if isinstance(record, dict)]
            return items[: max(0, int(limit))]
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] CNNVD 数据解析异常: %s", exc)
            raise FetchError(f"CNNVD 数据解析异常: {exc}") from exc

    @staticmethod
    def _to_item(record: Dict[str, Any]) -> CveItem:
        vul_name = str(record.get("vulName") or "")
        return CveItem(
            source=CnnvdSource.name,
            source_display=CnnvdSource.display_name,
            title=vul_name,
            source_id=str(record.get("cnnvdCode") or ""),
            cve_id=extract_cve(vul_name),
            severity=normalize_severity(str(record.get("hazardLevel") or "")),
            published=str(record.get("publishTime") or ""),
            url=DETAIL_URL_TEMPLATE.format(vul_id=str(record.get("vulId") or "")),
            description="",
            tags=[],
        )
