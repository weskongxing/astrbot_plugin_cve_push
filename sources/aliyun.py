"""阿里云安全 AVD 漏洞库信源适配器（首页服务端渲染表格解析）。

合规说明：仅使用公开 GET 读取公开数据，全部请求统一走 HttpFetcher 限速与退避重试。
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from bs4 import BeautifulSoup

from ..core.models import CveItem, extract_cve, normalize_severity
from .base import BaseSource, FetchError

logger = logging.getLogger("astrbot_plugin_cve_push")

HOMEPAGE_URL = "https://avd.aliyun.com/"
SITE_BASE = "https://avd.aliyun.com"

_AVD_RE = re.compile(r"AVD-\d{4}-\d+")
_DETAIL_HREF_RE = re.compile(r"/detail\?id=AVD-")

_UNDEFINED = "未定义"


class AliyunSource(BaseSource):
    """阿里云安全 AVD 信源。"""

    name = "aliyun"
    display_name = "阿里云安全"

    async def fetch_latest(self, limit: int = 10) -> List[CveItem]:
        try:
            html = await self.fetcher.request(
                "GET", HOMEPAGE_URL, expect_json=False
            )
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 阿里云请求异常: %s", exc)
            raise FetchError(f"阿里云请求异常: {exc}") from exc

        try:
            items = self._parse(html or "")
            if not items:
                raise FetchError("阿里云 AVD 首页结构变化，未解析到漏洞条目")
            return items[: max(0, int(limit))]
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 阿里云数据解析异常: %s", exc)
            raise FetchError(f"阿里云数据解析异常: {exc}") from exc

    @staticmethod
    def _parse(html: str) -> List[CveItem]:
        soup = BeautifulSoup(html or "", "html.parser")
        items: List[CveItem] = []
        for tr in soup.find_all("tr"):
            link = tr.find("a", href=_DETAIL_HREF_RE)
            if link is None:
                continue
            cells = [td for td in tr.find_all("td")]
            if len(cells) < 5:
                continue

            href = str(link.get("href") or "")
            avd_match = _AVD_RE.search(href)
            source_id = avd_match.group(0) if avd_match else ""
            if not source_id:
                cell_text = cells[0].get_text(" ", strip=True)
                m = _AVD_RE.search(cell_text)
                source_id = m.group(0) if m else cell_text

            title = cells[1].get_text(" ", strip=True)
            cve_type = cells[2].get_text(" ", strip=True)
            published = cells[3].get_text(" ", strip=True)
            status = cells[4].get_text(" ", strip=True)
            is_patched: Optional[bool] = None
            btn_texts = [status]
            for btn in cells[4].find_all("button"):
                btn_texts.append(btn.get_text(" ", strip=True))
                btn_texts.append(str(btn.get("title") or ""))
            joined_status = " ".join(btn_texts)
            if any(k in joined_status for k in ("补丁发布", "已修复", "官方补丁")):
                is_patched = True
            elif any(k in joined_status for k in ("暂无补丁", "未修复")):
                is_patched = False

            cve_id = extract_cve(title)
            if not cve_id:
                for btn in cells[4].find_all("button"):
                    cve_id = extract_cve(str(btn.get("title") or ""))
                    if cve_id:
                        break
            tags: List[str] = []
            if cve_type and cve_type != _UNDEFINED:
                tags = [cve_type]

            if status == _UNDEFINED or status in ("CVE PoC", "CVE", "PoC"):
                severity = normalize_severity("")
            else:
                severity = normalize_severity(status)

            items.append(
                CveItem(
                    source=AliyunSource.name,
                    source_display=AliyunSource.display_name,
                    title=title,
                    source_id=source_id,
                    cve_id=cve_id,
                    severity=severity,
                    published=published,
                    url=SITE_BASE + href,
                    description="",
                    tags=tags,
                    is_patched=is_patched,
                )
            )
        return items
