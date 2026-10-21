"""阿里云安全 AVD 漏洞库信源适配器（首页服务端渲染表格解析）。

合规说明：仅使用公开 GET 读取公开数据，全部请求统一走 HttpFetcher 限速与退避重试。
"""

from __future__ import annotations

import logging
import re
from typing import List

from bs4 import BeautifulSoup

from ..core.models import VulnItem, extract_cve, normalize_severity
from .base import BaseSource, FetchError

logger = logging.getLogger("astrbot_plugin_vuln_push")

HOMEPAGE_URL = "https://avd.aliyun.com/"
SITE_BASE = "https://avd.aliyun.com"

_AVD_RE = re.compile(r"AVD-\d{4}-\d+")
_DETAIL_HREF_RE = re.compile(r"/detail\?id=AVD-")

_UNDEFINED = "未定义"


class AliyunSource(BaseSource):
    """阿里云安全 AVD 信源。"""

    name = "aliyun"
    display_name = "阿里云安全"

    async def fetch_latest(self, limit: int = 10) -> List[VulnItem]:
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
    def _parse(html: str) -> List[VulnItem]:
        soup = BeautifulSoup(html or "", "html.parser")
        items: List[VulnItem] = []
        for tr in soup.find_all("tr"):
            link = tr.find("a", href=_DETAIL_HREF_RE)
            if link is None:
                continue
            cells = [td for td in tr.find_all("td")]
            if len(cells) < 5:
                continue

            href = str(link.get("href") or "")
            avd_match = _AVD_RE.search(href)
            vuln_id = avd_match.group(0) if avd_match else ""
            if not vuln_id:
                cell_text = cells[0].get_text(" ", strip=True)
                m = _AVD_RE.search(cell_text)
                vuln_id = m.group(0) if m else cell_text

            title = cells[1].get_text(" ", strip=True)
            vuln_type = cells[2].get_text(" ", strip=True)
            published = cells[3].get_text(" ", strip=True)
            status = cells[4].get_text(" ", strip=True)

            cve_id = extract_cve(title)
            tags: List[str] = []
            if vuln_type and vuln_type != _UNDEFINED:
                tags = [vuln_type]

            if status == _UNDEFINED:
                severity = normalize_severity("")
            else:
                severity = normalize_severity(status)

            items.append(
                VulnItem(
                    source=AliyunSource.name,
                    source_display=AliyunSource.display_name,
                    title=title,
                    vuln_id=vuln_id,
                    cve_id=cve_id,
                    severity=severity,
                    published=published,
                    url=SITE_BASE + href,
                    description="",
                    tags=tags,
                )
            )
        return items
