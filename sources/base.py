"""信源抓取基类与合规 HTTP 客户端。

合规底线（全部为硬约束，禁止放宽）：
1. 使用标准浏览器 User-Agent，不做任何伪装绕过；
2. 同一域名两次请求之间强制间隔 >= min_interval（默认 1.2 秒），禁止并发轰炸；
3. 仅使用公开 GET/POST 读取公开数据，失败采用指数退避重试，最多 2 次；
4. 单次任务对同一域名的请求次数受 max_requests_per_host 限制；
5. 不携带任何凭据 Cookie，不做登录/验证码绕过、参数爆破、目录扫描等行为。
"""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from ..core.models import VulnItem

logger = logging.getLogger("astrbot_plugin_vuln_push")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)


class FetchError(Exception):
    """信源抓取失败（网络、HTTP 状态或响应结构异常）。"""


class HttpFetcher:
    """带限速与退避重试的合规 HTTP 客户端。"""

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        min_interval: float = 1.2,
        max_retries: int = 2,
        max_requests_per_host: int = 5,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.timeout = max(3.0, float(timeout))
        self.min_interval = max(0.0, float(min_interval))
        self.max_retries = max(0, int(max_retries))
        self.max_requests_per_host = max(1, int(max_requests_per_host))
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self._last_request_at: Dict[str, float] = {}
        self._request_count: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    # ---------------------------------------------------------------- 内部
    async def _throttle(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            last = self._last_request_at.get(host, 0.0)
            wait = self.min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at[host] = time.monotonic()

    def _check_budget(self, host: str) -> None:
        used = self._request_count.get(host, 0)
        if used >= self.max_requests_per_host:
            raise FetchError(
                f"域名 {host} 本次任务请求次数已达上限 {self.max_requests_per_host}，"
                "为避免对目标站点造成压力已主动停止"
            )

    def _count(self, host: str) -> None:
        self._request_count[host] = self._request_count.get(host, 0) + 1

    def reset_budget(self) -> None:
        self._request_count.clear()

    # ---------------------------------------------------------------- 对外
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_json: bool = True,
    ) -> Any:
        """执行一次合规请求，返回 JSON 对象或响应文本。"""
        host = urlparse(url).netloc
        merged_headers = {
            "User-Agent": self.user_agent,
            "Accept-Language": "zh-CN,zh;q=0.9",
        }
        if headers:
            merged_headers.update(headers)

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            self._check_budget(host)
            await self._throttle(host)
            self._count(host)
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, follow_redirects=True
                ) as client:
                    response = await client.request(
                        method.upper(),
                        url,
                        headers=merged_headers,
                        json=json_body,
                        params=params,
                    )
                if response.status_code >= 400:
                    raise FetchError(
                        f"HTTP {response.status_code} 请求 {url} 失败"
                    )
                if expect_json:
                    try:
                        return response.json()
                    except ValueError as exc:
                        raise FetchError(f"响应不是合法 JSON: {url}") from exc
                return response.text
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt >= self.max_retries:
                    break
                backoff = 2 ** attempt
                logger.warning(
                    "[漏洞推送] 请求 %s 失败(%s)，%s 秒后重试（第 %s 次）",
                    url,
                    exc,
                    backoff,
                    attempt + 1,
                )
                await asyncio.sleep(backoff)
        raise FetchError(f"请求 {url} 最终失败: {last_error}")


class BaseSource(abc.ABC):
    """信源抽象基类。新增信源只需继承并实现 fetch_latest。"""

    name: str = "base"
    display_name: str = "未知信源"

    def __init__(self, config: Dict[str, Any], fetcher: HttpFetcher) -> None:
        self.config = config or {}
        self.fetcher = fetcher

    @abc.abstractmethod
    async def fetch_latest(self, limit: int = 10) -> List[VulnItem]:
        """抓取最新漏洞列表，失败时抛出 FetchError。"""
        raise NotImplementedError
