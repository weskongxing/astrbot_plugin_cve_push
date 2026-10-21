"""信源注册与构建入口。"""

from __future__ import annotations

import logging
from typing import Dict, List, Type

from .aliyun import AliyunSource
from .base import BaseSource, HttpFetcher
from .cnnvd import CnnvdSource
from .qianxin import QianxinSource

logger = logging.getLogger("astrbot_plugin_vuln_push")

SOURCE_REGISTRY: Dict[str, Type[BaseSource]] = {
    "qianxin": QianxinSource,
    "aliyun": AliyunSource,
    "cnnvd": CnnvdSource,
}


def build_sources(
    enabled_sources: List[str], config: dict, fetcher: HttpFetcher
) -> List[BaseSource]:
    """按 enabled_sources 顺序构建信源实例；未知名字忽略。"""
    sources: List[BaseSource] = []
    for name in enabled_sources or []:
        cls = SOURCE_REGISTRY.get(name)
        if cls is None:
            logger.warning("[漏洞推送] 未知信源名称已忽略: %s", name)
            continue
        try:
            sources.append(cls(config, fetcher))
        except Exception as exc:  # noqa: BLE001
            logger.exception("[漏洞推送] 构建信源 %s 失败: %s", name, exc)
    return sources
