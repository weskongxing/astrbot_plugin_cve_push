"""core 包：漏洞推送插件的核心支撑模块。

包含：
- cron_util: 轻量级 5 段 cron 解析与下次触发时间推算
- dedup: 跨信源持久化去重
- summarizer: 调用 AstrBot 已配置对话模型生成中文摘要
- formatter: 纯文本消息排版
"""

from .models import (
    SEVERITY_ORDER,
    CveItem,
    extract_cve,
    normalize_severity,
    severity_rank,
)

__all__ = [
    "CveItem",
    "extract_cve",
    "severity_rank",
    "normalize_severity",
    "SEVERITY_ORDER",
]
