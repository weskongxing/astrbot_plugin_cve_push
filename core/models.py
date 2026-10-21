"""统一漏洞数据模型。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SPACE_RE = re.compile(r"\s+")


@dataclass
class CveItem:
    """单条漏洞信息，跨信源统一结构。"""

    source: str = ""
    source_display: str = ""
    title: str = ""
    source_id: str = ""
    cve_id: str = ""
    severity: str = ""
    published: str = ""
    url: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------ 派生
    @property
    def dedup_key(self) -> str:
        """跨信源去重键：优先 CVE 编号，其次信源内编号，最后标题指纹。"""
        if self.cve_id:
            return "cve:" + self.cve_id.upper()
        if self.source_id:
            return "vid:" + self.source_id.upper()
        return "title:" + self.title_fingerprint

    @property
    def title_fingerprint(self) -> str:
        """标题归一化指纹（去空白、去标点、转小写后取摘要）。"""
        normalized = _SPACE_RE.sub("", self.title or "").lower()
        normalized = re.sub(r"[（）()【】\[\]，,。.：:、/\\\-—_]+", "", normalized)
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()[:16]

    @property
    def display_id(self) -> str:
        return self.cve_id or self.source_id or self.title_fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CveItem":
        allowed = {f for f in cls.__dataclass_fields__}
        payload = dict(data or {})
        # 兼容 v1.0.1 及更早版本写入去重库的旧字段名 vuln_id
        if "source_id" not in payload and "vuln_id" in payload:
            payload["source_id"] = payload.get("vuln_id")
        return cls(**{k: v for k, v in payload.items() if k in allowed})


def extract_cve(text: str) -> str:
    """从任意文本中提取第一个 CVE 编号。"""
    if not text:
        return ""
    match = _CVE_RE.search(text)
    return match.group(0).upper() if match else ""


SEVERITY_ORDER = ["极危", "超危", "严重", "高危", "中危", "低危", "未知"]


def severity_rank(severity: str) -> int:
    """风险等级排序权重，越小越高危。"""
    try:
        return SEVERITY_ORDER.index((severity or "").strip())
    except ValueError:
        return len(SEVERITY_ORDER)


def normalize_severity(raw: str) -> str:
    """归一化风险等级写法。"""
    value = (raw or "").strip()
    mapping = {
        "critical": "极危",
        "超危": "超危",
        "严重": "超危",
        "high": "高危",
        "medium": "中危",
        "moderate": "中危",
        "low": "低危",
    }
    if value in SEVERITY_ORDER:
        return value
    return mapping.get(value.lower(), value or "未知")
