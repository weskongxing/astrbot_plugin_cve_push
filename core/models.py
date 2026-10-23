"""统一漏洞数据模型。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

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
    cnnvd_id: str = ""
    is_patched: Optional[bool] = None

    # ------------------------------------------------------------------ 派生
    @property
    def dedup_key(self) -> str:
        """跨信源去重键：优先 CVE 编号，其次信源内编号，最后标题指纹。"""
        if self.cve_id:
            return "cve:" + self.cve_id.upper()
        if self.source_id:
            return "vid:" + self.source_id.upper()
        return "title:" + self.title_fingerprint

    def all_dedup_keys(self) -> List[str]:
        """收集该漏洞关联的所有唯一标识键（去重且保序）。"""
        keys: List[str] = []
        if self.cve_id:
            key = "cve:" + self.cve_id.strip().upper()
            if key not in keys:
                keys.append(key)
        if self.cnnvd_id:
            key = "vid:" + self.cnnvd_id.strip().upper()
            if key not in keys:
                keys.append(key)
        if self.source_id and not self.cve_id:
            key = "vid:" + self.source_id.strip().upper()
            if key not in keys:
                keys.append(key)
        if not keys:
            keys.append("title:" + self.title_fingerprint)
        return keys

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


def _extract_item_cnnvd(item: CveItem) -> str:
    """提取条目关联的 CNNVD 编号（大写）。"""
    if item.cnnvd_id and item.cnnvd_id.strip():
        return item.cnnvd_id.strip().upper()
    sid = (item.source_id or "").strip().upper()
    if sid.startswith("CNNVD-"):
        return sid
    return ""


def merge_cross_source_items(items: List[CveItem]) -> List[CveItem]:
    """跨信源或同信源同漏洞智能归并，统一合并并保留 CVE 编号。"""
    if not items:
        return []

    cloned = [CveItem.from_dict(item.to_dict()) for item in items]

    # 1) 建立 CNNVD -> CVE 映射表
    cnnvd_to_cve: Dict[str, str] = {}
    for item in cloned:
        cve = (item.cve_id or "").strip().upper()
        cnnvd = _extract_item_cnnvd(item)
        if cnnvd and not item.cnnvd_id:
            item.cnnvd_id = cnnvd
        if cve and cnnvd:
            item.cve_id = cve
            cnnvd_to_cve.setdefault(cnnvd, cve)

    # 2) 为仅有 CNNVD 编号但命中映射表的条目回填 CVE 编号
    for item in cloned:
        cnnvd = _extract_item_cnnvd(item)
        if cnnvd and not item.cnnvd_id:
            item.cnnvd_id = cnnvd
        if not item.cve_id and cnnvd and cnnvd in cnnvd_to_cve:
            item.cve_id = cnnvd_to_cve[cnnvd]

    # 3) 按主键归并
    grouped: Dict[str, CveItem] = {}
    for item in cloned:
        cve = (item.cve_id or "").strip().upper()
        cnnvd = (item.cnnvd_id or "").strip().upper()
        sid = (item.source_id or "").strip().upper()
        if cve:
            item.cve_id = cve
            group_key = "cve:" + cve
        elif cnnvd:
            item.cnnvd_id = cnnvd
            group_key = "vid:" + cnnvd
        elif sid:
            group_key = "vid:" + sid
        else:
            group_key = "title:" + item.title_fingerprint

        if group_key not in grouped:
            grouped[group_key] = item
            continue

        primary = grouped[group_key]

        # 合并 cve_id 与 cnnvd_id
        if not primary.cve_id and cve:
            primary.cve_id = cve
        if not primary.cnnvd_id and cnnvd:
            primary.cnnvd_id = cnnvd
        if not primary.source_id and item.source_id:
            primary.source_id = item.source_id

        # 合并 description（取较长者）
        if len(item.description or "") > len(primary.description or ""):
            primary.description = item.description

        # 合并 tags（去重保序）
        merged_tags = list(primary.tags or [])
        for t in item.tags or []:
            if t and t not in merged_tags:
                merged_tags.append(t)
        primary.tags = merged_tags

        # 合并 severity（若原为未知或空，或新条目风险等级更高）
        if item.severity and item.severity != "未知":
            if (
                not primary.severity
                or primary.severity == "未知"
                or severity_rank(item.severity) < severity_rank(primary.severity)
            ):
                primary.severity = item.severity

        # 合并 published 与 url
        if not primary.published and item.published:
            primary.published = item.published
        if not primary.url and item.url:
            primary.url = item.url

        # 合并 is_patched：任一为 True 则为 True，否则任一为 False 则为 False，否则 None
        if primary.is_patched is True or item.is_patched is True:
            primary.is_patched = True
        elif primary.is_patched is False or item.is_patched is False:
            primary.is_patched = False
        else:
            primary.is_patched = None

    return list(grouped.values())

