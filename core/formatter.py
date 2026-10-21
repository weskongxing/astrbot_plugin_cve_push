"""纯文本消息排版，无 emoji、无 Markdown 表格。"""

from __future__ import annotations

from typing import List

from .models import VulnItem

_LENGTH_LIMIT = 3500
_TRUNCATION_TAIL = "\n...（更多条目已省略）"
_SEVERITY_FALLBACK = "未知"


def _severity(item: VulnItem) -> str:
    value = (item.severity or "").strip()
    return value or _SEVERITY_FALLBACK


def _title_text(item: VulnItem) -> str:
    return (item.title or "").strip() or "未命名漏洞"


def _id_part(item: VulnItem) -> str:
    display_id = item.display_id
    return f"（{display_id}）" if display_id else ""


def format_item_line(index: int, item: VulnItem) -> str:
    """格式化单条漏洞为多行纯文本。"""
    lines: List[str] = [f"{index}. [{_severity(item)}] {_title_text(item)}{_id_part(item)}"]
    meta: List[str] = []
    if item.source_display:
        meta.append(f"来源: {item.source_display}")
    if item.published:
        meta.append(f"披露: {item.published}")
    if meta:
        lines.append("   " + " | ".join(meta))
    if item.url:
        lines.append(f"   链接: {item.url}")
    return "\n".join(lines)


def _apply_length_limit(text: str) -> str:
    if len(text) <= _LENGTH_LIMIT:
        return text
    return text[: _LENGTH_LIMIT - len(_TRUNCATION_TAIL)] + _TRUNCATION_TAIL


def format_raw_message(
    items: List[VulnItem],
    title: str = "最新安全漏洞播报",
    max_items: int = 10,
) -> str:
    """构建原始漏洞列表消息，最多展示 max_items 条，总长超限自动截断。"""
    max_items = max(0, int(max_items))
    selected = items[:max_items]
    lines: List[str] = [title]
    if not selected:
        return "\n".join([title, "", "暂无漏洞数据"])

    for index, item in enumerate(selected, 1):
        lines.append("")
        lines.append(format_item_line(index, item))

    if len(items) > max_items:
        lines.append("")
        lines.append(f"...（共 {len(items)} 条，仅展示前 {max_items} 条）")

    return _apply_length_limit("\n".join(lines))


def format_summary_message(
    summary: str,
    items: List[VulnItem],
    title: str = "安全漏洞情报摘要",
) -> str:
    """构建 AI 摘要 + 相关漏洞列表的纯文本消息。"""
    lines: List[str] = [title, ""]
    if summary and summary.strip():
        lines.append(summary.strip())
        lines.append("")

    if items:
        lines.append("涉及漏洞条目:")
        for index, item in enumerate(items, 1):
            lines.append(
                f"{index}. [{_severity(item)}] {_title_text(item)}{_id_part(item)}"
            )
    else:
        lines.append("暂无漏洞数据")

    return _apply_length_limit("\n".join(lines))


def format_status_message(info: dict) -> str:
    """把状态字典渲染为纯文本多行消息。"""
    lines: List[str] = ["插件运行状态"]
    for key, value in info.items():
        if isinstance(value, (list, tuple, set)):
            value = ", ".join(str(v) for v in value)
        lines.append(f"{key}: {value}")
    return "\n".join(lines)
