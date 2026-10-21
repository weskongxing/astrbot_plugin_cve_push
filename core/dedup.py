"""跨信源持久化去重存储。"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from .models import VulnItem

logger = logging.getLogger("astrbot_plugin_vuln_push")

_VERSION = 1
_EMPTY_DATA: Dict[str, object] = {"version": _VERSION, "records": {}}


class DedupStore:
    """基于 JSON 文件的去重记录存储。

    - 持久化格式: ``{"version": 1, "records": {"<dedup_key>": <unix_ts>}}``
    - 写盘使用临时文件 + ``os.replace`` 原子替换
    - 文件损坏时容错重置并记录 warning
    - 超过 ``window_days`` 的记录在 ``load()`` 与 ``mark_pushed()`` 时清理
    """

    def __init__(self, path: str, window_days: int = 30) -> None:
        self.path = path
        self.window_days = max(1, int(window_days))
        self._records: Dict[str, float] = {}
        self._lock = threading.RLock()
        target_dir = os.path.dirname(os.path.abspath(path))
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        self.load()

    # ------------------------------------------------------------------ 持久化
    def _cutoff(self, now: float) -> float:
        return now - self.window_days * 86400.0

    def _prune(self, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        cutoff = self._cutoff(now)
        stale = [key for key, ts in self._records.items() if ts < cutoff]
        for key in stale:
            del self._records[key]
        if stale:
            logger.info("[漏洞推送] 去重记录清理 %s 条过期项", len(stale))

    def load(self) -> None:
        """从文件加载去重记录；文件损坏时容错重置。"""
        with self._lock:
            if not os.path.exists(self.path):
                self._records = {}
                return
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if not content:
                    self._records = {}
                    return
                data = json.loads(content)
            except (OSError, ValueError) as exc:
                logger.warning(
                    "[漏洞推送] 去重记录文件损坏，已重置为空: %s (%s)",
                    self.path,
                    exc,
                )
                self._records = {}
                return

            records = data.get("records") if isinstance(data, dict) else None
            if not isinstance(records, dict):
                logger.warning("[漏洞推送] 去重记录结构异常，已重置为空: %s", self.path)
                self._records = {}
                return

            normalized: Dict[str, float] = {}
            for key, value in records.items():
                if not isinstance(key, str) or not key:
                    continue
                try:
                    normalized[key] = float(value)
                except (TypeError, ValueError):
                    continue
            self._records = normalized
            self._prune()

    def _save(self) -> None:
        """原子写盘（临时文件 + os.replace）。"""
        with self._lock:
            data: Dict[str, object] = {
                "version": _VERSION,
                "records": dict(self._records),
            }
            target_dir = os.path.dirname(os.path.abspath(self.path))
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)
            tmp_path = f"{self.path}.tmp.{os.getpid()}.{time.time_ns()}"
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, self.path)
            except OSError as exc:
                logger.warning("[漏洞推送] 去重记录写盘失败: %s (%s)", self.path, exc)
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

    # ------------------------------------------------------------------ 对外
    def is_pushed(self, item: VulnItem) -> bool:
        with self._lock:
            return item.dedup_key in self._records

    def filter_new(self, items: List[VulnItem]) -> List[VulnItem]:
        """保持原顺序，过滤掉已推送的条目。"""
        with self._lock:
            return [item for item in items if item.dedup_key not in self._records]

    def mark_pushed(self, items: List[VulnItem], now: Optional[float] = None) -> None:
        """标记一组条目为已推送，并清理过期记录后持久化。"""
        if not items:
            return
        if now is None:
            now = time.time()
        with self._lock:
            for item in items:
                self._records[item.dedup_key] = now
            self._prune(now)
            self._save()

    def reset(self) -> None:
        """清空全部去重记录并持久化。"""
        with self._lock:
            self._records = {}
            self._save()

    def stats(self) -> dict:
        with self._lock:
            if not self._records:
                return {
                    "total": 0,
                    "window_days": self.window_days,
                    "oldest": "",
                    "newest": "",
                }
            timestamps = sorted(self._records.values())
            return {
                "total": len(self._records),
                "window_days": self.window_days,
                "oldest": datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d %H:%M:%S"),
                "newest": datetime.fromtimestamp(timestamps[-1]).strftime("%Y-%m-%d %H:%M:%S"),
            }
