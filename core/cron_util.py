"""轻量级标准 5 段 cron 表达式解析与触发推算。"""

from __future__ import annotations

import calendar
from datetime import datetime, timedelta
from typing import Set

# 星期字段 0 与 7 均代表周日（1-6 为周一至周六）
_DOW_CRON_TO_ISO = 0  # 内部以 cron 规则存储，周日为 0


class CronSchedule:
    """解析 5 段 cron 表达式，提供分钟级匹配与下次触发时间推算。

    支持语法：
    - 分 (0-59)、时 (0-23)、日 (1-31)、月 (1-12)、周 (0-7，0 与 7 均为周日)
    - 通配符 ``*``、范围 ``a-b``、步长 ``*/n`` 与 ``a-b/n``、列表 ``a,b,c``
    """

    def __init__(self, expr: str) -> None:
        if not isinstance(expr, str) or not expr.strip():
            raise ValueError("Cron 表达式不能为空")
        raw = expr.strip()
        parts = raw.split()
        if len(parts) != 5:
            raise ValueError(
                f"无效的 Cron 表达式（要求标准 5 段格式，实际 {len(parts)} 段）: {expr!r}"
            )

        self._expr = raw
        raw_min, raw_hour, raw_dom, raw_month, raw_dow = parts

        self.minutes: Set[int] = self._parse_field(raw_min, 0, 59)
        self.hours: Set[int] = self._parse_field(raw_hour, 0, 23)
        self.doms: Set[int] = self._parse_field(raw_dom, 1, 31)
        self.months: Set[int] = self._parse_field(raw_month, 1, 12)
        # 周字段允许 0-7，7 归一化到 0（周日）
        self.dows: Set[int] = self._parse_field(raw_dow, 0, 7, normalize_7=True)

        self.is_dom_star = raw_dom == "*"
        self.is_dow_star = raw_dow == "*"

    @property
    def expr(self) -> str:
        """返回解析时使用的原始 cron 表达式。"""
        return self._expr

    # ------------------------------------------------------------------ 解析
    @staticmethod
    def _parse_field(
        field_str: str,
        min_val: int,
        max_val: int,
        normalize_7: bool = False,
    ) -> Set[int]:
        """解析单个字段，返回允许取值的集合。"""
        results: Set[int] = set()
        for token in field_str.split(","):
            token = token.strip()
            if not token:
                raise ValueError(f"Cron 字段含空项: {field_str!r}")

            if token == "*":
                results.update(range(min_val, max_val + 1))
                continue

            if "/" in token:
                range_part, step_str = token.split("/", 1)
                try:
                    step = int(step_str)
                except ValueError as exc:
                    raise ValueError(f"Cron 步长必须为整数: {token!r}") from exc
                if step <= 0:
                    raise ValueError(f"Cron 步长必须为正整数: {token!r}")

                if range_part in ("*", ""):
                    start, end = min_val, max_val
                elif "-" in range_part:
                    start, end = _parse_range(range_part, min_val, max_val)
                else:
                    start = _parse_int(range_part, min_val, max_val)
                    end = max_val

                if start > end:
                    raise ValueError(f"Cron 范围越界: {token!r}")
                results.update(range(start, end + 1, step))
            elif "-" in token:
                start, end = _parse_range(token, min_val, max_val)
                if start > end:
                    raise ValueError(f"Cron 范围越界: {token!r}")
                results.update(range(start, end + 1))
            else:
                results.add(_parse_int(token, min_val, max_val))

        if normalize_7 and 7 in results:
            results.discard(7)
            results.add(0)

        if not results:
            raise ValueError(f"Cron 字段解析结果为空: {field_str!r}")
        return results

    # ------------------------------------------------------------------ 匹配
    def _day_matches(self, year: int, month: int, day: int) -> bool:
        """判断某年某月某日是否命中日/周字段（遵循标准 cron 的 dom/dow 规则）。"""
        weekday = datetime(year, month, day).weekday()  # 0=周一 ... 6=周日
        cron_dow = (weekday + 1) % 7  # 0=周日 ... 6=周六
        dom_match = day in self.doms
        dow_match = cron_dow in self.dows

        if self.is_dom_star and self.is_dow_star:
            return True
        if self.is_dom_star:
            return dow_match
        if self.is_dow_star:
            return dom_match
        return dom_match or dow_match

    def matches(self, dt: datetime) -> bool:
        """判断指定时刻是否命中该 cron 表达式（精确到分钟）。"""
        if dt.minute not in self.minutes:
            return False
        if dt.hour not in self.hours:
            return False
        if dt.month not in self.months:
            return False
        return self._day_matches(dt.year, dt.month, dt.day)

    # ------------------------------------------------------------------ 推算
    @staticmethod
    def _advance_month(dt: datetime) -> datetime:
        """跳到下个月 1 号 00:00。"""
        if dt.month == 12:
            return dt.replace(
                year=dt.year + 1, month=1, day=1,
                hour=0, minute=0, second=0, microsecond=0,
            )
        return dt.replace(
            month=dt.month + 1, day=1,
            hour=0, minute=0, second=0, microsecond=0,
        )

    def next_run(self, after: datetime) -> datetime:
        """返回严格大于 ``after`` 的下一次触发时刻。"""
        curr = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        max_days = 366 * 5
        start_date = curr.date()

        while (curr.date() - start_date).days < max_days:
            if curr.month not in self.months:
                curr = self._advance_month(curr)
                continue

            if curr.day > calendar.monthrange(curr.year, curr.month)[1]:
                curr = self._advance_month(curr)
                continue

            if not self._day_matches(curr.year, curr.month, curr.day):
                curr = (curr + timedelta(days=1)).replace(hour=0, minute=0)
                continue

            if curr.hour not in self.hours:
                curr = (curr + timedelta(hours=1)).replace(minute=0)
                continue

            if curr.minute not in self.minutes:
                curr += timedelta(minutes=1)
                continue

            return curr

        raise ValueError(
            f"未来 5 年内未推算出符合该 Cron 表达式的触发时刻: {self._expr!r}"
        )


# ---------------------------------------------------------------------- 辅助
def _parse_int(token: str, min_val: int, max_val: int) -> int:
    try:
        value = int(token)
    except ValueError as exc:
        raise ValueError(f"Cron 字段包含非法整数: {token!r}") from exc
    if value < min_val or value > max_val:
        raise ValueError(
            f"Cron 数值越界: {token!r}（合法区间 {min_val}-{max_val}）"
        )
    return value


def _parse_range(token: str, min_val: int, max_val: int) -> "tuple[int, int]":
    if token.count("-") != 1:
        raise ValueError(f"Cron 范围格式错误: {token!r}")
    start_str, end_str = token.split("-", 1)
    start = _parse_int(start_str, min_val, max_val)
    end = _parse_int(end_str, min_val, max_val)
    return start, end
