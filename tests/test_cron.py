"""CronSchedule 5 段 cron 解析与 next_run 离线单元测试。"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_PARENT_DIR = os.path.dirname(_PLUGIN_DIR)
for _p in (_PARENT_DIR, _PLUGIN_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from astrbot_plugin_cve_push.core.cron_util import CronSchedule


class CronScheduleTests(unittest.TestCase):
    def test_daily_nine(self):
        sched = CronSchedule("0 9 * * *")
        self.assertEqual(sched.expr, "0 9 * * *")
        self.assertTrue(sched.matches(datetime(2026, 10, 21, 9, 0)))
        self.assertFalse(sched.matches(datetime(2026, 10, 21, 9, 1)))
        self.assertFalse(sched.matches(datetime(2026, 10, 21, 8, 0)))

        self.assertEqual(
            sched.next_run(datetime(2026, 10, 21, 8, 59)),
            datetime(2026, 10, 21, 9, 0),
        )
        # after 正好等于触发时刻时，应返回下一天的 9:00
        self.assertEqual(
            sched.next_run(datetime(2026, 10, 21, 9, 0)),
            datetime(2026, 10, 22, 9, 0),
        )

    def test_every_30_min(self):
        sched = CronSchedule("*/30 * * * *")
        self.assertTrue(sched.matches(datetime(2026, 10, 21, 12, 0)))
        self.assertTrue(sched.matches(datetime(2026, 10, 21, 12, 30)))
        self.assertFalse(sched.matches(datetime(2026, 10, 21, 12, 15)))

        self.assertEqual(
            sched.next_run(datetime(2026, 10, 21, 12, 0)),
            datetime(2026, 10, 21, 12, 30),
        )
        self.assertEqual(
            sched.next_run(datetime(2026, 10, 21, 12, 30)),
            datetime(2026, 10, 21, 13, 0),
        )

    def test_weekday_hours(self):
        sched = CronSchedule("*/15 8-18 * * 1-5")
        # 2026-10-21 是周三（工作日）
        self.assertTrue(sched.matches(datetime(2026, 10, 21, 9, 0)))
        self.assertTrue(sched.matches(datetime(2026, 10, 21, 9, 15)))
        self.assertTrue(sched.matches(datetime(2026, 10, 21, 8, 0)))
        self.assertFalse(sched.matches(datetime(2026, 10, 21, 7, 45)))
        self.assertFalse(sched.matches(datetime(2026, 10, 21, 19, 0)))
        # 2026-10-24 是周六
        self.assertFalse(sched.matches(datetime(2026, 10, 24, 9, 0)))

        # 工作日 18:45 之后的下一次触发应为次日 8:00
        self.assertEqual(
            sched.next_run(datetime(2026, 10, 21, 18, 45)),
            datetime(2026, 10, 22, 8, 0),
        )

    def test_monthly(self):
        sched = CronSchedule("0 0 1 * *")
        self.assertTrue(sched.matches(datetime(2026, 11, 1, 0, 0)))
        self.assertFalse(sched.matches(datetime(2026, 11, 2, 0, 0)))
        self.assertEqual(
            sched.next_run(datetime(2026, 10, 21, 12, 0)),
            datetime(2026, 11, 1, 0, 0),
        )

    def test_dow_0_and_7_both_sunday(self):
        # 2026-10-25 是周日
        self.assertTrue(CronSchedule("0 9 * * 0").matches(datetime(2026, 10, 25, 9, 0)))
        self.assertTrue(CronSchedule("0 9 * * 7").matches(datetime(2026, 10, 25, 9, 0)))

    def test_next_run_strictly_greater_and_matches(self):
        exprs = [
            "0 9 * * *",
            "*/30 * * * *",
            "*/15 8-18 * * 1-5",
            "0 0 1 * *",
            "5 4 3 2 1",
        ]
        after = datetime(2026, 1, 1, 0, 0)
        for expr in exprs:
            sched = CronSchedule(expr)
            result = sched.next_run(after)
            self.assertGreater(result, after, expr)
            self.assertTrue(sched.matches(result), expr)

    def test_invalid_expressions(self):
        invalid = [
            "",                      # 空串
            "   ",                   # 全空白
            "0 9 * *",               # 段数不足
            "0 9 * * * 1",           # 段数过多
            "60 9 * * *",            # 分钟越界
            "0 24 * * *",            # 小时越界
            "0 9 32 * *",            # 日越界
            "0 9 * 13 *",            # 月越界
            "0 9 * * 8",             # 周越界
            "*/0 * * * *",           # 步长为 0
            "0 9 * * abc",           # 非法整数
        ]
        for expr in invalid:
            with self.assertRaises(ValueError, msg=repr(expr)):
                CronSchedule(expr)


if __name__ == "__main__":
    unittest.main()
