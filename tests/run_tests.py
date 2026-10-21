"""离线单元测试聚合入口。

用法（任选其一）：
    python astrbot_plugin_cve_push/tests/run_tests.py
    cd astrbot_plugin_cve_push && python tests/run_tests.py
    python -m unittest discover -s astrbot_plugin_cve_push/tests -p "test_*.py"
"""

from __future__ import annotations

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_PARENT_DIR = os.path.dirname(_PLUGIN_DIR)
for _p in (_PARENT_DIR, _PLUGIN_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover(_TESTS_DIR, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
