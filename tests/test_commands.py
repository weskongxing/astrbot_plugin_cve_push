"""指令注册形态离线单元测试。

不依赖 astrbot 运行时，通过静态解析 main.py 的 AST，锁定指令必须符合
AstrBot 标准指令组规范：

- 根指令组使用 ``@filter.command_group("cve", alias={...})``；
- 子指令全部使用 ``@cve_group.command("<name>", alias={...})`` 注册；
- 不存在旧版的「单条指令 + sub 字符串参数」写法；
- 每条子指令都带中文 docstring（AstrBot 用它作为指令列表中的描述）；
- ``@register`` 的插件 id 与插件目录名保持一致。
"""

from __future__ import annotations

import ast
import os
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_DIR = os.path.dirname(_TESTS_DIR)
_MAIN_PY = os.path.join(_PLUGIN_DIR, "main.py")

GROUP_NAME = "cve"
SUB_COMMANDS = ("push", "targets", "status", "test", "reset", "help")


def _load_tree() -> ast.Module:
    with open(_MAIN_PY, "r", encoding="utf-8") as handle:
        return ast.parse(handle.read(), filename=_MAIN_PY)


def _decorator_attr(node: ast.AST) -> str:
    """把装饰器表达式还原成 a.b.c 形式的字符串。"""
    if isinstance(node, ast.Call):
        return _decorator_attr(node.func)
    if isinstance(node, ast.Attribute):
        base = _decorator_attr(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _decorator_call_args(node: ast.AST) -> tuple[list, dict]:
    if not isinstance(node, ast.Call):
        return [], {}
    args = []
    for arg in node.args:
        try:
            args.append(ast.literal_eval(arg))
        except Exception:  # noqa: BLE001
            args.append(None)
    kwargs = {}
    for kw in node.keywords:
        if kw.arg is None:
            continue
        try:
            kwargs[kw.arg] = ast.literal_eval(kw.value)
        except Exception:  # noqa: BLE001
            kwargs[kw.arg] = None
    return args, kwargs


def _find_plugin_class(tree: ast.Module) -> ast.ClassDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "CvePushPlugin":
            return node
    raise AssertionError("未找到 CvePushPlugin 类定义")


def _methods(cls: ast.ClassDef) -> list[ast.AsyncFunctionDef]:
    return [n for n in cls.body if isinstance(n, ast.AsyncFunctionDef)]


class CommandRegistrationTests(unittest.TestCase):
    """校验指令注册符合 AstrBot 指令组规范。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = _load_tree()
        cls.plugin_class = _find_plugin_class(cls.tree)
        cls.methods = _methods(cls.plugin_class)

    def test_plugin_registered_with_dir_name(self) -> None:
        dir_name = os.path.basename(_PLUGIN_DIR)
        found = None
        for node in self.plugin_class.decorator_list:
            if _decorator_attr(node) == "register":
                args, _ = _decorator_call_args(node)
                if args:
                    found = args[0]
        self.assertEqual(found, dir_name, "register 名称必须与插件目录名一致")

    def test_root_command_group_registered(self) -> None:
        groups = []
        for method in self.methods:
            for deco in method.decorator_list:
                if _decorator_attr(deco) == "filter.command_group":
                    args, kwargs = _decorator_call_args(deco)
                    groups.append((args[0] if args else None, kwargs.get("alias")))
        self.assertEqual(len(groups), 1, "必须且只能有一个根指令组")
        name, alias = groups[0]
        self.assertEqual(name, GROUP_NAME)
        self.assertIsInstance(alias, set)
        self.assertIn("漏洞", alias)

    def test_sub_commands_registered(self) -> None:
        registered = {}
        for method in self.methods:
            for deco in method.decorator_list:
                if _decorator_attr(deco) == "cve_group.command":
                    args, _ = _decorator_call_args(deco)
                    registered[args[0]] = method
        self.assertEqual(
            sorted(registered),
            sorted(SUB_COMMANDS),
            "子指令集合与预期不一致",
        )

    def test_no_legacy_single_command_with_sub_param(self) -> None:
        for method in self.methods:
            for deco in method.decorator_list:
                if _decorator_attr(deco) != "filter.command":
                    continue
                args, _ = _decorator_call_args(deco)
                self.assertNotIn(
                    "vuln",
                    [str(a) for a in args],
                    "不允许再注册裸 /vuln 指令",
                )
                # 旧写法：额外接收 sub 字符串参数
                self.assertNotIn(
                    "sub",
                    [a.arg for a in method.args.args],
                    "不允许再用 sub 字符串参数分发子指令（应改为指令组）",
                )

    def test_every_sub_command_has_docstring(self) -> None:
        for method in self.methods:
            names = [_decorator_attr(d) for d in method.decorator_list]
            if "cve_group.command" not in names:
                continue
            doc = ast.get_docstring(method) or ""
            self.assertTrue(doc.strip(), f"{method.name} 缺少 docstring，指令列表将显示无描述")
            self.assertFalse(
                any(ord(ch) > 0x1F000 for ch in doc),
                f"{method.name} 的 docstring 含 emoji",
            )

    def test_handlers_are_async_generators(self) -> None:
        for method in self.methods:
            names = [_decorator_attr(d) for d in method.decorator_list]
            if not any(n in ("cve_group.command", "filter.command_group") for n in names):
                continue
            has_yield = any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(method))
            if "filter.command_group" in names:
                # 根指令组允许纯 pass
                continue
            self.assertTrue(has_yield, f"{method.name} 必须是异步生成器（内部 yield 结果）")


if __name__ == "__main__":
    unittest.main()
