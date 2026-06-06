"""设计规约 — 6 条规则：单一职责、组合优于继承"""
import re
from typing import List

import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class DesignChecker(BaseChecker):
    def check_design(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_design"):
            return
        lines = content.split("\n")

        # 7.10 Single responsibility
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                field_count = 0
                method_count = 0
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        field_count += len(member.declarators)
                    elif isinstance(member, javalang.tree.MethodDeclaration):
                        method_count += 1
                if field_count > 20 and method_count > 20:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_SINGLE_RESPONSIBILITY",
                              f"类 '{node.name}' 职责可能过重（{field_count} 个字段, {method_count} 个方法），建议符合单一职责原则",
                              Severity.INFO, line=l, column=c)

        # 7.11 Favor composition over inheritance
        for i, line in enumerate(lines, 1):
            if re.search(r"\bextends\s+\w+\s*\{", line) and \
               not re.search(r"(Exception|RuntimeException|Throwable|Error|Thread|Base|Abstract)", line):
                m = re.search(r"class\s+(\w+)\s+extends\s+(\w+)", line)
                if m and not m.group(2).startswith(("Base", "Abstract")):
                    self._add(file_path, "ALIBABA_COMPOSITION",
                              f"类 '{m.group(1)}' 谨慎使用继承方式扩展，优先使用聚合/组合方式",
                              Severity.INFO, line=i)

        # 7.5 Interface should define contract
        for i, line in enumerate(lines, 1):
            m = re.search(r"interface\s+(\w+)", line)
            if m:
                iface_name = m.group(1)
                has_impl = False
                for j, line2 in enumerate(lines, 1):
                    if re.search(rf"\bimplements\s+\w*{re.escape(iface_name)}\w*", line2):
                        has_impl = True
                        break
                if not has_impl and not iface_name.startswith("Base"):
                    self._add(file_path, "ALIBABA_INTERFACE_EMPTY",
                              f"接口 '{iface_name}' 需要被实现才能存在",
                              Severity.INFO, line=i)

        # 7.6 Avoid deep inheritance (depth > 3)
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if node.extends:
                    parent = node.extends.name
                    depth = 1
                    cur = parent
                    while depth < 10:
                        found_parent = False
                        for path2, node2 in tree:
                            if isinstance(node2, javalang.tree.ClassDeclaration) and node2.name == cur:
                                if node2.extends:
                                    cur = node2.extends.name
                                    depth += 1
                                    found_parent = True
                                break
                        if not found_parent:
                            break
                    if depth >= 3:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_DEEP_INHERITANCE",
                                  f"类 '{node.name}' 继承层次过深（{depth} 层），最大不超过 3 层",
                                  Severity.INFO, line=l, column=c)

        # 7.8 No class with multiple if-else + switch > 10
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if_else_count = 0
                switch_count = 0
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration):
                        body_str = str(member.body or "")
                        if_else_count += len(re.findall(r"\bif\s*\(", body_str))
                        switch_count += len(re.findall(r"\bswitch\s*\(", body_str))
                if if_else_count > 15:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_EXCESSIVE_IFELSE",
                              f"类 '{node.name}' 包含 {if_else_count} 个 if-else，建议用策略模式替代",
                              Severity.WARNING, line=l, column=c)

        # 7.9 Business logic decomposed rather than one big method
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if isinstance(body, list) and len(body) > 50:
                    line_count = 0
                    for stmt in body:
                        stmt_lines = str(stmt).split("\n")
                        line_count += len(stmt_lines)
                    if line_count > 100:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_BIG_METHOD",
                                  f"方法 '{node.name}' 过长，应分解为多个小方法",
                                  Severity.WARNING, line=l, column=c)
