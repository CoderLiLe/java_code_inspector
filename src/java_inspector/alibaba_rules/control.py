"""控制语句 — 15 条规则：switch、if-else 深度、大括号"""
import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class ControlChecker(BaseChecker):

    def check_control(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_control"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.SwitchStatement):
                has_default = any(child.case is None for child in node.cases)
                if not has_default:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_SWITCH_DEFAULT",
                              "switch 块内必须包含一个 default 语句",
                              Severity.WARNING, line=l, column=c)
                for case in node.cases:
                    if case.case is not None:
                        stmts = case.statements or []
                        if stmts and not any(
                            isinstance(s, (javalang.tree.BreakStatement,
                                           javalang.tree.ReturnStatement,
                                           javalang.tree.ContinueStatement))
                            for s in stmts
                        ):
                            cl = case.case.position.line if hasattr(case.case, "position") and case.case.position else 0
                            self._add(file_path, "ALIBABA_SWITCH_BREAK",
                                      "switch 的每个 case 必须通过 break/return 等来终止",
                                      Severity.WARNING, line=cl)

        # 8.1 Switch fall-through must have comment
        for path, node in tree:
            if isinstance(node, javalang.tree.SwitchStatement):
                for case in node.cases:
                    if case.case is not None:
                        stmts = case.statements or []
                        if stmts and not any(
                            isinstance(s, (javalang.tree.BreakStatement,
                                           javalang.tree.ReturnStatement,
                                           javalang.tree.ContinueStatement,
                                           javalang.tree.ThrowStatement))
                            for s in stmts
                        ):
                            last_stmt_line = 0
                            for s in stmts:
                                if hasattr(s, "position") and s.position:
                                    last_stmt_line = s.position.line
                            # Check if next case line has a comment
                            has_comment = False
                            for j in range(last_stmt_line, min(last_stmt_line + 3, len(lines) + 1)):
                                if j <= len(lines) and re.search(r"//|/\*|\*", lines[j - 1]):
                                    has_comment = True
                                    break
                            if not has_comment:
                                cl = case.case.position.line if hasattr(case.case, "position") and case.case.position else 0
                                self._add(file_path, "ALIBABA_SWITCH_FALLTHROUGH",
                                          "case 穿透必须注释说明为什么会继续执行到下一个 case",
                                          Severity.INFO, line=cl)

        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|else\s+if|for|while|do)\s*\([^)]*\)\s*[^\s{;]", line) and \
               not re.search(r"\{\s*$", line):
                self._add(file_path, "ALIBABA_REQUIRE_BRACES",
                          "if/else/for/while/do 语句中必须使用大括号",
                          Severity.WARNING, line=i)

        for i, line in enumerate(lines, 1):
            m = re.search(r"\(\s*([a-zA-Z_]\w*)\s*==\s*null\s*\)\s*\?\s*([^:]+)\s*:\s*(\2)", line)
            if m:
                self._add(file_path, "ALIBABA_TERNARY_NPE",
                          "三元表达式可能引发空指针 NPE，注意自动拆箱导致的 NullPointerException",
                          Severity.INFO, line=i)

        # 8.2 - switch String null check
        in_switch = False
        for i, line in enumerate(lines, 1):
            if re.search(r"switch\s*\(\s*\w+\s*\)", line):
                in_switch = True
                continue
            if in_switch and re.search(r"^\s*\}\s*$", line):
                in_switch = False
            if in_switch and re.search(r"case\s+", line):
                self._add(file_path, "ALIBABA_SWITCH_STRING",
                          "当 switch 括号内的变量类型为 String 并且此变量为外部参数时，必须先进行 null 判断",
                          Severity.INFO, line=i)
                in_switch = False

        # 8.7 - if-else depth (simplified check for nested if)
        if_depth = 0
        max_depth = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("if") or stripped.startswith("else if"):
                if_depth += 1
                max_depth = max(max_depth, if_depth)
            elif stripped.startswith("}") or stripped.startswith("}"):
                if_depth = max(0, if_depth - 1)
        if max_depth > 3:
            self._add(file_path, "ALIBABA_IF_DEPTH",
                      "if-else 层级超过 3 层，建议使用卫语句、策略模式或状态模式重构",
                      Severity.INFO, line=0)

        # 8.9 No assignment in conditions
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|while)\s*\([^)]*=\s*[^=]", line) and \
               not re.search(r"[=!]=|&&|\|\|", line):
                code_part = re.sub(r"//.*|/\*.*?\*/|\".*?\"", "", line, flags=re.DOTALL)
                if "=" in code_part:
                    self._add(file_path, "ALIBABA_ASSIGN_IN_CONDITION",
                              "不要在条件表达式中插入赋值语句，赋值语句应清晰单独成为一行",
                              Severity.WARNING, line=i)

        # 8.11 Avoid negation
        for i, line in enumerate(lines, 1):
            if re.search(r"if\s*\(\s*!\(", line) and \
               not re.search(r"//.*if", line):
                self._add(file_path, "ALIBABA_AVOID_NOT",
                          "避免采用取反逻辑运算符，建议使用正向逻辑表达",
                          Severity.INFO, line=i)

        # 8.12 Public method input parameter validation
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []) and \
               node.name not in ("main", "toString", "equals", "hashCode", "get", "set",
                                "getClass", "notify", "wait"):
                has_object_param = False
                has_null_check = False
                body_stmts = node.body if isinstance(node.body, list) else \
                            getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body_stmts:
                    if isinstance(stmt, javalang.tree.IfStatement) and \
                       hasattr(stmt, "expression") and stmt.expression and \
                       "null" in str(stmt.expression):
                        has_null_check = True
                for param in (node.parameters or []):
                    pt = getattr(param, "type", None)
                    if pt and hasattr(pt, "name") and pt.name == "Object":
                        has_object_param = True
                    elif pt and hasattr(pt, "name") and pt.name not in (
                        "int", "long", "double", "float", "boolean", "char", "byte", "short",
                        "String", "Integer", "Long", "Double", "Float", "Boolean"
                    ):
                        has_object_param = True
                if has_object_param and not has_null_check and len(body_stmts) > 2:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_PARAM_VALIDATION",
                              "公开接口需要进行入参保护，对参数进行有效性验证",
                              Severity.INFO, line=l, column=c)

        # 8.10 Object creation in loop
        for path, node in tree:
            if isinstance(node, (javalang.tree.ForStatement, javalang.tree.WhileStatement)):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                new_count = sum(1 for s in body if "new " in str(s))
                if new_count > 3:
                    l = node.position.line if node.position else 0
                    self._add(file_path, "ALIBABA_LOOP_OBJECT_CREATION",
                              "循环体中的对象定义应尽量移至循环体外处理，提升性能",
                              Severity.INFO, line=l)

        # 8.10.2 Database connection in loop
        for path, node in tree:
            if isinstance(node, (javalang.tree.ForStatement, javalang.tree.WhileStatement)):
                body_str = str(node.body or "")
                if re.search(r"(getConnection|DataSource|createConnection|DriverManager|dataSource)", body_str, re.IGNORECASE):
                    l = node.position.line if node.position else 0
                    self._add(file_path, "ALIBABA_LOOP_CONNECTION",
                              "数据库连接获取不应放在循环体内，应移至循环外",
                              Severity.INFO, line=l)

        # 8.6 Blank line after return/throw (when method > 10 lines)
        method_line_counts = {}
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                if node.position:
                    ml = node.position.line
                    body = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                    if body and hasattr(body[-1], "position") and body[-1].position:
                        total = body[-1].position.line - ml
                        if total > 10:
                            for j in range(ml, ml + total):
                                if j - 1 < len(lines) and re.search(r"\b(return|throw)\b\s+[^;]+;", lines[j - 1]) and \
                                   j < len(lines) and lines[j].strip() != "" and not lines[j].strip().startswith("}"):
                                    self._add(file_path, "ALIBABA_RETURN_BLANK_LINE",
                                              "return/throw 等中断逻辑的右大括号后需要加一个空行",
                                              Severity.INFO, line=j)
                                    break

        # 8.8 Complex condition to variable
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|while)\s*\([^)]*&&[^)]*\|\|[^)]*\)", line) and \
               not re.search(r"//", line) and \
               not re.search(r"else\s+if", line):
                m = re.search(r"if\s*\((.{30,})\)", line)
                if m:
                    self._add(file_path, "ALIBABA_COMPLEX_CONDITION",
                              "复杂的条件判断建议将结果赋值给一个有意义的布尔变量名，提高可读性",
                              Severity.INFO, line=i)

        # 8.13 High-concurrency: avoid == as break/exit condition
        for path, node in tree:
            if isinstance(node, (javalang.tree.SynchronizedStatement, javalang.tree.MethodDeclaration)):
                mods = getattr(node, "modifiers", []) or []
                is_sync = "synchronized" in mods or isinstance(node, javalang.tree.SynchronizedStatement)
                if is_sync:
                    body_stmts = []
                    if isinstance(node, javalang.tree.SynchronizedStatement):
                        body_stmts = node.body.statements if hasattr(node.body, "statements") else (node.body if isinstance(node.body, list) else [])
                    else:
                        body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                    for stmt in body_stmts:
                        if isinstance(stmt, javalang.tree.IfStatement):
                            cond_str = str(stmt.expression)
                            if re.search(r"==\s*\d+$", cond_str) and \
                               re.search(r"\b(break|return|exit)\b", str(stmt.then_statement)):
                                l = stmt.position.line if stmt.position else 0
                                self._add(file_path, "ALIBABA_HIGH_CONCURRENCY_EQUAL",
                                          "高并发场景中避免使用等值判断(==)作为中断条件，建议用大于/小于区间判断",
                                          Severity.WARNING, line=l)
