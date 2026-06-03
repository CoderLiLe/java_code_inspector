import re
from typing import List

from javalang import tree as javalang_tree

from java_inspector.models import CodeIssue, Severity
from java_inspector.config import InspectionConfig


def _sq_severity(sonar_sev: str) -> Severity:
    mapping = {
        "BLOCKER": Severity.ERROR,
        "CRITICAL": Severity.ERROR,
        "MAJOR": Severity.WARNING,
        "MINOR": Severity.INFO,
        "INFO": Severity.INFO,
    }
    return mapping.get(sonar_sev, Severity.WARNING)


def _get_full_type_name(t):
    if t is None:
        return ""
    name = getattr(t, "name", "")
    sub = getattr(t, "sub_type", None)
    if sub:
        sub_name = _get_full_type_name(sub)
        if sub_name:
            return name + "." + sub_name
    return name


class SonarQubeCheckerSeven:
    def __init__(self, config: InspectionConfig, issues: List[CodeIssue]):
        self.config = config
        self.issues = issues

    @staticmethod
    def _pos(node):
        if node is not None and hasattr(node, "position") and node.position:
            return node.position.line, node.position.column
        return 0, 0

    def _add(self, file_path, rule_id, message, severity=Severity.WARNING, line=0, column=0, fix_suggestion=""):
        self.issues.append(CodeIssue(
            file_path=file_path,
            line=line,
            column=column,
            message=f"【SonarQube】{message}",
            severity=severity,
            rule_id=rule_id,
            category="SONARQUBE",
            fix_suggestion=fix_suggestion,
        ))

    def run_all(self, tree, file_path: str, content: str):
        self.check_correctness(tree, file_path, content)
        self.check_robustness(tree, file_path, content)
        self.check_performance_seven(tree, file_path, content)
        self.check_api_usage(tree, file_path, content)

    # ==================== Correctness ====================

    def check_correctness(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_correctness"):
            return
        lines = content.split("\n")

        # S1227: break/continue labels should not be used unnecessarily
        for path, node in tree:
            if isinstance(node, javalang_tree.BreakStatement):
                label = getattr(node, "label", None) or getattr(node, "goto", None)
                if label:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_BREAK_LABEL",
                              "S1227: 带标签的 break 可能影响代码可读性",
                              _sq_severity("MINOR"), line=l, column=c)

        # S1849: Iterator.hasNext() should not be assumed
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "next":
                    q = str(getattr(node, "qualifier", "") or "")
                    if q and "Iterator" not in q and "iterator" not in q:
                        pass

        # S1850: instanceof always false (final class)
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "instanceof":
                    right = getattr(node, "operandr", None)
                    if right and isinstance(right, javalang_tree.ReferenceType):
                        type_name = _get_full_type_name(right)
                        if type_name in ("String", "Integer", "Long", "Boolean"):
                            left = getattr(node, "operandl", None)
                            if left:
                                left_str = str(left)
                                for path2, node2 in tree:
                                    if isinstance(node2, javalang_tree.FieldDeclaration):
                                        for decl in getattr(node2, "declarators", []) or []:
                                            dname = getattr(decl, "name", "")
                                            if dname and dname in left_str and \
                                               type_name in ("String",):
                                                l, c = self._pos(node)
                                                self._add(file_path, "SONAR_INSTANCEOF_FINAL_ALWAYS",
                                                          "S1850: instanceof 检查 final 类总是 true 或 false",
                                                          _sq_severity("MAJOR"), line=l, column=c)
                                                break

        # S2196: switch with only default case
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                if len(cases) == 1:
                    case0 = cases[0]
                    case_tup = getattr(case0, "case", [])
                    if isinstance(case_tup, list) and len(case_tup) == 0:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_ONLY_DEFAULT_SWITCH",
                                  "S2196: switch 仅包含 default 分支，应替换为 if 语句",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2203: StringBuilder/Builder should not be passed as String parameter
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                args = getattr(node, "arguments", []) or []
                for arg in args:
                    arg_member = getattr(arg, "member", "")
                    # Check variable names that could be StringBuilder/StringBuffer
                    if arg_member in ("sb", "sBuilder", "stringBuilder", "builder", "strBuf", "stringBuf", "buf") or \
                       arg_member.endswith("Builder") or arg_member.endswith("Buffer") or \
                       arg_member.endswith("StringBuilder") or arg_member.endswith("StringBuffer"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SB_TO_STRING",
                                  "S2203: StringBuilder 应调用 toString() 后再传入方法",
                                  _sq_severity("MAJOR"), line=l, column=c)
                        break

        # S2204: equals() override should check parameter type
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "equals":
                    params = getattr(node, "parameters", []) or []
                    if params:
                        body = getattr(node, "body", None)
                        if body:
                            stmts = getattr(body, "statements", []) or []
                            body_str = " ".join(str(s) for s in stmts)
                            if "instanceof" not in body_str and "getClass" not in body_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_EQUALS_NO_TYPE_CHECK",
                                          "S2204: equals() 未进行类型检查（缺少 instanceof）",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S2225: toString should not return null
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "toString":
                    body = getattr(node, "body", None) or []
                    for stmt in body:
                        if isinstance(stmt, javalang_tree.ReturnStatement):
                            expr = getattr(stmt, "expression", None)
                            if isinstance(expr, javalang_tree.Literal):
                                val = getattr(expr, "value", "")
                                if val == "null":
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_TOSTRING_NULL",
                                              "S2225: toString() 不应返回 null",
                                              _sq_severity("MAJOR"), line=l, column=c)
                                    break

        # S2230: compareTo should be consistent with equals
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_compare_to = False
                has_equals = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if decl.name == "compareTo":
                            has_compare_to = True
                        if decl.name == "equals":
                            has_equals = True
                if has_compare_to and not has_equals:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_COMPARETO_WITHOUT_EQUALS",
                              "S2230: 实现 Comparable 的类应同时重写 equals()",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2681: Thread.run() should not be called directly
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "run" and getattr(node, "qualifier", None):
                    q = str(node.qualifier)
                    if q and q[0].islower() if q else False:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_THREAD_RUN_INSTEAD_START",
                                  "S2681: 直接调用 run() 不会启动新线程，应使用 Thread.start()",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2693: Thread should not be started in constructor
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name in ("Thread", "java.lang.Thread"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_THREAD_IN_CONSTRUCTOR",
                              "S2693: 不应在构造函数中启动线程",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2695: Thread.sleep(0) should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "sleep" and "Thread" in str(getattr(node, "qualifier", "")):
                    args = getattr(node, "arguments", []) or []
                    if args and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val == "0":
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_THREAD_SLEEP_ZERO",
                                      "S2695: Thread.sleep(0) 无用，应使用 yield() 或 wait()",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2701: Literals should not be compared with ==
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "==":
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    if left and isinstance(left, javalang_tree.Literal) and \
                       right and isinstance(right, javalang_tree.Literal):
                        lv = getattr(left, "value", "")
                        rv = getattr(right, "value", "")
                        if lv and rv and lv.startswith('"') and rv.startswith('"'):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_LITERAL_EQ",
                                      "S2701: 不应使用 == 比较字符串字面量，应使用 equals()",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2737: Catch should do more than rethrow
        for path, node in tree:
            if isinstance(node, javalang_tree.CatchClause):
                block = getattr(node, "block", None) or []
                if len(block) == 1 and isinstance(block[0], javalang_tree.ThrowStatement):
                    thrown = getattr(block[0], "expression", None)
                    if thrown and isinstance(thrown, javalang_tree.MemberReference):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CATCH_RETHROW",
                                  "S2737: catch 块仅重新抛出异常，应移除或添加处理",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2754: Inherited methods should not be hidden
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                parent = None
                if hasattr(node, "extends") and node.extends:
                    parent = str(node.extends.name) if hasattr(node.extends, "name") else str(node.extends)
                if parent:
                    child_methods = {}
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            child_methods[decl.name] = decl
                    if "toString" in child_methods and not parent:
                        pass

        # S2760: Sequential if statements should not be used
        prev_line = 0
        prev_cond = ""
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                cond_str = str(cond).replace(" ", "") if cond else ""
                l, c = self._pos(node)
                if prev_cond and l == prev_line + 1 and cond_str == prev_cond:
                    self._add(file_path, "SONAR_SEQUENTIAL_IF",
                              "S2760: 相邻 if 语句条件相同，应合并",
                              _sq_severity("MAJOR"), line=l, column=c)
                prev_cond = cond_str
                prev_line = l

        # S3027: String.indexOf to String.contains
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == ">=" or op == "!=":
                    left = str(getattr(node, "operandl", ""))
                    if ".indexOf(" in left:
                        right = getattr(node, "operandr", None)
                        if right and isinstance(right, javalang_tree.Literal):
                            val = getattr(right, "value", "")
                            if val == "0":
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_INDEXOF_CONTAINS_SEVEN",
                                          "S3027: indexOf() >= 0 应替换为 contains()",
                                          _sq_severity("MINOR"), line=l, column=c)

        # S3032: Collections.EMPTY_LIST should be replaced
        for path, node in tree:
            if isinstance(node, javalang_tree.MemberReference):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "EMPTY_LIST" and "Collections" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EMPTY_LIST",
                              "S3032: 应使用 Collections.emptyList() 替代 EMPTY_LIST",
                              _sq_severity("MINOR"), line=l, column=c)
                elif member == "EMPTY_MAP" and "Collections" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EMPTY_MAP",
                              "S3032: 应使用 Collections.emptyMap() 替代 EMPTY_MAP",
                              _sq_severity("MINOR"), line=l, column=c)
                elif member == "EMPTY_SET" and "Collections" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EMPTY_SET",
                              "S3032: 应使用 Collections.emptySet() 替代 EMPTY_SET",
                              _sq_severity("MINOR"), line=l, column=c)

        # S3046: wait should be in a loop
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "wait":
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Object" in q or not q:
                        for path2, node2 in tree:
                            if isinstance(node2, javalang_tree.IfStatement):
                                cond = getattr(node2, "condition", None)
                                if cond and "!" in str(cond) and "=" not in str(cond):
                                    break
                        else:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_WAIT_IN_LOOP",
                                      "S3046: wait() 应在循环中调用，避免虚假唤醒",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S3056: ConcurrentHashMap should be used for concurrent access
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name == "HashMap" or type_name == "java.util.HashMap":
                    for path2, node2 in tree:
                        if isinstance(node2, javalang_tree.SynchronizedStatement):
                            pass

        # S3065: Non-thread-safe should not be static
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = list(node.modifiers or [])
                if "static" in modifiers and "volatile" not in modifiers and \
                   "final" not in modifiers and "synchronized" not in modifiers:
                    type_node = getattr(node, "type", None)
                    if type_node:
                        type_name = _get_full_type_name(type_node)
                        if type_name in ("HashMap", "HashSet", "ArrayList",
                                         "SimpleDateFormat", "DecimalFormat"):
                            for decl in getattr(node, "declarators", []) or []:
                                name = getattr(decl, "name", "")
                                if name:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_NON_THREAD_SAFE_STATIC",
                                              "S3065: 非线程安全的 '" + type_name + "' 不应声明为 static",
                                              _sq_severity("MAJOR"), line=l, column=c)
                                    break

        # S3066: Enum with mutable field
        for path, node in tree:
            if isinstance(node, javalang_tree.EnumDeclaration):
                enum_body = getattr(node, "body", None)
                declarations = getattr(enum_body, "declarations", []) if enum_body else []
                for decl in declarations:
                    if isinstance(decl, javalang_tree.FieldDeclaration):
                        if "final" not in (decl.modifiers or []):
                            for var in getattr(decl, "declarators", []) or []:
                                name = getattr(var, "name", "")
                                if name:
                                    l, c = self._pos(var)
                                    self._add(file_path, "SONAR_ENUM_MUTABLE_FIELD",
                                              "S3066: 枚举字段 '" + name + "' 应声明为 final",
                                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Robustness ====================

    def check_robustness(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_robustness"):
            return
        lines = content.split("\n")

        # S1060: Multiple public classes in one file
        public_classes = []
        for path, node in tree:
            if isinstance(node, (javalang_tree.ClassDeclaration, javalang_tree.InterfaceDeclaration,
                                 javalang_tree.EnumDeclaration)):
                if "public" in (node.modifiers or []):
                    public_classes.append(node.name)
        if len(public_classes) > 1:
            for clazz in public_classes:
                self._add(file_path, "SONAR_MULTIPLE_PUBLIC_CLASSES",
                          "S1060: 文件中包含多个 public 类/接口",
                          _sq_severity("MAJOR"), line=0)

        # S1200: Classes should not be coupled to too many classes (>20)
        referenced_names = set()
        for path, node in tree:
            if isinstance(node, javalang_tree.ReferenceType):
                name = _get_full_type_name(node)
                if name and not name.startswith("java.lang."):
                    referenced_names.add(name)
        if len(referenced_names) > 20:
            for path, node in tree:
                if isinstance(node, javalang_tree.ClassDeclaration):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_HIGH_COUPLING",
                              "S1200: 类耦合度过高（引用了 " + str(len(referenced_names)) + " 个类型），建议拆分",
                              _sq_severity("MAJOR"), line=l, column=c)
                    break

        # S1241: equals/hashCode should not be called on arrays
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("equals", "hashCode"):
                    q = str(getattr(node, "qualifier", "") or "")
                    if q and "[]" not in q and "array" not in q.lower():
                        pass

        # S1309: @SuppressWarnings with "unchecked"
        for path, node in tree:
            if isinstance(node, (javalang_tree.MethodDeclaration, javalang_tree.FieldDeclaration)):
                anns = getattr(node, "annotations", []) or []
                for ann in anns:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "SuppressWarnings":
                        ann_element = getattr(ann, "element", None)
                        if ann_element:
                            element_str = str(ann_element)
                            if "unchecked" in element_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_UNCHECKED_WARNING",
                                          "S1309: @SuppressWarnings(\"unchecked\") 应避免使用",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S1310: Subtraction from zero should be avoided
        for path, node in tree:
            if isinstance(node, javalang_tree.Literal):
                prefix_ops = getattr(node, "prefix_operators", None) or []
                val = getattr(node, "value", "")
                if "-" in prefix_ops and val in ("0", "0.0", "0L", "0f", "0d"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_NEGATIVE_ZERO",
                              "S1310: 不应使用 -0 取负值",
                              _sq_severity("MINOR"), line=l, column=c)

        # S1598: Division by zero
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "/" or op == "%":
                    right = getattr(node, "operandr", None)
                    if isinstance(right, javalang_tree.Literal):
                        val = getattr(right, "value", "")
                        if val in ("0", "0.0", "0L", "0f", "0d"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_DIVISION_BY_ZERO",
                                      "S1598: 除数为零",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S1600: Null should not be returned from array method
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                return_type = getattr(node, "return_type", None)
                if return_type:
                    dims = getattr(return_type, "dimensions", None) or []
                    is_array = any(d is None or d is not None for d in dims) if isinstance(dims, list) else bool(dims)
                    if not is_array:
                        type_str = str(return_type)
                        is_array = "[" in type_str or "[]" in type_str
                    if is_array:
                        body = getattr(node, "body", None) or []
                        for stmt in body:
                            if isinstance(stmt, javalang_tree.ReturnStatement):
                                expr = getattr(stmt, "expression", None)
                                if isinstance(expr, javalang_tree.Literal) and \
                                   getattr(expr, "value", "") == "null":
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_RETURN_NULL_ARRAY",
                                              "S1600: 不应返回 null 数组，应返回空数组",
                                              _sq_severity("MAJOR"), line=l, column=c)

        # S1700: Method name same as field (already in sonarqube_rules.py)
        # S1725: Naming convention

        # S1761: Return from finally should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                finally_block = getattr(node, "finally_block", None) or []
                for stmt in finally_block:
                    if isinstance(stmt, javalang_tree.ReturnStatement):
                        l, c = self._pos(stmt)
                        self._add(file_path, "SONAR_FINALLY_RETURN_SEVEN",
                                  "S1761: finally 块中的 return 会覆盖 try/catch 中的 return",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1858: toString should not be called on String
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "toString" and q and not q.endswith("]"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TOSTRING_ON_STRING",
                              "S1858: 对 String 调用 toString() 是冗余的",
                              _sq_severity("MINOR"), line=l, column=c)

        # S1909: Assignments in sub-expressions
        # S1940: Boolean inversion
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "!=" and isinstance(getattr(node, "operandl", None), javalang_tree.Literal) and \
                   isinstance(getattr(node, "operandr", None), javalang_tree.Literal):
                    pass

        # S2125: instanceof should not be used with primitive wrappers
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "instanceof":
                    right = getattr(node, "operandr", None)
                    if right and isinstance(right, javalang_tree.ReferenceType):
                        type_name = _get_full_type_name(right)
                        if type_name in ("Integer", "Long", "Boolean", "Double",
                                         "Float", "Short", "Byte", "Character"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_INSTANCEOF_WRAPPER",
                                      "S2125: 不应使用 instanceof 检测包装类型，应使用 Class 方法",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2175: Collection isEmpty should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "==":
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    if isinstance(left, javalang_tree.MethodInvocation) and \
                       getattr(left, "member", "") == "size" and \
                       right and isinstance(right, javalang_tree.Literal) and \
                       getattr(right, "value", "") == "0":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SIZE_EQ_ZERO",
                                  "S2175: list.size() == 0 应替换为 list.isEmpty()",
                                  _sq_severity("MINOR"), line=l, column=c)

    # ==================== Performance Seven ====================

    def check_performance_seven(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_performance_seven"):
            return

        # S1155: Collection.size() == 0 should be isEmpty()
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("==", "!=", "<", ">", "<=", ">="):
                    left = str(getattr(node, "operandl", ""))
                    if ".size()" in left:
                        right = getattr(node, "operandr", None)
                        if right and isinstance(right, javalang_tree.Literal):
                            val = getattr(right, "value", "")
                            if val in ("0", "1"):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_SIZE_ISEMPTY_SEVEN",
                                          "S1155: 应使用 isEmpty() 替代 size() == 0",
                                          _sq_severity("MINOR"), line=l, column=c)

        # S1711: Standard charset should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "getBytes":
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 0:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_GETBYTES_CHARSET",
                                  "S1711: getBytes() 应指定字符集，避免平台依赖",
                                  _sq_severity("MAJOR"), line=l, column=c)
                if member == "getBytes" and len(args) == 1:
                    pass

        # S2134: String split with one char
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "split":
                    args = getattr(node, "arguments", []) or []
                    if args and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val and len(val) == 3 and val[0] == '"' and val[2] == '"':
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_SPLIT_SINGLE_CHAR",
                                      "S2134: split() 传入单字符字符串时，应使用 Guava Splitter 或 Pattern",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S2143: ThreadLocal should be removed when no longer needed
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    if type_name == "ThreadLocal" or type_name.startswith("ThreadLocal<"):
                        if "static" not in (node.modifiers or []):
                            for decl in getattr(node, "declarators", []) or []:
                                name = getattr(decl, "name", "")
                                if name:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_THREADLOCAL_NONSTATIC",
                                              "S2143: ThreadLocal 实例应声明为 static",
                                              _sq_severity("MAJOR"), line=l, column=c)

        # S2154: Integer division in floating-point context
        for path, node in tree:
            if isinstance(node, javalang_tree.VariableDeclaration):
                type_node = getattr(node, "type", None)
                if type_node and hasattr(type_node, "name"):
                    tname = getattr(type_node, "name", "")
                    if tname in ("float", "double", "Float", "Double"):
                        for decl in getattr(node, "declarators", []) or []:
                            init = getattr(decl, "initializer", None)
                            if isinstance(init, javalang_tree.BinaryOperation):
                                op = getattr(init, "operator", "")
                                if op == "/":
                                    left = getattr(init, "operandl", None)
                                    right = getattr(init, "operandr", None)
                                    if left and not isinstance(left, javalang_tree.Literal) or \
                                       not str(left).endswith("f") if isinstance(left, javalang_tree.Literal) else True:
                                        pass
        # S2234: Method parameters should match
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                args = getattr(node, "arguments", []) or []
                if len(args) >= 2:
                    last_arg = args[-1]
                    second_last = args[-2]
                    if isinstance(last_arg, javalang_tree.Literal) and \
                       isinstance(second_last, javalang_tree.Literal):
                        lv = getattr(last_arg, "value", "")
                        slv = getattr(second_last, "value", "")
                        if lv and slv:
                            pass

        # S2259: Null should not be checked with == on non-null
        # S2912: indexOf should not be compared with >
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == ">":
                    left = str(getattr(node, "operandl", ""))
                    right = str(getattr(node, "operandr", ""))
                    if ".indexOf(" in left and right == "0":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_INDEXOF_GT_ZERO",
                                  "S2912: indexOf() > 0 应替换为 contains() 或 indexOf() >= 0",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S3030: Math.abs should not be used on negative values
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "abs" and "Math" in q:
                    args = getattr(node, "arguments", []) or []
                    if args and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val and val.startswith("-"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_MATH_ABS_NEG",
                                      "S3030: Math.abs(Integer.MIN_VALUE) 可能返回负数",
                                      _sq_severity("MAJOR"), line=l, column=c)

    # ==================== API Usage ====================

    def check_api_usage(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_api_usage"):
            return
        lines = content.split("\n")

        # S1844: Object.finalize() should not be called
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "finalize":
                    q = str(getattr(node, "qualifier", "") or "")
                    if q and q != "super":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FINALIZE_CALL_API",
                                  "S1844: 不应显式调用 finalize()",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1872: Class.forName should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "forName" and "Class" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CLASS_FORNAME",
                              "S1872: 应避免使用 Class.forName()，建议使用类型安全的加载方式",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1873: Properties should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name == "Properties" or type_name == "java.util.Properties":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PROPERTIES_API",
                              "S1873: Properties 是遗留 API，建议使用更安全的配置方式",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2119: DateFormat should not be used locally
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name in ("SimpleDateFormat", "java.text.SimpleDateFormat"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SIMPLE_DATE_FORMAT",
                              "S2119: SimpleDateFormat 非线程安全，应使用 DateTimeFormatter",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2126: Runtime.exec should not be used (already in sonarqube_rules.py)

        # S2135: Statement.execute should be preferred
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("executeQuery", "executeUpdate"):
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Statement" in q:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_STATEMENT_EXECUTE",
                                  "S2135: 应使用 execute() 替代 executeQuery()/executeUpdate()",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S2136: Closeable should be closed in finally block
        # S2145: URL should be constructed properly
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name == "URL" or type_name == "java.net.URL":
                    args = getattr(node, "arguments", []) or []
                    if args and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val and val.startswith('"') and "http" in val.lower():
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_URL_CONSTRUCTION",
                                      "S2145: URL 构造应使用 URI 方式或处理 MalformedURLException",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2159: Clone should not be overridden
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "clone":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CLONE_OVERRIDE",
                              "S2159: 优先使用拷贝工厂或拷贝构造替代 clone()",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2165: ThreadLocal with mutable objects
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    if "ThreadLocal" in type_name:
                        for decl in getattr(node, "declarators", []) or []:
                            init = getattr(decl, "initializer", None)
                            if init:
                                init_str = str(init)
                                if "new " in init_str and "()" in init_str and \
                                   "initialValue" not in init_str and "withInitial" not in init_str:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_THREADLOCAL_MUTABLE",
                                              "S2165: ThreadLocal 中存储可变对象应重写 initialValue()",
                                              _sq_severity("MAJOR"), line=l, column=c)

        # S2296: Parentheses should not be used unnecessarily
        # S2388: Method chaining on collections

        # S2441: ThreadLocal should be static
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    if "ThreadLocal" in type_name:
                        if "static" not in (node.modifiers or []):
                            for decl in getattr(node, "declarators", []) or []:
                                name = getattr(decl, "name", "")
                                if name:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_THREADLOCAL_STATIC_SEVEN",
                                              "S2441: ThreadLocal 应声明为 static 以避免内存泄漏",
                                              _sq_severity("MAJOR"), line=l, column=c)

        # S2442: Synchronized class should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name in ("StringBuffer", "Vector", "Hashtable", "Stack"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SYNC_CLASS_USAGE",
                              "S2442: " + type_name + " 是同步类，在单线程环境下应使用非同步替代",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2671: Thread.yield should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "yield" and "Thread" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_THREAD_YIELD_API",
                              "S2671: Thread.yield() 行为不可预测，应避免使用",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2675: read(byte[]) return value should be checked (already in five)
        # S2688: read should not be used
        # S2692: indexOf should be contains (in sonarqube_rules.py)

        # S3012: Array as List should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "asList" and "Arrays" in q:
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 1 and isinstance(args[0], javalang_tree.MemberReference):
                        ref_member = getattr(args[0], "member", "")
                        ref_qualifier = str(getattr(args[0], "qualifier", "") or "")
                        if ref_member and not ref_qualifier:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_ARRAY_ASLIST",
                                      "S3012: Arrays.asList() 返回固定大小列表，修改会导致异常",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S3034: Files should be read properly
        # S3042: Optional.orElseGet should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "orElse":
                    args = getattr(node, "arguments", []) or []
                    if args and not isinstance(args[0], javalang_tree.Literal):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_OPTIONAL_ORELSEGET",
                                  "S3042: Optional.orElse(T) 在 T 需要计算时，应使用 orElseGet()",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S3251: Methods should not be empty (already covered)
        # S3254: Cast should not be redundant

        # S3328: Cipher instantiation should specify transformation
        # S3347: HTTP response splitting

        # S3355: Filter should be used with stream
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "forEach":
                    q = str(getattr(node, "qualifier", "") or "")
                    if ".stream()." in q or ".list()." in q:
                        pass

        # S3366: Thread.start should not be called in constructor
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "__init__":
                    for path2, node2 in tree:
                        if isinstance(node2, javalang_tree.MethodInvocation):
                            member = getattr(node2, "member", "")
                            if member == "start" and "Thread" in str(getattr(node2, "qualifier", "")):
                                l, c = self._pos(node2)
                                self._add(file_path, "SONAR_THREAD_START_INIT",
                                          "S3366: 不应在构造函数中调用 Thread.start()",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S3422: File.separator should not be hardcoded
        for i, line in enumerate(lines, 1):
            if '"/"' in line and 'File' in line or '"\\\\"' in line:
                self._add(file_path, "SONAR_FILE_SEPARATOR_API",
                          "S3422: 不应硬编码文件分隔符，应使用 File.separator",
                          _sq_severity("MINOR"), line=i)

        # S3436: valueOf should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "valueOf" and q in ("String", "Integer", "Long",
                                                  "Boolean", "Double", "Float",
                                                  "Short", "Byte"):
                    args = getattr(node, "arguments", []) or []
                    if args and isinstance(args[0], javalang_tree.Literal):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_VALUEOF_REDUNDANT",
                                  "S3436: 字面量不应使用 valueOf()，直接赋值即可",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S3451: For loop with break/continue should be simplified
        # S3516: Collection iteration should not use index
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                body = node.body
                if body is None:
                    continue
                body_str = str(body)
                if ".get(" in body_str and ".size()" in body_str:
                    init = getattr(node, "init", None)
                    if init and isinstance(init, javalang_tree.VariableDeclaration):
                        for decl in getattr(init, "declarators", []) or []:
                            name = getattr(decl, "name", "")
                            if name and ".get(" + name + ")" in body_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_FOR_INDEX_ITERATION",
                                          "S3516: 使用索引遍历集合，应使用增强型 for 循环",
                                          _sq_severity("MAJOR"), line=l, column=c)
                                break

        # S3553: Optional should not be used as parameter (in five)
        # S3599: Double-checked locking
        # S3616: Array to List conversion
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "asList" and "Arrays" in q:
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 1 and isinstance(args[0], javalang_tree.MemberReference):
                        pass

        # S3629: Stream should be used
        # S3631: System.arraycopy should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                body = node.body
                if body is None:
                    continue
                stmts = body.statements if hasattr(body, "statements") else \
                        (body if isinstance(body, list) else [])
                for stmt in stmts:
                    stmt_str = str(stmt)
                    if "[" in stmt_str and "=" in stmt_str and "i" in stmt_str:
                        pass
