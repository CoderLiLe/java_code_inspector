import re
from typing import List

import javalang
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


class SonarQubeCheckerFive:
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

    _METHOD_BLACKLIST = {
        "main", "toString", "equals", "hashCode", "getClass",
        "notify", "notifyAll", "wait", "finalize", "clone",
    }

    def run_all(self, tree, file_path: str, content: str):
        self.check_bugs_extra(tree, file_path, content)
        self.check_convention_extra(tree, file_path, content)
        self.check_maintainability(tree, file_path, content)

    # ==================== Bugs Extra ====================

    def check_bugs_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_bugs_extra"):
            return

        # S1067: Expressions should not be too complex
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("&&", "||", "&", "|"):
                    op_count = [0]
                    def count_ops(n):
                        if isinstance(n, javalang_tree.BinaryOperation):
                            o = getattr(n, "operator", "")
                            if o in ("&&", "||", "&", "|"):
                                op_count[0] += 1
                        for child in getattr(n, "children", []) or []:
                            if isinstance(child, (list, tuple)):
                                for c in child:
                                    if hasattr(c, "children"):
                                        count_ops(c)
                            elif hasattr(child, "children"):
                                count_ops(child)
                    count_ops(node)
                    if op_count[0] >= 3:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_COMPLEX_EXPRESSION",
                                  "S1067: 表达式过于复杂（包含 " + str(op_count[0]) +
                                  " 个逻辑运算符），建议提取局部变量",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1121: Assignments in sub-expressions (e.g. if (x = y()))
        for path, node in tree:
            if isinstance(node, javalang_tree.Assignment):
                assignment_str = str(node)
                for path2, node2 in tree:
                    if isinstance(node2, javalang_tree.IfStatement) or \
                       isinstance(node2, javalang_tree.WhileStatement) or \
                       isinstance(node2, javalang_tree.ForStatement):
                        stmt_str = str(node2)
                        if "=" in stmt_str and "==" not in stmt_str:
                            pass
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "=":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ASSIGN_IN_SUBEXPR",
                              "S1121: 不应在子表达式中使用赋值，可能是 == 之误",
                              _sq_severity("MAJOR"), line=l, column=c)
                    break

        # S1147: System.exit should not be called
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = getattr(node, "qualifier", "") or ""
                if member == "exit" and "System" in qualifier:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SYSTEM_EXIT",
                              "S1147: 不应调用 System.exit()，应抛出异常或返回状态码",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2447: NullPointerException should not be thrown
        for path, node in tree:
            if isinstance(node, javalang_tree.ThrowStatement):
                expr = getattr(node, "expression", None)
                if expr and isinstance(expr, javalang_tree.ClassCreator):
                    type_node = getattr(expr, "type", None)
                    type_name = _get_full_type_name(type_node)
                    if "NullPointerException" in type_name:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_NPE_THROWN",
                                  "S2447: 不应显式抛出 NullPointerException，应使用 NullPointerException 检查",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2259: Null pointer dereference (simple patterns)
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.BinaryOperation):
                    op = getattr(cond, "operator", "")
                    if op == "!=":
                        left = getattr(cond, "operandl", None)
                        right = getattr(cond, "operandr", None)
                        null_side = None
                        var_side = None
                        if isinstance(left, javalang_tree.Literal) and \
                           getattr(left, "value", "") == "null":
                            null_side, var_side = left, right
                        elif isinstance(right, javalang_tree.Literal) and \
                             getattr(right, "value", "") == "null":
                            null_side, var_side = right, left
                        if var_side and hasattr(var_side, "member"):
                            var_name = getattr(var_side, "member", "")
                            then_stmt = getattr(node, "then_statement", None)
                            if then_stmt:
                                then_str = str(then_stmt)
                                if var_name and var_name in then_str and \
                                   "." in then_str[then_str.find(var_name):then_str.find(var_name)+len(var_name)+5]:
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_NULL_DEREF",
                                              "S2259: 变量 '" + var_name +
                                              "' 在 null 检查之后被解引用",
                                              _sq_severity("MAJOR"), line=l, column=c)

        # S3296: Pattern.compile should not be inside loop
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement) or \
               isinstance(node, javalang_tree.WhileStatement):
                body = node.body
                if body is None:
                    continue
                stmts = body.statements if hasattr(body, "statements") else \
                        (body if isinstance(body, list) else [])
                for stmt in stmts:
                    expr = getattr(stmt, "expression", None)
                    if expr and isinstance(expr, javalang_tree.MethodInvocation):
                        member = getattr(expr, "member", "")
                        qualifier = getattr(expr, "qualifier", "") or ""
                        if member == "compile" and "Pattern" in qualifier:
                            l = getattr(getattr(expr, "position", None), "line", 0)
                            self._add(file_path, "SONAR_PATTERN_LOOP",
                                      "S3296: Pattern.compile() 不应放在循环中，应提取为常量",
                                      _sq_severity("MAJOR"), line=l)
                            break
                        elif member == "matches" and "Pattern" in qualifier:
                            l = getattr(getattr(expr, "position", None), "line", 0)
                            self._add(file_path, "SONAR_PATTERN_LOOP",
                                      "S3296: Pattern.matches() 不应放在循环中，应提取为常量",
                                      _sq_severity("MAJOR"), line=l)
                            break

        # S4141: List.size() should not be used in loop condition
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                control = getattr(node, "control", None)
                condition = getattr(control, "condition", None) if control else None
                if condition and isinstance(condition, javalang_tree.BinaryOperation):
                    for side in (getattr(condition, "operandl", None),
                                 getattr(condition, "operandr", None)):
                        if isinstance(side, javalang_tree.MethodInvocation) and \
                           getattr(side, "member", "") in ("size", "length"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_LOOP_SIZE",
                                      "S4141: 不应在循环条件中调用 .size()/.length()，建议提取到局部变量",
                                      _sq_severity("MAJOR"), line=l, column=c)
                            break

    # ==================== Convention Extra ====================

    def check_convention_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_convention_extra"):
            return
        lines = content.split("\n")

        # S1104: Fields should not have public accessibility
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "public" in modifiers and "static" not in modifiers and \
                   "final" not in modifiers:
                    for declarator in getattr(node, "declarators", []) or []:
                        name = getattr(declarator, "name", "")
                        if name:
                            l, c = self._pos(declarator)
                            self._add(file_path, "SONAR_PUBLIC_FIELD",
                                      "S1104: 非静态字段 '" + name +
                                      "' 不应声明为 public，建议使用 private + getter",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S1144: Unused private methods
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if "private" in (node.modifiers or []):
                    if node.name in self._METHOD_BLACKLIST:
                        continue
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_UNUSED_PRIVATE_METHOD",
                              "S1144: 私有方法 '" + node.name + "' 可能未使用",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1161: @Override annotation should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                modifiers = node.modifiers or []
                if "override" in [m.lower() for m in modifiers]:
                    continue
                annotations = getattr(node, "annotations", None) or []
                has_override = False
                for ann in annotations:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "Override":
                        has_override = True
                        break
                if not has_override:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_OVERRIDE_MISSING",
                              "S1161: 重写方法应添加 @Override 注解",
                              _sq_severity("MINOR"), line=l, column=c)

        # S1170: public static final constants should be UPPER_CASE
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "public" in modifiers and "static" in modifiers and "final" in modifiers:
                    for declarator in getattr(node, "declarators", []) or []:
                        name = getattr(declarator, "name", "")
                        if name and name != name.upper() and \
                           not all(c == "_" for c in name):
                            l, c = self._pos(declarator)
                            self._add(file_path, "SONAR_CONSTANT_CASE",
                                      "S1170: 常量 '" + name + "' 应使用全大写+下划线格式",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S1611: Method references should be used (lambda -> method ref)
        for path, node in tree:
            if isinstance(node, javalang_tree.LambdaExpression):
                lambda_str = str(node).replace(" ", "")
                patterns = [
                    r"x->x\.(\w+)\(",
                    r"\(\w+\)->\w+\.(\w+)\(",
                ]
                for pat in patterns:
                    m = re.search(pat, lambda_str)
                    if m:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_METHOD_REFERENCE",
                                  "S1611: Lambda 表达式可以替换为方法引用 '" + m.group(1) + "'",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S3740: Raw types should not be used
        raw_type_names = {"List", "Map", "Set", "ArrayList", "HashMap",
                          "HashSet", "LinkedList", "Vector", "Hashtable",
                          "Collection", "Optional", "Comparator",
                          "Iterator", "Iterable", "Enumeration"}
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node and isinstance(type_node, javalang_tree.ReferenceType):
                    type_args = getattr(type_node, "arguments", None)
                    if type_args is None:
                        full_name = _get_full_type_name(type_node)
                        base_name = full_name.split(".")[-1] if "." in full_name else full_name
                        if base_name in raw_type_names:
                            for declarator in getattr(node, "declarators", []) or []:
                                l, c = self._pos(declarator)
                                self._add(file_path, "SONAR_RAW_TYPE",
                                          "S3740: 原始类型 '" + full_name +
                                          "' 应带泛型参数（如 List<String>）",
                                          _sq_severity("MAJOR"), line=l, column=c)
                                break

        # S2333: Redundant modifiers (interface methods are implicitly public)
        for path, node in tree:
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if "public" in (decl.modifiers or []):
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_REDUNDANT_MODIFIER",
                                      "S2333: 接口方法隐式为 public，无需显式声明",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S1871: Switch with redundant branches (duplicate case logic)
        case_bodies = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                for case in cases:
                    stmts = getattr(case, "statements", []) or []
                    body_str = " ".join(str(s) for s in stmts)
                    if body_str:
                        case_labels = getattr(case, "case", [])
                        label_strs = [str(cl) for cl in case_labels] if \
                                     isinstance(case_labels, list) else [str(case_labels)]
                        for ls in label_strs:
                            if ls in case_bodies:
                                prev_body = case_bodies[ls]
                                if body_str == prev_body:
                                    l, c = self._pos(case)
                                    self._add(file_path, "SONAR_DUPLICATE_BRANCH",
                                              "S1871: switch 分支与 '" + ls + "' 分支逻辑重复",
                                              _sq_severity("MAJOR"), line=l, column=c)
                            else:
                                case_bodies[ls] = body_str

    # ==================== Maintainability ====================

    def check_maintainability(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_maintainability"):
            return
        lines = content.split("\n")

        # S1153: Number comparison with == (Integer/Long on non-cached range)
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("==", "!="):
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    left_type = type(left).__name__ if left else ""
                    right_type = type(right).__name__ if right else ""
                    if "MethodInvocation" in (left_type, right_type) or \
                       "MemberReference" in (left_type, right_type):
                        op_str = str(node).replace(" ", "")
                        if "Integer." in op_str or "Long." in op_str or \
                           "Short." in op_str or "Byte." in op_str:
                            if ".valueOf" in op_str or "parseInt" in op_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_VALUE_COMPARE_V2",
                                          "S1153: 包装类型值应使用 equals() 比较",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S1157: Case-insensitive string comparisons should use locale
        for i, line in enumerate(lines, 1):
            if re.search(r'\.toLowerCase\(\)\.equals\(', line) or \
               re.search(r'\.toUpperCase\(\)\.equals\(', line):
                self._add(file_path, "SONAR_CASE_INSENSITIVE",
                          "S1157: 大小写不敏感比较应指定 Locale，或使用 equalsIgnoreCase()",
                          _sq_severity("MINOR"), line=i)

        # S2437: Comparison of int with Integer
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("==", "!=", "<", ">", "<=", ">="):
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    for side in (left, right):
                        if isinstance(side, javalang_tree.MethodInvocation):
                            member = getattr(side, "member", "")
                            if member in ("intValue", "longValue", "shortValue",
                                          "byteValue", "doubleValue", "floatValue"):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_UNNECESSARY_UNBOXING",
                                          "S2437: 不必要的拆箱操作，可直接比较",
                                          _sq_severity("MINOR"), line=l, column=c)
                                break

        # S2674: InputStream.read() return value ignored
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "read":
                    qualifier = getattr(node, "qualifier", "") or ""
                    if qualifier and "Input" in qualifier:
                        # Check if the result is used
                        parent = path[-2] if len(path) >= 2 else None
                        if parent and isinstance(parent, javalang_tree.StatementExpression):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_READ_RETURN",
                                      "S2674: InputStream.read() 的返回值未使用，无法确认读取的字节数",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2675: InputStream.read(byte[]) should check return value
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "read":
                    args = getattr(node, "arguments", []) or []
                    if len(args) >= 1:
                        parent = path[-2] if len(path) >= 2 else None
                        if parent and isinstance(parent, javalang_tree.StatementExpression):
                            qualifier = getattr(node, "qualifier", "") or ""
                            if qualifier and "Input" in qualifier:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_READ_RETURN_CHECK",
                                          "S2675: InputStream.read(byte[]) 的返回值应检查实际读取的字节数",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S2598: Varargs should not be passed to non-varargs
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                args = getattr(node, "arguments", []) or []
                for arg in args:
                    if isinstance(arg, javalang_tree.MethodInvocation):
                        member = getattr(arg, "member", "")
                        qualifier = getattr(arg, "qualifier", "") or ""
                        if member == "asList" and "Arrays" in qualifier:
                            inner_args = getattr(arg, "arguments", []) or []
                            if len(inner_args) == 1:
                                inner_type = type(inner_args[0]).__name__
                                if inner_type == "MethodInvocation" or \
                                   "List" in str(inner_args[0]):
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_VARARG_WARNING",
                                              "S2598: 可变参数使用不当：Arrays.asList() 包装了单个集合",
                                              _sq_severity("MAJOR"), line=l, column=c)

        # S2637: @Nullable/@NonNull contracts
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                params = getattr(node, "parameters", []) or []
                for param in params:
                    type_node = getattr(param, "type", None)
                    if type_node:
                        type_name = _get_full_type_name(type_node)
                        if type_name == "Optional" or type_name.endswith(".Optional"):
                            l, c = self._pos(param)
                            self._add(file_path, "SONAR_OPTIONAL_PARAM",
                                      "S2637: 不应将 Optional 用作方法参数",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2698: File.createTempFile should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = getattr(node, "qualifier", "") or ""
                if member == "createTempFile" and "File" in qualifier:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CREATE_TEMP_FILE",
                              "S2698: 应使用 Files.createTempFile() 替代 File.createTempFile()",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2789: Redundant null check (after instanceof)
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                then_stmt = getattr(node, "then_statement", None)
                if cond and then_stmt:
                    cond_str = str(cond).replace(" ", "")
                    then_str = str(then_stmt).replace(" ", "")
                    if "!=null" in cond_str and "!=null" in then_str:
                        m = re.search(r'(\w+)\s*!=\s*null', cond_str)
                        if m:
                            var_name = m.group(1)
                            if var_name + "!=null" in then_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_REDUNDANT_NULL_CHECK",
                                          "S2789: 重复的 null 检查，条件中已检查 '" +
                                          var_name + " != null'",
                                          _sq_severity("MAJOR"), line=l, column=c)
