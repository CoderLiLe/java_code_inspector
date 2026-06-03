"""SonarQubeCheckerThirteen — 第十三批规则"""
"""SonarQubeCheckerThirteen — 第十三批规则"""
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


def _get_base_type_name(t):
    return _get_full_type_name(t).split(".")[-1]


class SonarQubeCheckerThirteen:
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
        self.check_framework_complete(tree, file_path, content)
        self.check_final_edge_cases(tree, file_path, content)
        self.check_java_twelve_plus(tree, file_path, content)
        self.check_code_patterns_extra(tree, file_path, content)

    @staticmethod
    def _short_ann_name(ann):
        return getattr(ann, "name", "").split(".")[-1]

    # ==================== Framework / JPA / REST / Logging ====================

    def check_framework_complete(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_framework_complete"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang_tree.Annotation):
                short_name = self._short_ann_name(node)
                if short_name in ("EJB", "Stateful", "Stateless", "MessageDriven",
                                  "PersistenceContext", "PersistenceUnit"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_JEE_RESOURCE",
                              "S1441: 建议优先使用 CDI (@Inject) 替代 EJB 注解",
                              _sq_severity("MINOR"), line=l, column=c)
                if short_name in ("Entity", "Table", "Column", "Id", "GeneratedValue"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_JPA_ENTITY",
                              "S4871: JPA 实体应重写 equals 和 hashCode",
                              _sq_severity("MAJOR"), line=l, column=c)
                if short_name == "Named":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_NAMED_CDI",
                              "S4738: 建议使用 @Inject 限定符而非 @Named",
                              _sq_severity("MINOR"), line=l, column=c)
                if short_name == "Value":
                    element = getattr(node, "element", None)
                    if element and hasattr(element, "value") and isinstance(getattr(element, "value", None), str):
                        val = element.value
                        if not val.startswith("${") and not val.startswith("#{"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_SPRING_VALUE",
                                      "S4682: @Value 应从配置属性获取值，而非硬编码",
                                      _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node) if type_node else ""
                if type_name in ("java.sql.DriverManager", "DriverManager",
                                 "java.net.HttpURLConnection", "HttpURLConnection"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_DIRECT_CONNECTION",
                              "S1475: 应使用连接池而非直接创建连接",
                              _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("addHeader", "setHeader", "setStatus"):
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        if hasattr(arg, "value") and isinstance(getattr(arg, "value", None), str):
                            val = arg.value
                            if re.search(r'\\[rn]', val):
                                l, c = self._pos(arg)
                                self._add(file_path, "SONAR_HEADER_INJECTION",
                                          "S4492: HTTP 响应头中可能包含 CRLF 注入",
                                          _sq_severity("CRITICAL"), line=l, column=c)
                                break

        for i, line in enumerate(lines, 1):
            if re.search(r'@RequestMapping\s*\(\s*["\']/actuator', line):
                self._add(file_path, "SONAR_ACTUATOR_EXPOSED",
                          "S4719: Spring Actuator 端点暴露可能存在安全风险",
                          _sq_severity("MAJOR"), line=i)

    # ==================== Final Edge Cases ====================

    def check_final_edge_cases(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_final_edge_cases"):
            return

        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                for i, case in enumerate(cases):
                    stmts = getattr(case, "statements", []) or []
                    if stmts and not isinstance(stmts[-1], (javalang_tree.BreakStatement,
                                                            javalang_tree.ReturnStatement,
                                                            javalang_tree.ThrowStatement)):
                        next_cases = cases[i+1:]
                        if next_cases:
                            next_labels = [str(getattr(c, "case", "")) for c in next_cases
                                           if getattr(c, "case", None) is not None]
                            if next_labels:
                                l, c = self._pos(case)
                                self._add(file_path, "SONAR_SWITCH_FALLTHROUGH",
                                          "S1219: switch case 缺少 break，可能非故意穿透",
                                          _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.CatchClause):
                param = getattr(node, "parameter", None)
                if param:
                    param_name = getattr(param, "name", "")
                    block = getattr(node, "block", []) or []
                    block_str = str(block)
                    if param_name and (not block or param_name not in block_str):
                        l, c = self._pos(param)
                        self._add(file_path, "SONAR_UNUSED_CATCH_PARAM",
                                  "S1291: 捕获的异常参数未使用",
                                  _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.Annotation):
                short_name = self._short_ann_name(node)
                if short_name == "SuppressWarnings":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SUPPRESS_WARNING",
                              "S1309: 应避免使用 @SuppressWarnings",
                              _sq_severity("MINOR"), line=l, column=c)

            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "instanceof":
                    left = getattr(node, "operandl", None)
                    if left and isinstance(left, javalang_tree.Literal) and \
                       str(getattr(left, "value", "")).strip().lower() == "null":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_NULL_INSTANCEOF",
                                  "S1310: instanceof 对 null 检查多余",
                                  _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.MethodDeclaration):
                name = getattr(node, "name", "")
                if name in ("finalize",):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_FINALIZE",
                              "S1274: 不应重写 finalize 方法",
                              _sq_severity("MAJOR"), line=l, column=c)
                modifiers = node.modifiers or []
                if "synchronized" in modifiers:
                    if name in ("compareTo", "clone"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SYNC_OVERRIDE",
                                  "S1282: synchronized 方法应使用同步块替代",
                                  _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "printStackTrace":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PRINT_STACKTRACE",
                              "S1789: 应使用日志框架记录异常而非 printStackTrace",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Java 12+ Features ====================

    def check_java_twelve_plus(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_java_twelve_plus"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.BinaryOperation):
                    op = getattr(cond, "operator", "")
                    if op == "instanceof":
                        right = getattr(cond, "operandr", None)
                        if right:
                            right_str = str(right)
                            then_stmts = []
                            then_body = getattr(node, "then_statement", None)
                            if then_body:
                                then_stmts = getattr(then_body, "statements", []) if hasattr(then_body, "statements") else \
                                             (then_body if isinstance(then_body, list) else [])
                            for stmt in then_stmts:
                                if isinstance(stmt, javalang_tree.LocalVariableDeclaration):
                                    var_type = getattr(stmt, "type", None)
                                    if var_type:
                                        base = _get_base_type_name(var_type)
                                        if base and base in right_str:
                                            l, c = self._pos(node)
                                            self._add(file_path, "SONAR_PATTERN_INSTANCEOF",
                                                      "S6201: 可使用模式匹配 instanceof 简化",
                                                      _sq_severity("MINOR"), line=l, column=c)
                                            break

            if isinstance(node, javalang_tree.ClassDeclaration):
                body = getattr(node, "body", []) or []
                method_count = sum(1 for d in body if isinstance(d, javalang_tree.MethodDeclaration))
                field_count = sum(1 for d in body if isinstance(d, javalang_tree.FieldDeclaration))
                ctor_count = sum(1 for d in body
                                 if isinstance(d, javalang_tree.ConstructorDeclaration))
                if field_count >= 2 and ctor_count >= 1 and method_count <= 3:
                    for d in body:
                        if isinstance(d, javalang_tree.MethodDeclaration) and d.name in ("equals", "hashCode", "toString"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_RECORD_ELIGIBLE",
                                      "S6207: 简单数据类可考虑改为 record",
                                      _sq_severity("INFO"), line=l, column=c)
                            break

            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node) if type_node else ""
                if "StringBuilder" in type_name:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_RECORD_STRING_TEMPLATE",
                              "S6211: 考虑使用 String Templates 替代 StringBuilder",
                              _sq_severity("INFO"), line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r'\b(sealed)\s+class\b', line) and not re.search(r'\bpermits\b', line):
                self._add(file_path, "SONAR_SEALED_PERMITS",
                          "S6222: sealed 类应使用 permits 声明许可子类",
                          _sq_severity("MAJOR"), line=i)

            if re.search(r'\bswitch\s*\([^)]*\)\s*\{[^}]*case\s+null\s*:', line):
                pass

            if re.search(r'\bswitch\s*\(', line) and re.search(r'\b(yield|->)\b', line):
                pass

    # ==================== Extra Code Patterns ====================

    def check_code_patterns_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_code_patterns_extra"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "toArray":
                    args = getattr(node, "arguments", []) or []
                    if not args:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TOARRAY_TYPED",
                                  "S1725: Collection.toArray() 应使用带类型参数的形式",
                                  _sq_severity("MAJOR"), line=l, column=c)

                if member in ("addHeader", "setHeader"):
                    pass

            if isinstance(node, javalang_tree.EnumDeclaration):
                body = getattr(node, "body", None)
                declarations = getattr(body, "declarations", []) if body else []
                for decl in declarations:
                    if isinstance(decl, javalang_tree.MethodDeclaration) and decl.name == "toString":
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_ENUM_TOSTRING",
                                  "S1744: 枚举不应重写 toString",
                                  _sq_severity("MINOR"), line=l, column=c)

            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node) if type_node else ""
                if type_name in ("java.lang.Boolean", "java.lang.Integer",
                                 "java.lang.Long", "java.lang.Double",
                                 "java.lang.Short", "java.lang.Byte",
                                 "java.lang.Float", "java.lang.Character"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PRIMITIVE_WRAPPER",
                              "S1778: 应使用 valueOf() 而非 new Boolean() 等构造器",
                              _sq_severity("MAJOR"), line=l, column=c)

            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "==":
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    left_is_str = isinstance(left, javalang_tree.Literal) and \
                                  isinstance(getattr(left, "value", None), str) and \
                                  len(getattr(left, "value", "")) > 0
                    right_is_str = isinstance(right, javalang_tree.Literal) and \
                                   isinstance(getattr(right, "value", None), str) and \
                                   len(getattr(right, "value", "")) > 0
                    if left_is_str or right_is_str:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_REF_EQUALS",
                                  "S1775: 字符串比较应使用 equals() 而非 ==",
                                  _sq_severity("MAJOR"), line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r'\.toArray\(\)', line) and not re.search(r'\.toArray\(new', line):
                pass

            if re.search(r'\[\].*\.toString\(\)', line) or \
               re.search(r'\.toString\(\s*\)', line) and \
               re.search(r'\bnew\s+\w+\s*\[\d*\]', lines[i-1] if i-1 < len(lines) else ""):
                pass

            if re.search(r'\bprintStackTrace\(\)', line):
                pass
