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


class SonarQubeCheckerNine:
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
        self.check_security_hotspots(tree, file_path, content)
        self.check_error_prone_nine(tree, file_path, content)
        self.check_miscellaneous(tree, file_path, content)

    # ==================== Security Hotspots ====================

    def check_security_hotspots(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security_hotspots"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S4834: Authorization check missing
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "PreAuthorize" not in ann_names and "Secured" not in ann_names and \
                   "RolesAllowed" not in ann_names:
                    if ann_names & {"RequestMapping", "GetMapping", "PostMapping",
                                    "PutMapping", "DeleteMapping", "PatchMapping"}:
                        body = getattr(node, "body", None)
                        has_auth_in_body = False
                        if body:
                            body_str = str(body)
                            if ".hasRole" in body_str or ".hasAuthority" in body_str or \
                               "SecurityContextHolder" in body_str:
                                has_auth_in_body = True
                        if not has_auth_in_body:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_MISSING_AUTHORIZATION",
                                      "S4834: Web 端点缺少授权检查（@PreAuthorize 等）",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S5280: CSP should be enabled
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "RequestMapping" in ann_names or "GetMapping" in ann_names:
                    body = getattr(node, "body", None)
                    if body:
                        body_str = str(body)
                        if "Content-Security-Policy" not in body_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_CSP_HEADER",
                                      "S5280: 建议设置 Content-Security-Policy 响应头",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S5693: Content-Type should be specified
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "PostMapping" or ann_name == "PutMapping":
                        ann_str = str(ann)
                        if "consumes" not in ann_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_CONTENT_TYPE",
                                      "S5693: @PostMapping/@PutMapping 应指定 consumes",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S5582: Open redirect prevention
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "sendRedirect":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_OPEN_REDIRECT_NINE",
                              "S5582: sendRedirect() 应验证目标 URL 避免开放重定向",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S5487: JSON injection
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "append" and "JSON" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_JSON_MANUAL",
                              "S5487: 应使用 JSON 库构建 JSON，避免字符串拼接",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S4830: SSL should not be disabled (additional check)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "setDefaultSSLSocketFactory" or member == "setHostnameVerifier":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SSL_DISABLED_NINE",
                              "S4830: SSL/TLS 验证不应被禁用",
                              _sq_severity("BLOCKER"), line=l, column=c)

            # S1313: Hardcoded IP (additional patterns)
            for i, line in enumerate(lines, 1):
                no_comment = re.sub(r'//.*', '', line)
                ips = re.findall(r'"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"', no_comment)
                for ip in ips:
                    if not ip.startswith("127.") and not ip.startswith("10.") and \
                       not ip.startswith("192.168.") and not ip.startswith("0."):
                        self._add(file_path, "SONAR_HARDCODED_IP_ADDRESS",
                                  "S1313: 不应硬编码 IP 地址 " + ip,
                                  _sq_severity("MAJOR"), line=i)

        # S4507: SQL injection (additional checks)
        for i, line in enumerate(lines, 1):
            no_comment = re.sub(r'//.*', '', line)
            if re.search(r'"\s*\+\s*\w+\s*\+.*(?i)(SELECT|INSERT|UPDATE|DELETE)', line):
                self._add(file_path, "SONAR_SQL_CONCATENATION",
                          "S4507: SQL 查询不应通过字符串拼接构建",
                          _sq_severity("MAJOR"), line=i)

        # S5332: Clear text protocols
        for i, line in enumerate(lines, 1):
            no_comment = re.sub(r'//.*', '', line)
            if re.search(r'new\s+URL\(\s*"http://', no_comment):
                self._add(file_path, "SONAR_CLEAR_TEXT_HTTP",
                          "S5332: 使用 http:// 而非 https:// 可能导致信息泄露",
                          _sq_severity("MAJOR"), line=i)

        # S5445: Regex injection (additional)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("matches", "replaceAll", "replaceFirst", "split"):
                    q = str(getattr(node, "qualifier", "") or "")
                    args = getattr(node, "arguments", []) or []
                    if args and not isinstance(args[0], javalang_tree.Literal):
                        if "Pattern" not in q and "String" not in q:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_REGEX_INJECTION_NINE",
                                      "S5445: 使用用户输入构造正则表达式可能导致 ReDoS",
                                      _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Error-Prone Nine ====================

    def check_error_prone_nine(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_error_prone_nine"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1241: equals/hashCode on arrays
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member in ("equals", "hashCode") and "[]" not in q:
                    for path2, node2 in tree:
                        if isinstance(node2, javalang_tree.VariableDeclaration):
                            for decl in getattr(node2, "declarators", []) or []:
                                dname = getattr(decl, "name", "")
                                if dname and dname == q:
                                    var_type = getattr(node2, "type", None)
                                    if var_type:
                                        type_str = str(var_type)
                                        if "[]" in type_str:
                                            l, c = self._pos(node)
                                            self._add(file_path, "SONAR_ARRAY_EQUALS",
                                                      "S1241: 数组应使用 Arrays.equals() 而非 equals()",
                                                      _sq_severity("MAJOR"), line=l, column=c)

            # S1849: Iterator should not be assumed to have next
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "next":
                    q = str(getattr(node, "qualifier", "") or "")
                    for path2, node2 in tree:
                        if isinstance(node2, javalang_tree.WhileStatement):
                            cond = getattr(node2, "condition", None)
                            if cond and q in str(cond) and "hasNext" in str(cond):
                                break
                        if isinstance(node2, javalang_tree.ForStatement):
                            init = getattr(node2, "init", None)
                            if init and q in str(init) and "iterator" in str(init):
                                break
                    else:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_NEXT_WITHOUT_HASNEXT",
                                  "S1849: 调用 next() 前应先检查 hasNext()",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S1948: Non-serializable field in Serializable class
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                for impl in imp:
                    impl_name = getattr(impl, "name", "") if hasattr(impl, "name") else str(impl)
                    if impl_name == "Serializable":
                        for decl in getattr(node, "body", []) or []:
                            if isinstance(decl, javalang_tree.FieldDeclaration):
                                if "transient" not in (decl.modifiers or []) and \
                                   "static" not in (decl.modifiers or []):
                                    type_node = getattr(decl, "type", None)
                                    if type_node:
                                        type_name = _get_full_type_name(type_node)
                                        base_name = type_name.split(".")[-1]
                                        if base_name not in ("String", "Integer", "Long",
                                                             "Boolean", "Double", "Float",
                                                             "Short", "Byte", "Character",
                                                             "BigDecimal", "BigInteger",
                                                             "Date", "List", "Set", "Map",
                                                             "Collection", "Optional",
                                                             "serialVersionUID"):
                                            l, c = self._pos(decl)
                                            self._add(file_path, "SONAR_NON_SERIALIZABLE",
                                                      "S1948: Serializable 类中的非 transient 字段非序列化",
                                                      _sq_severity("MAJOR"), line=l, column=c)

            # S1989: Exception should not be swallowed
            if isinstance(node, javalang_tree.CatchClause):
                body = getattr(node, "body", None) if hasattr(node, "block") else \
                       getattr(node, "block", None)
                body = getattr(node, "block", None) or getattr(node, "body", None)
                if isinstance(body, list):
                    stmts = body
                else:
                    stmts = getattr(body, "statements", []) if body else []
                has_logging = False
                for stmt in stmts:
                    stmt_str = str(stmt).lower()
                    if "log" in stmt_str or "logger" in stmt_str or \
                       "printstacktrace" in stmt_str:
                        has_logging = True
                        break
                if not has_logging and len(stmts) == 0:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SWALLOWED_EXCEPTION",
                              "S1989: 异常被吞噬未记录",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S2209: Null should not be passed where Object expected
            if isinstance(node, javalang_tree.MethodInvocation):
                args = getattr(node, "arguments", []) or []
                for arg in args:
                    if isinstance(arg, javalang_tree.Literal) and \
                       getattr(arg, "value", "") == "null":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_NULL_ARGUMENT",
                                  "S2209: 不应传递 null 字面量作为参数",
                                  _sq_severity("MAJOR"), line=l, column=c)
                        break

            # S2232: BigDecimal should be created from String
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                base_name = type_name.split(".")[-1]
                if base_name == "BigDecimal":
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 1 and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val and val.startswith('"') and val.endswith('"'):
                            pass
                        elif val and "." in val:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_BIG_DECIMAL_DOUBLE_NINE",
                                      "S2232: BigDecimal 不应使用 double 构造",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S2670: compareTo should not return constant
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "compareTo":
                    body = getattr(node, "body", None)
                    if body:
                        stmts = getattr(body, "statements", []) if hasattr(body, "statements") else \
                                (body if isinstance(body, list) else [])
                        for stmt in stmts:
                            if isinstance(stmt, javalang_tree.ReturnStatement):
                                expr = getattr(stmt, "expression", None)
                                if isinstance(expr, javalang_tree.Literal):
                                    val = getattr(expr, "value", "")
                                    if val in ("-1", "0", "1"):
                                        l, c = self._pos(node)
                                        self._add(file_path, "SONAR_COMPARETO_CONSTANT",
                                                  "S2670: compareTo() 不应返回常量",
                                                  _sq_severity("MAJOR"), line=l, column=c)
                                        break

            # S2692: indexOf should be contains (additional)
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "!=" or op == ">=":
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    left_member = getattr(left, "member", "") if hasattr(left, "member") else ""
                    right_val = getattr(right, "value", "") if hasattr(right, "value") else ""
                    right_prefix = getattr(right, "prefix_operators", None) or []
                    if left_member == "indexOf" and right_val == "1" and "-" in right_prefix:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_INDEXOF_CONTAINS_NINE",
                                  "S2692: indexOf() != -1 应替换为 contains()",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S2757: Wrong assignment operator (== vs =)
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "=":
                    for path2, node2 in tree:
                        if isinstance(node2, (javalang_tree.IfStatement,
                                              javalang_tree.WhileStatement)):
                            cond = getattr(node2, "condition", None)
                            if cond and str(cond).replace(" ", "") == str(node).replace(" ", ""):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_WRONG_ASSIGN_OPERATOR",
                                          "S2757: 条件表达式中使用 = 而非 ==",
                                          _sq_severity("MAJOR"), line=l, column=c)

            # S2924: Thread.sleep should not be used in tests
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "Test" in ann_names:
                    body = getattr(node, "body", None)
                    if body:
                        body_str = str(body).lower()
                        if "sleep(" in body_str and "thread" in body_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_SLEEP_IN_TEST",
                                      "S2924: 测试中不应使用 Thread.sleep()",
                                      _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Miscellaneous ====================

    def check_miscellaneous(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_miscellaneous"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1126: Return boolean expression directly
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if body:
                    stmts = getattr(body, "statements", []) if hasattr(body, "statements") else \
                            (body if isinstance(body, list) else [])
                    for stmt in stmts:
                        if isinstance(stmt, javalang_tree.IfStatement):
                            then_stmt = getattr(stmt, "then_statement", None)
                            else_stmt = getattr(stmt, "else_statement", None)
                            if then_stmt and else_stmt:
                                then_str = str(then_stmt)
                                else_str = str(else_stmt)
                                if "value=true" in then_str and "value=false" in else_str:
                                    l, c = self._pos(stmt)
                                    self._add(file_path, "SONAR_RETURN_BOOL_NINE",
                                              "S1126: if-else 返回布尔值应简化为 return 条件表达式",
                                              _sq_severity("MINOR"), line=l, column=c)
                                elif "value=false" in then_str and "value=true" in else_str:
                                    l, c = self._pos(stmt)
                                    self._add(file_path, "SONAR_RETURN_BOOL_NINE",
                                              "S1126: if-else 返回布尔值应简化为 return !条件表达式",
                                              _sq_severity("MINOR"), line=l, column=c)

            # S1215: System.gc should not be called (already covered)
            # S1315: Logger should be private static final
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    base_name = type_name.split(".")[-1]
                    if base_name == "Logger" or base_name == "Log":
                        modifiers = node.modifiers or []
                        if "private" not in modifiers:
                            for var in getattr(node, "declarators", []) or []:
                                name = getattr(var, "name", "")
                                if name:
                                    l, c = self._pos(var)
                                    self._add(file_path, "SONAR_LOGGER_VISIBILITY",
                                              "S1315: Logger 应声明为 private",
                                              _sq_severity("MAJOR"), line=l, column=c)
                        if "static" not in modifiers:
                            for var in getattr(node, "declarators", []) or []:
                                name = getattr(var, "name", "")
                                if name:
                                    l, c = self._pos(var)
                                    self._add(file_path, "SONAR_LOGGER_STATIC_NINE",
                                              "S1315: Logger 应声明为 static",
                                              _sq_severity("MAJOR"), line=l, column=c)

            # S1258: Variable naming (additional)
            if isinstance(node, javalang_tree.VariableDeclaration):
                for decl in getattr(node, "declarators", []) or []:
                    name = getattr(decl, "name", "")
                    if name and name.isupper() and len(name) > 1 and "_" not in name:
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_VARIABLE_UPPER_CASE",
                                  "S1258: 变量名不应全大写（常量应使用 static final）",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S1319: Use interface types (already covered)
            # S1449: Locale should be used (already covered)

            # S1596: Empty collection (already covered)

            # S1604: Lambda vs anonymous class (already covered)

            # S1659: Multiple variables on one line (already covered)

            # S1700: Method name same as field (already covered)

            # S1854: Dead store (already covered)

            # S2326: Unused type param (already covered)

            # S2386: Mutable array (already covered)

            # S2629: Log argument concatenation (already covered)

            # S2696: Static field write from instance (already covered)

            # S3242: Base type param (already covered)

            # S3358: Nested ternary (already covered)

            # S3398: Private method unused (already covered)

            # S3518: Division by zero (already covered)

            # S3959: Stream consumed (already covered)

            # S3981: Collection size to isEmpty (already covered)

            # S4143: Map overwrite (already covered)

            # S4275: Getter setter (already covered)

            # S4524: Switch default last (already covered)

            # S1123: @Deprecated should include documentation
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "Deprecated":
                        doc = getattr(node, "documentation", None)
                        if not doc or "@deprecated" not in doc:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_DEPRECATED_WITH_DOC",
                                      "S1123: @Deprecated 注解的方法应有 @deprecated Javadoc",
                                      _sq_severity("MINOR"), line=l, column=c)

            # S1130: Throws generic exception (additional)
            if isinstance(node, javalang_tree.MethodDeclaration):
                throws = getattr(node, "throws", None) or []
                for exc in throws:
                    exc_name = getattr(exc, "name", "") if hasattr(exc, "name") else str(exc)
                    if exc_name in ("Exception", "Throwable", "Error"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_GENERIC_THROWS_NINE",
                                  "S1130: 不应抛出通用异常类型 '" + exc_name + "'",
                                  _sq_severity("MAJOR"), line=l, column=c)
                        break

            # S1134: FIXME tag (already covered)
            # S1135: TODO tag (already covered)

            # S1141: Nested try (already covered)

            # S1149: Synchronized class (already covered)

            # S1151: Long case (already covered)

            # S1153: Integer comparison with == (already covered)

            # S1160: Too many throws (already covered)

            # S1165: Annotations usage
            if isinstance(node, (javalang_tree.ClassDeclaration, javalang_tree.InterfaceDeclaration)):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "FunctionalInterface":
                        methods = [d for d in getattr(node, "body", []) or []
                                   if isinstance(d, javalang_tree.MethodDeclaration)]
                        abstract_methods = [m for m in methods
                                            if "default" not in (m.modifiers or []) and
                                            "static" not in (m.modifiers or [])]
                        if len(abstract_methods) != 1:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_FUNCTIONAL_INTERFACE",
                                      "S1165: @FunctionalInterface 应恰好包含一个抽象方法",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S1172: Unused parameter (already covered)

            # S1174: finalize should be empty (additional)
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "finalize":
                    body = getattr(node, "body", None)
                    if body:
                        stmts = getattr(body, "statements", []) if hasattr(body, "statements") else \
                                (body if isinstance(body, list) else [])
                        if len(stmts) == 0 or \
                           (len(stmts) == 1 and "super.finalize()" in str(stmts[0])):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_FINALIZE_EMPTY",
                                      "S1174: finalize() 应为空或移除",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S1181: Throwable caught (already covered)

            # S1190: Enum switch missing case
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                has_default = False
                for case in cases:
                    case_tup = getattr(case, "case", [])
                    if isinstance(case_tup, list) and len(case_tup) == 0:
                        has_default = True
                if not has_default:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ENUM_SWITCH_DEFAULT",
                              "S1190: switch 缺少 default 分支",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S1193: Instanceof with final class (additional check in six)
            # S1201: Equals should handle null (additional)
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "equals":
                    body = getattr(node, "body", None)
                    if body:
                        body_str = str(body)
                        if "null" not in body_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_EQUALS_NO_NULL",
                                      "S1201: equals() 应处理 null 参数",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S128: Switch fall-through (additional)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("case ") and not stripped.startswith("case "):
                pass

        # S1301: Switch with few cases (already covered)
        # S1317: StringBuilder naming (already covered)
        # S1337: Unboxing (already covered)
        # S1340: Type param naming (already covered)
        # S139: Comments at end (already covered)
        # S1448: Too many methods (already covered)
        # S1451: File header comment
        if lines and len(lines) > 0:
            first_line = lines[0].strip()
            if not first_line.startswith("/*") and not first_line.startswith("//") and \
               not first_line.startswith("package ") and not first_line.startswith("import "):
                for path, node in tree:
                    if isinstance(node, javalang_tree.ClassDeclaration):
                        doc = getattr(node, "documentation", None)
                        if not doc:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_FILE_HEADER",
                                      "S1451: 文件缺少许可证/版权头部注释",
                                      _sq_severity("MINOR"), line=l)
                        break
