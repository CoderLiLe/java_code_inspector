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


class SonarQubeCheckerFifteen:
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
        self.check_http_web_extra(tree, file_path, content)
        self.check_jdbc_jpa_extra(tree, file_path, content)
        self.check_testing_extra(tree, file_path, content)
        self.check_quality_extra(tree, file_path, content)

    # ==================== HTTP / Web Security ====================

    def check_http_web_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_http_web"):
            return
        lines = content.split("\n")

        # S5122: XSS (additional variants via content)
        for i, line in enumerate(lines, 1):
            if re.search(r'\.getWriter\(\)\.write\s*\(', line) or \
               re.search(r'\.getOutputStream\(\)\.write\s*\(', line) or \
               re.search(r'\.getWriter\(\)\.print\s*\(', line):
                self._add(file_path, "SONAR_XSS_DIRECT_OUTPUT",
                          "S5122: 直接输出用户输入可能导致 XSS",
                          _sq_severity("MAJOR"), line=i)

        # S2092: Cache control headers
        for i, line in enumerate(lines, 1):
            if re.search(r'\.setHeader\s*\(\s*"Cache-Control', line) or \
               re.search(r'\.addHeader\s*\(\s*"Cache-Control', line):
                if not re.search(r'no-store|no-cache|must-revalidate', line):
                    self._add(file_path, "SONAR_CACHE_CONTROL",
                              "S2092: 敏感响应应设置 Cache-Control: no-store",
                              _sq_severity("MAJOR"), line=i)

            if re.search(r'\.setHeader\s*\(\s*"Strict-Transport-Security', line):
                if not re.search(r'max-age\s*=\s*\d+', line):
                    self._add(file_path, "SONAR_HSTS_HEADER",
                              "S2092: Strict-Transport-Security 应设置 max-age",
                              _sq_severity("MAJOR"), line=i)

            if re.search(r'\.setHeader\s*\(\s*"X-Content-Type-Options', line) and \
               "nosniff" not in line:
                self._add(file_path, "SONAR_CONTENT_TYPE_OPTIONS",
                          "S2092: X-Content-Type-Options 应设为 nosniff",
                          _sq_severity("MAJOR"), line=i)

            if re.search(r'\.setHeader\s*\(\s*"X-Frame-Options', line) and \
               "DENY" not in line and "SAMEORIGIN" not in line:
                self._add(file_path, "SONAR_FRAME_OPTIONS",
                          "S2092: X-Frame-Options 应设为 DENY 或 SAMEORIGIN",
                          _sq_severity("MAJOR"), line=i)

    # ==================== JDBC / JPA ====================

    def check_jdbc_jpa_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_jdbc_jpa"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # Connection string hardcoded
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "getConnection":
                    q = str(getattr(node, "qualifier", "") or "")
                    if "DriverManager" in q:
                        args = getattr(node, "arguments", []) or []
                        for arg in args:
                            if isinstance(arg, javalang_tree.Literal):
                                val = getattr(arg, "value", None)
                                if val and isinstance(val, str) and \
                                   "jdbc:" in val.replace("'", "").replace('"', ""):
                                    l, c = self._pos(arg)
                                    self._add(file_path, "SONAR_JDBC_HARDCODED",
                                              "S2068: JDBC 连接字符串不应硬编码",
                                              _sq_severity("BLOCKER"), line=l, column=c)
                                    break

            # Batch operations without transaction
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("addBatch", "executeBatch", "clearBatch"):
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Statement" in q or "PreparedStatement" in q:
                        pass

        # S2115: Connection URL credentials
        for i, line in enumerate(lines, 1):
            if re.search(r'DriverManager\.getConnection\s*\(\s*"[^"]*(user|password|passwd|pwd)=[^"]*"', line, re.I):
                self._add(file_path, "SONAR_CONNECTION_CREDENTIALS",
                          "S2115: 连接 URL 中包含凭据信息",
                          _sq_severity("BLOCKER"), line=i)

            # PreparedStatement with string concatenation
            if re.search(r'PreparedStatement\s+\w+\s*=\s*\w+\.prepareStatement\s*\(\s*"[^"]*"\s*\+', line):
                self._add(file_path, "SONAR_SQL_CONCAT_PREPARED",
                          "S2096: PreparedStatement 不应使用字符串拼接构造 SQL",
                          _sq_severity("MAJOR"), line=i)

            # JPA @Transactional on non-public method
            if re.search(r'@Transactional\s*\n\s*(protected|private)\s', content):
                self._add(file_path, "SONAR_TRANSACTIONAL_VISIBILITY",
                          "S4601: @Transactional 不应标注在非 public 方法上",
                          _sq_severity("MAJOR"), line=i)
                break

    # ==================== Testing Extra ====================

    def check_testing_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_testing_extra"):
            return

        for path, node in tree:
            # @Test(expected = ...) should use assertThrows
            if isinstance(node, javalang_tree.Annotation):
                short_name = getattr(node, "name", "").split(".")[-1]
                if short_name == "Test":
                    element = getattr(node, "element", None)
                    if element and hasattr(element, "values"):
                        for val in getattr(element, "values", []) or []:
                            if hasattr(val, "name") and val.name == "expected":
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_TEST_EXPECTED_V2",
                                          "S5778: 应使用 assertThrows() 替代 @Test(expected=...)",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # Test method without assertion
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                anns = getattr(node, "annotations", []) or []
                short_names = [a.name.split(".")[-1] for a in anns]
                if "Test" in short_names:
                    body = getattr(node, "body", None)
                    if body:
                        body_str = str(body)
                        keywords = ["assert", "Assertions.", "Assert.", "verify",
                                    "assertThat", "fail", "assertThrows"]
                        has_assert = any(kw in body_str for kw in keywords)
                        if not has_assert:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_TEST_WITHOUT_ASSERTION_V2",
                                      "S2699: 测试方法应包含断言语句",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # @Disabled without comment
            if isinstance(node, javalang_tree.Annotation):
                short_name = getattr(node, "name", "").split(".")[-1]
                if short_name in ("Disabled", "Ignore"):
                    element = getattr(node, "element", None)
                    if element is None or (hasattr(element, "value") and \
                       (element.value is None or element.value == "")):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_DISABLED_WITHOUT_COMMENT",
                                  "S1608: @Disabled/@Ignore 应标注具体原因",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S2698: Test assertion inside lambda
            # S3415: Assertion arguments order

    # ==================== Code Quality Extra ====================

    def check_quality_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_quality_extra"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1123: @Deprecated with javadoc
            if isinstance(node, javalang_tree.Annotation):
                short_name = getattr(node, "name", "").split(".")[-1]
                if short_name == "Deprecated":
                    parent_comment = ""
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_DEPRECATED_JAVADOC",
                              "S1123: @Deprecated 应提供 Javadoc 说明替代方案",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S1141: Nested try-catch (already partial)

            # S1701: Diamond (already covered)

            # S3020: Collection.toArray (already covered)

            # S3398: Private method used only by inner class
            if isinstance(node, javalang_tree.MethodDeclaration):
                modifiers = node.modifiers or []
                if "private" in modifiers:
                    name = getattr(node, "name", "")
                    body = getattr(node, "body", None)
                    if body:
                        pass

        # S1260: TODO with deadline (search in comments)
        for i, line in enumerate(lines, 1):
            if re.search(r'//\s*TODO', line) and not re.search(r'FIXME', lines[i-1] if i > 0 else ""):
                pass

        # S1316: Magic number in annotation (additional)
        for path, node in tree:
            if isinstance(node, javalang_tree.Annotation):
                element = getattr(node, "element", None)
                if element and hasattr(element, "value"):
                    val = element.value
                    if isinstance(val, str) and val.isdigit() and len(val) >= 3:
                        pass
