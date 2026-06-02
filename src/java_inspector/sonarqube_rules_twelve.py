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


class SonarQubeCheckerTwelve:
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
        self.check_security_twelve(tree, file_path, content)
        self.check_design_principles(tree, file_path, content)
        self.check_performance_twelve(tree, file_path, content)
        self.check_organization(tree, file_path, content)

    # ==================== Security (Additional) ====================

    def check_security_twelve(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security_twelve"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S2631: Checksum should be avoided
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("getChecksum", "getMessageDigest"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CHECKSUM_INSECURE",
                              "S2631: Checksum 不适用于安全用途，应使用 MAC",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S2068: Hardcoded password (additional patterns)
            if isinstance(node, javalang_tree.LocalVariableDeclaration):
                type_name = getattr(node.type, "name", "") if node.type else ""
                if type_name in ("String", "char", "StringBuilder"):
                    for decl in getattr(node, "declarators", []) or []:
                        name = getattr(decl, "name", "").lower()
                        init = getattr(decl, "initializer", None)
                        if any(kw in name for kw in ("password", "passwd", "pwd", "secret", "token", "apikey", "api_key")):
                            if init and isinstance(init, javalang_tree.Literal):
                                val = getattr(init, "value", "")
                                if val and len(val) > 3:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_HARDCODED_CREDENTIAL_TWELVE",
                                              "S2068: 凭据不应硬编码在代码中",
                                              _sq_severity("BLOCKER"), line=l, column=c)

            # S2245: Predictable random (additional)
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if "Random" in type_name and "Secure" not in type_name:
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 0 or \
                       (len(args) == 1 and hasattr(args[0], "value") and args[0].value is not None):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_PREDICTABLE_RANDOM_TWELVE",
                                  "S2245: 使用 java.util.Random 而非 SecureRandom 可能导致可预测值",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S2083: Path traversal (additional)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("getResource", "getResourceAsStream", "getAbsolutePath"):
                    if member == "getAbsolutePath":
                        args = getattr(node, "arguments", []) or []
                        if args:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_PATH_TRAVERSAL_TWELVE",
                                      "S2083: 未经校验的文件路径可能导致路径遍历漏洞",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S2089: HTTP parameter pollution
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member.startswith("getParameter"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_HTTP_PARAM_POLLUTION",
                              "S2089: HTTP 参数应有校验和长度限制",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S2092: Cookie secure (already in ext)

            # S3330: Cookie httponly (already in ext)

            # S5168: Unvalidated redirect
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("redirect", "forward", "sendRedirect"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_UNVALIDATED_REDIRECT",
                              "S5168: 未验证的重定向可能导致开放重定向漏洞",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S2070: Weak hash algorithm (additional)
            for i, line in enumerate(lines, 1):
                if re.search(r'\bMessageDigest\.getInstance\s*\(\s*"(MD2|MD4|MD5|SHA-?0?1?)"', line):
                    self._add(file_path, "SONAR_WEAK_HASH",
                              "S2070: 弱哈希算法 " + re.search(r'"(MD2|MD4|MD5|SHA-?0?1?)"', line).group(1) + " 不安全",
                              _sq_severity("MAJOR"), line=i)

            # S3329: Cipher without IV (already in fourth)

            # S5344: Timing attack
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "equals" and "MessageDigest" in str(getattr(node, "qualifier", "")):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TIMING_ATTACK",
                              "S5344: 应使用 MessageDigest.isEqual() 防止时序攻击",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S2629: Log injection (already in base)

    # ==================== Design Principles ====================

    def check_design_principles(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_design_principles"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1200: Coupling (already in seven)

            # S1287: Interface segregation
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                methods = [d for d in getattr(node, "body", []) or []
                           if isinstance(d, javalang_tree.MethodDeclaration)]
                if len(methods) > 10:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_INTERFACE_TOO_LARGE",
                              "S1287: 接口方法过多（" + str(len(methods)) + " 个），应考虑拆分",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S1701: Diamond operator (already in eight and full)

            # S1711: getBytes charset (already in seven)

            # S1712: Default encoding
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("getBytes", "InputStreamReader", "OutputStreamWriter",
                              "FileReader", "FileWriter"):
                    q = str(getattr(node, "qualifier", "") or "")
                    args = getattr(node, "arguments", []) or []
                    if not args:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_DEFAULT_ENCODING",
                                  "S1712: 使用默认编码可能导致编码不一致",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S1718: Identical expressions (already in base)

            # S1734: Equals for enum (already in full)

            # S1845: Method naming conventions
            if isinstance(node, javalang_tree.MethodDeclaration):
                name = getattr(node, "name", "")
                if name:
                    if name.isupper() and len(name) > 1:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_METHOD_UPPER_CASE",
                                  "S1845: 方法名不应全大写",
                                  _sq_severity("MAJOR"), line=l, column=c)
                    elif name.islower() and "_" in name:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_METHOD_UNDERSCORE",
                                  "S1845: 方法名应使用驼峰式而非下划线分隔",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S1860: Synchronization on mutable field (already in ext)

            # S2055: Empty collection (already in ten, partial)
            # S1994: Enhanced for loop (already in full)

            # S2130: Deprecation (already in base)

            # S2326: Unused type parameter (already in base)

            # S2325: Private method not used (already in base)

            # S2333: Redundant modifier (already in five)

            # S3030: Math.abs negative (already in seven)

            # S3242: Use base type (already in ext)

            # S3256: Loop variable (already in full)

            # S3280: Instance variable interface
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.FieldDeclaration):
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_INTERFACE_FIELD",
                                  "S3280: 接口中的字段隐式为 public static final，应避免",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S3358: Nested ternaries (already in base)

            # S3416: Logger naming (already in ext)

            # S3864: Stream peek (already in fourth)

            # S3985: Unused private inner (already in base)

            # S3986: Date pattern (already in ext)

            # S4143: Map overwrite (already in base)

            # S4144: Duplicate method (already in base)

            # S4275: Getter/setter (already in base)

            # S4347: SecureRandom (already in base)

            # S4408: Static class (already in full)

        # S119: Class name should start with uppercase
        for path, node in tree:
            if isinstance(node, (javalang_tree.ClassDeclaration, javalang_tree.InterfaceDeclaration)):
                type_name = getattr(node, "name", "")
                if type_name and type_name[0].islower():
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TYPE_NAME_CASE",
                              "S119: 类型名应以大写字母开头",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Performance ====================

    def check_performance_twelve(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_performance_twelve"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1155: Collection.isEmpty (already in seven)

            # S1596: Empty collection (already in base)

            # S1641: String split with single char (already in seven)

            # S1698: String equals (already in full)

            # S1700: Field/method name (already in base)

            # S1712: Default encoding (already in design_principles)

            # S1854: Dead store (already in base)

            # S1905: Redundant cast (already in base)

            # S1909: Self assignment (already in ten)

            # S2057: Serializable (already in eight)

            # S2116: String hashCode (already in six)

            # S2118: File.delete (already in six)

            # S2121: Iterator.remove (already in six)

            # S2126: Array cleaner
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "arraycopy":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ARRAYCOPY_LOOP",
                              "S2126: 数组复制应使用 System.arraycopy()",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S2131: Split with string (already in ext)

            # S2134: Split single char optimization (already in seven)

            # S2135: Statement execute (already in seven)

            # S2143: ThreadLocal naming (already in seven)

            # S2145: URL construction in loop
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if body:
                    body_str = str(body)
                    if "new URL" in body_str or "new URI" in body_str:
                        for stmt in body:
                            if isinstance(stmt, javalang_tree.ForStatement):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_URL_LOOP",
                                          "S2145: 循环中创建 URL/URI 对象可能影响性能",
                                          _sq_severity("MINOR"), line=l, column=c)
                                break

            # S2153: Boxing in loops (already in base)

            # S2154: Integer division (already in base)

            # S2157: Cloneable (already in fourth)

            # S2175: isEmpty (already in seven)

            # S2184: Divide int (already in six)

            # S2201: Ignored return (already in six)

            # S2203: StringBuilder toString (already in seven)

            # S2225: ToString null (already in seven)

            # S2232: BigDecimal double (already in nine)

            # S2250: String.intern (already in six)

            # S2251: Loop counter (already in six)

            # S2252: Float counter (already in six)

            # S2254: Double brace (already in full)

            # S2259: Null dereference (already in five)

            # S2260: Multiple catch (already in ext)

            # S2273: Sleep in loop (already in base)

            # S2293: Diamond (already in six)

            # S2296: Unnecessary parenthesis
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.BinaryOperation):
                    if getattr(cond, "operator", "") == "instanceof":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_UNNECESSARY_PREFIX",
                                  "S2296: 不必要的括号嵌套",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S2301: Map computeIfAbsent (already in base)

            # S2325: Private method could be static
            if isinstance(node, javalang_tree.MethodDeclaration):
                if "private" in (node.modifiers or []):
                    body = getattr(node, "body", None)
                    if body:
                        body_str = str(body)
                        if "this." not in body_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_PRIVATE_COULD_BE_STATIC",
                                      "S2325: 私有方法不访问实例字段可声明为 static",
                                      _sq_severity("MINOR"), line=l, column=c)

            # S2386: Mutable array (already in base)

            # S2388: Loop performance
            if isinstance(node, javalang_tree.ForStatement):
                body = node.body
                if body:
                    body_stmts = getattr(body, "statements", []) if hasattr(body, "statements") else \
                                 (body if isinstance(body, list) else [])
                    for stmt in body_stmts:
                        if isinstance(stmt, javalang_tree.MethodInvocation):
                            member = getattr(stmt, "member", "")
                            if member in ("length", "size"):
                                pass

            # S2390: Getter/setter (already in ten, partial)

            # S2437: Unboxing (already in five)

            # S2864: Keyset iteration (already in full)

            # S3012: Arrays.asList (already in seven)

            # S3252: Static access (already in full)

        # S2326: Unused type parameter (already in base)

    # ==================== Code Organization ====================

    def check_organization(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_organization"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S120: Package naming
            for path2, node2 in tree:
                if isinstance(node2, javalang_tree.PackageDeclaration):
                    pkg_name = getattr(node2, "name", "")
                    if pkg_name:
                        parts = pkg_name.split(".")
                        for part in parts:
                            if not part.islower() or part.startswith("_"):
                                l, c = self._pos(node2)
                                self._add(file_path, "SONAR_PACKAGE_NAMING_TWELVE",
                                          "S120: 包名应全部小写",
                                          _sq_severity("MAJOR"), line=l, column=c)
                                break

            # S1120: serialVersionUID (already in full)

            # S1128: Unused import (in inspector.py base)

            # S1147: System.exit (already in five)

            # S1149: Synchronized class (already in ext)

            # S1213: Member order (already in base)

            # S1214: Interface constants (already in ext)

            # S1220: Serial version (already in full)

            # S1221: Method name conflict (already in full)

            # S1258: Variable shadows field (already in full)

            # S1264: For to while (already in base)

            # S1312: Logger naming (already in full)

            # S1444: Public static final (already in base)

            # S1448: Too many methods (already in ext)

            # S1449: Locale (already in base)

            # S1450: Protected field (already in six)

            # S1451: File header (already in nine)

            # S1452: Wildcard return (already in eight)

            # S1479: Too many cases (already in base)

            # S1481: Unused local (already in full)

            # S1488: Local variable (already in base)

            # S1596: Empty collection (already in base)

            # S1600: Empty array (already in seven)

            # S1611: Method reference (already in five)

            # S1659: Multi-var declaration (already in full)

            # S1701: Diamond (already in eight)

            # S1751: Loop only break (already in eight)

            # S1763: Dead code after jump (already in full)

            # S1820: Too many fields (already in eight)

            # S1905: Redundant cast (already in base)

            # S1941: Variable type (already in ten)

        # S1598: Split class by responsibility
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                methods = [d for d in getattr(node, "body", []) or []
                           if isinstance(d, javalang_tree.MethodDeclaration)]
                fields = [d for d in getattr(node, "body", []) or []
                          if isinstance(d, javalang_tree.FieldDeclaration)]
                total_count = len(methods) + len(fields)
                if total_count > 30:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CLASS_TOO_LARGE_ORG",
                              "S1598: 类职责过多（" + str(total_count) + " 个成员），应拆分",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1067: Complex expression (already in five)

        # S1068: Unused field (already in base)

        # S107: Too many parameters (already in full)

        # S108: Empty block (already in ext)

        # S110: Deep inheritance (already in ext)

        # S112: General exception (already in ext)

        # S113: Comments (already in full)
