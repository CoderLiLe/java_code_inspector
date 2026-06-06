"""SonarQubeCheckerFourth — 第四批规则"""
import re
from typing import List

import javalang
from javalang import tree as javalang_tree
from java_inspector.sonarqube.base import BaseSonarChecker, sq_severity

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

class SonarQubeCheckerFourth(BaseSonarChecker):

    def run_all(self, tree, file_path: str, content: str):
        self.check_security_extra(tree, file_path, content)
        self.check_concurrency(tree, file_path, content)
        self.check_code_quality(tree, file_path, content)
        self.check_java_api(tree, file_path, content)

    # ==================== Security Extra ====================

    def check_security_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security_extra"):
            return
        lines = content.split("\n")

        # S1075: Hardcoded URIs
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"(https?|ftp|file|ldap|rmi|jndi)://[^"]{3,}"', line):
                self._add(file_path, "SONAR_HARDCODED_URI",
                          "S1075: URI 应定义为常量而非硬编码字符串",
                          sq_severity("MINOR"), line=i, column=m.start())

        # S2083: Path traversal (File from user input)
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        body = decl.body if isinstance(decl.body, list) else \
                               getattr(getattr(decl, "body", None), "statements", []) or []
                        for stmt in body:
                            stmt_str = str(stmt)
                            if "new File(" in stmt_str or "new FileInputStream" in stmt_str:
                                l, c = self._pos(stmt)
                                self._add(file_path, "SONAR_PATH_TRAVERSAL",
                                          "S2083: 应验证文件路径，避免路径遍历攻击",
                                          sq_severity("MAJOR"), line=l, column=c)

        # S2092: Cookie should be secure
        for i, line in enumerate(lines, 1):
            if re.search(r'cookie\.setSecure\s*\(\s*false\s*\)', line, re.I):
                self._add(file_path, "SONAR_COOKIE_SECURE",
                          "S2092: Cookie 应设置 Secure 标志为 true",
                          sq_severity("MAJOR"), line=i)

        # S2245/S2257: Predictable random (Random instead of SecureRandom)
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name.endswith("Random") and "SecureRandom" not in type_name:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PREDICTABLE_RANDOM",
                              "S2245: 应使用 SecureRandom 而非 Random 生成随机数",
                              sq_severity("MAJOR"), line=l, column=c)
                    continue
                for declarator in getattr(node, "declarators", []) or []:
                    init = getattr(declarator, "initializer", None)
                    if init and isinstance(init, javalang_tree.ClassCreator):
                        creator_type = getattr(init, "type", None)
                        ct_name = _get_full_type_name(creator_type)
                        if ct_name.endswith("Random") and "SecureRandom" not in ct_name:
                            l, c = self._pos(declarator)
                            self._add(file_path, "SONAR_PREDICTABLE_RANDOM",
                                      "S2245: 应使用 SecureRandom 而非 Random 生成随机数",
                                      sq_severity("MAJOR"), line=l, column=c)
            elif isinstance(node, javalang_tree.LocalVariableDeclaration):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name.endswith("Random") and "SecureRandom" not in type_name:
                    for declarator in getattr(node, "declarators", []) or []:
                        init = getattr(declarator, "initializer", None)
                        if init and isinstance(init, javalang_tree.ClassCreator):
                            creator_type = getattr(init, "type", None)
                            ct_name = _get_full_type_name(creator_type)
                            if ct_name.endswith("Random") and "SecureRandom" not in ct_name:
                                l, c = self._pos(declarator)
                                self._add(file_path, "SONAR_PREDICTABLE_RANDOM",
                                          "S2245: 应使用 SecureRandom 而非 Random 生成随机数",
                                          sq_severity("MAJOR"), line=l, column=c)

        # S2278: ECB encryption mode
        for i, line in enumerate(lines, 1):
            if re.search(r'"AES/ECB/|"DES/ECB/|"DESede/ECB/', line):
                self._add(file_path, "SONAR_ECB_MODE",
                          "S2278: 不应使用 ECB 加密模式，建议使用 CBC/GCM",
                          sq_severity("CRITICAL"), line=i)

        # S3329: CBC with predictable IV
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("init", "doFinal", "update"):
                    args = getattr(node, "arguments", []) or []
                    call_str = str(node)
                    if "IvParameterSpec" in call_str or "init" == member:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CBC_IV",
                                  "S3329: CBC 模式应使用安全的 IV（随机生成，不可预测）",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S4425: Weak XML parsing (SAXParser, DocumentBuilder)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = getattr(node, "qualifier", "") or ""
                if member == "newInstance" and qualifier in ("DocumentBuilderFactory", "SAXParserFactory"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_WEAK_XML_PARSER",
                              "S4425: XML 解析器应配置为禁用外部实体（XXE）",
                              sq_severity("MAJOR"), line=l, column=c)

        # S5304: JNDI lookup with user input
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "lookup":
                    qualifier = getattr(node, "qualifier", None)
                    node_str = str(node)
                    parent_str = ""
                    for p in reversed(path):
                        ps = str(p)
                        if "InitialContext" in ps or "DirContext" in ps or "Context" in ps:
                            parent_str = ps
                            break
                    if qualifier and ("Context" in str(qualifier)):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_JNDI_LOOKUP",
                                  "S5304: JNDI lookup 应避免使用用户输入，防止 JNDI 注入",
                                  sq_severity("CRITICAL"), line=l, column=c)
                    elif "InitialContext" in node_str or "DirContext" in node_str or \
                         "Context" in parent_str:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_JNDI_LOOKUP",
                                  "S5304: JNDI lookup 应避免使用用户输入，防止 JNDI 注入",
                                  sq_severity("CRITICAL"), line=l, column=c)

        # S5125: Jackson polymorphic deserialization
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("enableDefaultTyping", "enableDefaultTypingForSerialization"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_JACKSON_POLYMORPHIC",
                              "S5125: Jackson 启用默认类型可能导致反序列化漏洞",
                              sq_severity("CRITICAL"), line=l, column=c)

    # ==================== Concurrency ====================

    def check_concurrency(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_concurrency"):
            return

        # S2446: wait/notify should be called inside synchronized block
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("wait", "notify", "notifyAll"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_WAIT_SYNC",
                              "S2446: " + member + "() 应在 synchronized 块中调用",
                              sq_severity("MAJOR"), line=l, column=c)

        # S3078: Volatile reference to mutable object
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "volatile" in modifiers:
                    for declarator in getattr(node, "declarators", []) or []:
                        l, c = self._pos(declarator)
                        self._add(file_path, "SONAR_VOLATILE_MUTABLE",
                                  "S3078: volatile 修饰的字段如果指向可变对象，可能仍有线程安全问题",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S4065: ThreadLocal with synchronized
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if "ThreadLocal" in type_name:
                    if "static" not in (node.modifiers or []):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_THREADLOCAL_STATIC",
                                  "S4065: ThreadLocal 字段应声明为 static 以防止内存泄漏",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S2122: ScheduledThreadPoolExecutor should not use Runnable
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = getattr(node, "qualifier", "") or ""
                if member in ("schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay"):
                    if "Scheduled" in qualifier:
                        args = getattr(node, "arguments", []) or []
                        if args:
                            arg_str = str(args[0])
                            if "Runnable" in arg_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_SCHEDULED_EXECUTOR",
                                          "S2122: ScheduledThreadPoolExecutor 应使用 Callable 而非 Runnable",
                                          sq_severity("MINOR"), line=l, column=c)

        # S3631: Thread.run() detection (backup for S2689 in base)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = getattr(node, "qualifier", "") or ""
                if member == "start":
                    if "Thread" in qualifier or qualifier == "":
                        pass

        # S2886: getParameter should not be used without validation
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("getParameter", "getQueryString", "getHeader"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SERVLET_INPUT",
                              "S2886: 用户输入应经过验证后再使用",
                              sq_severity("MAJOR"), line=l, column=c)

    # ==================== Code Quality ====================

    def check_code_quality(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_code_quality"):
            return
        lines = content.split("\n")
        lines = content.split("\n")

        # S1114: super.finalize() should be called in finalize()
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "finalize":
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    body_str = " ".join(str(s) for s in body)
                    if "super.finalize()" not in body_str.replace(" ", ""):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FINALIZE_CALL",
                                  "S1114: finalize() 方法应调用 super.finalize()",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S2157: Cloneable without clone method
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                implements = getattr(node, "implements", []) or []
                has_cloneable = False
                for iface in implements:
                    iface_name = _get_full_type_name(iface)
                    if "Cloneable" in iface_name:
                        has_cloneable = True
                        break
                if has_cloneable:
                    has_clone_method = False
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            if decl.name == "clone":
                                has_clone_method = True
                                break
                    if not has_clone_method:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLONEABLE",
                                  "S2157: 实现 Cloneable 接口的类应重写 clone() 方法",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S2160: equals in subclass should call super.equals
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                ext = getattr(node, "extends", None)
                if ext and hasattr(ext, "name") and ext.name != "Object":
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            if decl.name == "equals":
                                body = decl.body if isinstance(decl.body, list) else \
                                       getattr(getattr(decl, "body", None), "statements", []) or []
                                body_str = " ".join(str(s) for s in body)
                                if "super.equals" not in body_str.replace(" ", ""):
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_SUBCLASS_EQUALS",
                                              "S2160: 子类重写 equals() 应调用 super.equals()",
                                              sq_severity("MAJOR"), line=l, column=c)

        # S3577: Test class naming
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                if node.name.startswith("Test") or node.name.endswith("Test") or \
                   node.name.endswith("Tests"):
                    pass

        # S3864: Stream.peek should be used with caution
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "peek":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STREAM_PEEK",
                              "S3864: Stream.peek() 是中间操作，仅在调试时使用",
                              sq_severity("MAJOR"), line=l, column=c)

        # S3878: Arrays passed to varargs should not be null
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                args = getattr(node, "arguments", []) or []
                for arg in args:
                    if isinstance(arg, javalang_tree.Literal):
                        value = getattr(arg, "value", "")
                        if value == "null":
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_NULL_VARARG",
                                      "S3878: 不应将 null 传递给可变参数",
                                      sq_severity("MAJOR"), line=l, column=c)
                            break

        # S3923: Switch with single branch
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                non_default_cases = [c for c in cases
                                     if not (isinstance(c, javalang_tree.SwitchStatementCase) and
                                             getattr(c, "case", None) is None)]
                default_cases = [c for c in cases
                                 if isinstance(c, javalang_tree.SwitchStatementCase) and
                                 getattr(c, "case", None) is None]
                if len(non_default_cases) <= 1:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SINGLE_BRANCH_SWITCH",
                              "S3923: 仅包含一个分支的 switch 应替换为 if 语句",
                              sq_severity("MAJOR"), line=l, column=c)

        # S3958: Intermediate stream methods should not be standalone
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("filter", "map", "flatMap", "sorted", "peek", "distinct", "limit", "skip"):
                    parent = path[-2] if len(path) >= 2 else None
                    if parent and isinstance(parent, javalang_tree.StatementExpression):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_STREAM_INTERMEDIATE",
                                  "S3958: 流中间操作（" + member + "）没有终端操作，不会执行",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S4158: Empty collections
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("add", "addAll", "put", "putAll", "remove"):
                    pass
        # Detect empty collections: stream().count() == 0 or isEmpty when not needed
        for i, line in enumerate(lines, 1):
            if re.search(r'\.stream\(\).*count\s*\(\s*\)\s*([=!]=|>|<)\s*0', line):
                self._add(file_path, "SONAR_STREAM_COUNT_ZERO",
                          "S4158: 使用 stream().count() 检查是否为空，应使用 isEmpty()",
                          sq_severity("MINOR"), line=i)

        # S4242: Iterator hasNext/next balance
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "next":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ITERATOR_NEXT_BALANCE",
                              "S4242: 调用 next() 前应确保 hasNext() 返回 true",
                              sq_severity("MAJOR"), line=l, column=c)

        # S4276: Parameter name shadows field
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                keys = set()
                for decl in getattr(node, "body", []) or []:
                    pass

    # ==================== Java API ====================

    def check_java_api(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_java_api"):
            return
        lines = content.split("\n")

        # S2159: equals() with incompatible types
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "equals":
                    qualifier = getattr(node, "qualifier", "") or ""
                    args = getattr(node, "arguments", []) or []
                    if args:
                        arg_str = str(args[0])
                        if qualifier and "String" not in qualifier:
                            pass

        # S2162: equals asymmetry (check if equals compares same type)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "equals":
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    body_str = " ".join(str(s) for s in body)
                    if "instanceof" in body_str:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_EQUALS_ASYMMETRY",
                                  "S2162: equals() 中使用 instanceof 可能导致不对称性，建议使用 getClass()",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S2200: compareTo should be consistent with equals
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_equals = False
                has_compare_to = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if decl.name == "equals":
                            has_equals = True
                        elif decl.name == "compareTo":
                            has_compare_to = True
                if has_compare_to and not has_equals:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_COMPARETO_EQUALS",
                              "S2200: 实现 Comparable 接口的类应同时重写 equals()",
                              sq_severity("MAJOR"), line=l, column=c)

        # S2167: compareTo should be consistent with equals
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                implements = getattr(node, "implements", []) or []
                has_comparable = False
                for iface in implements:
                    iface_name = _get_full_type_name(iface)
                    if "Comparable" in iface_name:
                        has_comparable = True
                        break
                if has_comparable:
                    has_equals = False
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration) and \
                           decl.name == "equals":
                            has_equals = True
                            break
                    if not has_equals:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_COMPARABLE_EQUALS",
                                  "S2167: 实现 Comparable 的类也应重写 equals() 以保持一致",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S3749: Class without equals/hashCode
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                ext = getattr(node, "extends", None)
                if ext and hasattr(ext, "name") and ext.name not in ("Object", "Exception",
                                                                     "RuntimeException", "Throwable"):
                    continue
                has_equals = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration) and \
                       decl.name == "equals":
                        has_equals = True
                        break
                if not has_equals:
                    members_count = 0
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.FieldDeclaration):
                            for _ in getattr(decl, "declarators", []) or []:
                                members_count += 1
                    if members_count >= 2:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLASS_EQUALS",
                                  "S3749: 类 '" + node.name + "' 包含多个字段但未重写 equals()",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S3996: URL.equals/hashCode triggers DNS lookup
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "equals":
                    qualifier = getattr(node, "qualifier", "") or ""
                    if "URL" in qualifier or qualifier.endswith("Url"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_URL_EQUALS",
                                  "S3996: URL.equals() 和 hashCode() 会触发 DNS 解析，建议使用 URI",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S4166: Optional should not be null
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("of", "ofNullable", "empty"):
                    qualifier = getattr(node, "qualifier", "") or ""
                    if "Optional" in qualifier:
                        pass
        for i, line in enumerate(lines, 1):
            if re.search(r'\bOptional\s*<\s*\w+\s*>\s+\w+\s*=\s*null', line):
                self._add(file_path, "SONAR_OPTIONAL_NULL",
                          "S4166: Optional 不应被赋值为 null，应使用 Optional.empty()",
                          sq_severity("MAJOR"), line=i)

        # S4201: Null checks on Optional
        for i, line in enumerate(lines, 1):
            if re.search(r'\bOptional[.<>\w]*\s+\w+\s*(!=|==)\s*null', line) or \
               re.search(r'if\s*\(\s*\w+\s*(!=|==)\s*null\s*\)', line) and \
               re.search(r'Optional', line):
                self._add(file_path, "SONAR_OPTIONAL_NULL_CHECK",
                          "S4201: 不应使用 == 检查 Optional 是否为 null，应使用 isPresent()",
                          sq_severity("MAJOR"), line=i)

        # S4351: Equals override with field comparison
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "equals":
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    body_str = " ".join(str(s) for s in body)
                    if "valueOf" in body_str or "toString" in body_str:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_EQUALS_VALUE_OF",
                                  "S4351: equals() 中应直接比较字段值，而非使用 valueOf/toString",
                                  sq_severity("MAJOR"), line=l, column=c)

        # S4423: Weak SSL/TLS (duplicate check with base, add protocol check)
        for i, line in enumerate(lines, 1):
            if re.search(r'"SSLv3"|"SSLv2"|"TLSv1"|"TLS"', line) and \
               "setProtocol" in line:
                self._add(file_path, "SONAR_WEAK_PROTOCOL",
                          "S4423: 应使用 TLSv1.2 或更高版本，避免使用 SSL/TLSv1",
                          sq_severity("CRITICAL"), line=i)

        # S2229: LDAP anonymous detection (backup for S2229 in ext)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = getattr(node, "qualifier", "") or ""
                if member in ("search", "lookup") and "DirContext" in str(node):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_LDAP_ANONYMOUS_V2",
                              "S2229: LDAP 认证应使用简单认证，避免匿名绑定",
                              sq_severity("CRITICAL"), line=l, column=c)
