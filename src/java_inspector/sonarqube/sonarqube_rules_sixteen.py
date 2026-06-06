"""SonarQubeCheckerSixteen — 第十六批规则"""
import re
from typing import List

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

class SonarQubeCheckerSixteen(BaseSonarChecker):

    def run_all(self, tree, file_path: str, content: str):
        self.check_json_xml(tree, file_path, content)
        self.check_nio_reflection(tree, file_path, content)
        self.check_datetime_extra(tree, file_path, content)
        self.check_sql_generalization(tree, file_path, content)

    # ==================== JSON / XML ====================

    def check_json_xml(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_json_xml"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S5336: Gson should disable HTML escaping
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "disableHtmlEscaping":
                    pass

            # S2445: Jackson @JsonIgnore on getter
            if isinstance(node, javalang_tree.MethodDeclaration):
                anns = getattr(node, "annotations", []) or []
                short_names = [a.name.split(".")[-1] for a in anns]
                if "JsonIgnore" in short_names:
                    name = getattr(node, "name", "")
                    if name.startswith("get") or name.startswith("is"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_JSON_IGNORE_REDUNDANT",
                                  "S2445: @JsonIgnore 标注在 getter 上应配合 @JsonProperty",
                                  sq_severity("MINOR"), line=l, column=c)

            # S4747: JAX-RS @QueryParam injection
            if isinstance(node, javalang_tree.Annotation):
                short_name = getattr(node, "name", "").split(".")[-1]
                if short_name == "QueryParam":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_QUERYPARAM_VALIDATION",
                              "S4747: @QueryParam 参数应有校验或默认值",
                              sq_severity("MAJOR"), line=l, column=c)

        # S5689: XMLDecoder usage
        for i, line in enumerate(lines, 1):
            if re.search(r'XMLDecoder\s*\(', line):
                self._add(file_path, "SONAR_XML_DECODER",
                          "S5689: XMLDecoder 可能导致反序列化漏洞",
                          sq_severity("CRITICAL"), line=i)

            # S2755: SAXParser external entities (additional variants)
            if re.search(r'DocumentBuilder|SAXParser|SAXReader|SAXBuilder', line) and \
               re.search(r'\.parse\s*\(', line):
                if not re.search(r'setFeature|setProperty', line):
                    self._add(file_path, "SONAR_XXE_PARSER",
                              "S2755: XML 解析器应禁用外部实体处理",
                              sq_severity("MAJOR"), line=i)

    # ==================== NIO / Reflection ====================

    def check_nio_reflection(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_nio_reflection"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S3725: FileChannel.force() not called
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("write", "read"):
                    q = str(getattr(node, "qualifier", "") or "")
                    if "FileChannel" in q:
                        pass

            # S3011: AccessibleObject.setAccessible(true)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "setAccessible":
                    args = getattr(node, "arguments", []) or []
                    if args and "true" in str(args[0]):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SET_ACCESSIBLE",
                                  "S3011: 使用 setAccessible(true) 破坏封装性",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S2135: Paths.get (already covered in seven)

            # S3039: String.isEmpty() on Files.lines result
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "lines":
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Files" in q or "java.nio.file.Files" in q:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FILES_LINES_STREAM",
                                  "S3039: Files.lines() 返回的 Stream 应关闭",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S4087: FileChannel read loop
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("read", "write"):
                    pass

            # S4349: ExecutorService.shutdown (additional)
            # Already in module 11

            # S4488: MethodHandle usage
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node) if type_node else ""
                if "MethodHandle" in type_name or "MethodHandles" in type_name:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_METHOD_HANDLE",
                              "S4488: 使用 MethodHandle 应确保安全性",
                              sq_severity("MINOR"), line=l, column=c)

            # S4551: Proxy usage
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "newProxyInstance":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PROXY_INSTANCE",
                              "S4551: 代理对象应谨慎使用",
                              sq_severity("MINOR"), line=l, column=c)

        # S4347: SecureRandom (additional content check)
        for i, line in enumerate(lines, 1):
            if re.search(r'new\s+SecureRandom\s*\(\s*("[^"]*"|[^)])', line):
                if not re.search(r'SHA1PRNG|NativePRNG', line):
                    pass

    # ==================== Date/Time ====================

    def check_datetime_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_datetime_extra"):
            return

        for path, node in tree:
            # S2141: Mutable date field
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    if "java.util.Date" in type_name or type_name == "Date":
                        if not node.modifiers:
                            pass

            # S2387: Date as constructor argument (already covered)
            # S2408: Date mutability
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    base = type_name.split(".")[-1]
                    if base in ("Date", "Calendar", "GregorianCalendar"):
                        modifiers = node.modifiers or []
                        for var in getattr(node, "declarators", []) or []:
                            init = getattr(var, "initializer", None)
                            if init and isinstance(init, javalang_tree.MethodInvocation):
                                if getattr(init, "member", "") == "getInstance":
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_DATE_MUTABLE_FIELD",
                                              "S2408: 可变日期字段应进行防御性复制",
                                              sq_severity("MAJOR"), line=l, column=c)

            # S2386: Calendar.getInstance (mutable constant)
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "static" in modifiers and "final" in modifiers:
                    type_node = getattr(node, "type", None)
                    if type_node:
                        type_name = _get_full_type_name(type_node)
                        base = type_name.split(".")[-1]
                        if base in ("Calendar", "DateFormat", "SimpleDateFormat",
                                    "Date", "GregorianCalendar"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_MUTABLE_DATE_CONSTANT",
                                      "S2386: 可变日期/时间对象不应定义为常量",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2387: Child field hides parent
            if isinstance(node, javalang_tree.ClassDeclaration):
                ext = getattr(node, "extends", None)
                if ext:
                    fields = [d for d in getattr(node, "body", []) or []
                              if isinstance(d, javalang_tree.FieldDeclaration)]
                    field_names = set()
                    for f in fields:
                        for v in getattr(f, "declarators", []) or []:
                            field_names.add(getattr(v, "name", ""))
                    if field_names:
                        pass

    # ==================== SQL / Generalization ====================

    def check_sql_generalization(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_sql_general"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1109: Close Statement (additional)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("executeQuery", "executeUpdate"):
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        if isinstance(arg, javalang_tree.BinaryOperation) and \
                           getattr(arg, "operator", "") in ("+", "PLUS"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_SQL_CONCAT_INJECTION",
                                      "S1109: SQL 查询中使用字符串拼接可能导致注入",
                                      sq_severity("BLOCKER"), line=l, column=c)
                            break

            # S2111: ResultSet.next() in loop pattern
            if isinstance(node, javalang_tree.WhileStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.MethodInvocation):
                    if getattr(cond, "member", "") == "next":
                        q = str(getattr(cond, "qualifier", "") or "")
                        if "ResultSet" in q or "rs" in q:
                            pass

            # S2122: SQL injection in LIKE clause (additional)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("executeQuery", "execute", "executeUpdate"):
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        arg_str = str(arg)
                        if "LIKE '" in arg_str or "like '" in arg_str:
                            if "?" not in arg_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_LIKE_INJECTION",
                                          "S2122: LIKE 查询应使用参数化查询",
                                          sq_severity("BLOCKER"), line=l, column=c)

        # S2077: SQL formatting with format()
        for i, line in enumerate(lines, 1):
            if re.search(r'String\.format\s*\([^)]*SELECT|String\.format\s*\([^)]*INSERT|String\.format\s*\([^)]*UPDATE|String\.format\s*\([^)]*DELETE', line, re.I):
                self._add(file_path, "SONAR_FORMAT_SQL_INJECTION",
                          "S2077: 使用 String.format() 构造 SQL 可能导致注入",
                          sq_severity("BLOCKER"), line=i)
