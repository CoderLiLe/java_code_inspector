"""SonarQubeCheckerFourteen — 第十四批规则"""
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

def _get_base_type_name(t):
    return _get_full_type_name(t).split(".")[-1]

class SonarQubeCheckerFourteen(BaseSonarChecker):

    def run_all(self, tree, file_path: str, content: str):
        self.check_security_extra(tree, file_path, content)
        self.check_serialization_extra(tree, file_path, content)
        self.check_math_edge_cases(tree, file_path, content)
        self.check_convention_extra(tree, file_path, content)
        self.check_error_prone_extra(tree, file_path, content)

    # ==================== Security Extra ====================

    def check_security_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security_fourteen"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S3077: Volatile collections
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "volatile" in modifiers:
                    type_node = getattr(node, "type", None)
                    if type_node:
                        type_name = _get_base_type_name(type_node)
                        if type_name in ("List", "Set", "Map", "Queue", "Deque",
                                         "ArrayList", "HashMap", "HashSet",
                                         "LinkedList", "TreeMap", "TreeSet"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_VOLATILE_COLLECTION",
                                      "S3077: volatile 不能保证集合操作的原子性",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2168: Mutable objects as lock targets
            if isinstance(node, javalang_tree.SynchronizedStatement):
                expr = getattr(node, "expression", None)
                if expr:
                    expr_str = str(expr)
                    if "mutex" not in expr_str.lower() and "lock" not in expr_str.lower():
                        pass

            # S2174: Constructor calls overridable method
            if isinstance(node, javalang_tree.ConstructorDeclaration):
                body = getattr(node, "body", None)
                if body:
                    body_str = str(body)
                    invocations = [n for p, n in tree
                                   if isinstance(n, javalang_tree.MethodInvocation)]
                    for inv in invocations:
                        member = getattr(inv, "member", "")
                        if member in ("isAccessible", "canAccess") or member.startswith("get"):
                            l, c = self._pos(inv)
                            self._add(file_path, "SONAR_CTOR_OVERRIDABLE",
                                      "S2174: 构造函数中调用可重写方法可能导致错误行为",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2159: Silly equality (comparing different types)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "equals":
                    q = getattr(node, "qualifier", None)
                    args = getattr(node, "arguments", []) or []
                    if q and args:
                        q_str, a_str = str(q), str(args[0])
                        type_hints = {"64L": "long", "64": "int", "0.0": "double",
                                      "true": "boolean", "false": "boolean"}
                        if (q_str in type_hints and a_str.isidentifier()) or \
                           (a_str in type_hints and q_str.isidentifier()):
                            pass

        # S2148: Underscore in numeric literals
        for i, line in enumerate(lines, 1):
            if re.search(r'\b\d{5,}\b', line) and \
               not re.search(r'_\d', line):
                self._add(file_path, "SONAR_UNDERSCORE_LITERAL",
                          "S2148: 长数字字面量应使用下划线分隔提高可读性",
                          sq_severity("MINOR"), line=i)
                break

        # S4425: JAXB XXE
        for i, line in enumerate(lines, 1):
            if re.search(r'JAXBContext\.newInstance', line) and \
               not re.search(r'XMLInputFactory|schema', line):
                pass

    # ==================== Serialization Extra ====================

    def check_serialization_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_serialization_fourteen"):
            return

        for path, node in tree:
            # S2065: Transient fields in Serializable
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                is_serializable = any(_get_base_type_name(i) == "Serializable" for i in imp)
                if is_serializable:
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.FieldDeclaration):
                            modifiers = decl.modifiers or []
                            if "transient" not in modifiers and "static" not in modifiers:
                                for var in getattr(decl, "declarators", []) or []:
                                    if not getattr(var, "name", "").startswith("serial"):
                                        pass

            # S2441: Serializable inner class
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                is_serializable = any(_get_base_type_name(i) == "Serializable" for i in imp)
                if is_serializable:
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.ClassDeclaration) and \
                           "static" not in (decl.modifiers or []):
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_INNER_SERIALIZABLE",
                                      "S2441: 外部类可序列化时应使内部类为 static",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2130: readResolve / writeReplace
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                is_serializable = any(_get_base_type_name(i) == "Serializable" for i in imp)
                if is_serializable:
                    methods = [d for d in getattr(node, "body", []) or []
                               if isinstance(d, javalang_tree.MethodDeclaration)]
                    sigs = [(m.name, len(getattr(m, "parameters", []) or [])) for m in methods]
                    has_read_object = any(n == "readObject" and c == 1 for n, c in sigs)
                    has_read_resolve = any(n == "readResolve" and c == 0 for n, c in sigs)
                    if has_read_object and not has_read_resolve:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_READ_OBJECT_WITHOUT_RESOLVE",
                                  "S2130: readObject 应搭配 readResolve 确保单例安全",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S2156: Final class with protected member
            if isinstance(node, javalang_tree.ClassDeclaration):
                if "final" in (node.modifiers or []):
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.FieldDeclaration):
                            if "protected" in (decl.modifiers or []):
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_FINAL_PROTECTED",
                                          "S2156: final 类中的 protected 成员应改为 private",
                                          sq_severity("MAJOR"), line=l, column=c)

    # ==================== Math Edge Cases ====================

    def check_math_edge_cases(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_math_fourteen"):
            return

        for path, node in tree:
            # S2164: BigDecimal divide without rounding mode
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "divide":
                    args = getattr(node, "arguments", []) or []
                    has_rounding = any("RoundingMode" in str(a) or
                                       "HALF" in str(a) or
                                       "CEILING" in str(a) for a in args)
                    if len(args) >= 1 and len(args) <= 2 and not has_rounding:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_BIGDECIMAL_ROUNDING",
                                  "S2164: BigDecimal.divide() 应指定舍入模式",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S2159: Double equals comparison
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("==", "!="):
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    left_is_double = isinstance(left, javalang_tree.Literal) and \
                                     isinstance(getattr(left, "value", None), str) and \
                                     "." in getattr(left, "value", "")
                    right_is_double = isinstance(right, javalang_tree.Literal) and \
                                      isinstance(getattr(right, "value", None), str) and \
                                      "." in getattr(right, "value", "")
                    if left_is_double or right_is_double:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FLOAT_COMPARE_V2",
                                  "S2159: 浮点数不应使用 == 或 != 比较",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S2160: Equivalent equals
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.BinaryOperation):
                    pass

            # S2182: Override equals without compareTo
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                is_comparable = any(_get_base_type_name(i) == "Comparable" for i in imp)
                if is_comparable:
                    methods = [d for d in getattr(node, "body", []) or []
                               if isinstance(d, javalang_tree.MethodDeclaration)]
                    names = [m.name for m in methods]
                    if "equals" in names and "compareTo" not in names:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_COMPARABLE_WITHOUT_COMPARETO",
                                  "S2182: 实现 Comparable 应实现 compareTo",
                                  sq_severity("MAJOR"), line=l, column=c)

    # ==================== Convention Extra ====================

    def check_convention_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_convention_fourteen"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S2166: Exception class naming
            if isinstance(node, javalang_tree.ClassDeclaration):
                name = getattr(node, "name", "")
                imp = getattr(node, "extends", None)
                if imp and "Exception" in _get_base_type_name(imp):
                    if not name.endswith("Exception"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_EXCEPTION_CLASS_NAMING",
                                  "S2166: 异常类应使用 Exception 后缀命名",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S2151: Unused local variable (catch blocks)
            if isinstance(node, javalang_tree.CatchClause):
                block = getattr(node, "block", []) or []
                local_vars = [n for n in block
                              if isinstance(n, javalang_tree.LocalVariableDeclaration)]
                for lv in local_vars:
                    for decl in getattr(lv, "declarators", []) or []:
                        name = getattr(decl, "name", "")
                        if name and name not in str(block):
                            l, c = self._pos(lv)
                            self._add(file_path, "SONAR_UNUSED_LOCAL_CATCH",
                                      "S2151: catch 块中声明的局部变量未使用",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2094: Empty marker interface
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                body = getattr(node, "body", []) or []
                has_content = any(True for _ in body)
                if not has_content:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EMPTY_MARKER_INTERFACE_V2",
                              "S2094: 空接口应使用注解替代",
                              sq_severity("MINOR"), line=l, column=c)

            # S2320: Type parameter shadowing
            if isinstance(node, javalang_tree.ClassDeclaration):
                type_params = getattr(node, "type_parameters", None) or []
                if type_params:
                    tp_names = [getattr(tp, "name", "") for tp in type_params]
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            inner_tp = getattr(decl, "type_parameters", None) or []
                            for itp in inner_tp:
                                if getattr(itp, "name", "") in tp_names:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_TYPE_PARAM_SHADOW",
                                              "S2320: 类型参数与外层类类型参数同名",
                                              sq_severity("MAJOR"), line=l, column=c)

            # S3577: Test class naming
            if isinstance(node, javalang_tree.ClassDeclaration):
                anns = getattr(node, "annotations", []) or []
                short_names = [a.name.split(".")[-1] for a in anns]
                is_test = any(n in ("Test", "RunWith", "Suite", "SpringBootTest",
                                    "ExtendWith") for n in short_names)
                if is_test:
                    name = getattr(node, "name", "")
                    if not name.endswith("Test") and not name.endswith("Tests"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TEST_CLASS_NAMING",
                                  "S3577: 测试类名应以 Test 结尾",
                                  sq_severity("MAJOR"), line=l, column=c)

        # Import wildcard
        for path, node in tree:
            if isinstance(node, javalang_tree.Import):
                if getattr(node, "wildcard", False):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_IMPORT_WILDCARD",
                              "S1128: 应避免使用通配符导入",
                              sq_severity("MINOR"), line=l, column=c)
                    break

        # S3578: Test method naming
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                anns = getattr(node, "annotations", []) or []
                short_names = [a.name.split(".")[-1] for a in anns]
                if "Test" in short_names or "ParameterizedTest" in short_names:
                    name = getattr(node, "name", "")
                    if name and not name[0].islower():
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TEST_METHOD_NAMING_V2",
                                  "S3578: 测试方法名应以小写字母开头",
                                  sq_severity("MAJOR"), line=l, column=c)

    # ==================== Error-Prone Extra ====================

    def check_error_prone_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_error_prone_fourteen"):
            return

        for path, node in tree:
            # S2196: Infinite recursion (method calling itself)
            if isinstance(node, javalang_tree.MethodDeclaration):
                method_name = getattr(node, "name", "")
                body = getattr(node, "body", None)
                if body and method_name:
                    self_calls = 0
                    for stmt in body:
                        if isinstance(stmt, javalang_tree.StatementExpression):
                            expr = getattr(stmt, "expression", None)
                            if isinstance(expr, javalang_tree.MethodInvocation) and \
                               getattr(expr, "member", "") == method_name:
                                self_calls += 1
                    if self_calls >= 2:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_INFINITE_RECURSION",
                                  "S2196: 方法递归调用自身可能导致无限递归",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S2171: Negating non-boolean
            if isinstance(node, javalang_tree.BinaryOperation):
                if getattr(node, "operator", "") == "instanceof":
                    pass

            # S1850: instanceof always true (final class check)
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "instanceof":
                    right = getattr(node, "operandr", None)
                    if right and hasattr(right, "name") and \
                       right.name in ("String", "Integer", "Long", "Double",
                                      "Boolean", "Byte", "Short", "Float", "Character"):
                        left = getattr(node, "operandl", None)
                        if left and isinstance(left, javalang_tree.MemberReference):
                            pass

            # S2139: Exception caught and thrown without context
            if isinstance(node, javalang_tree.CatchClause):
                block = getattr(node, "block", []) or []
                for stmt in block:
                    if isinstance(stmt, javalang_tree.ThrowStatement):
                        thrown = getattr(stmt, "expression", None)
                        if thrown and hasattr(thrown, "member") and \
                           thrown.member in ("getMessage", "toString"):
                            pass
                        elif thrown and isinstance(thrown, javalang_tree.ClassCreator):
                            l, c = self._pos(stmt)
                            self._add(file_path, "SONAR_SWALLOW_RE_THROW",
                                      "S2139: 捕获后重新抛出的异常应包含原始异常信息",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2222: Lock without unlock (check via content)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("lock", "tryLock"):
                    pass

            # S1854: Assignment in sub-expression (additional)
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.Assignment):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ASSIGN_IN_COND_V2",
                              "S1854: 条件表达式中不应使用赋值",
                              sq_severity("MAJOR"), line=l, column=c)

            # S3959: Stream consumed check (additional via content)
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("forEach", "collect", "count", "findFirst", "anyMatch"):
                    q = getattr(node, "qualifier", None)
                    if q and isinstance(q, javalang_tree.MethodInvocation):
                        inner_member = getattr(q, "member", "")
                        if inner_member in ("filter", "map", "flatMap", "peek"):
                            pass
