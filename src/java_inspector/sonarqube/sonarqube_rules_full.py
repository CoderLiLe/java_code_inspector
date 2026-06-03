"""SonarQubeCheckerFull — 完整规则集"""
"""SonarQubeCheckerFull — 完整规则集"""
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


class SonarQubeCheckerFull:
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
        self.check_error_prone(tree, file_path, content)
        self.check_best_practices(tree, file_path, content)
        self.check_clarity(tree, file_path, content)

    # ==================== Error-Prone ====================

    def check_error_prone(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_error_prone"):
            return
        lines = content.split("\n")

        # S107: Methods should not have too many parameters
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                params = getattr(node, "parameters", []) or []
                if len(params) > 7:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TOO_MANY_PARAMS",
                              "S107: 方法 '" + node.name + "' 有 " + str(len(params)) + " 个参数，建议不超过 7 个",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1118: Utility classes should not have public constructors
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                modifiers = node.modifiers or []
                if "abstract" in modifiers:
                    continue
                has_only_static_methods = True
                has_non_static_field = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if "static" not in (decl.modifiers or []):
                            has_only_static_methods = False
                    elif isinstance(decl, javalang_tree.FieldDeclaration):
                        if "static" not in (decl.modifiers or []):
                            has_non_static_field = True
                if has_only_static_methods and not has_non_static_field:
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.ConstructorDeclaration):
                            if not ("private" in (decl.modifiers or [])):
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_UTILITY_CLASS_CONSTRUCTOR",
                                          "S1118: 工具类 '" + node.name + "' 应包含私有构造方法以防止实例化",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S1134: Track uses of "FIXME" tags
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(?i)(fixme|FIXME)", line):
                col = line.index(m.group())
                self._add(file_path, "SONAR_FIXME_TAG",
                          "S1134: 代码中包含 FIXME 标记，表明存在待修复的问题",
                          _sq_severity("INFO"), line=i, column=col)

        # S1135: Track uses of "TODO" tags
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(?i)(todo|TODO)", line):
                col = line.index(m.group())
                self._add(file_path, "SONAR_TODO_TAG",
                          "S1135: 代码中包含 TODO 标记，表明有未完成的工作",
                          _sq_severity("INFO"), line=i, column=col)

        # S1182: Classes that override clone() should call super.clone()
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "clone":
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    has_super_clone = any(
                        "super.clone()" in str(stmt).replace(" ", "")
                        for stmt in body
                    )
                    if not has_super_clone:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLONE_SUPER",
                                  "S1182: 重写 clone() 的方法应调用 super.clone()",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1244: Floating point numbers should not be compared with ==
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("==", "!=") and \
                   isinstance(node.operandl, javalang_tree.Literal) and \
                   isinstance(node.operandr, javalang_tree.Literal):
                    left_val = getattr(node.operandl, "value", "")
                    right_val = getattr(node.operandr, "value", "")
                    if isinstance(left_val, str) and isinstance(right_val, str):
                        if re.match(r'^-?\d+\.\d+[fFdD]?$', left_val.strip('"')) or \
                           re.match(r'^-?\d+\.\d+[fFdD]?$', right_val.strip('"')):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_FLOAT_COMPARE",
                                      "S1244: 浮点数不应使用 '==' 比较，应检查误差范围",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S1258: Local variables should not shadow fields
        field_names = set()
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                for declarator in getattr(node, "declarators", []) or []:
                    field_names.add(getattr(declarator, "name", ""))
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body:
                    if isinstance(stmt, javalang_tree.LocalVariableDeclaration):
                        for declarator in getattr(stmt, "declarators", []) or []:
                            name = getattr(declarator, "name", "")
                            if name and name in field_names:
                                l, c = self._pos(stmt)
                                self._add(file_path, "SONAR_VARIABLE_SHADOWS_FIELD",
                                          "S1258: 局部变量 '" + name + "' 遮蔽了同名字段",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S134: Nested control flow should not be too deep (depth > 4)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else []
                if not body:
                    continue

                def depth_of_node(n, d=0):
                    issues = []
                    if d > 4:
                        l, _ = self._pos(n)
                        if l > 0:
                            issues.append(l)
                    children = getattr(n, "children", None) or []
                    for child in children:
                        if isinstance(child, (list, tuple)):
                            for c in child:
                                if hasattr(c, "children"):
                                    issues.extend(depth_of_node(c, d + 1))
                        elif hasattr(child, "children"):
                            issues.extend(depth_of_node(child, d + 1))
                    return issues

                check_lines = set()
                for stmt in body:
                    check_lines.update(depth_of_node(stmt, 0))
                for line in check_lines:
                    self._add(file_path, "SONAR_NESTED_DEPTH",
                              "S134: 控制流嵌套过深（超过 4 层），建议重构",
                              _sq_severity("MAJOR"), line=line)

        # S1481: Unused local variables
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                params = getattr(node, "parameters", []) or []
                param_names = {getattr(p, "name", "") for p in params}
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                local_vars = {}
                for stmt in body:
                    if isinstance(stmt, javalang_tree.LocalVariableDeclaration):
                        for declarator in getattr(stmt, "declarators", []) or []:
                            name = getattr(declarator, "name", "")
                            if name:
                                l, _ = self._pos(declarator)
                                if l == 0:
                                    l, _ = self._pos(stmt)
                                local_vars[name] = (l, 0, stmt)
                if not local_vars:
                    continue
                used_vars = set()
                for stmt in body:
                    stmt_str = str(stmt)
                    for vname in local_vars:
                        if stmt is not local_vars[vname][2] and \
                           re.search(r'\b' + re.escape(vname) + r'\b', stmt_str):
                            used_vars.add(vname)
                for vname, (l, c, _) in local_vars.items():
                    if vname not in used_vars:
                        self._add(file_path, "SONAR_UNUSED_LOCAL",
                                  "S1481: 未使用的局部变量 '" + vname + "'，建议移除",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2095: Resources should be closed
        for path, node in tree:
            if isinstance(node, javalang_tree.LocalVariableDeclaration):
                init = getattr(node, "initializer", None)
                if init and isinstance(init, javalang_tree.MethodInvocation):
                    method_name = getattr(init, "member", "")
                    if method_name in ("openStream", "openConnection", "getInputStream",
                                       "getOutputStream", "newInputStream", "newOutputStream",
                                       "newReader", "newWriter", "openInputStream", "openOutputStream"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLOSE_RESOURCE",
                                  "S2095: 打开的流/连接应使用 try-with-resources 或显式关闭",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2123: Values should not be compared with == to Integer/Long etc.
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
                        expr_str = str(node)
                        if any(
                            t in expr_str.replace(" ", "")
                            for t in ("Integer.valueOf", "Long.valueOf",
                                      ".intValue()", ".longValue()")
                        ):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_VALUE_COMPARE",
                                      "S2123: 包装类型值应使用 equals() 而非 == 进行比较",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2235: Enum values should be compared with == (not equals)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "equals":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ENUM_EQUALS",
                              "S2235: 枚举值应使用 == 而非 equals() 进行比较",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2254: Double Brace Initialization should not be used
        for i, line in enumerate(lines, 1):
            if re.search(r'new\s+[\w.]+\s*\(\s*\)\s*\{', line):
                self._add(file_path, "SONAR_DOUBLE_BRACE",
                          "S2254: 不应使用双大括号初始化（匿名内部类），会导致内存泄漏",
                          _sq_severity("MAJOR"), line=i)

        # S2676: "indexOf" should not be called on strings with a single character
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("indexOf", "lastIndexOf"):
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 1:
                        arg = args[0]
                        arg_value = getattr(arg, "value", "")
                        if isinstance(arg_value, str) and len(arg_value) == 3 and \
                           arg_value.startswith('"') and arg_value.endswith('"'):
                            inner = arg_value[1]
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_INDEXOF_CHAR",
                                      "S2676: indexOf/lastIndexOf 对单个字符应使用 char 字面量 '" +
                                      inner + "' 而非字符串 \"" + inner + "\"",
                                      _sq_severity("MINOR"), line=l, column=c,
                                      fix_suggestion="将 \"" + inner + "\" 替换为 '" + inner + "'")

        # S2677: "replace" should be called with char instead of String for single char
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("replace", "replaceAll", "replaceFirst"):
                    args = getattr(node, "arguments", []) or []
                    if len(args) >= 1 and member == "replace":
                        arg = args[0]
                        arg_value = getattr(arg, "value", "")
                        if isinstance(arg_value, str) and len(arg_value) == 3 and \
                           arg_value.startswith('"') and arg_value.endswith('"'):
                            inner = arg_value[1]
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_REPLACE_CHAR",
                                      "S2677: String.replace() 对单个字符应使用 char 字面量 '" +
                                      inner + "' 而非字符串",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S2864: Direct entrySet iteration instead of keySet + get
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "keySet":
                    qualifier = getattr(node, "qualifier", "") or ""
                    if qualifier:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_KEYSET_ITERATION",
                                  "S2864: 使用 keySet() 遍历后调用 get() 效率较低，建议使用 entrySet()",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S3011: Reflection should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("setAccessible", "getDeclaredField", "getDeclaredMethod",
                              "getDeclaredConstructor", "getField", "getMethod"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_REFLECTION",
                              "S3011: 不应使用反射 API '" + member + "()'，建议使用封装好的 API",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S3973: Empty statement (semicolon)
        for i, line in enumerate(lines, 1):
            no_comment = re.sub(r'//.*', '', line).strip()
            # Find empty semicolons (;; or a ; that is the only thing in a block)
            if re.search(r';[\s]*;', no_comment) or \
               re.search(r'\{[\s]*;[\s]*\}', no_comment):
                self._add(file_path, "SONAR_EMPTY_STATEMENT",
                          "S3973: 空语句（多余的分号），应移除",
                          _sq_severity("MAJOR"), line=i)

        # S4032: Collection.addAll should be used instead of forEach add
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body:
                    if isinstance(stmt, javalang_tree.StatementExpression):
                        expr = getattr(stmt, "expression", None)
                        if isinstance(expr, javalang_tree.MethodInvocation):
                            member = getattr(expr, "member", "")
                            if member == "add":
                                l, c = self._pos(stmt)
                                self._add(file_path, "SONAR_ADDALL",
                                          "S4032: 循环中逐个 add() 应替换为 addAll()",
                                          _sq_severity("MINOR"), line=l, column=c)

        # S4408: Classes with only static methods should be final
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                modifiers = node.modifiers or []
                if "final" in modifiers:
                    continue
                all_static = True
                has_method = False
                has_non_static = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        has_method = True
                        if "static" not in (decl.modifiers or []):
                            has_non_static = True
                            all_static = False
                if has_method and all_static and not has_non_static:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STATIC_CLASS_FINAL",
                              "S4408: 仅包含静态方法的类应声明为 final",
                              _sq_severity("MINOR"), line=l, column=c)

    # ==================== Best Practices ====================

    def check_best_practices(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_best_practices"):
            return
        lines = content.split("\n")

        # S114: Interfaces should not be empty (can also be merged with S1188)
        for path, node in tree:
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                body = getattr(node, "body", []) or []
                if not body or all(
                    isinstance(m, (javalang_tree.FieldDeclaration,)) and
                    not hasattr(m, "declarators") or
                    not getattr(m, "declarators", [])
                    for m in body if isinstance(m, javalang_tree.FieldDeclaration)
                ):
                    if not body or len(body) == 0:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_EMPTY_INTERFACE",
                                  "S114: 不应存在空的接口",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S115: Constant names should comply with a naming convention (UPPER_CASE)
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "static" in modifiers and "final" in modifiers:
                    for declarator in getattr(node, "declarators", []) or []:
                        name = getattr(declarator, "name", "")
                        if name and not re.match(r'^[A-Z][A-Z0-9_]*$', name) and \
                           not all(c == "_" for c in name):
                            l, c = self._pos(declarator)
                            self._add(file_path, "SONAR_CONSTANT_NAMING",
                                      "S115: 常量名称 '" + name + "' 应使用全大写加下划线格式（如 " +
                                      re.sub(r'(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])',
                                             '_', name).upper() + "）",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S116: Exception class names should end with "Exception"
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                extends = getattr(node, "extends", None)
                if extends and hasattr(extends, "name"):
                    if extends.name in ("Exception", "RuntimeException", "Throwable"):
                        if not node.name.endswith("Exception"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_EXCEPTION_NAMING",
                                      "S116: 异常类名 '" + node.name + "' 应以 'Exception' 结尾",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S117: Names of local variables should comply with naming convention
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body:
                    if isinstance(stmt, javalang_tree.LocalVariableDeclaration):
                        for declarator in getattr(stmt, "declarators", []) or []:
                            name = getattr(declarator, "name", "")
                            if name and name[0].isupper():
                                l, c = self._pos(declarator)
                                self._add(file_path, "SONAR_VARIABLE_NAMING",
                                          "S117: 局部变量名 '" + name + "' 应使用 camelCase 命名",
                                          _sq_severity("MINOR"), line=l, column=c)

        # S119: Type parameter names should comply with naming convention
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration) or \
               isinstance(node, javalang_tree.MethodDeclaration) or \
               isinstance(node, javalang_tree.InterfaceDeclaration):
                type_params = getattr(node, "type_parameters", []) or \
                              getattr(node, "typeParameters", None) or []
                for tp in type_params:
                    tp_name = getattr(tp, "name", str(tp))
                    if tp_name and not re.match(r'^[A-Z]$', tp_name) and \
                       not re.match(r'^[A-Z][A-Z0-9_]*$', tp_name):
                        l, _ = self._pos(tp) if hasattr(tp, "position") and tp.position else (0, 0)
                        if l == 0:
                            continue
                        self._add(file_path, "SONAR_TYPE_PARAM_NAMING",
                                  "S119: 类型参数名 '" + tp_name + "' 应使用单大写字母（如 T, E, K, V）",
                                  _sq_severity("MINOR"), line=l)

        # S120: Package names should comply with naming convention
        for path, node in tree:
            if isinstance(node, javalang_tree.PackageDeclaration):
                pkg_name = getattr(node, "name", "")
                if pkg_name:
                    parts = pkg_name.split(".")
                    for part in parts:
                        if part and part[0].isupper():
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_PACKAGE_NAMING",
                                      "S120: 包名 '" + pkg_name + "' 各部分应使用小写",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S1312: Loggers should be private static final
        def _get_full_type_name(t):
            name = getattr(t, "name", "")
            sub = getattr(t, "sub_type", None)
            if sub:
                sub_name = _get_full_type_name(sub)
                if sub_name:
                    return name + "." + sub_name
            return name

        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node) if type_node else ""
                if type_name.endswith(("Logger", "Log")):
                    modifiers = node.modifiers or []
                    if "private" not in modifiers:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_LOGGER_PRIVATE",
                                  "S1312: Logger 应声明为 private",
                                  _sq_severity("MAJOR"), line=l, column=c)
                    if "static" not in modifiers:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_LOGGER_STATIC",
                                  "S1312: Logger 应声明为 static",
                                  _sq_severity("MAJOR"), line=l, column=c)
                    if "final" not in modifiers:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_LOGGER_FINAL",
                                  "S1312: Logger 应声明为 final",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1607: JUnit tests should include assertions
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                has_test_annotation = False
                annotations = getattr(node, "annotations", None) or []
                for ann in annotations:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if "Test" in ann_name:
                        has_test_annotation = True
                        break
                if has_test_annotation or node.name.startswith("test"):
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    body_source = " ".join(str(s) for s in body)
                    if not re.search(r'\b(assert|Assert\.|Assertions\.|fail\s*\()', body_source):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TEST_ASSERTION",
                                  "S1607: 测试方法 '" + node.name + "' 中不包含断言",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1701: Diamond operator should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                continue
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_args = getattr(node, "type_arguments", None) or \
                            getattr(node, "typeArguments", []) or []
                if type_args:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_DIAMOND",
                              "S1701: 应使用菱形运算符 <> 代替显式的泛型类型参数",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2133: Strings should not be compared by == (partially covered in sonar_bugs)
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("!=", "=="):
                    left_type = type(getattr(node, "operandl", None)).__name__
                    right_type = type(getattr(node, "operandr", None)).__name__
                    if "MethodInvocation" in (left_type, right_type):
                        qualifier = getattr(getattr(node, "operandl", None), "qualifier", None) if \
                                    hasattr(getattr(node, "operandl", None), "qualifier") else ""
                        if qualifier == "String":
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_STRING_COMPARE",
                                      "S2133: 不应使用 == 比较字符串结果，应使用 equals()",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2699: Tests should include assertions (duplicate check with S1607)
        # Reusing S1607 above, also check for test methods annotated with @Test
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                annotations = getattr(node, "annotations", None) or []
                is_test = False
                for ann in annotations:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if "Test" in ann_name:
                        is_test = True
                        break
                if is_test:
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    body_source = " ".join(str(s) for s in body)
                    if not re.search(r'\b(assert|Assert\.|Assertions\.|fail\s*\()', body_source):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TEST_WITHOUT_ASSERTION",
                                  "S2699: @Test 方法 '" + node.name + "' 应包含断言",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S3252: Static members should be accessed statically
        for path, node in tree:
            if isinstance(node, javalang_tree.MemberReference):
                prefix = getattr(node, "prefix_operators", []) or []
                postfix = getattr(node, "postfix_operators", []) or []
                qualifier = getattr(node, "qualifier", "")
                member = getattr(node, "member", "")
                if qualifier and member and qualifier[0].islower():
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STATIC_ACCESS",
                              "S3252: 静态成员 '" + member + "' 应通过类名而非对象引用访问",
                              _sq_severity("MINOR"), line=l, column=c)

        # S3305: Annotations on enum constants
        for path, node in tree:
            if isinstance(node, javalang_tree.EnumDeclaration):
                body = getattr(node, "body", []) or []
                for decl in body:
                    if isinstance(decl, javalang_tree.EnumConstantDeclaration):
                        annotations = getattr(decl, "annotations", None) or []
                        if annotations:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_ENUM_CONSTANT_ANNOTATION",
                                      "S3305: 不应在枚举常量上使用注解",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S3546: Abstract classes should be declared with 'abstract' keyword
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                modifiers = node.modifiers or []
                if "abstract" in modifiers:
                    continue
                has_abstract_method = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if "abstract" in (decl.modifiers or []):
                            has_abstract_method = True
                            break
                if has_abstract_method:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ABSTRACT_CLASS",
                              "S3546: 包含抽象方法的类应使用 'abstract' 关键字声明",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Clarity ====================

    def check_clarity(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_clarity"):
            return
        lines = content.split("\n")

        # S100: Method names should comply with naming convention (camelCase)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                name = node.name
                if not re.match(r'^[a-z][a-zA-Z0-9]*$', name) and \
                   name != name.upper() and \
                   name not in self._METHOD_BLACKLIST and \
                   name != "<init>":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_METHOD_NAMING",
                              "S100: 方法名 '" + name + "' 应使用 camelCase 命名规范",
                              _sq_severity("MINOR"), line=l, column=c)

        # S101: Class names should comply with naming convention (PascalCase)
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                name = node.name
                if name and not re.match(r'^[A-Z][a-zA-Z0-9]*$', name) and \
                   not all(c.isupper() or c == "_" for c in name):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CLASS_NAMING",
                              "S101: 类名 '" + name + "' 应使用 PascalCase 命名规范",
                              _sq_severity("MINOR"), line=l, column=c)

        # S1066: Collapsible "if" statements
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                then_stmt = getattr(node, "then_statement", None)
                if then_stmt and isinstance(then_stmt, javalang_tree.BlockStatement):
                    block = then_stmt
                    statements = getattr(block, "statements", []) or \
                                getattr(block, "body", []) or []
                    if len(statements) == 1 and \
                       isinstance(statements[0], javalang_tree.IfStatement):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_COLLAPSIBLE_IF",
                                  "S1066: 可合并的 if 语句，建议将内层条件合并到外层",
                                  _sq_severity("MAJOR"), line=l, column=c,
                                  fix_suggestion="合并 if 条件")

        # S1117: Local variables should not shadow class type parameters or fields
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration) or \
               isinstance(node, javalang_tree.InterfaceDeclaration):
                type_params = getattr(node, "type_parameters", []) or \
                              getattr(node, "typeParameters", None) or []
                tp_names = {getattr(t, "name", str(t)) for t in type_params}
                for path2, node2 in tree:
                    if isinstance(node2, javalang_tree.LocalVariableDeclaration):
                        for decl in getattr(node2, "declarators", []) or []:
                            name = getattr(decl, "name", "")
                            if name in tp_names:
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_VARIABLE_SHADOWS_TYPE_PARAM",
                                          "S1117: 局部变量 '" + name + "' 遮蔽了类型参数",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S1120: Serializable classes should have serialVersionUID
        # (Also activates S1220 which was previously non-functioning)
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                implements = getattr(node, "implements", []) or []
                is_serializable = False
                for iface in implements:
                    iface_name = getattr(iface, "name", str(iface))
                    if "Serializable" in iface_name:
                        is_serializable = True
                        break
                extends = getattr(node, "extends", None)
                if extends and hasattr(extends, "name"):
                    if "Serializable" in getattr(extends, "name", ""):
                        is_serializable = True
                if is_serializable:
                    has_uid = False
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.FieldDeclaration):
                            for declarator in getattr(decl, "declarators", []) or []:
                                name = getattr(declarator, "name", "")
                                if "serialVersionUID" in name:
                                    has_uid = True
                                    modifiers = decl.modifiers or []
                                    if "private" not in modifiers:
                                        l, c = self._pos(decl)
                                        self._add(file_path, "SONAR_SERIAL_UID_PRIVATE",
                                                  "S1120: serialVersionUID 应声明为 private",
                                                  _sq_severity("MAJOR"), line=l, column=c)
                                    if "static" not in modifiers:
                                        l, c = self._pos(decl)
                                        self._add(file_path, "SONAR_SERIAL_UID_STATIC",
                                                  "S1120: serialVersionUID 应声明为 static",
                                                  _sq_severity("MAJOR"), line=l, column=c)
                                    if "final" not in modifiers:
                                        l, c = self._pos(decl)
                                        self._add(file_path, "SONAR_SERIAL_UID_FINAL",
                                                  "S1120: serialVersionUID 应声明为 final",
                                                  _sq_severity("MAJOR"), line=l, column=c)
                    if not has_uid:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SERIAL_VERSION_UID",
                                  "S1120: 实现 Serializable 的类 '" + node.name + "' 应定义 serialVersionUID",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1126: Return of boolean expressions should not be wrapped in if-then-else
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                then_stmt = getattr(node, "then_statement", None)
                else_stmt = getattr(node, "else_statement", None)
                if then_stmt and else_stmt:
                    then_stmts = getattr(then_stmt, "statements", []) if \
                                 isinstance(then_stmt, (javalang_tree.BlockStatement,)) else []
                    else_stmts = getattr(else_stmt, "statements", []) if \
                                 isinstance(else_stmt, (javalang_tree.BlockStatement,)) else []
                    if len(then_stmts) == 1 and len(else_stmts) == 1:
                        then_str = str(then_stmts[0])
                        else_str = str(else_stmts[0])
                        if "value=true" in then_str and "value=false" in else_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_RETURN_BOOL_EXPR",
                                      "S1126: 应直接返回布尔表达式而非 if-else",
                                      _sq_severity("MINOR"), line=l, column=c,
                                      fix_suggestion="替换为 'return <condition>'")
                        elif "value=false" in then_str and "value=true" in else_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_RETURN_BOOL_EXPR",
                                      "S1126: 应直接返回布尔表达式而非 if-else",
                                      _sq_severity("MINOR"), line=l, column=c,
                                      fix_suggestion="替换为 'return !<condition>'")

        # S1340: Type parameter names should not be suspiciously long
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration) or \
               isinstance(node, javalang_tree.MethodDeclaration):
                type_params = getattr(node, "type_parameters", []) or \
                              getattr(node, "typeParameters", None) or []
                for tp in type_params:
                    tp_name = getattr(tp, "name", str(tp))
                    if len(tp_name) > 3:
                        l, _ = self._pos(tp) if hasattr(tp, "position") and tp.position else (0, 0)
                        if l == 0:
                            continue
                        self._add(file_path, "SONAR_TYPE_PARAM_LONG",
                                  "S1340: 类型参数名 '" + tp_name + "' 过长，建议使用单大写字母",
                                  _sq_severity("MINOR"), line=l)

        # S139: Comments should not be placed at the end of lines
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if "//" in stripped:
                code_part = stripped.split("//")[0].strip()
                if code_part and len(code_part) > 0:
                    self._add(file_path, "SONAR_COMMENT_AT_END",
                              "S139: 不应在行尾添加注释，应将注释放在代码上方",
                              _sq_severity("INFO"), line=i)

        # S1659: Multiple variables should not be declared on the same line
        for path, node in tree:
            if isinstance(node, javalang_tree.LocalVariableDeclaration):
                declarators = getattr(node, "declarators", []) or []
                if len(declarators) > 1:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_MULTI_VAR_DECL",
                              "S1659: 不应在同一行声明多个变量，应分开声明",
                              _sq_severity("MINOR"), line=l, column=c)

        # S1763: Jump statements should not be followed by dead code
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for idx, stmt in enumerate(body):
                    if isinstance(stmt, (javalang_tree.ReturnStatement,
                                         javalang_tree.ThrowStatement,
                                         javalang_tree.BreakStatement,
                                         javalang_tree.ContinueStatement)):
                        if idx + 1 < len(body):
                            next_stmt = body[idx + 1]
                            if not isinstance(next_stmt,
                                              (javalang_tree.ReturnStatement,
                                               javalang_tree.ThrowStatement)):
                                l = getattr(getattr(next_stmt, "position", None), "line", 0)
                                if l:
                                    self._add(file_path, "SONAR_DEAD_CODE_AFTER_JUMP",
                                              "S1763: 跳转语句之后的代码将无法执行，应移除",
                                              _sq_severity("MAJOR"), line=l)

        # S1994: "for" loop increment clauses should modify loop variable
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                update = getattr(node, "update", []) or []
                control_var = getattr(node, "control", None)
                var_name = ""
                if control_var and hasattr(control_var, "var"):
                    var_name = getattr(control_var.var, "name", "")
                if var_name and update:
                    update_source = " ".join(str(u) for u in update)
                    if var_name not in update_source:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FOR_LOOP_VARIABLE",
                                  "S1994: for 循环的增量部分应修改循环控制变量 '" +
                                  var_name + "'",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S3256: The iterator of a "for" loop should not be used in the loop body
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                control = getattr(node, "control", None)
                if control and hasattr(control, "var"):
                    var_name = getattr(control.var, "name", "")
                    if var_name:
                        body = node.body if isinstance(node.body, list) else \
                               getattr(getattr(node, "body", None), "statements", []) or []
                        for stmt in body:
                            stmt_str = str(stmt)
                            patterns = [
                                var_name + ".add(",
                                var_name + ".remove(",
                                var_name + ".clear()",
                            ]
                            for pat in patterns:
                                if pat in stmt_str:
                                    l, c = self._pos(stmt)
                                    self._add(file_path, "SONAR_MODIFY_FOR_VARIABLE",
                                              "S3256: 不应在循环体中修改迭代器/循环变量 '" +
                                              var_name + "'",
                                              _sq_severity("MAJOR"), line=l, column=c)
                                    break

        # S1221: Method names should not differ only by case
        method_names = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        name = decl.name
                        name_lower = name.lower()
                        if name_lower in method_names:
                            other_name = method_names[name_lower]
                            if name != other_name:
                                self._add(file_path, "SONAR_METHOD_CASE_CONFLICT",
                                          "S1221: 方法名 '" + name + "' 与 '" +
                                          other_name + "' 仅在大小写上不同，会造成混淆",
                                          _sq_severity("MAJOR"),
                                          line=decl.position.line if decl.position else 0)
                        else:
                            method_names[name_lower] = name
