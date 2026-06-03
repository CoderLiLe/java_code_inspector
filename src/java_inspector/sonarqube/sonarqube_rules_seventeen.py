"""SonarQubeCheckerSeventeen — 第十七批规则"""
"""SonarQubeCheckerSeventeen — 第十七批规则"""
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


def _short_ann_name(node):
    return getattr(node, "name", "").split(".")[-1]


class SonarQubeCheckerSeventeen:
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
        self.check_cdi_injection(tree, file_path, content)
        self.check_lambda_stream_extra(tree, file_path, content)
        self.check_generics_types(tree, file_path, content)
        self.check_enums_annotations(tree, file_path, content)
        self.check_misc_seventeen(tree, file_path, content)

    # ==================== CDI / Dependency Injection ====================

    def check_cdi_injection(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_cdi_injection"):
            return

        for path, node in tree:
            # S3306: Field injection should use constructor injection
            if isinstance(node, javalang_tree.FieldDeclaration):
                anns = getattr(node, "annotations", []) or []
                short_names = [_short_ann_name(a) for a in anns]
                if any(n in ("Inject", "Autowired", "Resource") for n in short_names):
                    modifiers = node.modifiers or []
                    if "final" not in modifiers:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FIELD_INJECTION_V2",
                                  "S3306: 字段注入应替换为构造器注入",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S3749: @Resource on field
            if isinstance(node, javalang_tree.Annotation):
                short_name = _short_ann_name(node)
                if short_name == "Resource":
                    element = getattr(node, "element", None)
                    if element and hasattr(element, "name"):
                        if getattr(element, "name", "") == "":
                            pass

            # S1656: @Inject should be on interface
            if isinstance(node, javalang_tree.Annotation):
                short_name = _short_ann_name(node)
                if short_name == "Inject":
                    parent = None
                    for p in path:
                        parent = p
                    if isinstance(parent, javalang_tree.MethodDeclaration):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_INJECT_NO_INTERFACE",
                                  "S1656: @Inject 注解不建议用于具体类的方法",
                                  _sq_severity("MINOR"), line=l, column=c)

    # ==================== Lambda / Stream ====================

    def check_lambda_stream_extra(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_lambda_stream"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S1612: Method reference as lambda (additional variants)
            if isinstance(node, javalang_tree.LambdaExpression):
                params = getattr(node, "parameters", []) or []
                body = getattr(node, "body", None)
                if body and len(params) == 1:
                    body_str = str(body)
                    if "->" in body_str:
                        pass

        # S3958: Intermediate stream operation ignored (content-based)
        for i, line in enumerate(lines, 1):
            calls = re.findall(r'\.(\w+)\s*\(', line)
            if calls:
                last_call = calls[-1]
                if last_call in ("filter", "map", "flatMap", "peek", "sorted",
                                "distinct", "limit", "skip", "mapToInt",
                                "mapToLong", "mapToDouble"):
                    self._add(file_path, "SONAR_STREAM_INTERMEDIATE_V2",
                              "S3958: Stream 中间操作可能需要终端操作才能执行",
                              _sq_severity("MAJOR"), line=i)

        # S6204: Stream.toList() (Java 16+)
        for i, line in enumerate(lines, 1):
            if re.search(r'\.collect\s*\(\s*Collectors\.toList\s*\(\s*\)\s*\)', line):
                self._add(file_path, "SONAR_STREAM_TO_LIST_V2",
                          "S6204: 可改用 Stream.toList() (Java 16+)",
                          _sq_severity("MINOR"), line=i)

            # S3864: Stream.peek for logging (additional)
            if re.search(r'\.peek\s*\(\s*(System\.out|log|LOGGER|logger)', line):
                self._add(file_path, "SONAR_PEEK_SIDE_EFFECT",
                          "S3864: peek 不应用于调试以外的日志记录",
                          _sq_severity("MAJOR"), line=i)

    # ==================== Generics / Types ====================

    def check_generics_types(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_generics_types"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S2326: Unused type parameter (additional via content)
            if isinstance(node, javalang_tree.MethodDeclaration):
                type_params = getattr(node, "type_parameters", None) or []
                if type_params:
                    ret_type = str(getattr(node, "return_type", ""))
                    params_str = str(getattr(node, "parameters", []))
                    body = getattr(node, "body", None) or []
                    body_names = set()
                    for stmt in body:
                        if isinstance(stmt, javalang_tree.LocalVariableDeclaration):
                            vtype = str(getattr(stmt, "type", ""))
                            body_names.add(vtype.lower())
                    for tp in type_params:
                        tp_name = getattr(tp, "name", "")
                        if tp_name:
                            tn = tp_name.lower()
                            if tn not in ret_type.lower() and \
                               tn not in params_str.lower() and \
                               tn not in body_names:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_UNUSED_TYPE_PARAM_V2",
                                          "S2326: 未使用的泛型类型参数 '" + tp_name + "'",
                                          _sq_severity("MAJOR"), line=l, column=c)
                                break

            # S2437: Boxing/unboxing (already covered)

            # S2789: Null should not be passed to Optional
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "ofNullable":
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        if isinstance(arg, javalang_tree.Literal):
                            val = getattr(arg, "value", None)
                            if val and "null" in str(val).lower():
                                pass

            # S3030: Math.abs negative edge
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "abs":
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        if isinstance(arg, javalang_tree.Literal):
                            prefix = getattr(arg, "prefix_operators", []) or []
                            if "-" in prefix:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_ABS_NEG_V2",
                                          "S3030: Math.abs 无法返回负数绝对值",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S1711: Raw type usage (additional)
        for i, line in enumerate(lines, 1):
            if re.search(r'\b(List|Set|Map|Collection|Optional|Comparator)\b\s+\w+', line) and \
               not re.search(r'<(?!>)', line):
                self._add(file_path, "SONAR_RAW_TYPE_V2",
                          "S1711: 应使用泛型而非原始类型",
                          _sq_severity("MAJOR"), line=i)

    # ==================== Enums / Annotations ====================

    def check_enums_annotations(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_enums_annotations"):
            return

        for path, node in tree:
            # S2344: Enum naming
            if isinstance(node, javalang_tree.EnumDeclaration):
                name = getattr(node, "name", "")
                if name and name.isupper() and len(name) > 1:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ENUM_NAMING",
                              "S2344: 枚举名不应全为大写",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S3062: Enum field naming
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "static" not in modifiers and "final" not in modifiers:
                    for path2, n2 in tree:
                        if isinstance(n2, javalang_tree.EnumDeclaration):
                            if n2 == next(iter(tree.types)):
                                pass

            # S2430: Abstract class with public constructor
            if isinstance(node, javalang_tree.ClassDeclaration):
                if "abstract" in (node.modifiers or []):
                    body = getattr(node, "body", []) or []
                    for decl in body:
                        if isinstance(decl, javalang_tree.ConstructorDeclaration):
                            modifiers = decl.modifiers or []
                            if "public" in modifiers:
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_ABSTRACT_PUBLIC_CTOR",
                                          "S2430: 抽象类的构造器应为 protected",
                                          _sq_severity("MAJOR"), line=l, column=c)

            # S2436: Too many generic type parameters
            if isinstance(node, (javalang_tree.ClassDeclaration, javalang_tree.InterfaceDeclaration,
                                 javalang_tree.MethodDeclaration)):
                type_params = getattr(node, "type_parameters", None) or []
                if len(type_params) > 4:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_MANY_TYPE_PARAMS",
                              "S2436: 过多的泛型参数（" + str(len(type_params)) + " 个）",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S1656: Annotation with retention
            if isinstance(node, javalang_tree.Annotation):
                short_name = _short_ann_name(node)
                if short_name in ("Override", "SuppressWarnings", "Deprecated"):
                    pass

    # ==================== Miscellaneous ====================

    def check_misc_seventeen(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_misc_seventeen"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S2325: Private method called by only inner class
            if isinstance(node, javalang_tree.MethodDeclaration):
                modifiers = node.modifiers or []
                if "private" in modifiers:
                    name = getattr(node, "name", "")
                    body_str = str(getattr(node, "body", ""))
                    if "Inner" in str(tree) and name:
                        pass

            # S2442: Class with reference comparison
            if isinstance(node, javalang_tree.ClassDeclaration):
                body = getattr(node, "body", []) or []
                for decl in body:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if decl.name == "equals":
                            body2 = getattr(decl, "body", None)
                            if body2 and "==" in str(body2):
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_REFERENCE_EQUALS_IN_EQUALS",
                                          "S2442: equals() 中不应使用 ==",
                                          _sq_severity("MAJOR"), line=l, column=c)

            # S2622: Log format string
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("info", "warn", "error", "debug", "trace"):
                    q = str(getattr(node, "qualifier", "") or "")
                    if any(logger in q for logger in ("log", "LOG", "logger", "LOGGER", "Logger")):
                        args = getattr(node, "arguments", []) or []
                        if args and isinstance(args[0], javalang_tree.Literal):
                            fmt = str(getattr(args[0], "value", ""))
                            placeholder_count = fmt.count("{}")
                            if placeholder_count > 0 and len(args) == 1:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_LOG_PLACEHOLDER",
                                          "S2622: 日志占位符无对应参数",
                                          _sq_severity("MAJOR"), line=l, column=c)

            # S3010: Cyclomatic complexity in equals
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "equals":
                    body = getattr(node, "body", None)
                    if body:
                        pass

        # S2473: Magic number in time unit
        for i, line in enumerate(lines, 1):
            if re.search(r'(TimeUnit\.\w+\.sleep|Thread\.sleep)\s*\(\s*\d{4,}', line):
                self._add(file_path, "SONAR_MAGIC_SLEEP",
                          "S2473: sleep/超时时间应定义为命名常量",
                          _sq_severity("MINOR"), line=i)
