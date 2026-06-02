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


class SonarQubeCheckerEight:
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
        self.check_spring_framework(tree, file_path)
        self.check_java_features(tree, file_path, content)
        self.check_testing_patterns(tree, file_path, content)
        self.check_redundancy(tree, file_path)

    # ==================== Spring Framework ====================

    def check_spring_framework(self, tree, file_path: str):
        if not self.config.is_rule_enabled("sonar_spring"):
            return

        for path, node in tree:
            # S3751: @Controller class should not have field injection
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_controller = False
                injected_fields = []
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name in ("Controller", "RestController", "Service", "Repository", "Component"):
                        has_controller = True
                if has_controller:
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.FieldDeclaration):
                            for ann in getattr(decl, "annotations", []) or []:
                                ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                                if ann_name in ("Autowired", "Inject", "Resource"):
                                    for var in getattr(decl, "declarators", []) or []:
                                        name = getattr(var, "name", "")
                                        if name and "final" not in (decl.modifiers or []):
                                            l, c = self._pos(var)
                                            self._add(file_path, "SONAR_FIELD_INJECTION",
                                                      "S4605: 推荐使用构造器注入替代字段注入 @Autowired",
                                                      _sq_severity("MAJOR"), line=l, column=c)

            # S4602: @RequestMapping should be in @Controller
            if isinstance(node, javalang_tree.ClassDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        for ann in getattr(decl, "annotations", []) or []:
                            ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                            if ann_name in ("RequestMapping", "GetMapping", "PostMapping",
                                            "PutMapping", "DeleteMapping", "PatchMapping"):
                                if "Controller" not in ann_names and "RestController" not in ann_names:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_SPRING_MAPPING_WITHOUT_CONTROLLER",
                                              "S4602: 含 @RequestMapping 的类应标注 @Controller",
                                              _sq_severity("MAJOR"), line=l, column=c)

            # S4621: Spring MVC annotation should specify method
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "RequestMapping":
                        ann_element = getattr(ann, "element", None) or \
                                      getattr(ann, "attributes", None) or \
                                      getattr(ann, "args", None)
                        elem_str = str(ann_element) if ann_element else ""
                        if "method" not in elem_str and "RequestMethod" not in elem_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_SPRING_METHOD_HTTP_METHOD",
                                      "S4621: @RequestMapping 应指定 HTTP method（GET/POST 等）",
                                      _sq_severity("MINOR"), line=l, column=c)

            # S4682: @RequestMapping on class level should be preferred
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name in ("GetMapping", "PostMapping", "PutMapping",
                                    "DeleteMapping", "PatchMapping"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SPRING_SPECIFIC_MAPPING",
                                  "S4682: 建议使用 @RequestMapping 及 method 属性替代特定注解",
                                  _sq_severity("INFO"), line=l, column=c)

            # S4719: Spring Data repository should be interface
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                for impl in imp:
                    impl_name = getattr(impl, "name", "") if hasattr(impl, "name") else str(impl)
                    if "Repository" in impl_name or "JpaRepository" in impl_name:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SPRING_REPOSITORY",
                                  "S4719: Spring Data Repository 应定义为接口而非类",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S4635: @RequestParam should have default value
            if isinstance(node, javalang_tree.MethodDeclaration):
                params = getattr(node, "parameters", []) or []
                for param in params:
                    for ann in getattr(param, "annotations", []) or []:
                        ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                        if ann_name == "RequestParam":
                            l, c = self._pos(param)
                            self._add(file_path, "SONAR_REQUEST_PARAM_DEFAULT",
                                      "S4635: @RequestParam 应指定 defaultValue 或 required=false",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S4700: Spring SQL query should use parameter binding
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "Query":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SPRING_QUERY",
                                  "S4700: @Query 应使用参数绑定避免 SQL 注入",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S4604: @Autowired should be on constructor
            if isinstance(node, javalang_tree.FieldDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "Autowired":
                        for var in getattr(node, "declarators", []) or []:
                            name = getattr(var, "name", "")
                            if name:
                                l, c = self._pos(var)
                                self._add(file_path, "SONAR_AUTOWIRED_FIELD",
                                          "S4604: @Autowired 应使用构造器注入而非字段注入",
                                          _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Java Features (8+) ====================

    def check_java_features(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_java_features"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S5958: Lambda can be replaced with method reference
            if isinstance(node, javalang_tree.LambdaExpression):
                params = getattr(node, "parameters", []) or []
                body = getattr(node, "body", None)
                if body and len(params) == 1:
                    body_str = str(body).replace(" ", "").replace("\n", "")
                    param_name = str(params[0]).strip()
                    patterns = [
                        param_name + "->" + param_name + "\\.\\w+\\(",
                        param_name + "->\\w+\\." + param_name,
                        "\\(" + param_name + "\\)->" + param_name + "\\.\\w+\\(",
                    ]
                    for pat in patterns:
                        if re.match(pat, body_str):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_LAMBDA_METHOD_REF",
                                      "S5958: Lambda 可替换为方法引用",
                                      _sq_severity("MINOR"), line=l, column=c)
                            break

            # S5960: Comparator should be lambda
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                is_comparator = any(
                    "Comparator" in (getattr(i, "name", "") if hasattr(i, "name") else str(i))
                    for i in imp
                )
                if is_comparator:
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            if decl.name == "compare":
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_COMPARATOR_LAMBDA",
                                          "S5960: Comparator 应使用 Lambda 表达式替代匿名类",
                                          _sq_severity("MINOR"), line=l, column=c)

            # S3864: Stream peek for debugging only (already in fourth but let's add more)
            # S6092: Optional should not be used as field
            if isinstance(node, javalang_tree.FieldDeclaration):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                base_name = type_name.split(".")[-1] if "." in type_name else type_name
                if base_name == "Optional":
                    for var in getattr(node, "declarators", []) or []:
                        name = getattr(var, "name", "")
                        if name:
                            l, c = self._pos(var)
                            self._add(file_path, "SONAR_OPTIONAL_FIELD",
                                      "S6092: Optional 不应作为字段类型",
                                      _sq_severity("MAJOR"), line=l, column=c)

            # S6093: Lambda parameter type should be inferred
            if isinstance(node, javalang_tree.LambdaExpression):
                params = getattr(node, "parameters", []) or []
                for param in params:
                    param_str = str(param)
                    if " " in param_str or "int " in param_str or "String " in param_str or \
                       "Integer " in param_str or "Long " in param_str or "Boolean " in param_str:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_LAMBDA_PARAM_TYPE",
                                  "S6093: Lambda 参数类型可省略（类型推断）",
                                  _sq_severity("MINOR"), line=l, column=c)
                        break

            # S5994: Record should be used for simple data carriers
            if isinstance(node, javalang_tree.ClassDeclaration):
                fields = 0
                methods = 0
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.FieldDeclaration):
                        for ann in getattr(decl, "annotations", []) or []:
                            ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                            if ann_name == "Getter":
                                fields += 1
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if decl.name in ("get" + str(getattr(getattr(node, "name", ""), "", ""))):
                            methods += 1
                if fields >= 2 and methods >= fields:
                    pass

            # S5996: Text block should be used
            for i, line in enumerate(lines, 1):
                if '\\n"' in line or '\\r\\n"' in line or '\n+"' in line:
                    if line.strip().startswith('"') and '\\n' in line:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TEXT_BLOCK",
                                  "S5996: 多行字符串应使用 Java 13+ Text Block",
                                  _sq_severity("MINOR"), line=i)
                        break

            # S6000: Sealed class hierarchy
            if isinstance(node, javalang_tree.ClassDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "AllArgsConstructor" in ann_names or "Value" in ann_names:
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            if decl.name == "equals" or decl.name == "hashCode":
                                pass

            # S6021: Pattern matching instanceof
            for path2, node2 in tree:
                if isinstance(node2, javalang_tree.IfStatement):
                    cond = getattr(node2, "condition", None)
                    if cond and isinstance(cond, javalang_tree.BinaryOperation):
                        if getattr(cond, "operator", "") == "instanceof":
                            then_stmt = getattr(node2, "then_statement", None)
                            if then_stmt:
                                then_str = str(then_stmt)
                                var_name = None
                                right = getattr(cond, "operandr", None)
                                if right and hasattr(right, "name"):
                                    var_name = getattr(right, "name", "")
                                    if var_name and var_name[0].islower() if var_name else False:
                                        pass
                                right_str = str(getattr(cond, "operandr", ""))
                                if right_str and right_str[0].islower() if right_str else False:
                                    pass

            # S6023: Switch with arrow
            for path2, node2 in tree:
                if isinstance(node2, javalang_tree.SwitchStatement):
                    cases = getattr(node2, "cases", []) or []
                    for case in cases:
                        stmts = getattr(case, "statements", []) or []
                        for stmt in stmts:
                            stmt_str = str(stmt)
                            if "break" in stmt_str:
                                break
                        else:
                            l, c = self._pos(node2)
                            self._add(file_path, "SONAR_SWITCH_ARROW",
                                      "S6023: Switch 表达式可使用箭头语法简化",
                                      _sq_severity("INFO"), line=l, column=c)
                        break

            # S6025: Record accessor
            # S1452: Generic wildcard should not be used as return type
            if isinstance(node, javalang_tree.MethodDeclaration):
                return_type = getattr(node, "return_type", None)
                if return_type and isinstance(return_type, javalang_tree.ReferenceType):
                    # traverse to innermost sub_type to find type arguments
                    inner_type = return_type
                    while getattr(inner_type, "sub_type", None) is not None:
                        inner_type = inner_type.sub_type
                    type_args = getattr(inner_type, "arguments", None) or []
                    for ta in type_args:
                        ta_str = str(ta)
                        if "?" in ta_str and "extends" not in ta_str and "super" not in ta_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_WILDCARD_RETURN",
                                      "S1452: 返回值类型不应使用通配符泛型",
                                      _sq_severity("MAJOR"), line=l, column=c)
                            break

            # S1710: Annotation should be used consistently
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = {}
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names[ann_name] = ann_names.get(ann_name, 0) + 1
                for name, count in ann_names.items():
                    if count > 1:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_DUPLICATE_ANNOTATION",
                                  "S1710: 重复的 @" + name + " 注解",
                                  _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Testing Patterns ====================

    def check_testing_patterns(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_testing"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S5778: JUnit 5 test should not be public
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "Test" in ann_names or "ParameterizedTest" in ann_names:
                    if "public" in (node.modifiers or []):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_JUNIT5_VISIBILITY",
                                  "S5778: JUnit 5 测试方法不应声明为 public",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S5786: JUnit test class should not be public
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_test = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        for ann in getattr(decl, "annotations", []) or []:
                            ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                            if ann_name == "Test":
                                has_test = True
                                break
                if has_test and "public" in (node.modifiers or []):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_JUNIT5_CLASS_VISIBILITY",
                              "S5786: JUnit 5 测试类不应声明为 public",
                              _sq_severity("MINOR"), line=l, column=c)

            # S5810: JUnit 5 @Test should be used
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "org.junit.Test" or ann_name == "Test":
                        pass

            # S5853: JUnit assertion should use assertThat
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "Test":
                        body = getattr(node, "body", None)
                        if body:
                            body_str = str(body)
                            if "assertTrue" not in body_str and "assertEquals" not in body_str:
                                if "assertNotNull" not in body_str and "assertNull" not in body_str:
                                    pass

        # S5783: JUnit assertion in lambda
        for i, line in enumerate(lines, 1):
            if re.search(r'assertThrows\(.*,\s*\(\)\s*->', line):
                pass

        # S5856: AssertJ should be used
        for i, line in enumerate(lines, 1):
            if re.search(r'assertEquals|assertTrue|assertFalse|assertNull|assertNotNull', line):
                if "assertThat" not in line:
                    # Check if we're in a test
                    pass

        # S5857: JUnit 5 @DisplayName should be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "Test" in ann_names and "DisplayName" not in ann_names:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TEST_DISPLAY_NAME",
                              "S5857: JUnit 5 测试应使用 @DisplayName",
                              _sq_severity("INFO"), line=l, column=c)

            # S5854: JUnit 5 method visibility
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "BeforeEach" in ann_names or "AfterEach" in ann_names or \
                   "BeforeAll" in ann_names or "AfterAll" in ann_names:
                    if "public" in (node.modifiers or []):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_JUNIT5_LIFECYCLE_VISIBILITY",
                                  "S5854: JUnit 5 生命周期方法不应声明为 public",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S2187: Test class should have test methods
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_test_method = False
                has_test_runner = False
                class_name = getattr(node, "name", "")
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        for ann in getattr(decl, "annotations", []) or []:
                            ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                            if ann_name == "Test":
                                has_test_method = True
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.FieldDeclaration):
                        for var in getattr(decl, "declarators", []) or []:
                            init = getattr(var, "initializer", None)
                            if init and "TestRule" in str(init):
                                has_test_runner = True
                if class_name.endswith("Test") and not has_test_method and not has_test_runner:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TEST_CLASS_WITHOUT_TEST",
                              "S2187: 测试类应包含至少一个 @Test 方法",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Redundancy ====================

    def check_redundancy(self, tree, file_path: str):
        if not self.config.is_rule_enabled("sonar_redundancy"):
            return

        for path, node in tree:
            # S114: Empty interface should be annotation
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                body = getattr(node, "body", []) or []
                if len(body) == 0:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EMPTY_MARKER_INTERFACE",
                              "S114: 空接口应替换为 @FunctionalInterface 或 @Annotation",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S1185: Useless override (delegating to super)
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if body and isinstance(body, list) and len(body) == 1:
                    stmt = body[0]
                    if isinstance(stmt, javalang_tree.StatementExpression):
                        expr = getattr(stmt, "expression", None)
                        if isinstance(expr, (javalang_tree.MethodInvocation, javalang_tree.SuperMethodInvocation)):
                            member = getattr(expr, "member", "")
                            if member == node.name:
                                is_super = isinstance(expr, javalang_tree.SuperMethodInvocation) or \
                                           getattr(expr, "qualifier", "") == "super"
                                if is_super:
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_USELESS_OVERRIDE_EIGHT",
                                              "S1185: 重写方法仅调用 super 实现，可移除",
                                              _sq_severity("MAJOR"), line=l, column=c)

            # S1206: Method order (equals before hashCode)
            prev_method = ""
            if isinstance(node, javalang_tree.ClassDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if decl.name == "hashCode" and prev_method != "equals":
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_HASHCODE_BEFORE_EQUALS",
                                      "S1206: hashCode() 应放在 equals() 之后",
                                      _sq_severity("MINOR"), line=l, column=c)
                        prev_method = decl.name

            # S1259: Class name should match file name
            if isinstance(node, javalang_tree.ClassDeclaration):
                class_name = getattr(node, "name", "")
                if class_name:
                    file_stem = file_path.split("/")[-1].replace(".java", "")
                    if class_name.lower() == file_stem.lower() and class_name != file_stem:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLASS_NAME_CASE",
                                  "S1259: 类名大小写应与文件名一致",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S1701: Diamond operator should be used (Java 7+) - additional check
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                if type_node and isinstance(type_node, javalang_tree.ReferenceType):
                    type_args = getattr(type_node, "arguments", None)
                    if type_args and len(type_args) > 0:
                        base_name = _get_base_type_name(type_node)
                        if base_name in ("ArrayList", "HashMap", "HashSet",
                                         "LinkedList", "LinkedHashMap", "TreeMap",
                                         "TreeSet", "ArrayDeque", "PriorityQueue"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_DIAMOND_GENERIC",
                                      "S1701: 应使用菱形操作符 <> 简化泛型实例创建",
                                      _sq_severity("MINOR"), line=l, column=c)

            # S1751: Loop with only break in body
            if isinstance(node, javalang_tree.ForStatement):
                body = node.body
                if body:
                    stmts = getattr(body, "statements", []) if hasattr(body, "statements") else \
                            (body if isinstance(body, list) else [])
                    if len(stmts) == 1 and isinstance(stmts[0], javalang_tree.BreakStatement):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_LOOP_ONLY_BREAK",
                                  "S1751: 循环体仅含 break 语句，可移除",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S1820: Too many fields in class
            if isinstance(node, javalang_tree.ClassDeclaration):
                field_count = 0
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.FieldDeclaration):
                        field_count += len(getattr(decl, "declarators", []) or [])
                if field_count > 15:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TOO_MANY_FIELDS",
                              "S1820: 类包含过多字段（" + str(field_count) + " 个），建议拆分",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S1927: instanceof of non-coercible types
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "instanceof":
                    right = getattr(node, "operandr", None)
                    if right and isinstance(right, javalang_tree.ReferenceType):
                        type_name = _get_full_type_name(right)
                        base_name = type_name.split(".")[-1]
                        if base_name in ("String", "Integer", "Long", "Boolean"):
                            left = getattr(node, "operandl", None)
                            if left and isinstance(left, javalang_tree.MethodInvocation):
                                member = getattr(left, "member", "")
                                q = str(getattr(left, "qualifier", "") or "")
                                if member == "toString" or member == "valueOf":
                                    pass

            # S1940: Boolean should not be inverted
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if isinstance(cond, javalang_tree.BinaryOperation):
                    op = getattr(cond, "operator", "")
                    if op == "==":
                        left = getattr(cond, "operandl", None)
                        right = getattr(cond, "operandr", None)
                        if left and right:
                            if isinstance(left, javalang_tree.Literal) and \
                               str(getattr(left, "value", "")) == "false":
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_BOOLEAN_INVERSION",
                                          "S1940: 不应使用 == false 做判断，应直接取反",
                                          _sq_severity("MINOR"), line=l, column=c)
                            elif isinstance(right, javalang_tree.Literal) and \
                                 str(getattr(right, "value", "")) == "false":
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_BOOLEAN_INVERSION",
                                          "S1940: 不应使用 == false 做判断，应直接取反",
                                          _sq_severity("MINOR"), line=l, column=c)

            # S1941: Variable type should be more specific
            # S2057: Serialization should not be used
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                for impl in imp:
                    impl_name = getattr(impl, "name", "") if hasattr(impl, "name") else str(impl)
                    if impl_name == "Serializable":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SERIALIZABLE",
                                  "S2057: 实现 Serializable 需谨慎处理 serialVersionUID",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S2059: Serialization with non-transient fields
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                for impl in imp:
                    impl_name = getattr(impl, "name", "") if hasattr(impl, "name") else str(impl)
                    if impl_name == "Serializable":
                        for decl in getattr(node, "body", []) or []:
                            if isinstance(decl, javalang_tree.FieldDeclaration):
                                for var in getattr(decl, "declarators", []) or []:
                                    name = getattr(var, "name", "")
                                    if name and name != "serialVersionUID":
                                        type_node = getattr(decl, "type", None)
                                        if type_node:
                                            type_name = _get_full_type_name(type_node)
                                            if type_name.startswith("java.io.") or \
                                               type_name.startswith("java.net."):
                                                if "transient" not in (decl.modifiers or []):
                                                    l, c = self._pos(var)
                                                    self._add(file_path,
                                                              "SONAR_SERIALIZABLE_FIELD",
                                                              "S2059: Serializable 类中非 transient 的 IO/Net 字段",
                                                              _sq_severity("MAJOR"),
                                                              line=l, column=c)
