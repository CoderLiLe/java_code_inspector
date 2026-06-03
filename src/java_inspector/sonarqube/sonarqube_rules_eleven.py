"""SonarQubeCheckerEleven — 第十一批规则"""
"""SonarQubeCheckerEleven — 第十一批规则"""
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


class SonarQubeCheckerEleven:
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
        self.check_advanced_features(tree, file_path, content)
        self.check_complete_testing(tree, file_path, content)
        self.check_more_concurrency(tree, file_path, content)

    # ==================== Advanced Java Features ====================

    def check_advanced_features(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_advanced_features"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S3864: Stream.peek should not be used for troubleshooting (already in fourth)
            # S3864 duplicate in fourth, skip

            # S4471: CompletableFuture getNow
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "getNow":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_COMPLETABLE_FUTURE_GETNOW",
                              "S4471: CompletableFuture.getNow() 应检查返回值",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S4348: CompletableFuture should not be ignored
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("thenApplyAsync", "thenAcceptAsync", "thenRunAsync",
                              "thenComposeAsync", "exceptionallyAsync"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_COMPLETABLE_FUTURE_ASYNC",
                              "S4348: 异步 CompletableFuture 应合理处理异常",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S6204: Stream.toList should be used
            for i, line in enumerate(lines, 1):
                if '.collect(Collectors.toList())' in line:
                    self._add(file_path, "SONAR_STREAM_TO_LIST",
                              "S6204: Stream.collect(Collectors.toList()) 可替换为 Stream.toList()",
                              _sq_severity("MINOR"), line=i)

            # S6207: Stream.filter then findAny
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "findAny":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STREAM_FINDANY_FILTER",
                              "S6207: 使用 filter().findAny() 前应考虑流是否有序",
                              _sq_severity("INFO"), line=l, column=c)

            # S6213: Stream.flatMap should not be used with empty strea
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "flatMap":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STREAM_FLATMAP",
                              "S6213: flatMap 应确保内部流非空",
                              _sq_severity("MINOR"), line=l, column=c)

            # S3824: Optional.orElseGet for costly defaults (already in base)
            # S3824 already present in base, skip

            # S6208: Optional.isPresent should be isEmpty
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "isPresent":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_OPTIONAL_IS_PRESENT",
                              "S6208: Optional.isPresent() 可替换为 isEmpty() (Java 11+)",
                              _sq_severity("MINOR"), line=l, column=c)

            # S6214: Optional.map for null check
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.BinaryOperation):
                    left = getattr(cond, "operandl", None)
                    right = getattr(cond, "operandr", None)
                    op = getattr(cond, "operator", "")
                    if op in ("==", "!=") and right and hasattr(right, "value"):
                        if getattr(right, "value", "") == "null":
                            l_str = str(left) if left else ""
                            if "get()" in l_str or ".get(" in l_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_OPTIONAL_MAP_NULL",
                                          "S6214: Optional.get() null 检查可替换为 Optional.map()",
                                          _sq_severity("MINOR"), line=l, column=c)

            # S2122: ScheduledExecutorService should be used (already in fourth)

            # S2273: Thread.sleep with timeunit (already in base)

            # S6296: Stream should be closed
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("lines", "files", "list", "walk", "find"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STREAM_CLOSE",
                              "S6296: IO Stream / Path 流应使用 try-with-resources 关闭",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S6016: Structured concurrency
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("newStructuredTaskScope", "fork", "join", "shutdown"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STRUCTURED_CONCURRENCY",
                              "S6016: 结构化并发应正确管理作用域",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S6206: Switch with pattern matching
            if isinstance(node, javalang_tree.SwitchStatement):
                selector = getattr(node, "expression", None)
                if selector:
                    selector_str = str(selector)
                    if selector_str and not selector_str.isupper():
                        pass

            # S6104: Record equals/hashCode
            if isinstance(node, javalang_tree.ClassDeclaration):
                name = getattr(node, "name", "")
                if name and name.startswith("Record") or name.endswith("Record"):
                    for decl in getattr(node, "body", []) or []:
                        if isinstance(decl, javalang_tree.MethodDeclaration):
                            if decl.name in ("equals", "hashCode"):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_RECORD_METHOD",
                                          "S6104: Record 类无需显式 equals/hashCode",
                                          _sq_severity("MINOR"), line=l, column=c)
                                break

            # S5876: Thread should not be instantiated directly (already in six)

            # S1217: Thread.run should not be called (already in base)

        # S6218: Text block formatting
        for i, line in enumerate(lines, 1):
            if '"""' in line:
                pass

        # S5997: Unicode escapes in comments
        for i, line in enumerate(lines, 1):
            if "\\u" in line and '//' in line:
                self._add(file_path, "SONAR_UNICODE_COMMENT",
                          "S5997: 注释中的 Unicode 转义序列可能造成误解",
                          _sq_severity("MINOR"), line=i)

    # ==================== Complete Testing Patterns ====================

    def check_complete_testing(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_complete_testing"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S5785: JUnit 5 assertThrows should be used
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member in ("fail", "Assert.fail") or member == "fail" and "Assert" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ASSERT_FAIL",
                              "S5785: 应使用 assertThrows 替代 try-catch-fail 模式",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S5776: JUnit 5 @Tag should be used
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "Test" in ann_names and "Tag" not in ann_names:
                    pass

            # S5788: JUnit 5 @Nested should be used
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_test = False
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        for ann in getattr(decl, "annotations", []) or []:
                            ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                            if ann_name == "Test":
                                has_test = True
                                break
                if has_test:
                    ann_names = set()
                    for ann in getattr(node, "annotations", []) or []:
                        ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                        ann_names.add(ann_name)
                    if "Nested" not in ann_names:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_NESTED_CLASS_NOT",
                                  "S5788: 测试类可使用 @Nested 组织",
                                  _sq_severity("INFO"), line=l, column=c)

            # S5803: Mockito spy should be used carefully
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "spy":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_MOCKITO_SPY_FINAL",
                              "S5803: Mockito.spy() 对 final 类可能无效",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S5805: Mockito unnecessary stubbing
            if isinstance(node, javalang_tree.StatementExpression):
                expr = getattr(node, "expression", None)
                if expr and isinstance(expr, javalang_tree.MethodInvocation):
                    member = getattr(expr, "member", "")
                    if member == "when":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_MOCKITO_UNNECESSARY_STUB",
                                  "S5805: Mockito.when() 应确保该桩被使用",
                                  _sq_severity("MINOR"), line=l, column=c)

            # S5810: JUnit 5 @Test vs JUnit 4
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "org.junit.Test" or ann_name == "Test":
                        pass

            # S5852: AssertJ chained assertions
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member.startswith("assert") and member != "assertAll":
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Assertions" in q or "Assert" in q:
                        pass

            # S6068: Test method should be idempotent
            if isinstance(node, javalang_tree.MethodDeclaration):
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "Test" or ann_name == "RepeatedTest":
                        body = getattr(node, "body", None)
                        if body:
                            body_str = str(body)
                            if "Random" in body_str or "System.currentTimeMillis" in body_str:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_NON_DETERMINISTIC_TEST",
                                          "S6068: 测试方法应避免非确定性行为",
                                          _sq_severity("MAJOR"), line=l, column=c)

            # S1725: Test fixture naming (already in ten)

        for i, line in enumerate(lines, 1):
            if re.search(r'@Mock\s+', line) and '@InjectMocks' not in lines:
                self._add(file_path, "SONAR_MOCKITO_FIELD",
                          "S5806: Mockito @Mock 应配合 @InjectMocks 使用",
                          _sq_severity("MINOR"), line=i)

    # ==================== More Concurrency ====================

    def check_more_concurrency(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_more_concurrency"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S2273: Thread.sleep with TimeUnit (already in base, skip)
            # S2925: Thread.sleep in loop (already in ext, skip)

            # S2445: Synchronize on lock object (already in base)
            # S3077: Volatile array reference
            if isinstance(node, javalang_tree.FieldDeclaration):
                if "volatile" in (node.modifiers or []):
                    type_node = getattr(node, "type", None)
                    if type_node:
                        inner = type_node
                        while getattr(inner, "sub_type", None):
                            inner = inner.sub_type
                        if getattr(inner, "dimensions", None):
                            for var in getattr(node, "declarators", []) or []:
                                name = getattr(var, "name", "")
                                if name:
                                    l, c = self._pos(var)
                                    self._add(file_path, "SONAR_VOLATILE_ARRAY",
                                              "S3077: volatile 数组仅保证了引用的可见性",
                                              _sq_severity("MAJOR"), line=l, column=c)

            # S2440: Boxing comparison (already in six)

            # S2885: Non-private field in multithreaded context
            if isinstance(node, javalang_tree.FieldDeclaration):
                modifiers = node.modifiers or []
                if "private" not in modifiers and "final" not in modifiers:
                    if "static" not in modifiers:
                        for var in getattr(node, "declarators", []) or []:
                            name = getattr(var, "name", "")
                            if name:
                                l, c = self._pos(var)
                                self._add(file_path, "SONAR_PACKAGE_PRIVATE_FIELD",
                                          "S2885: 多线程环境中包私有字段可能导致可见性问题",
                                          _sq_severity("MAJOR"), line=l, column=c)

            # S3078: Volatile field in double-checked locking
            if isinstance(node, javalang_tree.ClassDeclaration):
                volatile_fields = set()
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.FieldDeclaration):
                        if "volatile" in (decl.modifiers or []):
                            for var in getattr(decl, "declarators", []) or []:
                                volatile_fields.add(getattr(var, "name", ""))
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        body = getattr(decl, "body", None)
                        if body:
                            body_str = str(body)
                            for vf in volatile_fields:
                                if f"synchronized({vf})" in body_str or \
                                   f"synchronized ({vf})" in body_str:
                                    l, c = self._pos(node)
                                    self._add(file_path, "SONAR_VOLATILE_DCL",
                                              "S3078: volatile 字段不应作为同步锁对象",
                                              _sq_severity("MAJOR"), line=l, column=c)
                                    break

            # S1217: Thread.run (already in base)

            # S2446: Thread.wait should be in synchronized (already in fourth)

            # S2442: Class-level synchronization
            if isinstance(node, javalang_tree.SynchronizedStatement):
                expr = getattr(node, "expression", None)
                if expr:
                    expr_str = str(expr)
                    if expr_str in (".class", "getClass()", "Foo.class"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLASS_SYNC",
                                  "S2442: 类级同步应使用专用的锁对象",
                                  _sq_severity("MAJOR"), line=l, column=c)

            # S4349: ExecutorService shutdown
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("newFixedThreadPool", "newCachedThreadPool",
                              "newSingleThreadExecutor", "newScheduledThreadPool"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EXECUTOR_CREATED",
                              "S4349: 创建的 ExecutorService 应在适当时候关闭",
                              _sq_severity("MAJOR"), line=l, column=c)

            # S5164: ThreadLocal should be removed
            for i, line in enumerate(lines, 1):
                if re.search(r'\bThreadLocal\b.*\.set\(', line):
                    self._add(file_path, "SONAR_THREADLOCAL_SET",
                              "S5164: ThreadLocal 值使用后应调用 remove() 清理",
                              _sq_severity("MAJOR"), line=i)

            # S2122: ScheduledExecutorService (already in fourth)
            # S2274: TimeUnit.sleep (already in base)

            # S2689: Thread.run should not be called (already in base)

            # S2222: Lock unlock (already in base)

            # S3046: Wait in while loop (already in seven)

        # S2441: ThreadLocal should be static (already in seven, but checking pattern)
        for i, line in enumerate(lines, 1):
            if re.search(r'new\s+ThreadLocal\b', line) and \
               'static' not in (lines[i-2] if i >= 2 else ''):
                self._add(file_path, "SONAR_THREADLOCAL_NONSTATIC_ELEVEN",
                          "S2441: ThreadLocal 应声明为 static",
                          _sq_severity("MAJOR"), line=i)
