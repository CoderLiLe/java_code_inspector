"""SonarQubeChecker — 主检查器：Bugs / Code Smell / Security"""
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


class SonarQubeChecker:
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
        self.check_bugs(tree, file_path, content)
        self.check_code_smell(tree, file_path, content)
        self.check_security(tree, file_path, content)

    # ==================== Bugs ====================
    def check_bugs(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_bugs"):
            return
        lines = content.split("\n")

        # S1125: Redundant boolean literals in if/while conditions
        for path, node in tree:
            attr = "condition" if isinstance(node, (javalang_tree.IfStatement, javalang_tree.WhileStatement)) else "expression"
            if isinstance(node, (javalang_tree.IfStatement, javalang_tree.WhileStatement)) and \
               hasattr(node, attr) and getattr(node, attr, None):
                cond = getattr(node, attr)
                cond_val = getattr(cond, "value", str(cond))
                if cond_val in ("true", "Boolean.TRUE"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_BOOLEAN_LITERAL",
                              "S1125: 条件判断中使用了冗余的布尔字面量 'true'，应直接使用表达式",
                              _sq_severity("MAJOR"), line=l, column=c)
                elif cond_val in ("false", "Boolean.FALSE"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_BOOLEAN_LITERAL",
                              "S1125: 条件判断中使用了冗余的布尔字面量 'false'，应使用 ! 取反",
                              _sq_severity("MAJOR"), line=l, column=c)
        # S1764: Identical sub-expressions on both sides of binary operator
        binary_pat = re.compile(r"(\w+(?:\.\w+)*)\s*(==|!=|&&|\|\||<|>|<=|>=)\s*\1\b")
        for i, line in enumerate(lines, 1):
            m = binary_pat.search(line)
            if m and m.group(2) in ("==", "!="):
                self._add(file_path, "SONAR_IDENTICAL_EXPR",
                          f"S1764: 二元运算符 '{m.group(2)}' 两侧使用了相同表达式 '{m.group(1)}'，可能为逻辑错误",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S3981: Collection.size() > 0 -> !Collection.isEmpty()
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\.size\s*\(\s*\)\s*(==|!=|>)\s*(-?\d+)", line):
                val = int(m.group(3))
                if m.group(2) == "==" and val == 0:
                    pass
                elif m.group(2) == ">" and val == 0:
                    self._add(file_path, "SONAR_SIZE_ISEMPTY",
                              "S3981: 使用 'isEmpty()' 替代 'size() > 0' 来判断集合是否非空",
                              _sq_severity("MINOR"), line=i, column=m.start())
                elif m.group(2) == "!=" and val == 0:
                    self._add(file_path, "SONAR_SIZE_ISEMPTY",
                              "S3981: 使用 '!isEmpty()' 替代 'size() != 0' 来判断集合是否非空",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S4973: String equality with == instead of equals()
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"[^"]*"\s*==\s*(\w+|"[^"]*")', line):
                self._add(file_path, "SONAR_STRING_EQ",
                          "S4973: 使用了 == 比较字符串，应使用 equals() 方法",
                          _sq_severity("MAJOR"), line=i, column=m.start())
                break

        # S2689: Thread.run() should not be called directly
        for i, line in enumerate(lines, 1):
            if re.search(r"\.run\s*\(\s*\)\s*;", line) and \
               not re.search(r"//.*|/\*.*\*/", line):
                st = line.strip()
                if not st.startswith("//") and not st.startswith("/*"):
                    self._add(file_path, "SONAR_THREAD_RUN",
                              "S2689: 直接调用了 'run()' 方法（多线程场景下应调用 'start()'）",
                              _sq_severity("MAJOR"), line=i)

        # S2445: Synchronize on non-final field
        for path, node in tree:
            if isinstance(node, javalang_tree.SynchronizedStatement):
                lock_obj = str(getattr(node, "lock", ""))
                if not lock_obj:
                    lock_obj = str(getattr(node, "expression", ""))
                if lock_obj and "this" not in lock_obj:
                    field_name = expr.strip()
                    is_final = False
                    for p2, n2 in tree:
                        if isinstance(n2, javalang_tree.FieldDeclaration) and \
                           "final" in (n2.modifiers or []):
                            for decl in n2.declarators:
                                if decl.name == field_name:
                                    is_final = True
                                    break
                        if is_final:
                            break
                    if not is_final:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SYNC_FIELD",
                                  "S2445: 同步加锁的对象应为 final 字段，否则对象引用被修改后会导致不同步",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S3020: Iterator next() without hasNext()
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation) and \
               node.member == "next" and \
               hasattr(node, "qualifier") and node.qualifier:
                q = str(node.qualifier)
                has_hasnext_check = False
                for p2, n2 in tree:
                    cond_attr = "condition" if isinstance(n2, (javalang_tree.IfStatement, javalang_tree.WhileStatement)) else None
                    if cond_attr and hasattr(n2, cond_attr) and getattr(n2, cond_attr, None):
                        cond_str = str(getattr(n2, cond_attr))
                        if f"{q}.hasNext" in cond_str:
                            has_hasnext_check = True
                            break
                if not has_hasnext_check:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_ITERATOR_NEXT",
                              "S3020: 在调用 'next()' 前应使用 'hasNext()' 检查是否还有元素",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S3655: Optional.get() without isPresent() check
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation) and \
               node.member == "get" and hasattr(node, "qualifier"):
                q = str(node.qualifier)
                if "Optional" in q or any(
                    isinstance(t, javalang_tree.VariableDeclaration) and
                    "Optional" in str(getattr(t, "type", "")) and
                    any(d.name == q for d in t.declarators)
                    for _, t in tree if isinstance(t, javalang_tree.VariableDeclaration)
                ):
                    has_present_check = False
                    for p2, n2 in tree:
                        cond_attr = "condition" if isinstance(n2, javalang_tree.IfStatement) else None
                        if cond_attr and hasattr(n2, cond_attr) and getattr(n2, cond_attr, None):
                            cond_str = str(getattr(n2, cond_attr))
                            if f"{q}.isPresent" in cond_str or \
                               f"{q}.isEmpty" in cond_str:
                                has_present_check = True
                                break
                        if isinstance(n2, javalang_tree.MethodInvocation) and \
                           n2.member == "orElse" and q in str(n2):
                            has_present_check = True
                            break
                        if isinstance(n2, javalang_tree.MethodInvocation) and \
                           n2.member == "orElseGet" and q in str(n2):
                            has_present_check = True
                            break
                        if isinstance(n2, javalang_tree.MethodInvocation) and \
                           n2.member == "orElseThrow" and q in str(n2):
                            has_present_check = True
                            break
                    if not has_present_check:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_OPTIONAL_GET",
                                  "S3655: 直接调用 'Optional.get()' 前应先使用 'isPresent()' 检查，否则可能抛出 NoSuchElementException",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1215: System.gc() called
        for i, line in enumerate(lines, 1):
            if re.search(r"System\.gc\s*\(\s*\)", line) and not re.search(r"//.*", line):
                self._add(file_path, "SONAR_SYSTEM_GC",
                          "S1215: 不应主动调用 'System.gc()'，JVM 的 GC 策略由其自行管理",
                          _sq_severity("MAJOR"), line=i)

        # S3346: Equal expressions in switch cases (duplicate case values)
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                case_values = {}
                for case in getattr(node, "cases", []) or []:
                    cval = getattr(case, "case", None)
                    if cval is not None:
                        cs = str(cval)
                        if cs in case_values:
                            l, c = self._pos(case)
                            self._add(file_path, "SONAR_DUP_CASE",
                                      "S3346: switch 中包含重复的 case 值，会导致不可达代码",
                                      _sq_severity("MAJOR"), line=l, column=c)
                        else:
                            case_values[cs] = True

        # S2273: Thread.sleep() inside loop
        for path, node in tree:
            if isinstance(node, (javalang_tree.ForStatement, javalang_tree.WhileStatement, javalang_tree.DoStatement)):
                body_stmts = node.body if isinstance(node.body, list) else \
                            getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body_stmts:
                    if "Thread.sleep" in str(stmt) or "TimeUnit" in str(stmt):
                        l = node.position.line if node.position else 0
                        self._add(file_path, "SONAR_SLEEP_LOOP",
                                  "S2273: 在循环中调用 'Thread.sleep()' 会影响性能，考虑改用定时器或 ScheduledExecutorService",
                                  _sq_severity("MINOR"), line=l)
                        break

        # S2222: Lock without unlock in finally
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation) and \
               node.member == "lock" and hasattr(node, "qualifier"):
                q = str(node.qualifier)
                for p2, n2 in tree:
                    if isinstance(n2, javalang_tree.TryStatement):
                        try_str = str(n2)
                        if q in try_str:
                            has_finally_unlock = False
                            finally_block = getattr(n2, "finally_block", None)
                            if finally_block:
                                finally_stmts = finally_block.statements if \
                                    hasattr(finally_block, "statements") else []
                                for fs in finally_stmts:
                                    if f"{q}.unlock" in str(fs):
                                        has_finally_unlock = True
                                        break
                            catches = getattr(n2, "catches", []) or []
                            for catch in catches:
                                catch_str = str(getattr(catch, "block", ""))
                                if f"{q}.unlock" in catch_str:
                                    has_finally_unlock = True
                                    break
                            if not has_finally_unlock:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_LOCK_UNLOCK",
                                          "S2222: Lock.lock() 后必须在 finally 块中调用 unlock()，否则可能导致死锁",
                                          _sq_severity("BLOCKER"), line=l, column=c)
                            break

        # S1854: Dead store assignment (variable assigned but never read meaningfully)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                method_name = node.name
                if method_name in self._METHOD_BLACKLIST:
                    continue
                for i, stmt in enumerate(body):
                    if isinstance(stmt, javalang_tree.LocalVariableDeclaration):
                        for decl in stmt.declarators:
                            vname = decl.name
                            assigned_but_unused = True
                            for j in range(i + 1, len(body)):
                                s2 = body[j]
                                if isinstance(s2, (javalang_tree.ReturnStatement,
                                                   javalang_tree.ThrowStatement)):
                                    continue
                                if vname in str(s2):
                                    assigned_but_unused = False
                                    break
                            if assigned_but_unused and len(body) > i + 1 and \
                               not isinstance(body[i + 1], javalang_tree.ReturnStatement):
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_DEAD_STORE",
                                          "S1854: 变量 '" + vname + "' 赋值后未被使用，存在死存储",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S3984: Exception created but not thrown
        for path, node in tree:
            if isinstance(node, javalang_tree.StatementExpression) and \
               isinstance(node.expression, javalang_tree.MethodInvocation):
                expr = node.expression
                if "new " in str(expr) and any(
                    sn in str(expr) for sn in ("Exception", "Error", "Throwable")
                ):
                    if expr.member in ("toString", "getMessage"):
                        continue
                    l, c = self._pos(expr)
                    self._add(file_path, "SONAR_EXC_NOT_THROWN",
                              "S3984: 创建了异常对象但未抛出，可能是遗漏了 throw 关键字",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1065: Unnecessary label
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\s*:\s*(for|while|do)\b", line):
                self._add(file_path, "SONAR_UNNECESSARY_LABEL",
                          "S1065: 不必要的标签 '" + m.group(1) + "'，可移除",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S2186: Thread.yield() called
        for i, line in enumerate(lines, 1):
            if re.search(r"Thread\.yield\s*\(\s*\)", line) and not re.search(r"//.*", line):
                self._add(file_path, "SONAR_THREAD_YIELD",
                          "S2186: 'Thread.yield()' 不可预测且不可依赖，应使用更可靠的同步机制",
                          _sq_severity("MINOR"), line=i)

    # ==================== Code Smells ====================
    def check_code_smell(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_code_smell"):
            return
        lines = content.split("\n")

        # S1068: Unused private fields
        class_fields = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                cn = node.name
                class_fields[cn] = {}
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.FieldDeclaration):
                        for decl in member.declarators:
                            if "private" in (member.modifiers or []):
                                class_fields[cn][decl.name] = (decl, member)
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                cn = node.name
                body_str = ""
                for member in (node.body or []):
                    body_str += str(member)
                for fname, (decl, member) in class_fields.get(cn, {}).items():
                    usages = [m.start() for m in re.finditer(r"\b" + re.escape(fname) + r"\b", body_str)]
                    if len(usages) <= 1:
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_UNUSED_FIELD",
                                  "S1068: 私有字段 '" + fname + "' 未被使用，应移除",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1132: String literal on left side of equals()
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"[^"]*"\s*\.\s*equals\s*\(', line):
                self._add(file_path, "SONAR_STRING_LHS",
                          "S1132: 字符串字面量应在 equals() 右侧，避免空指针异常",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S1155: Collection.isEmpty() instead of .size() > 0
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\.size\s*\(\s*\)\s*==\s*0", line):
                self._add(file_path, "SONAR_SIZE_ZERO",
                          "S1155: 使用 'isEmpty()' 替代 'size() == 0' 来判断集合是否为空",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S1210: equals() without hashCode() override
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                has_equals = False
                has_hashcode = False
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.MethodDeclaration):
                        if member.name == "equals" and len(getattr(member, "parameters", []) or []) == 1:
                            has_equals = True
                        if member.name == "hashCode" and len(getattr(member, "parameters", []) or []) == 0:
                            has_hashcode = True
                if has_equals and not has_hashcode:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EQUALS_HASHCODE",
                              "S1210: 重写了 equals() 但未重写 hashCode()，违反 hashCode 约定",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1213: Static fields before instance fields
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                saw_instance_field = False
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.FieldDeclaration):
                        is_static = "static" in (member.modifiers or [])
                        if not is_static:
                            saw_instance_field = True
                        elif saw_instance_field:
                            for decl in member.declarators:
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_MEMBER_ORDER",
                                          "S1213: 静态变量应定义在实例变量之前，遵循 'Statics before Instance' 约定",
                                          _sq_severity("MINOR"), line=l, column=c)
                                break

        # S1319: Declare with interface types (List, Map, Set) instead of implementations
        interface_types = {
            "ArrayList": "List", "LinkedList": "List", "Vector": "List",
            "HashMap": "Map", "TreeMap": "Map", "LinkedHashMap": "Map",
            "HashSet": "Set", "TreeSet": "Set", "LinkedHashSet": "Set",
        }

        def _get_ref_type_name(rt):
            if hasattr(rt, "name") and not getattr(rt, "qualifier", None):
                if rt.name in interface_types:
                    return rt.name
            if hasattr(rt, "sub_type") and rt.sub_type:
                return _get_ref_type_name(rt.sub_type)
            if hasattr(rt, "qualifier") and rt.qualifier:
                return _get_ref_type_name(rt.qualifier)
            return getattr(rt, "name", None)

        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration) and \
               hasattr(node, "type") and node.type and \
               hasattr(node.type, "name"):
                impl_name = _get_ref_type_name(node.type)
                if impl_name in interface_types:
                    iface_name = interface_types[impl_name]
                    for decl in node.declarators:
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_USE_INTERFACE_TYPE",
                                  "S1319: 使用接口类型 '" + iface_name + "' 而非实现类 '" + impl_name + "' 声明变量",
                                  _sq_severity("MINOR"), line=l, column=c)
            elif isinstance(node, javalang_tree.VariableDeclaration) and \
                 hasattr(node, "type") and node.type and \
                 hasattr(node.type, "name"):
                impl_name = _get_ref_type_name(node.type)
                if impl_name in interface_types:
                    iface_name = interface_types[impl_name]
                    for decl in node.declarators:
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_USE_INTERFACE_TYPE",
                                  "S1319: 使用接口类型 '" + iface_name + "' 而非实现类 '" + impl_name + "' 声明变量",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S1444: public static field should be final
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                mods = node.modifiers or []
                if "public" in mods and "static" in mods and "final" not in mods:
                    for decl in node.declarators:
                        l, c = self._pos(decl)
                        self._add(file_path, "SONAR_PUBLIC_STATIC_FINAL",
                                  "S1444: 'public static' 字段 '" + decl.name + "' 应声明为 'final' 以避免被篡改",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1488: Local variable immediately returned
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for i, stmt in enumerate(body):
                    if isinstance(stmt, javalang_tree.LocalVariableDeclaration) and \
                       len(stmt.declarators) == 1:
                        decl = stmt.declarators[0]
                        if i + 1 < len(body) and \
                           isinstance(body[i + 1], javalang_tree.ReturnStatement) and \
                           hasattr(body[i + 1], "expression") and body[i + 1].expression and \
                           str(body[i + 1].expression) == decl.name:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_REDUNDANT_LOCAL",
                                      "S1488: 局部变量 '" + decl.name + "' 仅用于立即返回，可直接内联返回表达式",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S1700: Field name same as method name
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                field_names = set()
                method_names = set()
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.FieldDeclaration):
                        for decl in member.declarators:
                            field_names.add(decl.name)
                    elif isinstance(member, javalang_tree.MethodDeclaration):
                        method_names.add(member.name)
                overlap = field_names & method_names
                for name in overlap:
                    for member in (node.body or []):
                        if isinstance(member, javalang_tree.FieldDeclaration):
                            for decl in member.declarators:
                                if decl.name == name:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "SONAR_FIELD_METHOD_NAME",
                                              "S1700: 字段 '" + name + "' 与同名方法冲突，考虑重命名",
                                              _sq_severity("MINOR"), line=l, column=c)
                                    break

        # S2325: private method can be static
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                mods = node.modifiers or []
                if "private" in mods and "static" not in mods and \
                   "abstract" not in mods and node.name not in self._METHOD_BLACKLIST and \
                   node.name != "<init>":
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    accesses_instance = False
                    for stmt in body:
                        s = str(stmt)
                        if "this." in s:
                            accesses_instance = True
                            break
                        if "super." in s:
                            accesses_instance = True
                            break
                    if not accesses_instance:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_STATIC_METHOD",
                                  "S2325: 方法 '" + node.name + "' 未访问实例成员，可声明为 'static'",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S2696: Instance method writing to static field
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                mods = node.modifiers or []
                if "static" in mods:
                    continue
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body:
                    s = str(stmt)
                    if re.search(r"\w+\.\w+\s*=", s):
                        for p2, n2 in tree:
                            if isinstance(n2, javalang_tree.FieldDeclaration) and \
                               "static" in (n2.modifiers or []):
                                for decl in n2.declarators:
                                    if decl.name in s:
                                        l, c = self._pos(node)
                                        self._add(file_path, "SONAR_STATIC_WRITE",
                                                  "S2696: 实例方法 '" + node.name + "' 修改了静态字段 '" + decl.name + "'",
                                                  _sq_severity("MAJOR"), line=l, column=c)
                                        break

        # S3518: Division by zero
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"/\s*0\b(?!\.|\d)", line):
                before = line[:m.start()]
                if "//" not in before:
                    self._add(file_path, "SONAR_DIVISION_ZERO",
                              "S3518: 检测到除以零的运算，将抛出 ArithmeticException",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S4524: Switch default not in last position
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                default_idx = -1
                for idx, case in enumerate(cases):
                    if getattr(case, "case", None) is None:
                        default_idx = idx
                        break
                if default_idx >= 0 and default_idx < len(cases) - 1:
                    l = node.position.line if node.position else 0
                    self._add(file_path, "SONAR_SWITCH_DEFAULT_LAST",
                              "S4524: 'default' 分支应放在 switch 语句的最后",
                              _sq_severity("MINOR"), line=l)

        # S1449: Locale in String upper/lower case
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\.toUpperCase\s*\(\s*\)|\.toLowerCase\s*\(\s*\)", line):
                if "Locale" not in line and not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_LOCALE",
                              "S1449: 字符串大小写转换应指定 Locale，避免国际化场景下行为异常（如土耳其语 I）",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S1479: Switch with too many cases
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                case_count = sum(1 for c in cases if getattr(c, "case", None) is not None)
                if case_count >= 30:
                    l = node.position.line if node.position else 0
                    self._add(file_path, "SONAR_TOO_MANY_CASES",
                              "S1479: switch 语句包含 " + str(case_count) + " 个 case，考虑用多态或 Map 重构",
                              _sq_severity("MINOR"), line=l)

        # S1596: Collections.EMPTY_LIST vs emptyList()
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"Collections\.EMPTY_(LIST|MAP|SET)", line):
                what = m.group(1).lower()
                self._add(file_path, "SONAR_EMPTY_COLLECTION",
                          "S1596: 使用 'Collections.empty" + what.capitalize() + "()' 替代 'Collections.EMPTY_" + m.group(1) + "'",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S1604: Anonymous inner class can be lambda
        for path, node in tree:
            if isinstance(node, javalang_tree.Creator):
                if hasattr(node, "body") and node.body and \
                   hasattr(node.body, "statements"):
                    if hasattr(node, "type") and node.type and \
                       hasattr(node.type, "name"):
                        tn = node.type.name
                        if tn in ("Runnable", "Callable", "Comparator", "Consumer",
                                  "Function", "Predicate", "Supplier"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_LAMBDA",
                                      "S1604: 匿名内部类可替换为 lambda 表达式（" + tn + "接口只有一个抽象方法）",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S1905: Redundant cast
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\(\s*(\w+)\s*\)\s*\1\b", line, re.IGNORECASE):
                self._add(file_path, "SONAR_REDUNDANT_CAST",
                          "S1905: 多余的强制类型转换，表达式已经是目标类型",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S2130: @Deprecated without annotation or Javadoc tag
        for i, line in enumerate(lines, 1):
            if re.search(r"@Deprecated", line):
                has_doc = False
                for j in range(max(0, i - 5), i):
                    if j < len(lines) and re.search(r"@deprecated", lines[j]):
                        has_doc = True
                        break
                if not has_doc:
                    self._add(file_path, "SONAR_DEPRECATED",
                              "S2130: '@Deprecated' 注解应配合 Javadoc '@deprecated' 标记，说明替代方案",
                              _sq_severity("MINOR"), line=i)

        # S2142: InterruptedException not re-interrupted
        for i, line in enumerate(lines, 1):
            if "InterruptedException" in line and "catch" in line:
                for j in range(i, min(i + 15, len(lines))):
                    if j >= len(lines):
                        break
                    lj = lines[j]
                    if "Thread.currentThread().interrupt()" in lj:
                        break
                    if lj.strip().startswith("throw") and "Interrupted" in lj:
                        break
                else:
                    self._add(file_path, "SONAR_INTERRUPTED",
                              "S2142: 捕获 InterruptedException 后应调用 'Thread.currentThread().interrupt()' 恢复中断状态",
                              _sq_severity("MAJOR"), line=i)

        # S2153: Boxing/unboxing in a loop
        for path, node in tree:
            if isinstance(node, (javalang_tree.ForStatement, javalang_tree.WhileStatement)):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                loop_str = " ".join(str(s) for s in body)
                wrapper_methods = ["Integer.valueOf", "Long.valueOf", "Double.valueOf",
                                   "Boolean.valueOf", "new Integer", "new Long", "new Double"]
                for wm in wrapper_methods:
                    if wm in loop_str:
                        l = node.position.line if node.position else 0
                        self._add(file_path, "SONAR_BOXING_LOOP",
                                  "S2153: 循环中避免装箱/拆箱操作，影响性能",
                                  _sq_severity("MINOR"), line=l)
                        break

        # S2164: Integer division cast to double
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\(\s*double\s*\)\s*\(\s*\w+\s*/\s*\w+\s*\)", line):
                self._add(file_path, "SONAR_INT_DIVISION",
                          "S2164: 整数除法后再转 double 会丢失精度，应在除法前将操作数转为 double",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S3052: Field initializing to default value
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                for decl in node.declarators:
                    init = getattr(decl, "initializer", None)
                    if init is not None:
                        init_val = getattr(init, "value", str(init))
                        if init_val in ("null", "0", "0L", "0.0f", "0.0d", "false", "'\\u0000'"):
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_DEFAULT_INIT",
                                      "S3052: 字段 '" + decl.name + "' 的初始值 '" + init_val + "' 是类型的默认值，无需显式赋值",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S3358: Ternary operator with nested ternary
        for i, line in enumerate(lines, 1):
            ternary_count = line.count("?") + line.count(":")
            if ternary_count >= 4:
                st = line.strip()
                if st.startswith("//"):
                    continue
                self._add(file_path, "SONAR_NESTED_TERNARY",
                          "S3358: 三元运算符嵌套降低了可读性，应提取为独立的方法或 if语句",
                          _sq_severity("MINOR"), line=i)

        # S3440: Redundant null check before instanceof
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\s*!=\s*null\s*&&\s*\1\s+instanceof\b", line):
                self._add(file_path, "SONAR_NULL_INSTANCEOF",
                          "S3440: 'instanceof' 已包含非 null 检查，无需前面的 '!= null' 判断",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S3824: Map.computeIfAbsent usage
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\.get\s*\(\s*(\w+)\s*\)\s*==\s*null\s*\)?\s*\{\s*\1\.put\s*\(", line):
                self._add(file_path, "SONAR_COMPUTE_IF_ABSENT",
                          "S3824: 'get + null check + put' 可用 'computeIfAbsent' 一行替代（原子性且更高效）",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S4275: Getter/setter accessing wrong field
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                fields = {}
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.FieldDeclaration):
                        for decl in member.declarators:
                            fields[decl.name] = decl
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.MethodDeclaration):
                        mn = member.name
                        body = member.body if isinstance(member.body, list) else \
                               getattr(getattr(member, "body", None), "statements", []) or []
                        if mn.startswith("get") and len(mn) > 3:
                            expected_field = mn[3].lower() + mn[4:]
                            body_str = " ".join(str(s) for s in body)
                            if expected_field in fields and \
                               "return " + expected_field not in body_str:
                                l, c = self._pos(member)
                                self._add(file_path, "SONAR_GETTER_SETTER",
                                          "S4275: getter 方法 '" + mn + "' 可能未访问正确的字段 '" + expected_field + "'",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S4144: Identical methods (same body)
        methods_by_body = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.MethodDeclaration) and \
                       member.name not in self._METHOD_BLACKLIST and \
                       member.name != "<init>":
                        body_str = " ".join(str(s) for s in (
                            member.body if isinstance(member.body, list) else
                            getattr(getattr(member, "body", None), "statements", []) or []
                        ))
                        params_str = ",".join(
                            str(getattr(p, "type", "")) for p in
                            (getattr(member, "parameters", []) or [])
                        )
                        key = body_str + "|" + params_str
                        if key in methods_by_body:
                            prev_name = methods_by_body[key]
                            l, c = self._pos(member)
                            self._add(file_path, "SONAR_DUPLICATE_METHOD",
                                      "S4144: 方法 '" + member.name + "' 与方法 '" + prev_name + "' 完全相同",
                                      _sq_severity("MAJOR"), line=l, column=c)
                        else:
                            methods_by_body[key] = member.name

        # S3985: Unused private inner class
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                outer_body_str = " ".join(str(m) for m in (node.body or []))
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.ClassDeclaration) and \
                       "private" in (member.modifiers or []):
                        inner_name = member.name
                        usage_count = outer_body_str.count(inner_name)
                        if usage_count <= 1:
                            l, c = self._pos(member)
                            self._add(file_path, "SONAR_UNUSED_INNER",
                                      "S3985: 私有内部类 '" + inner_name + "' 未被使用，应移除",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2386: Mutable field in public array
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                mods = node.modifiers or []
                if "public" in mods and not "final" in mods:
                    vtype = getattr(node, "type", None)
                    if vtype and hasattr(vtype, "name") and \
                       vtype.name in ("String[]", "int[]", "Object[]"):
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_MUTABLE_ARRAY",
                                      "S2386: public 字段 '" + decl.name + "' 是可变数组，可被外部修改；应返回副本或使用不可变集合",
                                      _sq_severity("MAJOR"), line=l, column=c)
                    elif vtype and hasattr(vtype, "name") and \
                         "[]" in vtype.name:
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_MUTABLE_ARRAY",
                                      "S2386: public 字段 '" + decl.name + "' 是可变数组，可被外部修改",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S3457: String.format with wrong placeholders
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'String\.format\s*\(\s*"[^"]*"\s*,\s*\)', line):
                self._add(file_path, "SONAR_FORMAT_PLACEHOLDER",
                          "S3457: String.format 调用中没有格式化参数，格式字符串包含占位符但没有对应参数",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S3725: Boolean should be used in assertions
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"assert\s+(true|false)\b", line):
                self._add(file_path, "SONAR_BOOLEAN_ASSERT",
                          "S3725: assert 断言中使用了布尔字面量，断言总是通过或总是失败，删除或修改断言",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S3959: Consumed stream (Stream that has been consumed)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\.stream\b.*\1\.(count|collect|forEach|findFirst|findAny|anyMatch|"
                                 r"allMatch|noneMatch|reduce|min|max|sorted|filter|map)\b", line):
                self._add(file_path, "SONAR_STREAM_CONSUMED",
                          "S3959: Stream 已被消费，不可重复使用终端操作",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S4143: Map key overwritten (map.put with same key)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\.put\s*\(\s*([^,]+)\s*,\s*[^)]+\)\s*;", line):
                key_val = m.group(2).strip()
                for j in range(max(0, i - 10), i):
                    if j < len(lines) and re.search(re.escape(key_val), lines[j]) and \
                       re.search(r"\." + re.escape(m.group(1)), lines[j]) and \
                       ".put(" in lines[j]:
                        self._add(file_path, "SONAR_MAP_OVERWRITE",
                                  "S4143: Map '" + m.group(1) + "' 的键 '" + key_val + "' 被重复 put，可能覆盖了之前的值",
                                  _sq_severity("MINOR"), line=i, column=m.start())

        # S1264: for loop can be replaced by while
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                if hasattr(node, "control") and node.control:
                    init = getattr(node.control, "init", []) or []
                    update = getattr(node.control, "update", []) or []
                    if not init and not update:
                        l = node.position.line if node.position else 0
                        self._add(file_path, "SONAR_FOR_TO_WHILE",
                                  "S1264: 该 'for' 循环没有初始化或更新语句，应使用 'while' 循环",
                                  _sq_severity("MINOR"), line=l)

        # S2326: Unused type parameters
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                tp = getattr(node, "type_parameters", None)
                if tp:
                    body_str = " ".join(str(m) for m in (node.body or []))
                    for param in tp:
                        pname = param.name if hasattr(param, "name") else str(param)
                        if pname and pname not in body_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_UNUSED_TYPE_PARAM",
                                      "S2326: 类型参数 '" + pname + "' 未被使用，应移除",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2629: Logger calls with string concatenation
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(logger|log|LOGGER|LOG)\.(info|debug|warn|error|trace)\s*\(\s*\"\s*\+\s*", line):
                self._add(file_path, "SONAR_LOG_CONCAT",
                          "S2629: 日志调用中使用字符串拼接而非占位符 '{}'，影响性能（即使日志级别被禁用也会执行拼接）",
                          _sq_severity("MINOR"), line=i, column=m.start())

        # S2692: indexOf > 0 should be replaced by contains
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\.indexOf\s*\([^)]+\)\s*>\s*0", line):
                self._add(file_path, "SONAR_INDEXOF_CONTAINS",
                          "S2692: 'indexOf() > 0' 应使用 'contains()' 替代；'indexOf() > -1' 可判断存在性",
                          _sq_severity("MINOR"), line=i, column=m.start())

    # ==================== Security ====================
    def check_security(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security"):
            return
        lines = content.split("\n")

        # S2076: OS command injection (Runtime.exec)
        for i, line in enumerate(lines, 1):
            if re.search(r"Runtime\.getRuntime\(\)\.exec\s*\(", line) and \
               not re.search(r"//.*", line) and not re.search(r"\"[^\"]*\"", line):
                self._add(file_path, "SONAR_OS_COMMAND_INJECTION",
                          "S2076: 检测到 OS 命令执行，避免拼接用户输入，使用 ProcessBuilder 并参数化",
                          _sq_severity("BLOCKER"), line=i)

        # S2228: System.out/err logging
        for i, line in enumerate(lines, 1):
            if re.search(r"System\.out\.\w+|System\.err\.\w+", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "SONAR_SYSTEM_OUT",
                          "S2228: 禁止在生产代码中使用 'System.out' 或 'System.err'，应使用日志框架",
                          _sq_severity("MAJOR"), line=i)

        # S4507: SQL injection
        for i, line in enumerate(lines, 1):
            if re.search(r'"\s*\+\s*\w+\s*\+\s*".*?(?:executeQuery|executeUpdate|execute|createQuery)\b', line) or \
               re.search(r"Statement.*\.execute\w*\s*\(\s*\"", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_SQL_INJECTION",
                              "S4507: SQL 注入风险：避免字符串拼接 SQL 查询，使用 PreparedStatement 参数化查询",
                              _sq_severity("BLOCKER"), line=i)

        # S2070: SHA-1 should not be used
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"SHA(-1)?["\s]|"SHA1["\s]|MessageDigest\.getInstance\s*\(\s*"SHA1?"\s*\)', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_SHA1",
                              "S2070: SHA-1 已被证明不安全，使用 SHA-256 或更强的哈希算法",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S4432: DES/3DES should not be used
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"(DES|DESede|3DES)"\s*[)\s]|Cipher\.getInstance\s*\(\s*"(DES|DESede)"', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_DES",
                              "S4432: DES/3DES 加密算法强度不足，应使用 AES（推荐 256 位）",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S4423: Weak SSL/TLS
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"(SSL|TLSv1|TLSv1\.1)"\s*[)\s]|SSLContext\.getInstance\s*\(\s*"(SSLv3|TLSv1|TLSv1\.1)"', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_WEAK_SSL",
                              "S4423: 使用弱 SSL/TLS 协议版本，应使用 TLSv1.2 或 TLSv1.3",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S4347: SecureRandom instead of Random
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+(java\.util\.)?Random\s*\(\s*\)", line) and \
               not re.search(r"//.*", line) and \
               not re.search(r"ThreadLocalRandom|SecureRandom", line):
                self._add(file_path, "SONAR_SECURE_RANDOM",
                          "S4347: 使用 'java.util.Random' 生成随机数不适用于安全敏感场景，应使用 'SecureRandom'",
                          _sq_severity("CRITICAL"), line=i)

        # S4929: MessageDigest not thread-safe
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "MessageDigest" in vtype:
                    mods = node.modifiers or []
                    if "static" in mods:
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_MD_THREADSAFE",
                                      "S4929: MessageDigest 不是线程安全的，static 字段可能导致并发问题；使用 ThreadLocal 或每次创建新实例",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2755: XXE (XML External Entity)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(DocumentBuilderFactory|SAXParser|SAXBuilder)\.newInstance\b", line):
                for j in range(i, min(i + 10, len(lines))):
                    if j < len(lines) and \
                       ("setFeature" not in lines[j] or
                        "http://apache.org/xml/features/disallow-doctype-decl" not in lines[j]):
                        continue
                    break
                else:
                    self._add(file_path, "SONAR_XXE",
                              "S2755: XML 解析器应禁用外部实体处理（XXE），防止 XML 外部实体注入攻击",
                              _sq_severity("BLOCKER"), line=i)

        # S4956: Runtime.exec called
        for i, line in enumerate(lines, 1):
            if re.search(r"Runtime\.getRuntime\(\)\.exec", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "SONAR_RUNTIME_EXEC",
                          "S4956: 'Runtime.exec()' 易受命令注入攻击，优先使用 ProcessBuilder 并参数化",
                          _sq_severity("CRITICAL"), line=i)

        # S4823: Command injection (ProcessBuilder)
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+ProcessBuilder\s*\([^)]*\)", line) and \
               not re.search(r"\"[^\"]*\"", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "SONAR_COMMAND_INJECTION",
                          "S4823: 命令行参数包含变量，可能存在命令注入风险；应使用列表形式传递参数",
                          _sq_severity("BLOCKER"), line=i)

        # S4792: Logger configuration should be secure
        for i, line in enumerate(lines, 1):
            if re.search(r"FileHandler|SocketHandler|SMTPHandler", line) and \
               not re.search(r"//.*", line) and \
               re.search(r"Logger|logger", line):
                self._add(file_path, "SONAR_LOGGER_SECURE",
                          "S4792: 确保日志记录器配置不会泄露敏感信息，避免记录密码、密钥等",
                          _sq_severity("MAJOR"), line=i)

        # S4800: Hardcoded cryptographic keys
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(?:key|secret|password|token|api[Kk]ey)\s*=\s*"[^"]{8,}"',
                                 line, re.IGNORECASE):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_HARDCODED_KEY",
                              "S4800: 硬编码的密钥/密码，应从环境变量或安全的密钥管理服务中获取",
                              _sq_severity("BLOCKER"), line=i, column=m.start())

        # S5290: Hardcoded passwords
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(password|passwd|pwd)\s*=\s*"[^"]{3,}"', line, re.IGNORECASE):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_HARDCODED_PASSWORD",
                              "S5290: 硬编码密码，应将密码存储在安全配置中或使用密钥管理服务",
                              _sq_severity("BLOCKER"), line=i, column=m.start())

        # S4925: Weak hash MD5
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"MD5["\s)]|MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_MD5",
                              "S4925: MD5 哈希算法已被证明不安全，不适合用于安全敏感场景（如密码存储、数字签名）",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5332: Clear text using HTTP
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"http://[\w./]+"', line):
                url = m.group()
                if "localhost" in url or "127.0.0.1" in url or "//test" in url:
                    continue
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_CLEAR_TEXT",
                              "S5332: 使用 HTTP 明文通信，敏感数据可能被窃听；应使用 HTTPS",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5042: ZIP entry traversal (ZipSlip)
        for i, line in enumerate(lines, 1):
            if re.search(r"ZipInputStream|ZipFile", line) and \
               not re.search(r"getName.*\.\.", line) and \
               not re.search(r"//.*", line):
                for j in range(i, min(i + 10, len(lines))):
                    if j < len(lines) and "getName" in lines[j]:
                        if ".." not in lines[j]:
                            self._add(file_path, "SONAR_ZIP_SLIP",
                                      "S5042: ZIP 文件解压时未检查文件名中的路径遍历（如 '../'），可能导致 ZipSlip 漏洞",
                                      _sq_severity("BLOCKER"), line=i)
                        break

        # S5135: Deserialization
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(ObjectInputStream|readObject|readUnshared)\b", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_DESERIALIZATION",
                              "S5135: Java 反序列化操作可能导致远程代码执行；对不可信数据应验证或使用白名单",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5145: Log injection
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(logger|log|LOGGER|LOG)\.(info|warn|error)\s*\(\s*\w+\s*\+\s*\w+", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_LOG_INJECTION",
                              "S5145: 日志中拼接用户输入可能导致日志注入，应清理或编码用户输入后再记录",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S5122: XSS (Cross-Site Scripting)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(HttpServletResponse|PrintWriter)\.(write|print|println)\s*\(\s*\w+", line):
                if not re.search(r"//.*", line) and \
                   not re.search(r"(Encode|escape|sanitize|filter)\(", line):
                    self._add(file_path, "SONAR_XSS",
                              "S5122: 直接将变量写入 HTTP 响应可能造成 XSS 跨站脚本攻击，应编码输出",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5547: SSRF (Server-Side Request Forgery)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(URL|HttpURLConnection|CloseableHttpClient|RestTemplate|WebClient)\b.*\b(openConnection|execute|getForObject|postForEntity)\b", line):
                if re.search(r"\w+\s*\+\s*\w+", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_SSRF",
                                  "S5547: 基于用户输入的 URL 发起远程请求可能导致 SSRF 攻击；应验证 URL 的目标地址",
                                  _sq_severity("CRITICAL"), line=i, column=m.start())

        # S4830: SSL certificate verification disabled
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"setDefaultHostnameVerifier|TrustAllCertificates|"
                                 r"setTrustManager\s*\(\s*new\s+X509TrustManager|"
                                 r"ALLOW_ALL_HOSTNAME_VERIFIER", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_SSL_DISABLED",
                              "S4830: 禁用了 SSL 证书验证，可能导致中间人攻击",
                              _sq_severity("BLOCKER"), line=i, column=m.start())

        # S5445: Regex injection (DoS via ReDoS)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"Pattern\.compile\s*\(\s*\w+\s*\)", line):
                if re.search(r"\+\s*\w+", line) or re.search(r"\.compile\s*\(\s*\w+\s*\+\s*", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_REGEX_INJECTION",
                                  "S5445: 基于用户输入动态编译正则表达式可能导致 ReDoS 攻击",
                                  _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5322: LDAP injection
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(?:javax\.naming\.|javax\.ldap\.).*\b(search|lookup|bind)\b', line):
                if re.search(r"\w+\s*\+\s*\w+", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_LDAP_INJECTION",
                                  "S5322: LDAP 查询中拼接用户输入可能导致 LDAP 注入",
                                  _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5301: Mail injection (SMTP headers)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'javax\.mail\.(Transport|Session)\b', line):
                if re.search(r"\w+\s*\+\s*\w+", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_MAIL_INJECTION",
                                  "S5301: 邮件头部拼接用户输入可能导致 SMTP 注入",
                                  _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5443: World-readable temporary files
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"File\.createTempFile|new\s+File\s*\([^)]*\"[^)]*\btemp\b", line, re.IGNORECASE):
                if not re.search(r"setReadable|setWritable|setExecutable", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_TEMP_FILE",
                                  "S5443: 临时文件可能被其他进程读取，应设置适当的文件权限",
                                  _sq_severity("MAJOR"), line=i, column=m.start())

        # S5659: JWT hardcoded
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(?:jwt|JWT|jwtSecret|jwtKey)\s*=\s*"[^"]{8,}"', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_JWT_KEY",
                              "S5659: JWT 签名密钥硬编码，应从环境变量或密钥管理服务获取",
                              _sq_severity("BLOCKER"), line=i, column=m.start())

        # S5661: Log forging (CRLF injection in logs)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(logger|log|LOGGER|LOG)\.(info|warn|error|debug)\s*\(\s*\w+', line):
                if re.search(r"\w+\s*\+\s*\w+", line) and \
                   not re.search(r"(Encode|escape|sanitize|replaceAll.*[rn])", line) and \
                   not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_LOG_FORGING",
                              "S5661: 日志输出中拼接用户输入可能导致日志伪造/注入，应清理换行符等控制字符",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S3281: World-writable files
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"setWritable\s*\(\s*true\b|setReadable\s*\(\s*true\b|setExecutable\s*\(\s*true\b", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_FILE_PERM",
                              "S3281: 赋予所有人读写执行权限可能导致安全风险",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5542: XML external entity
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(TransformerFactory|SAXTransformerFactory)\.newInstance\b', line):
                for j in range(i, min(i + 10, len(lines))):
                    if j < len(lines) and \
                       ("setFeature" in lines[j] and
                        "javax.xml.XMLConstants" in lines[j]):
                        break
                else:
                    self._add(file_path, "SONAR_XML_PROCESS",
                              "S5542: XML 转换器应禁用外部实体处理（XXE）以防止注入攻击",
                              _sq_severity("BLOCKER"), line=i)

        # S4972: Forbidden URL redirect
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(sendRedirect|setHeader\s*\(\s*\"Location\")\s*\(\s*\w+", line):
                if not re.search(r"\"[^\"]*\"", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_OPEN_REDIRECT",
                                  "S4972: 基于用户输入的重定向可能导致开放重定向攻击",
                                  _sq_severity("CRITICAL"), line=i, column=m.start())
