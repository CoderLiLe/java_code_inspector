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


class SonarQubeCheckerSix:
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
        self.check_bugs_six(tree, file_path, content)
        self.check_code_smell_six(tree, file_path, content)
        self.check_security_six(tree, file_path, content)

    # ==================== Bugs Six ====================

    def check_bugs_six(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_bugs_six"):
            return
        lines = content.split("\n")

        # S1148: printStackTrace should not be called
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "printStackTrace":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PRINT_STACK_TRACE",
                              "S1148: 不应直接调用 printStackTrace()，应使用日志框架",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1163: Exceptions should not be thrown in finally blocks
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                finally_block = getattr(node, "finally_block", None)
                if finally_block and isinstance(finally_block, list):
                    for stmt in finally_block:
                        if isinstance(stmt, javalang_tree.ThrowStatement):
                            l, c = self._pos(stmt)
                            self._add(file_path, "SONAR_THROW_IN_FINALLY",
                                      "S1163: finally 块中不应抛出异常",
                                      _sq_severity("MAJOR"), line=l, column=c)
                            break

        # S1180: @SuppressWarnings should not be used for deprecation
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                anns = getattr(node, "annotations", []) or []
                for ann in anns:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "SuppressWarnings":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SUPPRESS_WARNING",
                                  "S1180: 应避免使用 @SuppressWarnings，应修复潜在问题",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S1193: instanceof used with incompatible types (simple: comparing with final class siblings)
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "instanceof":
                    right = getattr(node, "operandr", None)
                    right_type = type(right).__name__
                    if right_type == "ReferenceType":
                        type_name = _get_full_type_name(right)
                        if type_name in ("String", "Integer", "Long", "Boolean", "Double", "Short", "Byte", "Float"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_INSTANCEOF_FINAL",
                                      "S1193: 不应使用 instanceof 检测 final 类 '" + type_name + "'",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S1195: Array designators should be on the type (String[] args not String args[])
        for i, line in enumerate(lines, 1):
            m = re.search(r'(?<!\w)(\w+)\s+(\w+)\s*\[\]', line)
            if m and not re.match(r'^\s*\*', line) and not line.strip().startswith("//"):
                self._add(file_path, "SONAR_ARRAY_DESIGNATOR_TYPE",
                          "S1195: 数组方括号应放在类型上（" + m.group(1) + "[] " + m.group(2) + "）",
                          _sq_severity("MINOR"), line=i)

        # S1197: Array designators should be on the variable (only one var per line)
        for i, line in enumerate(lines, 1):
            m = re.search(r'(\w+\s*\[\])\s*,?\s*(\w+)\s*=', line)
            if m and not line.strip().startswith(("//", "*", "/*")) and not re.match(r'^\s*\*', line):
                pass

        # S1199: Nested code blocks should not be empty
        for path, node in tree:
            if isinstance(node, javalang_tree.BlockStatement):
                stmts = getattr(node, "statements", []) or []
                if len(stmts) == 0:
                    # Find the actual parent by going through path to skip list wrappers
                    parent = None
                    for p in reversed(path):
                        if not isinstance(p, list):
                            parent = p
                            break
                    if parent and not isinstance(parent, (javalang_tree.ForStatement,
                                                           javalang_tree.WhileStatement,
                                                           javalang_tree.IfStatement,
                                                           javalang_tree.TryStatement,
                                                           javalang_tree.CatchClause)):
                        # Exclude method body itself: check if this block is in a statements list
                        if isinstance(parent, javalang_tree.MethodDeclaration):
                            is_in_list = len(path) >= 1 and isinstance(path[-1], list)
                            if not is_in_list:
                                continue
                        l, c = self._pos(node)
                        if l:
                            self._add(file_path, "SONAR_EMPTY_NESTED_BLOCK",
                                      "S1199: 嵌套代码块不应为空",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S1202: StringBuffer should not be used; StringBuilder preferred
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name == "StringBuffer":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STRING_BUFFER",
                              "S1202: 应使用 StringBuilder 替代 StringBuffer（除非涉及线程安全）",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2111 / S2232: BigDecimal(double) should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name == "BigDecimal" or type_name == "java.math.BigDecimal":
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 1 and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val and "." in val:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_BIG_DECIMAL_DOUBLE",
                                      "S2111: 不应使用 BigDecimal(double)，应使用 BigDecimal(String)",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2129: String concatenation should not be in loop
        for path, node in tree:
            if isinstance(node, (javalang_tree.ForStatement, javalang_tree.WhileStatement)):
                body = node.body
                if body is None:
                    continue
                stmts = body.statements if hasattr(body, "statements") else \
                        (body if isinstance(body, list) else [])
                for stmt in stmts:
                    expr = getattr(stmt, "expression", None)
                    if expr and isinstance(expr, javalang_tree.Assignment):
                        expr_str = str(expr)
                        if "+=" in expr_str:
                            left = getattr(expr, "expressionl", None)
                            if left and hasattr(left, "member"):
                                m_name = getattr(left, "member", "")
                                if m_name and m_name not in ("i", "j", "k", "index", "count", "len"):
                                    l, c = self._pos(stmt)
                                    self._add(file_path, "SONAR_STRING_CONCAT_LOOP",
                                              "S2129: 循环中使用字符串拼接，建议使用 StringBuilder",
                                              _sq_severity("MAJOR"), line=l, column=c)
                                    break

        # S2139: Exceptions should not be simply rethrown
        for path, node in tree:
            if isinstance(node, javalang_tree.CatchClause):
                block = getattr(node, "block", None) or []
                for stmt in block:
                    if isinstance(stmt, javalang_tree.ThrowStatement):
                        thrown = getattr(stmt, "expression", None)
                        if thrown and isinstance(thrown, javalang_tree.MemberReference):
                            l, c = self._pos(stmt)
                            self._add(file_path, "SONAR_EXCEPTION_RETHROW",
                                      "S2139: catch 块不应仅重新抛出异常，应记录日志或处理",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2140: Double-checked locking should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                if cond and isinstance(cond, javalang_tree.BinaryOperation):
                    cond_str = str(cond).replace(" ", "")
                    if "!=null" in cond_str:
                        parent_path = path[:-1]
                        for ancestor_node in reversed(parent_path):
                            if isinstance(ancestor_node, javalang_tree.SynchronizedStatement):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_DOUBLE_CHECK_LOCK",
                                          "S2140: 双重检查锁定模式可能不安全，应使用 volatile 或 AtomicReference",
                                          _sq_severity("MAJOR"), line=l, column=c)
                                break

        # S2151: Thread.start should not be called in constructor
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "__init__":
                    for path2, node2 in tree:
                        if isinstance(node2, javalang_tree.MethodInvocation):
                            member = getattr(node2, "member", "")
                            qualifier = getattr(node2, "qualifier", "") or ""
                            if member == "start" and ("Thread" in qualifier or not qualifier):
                                l, c = self._pos(node2)
                                self._add(file_path, "SONAR_THREAD_START_CONSTRUCTOR",
                                          "S2151: 不应在构造函数中调用 Thread.start()",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S2184: Int division cast to float
        for path, node in tree:
            if isinstance(node, javalang_tree.Cast):
                operand = getattr(node, "operand", None)
                type_node = getattr(node, "type", None)
                if operand and type_node:
                    to_type = _get_full_type_name(type_node)
                    if to_type in ("float", "double", "Float", "Double"):
                        if isinstance(operand, javalang_tree.BinaryOperation):
                            op = getattr(operand, "operator", "")
                            if op == "/":
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_INT_DIV_CAST",
                                          "S2184: 整数除法后转换为浮点数，应在除法前转换避免精度损失",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S2201: Return value ignored
        for path, node in tree:
            if isinstance(node, javalang_tree.StatementExpression):
                expr = getattr(node, "expression", None)
                if isinstance(expr, javalang_tree.MethodInvocation):
                    member = getattr(expr, "member", "")
                    ignored = {"trim", "substring", "toLowerCase", "toUpperCase",
                               "replace", "replaceAll", "replaceFirst", "strip",
                               "intern", "toString"}
                    if member in ignored:
                        l, c = self._pos(expr)
                        self._add(file_path, "SONAR_IGNORED_RETURN",
                                  "S2201: " + member + "() 的返回值被忽略（String 不可变）",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S2251: For loop counter should not be assigned in body
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                init = getattr(node, "init", None)
                loop_var = None
                if init and isinstance(init, javalang_tree.VariableDeclaration):
                    for decl in getattr(init, "declarators", []) or []:
                        loop_var = getattr(decl, "name", "")
                        break
                if loop_var:
                    body = node.body
                    if body is None:
                        continue
                    stmts = body.statements if hasattr(body, "statements") else \
                            (body if isinstance(body, list) else [])
                    for stmt in stmts:
                        stmt_str = str(stmt)
                        if " " + loop_var + " =" in stmt_str or loop_var + "=" in stmt_str:
                            l, c = self._pos(stmt)
                            self._add(file_path, "SONAR_LOOP_COUNTER_ASSIGN",
                                      "S2251: 不应在循环体内修改循环计数器 '" + loop_var + "'",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2252: Float should not be used as loop counter
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                init = getattr(node, "init", None)
                if init and isinstance(init, javalang_tree.VariableDeclaration):
                    var_type = getattr(init, "type", None)
                    if var_type:
                        type_name = _get_full_type_name(var_type)
                        if type_name in ("float", "double", "Float", "Double"):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_FLOAT_LOOP_COUNTER",
                                      "S2252: 不应使用浮点数作为循环计数器，可能导致精度问题",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2293: Diamond operator should be used (Java 7+)
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                args = getattr(node, "arguments", []) or []
                type_node = getattr(node, "type", None)
                if type_node and isinstance(type_node, javalang_tree.ReferenceType):
                    type_args = getattr(type_node, "arguments", None)
                    if type_args and len(type_args) > 0:
                        type_name = _get_full_type_name(type_node)
                        if not type_name.startswith("java."):
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_DIAMOND_MISSING",
                                      "S2293: 应使用菱形操作符 <> 简化泛型实例创建",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S2440: Boxing/unboxing should not be used for comparison
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op in ("==", "!="):
                    left = getattr(node, "operandl", None)
                    right = getattr(node, "operandr", None)
                    for side in (left, right):
                        if isinstance(side, javalang_tree.MethodInvocation):
                            member = getattr(side, "member", "")
                            if member in ("intValue", "longValue", "shortValue",
                                          "byteValue", "doubleValue", "floatValue"):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_BOXING_COMPARE",
                                          "S2440: 不必要的装箱/拆箱比较，建议直接比较值",
                                          _sq_severity("MINOR"), line=l, column=c)
                                break

        # S3398: Private method called only from inner class
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.MethodDeclaration):
                        if "private" in (decl.modifiers or []) and \
                           decl.name not in self._METHOD_BLACKLIST and \
                           not decl.name.startswith("set") and \
                           not decl.name.startswith("get"):
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_PRIVATE_METHOD_NOT_USED",
                                      "S3398: 私有方法 '" + decl.name + "' 可能未被使用",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S3972: Conditionally executed code should be comprehensible
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                else_stmt = getattr(node, "else_statement", None)
                if else_stmt:
                    if isinstance(else_stmt, javalang_tree.IfStatement):
                        cond2 = getattr(node, "condition", None)
                        cond3 = getattr(else_stmt, "condition", None)
                        if cond2 and cond3:
                            cond2_str = str(cond2).replace(" ", "")
                            cond3_str = str(cond3).replace(" ", "")
                            neg_cond2 = "!" + cond2_str if not cond2_str.startswith("!") else cond2_str[1:]
                            if cond3_str == neg_cond2:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_NEGATED_ELSE_IF",
                                          "S3972: else-if 条件与前一条件互为否定，应合并为 if-else",
                                          _sq_severity("MINOR"), line=l, column=c)

        # S3988: Parallel stream should not be used without reason
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("parallel", "parallelStream"):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_PARALLEL_STREAM_SIX",
                              "S3988: 使用并行流需注意线程安全和性能开销",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Code Smell Six ====================

    def check_code_smell_six(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_code_smell_six"):
            return
        lines = content.split("\n")

        # S1121: Assignment in boolean expression
        for path, node in tree:
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == "=":
                    for path2, node2 in tree:
                        if isinstance(node2, (javalang_tree.IfStatement,
                                              javalang_tree.WhileStatement)):
                            cond = getattr(node2, "condition", None)
                            if cond and str(cond).replace(" ", "") == str(node).replace(" ", ""):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_ASSIGN_IN_COND_SIX",
                                          "S1121(改): 条件表达式中不应使用赋值",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S1132: String literal should not be duplicated (covers 5+ occurrences)
        string_counts = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.Literal):
                val = getattr(node, "value", "")
                if val and len(val) >= 3 and val.startswith('"') and val.endswith('"'):
                    string_counts[val] = string_counts.get(val, 0) + 1
        for val, count in string_counts.items():
            if count >= 5:
                for path, node in tree:
                    if isinstance(node, javalang_tree.Literal):
                        v = getattr(node, "value", "")
                        if v == val:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_DUPLICATE_STRING_LITERAL",
                                      "S1132: 字符串 '" + val + "' 重复出现 " + str(count) + " 次，应提取为常量",
                                      _sq_severity("MINOR"), line=l, column=c)
                            break

        # S1133: Deprecated code should be removed
        for i, line in enumerate(lines, 1):
            if re.search(r'@Deprecated', line) and not line.strip().startswith("//"):
                for path, node in tree:
                    if isinstance(node, (javalang_tree.MethodDeclaration,
                                         javalang_tree.ClassDeclaration,
                                         javalang_tree.FieldDeclaration)):
                        anns = getattr(node, "annotations", []) or []
                        for ann in anns:
                            ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                            if ann_name == "Deprecated":
                                l = getattr(getattr(node, "position", None), "line", 0)
                                if l:
                                    self._add(file_path, "SONAR_DEPRECATED_CODE",
                                              "S1133: @Deprecated 标记的代码应在下一个主版本中移除",
                                              _sq_severity("MINOR"), line=l)

        # S1150: Anonymous classes should not be too long (>20 lines)
        current_anon = []
        in_anon = False
        anon_start = 0
        anon_line_count = 0
        brace_depth = 0
        for i, line in enumerate(lines, 1):
            if 'new ' in line and '{' in line and not line.strip().startswith("//"):
                m = re.search(r'new\s+\w+\s*\([^)]*\)\s*\{', line)
                if m:
                    current_anon.append((i, i))
                    in_anon = True
                    anon_start = i
                    anon_line_count = 1
                    brace_depth = line.count('{') - line.count('}')
                    continue
            if in_anon:
                anon_line_count += 1
                brace_depth += line.count('{') - line.count('}')
                if brace_depth <= 0:
                    if anon_line_count > 20:
                        self._add(file_path, "SONAR_LONG_ANON_CLASS",
                                  "S1150: 匿名类过长（" + str(anon_line_count) + " 行），建议提取为内部类",
                                  _sq_severity("MAJOR"), line=anon_start)
                    in_anon = False
                    current_anon.pop() if current_anon else None

        # S1160: Methods should not throw too many exceptions (>= 4)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                throws = getattr(node, "throws", None) or []
                if isinstance(throws, list) and len(throws) >= 4:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TOO_MANY_THROWS",
                              "S1160: 方法声明了过多异常（" + str(len(throws)) + " 个），建议拆分",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1171: String literal should be on LHS of equals
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                qualifier = str(getattr(node, "qualifier", "") or "")
                if member == "equals" and qualifier and not qualifier.startswith('"'):
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        if isinstance(arg, javalang_tree.Literal):
                            val = getattr(arg, "value", "")
                            if val and val.startswith('"') and val.endswith('"'):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_STRING_LHS_EQUALS",
                                          "S1171: 字符串字面量应放在 equals() 左侧以避免 NPE",
                                          _sq_severity("MAJOR"), line=l, column=c)
                                break

        # S1223: finalize() should not be protected
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name == "finalize" and "protected" in (node.modifiers or []):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_FINALIZE_PROTECTED",
                              "S1223: finalize() 不应声明为 protected",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1450: Protected fields should not be exposed
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                if "protected" in (node.modifiers or []) and \
                   "static" not in (node.modifiers or []) and \
                   "final" not in (node.modifiers or []):
                    for decl in getattr(node, "declarators", []) or []:
                        name = getattr(decl, "name", "")
                        if name:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_PROTECTED_FIELD",
                                      "S1450: protected 字段 '" + name + "' 应改为 private 并提供 getter/setter",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S1862: Duplicate conditions in if/else-if chain
        conditions = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.IfStatement):
                cond = getattr(node, "condition", None)
                cond_str = str(cond).replace(" ", "") if cond else ""
                if cond_str and cond_str != "true" and cond_str != "false":
                    if cond_str in conditions:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_DUPLICATE_CONDITION",
                                  "S1862: if/else-if 中存在重复条件",
                                  _sq_severity("MAJOR"), line=l, column=c)
                    else:
                        conditions[cond_str] = True
                else_stmt = getattr(node, "else_statement", None)
                if isinstance(else_stmt, javalang_tree.IfStatement):
                    continue
                else:
                    conditions.clear()

        # S2112: URL.hashCode should be avoided
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "hashCode" and getattr(node, "qualifier", None):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_URL_HASHCODE",
                              "S2112: URL.hashCode() 可能执行 DNS 查询，应避免在集合中使用",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2114: Collection.remove should not use index for List
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "remove":
                    q = str(getattr(node, "qualifier", "") or "")
                    args = getattr(node, "arguments", []) or []
                    if len(args) == 1 and isinstance(args[0], javalang_tree.Literal):
                        val = getattr(args[0], "value", "")
                        if val.isdigit():
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_LIST_REMOVE_INT",
                                      "S2114: List.remove(int) 使用索引而非对象删除，可能不是本意",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2116: String.hashCode() should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "hashCode" and q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STRING_HASHCODE",
                              "S2116: String.hashCode() 在不同 JVM 间可能不一致",
                              _sq_severity("MINOR"), line=l, column=c)

        # S2118: File.delete() should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "delete" and "File" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_FILE_DELETE",
                              "S2118: File.delete() 应检查返回值，建议使用 Files.delete()",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2121: Iterator.remove() should be used instead of List.remove() in loop
        for path, node in tree:
            if isinstance(node, javalang_tree.ForStatement):
                body = node.body
                if body is None:
                    continue
                stmts = body.statements if hasattr(body, "statements") else \
                        (body if isinstance(body, list) else [])
                for stmt in stmts:
                    stmt_str = str(stmt)
                    if ".remove(" in stmt_str and "iterator" not in stmt_str.lower():
                        l, c = self._pos(stmt)
                        self._add(file_path, "SONAR_LIST_REMOVE_LOOP",
                                  "S2121: 遍历时使用 List.remove() 会导致异常，应使用 Iterator.remove()",
                                  _sq_severity("MAJOR"), line=l, column=c)
                        break

        # S2250: String.intern() should not be used
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "intern":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STRING_INTERN",
                              "S2250: String.intern() 可能影响性能，应避免使用",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S2236: wait should not be called on Thread
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "wait" and getattr(node, "qualifier", None):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_THREAD_WAIT",
                              "S2236: 不应在 Thread 实例上调用 wait()，应使用 join()",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Security Six ====================

    def check_security_six(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security_six"):
            return
        lines = content.split("\n")

        # S2257: Non-constant string should not be used in crypto
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "getInstance":
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Cipher" in q or "MessageDigest" in q or "Mac" in q or "Signature" in q:
                        args = getattr(node, "arguments", []) or []
                        if args:
                            arg = args[0]
                            if not isinstance(arg, javalang_tree.Literal) or \
                               not str(getattr(arg, "value", "")).startswith('"'):
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_CRYPTO_VARIABLE",
                                          "S2257: 不应使用非字面量字符串作为加密算法参数",
                                          _sq_severity("MAJOR"), line=l, column=c)

        # S2245: Random should not be used for security (already in fourth)
        # S4347: SecureRandom should be used with strong algorithm

        # S4426: Weak cryptographic key length
        for i, line in enumerate(lines, 1):
            if re.search(r'KeyPairGenerator.*getInstance\s*\(\s*"RSA"\s*\)', line) or \
               re.search(r'KeyGenerator.*getInstance\s*\(\s*"AES"\s*\)', line):
                pass

        # S4431: Servlet mapping should not be case-insensitive
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                anns = getattr(node, "annotations", []) or []
                for ann in anns:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name in ("RequestMapping", "GetMapping", "PostMapping",
                                    "PutMapping", "DeleteMapping", "PatchMapping"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_WEB_MAPPING",
                                  "S4431: Web 映射应显式指定 method 属性",
                                  _sq_severity("MINOR"), line=l, column=c)
                        break

        # S4517: Resource should be closed (try-with-resources)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                stmts = getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in stmts:
                    if isinstance(stmt, javalang_tree.VariableDeclaration):
                        var_type = getattr(stmt, "type", None)
                        if var_type:
                            type_name = _get_full_type_name(var_type)
                            if type_name in ("FileInputStream", "FileOutputStream",
                                             "FileReader", "FileWriter",
                                             "BufferedReader", "BufferedWriter",
                                             "InputStream", "OutputStream",
                                             "Connection", "Statement", "ResultSet"):
                                for decl in getattr(stmt, "declarators", []) or []:
                                    init = getattr(decl, "initializer", None)
                                    if init:
                                        l, c = self._pos(stmt)
                                        self._add(file_path, "SONAR_RESOURCE_TRY_WITH",
                                                  "S4517: 应使用 try-with-resources 自动关闭资源",
                                                  _sq_severity("MAJOR"), line=l, column=c)
                                        break

        # S4838: JSON should be parsed securely
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "fromJson" and "Gson" in q:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_GSON_JSON",
                              "S4838: 使用 Gson.fromJson() 时注意反序列化安全",
                              _sq_severity("MAJOR"), line=l, column=c)

                if member == "readValue" and ("ObjectMapper" in q or "Json" in q):
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_JACKSON_JSON",
                              "S4838: 使用 Jackson 反序列化时需防范多态反序列化攻击",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S5131: XSS vulnerabilities in JSP/Spring
        for i, line in enumerate(lines, 1):
            if re.search(r'response\.getWriter\(\)\.print\(', line):
                self._add(file_path, "SONAR_XSS_OUTPUT",
                          "S5131: 直接输出用户输入可能导致 XSS，应进行转义",
                          _sq_severity("MAJOR"), line=i)

        # S5280: CSP should not be disabled
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "setHeader" and "response" in q:
                    args = getattr(node, "arguments", []) or []
                    for arg in args:
                        if isinstance(arg, javalang_tree.Literal):
                            val = getattr(arg, "value", "")
                            if "X-Content-Type-Options" in val or \
                               "X-Frame-Options" in val or \
                               "Content-Security-Policy" in val:
                                pass

        # S5693: Content type should be specified
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                anns = getattr(node, "annotations", []) or []
                for ann in anns:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    if ann_name == "PostMapping":
                        ann_element = getattr(ann, "element", None)
                        if ann_element and "consumes" not in str(ann_element):
                            pass

        # S5852: Regex DOS (ReDoS) - simple patterns
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member in ("compile", "matches", "split"):
                    q = str(getattr(node, "qualifier", "") or "")
                    if "Pattern" in q or "String" in q:
                        args = getattr(node, "arguments", []) or []
                        if args and isinstance(args[0], javalang_tree.Literal):
                            val = getattr(args[0], "value", "")
                            if val and len(val) > 3:
                                self._check_regex_dos(val, node, file_path)

        # S5860: getClass should not be used for authentication
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "getClass":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_GETCLASS_AUTH",
                              "S5860: getClass() 不应用于身份验证，应使用 instanceof",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S5876: Thread should not be created manually
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassCreator):
                type_node = getattr(node, "type", None)
                type_name = _get_full_type_name(type_node)
                if type_name == "Thread" or type_name == "java.lang.Thread":
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_MANUAL_THREAD",
                              "S5876: 应使用 ExecutorService 替代直接创建 Thread",
                              _sq_severity("MAJOR"), line=l, column=c)

    def _check_regex_dos(self, pattern: str, node, file_path: str):
        dangerous = [
            r'\(\.\*\+\)',
            r'\(\.\+\+\)',
            r'\(\w\{2,\}\)\+',
            r'\(\w\+\)\+',
            r'\(\[\^\]\+\)\+',
        ]
        for d in dangerous:
            if re.search(d, pattern):
                l, c = self._pos(node)
                self._add(file_path, "SONAR_REGEX_DOS",
                          "S5852: 正则表达式存在 ReDoS 风险（" + pattern + "）",
                          _sq_severity("MAJOR"), line=l, column=c)
                return
