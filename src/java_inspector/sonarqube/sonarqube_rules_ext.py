"""SonarQubeCheckerExt — 扩展检查器"""
"""SonarQubeCheckerExt — 扩展检查器"""
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


class SonarQubeCheckerExt:
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
        self.check_performance(tree, file_path, content)
        self.check_reliability(tree, file_path, content)
        self.check_design(tree, file_path, content)
        self.check_bugs_ext(tree, file_path, content)
        self.check_security_ext(tree, file_path, content)

    # ==================== Performance ====================
    def check_performance(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_performance"):
            return
        lines = content.split("\n")

        # S1158: Primitive wrapper instantiation
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"new\s+(Integer|Long|Double|Float|Short|Byte|Boolean|Character)\s*\(\s*\d+", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_WRAPPER_INSTANCE",
                              "S1158: 使用 'valueOf()' 而非 'new Wrapper()' 创建包装类型，valueOf 有缓存优化",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S1191: Replace legacy collections
        legacy_map = {"Vector": "ArrayList", "Hashtable": "HashMap", "StringBuffer": "StringBuilder"}
        for i, line in enumerate(lines, 1):
            for name, replacement in legacy_map.items():
                if re.search(r"(new\s+|\b)" + name + r"\b", line) and \
                   "java.util" not in line and not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_LEGACY_COLLECTION",
                              "S1191: 使用 '" + replacement + "' 替代 '" + name + "'，" + {
                                  "Vector": "Vector 是线程安全的但性能差",
                                  "Hashtable": "Hashtable 是线程安全的但性能差",
                                  "StringBuffer": "单线程环境应使用 StringBuilder"
                              }[name],
                              _sq_severity("MAJOR"), line=i)

        # S2131: Split on single char should use indexOf
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'\.split\s*\(\s*"[^"]{1}"\s*\)', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_SPLIT_CHAR",
                              "S2131: 分割单字符字符串应使用 indexOf 或循环遍历而非 split，split 开销较大",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S2168: Return empty collection instead of null
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                ret_type = str(getattr(node, "return_type", ""))
                if "List" in ret_type or "Set" in ret_type or "Map" in ret_type or "Collection" in ret_type:
                    for stmt in body:
                        s = str(stmt)
                        if "return null;" in s:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_RETURN_EMPTY",
                                      "S2168: 返回集合/Map 的方法应返回空集合而非 null，避免调用者空指针",
                                      _sq_severity("MAJOR"), line=l, column=c)
                            break

        # S3416: Logger naming convention
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(?:Logger|logger|Log|log)\s+\w+\s*=\s*(?:Logger|LogFactory)", line):
                if not re.search(r"//.*", line):
                    parts = line.split("=")
                    if len(parts) >= 1:
                        var_part = parts[0].strip().split()[-1] if parts[0].strip() else ""
                        if var_part and var_part not in ("logger", "log", "LOGGER", "LOG", "log_", "_log"):
                            pass
                    self._add(file_path, "SONAR_LOGGER_NAMING",
                              "S3416: 日志变量应命名为 'logger' 或 'LOG'，保持命名一致性",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S3421: File separator should be File.separator
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"[^"]*(?:\\\\|/)[^"]*"', line):
                s = m.group()
                if "File.separator" not in line and "FileSystem" not in line:
                    self._add(file_path, "SONAR_FILE_SEPARATOR",
                              "S3421: 应使用 'File.separator' 或 '/' 替代硬编码的文件分隔符 '\\\\'",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S3610: Empty array should be `new Type[0]`
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"new\s+\w+\[\s*0\s*\]", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_EMPTY_ARRAY",
                              "S3610: 创建零长度数组时使用 'new Type[0]' 优于空列表的 toArray 方法",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S3457: String.format with wrong placeholder count
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'String\.format\s*\(\s*"[^"]*%[sd]",\s*\)', line):
                self._add(file_path, "SONAR_FORMAT_ARGS",
                          "S3457: String.format 格式字符串包含占位符但未提供对应参数",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S1711: StringBuffer in single-thread
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+StringBuffer\b", line) and \
               not re.search(r"//.*", line) and \
               not re.search(r"synchronized|lock|volatile|Thread", line):
                self._add(file_path, "SONAR_STRING_BUFFER",
                          "S1711: StringBuffer 是线程安全的但性能差，单线程环境应使用 StringBuilder",
                          _sq_severity("MAJOR"), line=i)

        # S3626: Jump statements in loop (break/continue with label)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\b(break|continue)\s+\w+\s*;", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_LABELED_JUMP",
                              "S3626: 循环中使用带标签的 break/continue 降低了代码可读性，应重构",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S3242: Use base type for parameters (if method uses only base type methods)
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                for param in (getattr(node, "parameters", []) or []):
                    pt = getattr(param, "type", None)
                    if pt and hasattr(pt, "name") and pt.name in ("ArrayList", "LinkedList"):
                        body_str = " ".join(str(s) for s in (
                            node.body if isinstance(node.body, list) else
                            getattr(getattr(node, "body", None), "statements", []) or []
                        ))
                        impl_specific = pt.name == "ArrayList" and "ensureCapacity" in body_str
                        impl_specific = impl_specific or (pt.name == "LinkedList" and (
                            "addFirst" in body_str or "addLast" in body_str or
                            "getFirst" in body_str or "getLast" in body_str or
                            "removeFirst" in body_str or "removeLast" in body_str
                        ))
                        if not impl_specific:
                            l, c = self._pos(param)
                            self._add(file_path, "SONAR_BASE_TYPE_PARAM",
                                      "S3242: 使用接口类型 'List' 替代实现类 '" + pt.name + "' 作为参数类型",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S3986: Date format pattern variable
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"(yyyy|MM|dd|HH|mm|ss)[^"]*"', line):
                if "SimpleDateFormat" in line or "DateTimeFormatter" in line:
                    self._add(file_path, "SONAR_DATE_FORMAT",
                              "S3986: 日期格式字符串应定义为常量，避免重复创建",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S4165: Hardcoded numeric literals (magic numbers) - basic
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"[^a-zA-Z](\d{4,})\b(?!\s*\.)", line):
                val = m.group(1)
                if val in ("1000", "1024", "2048", "4096", "3600", "86400", "365", "366"):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_MAGIC_NUMBER",
                                  "S4165: 建议将硬编码的数值 '" + val + "' 定义为命名常量",
                                  _sq_severity("MINOR"), line=i, column=m.start())

        # S1602: Unnecessary boxing
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"Integer\.valueOf\(\s*(\d+)\s*\)", line):
                if int(m.group(1)) < 0 or int(m.group(1)) > 127:
                    pass
                else:
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_UNNECESSARY_BOXING",
                                  "S1602: 自动装箱不需要显式调用 'Integer.valueOf()'，可直接赋值",
                                  _sq_severity("MINOR"), line=i, column=m.start())

    # ==================== Reliability ====================
    def check_reliability(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_reliability"):
            return
        lines = content.split("\n")

        # S112: General exception types should not be thrown
        for path, node in tree:
            if isinstance(node, javalang_tree.ThrowStatement) and \
               hasattr(node, "expression") and node.expression:
                ex_str = str(node.expression)
                if "RuntimeException" in ex_str and "new " in ex_str:
                    pass
                elif "Exception" in ex_str and "new " in ex_str:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_GENERAL_EXCEPTION",
                              "S112: 不应抛出通用异常类型 'Exception'，应使用更具体的异常类型",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1130: Throws declaration should be specific
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                throws = getattr(node, "throws", None) or []
                for t in throws:
                    tn = getattr(t, "name", str(t))
                    if tn in ("Exception", "Throwable"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_GENERIC_THROWS",
                                  "S1130: 方法的 throws 声明应使用具体异常类型而非通用 '" + tn + "'",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1143: Return/throw from finally block
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                finally_block = getattr(node, "finally_block", None)
                if finally_block and isinstance(finally_block, list):
                    for stmt in finally_block:
                        if isinstance(stmt, (javalang_tree.ReturnStatement, javalang_tree.ThrowStatement)):
                            l = stmt.position.line if stmt.position else 0
                            rule = "SONAR_FINALLY_RETURN" if isinstance(stmt, javalang_tree.ReturnStatement) \
                                   else "SONAR_FINALLY_THROW"
                            msg = "S1143: finally 块中不应使用 'return'，会覆盖 try 中的返回值或异常" if \
                                  isinstance(stmt, javalang_tree.ReturnStatement) else \
                                  "S1143: finally 块中不应抛出异常，会覆盖 try 中的异常"
                            self._add(file_path, rule, msg,
                                      _sq_severity("CRITICAL"), line=l)

        # S1181: Throwable should not be caught
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                for catch in (node.catches or []):
                    param = getattr(catch, "parameter", None)
                    if param:
                        types = getattr(param, "types", [])
                        for t in types:
                            tn = getattr(t, "name", str(t)) if hasattr(t, "name") else str(t)
                            if tn == "Throwable":
                                l = catch.position.line if catch.position else 0
                                self._add(file_path, "SONAR_CATCH_THROWABLE",
                                          "S1181: 不应捕获 'Throwable'，它包含 'Error' 等不可恢复的异常",
                                          _sq_severity("MAJOR"), line=l)

        # S1168: Return empty collection instead of null
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                ret_type = str(getattr(node, "return_type", ""))
                for stmt in body:
                    s = str(stmt)
                    if "return null;" in s and "Collection" in ret_type:
                        l = stmt.position.line if stmt.position else 0
                        self._add(file_path, "SONAR_NULL_COLLECTION",
                                  "S1168: 返回集合类型的方法应返回空集合而非 null",
                                  _sq_severity("MAJOR"), line=l)

        # S1172: Unused method parameters
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if node.name in self._METHOD_BLACKLIST or \
                   node.name == "<init>" or \
                   "abstract" in (node.modifiers or []):
                    continue
                params = getattr(node, "parameters", []) or []
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                if not body:
                    continue

                # Determine body start column on its first line (to skip method signature)
                body_start_col = 0
                if body[0].position:
                    body_line = body[0].position.line
                    body_start_col = body[0].position.column

                param_names = {getattr(p, "name", "") for p in params}
                for param in params:
                    pname = getattr(param, "name", "")
                    if not pname:
                        continue
                    used = False
                    for stmt in body:
                        stmt_line = getattr(getattr(stmt, "position", None), "line", None)
                        if not stmt_line:
                            continue
                        line_idx = stmt_line - 1
                        if line_idx >= len(lines):
                            continue
                        line_text = lines[line_idx]
                        # For the line containing the method signature, only check after body start column
                        if stmt_line == body[0].position.line:
                            col = body[0].position.column
                            line_text = line_text[col - 1:]
                        if re.search(r'\b' + re.escape(pname) + r'\b', line_text):
                            used = True
                            break
                    if not used:
                        l, c = self._pos(param)
                        self._add(file_path, "SONAR_UNUSED_PARAMETER",
                                  "S1172: 参数 '" + pname + "' 在方法 '" + node.name + "' 中未使用，应移除",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1192: String literals should not be duplicated
        string_counts = {}
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"[^"]{6,}"', line):
                s = m.group()
                if s not in string_counts:
                    string_counts[s] = []
                string_counts[s].append(i)
        for s, positions in string_counts.items():
            if len(positions) >= 3:
                self._add(file_path, "SONAR_DUPLICATE_STRING",
                          "S1192: 字符串 " + s + " 重复了 " + str(len(positions)) + " 次，应定义为常量",
                          _sq_severity("MINOR"), line=positions[0])

        # S1656: Variable assigned to itself
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\s*=\s*\1\s*;", line):
                before = line[:m.start()]
                if "==" not in before and "!=" not in before and \
                   not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_SELF_ASSIGNMENT",
                              "S1656: 变量 '" + m.group(1) + "' 赋值给了自身，可能是逻辑错误",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S128: Switch fall-through without comment
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                for idx, case in enumerate(cases):
                    stmts = getattr(case, "statements", []) or []
                    if stmts:
                        last_stmt = stmts[-1]
                        if not isinstance(last_stmt, (javalang_tree.BreakStatement,
                                                       javalang_tree.ReturnStatement,
                                                       javalang_tree.ThrowStatement,
                                                       javalang_tree.ContinueStatement)):
                            if idx + 1 < len(cases) and getattr(cases[idx + 1], "case", None):
                                l = case.position.line if case.position else 0
                                self._add(file_path, "SONAR_FALL_THROUGH",
                                          "S128: switch case 存在穿透（fall-through），应添加 'break' 或注释说明意图",
                                          _sq_severity("MAJOR"), line=l)

        # S1317: StringBuilder variable name
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(StringBuilder|StringBuffer)\s+(sb|builder|stringBuilder|buffer)\b", line):
                pass
            for m in re.finditer(r"(StringBuilder|StringBuffer)\s+(\w+)\b", line):
                name = m.group(2)
                if name not in ("sb", "builder", "stringBuilder", "buffer", "strBuf", "strBuilder"):
                    self._add(file_path, "SONAR_SB_NAMING",
                              "S1317: StringBuilder 变量推荐命名为 'sb' 或 'builder'，当前名为 '" + name + "'",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S1337: Unnecessary unboxing
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\.(intValue|longValue|doubleValue|booleanValue|floatValue)\s*\(\s*\)", line):
                before = line[:m.start()]
                if "(" in before and "int" not in before:
                    self._add(file_path, "SONAR_UNBOXING",
                              "S1337: 不必要的显式拆箱，可直接用于需要基本类型的上下文中",
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S1141: Nested try blocks
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                try_block = getattr(node, "block", None) or []
                body = try_block if isinstance(try_block, list) else \
                       getattr(try_block, "statements", []) or []
                for stmt in body:
                    if isinstance(stmt, javalang_tree.TryStatement):
                        l = stmt.position.line if stmt.position else 0
                        self._add(file_path, "SONAR_NESTED_TRY",
                                  "S1141: 嵌套的 try 块降低了可读性，应提取为独立方法",
                                  _sq_severity("MINOR"), line=l)

        # S1201: equals/hashCode/toString consistency check
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                methods = {}
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.MethodDeclaration):
                        methods[member.name] = len(getattr(member, "parameters", []) or [])
                has_equals = methods.get("equals") == 1
                has_hashcode = methods.get("hashCode") == 0
                has_tostring = methods.get("toString") == 0
                if (has_equals or has_hashcode) and not has_tostring:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EQUALS_TOSTRING",
                              "S1201: 重写了 equals/hashCode 的类应同时重写 toString 方法",
                              _sq_severity("MINOR"), line=l, column=c)

        # S135: Loop with too many break/continue statements
        for path, node in tree:
            if isinstance(node, (javalang_tree.ForStatement, javalang_tree.WhileStatement, javalang_tree.DoStatement)):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                count = sum(1 for s in str(body) for kw in ["break;", "continue;"] if kw in str(s))
                if count > 3:
                    l = node.position.line if node.position else 0
                    self._add(file_path, "SONAR_LOOP_JUMPS",
                              "S135: 循环包含 " + str(count) + " 个跳转语句（break/continue），应重构降低复杂度",
                              _sq_severity("MINOR"), line=l)

        # S1697: Short-circuit logic
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(\w+)\s*!=\s*null\s*\?\s*\1\.(\w+)\s*:\s*null", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_SHORT_CIRCUIT",
                              "S1697: 条件表达式应为短路的 && 或 ||，避免空指针",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S1860: Synchronized on String/Integer
        for path, node in tree:
            if isinstance(node, javalang_tree.SynchronizedStatement):
                lock_obj = str(getattr(node, "lock", "")) or str(getattr(node, "expression", ""))
                for key in ('"', "Integer", "String", "Boolean"):
                    if key in lock_obj:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SYNC_IMMUTABLE",
                                  "S1860: 对 String/Integer 等不可变对象加锁是危险的，因为 JVM 可能重用这些对象",
                                  _sq_severity("MAJOR"), line=l, column=c)
                        break

        # S1220: Serial version UID
        def _get_impl_name(iface):
            name = getattr(iface, "name", "")
            sub = getattr(iface, "sub_type", None)
            if sub:
                sub_name = _get_impl_name(sub)
                if sub_name:
                    return name + "." + sub_name
            return name

        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                ext = getattr(node, "extends", None)
                if ext and hasattr(ext, "name") and \
                   ext.name in ("Exception", "RuntimeException", "Throwable", "Error"):
                    continue
                implements = getattr(node, "implements", []) or []
                is_serializable = False
                for iface in implements:
                    full_name = _get_impl_name(iface)
                    if "Serializable" in full_name:
                        is_serializable = True
                        break
                if not is_serializable:
                    continue
                has_suid = False
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.FieldDeclaration):
                        for decl in member.declarators:
                            if getattr(decl, "name", "") == "serialVersionUID":
                                has_suid = True
                if not has_suid:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_SERIAL_VERSION_UID",
                              "S1220: 实现 Serializable 的类 '" + node.name + "' 应定义 serialVersionUID",
                              _sq_severity("MAJOR"), line=l, column=c)

    # ==================== Design ====================
    def check_design(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_design"):
            return
        lines = content.split("\n")

        # S108: Empty block should be documented or removed (skip catch/finally blocks handled separately)
        for path, node in tree:
            if isinstance(node, javalang_tree.BlockStatement):
                stmts = getattr(node, "statements", []) or []
                if stmts:
                    continue
                # Check if this is a try's catch or finally block (handled elsewhere)
                parent_path = path[-2] if len(path) >= 2 else None
                if parent_path and isinstance(parent_path, (javalang_tree.CatchClause,
                                                             javalang_tree.TryStatement)):
                    continue
                l, c = self._pos(node)
                self._add(file_path, "SONAR_EMPTY_BLOCK",
                          "S108: 空代码块应添加注释说明或移除",
                          _sq_severity("MAJOR"), line=l, column=c)

        # S110: Check inheritance depth (> 6)
        class_parents = {}
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                depth = 0
                ext = getattr(node, "extends", None)
                if ext and hasattr(ext, "name"):
                    parent_name = ext.name
                    p = parent_name
                    while p in class_parents:
                        depth += 1
                        p = class_parents.get(p, "")
                        if not p:
                            break
                    if depth > 6:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_DEEP_INHERITANCE",
                                  "S110: 类继承深度超过 6 层，应减少继承层次或使用组合替代继承",
                                  _sq_severity("MAJOR"), line=l, column=c)

        # S1126: Return of boolean expression
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                for i, stmt in enumerate(body):
                    if isinstance(stmt, javalang_tree.IfStatement):
                        if i + 1 < len(body) and \
                           isinstance(body[i + 1], javalang_tree.ReturnStatement) and \
                           getattr(body[i + 1], "expression", None):
                            ret_expr = str(body[i + 1].expression)
                            cond = getattr(stmt, "condition", None)
                            if cond and ret_expr in ("true", "false", "Boolean.TRUE", "Boolean.FALSE"):
                                l, c = self._pos(stmt)
                                self._add(file_path, "SONAR_RETURN_BOOL",
                                          "S1126: 'if-true-return-true' 可简化为直接 'return condition'",
                                          _sq_severity("MINOR"), line=l, column=c)

        # S1149: Synchronized class (Vector, Hashtable)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\b(Vector|Hashtable|StringBuffer)\b", line):
                if not re.search(r"//.*|import\s", line):
                    self._add(file_path, "SONAR_SYNC_CLASS",
                              "S1149: 使用同步类 '" + m.group(1) + "' 可能引起性能问题，" + {
                                  "Vector": "优先使用 ArrayList",
                                  "Hashtable": "优先使用 HashMap",
                                  "StringBuffer": "单线程用 StringBuilder"
                              }[m.group(1)],
                              _sq_severity("MINOR"), line=i, column=m.start())

        # S1151: Switch case too many lines
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                for case in (getattr(node, "cases", []) or []):
                    stmts = getattr(case, "statements", []) or []
                    if len(stmts) > 20:
                        l = case.position.line if case.position else 0
                        self._add(file_path, "SONAR_LONG_CASE",
                                  "S1151: case 分支包含 " + str(len(stmts)) + " 行语句，应提取为独立方法",
                                  _sq_severity("MINOR"), line=l)

        # S1185: Overriding method does nothing but call super
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                mods = node.modifiers or []
                if "Override" in str(mods):
                    body = node.body if isinstance(node.body, list) else \
                           getattr(getattr(node, "body", None), "statements", []) or []
                    if len(body) == 1:
                        s = str(body[0])
                        if "super." + node.name in s:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_USELESS_OVERRIDE",
                                      "S1185: 重写方法仅调用了 'super." + node.name + "()'，可删除",
                                      _sq_severity("MINOR"), line=l, column=c)

        # S1186: Empty methods
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                if "abstract" in (node.modifiers or []):
                    continue
                body = getattr(node, "body", None)
                is_empty = body is None
                if not is_empty:
                    stmts = body if isinstance(body, list) else \
                            getattr(body, "statements", []) or []
                    is_empty = len(stmts) == 0
                if is_empty:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EMPTY_METHOD",
                              "S1186: 方法 '" + node.name + "' 为空，应添加实现或标记为抽象",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1190: Enum switch should handle all cases
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                expr = getattr(node, "expression", None)
                if expr and hasattr(expr, "qualifier"):
                    cases = getattr(node, "cases", []) or []
                    has_default = any(
                        not getattr(c, "case", None)
                        for c in cases
                    )
                    if not has_default:
                        l = node.position.line if node.position else 0
                        for p2, n2 in tree:
                            if isinstance(n2, javalang_tree.EnumDeclaration) and \
                               hasattr(n2, "body") and n2.body:
                                if str(expr.qualifier) == n2.name:
                                    self._add(file_path, "SONAR_ENUM_SWITCH",
                                              "S1190: 枚举类型的 switch 应包含 default 分支或处理所有枚举常量",
                                              _sq_severity("MAJOR"), line=l)
                                    break

        # S1206: equals/hashCode/toString ordering
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                seen_order = []
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.MethodDeclaration):
                        if member.name in ("equals", "hashCode", "toString"):
                            seen_order.append(member.name)
                if len(seen_order) >= 2:
                    eq_idx = seen_order.index("equals") if "equals" in seen_order else -1
                    hc_idx = seen_order.index("hashCode") if "hashCode" in seen_order else -1
                    if eq_idx >= 0 and hc_idx >= 0 and abs(eq_idx - hc_idx) > 1:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_METHOD_ORDER",
                                  "S1206: equals() 和 hashCode() 方法的定义应相邻，便于代码审查",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S1214: Constants in interfaces
        for path, node in tree:
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                for member in (node.body or []):
                    if isinstance(member, javalang_tree.FieldDeclaration):
                        l, c = self._pos(member.declarators[0] if member.declarators else member)
                        self._add(file_path, "SONAR_INTERFACE_CONSTANT",
                                  "S1214: 接口中不应定义常量，应使用枚举或常量类",
                                  _sq_severity("MINOR"), line=l, column=c)

        # S1448: Too many methods in class (> 20)
        for path, node in tree:
            if isinstance(node, javalang_tree.ClassDeclaration):
                method_count = sum(
                    1 for m in (node.body or [])
                    if isinstance(m, javalang_tree.MethodDeclaration) and
                    m.name != "<init>"
                )
                if method_count > 20:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_TOO_MANY_METHODS",
                              "S1448: 类 '" + node.name + "' 包含 " + str(method_count) + " 个方法（超过 20），应考虑拆分",
                              _sq_severity("MAJOR"), line=l, column=c)

        # S1301: switch with 2 or fewer cases should be if
        for path, node in tree:
            if isinstance(node, javalang_tree.SwitchStatement):
                cases = getattr(node, "cases", []) or []
                case_count = sum(1 for c in cases if getattr(c, "case", None))
                if case_count <= 2:
                    l = node.position.line if node.position else 0
                    self._add(file_path, "SONAR_SWITCH_TO_IF",
                              "S1301: switch 仅有 " + str(case_count) + " 个 case，应使用 if-else 替代",
                              _sq_severity("MINOR"), line=l)

        # S1188: Anonymous class too long
        for path, node in tree:
            if isinstance(node, javalang_tree.Creator):
                body = getattr(node, "body", None)
                if body:
                    stmts = getattr(body, "statements", []) or []
                    if len(stmts) > 20:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_LONG_ANON_CLASS",
                                  "S1188: 匿名内部类超过 20 行，应转换为内部类或 lambda",
                                  _sq_severity("MINOR"), line=l, column=c)

    # ==================== Extended Bugs ====================
    def check_bugs_ext(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_bugs"):
            return
        lines = content.split("\n")

        # S1060: Duplicate string literals already handled in reliability

        # S108: Empty catch block (without comment)
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                for catch in (node.catches or []):
                    block = catch.block if hasattr(catch, "block") and catch.block else \
                            getattr(catch, "body", None)
                    stmts = block.statements if hasattr(block, "statements") else \
                            (block if isinstance(block, list) else [])
                    if len(stmts) == 0:
                        l = catch.position.line if catch.position else 0
                        self._add(file_path, "SONAR_EMPTY_CATCH_EXT",
                                  "S108: 空的 catch 块应包含注释说明为何忽略异常，或记录日志",
                                  _sq_severity("MAJOR"), line=l)
                    elif len(stmts) == 1:
                        s = str(stmts[0])
                        if "//" not in s and "/*" not in s and \
                           not s.strip() and not stmts[0].position:
                            l = catch.position.line if catch.position else 0
                            self._add(file_path, "SONAR_EMPTY_CATCH_EXT",
                                      "S108: catch 块为空或只包含注释，应记录异常",
                                      _sq_severity("MAJOR"), line=l)

        # S1123: @Deprecated without @deprecated Javadoc tag
        for i, line in enumerate(lines, 1):
            if "@Deprecated" in line:
                has_javadoc_tag = False
                for j in range(max(0, i - 6), i):
                    if j < len(lines) and "@deprecated" in lines[j]:
                        has_javadoc_tag = True
                        break
                if not has_javadoc_tag:
                    self._add(file_path, "SONAR_DEPRECATED_DOC",
                              "S1123: '@Deprecated' 注解应配合 Javadoc '@deprecated' 标记说明原因和替代方案",
                              _sq_severity("MAJOR"), line=i)

        # S1166: Exception caught but not logged
        for path, node in tree:
            if isinstance(node, javalang_tree.TryStatement):
                for catch in (node.catches or []):
                    block = catch.block if hasattr(catch, "block") and catch.block else \
                            getattr(catch, "body", None)
                    stmts = block.statements if hasattr(block, "statements") else \
                            (block if isinstance(block, list) else [])
                    body_str = " ".join(str(s) for s in stmts)
                    param = getattr(catch, "parameter", None)
                    param_name = getattr(param, "name", "") if param else ""
                    has_log = any(
                        kw in body_str.lower() for kw in
                        ["logger.", "log.", "log.warn", "log.error", "log.info",
                         "LOGGER.", "LOG.", "log.debug", "log.trace",
                         "System.err.print", "e.print"]
                    )
                    has_rethrow = "throw " + param_name in body_str or \
                                  "throw new " in body_str
                    if not has_log and not has_rethrow:
                        l = catch.position.line if catch.position else 0
                        self._add(file_path, "SONAR_EXCEPTION_LOG",
                                  "S1166: 捕获异常后应记录日志或重新抛出，不应忽略",
                                  _sq_severity("MAJOR"), line=l)

        # S1226: Parameters should not be reassigned
        for path, node in tree:
            if isinstance(node, javalang_tree.MethodDeclaration):
                params = getattr(node, "parameters", []) or []
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                body_str = " ".join(str(s) for s in body)
                for param in params:
                    pname = getattr(param, "name", "")
                    if pname:
                        pat = re.compile(r"\b" + re.escape(pname) + r"\s*=")
                        if pat.search(body_str):
                            l, c = self._pos(param)
                            self._add(file_path, "SONAR_PARAM_ASSIGN",
                                      "S1226: 方法参数 '" + pname + "' 被重新赋值，应使用局部变量",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2757: Assignment in condition (= instead of ==)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\bif\s*\(\s*\w+\s*=\s*\w+", line):
                self._add(file_path, "SONAR_ASSIGN_IN_COND",
                          "S2757: 条件表达式中使用了 '='（赋值），应为 '=='（比较）",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S2589: Boolean expression not updated (always true/false)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\bif\s*\(\s*(true|false)\s*\)", line):
                self._add(file_path, "SONAR_ALWAYS_BOOL",
                          "S2589: 条件 '" + m.group(1) + "' 是常量，表达式永远不会改变，应移除或修正",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S2772: SerialVersionUID should be private static final long
        for path, node in tree:
            if isinstance(node, javalang_tree.FieldDeclaration):
                for decl in node.declarators:
                    if decl.name == "serialVersionUID":
                        mods = node.modifiers or []
                        if "private" not in mods or "static" not in mods or "final" not in mods:
                            l, c = self._pos(decl)
                            self._add(file_path, "SONAR_SERIAL_VERSION",
                                      "S2772: 'serialVersionUID' 必须声明为 'private static final long'",
                                      _sq_severity("MAJOR"), line=l, column=c)

        # S2761: Double prefix increment
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(!\s*!)+\s*\w+", line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_DOUBLE_NOT",
                              "S2761: 双重复合取反运算符 '!!' 可简化为直接使用表达式",
                              _sq_severity("MAJOR"), line=i, column=m.start())

        # S2925: Thread.sleep should not be used in tests
        for i, line in enumerate(lines, 1):
            if re.search(r"Thread\.sleep\s*\(", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "SONAR_THREAD_SLEEP",
                          "S2925: 'Thread.sleep()' 不应用于测试或生产代码，考虑使用 awaitility 或定时器",
                          _sq_severity("MAJOR"), line=i)

    # ==================== Extended Security ====================
    def check_security_ext(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_security"):
            return
        lines = content.split("\n")

        # S1313: Hardcoded IP addresses
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*"', line):
                ip = m.group(1)
                if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "localhost") and \
                   not ip.startswith("192.168.") and not ip.startswith("10.") and \
                   not ip.startswith("172.16."):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_HARDCODED_IP",
                                  "S1313: 硬编码的 IP 地址 '" + ip + "'，应从配置文件中获取",
                                  _sq_severity("CRITICAL"), line=i, column=m.start())

        # S2068: Hardcoded credentials (password-like variable names)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(password|passwd|secret|apiKey|api_key|accessKey|' +
                                 r'access_key|secretKey|secret_key|authToken|auth_token)\s*=\s*"[^"]{4,}"',
                                 line, re.IGNORECASE):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_HARDCODED_CREDENTIAL",
                              "S2068: 硬编码的凭证信息，应存储在安全的凭证管理服务中",
                              _sq_severity("BLOCKER"), line=i, column=m.start())

        # S2077: SQL injection in PreparedStatement
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(?:PreparedStatement|Statement|Connection)\.\s*(?:prepare|execute|create)",
                                 line):
                if re.search(r"\w+\s*\+\s*\w+", line) and \
                   not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_PREP_STMT_INJECTION",
                              "S2077: PreparedStatement 中拼接 SQL 参数仍存在注入风险，应使用 '?' 占位符",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S2076: Command injection via ProcessBuilder (already in base)

        # S2229: LDAP anonymous bind
        for i, line in enumerate(lines, 1):
            if re.search(r"InitialDirContext|InitialLdapContext|LdapContext", line):
                if "simple" not in line and \
                   not re.search(r"Context\.SECURITY_AUTHENTICATION", line):
                    self._add(file_path, "SONAR_LDAP_ANONYMOUS",
                              "S2229: LDAP 匿名绑定存在安全风险，应配置认证信息",
                              _sq_severity("CRITICAL"), line=i)

        # S2583: Conditionally executed blocks (dead code)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"\bif\s*\(\s*(false|null)\s*\)", line):
                self._add(file_path, "SONAR_DEAD_CODE",
                          "S2583: 条件始终为 false 的代码块不可达，应移除死代码",
                          _sq_severity("MAJOR"), line=i, column=m.start())

        # S2638: Spring/Hibernate injection
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'@Value\s*\(\s*"#\{|@Value\s*\(\s*"\$\{[^}]*\}"\s*\)', line):
                if re.search(r"\$\{[^}]*:[^}]*\}", line):
                    pass
                else:
                    continue

        # S2647: Basic authentication
        for i, line in enumerate(lines, 1):
            if re.search(r"Authenticator|Base64\.getEncoder|Base64\.getMimeEncoder", line) and \
               re.search(r"password|passwd|credential|token", line.lower()):
                self._add(file_path, "SONAR_BASIC_AUTH",
                          "S2647: 基础认证信息应使用安全的传输方式（HTTPS），避免明文传输",
                          _sq_severity("CRITICAL"), line=i)

        # S3330: Cookie without HttpOnly
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"Cookie\s+\w+\s*=\s*new\s+Cookie", line):
                for j in range(i, min(i + 5, len(lines))):
                    if "setHttpOnly" in lines[j] and "true" in lines[j]:
                        break
                else:
                    self._add(file_path, "SONAR_COOKIE_HTTPONLY",
                              "S3330: Cookie 应设置 HttpOnly 属性以防止 XSS 攻击窃取 Cookie",
                              _sq_severity("CRITICAL"), line=i)

        # S3649: SQL injection in JPA
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"(?:@Query|@NamedQuery|entityManager\.createQuery|"
                                 r"entityManager\.createNativeQuery)\s*\(", line):
                if re.search(r"\w+\s*\+\s*\"", line) or \
                   re.search(r"\w+\s*\+\s*\w+", line):
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_JPA_INJECTION",
                                  "S3649: JPA 查询中拼接用户输入可能造成 JPQL/SQL 注入",
                                  _sq_severity("BLOCKER"), line=i, column=m.start())

        # S4784: ReDoS via regex injection (already in base)

        # S5160: Insecure Random (use of java.util.Random)
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+(java\.util\.)?Random\s*\(\s*\)", line) and \
               not re.search(r"SecureRandom|ThreadLocalRandom", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "SONAR_INSECURE_RANDOM",
                          "S5160: 'java.util.Random' 在安全敏感场景不可预测，应使用 'java.security.SecureRandom'",
                          _sq_severity("CRITICAL"), line=i)

        # S5341: MAC (Message Authentication Code) should not be predictable
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'Mac\.getInstance\s*\(\s*"(HmacMD5|HmacSHA1)"', line):
                if not re.search(r"//.*", line):
                    self._add(file_path, "SONAR_WEAK_MAC",
                              "S5341: 弱 MAC 算法 '" + m.group(1) + "' 应使用 HmacSHA256 或更强算法",
                              _sq_severity("CRITICAL"), line=i, column=m.start())

        # S5542: XML processing (XXE prevention)
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r'(DocumentBuilder|SAXParser|SAXReader|XMLReader)\.(newInstance|parse|read)\b',
                                 line):
                for j in range(i, min(i + 5, len(lines))):
                    if j < len(lines) and \
                       ("setFeature" in lines[j] and
                        "http://apache.org/xml/features/disallow-doctype-decl" in lines[j]):
                        break
                else:
                    if not re.search(r"//.*", line):
                        self._add(file_path, "SONAR_XXE_EXT",
                                  "S5542: XML 解析器应正确配置以禁用外部实体注入（XXE）",
                                  _sq_severity("BLOCKER"), line=i)
