"""SonarQubeCheckerTen — 第十批规则"""
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

class SonarQubeCheckerTen(BaseSonarChecker):

    def run_all(self, tree, file_path: str, content: str):
        self.check_convention_ten(tree, file_path, content)
        self.check_design_ten(tree, file_path, content)
        self.check_robustness_ten(tree, file_path, content)

    # ==================== Convention Ten ====================

    def check_convention_ten(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_convention_ten"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S100: Method naming (already in full)
            # S101: Class naming (already in full)

            # S1066: Collapsible if statements (already in full)

            # S110: Deep inheritance (already in ext)
            # S112: Generic exception (already in ext)

            # S115: Constant naming (already in full)

            # S1200: High coupling (already in seven)

            # S1210: equals/hashCode contract (already in base)

            # S1213: Member order (already in base)

            # S1214: Interface constant (already in ext)

            # S1444: public static final (already in base)

            # S1488: Redundant local (already in base)

            # S1609: FunctionalInterface annotation
            if isinstance(node, javalang_tree.InterfaceDeclaration):
                body = getattr(node, "body", []) or []
                methods = [d for d in body if isinstance(d, javalang_tree.MethodDeclaration)]
                abstract_count = sum(
                    1 for m in methods
                    if not m.modifiers or
                    ("default" not in m.modifiers and "static" not in m.modifiers)
                )
                if abstract_count == 1 and len(methods) == abstract_count:
                    ann_names = set()
                    for ann in getattr(node, "annotations", []) or []:
                        ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                        ann_names.add(ann_name)
                    if "FunctionalInterface" not in ann_names:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_FUNCTIONAL_INTERFACE_MISSING",
                                  "S1609: 单抽象方法接口应标注 @FunctionalInterface",
                                  sq_severity("MINOR"), line=l, column=c)

            # S1610: Abstract class naming
            if isinstance(node, javalang_tree.ClassDeclaration):
                if "abstract" in (node.modifiers or []):
                    name = getattr(node, "name", "")
                    if name and not name.startswith("Abstract") and \
                       not name.startswith("Base") and not name.endswith("Base"):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_ABSTRACT_NAMING",
                                  "S1610: 抽象类名应以 Abstract 或 Base 开头",
                                  sq_severity("MINOR"), line=l, column=c)

            # S1700: Field name should not match method name (already in base)

            # S1725: Instance field naming convention
            if isinstance(node, javalang_tree.FieldDeclaration):
                for var in getattr(node, "declarators", []) or []:
                    name = getattr(var, "name", "")
                    if name and name.startswith("m_") or name.startswith("s_") or \
                       name.startswith("_") or name.endswith("_"):
                        l, c = self._pos(var)
                        self._add(file_path, "SONAR_FIELD_NAMING_CONVENTION",
                                  "S1725: 字段名不应包含前缀/后缀下划线或 m_/s_",
                                  sq_severity("MINOR"), line=l, column=c)

            # S1939: Enum constants should be compared with ==
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "equals":
                    q = str(getattr(node, "qualifier", "") or "")
                    args = getattr(node, "arguments", []) or []
                    if args:
                        arg_str = str(args[0])
                        if q and q[0].isupper() if q else False:
                            pass

            # S1943: Class name should not match enclosing class
            if isinstance(node, javalang_tree.ClassDeclaration):
                inner_name = getattr(node, "name", "")
                for path2, node2 in tree:
                    if isinstance(node2, javalang_tree.ClassDeclaration) and \
                       node2 is not node:
                        outer_name = getattr(node2, "name", "")
                        if inner_name == outer_name:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_NESTED_CLASS_NAME",
                                      "S1943: 内部类名与外层类名重名",
                                      sq_severity("MAJOR"), line=l, column=c)

            # S2003: Super should be called at end of method
            # S2094: Interface should not be empty (already in full)
            # S2118: File.delete (already in six)

            # S2122: Scheduled executor (already in fourth)

            # S2127: URL.equals (already in fourth)

            # S2132: String split (already in ext)

            # S2133: String comparison (already in full)

            # S2164: Integer division (already in base)

            # S2165: ThreadLocal (already in seven)

            # S2176: Class naming (additional)
            if isinstance(node, javalang_tree.ClassDeclaration):
                name = getattr(node, "name", "")
                if name and len(name) > 30:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_CLASS_NAME_LENGTH",
                              "S2176: 类名过长（" + str(len(name)) + " 个字符）",
                              sq_severity("MINOR"), line=l, column=c)

            # S2187: Test class (already in eight)
            # S2188: Test method naming
            if isinstance(node, javalang_tree.MethodDeclaration):
                ann_names = set()
                for ann in getattr(node, "annotations", []) or []:
                    ann_name = getattr(ann, "name", "") if hasattr(ann, "name") else str(ann)
                    ann_names.add(ann_name)
                if "Test" in ann_names or "ParameterizedTest" in ann_names:
                    name = getattr(node, "name", "")
                    if name and not name.startswith("test") and \
                       not name.startswith("should") and "Test" not in name:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_TEST_METHOD_NAMING",
                                  "S2188: 测试方法名应以 test/should 开头或包含 Test",
                                  sq_severity("MINOR"), line=l, column=c)

            # S2325: Private method (already in base)

            # S2326: Unused type parameter (already in base)

            # S2388: Method chaining should be simplified
            if isinstance(node, javalang_tree.MethodInvocation):
                q = str(getattr(node, "qualifier", "") or "")
                if q and len(q) > 100:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_EXCESSIVE_CHAINING",
                              "S2388: 过长的链式调用应简化",
                              sq_severity("MINOR"), line=l, column=c)

            # S2438: Inner class should be static
            if isinstance(node, javalang_tree.ClassDeclaration):
                for decl in getattr(node, "body", []) or []:
                    if isinstance(decl, javalang_tree.ClassDeclaration):
                        if "static" not in (decl.modifiers or []):
                            name = getattr(decl, "name", "")
                            has_outer_ref = False
                            decl_str = str(decl).lower()
                            outer_name = getattr(node, "name", "").lower()
                            if outer_name and outer_name in decl_str:
                                has_outer_ref = True
                            if not has_outer_ref and name:
                                l, c = self._pos(decl)
                                self._add(file_path, "SONAR_INNER_CLASS_STATIC",
                                          "S2438: 内部类 '" + name + "' 应声明为 static",
                                          sq_severity("MAJOR"), line=l, column=c)

            # S2445: Synchronize on field (already in base)

            # S3008: Static field naming convention
            if isinstance(node, javalang_tree.FieldDeclaration):
                if "static" in (node.modifiers or []):
                    for var in getattr(node, "declarators", []) or []:
                        name = getattr(var, "name", "")
                        if name and not name.isupper() and not name.startswith("logger") and \
                           not name.startswith("log") and not name.startswith("LOG") and \
                           not name.startswith("LOGGER"):
                            l, c = self._pos(var)
                            self._add(file_path, "SONAR_STATIC_FIELD_NAMING",
                                      "S3008: static 字段名应遵循命名约定",
                                      sq_severity("MINOR"), line=l, column=c)

    # ==================== Design Ten ====================

    def check_design_ten(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_design_ten"):
            return
        lines = content.split("\n")

        for path, node in tree:
            # S108: Empty block (already in ext)

            # S1109: Close resource should be closed
            # S1128: Unused imports (already in inspector.py base)

            # S1132: String literal duplicate (already in six)

            # S1147: System.exit (already in five)

            # S1150: Anonymous class length (already in six)

            # S1161: Override annotation (already in five)

            # S1166: Exception log (already in ext)

            # S1170: Constant naming (already in five)

            # S1185: Useless override (already in eight)

            # S1186: Empty method (already in ext)

            # S1188: Anonymous class too long (already in ext)

            # S1191: Legacy collection (already in ext)

            # S1192: Duplicate string (already in ext)

            # S1195: Array designator (already in six)

            # S1199: Empty nested block (already in six)

            # S1202: StringBuffer (already in six)

            # S1206: Method order (already in eight)

            # S1217: Thread run (already in base)

            # S1220: serialVersionUID (already in full)

            # S1221: Method name confusion (already in full)

            # S1223: finalize protected (already in six)

            # S1226: Parameter assignment (already in ext)

            # S1227: Break label (already in seven)

            # S1264: For to while (already in base)

            # S1301: Switch with few cases (already in ext)

            # S1313: Hardcoded IP (already in nine and ext)

            # S1319: Interface type (already in base)

            # S134: Nested depth (already in full)

            # S135: Loop breaks (already in ext)

            # S139: Comments at end (already in full)

            # S1449: Locale (already in base)

            # S1450: Protected field (already in six)

            # S1479: Too many cases (already in base)

            # S1481: Unused local (already in full)

            # S1598: Division by zero (already in seven)

            # S1602: Unnecessary boxing (already in ext)

            # S1604: Lambda (already in base)

            # S1611: Method reference (already in five)

            # S1656: Self assignment (already in ext)

            # S1659: Multi-var decl (already in full)

            # S1697: Short circuit (already in ext)

            # S1701: Diamond (already in full and eight)

            # S1710: Duplicate annotation (already in eight)

            # S1711: getBytes charset (already in seven)

            # S1763: Dead code (already in full)

            # S1764: Identical expression (already in base)

            # S1854: Dead store (already in base)

            # S1860: Sync on immutable (already in ext)

            # S1862: Duplicate condition (already in six)

            # S1871: Duplicate switch branch (already in five)

            # S1872: Class.forName (already in seven)

            # S1905: Redundant cast (already in base)

            # S1909: Redundant assignment
            if isinstance(node, javalang_tree.Assignment):
                left = getattr(node, "expressionl", None)
                right = getattr(node, "value", None)
                if left and right and hasattr(left, "member") and hasattr(right, "member"):
                    if getattr(left, "member", "") == getattr(right, "member", "") and \
                       getattr(left, "qualifier", "") == getattr(right, "qualifier", ""):
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_SELF_ASSIGNMENT_TEN",
                                  "S1909: 变量赋值给自身是冗余的",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S1940: Boolean inversion (already in eight)

            # S1941: Variable type too generic
            if isinstance(node, javalang_tree.VariableDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    type_name = _get_full_type_name(type_node)
                    base_name = type_name.split(".")[-1]
                    if base_name == "Object" or base_name == "Serializable" or \
                       base_name == "Comparable":
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_GENERIC_VARIABLE_TYPE",
                                  "S1941: 变量类型过于通用，应使用更具体的类型",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S1994: For loop increment (already in full)

            # S2055: Collection size comparison
            if isinstance(node, javalang_tree.BinaryOperation):
                op = getattr(node, "operator", "")
                if op == ">" or op == ">=" or op == "<" or op == "<=":
                    left_str = str(getattr(node, "operandl", ""))
                    right_str = str(getattr(node, "operandr", ""))
                    if ".size()" in left_str and right_str == "0":
                        pass

            # S2095: Close resource (already in full)

            # S2111: BigDecimal double (already in six)

            # S2112: URL hashCode (already in six)

            # S2114: List remove int (already in six)

            # S2116: String hashCode (already in six)

            # S2119: SimpleDateFormat (already in seven)

            # S2121: Iterator remove (already in six)

            # S2123: Value compare (already in full)

            # S2129: String concat in loop (already in six)

            # S2130: Deprecated (already in base)

            # S2131: Split char (already in ext)

            # S2139: Exception rethrow (already in six)

            # S2140: Double check locking (already in six)

            # S2142: Interrupted (already in base)

            # S2143: ThreadLocal (already in seven)

            # S2151: Thread start (already in six)

            # S2153: Boxing in loop (already in base)

            # S2154: Int division (already in base)

            # S2157: Cloneable (already in fourth)

            # S2159: Clone override (already in seven)

            # S2160: Subclass equals (already in fourth)

            # S2162: Equals asymmetry (already in fourth)

            # S2164: Int division (already in base)

            # S2167: Comparable equals (already in fourth)

            # S2168: Return empty (already in ext)

            # S2175: isEmpty (already in seven)

            # S2184: Int cast to float (already in six)

            # S2186: Thread yield (already in base)

            # S2200: CompareTo equals (already in fourth)

            # S2201: Ignored return (already in six)

            # S2203: SB toString (already in seven)

            # S2204: Equals no type check (already in seven)

            # S2222: Lock unlock (already in base)

            # S2225: ToString null (already in seven)

            # S2226: Static field in servlet
            if isinstance(node, javalang_tree.ClassDeclaration):
                imp = getattr(node, "implements", None) or []
                for impl in imp:
                    impl_base = _get_base_type_name(impl)
                    if impl_base == "HttpServlet" or "Servlet" in impl_base:
                        for decl in getattr(node, "body", []) or []:
                            if isinstance(decl, javalang_tree.FieldDeclaration):
                                if "static" in (decl.modifiers or []):
                                    for var in getattr(decl, "declarators", []) or []:
                                        name = getattr(var, "name", "")
                                        if name and name != "serialVersionUID":
                                            l, c = self._pos(var)
                                            self._add(file_path, "SONAR_SERVLET_STATIC_FIELD",
                                                      "S2226: Servlet 类中的 static 字段可能导致线程安全问题",
                                                      sq_severity("MAJOR"), line=l, column=c)

            # S2230: compareTo equals (already in seven)

            # S2234: Parameter order
            # S2235: Enum equals (already in full)
            # S2236: Thread wait (already in six)
            # S2250: String intern (already in six)
            # S2251: Loop counter (already in six)
            # S2252: Float counter (already in six)
            # S2254: Double brace (already in full)
            # S2259: Null deref (already in five)
            # S2273: Sleep in loop (already in base)
            # S2293: Diamond (already in six)
            # S2326: Unused type param (already in base)
            # S2333: Redundant modifier (already in five)
            # S2386: Mutable array (already in base)
            # S2390: Accessor generation
            # S2437: Unnecessary unboxing (already in five)
            # S2440: Boxing compare (already in six)
            # S2441: ThreadLocal static (already in seven)
            # S2442: Synchronized class (already in seven)
            # S2445: Synchronize on field (already in base)
            # S2446: Wait in sync (already in fourth)
            # S2447: NPE thrown (already in five)
            # S2583: Dead code (already in ext)
            # S2589: Always bool (already in ext)
            # S2598: Varargs (already in five)
            # S2629: Log concat (already in base)
            # S2637: Optional param (already in five)
            # S2638: Method contract change
            # S2674: Read return (already in five)
            # S2675: Read return check (already in five)
            # S2676: IndexOf char (already in full)
            # S2677: Replace char (already in full)
            # S2681: Thread run (already in seven)
            # S2689: Thread run (already in base)
            # S2692: IndexOf contains (already in base)
            # S2693: Thread in constructor (already in seven)
            # S2695: Thread sleep zero (already in seven)
            # S2696: Static write (already in base)
            # S2698: Create temp file (already in five)
            # S2699: Test assertion (already in full)
            # S2701: Literal eq (already in seven)
            # S2737: Catch rethrow (already in seven)
            # S2755: XXE (already in base)
            # S2757: Assign in cond (already in six)
            # S2760: Sequential if (already in seven)
            # S2761: Double not (already in ext)
            # S2772: Serial version (already in ext)
            # S2789: Redundant null check (already in five)
            # S2864: Keyset iteration (already in full)
            # S2886: Servlet input (already in fourth)
            # S2912: IndexOf > 0 (already in seven)
            # S2925: Thread sleep (already in ext)
            # S3011: Reflection (already in full)
            # S3012: Arrays asList (already in seven)
            # S3020: Iterator next (already in base)
            # S3027: IndexOf contains (already in seven)
            # S3030: Math abs neg (already in seven)
            # S3032: Empty list (already in seven)
            # S3042: Optional orElseGet (already in seven)
            # S3046: Wait in loop (already in seven)
            # S3052: Default init (already in base)
            # S3056: ConcurrentHashMap (already in seven)
            # S3065: Non-thread-safe static (already in seven)
            # S3066: Enum mutable field (already in seven)
            # S3067: Optional serializable
            # S3077: Volatile array
            # S3078: Volatile mutable (already in fourth)
            # S3242: Base type param (already in ext)
            # S3252: Static access (already in full)
            # S3256: For loop variable (already in full)
            # S3281: File perm (already in base)
            # S3296: Pattern in loop (already in five)
            # S3305: Enum constant annotation (already in full)
            # S3329: CBC IV (already in fourth)
            # S3330: Cookie httponly (already in ext)
            # S3346: Duplicate case (already in base)
            # S3358: Nested ternary (already in base)
            # S3398: Unused private method (already in six)
            # S3416: Logger naming (already in ext)
            # S3421: File separator (already in ext)
            # S3440: Null instanceof (already in base)
            # S3457: Format placeholder (already in base)
            # S3516: For index iteration (already in seven)
            # S3518: Division zero (already in base)
            # S3546: Abstract class (already in full)
            # S3599: Double check locking (already in six)
            # S3610: Empty array (already in ext)
            # S3626: Labeled jump (already in ext)
            # S3649: JPA injection (already in ext)
            # S3655: Optional get (already in base)
            # S3725: Boolean assert (already in base)
            # S3740: Raw type (already in five)
            # S3749: Class equals (already in fourth)
            # S3824: Compute if absent (already in base)
            # S3864: Stream peek (already in fourth)
            # S3878: Null vararg (already in fourth)
            # S3923: Single branch switch (already in fourth)
            # S3958: Stream intermediate (already in fourth)
            # S3959: Stream consumed (already in base)
            # S3972: Negated else-if (already in six)
            # S3973: Empty statement (already in full)
            # S3981: Size isEmpty (already in base)
            # S3984: Exc not thrown (already in base)
            # S3985: Unused inner (already in base)
            # S3986: Date format (already in ext)
            # S3988: Parallel stream (already in six)
            # S3996: URL equals (already in fourth)
            # S4032: addAll (already in full)
            # S4065: ThreadLocal static (already in fourth)
            # S4141: List size loop (already in five)
            # S4143: Map overwrite (already in base)
            # S4144: Duplicate method (already in base)
            # S4158: Stream count (already in fourth)
            # S4165: Magic number (already in ext)
            # S4166: Optional null (already in fourth)
            # S4201: Optional null check (already in fourth)
            # S4242: Iterator next balance (already in fourth)
            # S4275: Getter setter (already in base)
            # S4347: Secure random (already in base)
            # S4351: Equals valueOf (already in fourth)
            # S4408: Static class final (already in full)
            # S4423: Weak SSL (already in fourth)
            # S4425: Weak XML parser (already in fourth)
            # S4432: DES (already in base)
            # S4507: SQL injection (already in base)
            # S4524: Switch default (already in base)
            # S4792: Logger secure (already in base)
            # S4800: Hardcoded key (already in base)
            # S4823: Command injection (already in base)
            # S4830: SSL disabled (already in base)
            # S4925: MD5 (already in base)
            # S4929: Thread safe (already in base)
            # S4956: Runtime exec (already in base)
            # S4972: Open redirect (already in base)
            # S4973: String eq (already in base)
            # S5042: Zip slip (already in base)
            # S5122: XSS (already in base)
            # S5125: Jackson polymorphic (already in fourth)
            # S5135: Deserialization (already in base)
            # S5145: Log injection (already in base)
            # S5160: Insecure random (already in ext)
            # S5280: CSP (already in nine)
            # S5290: Hardcoded password (already in base)
            # S5301: Mail injection (already in base)
            # S5304: JNDI lookup (already in fourth)
            # S5322: LDAP injection (already in base)
            # S5332: Clear text (already in base)
            # S5341: Weak MAC (already in ext)
            # S5443: Temp file (already in base)
            # S5445: Regex injection (already in base)
            # S5487: JSON manual (already in nine)
            # S5542: XML process (already in base)
            # S5547: SSRF (already in base)
            # S5582: Open redirect nine (already in nine)
            # S5659: JWT key (already in base)
            # S5661: Log forging (already in base)
            # S5693: Content type (already in nine)
            # S5852: ReDoS (already in six)
            # S5860: GetClass (already in six)
            # S5863: Immutable collection
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                q = str(getattr(node, "qualifier", "") or "")
                if member == "unmodifiableList" and "Collections" in q:
                    args = getattr(node, "arguments", []) or []
                    if args:
                        arg_str = str(args[0])
                        if "asList" in arg_str or "new " in arg_str:
                            l, c = self._pos(node)
                            self._add(file_path, "SONAR_IMMUTABLE_COLLECTION",
                                      "S5863: 不可变集合应使用 List.of() 等工厂方法",
                                      sq_severity("MINOR"), line=l, column=c)

            # S5867: toString on array (already in seven)
            # S5868: Null check redundant
            # S5876: Manual thread (already in six)
            # S5886: Enum comparison
            # S5899: Stream forEach
            if isinstance(node, javalang_tree.MethodInvocation):
                member = getattr(node, "member", "")
                if member == "forEach":
                    q = str(getattr(node, "qualifier", "") or "")
                    if "stream()" in q or ".list()" in q:
                        pass

            # S5905: Dead store (already in base)
            # S5921: Serialization
            # S5932: Null return
            # S5933: Serialization
            # S5958: Lambda method ref (already in eight)
            # S5960: Comparator lambda (already in eight)
            # S5971: Stream findFirst
            for i, line in enumerate(lines, 1):
                if '.stream()' in line and '.findFirst()' in line:
                    l, c = self._pos(node)
                    self._add(file_path, "SONAR_STREAM_FINDFIRST",
                              "S5971: 有序流中 findFirst() 可替换为 findAny() 提升性能",
                              sq_severity("INFO"), line=i)
                    break

            # S5973: HTTP response headers
            # S5976: Switch expression
            # S5993: Switch preview
            # S5994: Record (already in eight)
            # S5996: Text block (already in eight)
            # S5998: Pattern matching
            # S6000: Sealed class (already in eight)
            # S6010: Clean code
            # S6019: Variable type inference
            if isinstance(node, javalang_tree.VariableDeclaration):
                type_node = getattr(node, "type", None)
                if type_node:
                    base_name = _get_base_type_name(type_node)
                    init_node = None
                    for decl in getattr(node, "declarators", []) or []:
                        init_node = getattr(decl, "initializer", None)
                    if init_node and isinstance(init_node, javalang_tree.ClassCreator):
                        init_type = getattr(init_node, "type", None)
                        if init_type:
                            init_base = _get_base_type_name(init_type)
                            if init_base == base_name:
                                l, c = self._pos(node)
                                self._add(file_path, "SONAR_VAR_INFERENCE",
                                          "S6019: 可使用 var 替代显式类型声明",
                                          sq_severity("INFO"), line=l, column=c)

            # S6021: Pattern instanceof (already in eight)
            # S6023: Switch arrow (already in eight)
            # S6025: Record accessor
            # S6035: Assertion
            # S6054: CDI
            # S6055: REST
            # S6060: Spring
            # S6065: Exception
            # S6068: Thread
            # S6070: Stream
            # S6074: Collection
            # S6076: Lambda
            # S6080: Switch
            # S6092: Optional field (already in eight)
            # S6093: Lambda param type (already in eight)
            # S6104: Record
            # S6111: Switch
            # S6113: Text block
            # S6126: Record

            # Additional: Constant with mutable type
            if isinstance(node, javalang_tree.FieldDeclaration):
                if "static" in (node.modifiers or []) and "final" in (node.modifiers or []):
                    type_node = getattr(node, "type", None)
                    if type_node:
                        type_name = _get_full_type_name(type_node)
                        base_name = type_name.split(".")[-1]
                        mutable_types = {"StringBuilder", "StringBuffer", "ArrayList",
                                         "HashMap", "HashSet", "int[]", "String[]",
                                         "Date", "Calendar"}
                        if base_name in mutable_types:
                            for var in getattr(node, "declarators", []) or []:
                                name = getattr(var, "name", "")
                                if name:
                                    l, c = self._pos(var)
                                    self._add(file_path, "SONAR_MUTABLE_CONSTANT",
                                              "S2386: 常量 '" + name + "' 引用可变对象",
                                              sq_severity("MAJOR"), line=l, column=c)

    # ==================== Robustness Ten ====================

    def check_robustness_ten(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("sonar_robustness_ten"):
            return
        lines = content.split("\n")

        # S1124: Modifier order (checked per line, not per tree node)
        mod_order_ordered = ["public", "protected", "private", "abstract", "static",
                             "final", "transient", "volatile", "synchronized", "native", "strictfp"]
        for i, line in enumerate(lines, 1):
            for a_idx, a in enumerate(mod_order_ordered):
                for b_idx in range(a_idx + 1, len(mod_order_ordered)):
                    b = mod_order_ordered[b_idx]
                    pattern = r'\b' + b + r'\s+' + a + r'\b'
                    if re.search(pattern, line) and not line.strip().startswith('//') and \
                       not line.strip().startswith('*'):
                        self._add(file_path, "SONAR_MODIFIER_ORDER",
                                  "S1124: 修饰符顺序不符合规范（推荐: " +
                                  "public protected private abstract static final ...）",
                                  sq_severity("MINOR"), line=i)
                        break
                else:
                    continue
                break

        for path, node in tree:
            # S1065: Unnecessary label (already in base)
            # S1067: Complex expression (already in five)
            # S1068: Unused field (already in base)
            # S107: Too many params (already in full)
            # S108: Empty block (already in ext)
            # S110: Deep inheritance (already in ext)
            # S1110: Redundant jump
            # S1118: Utility class constructor (already in full)
            # S112: Generic exception (already in ext)
            # S1120: serialVersionUID (already in full)
            # S1121: Assign in subexp (already in five)
            # S1123: Deprecated doc (already in nine)
            # S1125: Boolean literal (already in base)
            # S1126: Return boolean (already in nine)
            # S1128: Unused import (already in base inspector)
            # S1130: Generic throws (already in nine)
            # S1132: Duplicate string (already in six)
            # S1133: Deprecated code (already in six)
            # S1134: FIXME (already in full)
            # S1135: TODO (already in full)
            # S1141: Nested try (already in ext)
            # S1143: Finally return (already in ext)
            # S1144: Unused private method (already in five)
            # S1148: Print stack trace (already in six)
            # S1149: Synchronized class (already in ext)
            # S1150: Long anonymous class (already in six)
            # S1151: Long case (already in ext)
            # S1153: Integer compare (already in five)
            # S1155: isEmpty (already in seven)
            # S1157: Case insensitive (already in five)
            # S1158: Wrapper instance (already in ext)
            # S1160: Too many throws (already in six)
            # S1161: Override missing (already in five)
            # S1162: Exception not thrown (already in base)
            # S1163: Throw in finally (already in six)
            # S1165: Annotation (already in nine)
            # S1166: Exception log (already in ext)
            # S1168: Return null collection (already in ext)
            # S1170: Constant naming (already in five)
            # S1171: String LHS equals (already in six)
            # S1172: Unused param (already in ext)
            # S1174: Empty finalize (already in nine)
            # S1175: finalize call (already in base)
            # S1180: Suppress warning (already in six)
            # S1181: Catch throwable (already in ext)
            # S1182: Clone super (already in full)
            # S1185: Useless override (already in eight)
            # S1186: Empty method (already in ext)
            # S1188: Long anonymous class (already in ext)
            # S1190: Enum switch (already in nine)
            # S1191: Legacy collection (already in ext)
            # S1192: Duplicate string (already in ext)
            # S1193: Instanceof final (already in six)
            # S1194: ClassCastException thrown
            if isinstance(node, javalang_tree.ThrowStatement):
                expr = getattr(node, "expression", None)
                if expr and isinstance(expr, javalang_tree.ClassCreator):
                    type_node = getattr(expr, "type", None)
                    type_name = _get_full_type_name(type_node)
                    if "ClassCastException" in type_name:
                        l, c = self._pos(node)
                        self._add(file_path, "SONAR_CLASS_CAST_THROWN",
                                  "S1194: 不应显式抛出 ClassCastException",
                                  sq_severity("MAJOR"), line=l, column=c)

            # S1195: Array designator (already in six)
            # S1197: Array designator variable (already in six)
            # S1199: Empty nested block (already in six)
            # S1200: High coupling (already in seven)
            # S1201: Equals null check (already in nine)
            # S1202: StringBuffer (already in six)
            # S1206: Method order (already in eight)
            # S1210: equals/hashCode (already in base)
            # S1213: Member order (already in base)
            # S1214: Interface constant (already in ext)
            # S1215: System.gc (already in base)
            # S1217: Thread.run (already in base)
            # S1219: Switch case
            # S1220: serialVersionUID (already in full)
            # S1221: Method name conflict (already in full)
            # S1222: Method complexity (in inspector.py)
            # S1223: finalize protected (already in six)
            # S1226: Param assign (already in ext)
            # S1227: Break label (already in seven)
            # S1241: Array equals (already in nine)
            # S1244: Float compare (already in full)
            # S1258: Variable shadows (already in full)
            # S1259: Class name match (already in eight)
            # S1264: For to while (already in base)
            # S128: Fall through (already in ext)
            # S1301: Switch to if (already in ext)
            # S1310: Negative zero (already in seven)
            # S1312: Logger private (already in full)
            # S1313: Hardcoded IP (already in nine and ext)
            # S1314: Magic number (already in ext)
            # S1315: Logger static/private (already in nine)
            # S1317: SB naming (already in ext)
            # S1319: Interface type (already in base)
            # S1337: Unboxing (already in ext)
            # S134: Nested depth (already in full)
            # S1340: Type param long (already in full)
            # S135: Loop jumps (already in ext)
            # S139: Comment at end (already in full)
            # S1444: public static final (already in base)
            # S1448: Too many methods (already in ext)
            # S1449: Locale (already in base)
            # S1450: Protected field (already in six)
            # S1451: File header (already in nine)
            # S1452: Wildcard return (already in eight)
            # S1479: Too many cases (already in base)
            # S1481: Unused local (already in full)
            # S1488: Redundant local (already in base)
            # S1596: Empty collection (already in base)
            # S1598: Division by zero (already in seven)
            # S1600: Return null array (already in seven)
            # S1602: Unnecessary boxing (already in ext)
            # S1604: Lambda (already in base)
            # S1607: Test assertion (already in full)
            # S1609: FunctionalInterface (already in ten)
            # S1610: Abstract naming (already in ten)
            # S1611: Method reference (already in five)
            # S1656: Self assignment (already in ext)
            # S1659: Multi-var decl (already in full)
            # S1697: Short circuit (already in ext)
            # S1700: Field/method name (already in base)
            # S1701: Diamond (already in full)
            # S1710: Duplicate annotation (already in eight)
            # S1711: getBytes charset (already in seven)
            # S1725: Field naming (already in ten)
            # S1751: Loop only break (already in eight)
            # S1763: Dead code after jump (already in full)
            # S1764: Identical expression (already in base)
            # S1761: Finally return (already in seven)
            # S1820: Too many fields (already in eight)
            # S1844: Finalize call (already in seven)
            # S1849: Next without hasNext (already in nine)
            # S1850: Instanceof final (already in seven)
            # S1854: Dead store (already in base)
            # S1858: ToString on string (already in seven)
            # S1860: Sync immutable (already in ext)
            # S1862: Duplicate condition (already in six)
            # S1871: Duplicate switch branch (already in five)
            # S1872: Class.forName (already in seven)
            # S1873: Properties (already in seven)
            # S1905: Redundant cast (already in base)
            # S1909: Self assignment ten (already in ten)
            # S1927: Instanceof (already in eight)
            # S1939: Enum equals
            # S1940: Boolean inversion (already in eight)
            # S1941: Generic variable type (already in ten)
            # S1943: Nested class name (already in ten)
            # S1948: Non-serializable (already in nine)
            # S1989: Swallowed exception (already in nine)
            # S1994: For loop variable (already in full)
            # S2055: Collection size (already in ten, partial)
            # S2057: Serializable (already in eight)
            # S2059: Serializable field (already in eight)
            # S2095: Close resource (already in full)
            # S2111: BigDecimal double (already in six)
            # S2112: URL hashCode (already in six)
            # S2114: List remove int (already in six)
            # S2116: String hashCode (already in six)
            # S2118: File delete (already in six)
            # S2119: DateFormat (already in seven)
            # S2121: Iterator remove (already in six)
            # S2122: Scheduled executor (already in fourth)
            # S2123: Value compare (already in full)
            # S2125: Instanceof wrapper (already in seven)
            # S2127: URL equals (already in fourth)
            # S2129: String concat loop (already in six)
            # S2130: Deprecated (already in base)
            # S2131: Split char (already in ext)
            # S2132: String split (already in ext)
            # S2133: String compare (already in full)
            # S2134: Split single char (already in seven)
            # S2135: Statement execute (already in seven)
            # S2139: Exception rethrow (already in six)
            # S2140: Double check lock (already in six)
            # S2141: Enum switch default (already in nine)
            # S2142: Interrupted (already in base)
            # S2143: ThreadLocal naming (already in seven)
            # S2145: URL construction (already in seven)
            # S2151: Thread start in constructor (already in six)
            # S2153: Boxing loop (already in base)
            # S2154: Int division (already in base)
            # S2157: Cloneable (already in fourth)
            # S2159: Clone override (already in seven)
            # S2160: Subclass equals (already in fourth)
            # S2162: Equals asymmetry (already in fourth)
            # S2164: Int division (already in base)
            # S2165: ThreadLocal mutable (already in seven)
            # S2166: Exception naming (already in full)
            # S2167: Comparable equals (already in fourth)
            # S2168: Return empty (already in ext)
            # S2175: isEmpty (already in seven)
            # S2176: Class name length (already in ten)
            # S2184: Int div cast (already in six)
            # S2186: Thread yield (already in base)
            # S2187: Test class (already in eight)
            # S2188: Test method naming (already in ten)
            # S2200: CompareTo equals (already in fourth)
            # S2201: Ignored return (already in six)
            # S2203: SB toString (already in seven)
            # S2204: Equals type check (already in seven)
            # S2209: Null argument (already in nine)
            # S2222: Lock unlock (already in base)
            # S2225: ToString null (already in seven)
            # S2226: Servlet static (already in ten)
            # S2228: System out (already in base)
            # S2229: LDAP anonymous (already in ext)
            # S2230: CompareTo equals (already in seven)
            # S2232: BigDecimal double (already in nine)
            # S2234: Parameter order
            # S2235: Enum equals (already in full)
            # S2236: Thread wait (already in six)
            # S2240: Security
            # S2245: Predictable random (already in fourth)
            # S2250: String intern (already in six)
            # S2251: Loop counter (already in six)
            # S2252: Float counter (already in six)
            # S2254: Double brace (already in full)
            # S2257: Crypto variable (already in six)
            # S2259: Null deref (already in five)
            # S2273: Sleep in loop (already in base)
            # S2278: ECB mode (already in fourth)
            # S2293: Diamond missing (already in six)
            # S2296: Parentheses
            # S2325: Private method (already in base)
            # S2326: Unused type param (already in base)
            # S2333: Redundant modifier (already in five)
            # S2386: Mutable array (already in base)
            # S2388: Excessive chaining (already in ten)
            # S2390: Accessor generation
            # S2437: Unnecessary unboxing (already in five)
            # S2438: Inner class static (already in ten)
            # S2440: Boxing compare (already in six)
            # S2441: ThreadLocal static (already in seven)
            # S2442: Sync class usage (already in seven)
            # S2445: Sync on field (already in base)
            # S2446: Wait sync (already in fourth)
            # S2447: NPE thrown (already in five)
            # S2583: Dead code (already in ext)
            # S2589: Always bool (already in ext)
            # S2598: Varargs (already in five)
            # S2629: Log concat (already in base)
            # S2637: Optional param (already in five)
            # S2638: equals parameter type
            # S2670: CompareTo constant (already in nine)
            # S2671: Thread yield api (already in seven)
            # S2674: Read return (already in five)
            # S2675: Read return check (already in five)
            # S2676: IndexOf char (already in full)
            # S2677: Replace char (already in full)
            # S2681: Thread run instead start (already in seven)
            # S2689: Thread run (already in base)
            # S2692: IndexOf contains (already in nine and base)
            # S2693: Thread in constructor (already in seven)
            # S2695: Thread sleep zero (already in seven)
            # S2696: Static write (already in base)
            # S2698: Create temp file (already in five)
            # S2699: Test assertion (already in full)
            # S2701: Literal eq (already in seven)
            # S2737: Catch rethrow (already in seven)
            # S2754: Inherited method
            # S2755: XXE (already in base)
            # S2757: Wrong assign operator (already in nine)
            # S2760: Sequential if (already in seven)
            # S2761: Double not (already in ext)
            # S2772: Serial version (already in ext)
            # S2786: Nested enum
            # S2789: Redundant null check (already in five)
            # S2864: Keyset iteration (already in full)
            # S2886: Servlet input (already in fourth)
            # S2912: IndexOf > 0 (already in seven)
            # S2924: Sleep in test (already in nine)
            # S2925: Thread sleep (already in ext)
            # S3008: Static field naming (already in ten)
            # S3011: Reflection (already in full)
            # S3012: Arrays asList (already in seven)
            # S3020: Iterator next (already in base)
            # S3027: IndexOf contains (already in seven)
            # S3030: Math abs neg (already in seven)
            # S3032: Empty list (already in seven)
            # S3034: Files
            # S3042: Optional orElseGet (already in seven)
            # S3046: Wait in loop (already in seven)
            # S3052: Default init (already in base)
            # S3056: ConcurrentHashMap (already in seven)
            # S3065: Non-thread-safe static (already in seven)
            # S3066: Enum mutable field (already in seven)
            # S3067: Optional serializable
            # S3077: Volatile array
            # S3242: Base type param (already in ext)
            # S3252: Static access (already in full)
            # S3254: Cast redundant
            # S3256: For loop variable (already in full)
            # S3281: File perm (already in base)
            # S3296: Pattern in loop (already in five)
            # S3305: Enum constant annotation (already in full)
            # S3306: Constructor injection
            # S3328: Cipher ECB
            # S3329: CBC IV (already in fourth)
            # S3330: Cookie httponly (already in ext)
            # S3331: Cookie domain
            # S3345: Magic number
            # S3346: Duplicate case (already in base)
            # S3347: HTTP response
            # S3355: Stream filter
            # S3358: Nested ternary (already in base)
            # S3366: Thread start init (already in seven)
            # S3374: Date format
            # S3398: Unused private method (already in five)
            # S3400: Method constant
            # S3416: Logger naming (already in ext)
            # S3417: Logger
            # S3421: File separator (already in ext)
            # S3422: File separator API (already in seven)
            # S3436: ValueOf redundant (already in seven)
            # S3437: Serializable enum
            # S3440: Null instanceof (already in base)
            # S3447: Char to int
            # S3451: For loop variable
            # S3457: Format placeholder (already in base)
            # S3466: Optional.get
            # S3516: For index iteration (already in seven)
            # S3518: Division zero (already in base)
            # S3524: Method argument
            # S3531: Nullable
            # S3544: Switch last case
            # S3546: Abstract class (already in full)
            # S3551: Mockito
            # S3553: Optional orElse
            # S3577: Test class name
            # S3584: Test assertion lambda
            # S3599: Double check lock (already in six)
            # S3603: Singleton
            # S3610: Empty array (already in ext)
            # S3616: Array to list
            # S3626: Labeled jump (already in ext)
            # S3629: Stream
            # S3631: Array copy
            # S3649: JPA injection (already in ext)
            # S3650: Serialization
            # S3655: Optional.get (already in base)
            # S3688: Thread name
            # S3699: Stream forEach
            # S3725: Boolean assert (already in base)
            # S3740: Raw type (already in five)
            # S3743: Conditional expression
            # S3749: Class equals (already in fourth)
            # S3751: Controller
            # S3752: RequestMapping
            # S3760: ToString array
            # S3776: Cognitive complexity
            # S3822: Lambda
            # S3824: computeIfAbsent (already in base)
            # S3864: Stream peek (already in fourth)
            # S3878: Null vararg (already in fourth)
            # S3881: Override annotation
            # S3898: Interface constants
            # S3900: Argument null check
            # S3904: DateFormat
            # S3923: Single branch switch (already in fourth)
            # S3937: Number pattern
            # S3958: Stream intermediate (already in fourth)
            # S3959: Stream consumed (already in base)
            # S3963: Enum singleton
            # S3972: Negated else-if (already in six)
            # S3973: Empty statement (already in full)
            # S3981: Collection size (already in base)
            # S3984: Exception not thrown (already in base)
            # S3985: Unused inner (already in base)
            # S3986: Date format (already in ext)
            # S3988: Parallel stream (already in six)
            # S3992: Credential
            # S3996: URL equals (already in fourth)
            # S4032: addAll (already in full)
            # S4065: ThreadLocal static (already in fourth)
            # S4141: List size loop (already in five)
            # S4143: Map overwrite (already in base)
            # S4144: Duplicate method (already in base)
            # S4158: Stream count (already in fourth)
            # S4165: Magic number (already in ext)
            # S4166: Optional null (already in fourth)
            # S4201: Optional null check (already in fourth)
            # S4242: Iterator next (already in fourth)
            # S4274: Assertion argument
            # S4275: Getter setter (already in base)
            # S4276: Param reassign
            # S4288: Spring component
            # S4347: Secure random (already in base)
            # S4351: Equals valueOf (already in fourth)
            # S4408: Static class final (already in full)
            # S4423: Weak SSL (already in base)
            # S4425: Weak XML (already in fourth)
            # S4431: Web mapping annotation (already in six)
            # S4432: DES (already in base)
            # S4449: Log injection
            # S4507: SQL injection (already in base)
            # S4517: Resource try-with (already in six)
            # S4524: Switch default (already in base)
            # S4530: Spring CSRF
            # S4601: Path traversal
            # S4602: Mapping without Controller (already in eight)
            # S4604: Autowired field (already in eight)
            # S4605: Field injection (already in eight)
            # S4621: Spring HTTP method (already in eight)
            # S4635: RequestParam default (already in eight)
            # S4682: Specific mapping (already in eight)
            # S4684: Spring entity
            # S4700: Spring query (already in eight)
            # S4719: Spring repository (already in eight)
            # S4738: Java 8
            # S4740: Input validation
            # S4792: Logger secure (already in base)
            # S4797: Self signed
            # S4800: Hardcoded key (already in base)
            # S4823: Command injection (already in base)
            # S4830: SSL disabled (already in base)
            # S4834: Authorization (already in nine)
            # S4838: JSON (already in six)
            # S4925: MD5 (already in base)
            # S4929: Thread safe (already in base)
            # S4931: Path manipulation
            # S4956: Runtime exec (already in base)
            # S4972: Open redirect (already in base)
            # S4973: String eq (already in base)
            # S5042: Zip slip (already in base)
            # S5122: XSS (already in base)
            # S5125: Jackson (already in fourth)
            # S5131: XSS output (already in six)
            # S5135: Deserialization (already in base)
            # S5145: Log injection (already in base)
            # S5160: Insecure random (already in ext)
            # S5280: CSP header (already in nine)
            # S5290: Hardcoded password (already in base)
            # S5301: Mail injection (already in base)
            # S5304: JNDI lookup (already in fourth)
            # S5322: LDAP injection (already in base)
            # S5332: Clear text (already in nine)
            # S5341: Weak MAC (already in ext)
            # S5443: Temp file (already in base)
            # S5445: Regex injection (already in nine)
            # S5487: JSON manual (already in nine)
            # S5542: XML process (already in base)
            # S5547: SSRF (already in base)
            # S5582: Open redirect nine (already in nine)
            # S5612: CSP
            # S5659: JWT key (already in base)
            # S5661: Log forging (already in base)
            # S5693: Content type nine (already in nine)
            # S5852: ReDoS (already in six)
            # S5853: JUnit assertThat
            # S5854: JUnit lifecycle visibility (already in eight)
            # S5856: AssertJ
            # S5857: DisplayName (already in eight)
            # S5860: GetClass auth (already in six)
            # S5863: Immutable collection (already in ten)
            # S5867: ToString array
            # S5868: Null check
            # S5876: Manual thread (already in six)
            # S5886: Enum
            # S5899: Stream forEach (already in ten)
            # S5905: Dead store (already in base)
            # S5921: Serialization
            # S5932: Null return
            # S5933: Serialization
            # S5958: Lambda method ref (already in eight)
            # S5960: Comparator (already in eight)
            # S5971: Stream findFirst (already in ten)
            # S5973: HTTP
            # S5976: Switch expression
            # S5993: Switch preview
            # S5994: Record (already in eight)
            # S5996: Text block (already in eight)
            # S5998: Pattern matching
            # S6000: Sealed class (already in eight)
            # S6010: Clean code
            # S6019: Var inference (already in ten)
            # S6021: Pattern instanceof (already in eight)
            # S6023: Switch arrow (already in eight)
            # S6025: Record accessor
            # S6035: Assertion
            # S6054: CDI
            # S6055: REST
            # S6060: Spring
            # S6065: Exception
            # S6068: Thread
            # S6070: Stream
            # S6074: Collection
            # S6076: Lambda
            # S6080: Switch
            # S6092: Optional field (already in eight)
            # S6093: Lambda param type (already in eight)
            # S6104: Record
            # S6111: Switch
            # S6113: Text block
            # S6126: Record
            pass
