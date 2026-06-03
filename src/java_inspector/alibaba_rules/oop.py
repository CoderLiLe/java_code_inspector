import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class OopChecker(BaseChecker):

    def check_oop(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_oop"):
            return
        lines = content.split("\n")
        has_to_string = False
        is_pojo = False
        pojo_class_name = ""

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and node.name in ("toString", "equals"):
                has_to_string = True

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                pojo_class_name = node.name
                skip_types = ("Controller", "Service", "Repository", "Application", "Utils", "Util")
                if not node.name.endswith(skip_types):
                    is_pojo = True

        if is_pojo and pojo_class_name and not has_to_string:
            for path, node in tree:
                if isinstance(node, javalang.tree.ClassDeclaration) and node.name == pojo_class_name:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_TO_STRING",
                              f"POJO 类 '{pojo_class_name}' 必须写 toString 方法",
                              Severity.WARNING, line=l, column=c)
                    break

        for i, line in enumerate(lines, 1):
            m = re.search(r"(\w+)\.equals\([^)]+\)", line)
            if m and m.group(1)[0].islower() and m.group(1) not in ("this", "super"):
                if not re.search(r'["\'].+["\']\.equals\(', line):
                    self._add(file_path, "ALIBABA_EQUALS_STYLE",
                              f"equals 应使用常量调用，建议: \"constant\".equals({m.group(1)})",
                              Severity.INFO, line=i,
                              column=line.find(m.group(1) + ".equals("))

            if re.search(r"\b(Integer|Long|Short|Byte)\s+\w+\s*[=!]=\s*\w+", line) and \
               ".intValue()" not in line and ".longValue()" not in line:
                self._add(file_path, "ALIBABA_INTEGER_COMPARE",
                          "整型包装类对象之间值的比较，全部使用 equals 方法比较",
                          Severity.WARNING, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                class_fields = {}
                for p2, n2 in tree:
                    if isinstance(n2, javalang.tree.FieldDeclaration) and not any(
                        m in (n2.modifiers or []) for m in ("static", "final")
                    ):
                        for declarator in n2.declarators:
                            class_fields[declarator.name] = declarator
                has_getter = {}
                has_is_method = {}
                for p2, n2 in tree:
                    if isinstance(n2, javalang.tree.MethodDeclaration):
                        for fname in class_fields:
                            if n2.name == "get" + fname[0].upper() + fname[1:]:
                                has_getter[fname] = True
                            if n2.name == "is" + fname[0].upper() + fname[1:]:
                                has_is_method[fname] = True
                for fname in class_fields:
                    if has_getter.get(fname) and has_is_method.get(fname):
                        l, c = self._pos(class_fields[fname])
                        self._add(file_path, "ALIBABA_BOTH_IS_GET",
                                  f"POJO 类中不能同时存在对应属性 '{fname}' 的 isXxx() 和 getXxx() 方法",
                                  Severity.WARNING, line=l, column=c)

        in_loop = False
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(for|while)\s*\(", line):
                in_loop = True
            if in_loop:
                if re.search(r'\bstr\b.*\+=', line) or re.search(r'\bString\s+\w+\s*=\s*["\']', line):
                    for j, nl in enumerate(lines[i:min(i + 5, len(lines))]):
                        if re.search(r"\+=", nl) and i + j > i:
                            self._add(file_path, "ALIBABA_STRING_BUILDER",
                                      "循环体内字符串连接应使用 StringBuilder 的 append 方法",
                                      Severity.INFO, line=i + j + 1)
                            break
                if re.search(r"^\s*\}", line):
                    in_loop = False

        # 4.2 All override methods must have @Override
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                parent = getattr(node, "extends", None) is not None or \
                         len(getattr(node, "implements", []) or []) > 0
                if parent:
                    for p2, n2 in tree:
                        if isinstance(n2, javalang.tree.MethodDeclaration) and \
                           n2.name in ("toString", "equals", "hashCode", "clone", "finalize") and \
                           not any(m == "static" for m in (n2.modifiers or [])):
                            has_override = any(
                                getattr(ann, "name", "") == "Override"
                                for ann in (n2.annotations or [])
                            )
                            if not has_override:
                                l, c = self._pos(n2) if hasattr(n2, "position") else (0, 0)
                                self._add(file_path, "ALIBABA_OVERRIDE_ANNOTATION",
                                          f"覆写方法 '{n2.name}' 必须加 @Override 注解",
                                          Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and \
               isinstance(node.qualifier, javalang.tree.MemberReference):
                name_str = str(node.qualifier)
                if name_str and name_str[0].islower() and name_str[0] == name_str[0].lower():
                    for p2, n2 in tree:
                        if isinstance(n2, javalang.tree.VariableDeclaration) and \
                           any(d.name == name_str for d in n2.declarators):
                            break
                    else:
                        if node.member in ("toString", "hashCode", "getClass", "notify", "wait"):
                            pass
                        elif hasattr(node, "qualifier") and \
                             isinstance(getattr(node.qualifier, "qualifier", None), javalang.tree.This):
                            pass
                        else:
                            for p2, n2 in tree:
                                if isinstance(n2, javalang.tree.ClassDeclaration):
                                    for p3, n3 in tree:
                                        if isinstance(n3, javalang.tree.MethodDeclaration) and \
                                           n3.name == node.member and \
                                           "static" in (n3.modifiers or []):
                                            l, c = self._pos(node)
                                            self._add(file_path, "ALIBABA_STATIC_ACCESS",
                                                      f"应通过类名直接访问静态方法 '{node.member}'，而非通过实例对象",
                                  Severity.WARNING, line=l, column=c)

        # 1.5.4 Local variables lowerCamelCase
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                local_vars = []
                for stmt in (node.body if isinstance(node.body, list) else
                            getattr(getattr(node, "body", None), "statements", []) or []):
                    for sub in (getattr(stmt, "statements", []) if hasattr(stmt, "statements") else []):
                        local_vars.append(sub)
                local_vars.extend(node.body if isinstance(node.body, list) else [])
                for n in local_vars:
                    if isinstance(n, javalang.tree.LocalVariableDeclaration):
                        for declarator in n.declarators:
                            vn = declarator.name
                            if vn and vn[0].isupper() and vn != vn.upper() and len(vn) > 1 and \
                               not any(vn.endswith(s) for s in ("VO", "PO", "DO", "DTO", "BO", "AO", "UID")):
                                l, c = self._pos(declarator)
                                self._add(file_path, "ALIBABA_LOCAL_VAR_CASE",
                                          f"局部变量 '{vn}' 应使用 lowerCamelCase 风格（首字母小写）",
                                          Severity.WARNING, line=l, column=c)

        # 1.5.5 Method parameter vs field name collision (non-setter)
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                field_names = set()
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        for decl in member.declarators:
                            field_names.add(decl.name.lower())
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration):
                        mn = member.name
                        if not mn.startswith("set"):
                            for param in (member.parameters or []):
                                if param.name.lower() in field_names:
                                    l, c = self._pos(param)
                                    self._add(file_path, "ALIBABA_PARAM_FIELD_CONFLICT",
                                              f"参数 '{param.name}' 与成员变量同名，非 setter 方法应避免",
                                              Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodReference) or \
               isinstance(node, javalang.tree.MemberReference):
                if hasattr(node, "member") and node.member.startswith("get") and \
                   hasattr(node, "qualifier"):
                    dep_methods = ["getDate", "getYear", "getMonth", "getDay"]
                    if node.member in dep_methods:
                        l, c = self._pos(node) if hasattr(node, "position") else (0, 0)
                        self._add(file_path, "ALIBABA_DEPRECATED_METHOD",
                                  f"避免使用过时的方法 '{node.member}'",
                                  Severity.WARNING, line=l, column=c)

        # 4.4 Interface deprecation: @deprecated Javadoc must have @Deprecated annotation
        for path, node in tree:
            if isinstance(node, (javalang.tree.MethodDeclaration, javalang.tree.ClassDeclaration,
                                 javalang.tree.InterfaceDeclaration)):
                ml = node.position.line if node.position else 0
                has_deprecated_javadoc = False
                has_deprecated_annotation = False
                for jj in range(max(0, ml - 8), ml - 1):
                    if jj < len(lines) and re.search(r"@deprecated", lines[jj]):
                        has_deprecated_javadoc = True
                    if jj < len(lines) and re.search(r"@Deprecated", lines[jj]):
                        has_deprecated_annotation = True
                if has_deprecated_javadoc and not has_deprecated_annotation:
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if "Deprecated" not in ann_names:
                        l, c = self._pos(node)
                        name = getattr(node, "name", "element")
                        self._add(file_path, "ALIBABA_INTERFACE_DEPRECATED",
                                  f"'{name}' 在 Javadoc 中已标注 @deprecated 但缺少 @Deprecated 注解",
                                  Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                params = node.parameters or []
                if len(params) > 1:
                    last_param = params[-1]
                    if hasattr(last_param, "type") and hasattr(last_param.type, "name") and \
                       last_param.type.name != "Object" and \
                       getattr(last_param, "varargs", False) is False:
                        pass
                    for param in params[:-1]:
                        if getattr(param, "varargs", False):
                            l, c = self._pos(param)
                            self._add(file_path, "ALIBABA_VARARGS_LAST",
                                      "可变参数必须放置在参数列表的最后",
                                      Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if not node.name.endswith(("Controller", "Service", "Repository", "Application", "Utils", "Util")):
                    for field in node.body or []:
                        if isinstance(field, javalang.tree.FieldDeclaration):
                            ft = getattr(field, "type", None)
                            if ft and hasattr(ft, "name") and ft.name in (
                                "int", "long", "double", "float", "boolean", "char", "byte", "short"
                            ):
                                for decl in field.declarators:
                                    if decl.name and not decl.name.upper() == decl.name:
                                        l, c = self._pos(decl)
                                        self._add(file_path, "ALIBABA_POJO_WRAPPER",
                                                  f"POJO 类属性 '{decl.name}' 必须使用包装数据类型，而非基本类型 '{ft.name}'",
                                                  Severity.WARNING, line=l, column=c)

        # 4.8 DO field type matching DB column types
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               node.name.endswith(("DO", "PO", "Entity")):
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        ft = getattr(field, "type", None)
                        if ft and hasattr(ft, "name"):
                            for decl in field.declarators:
                                fn = decl.name.lower()
                                ftn = ft.name
                                # id/Id fields should be Long for bigint
                                if (fn in ("id",) or fn.endswith("id")) and \
                                   ftn in ("int", "Integer"):
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_DO_FIELD_TYPE_MISMATCH",
                                              f"DO 字段 '{decl.name}' 类型为 {ftn}，数据库 bigint 应对应 Long 类型",
                                              Severity.WARNING, line=l, column=c)
                                # status/type fields should be Integer (nullable)
                                if fn in ("status", "type", "state", "flag") and \
                                   ftn == "int":
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_DO_FIELD_TYPE_MISMATCH",
                                              f"DO 字段 '{decl.name}' 类型为 int，建议使用 Integer（可为 null）",
                                              Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                implements_serializable = any(
                    hasattr(iface, "name") and iface.name == "Serializable"
                    for iface in getattr(node, "implements", []) or []
                ) or "Serializable" in str(getattr(node, "implements", ""))
                if implements_serializable:
                    has_suid = any(
                        isinstance(f, javalang.tree.FieldDeclaration) and
                        any(d.name == "serialVersionUID" for d in f.declarators)
                        for f in (node.body or [])
                    )
                    if not has_suid:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_SERIAL_VERSION_UID",
                                  f"实现 Serializable 的类 '{node.name}' 应声明 serialVersionUID 字段",
                                  Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.ConstructorDeclaration):
                body = node.body or []
                has_logic = False
                for stmt in body:
                    if isinstance(stmt, (javalang.tree.MethodInvocation,
                                        javalang.tree.IfStatement,
                                        javalang.tree.ForStatement,
                                        javalang.tree.WhileStatement,
                                        javalang.tree.TryStatement)):
                        has_logic = True
                        break
                if has_logic:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_CONSTRUCTOR_LOGIC",
                              "构造方法里面禁止加入任何业务逻辑，如果有初始化逻辑请放在 init 方法中",
                              Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            m = re.search(r"(\w+)\s*==\s*(\w+)\s*$", line)
            if m:
                a, b = m.group(1), m.group(2)
                if a.lower() != b.lower() and \
                   re.search(r"\b(float|double|Float|Double)\s+" + re.escape(a) + r"\b", line) or \
                   re.search(r"\b(float|double|Float|Double)\s+" + re.escape(b) + r"\b", line):
                    self._add(file_path, "ALIBABA_FLOAT_COMPARE",
                              "浮点数之间的等值判断，基本数据类型不能使用 == 进行比较，包装数据类型不能使用 equals",
                              Severity.WARNING, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and node.member == "equals":
                for p2, n2 in tree:
                    if isinstance(n2, javalang.tree.VariableDeclaration) and \
                       any(d.name == getattr(node.qualifier, "member", "") or
                           d.name == str(node.qualifier) for d in n2.declarators):
                        vtype = getattr(n2, "type", None)
                        if vtype and hasattr(vtype, "name") and vtype.name == "BigDecimal":
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_BIGDECIMAL_EQUALS",
                                      "BigDecimal 的等值比较应使用 compareTo() 方法，而不是 equals() 方法",
                                      Severity.WARNING, line=l, column=c)
                        break

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "DTO", "VO", "BO", "PO", "POJO")):
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            if decl.initializer is not None:
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_POJO_DEFAULT",
                                          f"POJO 类 '{node.name}' 属性 '{decl.name}' 不要设定任何属性默认值",
                                          Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"\.clone\s*\(\)", line) and not re.search(r"//.*\.clone", line):
                self._add(file_path, "ALIBABA_CLONE_USAGE",
                          "慎用 Object 的 clone 方法来拷贝对象，默认是浅拷贝",
                          Severity.INFO, line=i)

        # 4.26 Private constructor for utility classes
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                all_static_methods = True
                has_public_ctor = False
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration) and \
                       "static" not in (member.modifiers or []):
                        all_static_methods = False
                    if isinstance(member, javalang.tree.ConstructorDeclaration):
                        if "private" not in (member.modifiers or []):
                            has_public_ctor = True
                if all_static_methods and has_public_ctor:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_UTILITY_CTOR",
                              f"工具类 '{node.name}' 不允许有 public 或 default 构造方法，构造方法应为 private",
                              Severity.WARNING, line=l, column=c)

        # 4.22 No business logic in getter/setter
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mn = node.name
                if mn.startswith(("get", "is")) and len(mn) > 3 and \
                   "static" not in (node.modifiers or []):
                    body = node.body or []
                    stmt_count = len(body) if isinstance(body, list) else \
                                 len(getattr(body, "statements", []) or [])
                    if stmt_count > 2:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_GETTER_LOGIC",
                                  f"getter 方法 '{mn}' 不应包含业务逻辑，应仅做属性返回",
                                  Severity.INFO, line=l, column=c)
                elif mn.startswith("set") and len(mn) > 3 and \
                     "static" not in (node.modifiers or []):
                    body = node.body or []
                    stmt_count = len(body) if isinstance(body, list) else \
                                 len(getattr(body, "statements", []) or [])
                    if stmt_count > 3:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_SETTER_LOGIC",
                                  f"setter 方法 '{mn}' 不应包含业务逻辑，应仅做属性赋值",
                                  Severity.INFO, line=l, column=c)

        # 4.19 Split result bounds check
        for i, line in enumerate(lines, 1):
            if re.search(r"\.split\s*\([^)]+\)\s*\[", line):
                for j in range(max(0, i - 5), i):
                    if j < len(lines) and re.search(r"\.length\s*[>=]", lines[j]) and \
                       re.search(r"\.split", lines[j]):
                        break
                else:
                    self._add(file_path, "ALIBABA_SPLIT_RESULT",
                              "使用索引访问 String 的 split 方法得到的数组时，需做最后一个分隔符后有无内容的检查",
                              Severity.INFO, line=i)

        # 4.8 Money in smallest unit type
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(double|float)\s+\w*(Price|Amount|Money|Salary|Cost|Budget|Fee|Payment|Total|Sum)", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_MONEY_TYPE",
                          "任何货币金额均以最小货币单位且为整型类型进行存储，建议使用 Long 或 int 而非 double/float",
                          Severity.WARNING, line=i)

        # 4.20 Multiple constructors should be grouped
        current_class = None
        ctors = []
        methods_seen = []
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                current_class = node.name
                ctors = []
                methods_seen = []
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.ConstructorDeclaration):
                        ctors.append(member.name)
                    elif isinstance(member, javalang.tree.MethodDeclaration):
                        methods_seen.append(member.name)
                if len(ctors) > 1:
                    for method_name in methods_seen:
                        for ctor in ctors:
                            if method_name == ctor:
                                pass
                if len(ctors) >= 2:
                    first_ctor_line = None
                    last_ctor_line = None
                    method_between = False
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.ConstructorDeclaration):
                            if first_ctor_line is None:
                                first_ctor_line = member.position.line if member.position else 0
                            last_ctor_line = member.position.line if member.position else 0
                        elif isinstance(member, javalang.tree.MethodDeclaration) and \
                             first_ctor_line is not None and last_ctor_line is not None and \
                             member.position and member.position.line > first_ctor_line and \
                             member.position.line < last_ctor_line:
                            method_between = True
                    if method_between:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_CTOR_GROUPING",
                                  "当一个类有多个构造方法时，这些构造方法应该按顺序放置在一起",
                                  Severity.INFO, line=l, column=c)

        # 4.22 Avoid BigDecimal(double)
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+BigDecimal\s*\(\s*\d+\.\d+\s*\)", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_BIGDECIMAL_DOUBLE",
                          "禁止使用构造方法 BigDecimal(double) 的方式把 double 值转化为 BigDecimal 对象",
                          Severity.WARNING, line=i)

        # 4.23 Use equals for wrapper type comparison
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(Integer|Long|Short|Byte|Double|Float|Boolean)\b.*[=!]=\s*\d+", line) and \
               not re.search(r"//|==\s*null|null\s*==", line):
                m = re.search(r"(\w+)\s*[=!]=\s*(-?\d+)", line)
                if m:
                    self._add(file_path, "ALIBABA_WRAPPER_EQUALS",
                              "包装类对象之间值的比较应使用 equals 方法而非 '=='",
                              Severity.WARNING, line=i, column=line.find(m.group(2)))

        # 4.24 final keyword recommendation
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(String|Integer|Long|Boolean)\s+(\w+)\s*=", line) and \
               not re.search(r"\bfinal\b", line) and \
               not re.search(r"//", line) and \
               not re.search(r"(this\.|return|param|arg)", line):
                m = re.search(r"\b(String|Integer|Long|Boolean)\s+(\w+)\s*=", line)
                if m and m.group(2)[0].islower() and len(m.group(2)) > 1:
                    pass

        # 4.3 Varargs type should not be Object
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                for param in (node.parameters or []):
                    if getattr(param, "varargs", False) and hasattr(param, "type") and param.type:
                        vt = param.type.name if hasattr(param.type, "name") else str(param.type)
                        if vt == "Object":
                            l, c = self._pos(param)
                            self._add(file_path, "ALIBABA_VARARGS_OBJECT",
                                      "可变参数类型避免定义为 Object，应指定具体类型",
                                      Severity.WARNING, line=l, column=c)

        # 4.4 @Deprecated on outdated interfaces
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []) and \
               not node.name.startswith(("get", "set", "is")):
                body = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                if not body:
                    continue
                for stmt in body:
                    if isinstance(stmt, javalang.tree.ReturnStatement):
                        continue
                l, c = self._pos(node)
                for p2, n2 in tree:
                    if isinstance(n2, javalang.tree.InterfaceDeclaration):
                        for m2 in (n2.body or []):
                            if isinstance(m2, javalang.tree.MethodDeclaration) and \
                               m2.name == node.name:
                                has_deprecated = any(
                                    getattr(ann, "name", "") == "Deprecated"
                                    for ann in (m2.annotations or [])
                                )
                                break

        # 4.13.2 RPC interface return/param should use wrapper types
        for path, node in tree:
            if isinstance(node, javalang.tree.InterfaceDeclaration):
                for m in (node.body or []):
                    if isinstance(m, javalang.tree.MethodDeclaration):
                        ret = getattr(m, "return_type", None)
                        if ret and hasattr(ret, "name") and ret.name in (
                            "int", "long", "double", "float", "boolean", "char", "byte", "short"
                        ):
                            l, c = self._pos(m)
                            self._add(file_path, "ALIBABA_RPC_WRAPPER_RETURN",
                                      f"RPC 接口方法 '{m.name}' 返回值应使用包装数据类型 '{ret.name.title()}'",
                                      Severity.WARNING, line=l, column=c)
                        for param in (m.parameters or []):
                            pt = getattr(param, "type", None)
                            if pt and hasattr(pt, "name") and pt.name in (
                                "int", "long", "double", "float", "boolean", "char", "byte", "short"
                            ):
                                l, c = self._pos(param)
                                self._add(file_path, "ALIBABA_RPC_WRAPPER_PARAM",
                                          f"RPC 接口方法 '{m.name}' 参数 '{param.name}' 应使用包装数据类型 '{pt.name.title()}'",
                                          Severity.WARNING, line=l, column=c)

        # 4.13.3 Local variables prefer primitives
        for i, line in enumerate(lines, 1):
            m = re.search(r"\b(Integer|Long|Boolean|Double|Float)\s+(\w+)\s*=", line)
            if m and not re.search(r"//", line) and not re.search(r"(static|final|private|protected|public)", line):
                wrapper_type = m.group(1)
                var_name = m.group(2)
                if var_name[0].islower() and not re.search(r"(null|new\s)", line):
                    self._add(file_path, "ALIBABA_LOCAL_PRIMITIVE",
                              f"局部变量 '{var_name}' 建议使用基本类型 '{wrapper_type.lower()}' 而非包装类型",
                              Severity.INFO, line=i)

        # 4.21 Method ordering: public/protected > private > getter/setter
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                methods_by_line = []
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration) and member.position:
                        mods = member.modifiers or []
                        if "public" in mods:
                            cat = 0
                        elif "protected" in mods:
                            cat = 1
                        else:
                            cat = 2
                        if member.name.startswith(("get", "set", "is")):
                            cat = 3
                        methods_by_line.append((member.position.line, cat, member.name))
                methods_by_line.sort()
                seen_cats = set()
                last_cat = -1
                for _, cat, _ in methods_by_line:
                    if cat < last_cat:
                        break
                    last_cat = cat
                else:
                    for _, cat, _ in methods_by_line:
                        pass

        # 4.26 Access control: private constructor for non-instantiable classes
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                has_public_ctor = False
                all_ctors_private = True
                has_ctor = False
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.ConstructorDeclaration):
                        has_ctor = True
                        if "private" not in (member.modifiers or []):
                            all_ctors_private = False
                            if "public" in (member.modifiers or []):
                                has_public_ctor = True
                if has_public_ctor and len([m for m in (node.body or []) if isinstance(m, javalang.tree.MethodDeclaration) and "static" in (m.modifiers or [])]) > 5:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_ACCESS_CTOR",
                              f"类 '{node.name}' 包含大量静态方法，构造方法应设为 private",
                              Severity.INFO, line=l, column=c)

        # 4.14 StringBuilder in loops
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body_str = str(getattr(node, "body", "") or "")
                loops = re.findall(r"(for|while)\s*\(", body_str)
                if loops and "+=" in body_str and re.search(r"\w+\s*\+=?\s*\w+\s*\+", body_str):
                    for i, line in enumerate(lines, 1):
                        if re.search(r"\+\s*=?\s*\w+\s*\+", line) and \
                           re.search(r"(for|while)\(", lines[max(0, i - 3)]) and \
                           not re.search(r"StringBuilder|StringBuffer|String\.format|MessageFormat", line):
                            self._add(file_path, "ALIBABA_STRING_CONCAT_LOOP",
                                      "循环体内字符串连接使用 StringBuilder 的 append 方法进行扩展",
                                      Severity.WARNING, line=i)
                            break

        # 4.17 toString in catch block
        for path, node in tree:
            if isinstance(node, javalang.tree.CatchClause):
                l = node.position.line if node.position else 0
                block = getattr(node, "block", None) or getattr(node, "body", "")
                body_str = str(block)
                if "toString" in body_str and "printStackTrace" not in body_str:
                    self._add(file_path, "ALIBABA_TOSTRING_CATCH",
                              "异常捕获后直接使用 toString 输出堆栈信息应当使用 printStackTrace 或日志框架",
                              Severity.INFO, line=l)

        # 4.19 Use className.isInstance instead of instanceof in large conditionals
        for i, line in enumerate(lines, 1):
            if re.search(r"\binstanceof\b", line):
                count = 0
                for j in range(max(0, i - 3), i + 1):
                    if j < len(lines):
                        count += lines[j].count("instanceof")
                if count >= 3:
                    self._add(file_path, "ALIBABA_MULTIPLE_INSTANCEOF",
                              "多个 instanceof 判断建议使用多态或设计模式重构",
                              Severity.INFO, line=i)

        # 4.13.x Interface should not return enum for API
        for path, node in tree:
            if isinstance(node, javalang.tree.InterfaceDeclaration):
                for m in (node.body or []):
                    if isinstance(m, javalang.tree.MethodDeclaration):
                        ret = getattr(m, "return_type", None)
                        if ret and hasattr(ret, "name"):
                            rn = ret.name
                            if rn.endswith("Enum") or rn in ("Enum",):
                                l, c = self._pos(m)
                                self._add(file_path, "ALIBABA_INTERFACE_ENUM_RETURN",
                                          f"接口方法 '{m.name}' 返回值禁止使用枚举类型 '{rn}'",
                                          Severity.WARNING, line=l, column=c)

        # 4.26 Access control: prefer private over default (package-private)
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                mods = node.modifiers or []
                if not any(m in mods for m in ("private", "public", "protected")) and \
                   not any("static" in mods and "final" in mods):
                    for decl in node.declarators:
                        if not decl.name.startswith("serialVersionUID"):
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_ACCESS_DEFAULT",
                                      f"字段 '{decl.name}' 缺少访问修饰符，建议使用 private",
                                      Severity.INFO, line=l, column=c)
            elif isinstance(node, javalang.tree.MethodDeclaration):
                mods = node.modifiers or []
                mn = node.name
                if not any(m in mods for m in ("private", "public", "protected")) and \
                   not mn.startswith(("get", "set", "is")) and \
                   "static" not in mods and \
                   "override" not in str(getattr(node, "annotations", "")).lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_ACCESS_DEFAULT_METHOD",
                              f"方法 '{mn}' 缺少访问修饰符，建议明确指定为 private/protected/public",
                              Severity.INFO, line=l, column=c)

        # 4.26 Override annotation required
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mods = node.modifiers or []
                if "public" in mods or "protected" in mods:
                    mn = node.name
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    # Check if this method might be overriding (not a new method)
                    if not any(a in ann_names for a in ("Override", "Override", "override")) and \
                       not mn.startswith(("get", "set", "is")) and \
                       "static" not in mods:
                        # Check if parent class exists in same file
                        for p2, n2 in tree:
                            if isinstance(n2, javalang.tree.ClassDeclaration) and \
                               n2.name != getattr(node, "name", ""):
                                # This is a simplified check - just flag methods that look like overrides
                                if not mn.startswith("_"):
                                    pass  # Too noisy without cross-file analysis

        # Setter parameter name check
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                fields = {}
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        for decl in member.declarators:
                            fields[decl.name.lower()] = decl.name
                    elif isinstance(member, javalang.tree.MethodDeclaration):
                        mn = member.name
                        if mn.startswith("set") and len(mn) > 3:
                            expected_field = mn[3].lower() + mn[4:]
                            if expected_field in fields:
                                for param in (member.parameters or []):
                                    if hasattr(param, "name"):
                                        expected_param = fields[expected_field]
                                        if param.name.lower() != expected_param.lower():
                                            l, c = self._pos(member)
                                            self._add(file_path, "ALIBABA_SETTER_PARAM_NAME",
                                                      f"setter '{mn}' 参数名应为 '{expected_param}' 而非 '{param.name}'，需与字段名一致",
                                                      Severity.INFO, line=l, column=c)

        # 4.28 Method order: public/protected > private > getter/setter
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                methods = []
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration):
                        mods = member.modifiers or []
                        if "public" in mods:
                            tier = 0
                        elif "protected" in mods:
                            tier = 1
                        elif "private" in mods and member.name.startswith(("get", "set", "is")):
                            tier = 3
                        elif "private" in mods:
                            tier = 2
                        else:
                            tier = 0
                        methods.append((tier, member))
                for idx in range(1, len(methods)):
                    if methods[idx][0] < methods[idx - 1][0]:
                        l = methods[idx][1].position.line if methods[idx][1].position else 0
                        self._add(file_path, "ALIBABA_METHOD_ORDER",
                                  f"方法 '{methods[idx][1].name}' 顺序不合理，建议按 public/protected/private/getter/setter 排列",
                                  Severity.INFO, line=l)
                        break
