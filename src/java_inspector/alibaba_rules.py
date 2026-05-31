import re
from typing import List

import javalang

from java_inspector.models import CodeIssue, Severity
from java_inspector.config import InspectionConfig


RACIST_PATTERNS = re.compile(
    r"\b(blackList|black_list|whiteList|white_list|slave|master)\b", re.IGNORECASE
)
CHINESE_PATTERN = re.compile(r"[\u4e00-\u9fff]")
INSULT_PATTERNS = re.compile(r"\b(SB|WTF|TMD|NMD|MDZZ)\b")


class AlibabaRulesChecker:
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
            message=f"【阿里规约】{message}",
            severity=severity,
            rule_id=rule_id,
            category="ALIBABA",
            fix_suggestion=fix_suggestion,
        ))

    # Short identifier heuristic for cryptic abbreviations
    ABBREV_PATTERN = re.compile(r"\b[a-z]{1,2}\b")

    # ==================== (一) 命名风格 ====================
    def check_naming(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_naming"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                is_abstract = "abstract" in (node.modifiers or [])
                if is_abstract and not node.name.startswith(("Abstract", "Base")):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_ABSTRACT_NAMING",
                              f"抽象类 '{node.name}' 命名应以 Abstract 或 Base 开头",
                              Severity.WARNING, line=l, column=c)
            elif isinstance(node, javalang.tree.EnumDeclaration):
                if node.name and not node.name.endswith("Enum"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_ENUM_NAMING",
                              f"枚举类 '{node.name}' 命名应以 Enum 结尾",
                              Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.PackageDeclaration) and node.name != node.name.lower():
                l, c = self._pos(node)
                self._add(file_path, "ALIBABA_PACKAGE_NAME",
                          f"包名 '{node.name}' 必须全部小写",
                          Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"(int|byte|short|long|float|double|char|boolean)\s+\w+\s*\[\]", line):
                self._add(file_path, "ALIBABA_ARRAY_STYLE",
                          "类型与中括号应紧挨相连来定义数组，如 int[] arrayDemo",
                          Severity.WARNING, line=i)

            m = RACIST_PATTERNS.search(line)
            if m:
                self._add(file_path, "ALIBABA_NO_RACIST",
                          f"避免使用种族歧视性词语 '{m.group()}'，建议使用 blockList/allowList/secondary",
                          Severity.WARNING, line=i)

            code_part = re.sub(r"//.*|/\*.*?\*/|'.*?'|\".*?\"", "", line, flags=re.DOTALL)
            if CHINESE_PATTERN.search(code_part):
                self._add(file_path, "ALIBABA_NO_CHINESE",
                          "命名中禁止使用中文或拼音", Severity.WARNING, line=i)

            if INSULT_PATTERNS.search(line):
                self._add(file_path, "ALIBABA_NO_INSULT",
                          "避免使用侮辱性词语", Severity.WARNING, line=i)

            if re.search(r"\b[a-z]{1,2}\b", line) and \
               re.search(r"\b(int|long|String|boolean|double|float|Object)\s+\b[a-z]{1,2}\b", line):
                m = re.search(r"\b(int|long|String|boolean|double|float|Object)\s+([a-z]{1,2})\b", line)
                if m and not re.search(r"//.*$", line):
                    self._add(file_path, "ALIBABA_CRYPTIC_NAME",
                              f"杜绝不规范的缩写 '{m.group(2)}'，应使用完整单词组合来表达语义",
                              Severity.INFO, line=i)

            if re.search(r"\b\$", line) and not re.search(r"\"", line):
                m = re.search(r"\$(\w+)", line)
                if m:
                    self._add(file_path, "ALIBABA_DOLLAR_NAME",
                              "所有编程相关的命名均不能以美元符号开始或结束",
                              Severity.WARNING, line=i)
            if re.search(r"\$\b", line):
                m = re.search(r"(\w+)\$", line)
                if m:
                    self._add(file_path, "ALIBABA_DOLLAR_NAME",
                              "所有编程相关的命名均不能以美元符号开始或结束",
                              Severity.WARNING, line=i)

        # 1.4 UpperCamelCase for classes (except DO/PO/DTO/BO/VO/UID)
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               not any(m == "abstract" for m in (node.modifiers or [])):
                cn = node.name
                if cn[0].islower() and not cn.startswith(("DO", "PO", "VO", "BO", "UID")):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_UPPER_CAMEL",
                              f"类名 '{cn}' 应使用 UpperCamelCase 风格（首字母大写）",
                              Severity.WARNING, line=l, column=c)

        # 1.5 lowerCamelCase for methods, params, variables
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mn = node.name
                if mn[0].isupper() and mn != mn.upper() and not mn.startswith("_"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_LOWER_CAMEL_METHOD",
                              f"方法名 '{mn}' 应使用 lowerCamelCase 风格（首字母小写）",
                              Severity.WARNING, line=l, column=c)
                for param in (node.parameters or []):
                    pn = param.name
                    if pn and pn[0].isupper() and pn != pn.upper() and len(pn) > 1:
                        l, c = self._pos(param)
                        self._add(file_path, "ALIBABA_LOWER_CAMEL_PARAM",
                                  f"参数名 '{pn}' 应使用 lowerCamelCase 风格（首字母小写）",
                                  Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration) and \
               not any(m in (node.modifiers or []) for m in ("static", "final")):
                for decl in node.declarators:
                    fn = decl.name
                    if fn and fn[0].isupper() and fn != fn.upper() and len(fn) > 1:
                        l, c = self._pos(decl)
                        self._add(file_path, "ALIBABA_LOWER_CAMEL_FIELD",
                                  f"成员变量 '{fn}' 应使用 lowerCamelCase 风格（首字母小写）",
                                  Severity.WARNING, line=l, column=c)

        # 1.6 Constants ALL_CAPS
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration) and \
               "static" in (node.modifiers or []) and \
               "final" in (node.modifiers or []):
                for decl in node.declarators:
                    cn = decl.name
                    if cn != cn.upper() and not cn.startswith("serialVersionUID"):
                        l, c = self._pos(decl)
                        self._add(file_path, "ALIBABA_CONSTANT_NAMING",
                                  f"常量 '{cn}' 应全部大写，单词间用下划线隔开",
                                  Severity.WARNING, line=l, column=c)

        # 1.18 Enum member names ALL_CAPS
        for path, node in tree:
            if isinstance(node, javalang.tree.EnumDeclaration):
                for decl in (node.body or []):
                    if isinstance(decl, javalang.tree.EnumConstantDeclaration):
                        en = decl.name
                        if en != en.upper():
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_ENUM_MEMBER_NAMING",
                                      f"枚举成员 '{en}' 应全部大写，单词间用下划线隔开",
                                      Severity.WARNING, line=l, column=c)

        # 1.11 Avoid same names across parent/child/local blocks
        parent_field_names = {}
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                fields = set()
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        for decl in member.declarators:
                            fields.add(decl.name)
                parent_field_names[node.name] = (fields, path)
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                ext = getattr(node, "extends", None)
                if ext and hasattr(ext, "name") and ext.name in parent_field_names:
                    parent_fields, _ = parent_field_names[ext.name]
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.FieldDeclaration):
                            for decl in member.declarators:
                                if decl.name in parent_fields:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_NAMING_CONFLICT",
                                              f"子类 '{node.name}' 的成员变量 '{decl.name}' 与父类 '{ext.name}' 的成员变量同名，避免混淆",
                                              Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                extends_exception = False
                ext = getattr(node, "extends", None)
                if ext and hasattr(ext, "name"):
                    en = ext.name
                    if en in ("Exception", "RuntimeException", "Throwable", "Error") or \
                       en.endswith("Exception") or en.endswith("Error"):
                        extends_exception = True
                        if not cn.endswith("Exception") and not cn.endswith("Error"):
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_EXCEPTION_NAMING",
                                      f"异常类 '{cn}' 命名应以 Exception 结尾",
                                      Severity.WARNING, line=l, column=c)
                if cn.endswith("Test") and not extends_exception and \
                   "abstract" not in (node.modifiers or []):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_TEST_NAMING",
                              f"测试类 '{cn}' 命名应以被测试类名为前缀加 Test 结尾",
                              Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.InterfaceDeclaration):
                for method in node.body or []:
                    if isinstance(method, javalang.tree.MethodDeclaration):
                        mods = method.modifiers or []
                        if "public" in mods or "abstract" in mods:
                            l, c = self._pos(method)
                            self._add(file_path, "ALIBABA_INTERFACE_MODIFIER",
                                      "接口中的方法和属性不要加任何修饰符号（public 也不要加）",
                                      Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("Impl") and not any(
                    isinstance(p2, javalang.tree.InterfaceDeclaration) and
                    cn[:-4] == p2.name
                    for p2, _ in tree
                ):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_IMPL_NAMING",
                              f"实现类 '{cn}' 应实现对应的接口（{cn[:-4]}）",
                              Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                for declarator in node.declarators:
                    if declarator.name.lower().startswith("is") and len(declarator.name) > 2:
                        type_name = getattr(getattr(node, "type", None), "name", "")
                        if type_name.lower() in ("boolean", "bool"):
                            l, c = self._pos(declarator)
                            self._add(file_path, "ALIBABA_BOOLEAN_PREFIX",
                                      f"POJO 类中布尔类型变量 '{declarator.name}' 不应加 is 前缀",
                                      Severity.WARNING, line=l, column=c)

    # ==================== (二) 常量定义 ====================
    def check_constant(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_constant"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for match in re.finditer(r"(\d+)[lL]\s*[;,]", line):
                num = match.group(1)
                suffix = line[match.start(1) + len(num):match.start(1) + len(num) + 1]
                if suffix == "l":
                    self._add(file_path, "ALIBABA_LONG_SUFFIX",
                              "long 赋值时数值后的 L 应大写，不能是小写 l",
                              Severity.INFO, line=i, column=match.start())
            for match in re.finditer(r"(\d+\.\d+)[fFdD]", line):
                suffix = line[match.end(1):match.end(1) + 1]
                if suffix.lower() == suffix and suffix in ("f", "d"):
                    self._add(file_path, "ALIBABA_FLOAT_SUFFIX",
                              "浮点数类型的数值后缀应统一为大写的 D 或 F",
                              Severity.INFO, line=i, column=match.start())

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               re.search(r"(Const|Constant)s?$", node.name):
                has_many_fields = sum(
                    1 for f in (node.body or [])
                    if isinstance(f, (javalang.tree.FieldDeclaration, javalang.tree.MethodDeclaration))
                )
                if has_many_fields > 15:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_MANY_CONSTANTS",
                              "不要使用一个常量类维护所有常量，应按功能进行归类分开维护",
                              Severity.INFO, line=l, column=c)

    # ==================== (三) 代码格式 ====================
    def check_code_style(self, tree, file_path: str, content: str):
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|while|for|switch|catch|synchronized)\(", line) and \
               not re.search(r"\b(if|while|for|switch|catch|synchronized)\s\(", line):
                kw = re.search(r"\b(if|while|for|switch|catch|synchronized)\(", line)
                if kw:
                    self._add(file_path, "ALIBABA_KEYWORD_SPACING",
                              f"'{kw.group(1)}' 关键字与括号之间必须加空格",
                              Severity.INFO, line=i)

            if re.search(r"\/\/[^\s]", line) and not re.search(r"https?://", line):
                self._add(file_path, "ALIBABA_COMMENT_SPACING",
                          "// 注释的 // 后应紧跟一个空格",
                          Severity.INFO, line=i)

            if "\t" in line:
                self._add(file_path, "ALIBABA_NO_TABS",
                          "代码换行缩进禁止使用 Tab，请使用空格代替",
                          Severity.INFO, line=i)

            if re.search(r"[a-z]\)[a-z]", line):
                self._add(file_path, "ALIBABA_RPAREN_SPACING",
                          "右括号 ')' 后面应加空格",
                          Severity.INFO, line=i)

            if re.search(r"\w(\+|-|\*|/|%|=|==|!=|<=|>=|&&|\|\|)\w", line) and \
               not re.search(r"[\"'].*[\+].*[\"']", line) and \
               not re.search(r"\w\s*;", line):
                m = re.search(r"(\w)(\+|-|\*|/|%|=|==|!=|<=|>=|&&|\|\|)(\w)", line)
                if m and not re.search(r"import\s+.*\.", line):
                    pass  # many false positives with single-line expressions

            if re.search(r"\)\)\s+\w", line):
                m = re.search(r"\(\((\w+)\)\)\s+(\w+)", line)
                if m:
                    self._add(file_path, "ALIBABA_CAST_SPACING",
                              "强制转换的右括号后不加空格，如：(String)a",
                              Severity.INFO, line=i)

            if re.search(r",\S", line) and not re.search(r"[\"'].*,\S.*[\"']", line):
                m = re.search(r",(\S)", line)
                if m and m.group(1) not in (")", "]"):
                    self._add(file_path, "ALIBABA_COMMA_SPACING",
                              "逗号后必须加空格",
                              Severity.INFO, line=i)
            if re.search(r"//\S", line):
                self._add(file_path, "ALIBABA_COMMENT_SPACE",
                          "注释的双斜线与注释内容之间应有且仅有一个空格",
                          Severity.INFO, line=i)
            stripped = line.strip()
            if stripped and "\t" in line[:line.index(stripped[0])]:
                self._add(file_path, "ALIBABA_NO_TAB",
                          "禁止使用 Tab 字符缩进，请使用 4 个空格",
                          Severity.WARNING, line=i)
            if re.search(r"catch\s*\([^)]+\)\s*\{\s*\}", line):
                self._add(file_path, "ALIBABA_EMPTY_CATCH_BRACE",
                          "大括号内为空时应简洁地写成 {}",
                          Severity.INFO, line=i)

    # ==================== (四) OOP 规约 ====================
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
                                            break

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

    # ==================== (五) 日期时间 ====================
    def check_date(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_date"):
            return
        lines = content.split("\n")
        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                ip = node.path or ""
                if ip in ("java.sql.Date", "java.sql.Time", "java.sql.Timestamp"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_NO_SQL_DATE",
                              f"禁止使用 {ip}，应使用 java.util.Date 或 JDK8 时间类",
                              Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+Date\(\)\.getTime\(\)", line):
                self._add(file_path, "ALIBABA_CURRENT_TIME_MILLIS",
                          "获取当前毫秒数应使用 System.currentTimeMillis() 而不是 new Date().getTime()",
                          Severity.INFO, line=i)
            if re.search(r"YYYY", line) and not re.search(r"//\s*", line):
                self._add(file_path, "ALIBABA_DATE_FORMAT_YEAR",
                          "日期格式化时表示年份应使用小写 yyyy，大写 YYYY 表示 week in which year",
                          Severity.WARNING, line=i)

            if re.search(r"SimpleDateFormat.*\"", line):
                m = re.search(r"SimpleDateFormat.*\"([^\"]+)\"", line)
                if m:
                    fmt = m.group(1)
                    has_valid = False
                    if "M" in fmt and "m" in fmt:
                        self._add(file_path, "ALIBABA_DATE_FORMAT_CASE",
                                  "日期格式中月份为大写 M，分钟为小写 m，请勿混淆",
                                  Severity.WARNING, line=i)
                        has_valid = True
                    if "H" in fmt and "h" in fmt:
                        self._add(file_path, "ALIBABA_DATE_FORMAT_CASE",
                                  "日期格式中 24 小时制为大写 H，12 小时制为小写 h，请确认意图",
                                  Severity.WARNING, line=i)
                        has_valid = True
                    if re.search(r"[Mm]{3,}", fmt):
                        self._add(file_path, "ALIBABA_DATE_FORMAT_CASE",
                                  "月份格式 MMM/MMMM 可能不符合预期，推荐使用 MM",
                                  Severity.INFO, line=i)

            if re.search(r"365", line) and re.search(r"(day|year|date|DAYS|Calendar)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_HARDCODED_365",
                          "禁止在程序中写死一年为 365 天，应使用 LocalDate.lengthOfYear() 等方式",
                          Severity.WARNING, line=i)

    # ==================== (六) 集合处理 ====================
    def check_collection(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_collection"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                has_equals = any(
                    isinstance(n2, javalang.tree.MethodDeclaration) and n2.name == "equals"
                    for p2, n2 in tree
                )
                has_hashcode = any(
                    isinstance(n2, javalang.tree.MethodDeclaration) and n2.name == "hashCode"
                    for p2, n2 in tree
                )
                if has_equals and not has_hashcode:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_HASHCODE_EQUALS",
                              "覆写 equals 时必须同时覆写 hashCode",
                              Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and \
               node.member == "toMap" and node.qualifier and \
               "Collectors" in str(node.qualifier):
                line_num = node.position.line if node.position else 0
                args_str = content.split("\n")[line_num - 1] if 0 < line_num <= len(lines) else ""
                if "BinaryOperator" not in args_str:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_TO_MAP_MERGE",
                              "Collectors.toMap() 必须使用参数类型为 BinaryOperator 的 mergeFunction 方法",
                              Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"\.size\(\)\s*==\s*0", line) and not re.search(r"//.*\.size\(\)", line):
                self._add(file_path, "ALIBABA_IS_EMPTY",
                          "判断集合是否为空应使用 isEmpty() 方法，而不是 size() == 0",
                          Severity.INFO, line=i, column=line.find(".size()"))

            if re.search(r"for\s*\([^:]+:\s*\w+\)", line):
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"\.remove\(", lines[j - 1]):
                        self._add(file_path, "ALIBABA_FOREACH_REMOVE",
                                  "不要在 foreach 循环里进行元素的 remove 操作，请使用 iterator 方式",
                                  Severity.WARNING, line=j)
                        break
                    if j <= len(lines) and re.search(r"^\s*\}", lines[j - 1]):
                        break

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and node.member == "toArray" and \
               not node.arguments:
                l, c = self._pos(node)
                self._add(file_path, "ALIBABA_TO_ARRAY",
                          "使用集合转数组时，必须使用 toArray(T[])，传入类型一致的空数组",
                          Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+(HashMap|ArrayList|HashSet|LinkedHashMap|LinkedHashSet)\s*\(\s*\)", line):
                self._add(file_path, "ALIBABA_INIT_CAPACITY",
                          "集合初始化时应指定初始值大小，如 new HashMap<>(16)",
                          Severity.INFO, line=i)

            if re.search(r"new\s+(HashMap|ArrayList|HashSet|HashMap|LinkedHashMap|LinkedHashSet)\s*<", line) and \
               not re.search(r"new\s+\w+\s*<>", line):
                self._add(file_path, "ALIBABA_DIAMOND_OP",
                          "使用菱形语法 <> 简化泛型声明，如 new ArrayList<>()",
                          Severity.INFO, line=i)

            if re.search(r"Arrays\.asList\(\s*[^)]*\s*\)\.add\(", line):
                self._add(file_path, "ALIBABA_ASLIST_MODIFY",
                          "Arrays.asList() 返回的列表不可变，不能调用 add/remove/clear 方法",
                          Severity.WARNING, line=i)
            if re.search(r"Arrays\.asList\(\s*[^)]*\s*\)\.remove\(", line):
                self._add(file_path, "ALIBABA_ASLIST_MODIFY",
                          "Arrays.asList() 返回的列表不可变，不能调用 add/remove/clear 方法",
                          Severity.WARNING, line=i)

            if re.search(r"\.subList\(", line):
                self._add(file_path, "ALIBABA_SUBLIST_ARRAYLIST",
                          "subList() 返回的是原集合的内部类视图，不可强转为 ArrayList，且对原集合的修改可能导致视图异常",
                          Severity.INFO, line=i)

            if re.search(r"\.put\s*\(\s*[^,]+,\s*null\s*\)", line):
                self._add(file_path, "ALIBABA_MAP_NULL_VALUE",
                          "Map 的 value 不应存储 null 值，以免在使用 containsKey 判断时混淆",
                          Severity.WARNING, line=i)

            if re.search(r"\.(keySet|values|entrySet)\s*\(\s*\)\s*\.\s*add\s*\(", line):
                self._add(file_path, "ALIBABA_VIEW_ADD",
                          "Map 的 keySet/values/entrySet 返回的集合不可添加元素",
                          Severity.WARNING, line=i)

            if re.search(r"\.addAll\s*\([^)]+\)", line):
                prev_lines = [lines[j] for j in range(max(0, i-6), i-1)]
                has_null_check = any("null" in pl for pl in prev_lines)
                if not has_null_check:
                    self._add(file_path, "ALIBABA_ADDALL_NPE",
                              "使用 addAll 方法时，要对输入的集合参数进行 NPE 判断",
                              Severity.INFO, line=i)

        # 6.18 entrySet over keySet - detect keySet() loop followed by .get()
        for i, line in enumerate(lines, 1):
            if re.search(r"\.keySet\s*\(\)", line):
                for j in range(i, min(i + 15, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"\.get\s*\(", lines[j - 1]):
                        self._add(file_path, "ALIBABA_KEYSET_LOOP",
                                  "遍历 Map 推荐使用 entrySet 而非 keySet，避免重复 get 调用",
                                  Severity.INFO, line=i)
                        break
                    if j <= len(lines) and re.search(r"^\s*\}", lines[j - 1]):
                        break

        # 6.21 Set for dedup
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(for|while)\s*\(", line):
                loop_start = i
                for j in range(i, min(i + 15, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"\.contains\(", lines[j - 1]):
                        m = re.search(r"(\w+)\.contains\(", lines[j - 1])
                        if m and m.group(1)[0].islower():
                            self._add(file_path, "ALIBABA_LIST_CONTAINS",
                                      "利用 Set 元素唯一的特性，可快速去重，避免使用 List 的 contains() 遍历",
                                      Severity.INFO, line=j)
                        break
                    if j <= len(lines) and re.search(r"^\s*\}", lines[j - 1]):
                        break

        # 6.7 Collections.emptyList/singletonList immutable
        for i, line in enumerate(lines, 1):
            if re.search(r"Collections\.(empty|singleton)\w*\s*\(\s*\)\s*\.\s*(add|remove|clear)\s*\(", line):
                self._add(file_path, "ALIBABA_IMMUTABLE_COLLECTION",
                          "Collections.emptyList()/singletonList() 等返回的是不可变集合，不能调用 add/remove/clear",
                          Severity.WARNING, line=i)

        # 6.13 Raw type collections
        for path, node in tree:
            if not isinstance(node, javalang.tree.VariableDeclaration):
                continue
            if not hasattr(node, "type") or not node.type:
                continue
            if not hasattr(node.type, "name"):
                continue
            if node.type.name not in ("List", "Map", "Set", "ArrayList", "HashMap", "HashSet"):
                continue
            has_type_args = hasattr(node.type, "type_arguments") and node.type.type_arguments
            if has_type_args:
                continue
            for decl in node.declarators:
                init = getattr(decl, "initializer", None)
                if init and hasattr(init, "type_arguments") and not init.type_arguments:
                    continue
                if init and isinstance(init, javalang.tree.MethodInvocation) and \
                   "asList" in str(init):
                    continue
                l, c = self._pos(decl)
                self._add(file_path, "ALIBABA_RAW_TYPE",
                          "在无泛型限制定义的集合赋值给泛型限制的集合时，在进行元素使用时需要做 instanceof 判断",
                          Severity.INFO, line=l, column=c)

        # ==================== (八) 控制语句 ====================
    def check_control(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_control"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.SwitchStatement):
                has_default = any(child.case is None for child in node.cases)
                if not has_default:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_SWITCH_DEFAULT",
                              "switch 块内必须包含一个 default 语句",
                              Severity.WARNING, line=l, column=c)
                for case in node.cases:
                    if case.case is not None:
                        stmts = case.statements or []
                        if stmts and not any(
                            isinstance(s, (javalang.tree.BreakStatement,
                                           javalang.tree.ReturnStatement,
                                           javalang.tree.ContinueStatement))
                            for s in stmts
                        ):
                            cl = case.case.position.line if hasattr(case.case, "position") and case.case.position else 0
                            self._add(file_path, "ALIBABA_SWITCH_BREAK",
                                      "switch 的每个 case 必须通过 break/return 等来终止",
                                      Severity.WARNING, line=cl)

        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|else\s+if|for|while|do)\s*\([^)]*\)\s*[^\s{;]", line) and \
               not re.search(r"\{\s*$", line):
                self._add(file_path, "ALIBABA_REQUIRE_BRACES",
                          "if/else/for/while/do 语句中必须使用大括号",
                          Severity.WARNING, line=i)

        for i, line in enumerate(lines, 1):
            m = re.search(r"\(\s*([a-zA-Z_]\w*)\s*==\s*null\s*\)\s*\?\s*([^:]+)\s*:\s*(\2)", line)
            if m:
                self._add(file_path, "ALIBABA_TERNARY_NPE",
                          "三元表达式可能引发空指针 NPE，注意自动拆箱导致的 NullPointerException",
                          Severity.INFO, line=i)

        # 8.2 - switch String null check
        in_switch = False
        for i, line in enumerate(lines, 1):
            if re.search(r"switch\s*\(\s*\w+\s*\)", line):
                in_switch = True
                continue
            if in_switch and re.search(r"^\s*\}\s*$", line):
                in_switch = False
            if in_switch and re.search(r"case\s+", line):
                self._add(file_path, "ALIBABA_SWITCH_STRING",
                          "当 switch 括号内的变量类型为 String 并且此变量为外部参数时，必须先进行 null 判断",
                          Severity.INFO, line=i)
                in_switch = False

        # 8.7 - if-else depth (simplified check for nested if)
        if_depth = 0
        max_depth = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("if") or stripped.startswith("else if"):
                if_depth += 1
                max_depth = max(max_depth, if_depth)
            elif stripped.startswith("}") or stripped.startswith("}"):
                if_depth = max(0, if_depth - 1)
        if max_depth > 3:
            self._add(file_path, "ALIBABA_IF_DEPTH",
                      "if-else 层级超过 3 层，建议使用卫语句、策略模式或状态模式重构",
                      Severity.INFO, line=0)

        # 8.9 No assignment in conditions
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|while)\s*\([^)]*=\s*[^=]", line) and \
               not re.search(r"[=!]=|&&|\|\|", line):
                code_part = re.sub(r"//.*|/\*.*?\*/|\".*?\"", "", line, flags=re.DOTALL)
                if "=" in code_part:
                    self._add(file_path, "ALIBABA_ASSIGN_IN_CONDITION",
                              "不要在条件表达式中插入赋值语句，赋值语句应清晰单独成为一行",
                              Severity.WARNING, line=i)

        # 8.11 Avoid negation
        for i, line in enumerate(lines, 1):
            if re.search(r"if\s*\(\s*!\(", line) and \
               not re.search(r"//.*if", line):
                self._add(file_path, "ALIBABA_AVOID_NOT",
                          "避免采用取反逻辑运算符，建议使用正向逻辑表达",
                          Severity.INFO, line=i)

        # 8.12 Public method input parameter validation
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []) and \
               node.name not in ("main", "toString", "equals", "hashCode", "get", "set",
                                "getClass", "notify", "wait"):
                has_object_param = False
                has_null_check = False
                body_stmts = node.body if isinstance(node.body, list) else \
                            getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body_stmts:
                    if isinstance(stmt, javalang.tree.IfStatement) and \
                       hasattr(stmt, "expression") and stmt.expression and \
                       "null" in str(stmt.expression):
                        has_null_check = True
                for param in (node.parameters or []):
                    pt = getattr(param, "type", None)
                    if pt and hasattr(pt, "name") and pt.name == "Object":
                        has_object_param = True
                    elif pt and hasattr(pt, "name") and pt.name not in (
                        "int", "long", "double", "float", "boolean", "char", "byte", "short",
                        "String", "Integer", "Long", "Double", "Float", "Boolean"
                    ):
                        has_object_param = True
                if has_object_param and not has_null_check and len(body_stmts) > 2:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_PARAM_VALIDATION",
                              "公开接口需要进行入参保护，对参数进行有效性验证",
                              Severity.INFO, line=l, column=c)

        # 8.10 Object creation in loop
        for path, node in tree:
            if isinstance(node, (javalang.tree.ForStatement, javalang.tree.WhileStatement)):
                body = node.body if isinstance(node.body, list) else \
                       getattr(getattr(node, "body", None), "statements", []) or []
                new_count = sum(1 for s in body if "new " in str(s))
                if new_count > 3:
                    l = node.position.line if node.position else 0
                    self._add(file_path, "ALIBABA_LOOP_OBJECT_CREATION",
                              "循环体中的对象定义应尽量移至循环体外处理，提升性能",
                              Severity.INFO, line=l)

    # ==================== (七) 并发处理 ====================
    def check_concurrency(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_concurrency"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+Thread\s*\(\s*\)", line):
                self._add(file_path, "ALIBABA_THREAD_NAME",
                          "创建线程或线程池时请指定有意义的线程名称，方便出错时回溯",
                          Severity.INFO, line=i)
        for i, line in enumerate(lines, 1):
            if re.search(r"\bnew\s+Thread\b", line) and not re.search(r"new\s+Thread\s*\([^)]+\)\s*\{", line):
                self._add(file_path, "ALIBABA_NEW_THREAD",
                          "线程创建应使用线程池（ThreadPoolExecutor），避免显式 new Thread",
                          Severity.WARNING, line=i)
            if re.search(r"Executors\.new(Cached|Fixed|Single|Scheduled)Thread", line):
                self._add(file_path, "ALIBABA_EXECUTORS_POOL",
                          "应使用 ThreadPoolExecutor 创建线程池，而非 Executors 工具类",
                          Severity.WARNING, line=i)
            if re.search(r"new\s+T\w*imerTask\b", line) or \
               re.search(r"new\s+Timer\b", line):
                self._add(file_path, "ALIBABA_TIMER_TASK",
                          "Timer/TimerTask 应使用 ScheduledExecutorService 替代",
                          Severity.WARNING, line=i)
            if re.search(r"private\s+static\s+final\s+SimpleDateFormat\b", line):
                self._add(file_path, "ALIBABA_SIMPLE_DATE_FORMAT",
                          "SimpleDateFormat 是线程不安全的类，应使用 ThreadLocal 或 DateTimeFormatter",
                          Severity.WARNING, line=i)
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member == "lock" and isinstance(getattr(node, "qualifier", None), javalang.tree.MemberReference):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_LOCK_IN_TRY",
                              "Lock 的 lock() 方法调用必须紧跟 try 语句，并在 finally 中 unlock()",
                              Severity.WARNING, line=l, column=c)
                    break
        for i, line in enumerate(lines, 1):
            if re.search(r"tryLock\s*\([^)]*\)\s*;\s*$", line) or \
               re.search(r"tryLock\s*\([^)]*\)\s*\)\s*;", line):
                self._add(file_path, "ALIBABA_TRYLOCK_CHECK",
                          "tryLock() 调用后必须检查返回值",
                          Severity.WARNING, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "ThreadLocal" in vtype:
                    for decl in node.declarators:
                        after = content[decl.position.offset:decl.position.offset + 5000] if decl.position else ""
                        if ".remove()" not in after and ".set(null)" not in after:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_THREADLOCAL_CLEANUP",
                                      "必须回收自定义的 ThreadLocal 变量记录的当前线程值，应在 finally 中调用 remove()",
                                      Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "ThreadLocal" in vtype:
                    mods = node.modifiers or []
                    if "static" not in mods:
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_THREADLOCAL_STATIC",
                                      "ThreadLocal 对象必须使用 static 修饰",
                                      Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"Random\s+\w+\s*=\s*new\s+Random\b", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "ALIBABA_RANDOM_INSTANCE",
                          "避免 Random 实例被多线程使用，推荐使用 ThreadLocalRandom",
                          Severity.INFO, line=i)

        # 7.16 Double-checked locking without volatile
        for path, node in tree:
            if isinstance(node, javalang.tree.SynchronizedStatement):
                body_stmts = node.body if isinstance(node.body, list) else \
                            getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body_stmts:
                    if isinstance(stmt, javalang.tree.IfStatement) and \
                       hasattr(stmt, "expression") and stmt.expression:
                        if_str = str(stmt.expression)
                        if "null" in if_str and "==" in if_str:
                            l = node.position.line if node.position else 0
                            for p2, n2 in tree:
                                if isinstance(n2, javalang.tree.FieldDeclaration) and \
                                   "volatile" not in (n2.modifiers or []):
                                    for decl in n2.declarators:
                                        df = str(decl)
                                        if df.split("=")[0].strip() in if_str:
                                            ll, cc = self._pos(decl)
                                            self._add(file_path, "ALIBABA_DCL_VOLATILE",
                                                      "双重检查锁（double-checked locking）实现延迟初始化需要将目标属性声明为 volatile",
                                                      Severity.WARNING, line=ll, column=cc)
                                            break

        # 7.14 CountDownLatch without guaranteed countDown
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and \
               node.member == "await" and \
               hasattr(node, "qualifier") and "CountDownLatch" in str(node.qualifier):
                l = node.position.line if hasattr(node, "position") and node.position else 0
                for j in range(max(0, l - 2), l + 30):
                    if j < len(lines) and "countDown" not in lines[j] and \
                       j < len(lines) and "finally" in lines[j]:
                        break
                else:
                    if l > 0:
                        self._add(file_path, "ALIBABA_COUNTDOWN_AWAIT",
                                  "使用 CountDownLatch 进行异步转同步，每个线程退出前必须调用 countDown 方法，确保在 finally 中执行",
                                  Severity.WARNING, line=l)

    # ==================== (九) 注释规约 ====================
    def check_comment(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_comment"):
            return
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            if re.search(r"TODO", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_TODO",
                          "存在 TODO 标记，请注明标记人与标记时间并及时处理",
                          Severity.INFO, line=i)
            if re.search(r"FIXME", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_FIXME",
                          "存在 FIXME 标记，请注明标记人与标记时间并及时处理",
                          Severity.INFO, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.EnumDeclaration):
                for decl in (node.body or []):
                    if isinstance(decl, javalang.tree.EnumConstantDeclaration):
                        cl = decl.position.line if decl.position else 0
                        if cl >= 2 and cl <= len(lines) + 1:
                            prev_line = lines[cl - 2] if cl >= 2 else ""
                            if not prev_line.strip().startswith(("//", "/*", "*", "/**")):
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_ENUM_COMMENT",
                                          f"枚举项 '{decl.name}' 缺少注释说明",
                                          Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cl = node.position.line if node.position else 0
                has_javadoc = False
                for jj in range(max(0, cl - 5), cl - 1):
                    if jj < len(lines) and re.search(r"/\*\*", lines[jj]):
                        has_javadoc = True
                        break
                if not has_javadoc:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_CLASS_JAVADOC",
                              f"类 '{node.name}' 缺少 Javadoc 注释（创建者和创建日期）",
                              Severity.INFO, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               ("abstract" in (node.modifiers or []) or
                (isinstance(path[-2] if len(path) >= 2 else None, javalang.tree.InterfaceDeclaration))):
                ml = node.position.line if node.position else 0
                has_javadoc = False
                for jj in range(max(0, ml - 5), ml - 1):
                    if jj < len(lines) and re.search(r"/\*\*", lines[jj]):
                        has_javadoc = True
                        break
                if not has_javadoc:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_ABSTRACT_JAVADOC",
                              f"抽象方法（接口方法）'{node.name}' 必须使用 Javadoc 注释",
                              Severity.INFO, line=l, column=c)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") and re.search(
                r"\b(import |public |private |protected |class |interface |enum |void |return |throw |try |catch |if |for |while )",
                stripped
            ):
                self._add(file_path, "ALIBABA_COMMENTED_CODE",
                          "请删除被注释的代码，不要将无用代码保留在源码中",
                          Severity.INFO, line=i)

    # ==================== (二) 异常处理 ====================
    def check_exception(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_exception"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                for catch in (node.catches or []):
                    block = catch.block if hasattr(catch, "block") and catch.block else \
                            getattr(catch, "body", None)
                    body_stmts = block.statements if hasattr(block, "statements") else \
                                 (block if isinstance(block, list) else [])
                    non_comment_stmts = [s for s in body_stmts if not isinstance(s, javalang.tree.StatementExpression)]
                    if not non_comment_stmts:
                        cl = catch.parameter.position.line if catch.parameter and catch.parameter.position else 0
                        self._add(file_path, "ALIBABA_EMPTY_CATCH",
                                  "捕获异常是为了处理它，不要捕获了却什么都不处理而抛弃之",
                                  Severity.WARNING, line=cl)

        # 6 - Close resources in finally / use try-with-resources
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+(File(Input|Output)Stream|FileReader|FileWriter|BufferedReader|BufferedWriter"
                         r"|InputStreamReader|OutputStreamWriter)", line):
                for j in range(i, min(i + 30, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"\.close\s*\(\)", lines[j - 1]):
                        break
                else:
                    close_seen = False
                    for j in range(i, min(i + 30, len(lines) + 1)):
                        if j <= len(lines) and re.search(r"try\s*[({]|try\s*[\(]", lines[j - 1]):
                            parent_line = re.search(r"try\s*[(]?\s*[^)]*" + re.escape(line.strip()[:20]), lines[j - 1]) if j - 1 < len(lines) else None
                            break
                    self._add(file_path, "ALIBABA_STREAM_CLOSE",
                              "IO 流必须通过 finally 块 close 关闭或使用 try-with-resources 方式",
                              Severity.WARNING, line=i)

        # 11 - NPE from auto-unboxing
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ret_type = getattr(node, "return_type", None)
                if ret_type and hasattr(ret_type, "name") and ret_type.name in ("int", "long", "boolean", "double"):
                    for p2, n2 in tree:
                        if isinstance(n2, javalang.tree.ReturnStatement) and \
                           hasattr(n2, "expression") and n2.expression and \
                           hasattr(n2.expression, "qualifier") and \
                           isinstance(n2.expression.qualifier, javalang.tree.MemberReference):
                            pass
                        elif isinstance(n2, javalang.tree.ReturnStatement) and \
                             hasattr(n2, "expression") and n2.expression and \
                             hasattr(n2.expression, "prefix_operators") and \
                             "(" in str(getattr(n2.expression, "selectors", [])):
                            pass

        for i, line in enumerate(lines, 1):
            if re.search(r"\breturn\s+(Integer|Long|Boolean|Double|Float)\.valueOf\(", line) and \
               re.search(r"(int|long|boolean|double|float)\s+\w+\s*=", line):
                self._add(file_path, "ALIBABA_NPE_AUTOBOX",
                          "注意自动拆箱可能产生 NPE，返回包装类型对象给基本类型时可能为 null",
                          Severity.WARNING, line=i)

        for i, line in enumerate(lines, 1):
            if re.search(r"catch\s*\(\s*(NullPointerException|IndexOutOfBoundsException|"
                         r"ArithmeticException|ClassCastException)", line):
                self._add(file_path, "ALIBABA_CATCH_RUNTIME",
                          "可通过预检查规避的 RuntimeException 不应通过 catch 方式处理",
                          Severity.WARNING, line=i)

        in_finally = False
        for i, line in enumerate(lines, 1):
            if re.search(r"finally\s*\{", line):
                in_finally = True
                continue
            if in_finally:
                if re.search(r"\breturn\b", line) and not re.search(r"//.*return", line):
                    self._add(file_path, "ALIBABA_FINALLY_RETURN",
                              "不要在 finally 块中使用 return，会丢弃 try 块中的返回值",
                              Severity.WARNING, line=i)
                    in_finally = False
                if re.search(r"^\s*\}", line):
                    in_finally = False

        # 12 - Don't throw raw RuntimeException/Exception
        for i, line in enumerate(lines, 1):
            if re.search(r"throw\s+new\s+(RuntimeException|Exception)\s*\(", line) and \
               not re.search(r"//.*throw", line):
                self._add(file_path, "ALIBABA_RAW_EXCEPTION",
                          "禁止直接抛出 RuntimeException 或 Exception，应使用有业务含义的自定义异常",
                          Severity.WARNING, line=i)
            if re.search(r"catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)", line) and \
               not re.search(r"(RPC|反射|reflect|Proxy|动态)", content, re.IGNORECASE):
                self._add(file_path, "ALIBABA_CATCH_GENERIC",
                          "catch 时应尽可能区分异常类型，避免使用 Exception/Throwable 捕获所有异常",
                          Severity.INFO, line=i)

    # ==================== (三) 日志规约 ====================
    def check_logging(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_logging"):
            return
        lines = content.split("\n")

        uses_log4j = False
        uses_slf4j = False
        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                ip = node.path or ""
                if "org.apache.log4j" in ip or "org.apache.logging" in ip:
                    uses_log4j = True
                if "org.slf4j" in ip:
                    uses_slf4j = True

        if uses_log4j and not uses_slf4j:
            for path, node in tree:
                if isinstance(node, javalang.tree.Import) and \
                   ("org.apache.log4j" in (node.path or "") or "org.apache.logging" in (node.path or "")):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_LOG_FACADE",
                              "应使用 SLF4J 门面模式的日志框架，而非直接使用 Log4j/Logback API",
                              Severity.WARNING, line=l, column=c)
                    break

        for i, line in enumerate(lines, 1):
            if re.search(r'logger\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+', line) or \
               re.search(r'log\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+', line):
                self._add(file_path, "ALIBABA_LOG_PLACEHOLDER",
                          "日志字符串拼接应使用占位符 {} 方式，如 logger.info(\"msg {}\", var)",
                          Severity.INFO, line=i)

            if re.search(r'logger\.(debug|trace)\s*\(', line) and \
               not re.search(r'is(Debug|Trace)Enabled', line):
                self._add(file_path, "ALIBABA_LOG_LEVEL_CHECK",
                          "trace/debug 级别日志输出必须进行级别开关判断",
                          Severity.INFO, line=i)

            if re.search(r"System\.(out|err)\.(print|println|printf)", line):
                self._add(file_path, "ALIBABA_SYSTEM_OUT",
                          "生产环境禁止使用 System.out/err 输出或使用 e.printStackTrace() 打印异常堆栈",
                          Severity.WARNING, line=i)
            if re.search(r"\.printStackTrace\s*\(\)", line):
                self._add(file_path, "ALIBABA_SYSTEM_OUT",
                          "生产环境禁止使用 System.out/err 输出或使用 e.printStackTrace() 打印异常堆栈",
                          Severity.WARNING, line=i)

    # ==================== (十一) 其他 ====================
    def check_other(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_other"):
            return
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            if re.search(r"Pattern\s+\w+\s*=\s*Pattern\.compile\(", line) and \
               not re.search(r"(static|final)\s", lines[i - 2] if i >= 2 else ""):
                self._add(file_path, "ALIBABA_PATTERN_COMPILE",
                          "正则表达式应利用预编译功能，将 Pattern 定义为 static final 常量",
                          Severity.WARNING, line=i)

            if re.search(r"BeanUtils\.copyProperties\(", line) or \
               re.search(r"org\.apache\.commons\.beanutils", line):
                self._add(file_path, "ALIBABA_BEANUTILS",
                          "避免使用 Apache BeanUtils 进行属性拷贝（性能较差），推荐 Spring BeanUtils 或 Cglib BeanCopier",
                          Severity.WARNING, line=i)

            if re.search(r"new\s+BigDecimal\s*\(\s*\d+\.\d+\s*\)", line):
                self._add(file_path, "ALIBABA_BIGDECIMAL_CONSTRUCTOR",
                          "禁止使用 BigDecimal(double) 构造方法，应使用 BigDecimal(String) 或 BigDecimal.valueOf()",
                          Severity.WARNING, line=i)

            if re.search(r"Math\.random\(\)", line):
                self._add(file_path, "ALIBABA_MATH_RANDOM",
                          "注意 Math.random() 返回 double 类型，取值范围 0≤x<1，建议使用 Random 或 ThreadLocalRandom",
                          Severity.INFO, line=i)

            if re.search(r"\.executeQuery\s*\(\s*\"", line) or \
               re.search(r"\.executeUpdate\s*\(\s*\"", line) or \
               re.search(r"\.prepareStatement\s*\(\s*\"", line):
                pass  # Already using parameterized query - OK
            elif re.search(r"(SELECT|INSERT|UPDATE|DELETE)\s", line, re.IGNORECASE) and \
                 re.search(r"\+", line) and \
                 not re.search(r"//", line):
                self._add(file_path, "ALIBABA_SQL_INJECTION",
                          "禁止字符串拼接 SQL 语句，应使用参数绑定方式防止 SQL 注入",
                          Severity.WARNING, line=i)

            # 2.1 Magic string values
            if re.search(r'\.equals\s*\(\s*"', line) or \
               re.search(r'\.put\s*\(\s*"', line) or \
               re.search(r'case\s+"', line):
                m = re.search(r'"(?:[^"\\]|\\.)*"', line)
                if m and not re.search(r'static\s+final\s+\w+\s*=\s*', line):
                    literal = m.group(0)
                    if len(literal) > 5 and len(literal) < 40:
                        self._add(file_path, "ALIBABA_MAGIC_STRING",
                                  f"不允许魔法值（未经预先定义的常量）直接出现在代码中: {literal}",
                                  Severity.INFO, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.EnumDeclaration):
                for decl in (node.body or []):
                    if isinstance(decl, javalang.tree.FieldDeclaration):
                        mods = decl.modifiers or []
                        if not any(m in mods for m in ("private", "public", "protected")):
                            for declarator in decl.declarators:
                                l, c = self._pos(declarator)
                                self._add(file_path, "ALIBABA_ENUM_FIELD_VISIBILITY",
                                          f"枚举成员变量 '{declarator.name}' 必须私有且不可变",
                                          Severity.WARNING, line=l, column=c)
                        if "static" not in mods:
                            for declarator in decl.declarators:
                                l, c = self._pos(declarator)
                                self._add(file_path, "ALIBABA_ENUM_FIELD_VISIBILITY",
                                          f"枚举成员变量 '{declarator.name}' 必须私有且不可变",
                                          Severity.WARNING, line=l, column=c)

    def check_method_length(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_method_length"):
            return
        max_lines = self.config.get_rule_config("alibaba_method_length").get("max_lines", 80)
        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            if method.position:
                start_line = method.position.line
                body_lines = 0
                if method.body:
                    stmts = method.body if isinstance(method.body, list) else getattr(method.body, "statements", [])
                    if stmts:
                        last = stmts[-1]
                        if hasattr(last, "position") and last.position:
                            body_lines = last.position.line - start_line
                if body_lines > max_lines:
                    l, c = self._pos(method)
                    self._add(file_path, "ALIBABA_METHOD_LENGTH",
                              f"方法 '{method.name}' 总行数 {body_lines} 超过建议值 {max_lines} 行",
                              Severity.WARNING, line=l, column=c)

    def run_all(self, tree, file_path: str, content: str):
        self.check_naming(tree, file_path, content)
        self.check_code_style(tree, file_path, content)
        self.check_oop(tree, file_path, content)
        self.check_date(tree, file_path, content)
        self.check_collection(tree, file_path, content)
        self.check_control(tree, file_path, content)
        self.check_concurrency(tree, file_path, content)
        self.check_comment(tree, file_path, content)
        self.check_constant(tree, file_path, content)
        self.check_exception(tree, file_path, content)
        self.check_logging(tree, file_path, content)
        self.check_other(tree, file_path, content)
        self.check_method_length(tree, file_path, content)
