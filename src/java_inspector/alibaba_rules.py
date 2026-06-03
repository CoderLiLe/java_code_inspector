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

            # 1.12 Bad abbreviations dictionary
            BAD_ABBREVS = re.compile(
                r"\b(AbsClass|condi|Fu|msgUtil|dateUtil|numUtil|strUtil|objUtil|"
                r"tempUtil|DbHelper|BizHelper|CommHelper|MgrHelper|"
                r"intVal|strVal|boolVal|objVal|"
                r"paramMap|paramList|retMap|retList|"
                r"respDTO|reqDTO|queryParam|pageQuery)\b"
            )
            m = BAD_ABBREVS.search(line)
            if m:
                self._add(file_path, "ALIBABA_BAD_ABBREVIATION",
                          f"杜绝完全不规范的英文缩写 '{m.group(1)}'，避免望文不知义",
                          Severity.WARNING, line=i, column=line.find(m.group(1)))

            # 1.13 Single-letter variable names (1-3 char, excluding loop vars)
            code_part = re.sub(r"//.*|/\*.*?\*/|\".*?\"", "", line, flags=re.DOTALL)
            m = re.search(r"\b(int|long|String|boolean|double|float|Object|List|Map)\s+([a-z])[^a-zA-Z]", code_part)
            if m and m.group(2) not in ("i", "j", "k", "x", "y", "z"):
                self._add(file_path, "ALIBABA_SINGLE_LETTER_VAR",
                          f"变量名 '{m.group(2)}' 过于简短，应使用完整的单词组合来表达语义",
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
            if re.search(r"\b_\w+", line) and not re.search(r"\"", line):
                m = re.search(r"\b(_+[a-zA-Z]\w*)", line)
                if m and not re.search(r"_\s*=|_\s*\)|_\s*;", line):
                    self._add(file_path, "ALIBABA_UNDERSCORE_NAME",
                              "命名不能以下划线开始或结束",
                              Severity.WARNING, line=i, column=line.find(m.group(1)))
            if re.search(r"\w+_\b", line) and not re.search(r"\"", line):
                m = re.search(r"([a-zA-Z]\w*_+)\b", line)
                if m and not re.search(r"__|_\s*=|_\s*\)", line):
                    self._add(file_path, "ALIBABA_UNDERSCORE_NAME",
                              "命名不能以下划线开始或结束",
                              Severity.WARNING, line=i, column=line.find(m.group(1)))

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

        # 1.14 Type noun at end of name
        for i, line in enumerate(lines, 1):
            m = re.search(r"\b(int|long|String|boolean|double|float|Date|List|Set|Map|Collection)\s+(\w+)(Time|List|Set|Map|Count|Num|Price|Amount|Code|Name|Desc|Type|Status|Url|Id|Key|Value|Rate|Ratio|Level|Size|Sum|Total|Avg)", line)
            if m:
                var_name = m.group(2) + m.group(3)
                if m.group(2)[0].islower() and not m.group(2)[0].isupper():
                    pass
            m = re.search(r"\b(\w+)(Time|List|Set|Map|Count|Num|Amount|Code|Name|Desc|Type|Status|Id|Key|Value)\b.*=.*new\s+\w+", line)
            if m and m.group(1)[0].islower():
                self._add(file_path, "ALIBABA_TYPE_NOUN_SUFFIX",
                          f"变量 '{m.group(1)}{m.group(2)}' 中类型名词 '{m.group(2)}' 建议放在变量名末尾以提升辨识度",
                          Severity.INFO, line=i)

        # 1.15 Design pattern in name
        pattern_keywords = ["Factory", "Proxy", "Observer", "Strategy", "Adapter", "Facade",
                           "Decorator", "Template", "Iterator", "Builder", "Singleton",
                           "Prototype", "Chain", "Command", "Mediator", "Memento", "State",
                           "Visitor", "Composite", "Bridge", "Flyweight"]
        for path, node in tree:
            if isinstance(node, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                cn = node.name
                for pk in pattern_keywords:
                    if pk in cn and not cn.endswith(pk) and not cn.startswith("Abstract"):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_PATTERN_NAME",
                                  f"类 '{cn}' 包含设计模式名 '{pk}'，建议将模式名放在类名末尾如 '{cn.replace(pk, '')}{pk}'",
                                  Severity.INFO, line=l, column=c)
                        break

        # 1.19 Layer naming conventions for Service/DAO methods
        for path, node in tree:
            if isinstance(node, javalang.tree.InterfaceDeclaration):
                if node.name.endswith("Service") or node.name.endswith("DAO") or node.name.endswith("Mapper"):
                    for m in (node.body or []):
                        if isinstance(m, javalang.tree.MethodDeclaration):
                            mn = m.name
                            msg = None
                            if mn.startswith("find") and not mn.startswith("findBy"):
                                msg = f"DAO/Service 方法 '{mn}' 获取单个对象建议用 get 前缀，获取多个对象建议用 list 前缀"
                            elif mn.startswith("query"):
                                msg = f"DAO/Service 方法 '{mn}' 建议使用 get/list/count 前缀替代 query"
                            elif mn.startswith("delete") and not mn.startswith("deleteBy"):
                                msg = f"DAO/Service 方法 '{mn}' 删除建议用 remove/delete 前缀"
                            if msg:
                                l, c = self._pos(m)
                                self._add(file_path, "ALIBABA_LAYER_METHOD",
                                          msg, Severity.INFO, line=l, column=c)

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

            m = re.search(r"static\s+final\s+(int|long|String)\s+(\w+)\s*=\s*(\d+|'.')", line)
            if m:
                val = m.group(3)
                if val.isdigit() and int(val) in range(1, 13):
                    for j in range(max(0, i-3), i):
                        if re.search(r"enum", lines[j], re.IGNORECASE):
                            break
                    else:
                        pass

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

        # Magic values: hardcoded numbers (except 0,1,-1,2,3,100,1000,etc)
        COMMON_MAGIC = set(range(-1, 13)) | {60, 100, 200, 256, 365, 400, 500, 1000, 1024, 2048, 4096, 3600, 86400}
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"[^.\w](\d{3,})[^.\w]", line):
                val = int(m.group(1))
                if val not in COMMON_MAGIC and val % 1000 not in (0, 500):
                    if re.search(r"(if|else|return|throw|new)", line) and \
                       not re.search(r"//.*magic|//.*constant", line, re.IGNORECASE) and \
                       not re.search(r"@|\.\w+\s*=\s*\d", line):
                        self._add(file_path, "ALIBABA_MAGIC_NUMBER",
                                  f"魔法值 {val} 应定义为类或接口常量，避免直接使用",
                                  Severity.INFO, line=i)
                        break

        # Constants should be defined with final
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                mods = node.modifiers or []
                if "static" in mods and "final" not in mods and "public" in mods:
                    for decl in node.declarators:
                        if decl.name.isupper() and "_" in decl.name:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_CONST_FINAL",
                                      f"常量 '{decl.name}' 应为 static final",
                                      Severity.WARNING, line=l, column=c)

    # ==================== (三) 代码格式 ====================
    def check_code_style(self, tree, file_path: str, content: str):
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            # 3.2 Left brace spacing
            if re.search(r"(if|for|while|do|switch|try|catch|synchronized)\s*\([^)]*\)\s*[^\s{]", line) and \
               not re.search(r"\(\s*\)\s*;|\)\s*\{", line) and \
               not re.search(r"\{\s*$", line):
                pass

            if re.search(r"\b(if|while|for|switch|catch|synchronized)\(", line) and \
               not re.search(r"\b(if|while|for|switch|catch|synchronized)\s\(", line):
                kw = re.search(r"\b(if|while|for|switch|catch|synchronized)\(", line)
                if kw:
                    self._add(file_path, "ALIBABA_KEYWORD_SPACING",
                              f"'{kw.group(1)}' 关键字与括号之间必须加空格",
                              Severity.INFO, line=i)

            # 3.4 Operator spacing
            if re.search(r"\w(==|!=|<=|>=|&&|\|\|)\w", line) and \
               not re.search(r"[\"'].*[\+\-*/%=<>!&|].*[\"']", line) and \
               not re.search(r"import\s", line) and \
               not re.search(r"//", line):
                m = re.search(r"(\w)(==|!=|<=|>=|&&|\|\|)(\w)", line)
                if m and m.group(1)[-1].isalnum() and m.group(3)[0].isalnum():
                    if not re.search(re.escape(m.group(1)) + r"\s+" + re.escape(m.group(2)) + r"\s+" + re.escape(m.group(3)), line):
                        self._add(file_path, "ALIBABA_OPERATOR_SPACING",
                                  f"二目运算符 '{m.group(2)}' 左右两边都需要加一个空格",
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

            # 3.8 Line length 120
            if len(line.rstrip('\n')) > 120 and not re.match(r"^\s*(//|\*)", line) and \
               not re.search(r"https?://", line):
                self._add(file_path, "ALIBABA_LINE_LENGTH",
                          "单行字符数限制不超过 120 个，超出需要换行",
                          Severity.INFO, line=i)

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

        # 3.10 UTF-8 / Unix line endings
        if "\r\n" in content:
            self._add(file_path, "ALIBABA_LINE_ENDING",
                      "文件中使用了 Windows 格式换行符（CRLF），应使用 Unix 格式（LF）",
                      Severity.INFO, line=0)

        # 3.13 Blank lines between sections
        consecutive_blank = 0
        for i, line in enumerate(lines, 1):
            if line.strip() == "":
                consecutive_blank += 1
            else:
                if consecutive_blank > 2:
                    self._add(file_path, "ALIBABA_TOO_MANY_BLANKS",
                              "代码中不应出现连续超过 2 个空行",
                              Severity.INFO, line=i)
                consecutive_blank = 0

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
                body_str = str(node.body or "")
                if ".toString()" in body_str and "printStackTrace" not in body_str:
                    l = node.position.line if node.position else 0
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

            # 5.7 Use enum for months
            if re.search(r"\b(Calendar\.|new\s+GregorianCalendar\s*\()", line) and \
               re.search(r"\b(JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER)", line, re.IGNORECASE):
                pass

            if re.search(r"\b(1[0-2]|[1-9])\b.*\b(month|MONTH|Month)\b", line) and \
               not re.search(r"//", line) and \
               not re.search(r"Calendar\.", line):
                m = re.search(r"\b(1[0-2]|[1-9])\b", line)
                if m:
                    self._add(file_path, "ALIBABA_MONTH_ENUM",
                              "建议使用枚举值来指代月份，而非使用数字字面量",
                              Severity.INFO, line=i)

        # 1.8 Use JDK8 time API instead of java.util.Date/Calendar
        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                ip = node.path or ""
                if ip in ("java.util.Date", "java.util.Calendar", "java.text.SimpleDateFormat"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_USE_LOCALDATETIME",
                              f"避免使用 {ip}，推荐使用 JDK8 新时间 API（LocalDate/LocalTime/LocalDateTime/Instant）",
                              Severity.INFO, line=l, column=c)

        # 1.9 Time should always carry time zone
        for i, line in enumerate(lines, 1):
            if re.search(r"@JsonFormat", line) and \
               not re.search(r"timezone|TimeZone|GMT|UTC|Asia/Shanghai", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_TIME_ZONE",
                          "序列化日期时建议指定 timezone 参数",
                          Severity.INFO, line=i)

        # 1.12 Do not use int for timestamp
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name == "int" and not ft.name == "long":
                    for decl in node.declarators:
                        fn = decl.name.lower()
                        if any(kw in fn for kw in ("timestamp", "create_time", "update_time", "createTime", "updateTime", "expire_time")):
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_TIMESTAMP_INT",
                                      f"时间戳字段 '{decl.name}' 使用 long 而非 int",
                                      Severity.WARNING, line=l, column=c)

        # 1.5 Do not use Calendar.get() with magic numbers
        for i, line in enumerate(lines, 1):
            if re.search(r"Calendar\.get\(", line) and \
               re.search(r"\b(0|7|8|9|10|11|12)\b", line) and \
               not re.search(r"Calendar\.(YEAR|MONTH|DATE|HOUR|MINUTE|SECOND|MILLISECOND)", line):
                self._add(file_path, "ALIBABA_CALENDAR_MAGIC",
                          "Calendar 获取值请使用常量如 Calendar.DAY_OF_MONTH 而非数字",
                          Severity.INFO, line=i)

        # 1.6 Leap year: 2/29 hardcoded
        for i, line in enumerate(lines, 1):
            if re.search(r"(02-29|02/29|2-29|2/29|\"Feb 29\"|'Feb 29'|February 29|2月29)", line) and \
               not re.search(r"//.*闰年|//.*leap|//.*valid", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_LEAP_YEAR_FEB29",
                          "避免硬编码 2 月 29 日，闰年 2 月 29 日需要特殊处理",
                          Severity.INFO, line=i)

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

        # 6.4 toMap null value NPE
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and \
               node.member == "toMap" and node.qualifier and \
               "Collectors" in str(node.qualifier):
                line_num = node.position.line if node.position else 0
                args_str = content.split("\n")[line_num - 1] if 0 < line_num <= len(lines) else ""
                if "null" in args_str.split("value")[-1] if "value" in args_str else args_str:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_TO_MAP_NULL_VALUE",
                              "Collectors.toMap() 方法转为 Map 时，当 value 为 null 时会抛 NPE 异常",
                              Severity.WARNING, line=l, column=c)

        # 6.8 subList parent modification caution
        for i, line in enumerate(lines, 1):
            if re.search(r"\.subList\(", line) and \
               re.search(r"\.(add|remove|clear)\s*\(", lines[i] if i < len(lines) else ""):
                self._add(file_path, "ALIBABA_SUBLIST_MODIFY",
                          "对父集合元素的增加或删除会导致子列表的遍历、增加、删除产生 ConcurrentModificationException",
                          Severity.WARNING, line=i)

        # 6.12 Wildcard extends/super usage
        for i, line in enumerate(lines, 1):
            if re.search(r"<\?\s+extends\s+\w+>\s+\w+\s*=\s*", line) and \
               not re.search(r"//", line):
                m = re.search(r"<\?\s+extends\s+(\w+)>\s+(\w+)", line)
                if m:
                    self._add(file_path, "ALIBABA_WILDCARD_EXTENDS",
                              "泛型通配符<? extends T>的集合不能使用 add 方法",
                              Severity.INFO, line=i, column=line.find("?"))

        # 6.12 Wildcard super get check
        for i, line in enumerate(lines, 1):
            if re.search(r"<\?\s+super\s+\w+>\s+\w+", line) and \
               re.search(r"\.\s*get\s*\(", line) and \
               not re.search(r"//", line):
                m = re.search(r"<\?\s+super\s+(\w+)>", line)
                if m:
                    self._add(file_path, "ALIBABA_WILDCARD_SUPER_GET",
                              f"泛型通配符<? super {m.group(1)}> 的集合不能安全使用 get 方法，只能保证是 Object",
                              Severity.WARNING, line=i, column=line.find("?"))

        # 6.15 Comparator conditions
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.ClassDeclaration) and \
                       member.name.endswith(("Comparator", "Comparable")):
                        l, c = self._pos(member)
                        self._add(file_path, "ALIBABA_COMPARATOR_CONDITIONS",
                                  "Comparator 实现类需满足自反性、传递性、对称性，否则会抛 IllegalArgumentException",
                                  Severity.WARNING, line=l, column=c)

        # 6.15 Use enum for fixed-range values
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name == "String" and \
                   "static" in (node.modifiers or []) and "final" in (node.modifiers or []):
                    for decl in node.declarators:
                        if decl.initializer and isinstance(decl.initializer, javalang.tree.Literal) and \
                           len(str(decl.initializer).strip('"')) > 0:
                            val = str(decl.initializer).strip('"')
                            if val in ("0", "1", "Y", "N", "YES", "NO", "TRUE", "FALSE", "SUCCESS", "FAIL"):
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_ENUM_FIXED_VALUE",
                                          f"固定范围值 '{decl.name}' 建议使用枚举类型定义",
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

        # 8.6 Blank line after return/throw (when method > 10 lines)
        method_line_counts = {}
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                if node.position:
                    ml = node.position.line
                    body = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                    if body and hasattr(body[-1], "position") and body[-1].position:
                        total = body[-1].position.line - ml
                        if total > 10:
                            for j in range(ml, ml + total):
                                if j - 1 < len(lines) and re.search(r"\b(return|throw)\b\s+[^;]+;", lines[j - 1]) and \
                                   j < len(lines) and lines[j].strip() != "" and not lines[j].strip().startswith("}"):
                                    self._add(file_path, "ALIBABA_RETURN_BLANK_LINE",
                                              "return/throw 等中断逻辑的右大括号后需要加一个空行",
                                              Severity.INFO, line=j)
                                    break

        # 8.8 Complex condition to variable
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(if|while)\s*\([^)]*&&[^)]*\|\|[^)]*\)", line) and \
               not re.search(r"//", line) and \
               not re.search(r"else\s+if", line):
                m = re.search(r"if\s*\((.{30,})\)", line)
                if m:
                    self._add(file_path, "ALIBABA_COMPLEX_CONDITION",
                              "复杂的条件判断建议将结果赋值给一个有意义的布尔变量名，提高可读性",
                              Severity.INFO, line=i)

        # 8.13 High-concurrency: avoid == as break/exit condition
        for path, node in tree:
            if isinstance(node, (javalang.tree.SynchronizedStatement, javalang.tree.MethodDeclaration)):
                mods = getattr(node, "modifiers", []) or []
                is_sync = "synchronized" in mods or isinstance(node, javalang.tree.SynchronizedStatement)
                if is_sync:
                    body_stmts = []
                    if isinstance(node, javalang.tree.SynchronizedStatement):
                        body_stmts = node.body.statements if hasattr(node.body, "statements") else (node.body if isinstance(node.body, list) else [])
                    else:
                        body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                    for stmt in body_stmts:
                        if isinstance(stmt, javalang.tree.IfStatement):
                            cond_str = str(stmt.expression)
                            if re.search(r"==\s*\d+$", cond_str) and \
                               re.search(r"\b(break|return|exit)\b", str(stmt.then_statement)):
                                l = stmt.position.line if stmt.position else 0
                                self._add(file_path, "ALIBABA_HIGH_CONCURRENCY_EQUAL",
                                          "高并发场景中避免使用等值判断(==)作为中断条件，建议用大于/小于区间判断",
                                          Severity.WARNING, line=l)

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

        # Thread pool should not use Executors
        for i, line in enumerate(lines, 1):
            if re.search(r"Executors\.new\w+Pool\s*\(", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_CUSTOM_THREAD_POOL",
                          "线程池不允许使用 Executors 去创建，而是通过 ThreadPoolExecutor 的方式",
                          Severity.WARNING, line=i)

        # Thread naming not specified
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+Thread\s*\(", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_NAMED_THREAD",
                          "创建线程或线程池时请指定有意义的线程名称，方便出错时回溯",
                          Severity.INFO, line=i)

        # ThreadPoolExecutor: check if named
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+ThreadPoolExecutor\s*\(", line) and \
               not re.search(r"ThreadFactory|threadFactory", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_THREAD_FACTORY",
                          "创建线程池必须指定 ThreadFactory 以命名线程",
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

        # 7.7/7.8 Lock performance and order
        for i, line in enumerate(lines, 1):
            if re.search(r"synchronized\s*\([^)]*\)\s*\{", line):
                for j in range(i, min(i + 5, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"synchronized\s*\([^)]*\)\s*\{", lines[j - 1]) and \
                       j - 1 != i:
                        self._add(file_path, "ALIBABA_MULTIPLE_LOCKS",
                                  "对多个资源同时加锁时需要保持一致的加锁顺序，否则可能造成死锁",
                                  Severity.WARNING, line=i)
                        break

        # 7.11 Concurrent update without lock
        for i, line in enumerate(lines, 1):
            if re.search(r"UPDATE\s+\w+\s+SET\s+\w+\s*=\s*\w+\s*\+\s*1", line, re.IGNORECASE) and \
               not re.search(r"(version|optimistic|lock|for\s+update)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_CONCURRENT_UPDATE",
                          "并发修改同一记录时避免更新丢失，需要加锁（应用层/缓存层/数据库乐观锁）",
                          Severity.WARNING, line=i)

        # 7.18 HashMap resize dead link (reference)
        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "HashMap" in vtype and "ConcurrentHashMap" not in vtype:
                    mods = node.modifiers or []
                    if "static" in mods and "final" in mods:
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_HASHMAP_RESIZE",
                                      "HashMap 在容量不够进行 resize 时由于高并发可能出现死链，导致 CPU 飙升，高并发场景建议使用 ConcurrentHashMap",
                                      Severity.INFO, line=l, column=c)
                            break

        # 7.1 Singleton thread safety
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               node.name in ("getInstance", "getSingleton") and \
               "static" in (node.modifiers or []) and \
               not any("synchronized" in str(a) or "synchronized" in (node.modifiers or [])
                       for a in ([node.modifiers] if isinstance(node.modifiers, list) else [])):
                l, c = self._pos(node)
                self._add(file_path, "ALIBABA_SINGLETON_THREAD_SAFE",
                          "获取单例对象需要保证线程安全，建议使用 synchronized 或双重检查锁",
                          Severity.WARNING, line=l, column=c)

        # 7.17 volatile without atomic for multi-write
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration) and \
               "volatile" in (node.modifiers or []):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name in ("int", "long", "boolean", "double"):
                    for decl in node.declarators:
                        l, c = self._pos(decl)
                        self._add(file_path, "ALIBABA_VOLATILE_ATOMIC",
                                  "volatile 解决多线程内存不可见问题，一写多读可用；多写场景需使用 Atomic 类或锁",
                                  Severity.INFO, line=l, column=c)

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

        # 9.4 Inline comment format check (single-line comments should be above the code)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if re.search(r"\w+\s*;.*//\s", line) and \
               not re.search(r"//.*TODO|//.*FIXME|//.*http", line, re.IGNORECASE):
                m = re.search(r"(\w+\s*;)\s*(/\*.*\*/|//.*)$", line)
                if m:
                    self._add(file_path, "ALIBABA_INLINE_COMMENT",
                              "方法内部单行注释应放在被注释语句上方另起一行，而非代码行尾",
                              Severity.INFO, line=i)

        # 9.3 Class must have @author and @date in Javadoc
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cl = node.position.line if node.position else 0
                has_author = False
                has_date = False
                for jj in range(max(0, cl - 10), cl):
                    if jj < len(lines):
                        if re.search(r"@author", lines[jj]):
                            has_author = True
                        if re.search(r"@date|@since|@create", lines[jj]):
                            has_date = True
                if cl > 0:
                    if not has_author:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_JAVADOC_AUTHOR",
                                  f"类 '{node.name}' 缺少 @author 创建者标记",
                                  Severity.INFO, line=l, column=c)
                    if not has_date:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_JAVADOC_DATE",
                                  f"类 '{node.name}' 缺少创建日期标记 (@date/@since)",
                                  Severity.INFO, line=l, column=c)

        # 9.8 Delete unused private fields/methods/parameters
        all_method_names = set()
        all_field_names = set()
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                all_method_names.add(node.name)
                for param in (node.parameters or []):
                    if hasattr(param, "name"):
                        all_field_names.add(param.name)
            elif isinstance(node, javalang.tree.FieldDeclaration):
                for decl in node.declarators:
                    all_field_names.add(decl.name)
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        mods = member.modifiers or []
                        if "private" in mods and "static" not in mods:
                            for decl in member.declarators:
                                fn = decl.name
                                if fn not in all_method_names and fn not in all_field_names and \
                                   not fn.startswith("serialVersionUID"):
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_UNUSED_PRIVATE_FIELD",
                                              f"私有字段 '{fn}' 未被使用，应移除",
                                              Severity.WARNING, line=l, column=c)

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

        # Transaction rollback check in catch
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "Transactional" in ann_names:
                    for stmt in (node.body if isinstance(node.body, list) else []):
                        if isinstance(stmt, javalang.tree.TryStatement):
                            for catch in (stmt.catches or []):
                                block_str = str(catch.body or "")
                                if "TransactionAspectSupport" not in block_str and \
                                   "rollback" not in block_str.lower() and \
                                   "setRollbackOnly" not in block_str:
                                    l = catch.parameter.position.line if catch.parameter and catch.parameter.position else 0
                                    self._add(file_path, "ALIBABA_TRANSACTION_ROLLBACK",
                                              "事务场景中捕获异常后需要回滚事务，注意手动回滚或重新抛出",
                                              Severity.WARNING, line=l)

        # Open API should use error codes (not just exception)
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                    body_str = str(getattr(node, "body", "") or "")
                    if re.search(r"throw new (RuntimeException|Exception)\(", body_str) and \
                       not re.search(r"Result|Response|ErrorCode|errorCode|error_code|ApiResult|ApiResponse", body_str):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_OPEN_API_ERRORCODE",
                                  "开放接口必须使用错误码，不推荐内部异常直接抛出",
                                  Severity.INFO, line=l, column=c)

        # 8. Exceptions not for flow control
        for i, line in enumerate(lines, 1):
            if re.search(r"try\s*\{", line) and \
               re.search(r"(if|while|for)\s*\(", lines[i] if i < len(lines) else ""):
                pass

        # 9. Exception used as flow control
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                body_stmts = node.body if hasattr(node, "body") and isinstance(node.body, list) else \
                            getattr(getattr(node, "body", None), "statements", []) or []
                if not body_stmts:
                    continue
                for s in body_stmts:
                    s_str = str(s)
                    if "return" in s_str and any(
                        kw in s_str for kw in ("null", "false", "-1", "0")
                    ):
                        for catch in (node.catches or []):
                            if catch.parameter and catch.parameter.type and \
                               hasattr(catch.parameter.type, "name") and \
                               catch.parameter.type.name in ("Exception", "RuntimeException"):
                                l = catch.parameter.position.line if catch.parameter.position else 0
                                self._add(file_path, "ALIBABA_EXCEPTION_FLOW",
                                          "异常捕获后不要用来做流程控制，不应通过异常控制业务分支",
                                          Severity.WARNING, line=l)
                                break

        # 10. Exception type matching
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                for catch in (node.catches or []):
                    cp = catch.parameter if hasattr(catch, "parameter") else None
                    if cp and hasattr(cp, "type") and cp.type:
                        caught_type = cp.type.name
                        caught_super = {"Exception": ("RuntimeException", "IOException", "SQLException"),
                                        "RuntimeException": ("IllegalArgumentException", "NullPointerException",
                                                             "IndexOutOfBoundsException", "IllegalStateException",
                                                             "UnsupportedOperationException")}
                        for stmt in (catch.block.statements if hasattr(catch.block, "statements") else []):
                            if isinstance(stmt, javalang.tree.ThrowStatement) and \
                               hasattr(stmt, "expression") and stmt.expression and \
                               hasattr(stmt.expression, "type") and stmt.expression.type:
                                thrown_type = stmt.expression.type.name
                                if thrown_type not in (caught_type, "Exception", "RuntimeException", "Throwable"):
                                    l = stmt.position.line if stmt.position else 0
                                    self._add(file_path, "ALIBABA_EXCEPTION_TYPE_MISMATCH",
                                              f"catch 捕获 '{caught_type}' 但抛出不兼容类型 '{thrown_type}'，应匹配或为父类",
                                              Severity.WARNING, line=l)

        # 11. Distinguish stable vs non-stable code in catch
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                if len(node.catches or []) == 1:
                    catch = node.catches[0]
                    if catch.parameter and catch.parameter.type and \
                       hasattr(catch.parameter.type, "name") and \
                       catch.parameter.type.name == "Exception":
                        body_stmts = node.body if hasattr(node, "body") and isinstance(node.body, list) else \
                                    getattr(getattr(node, "body", None), "statements", []) or []
                        invocations = [s for s in body_stmts
                                       if isinstance(s, (javalang.tree.MethodInvocation,
                                                         javalang.tree.StatementExpression))]
                        if len(invocations) >= 3 and len(node.catches) == 1:
                            l = catch.parameter.position.line if catch.parameter.position else 0
                            self._add(file_path, "ALIBABA_CATCH_TYPE_DISTINGUISH",
                                      "catch 需分清稳定代码与非稳定代码，多个可能异常的方法建议分开 try-catch 处理",
                                      Severity.INFO, line=l)

        # 10. Return null with annotation check
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                has_null_return = False
                if node.body:
                    stmts = node.body if isinstance(node.body, list) else getattr(node.body, "statements", [])
                    for stmt in stmts:
                        if isinstance(stmt, javalang.tree.ReturnStatement) and \
                           hasattr(stmt, "expression") and \
                           str(stmt.expression) == "null":
                            has_null_return = True
                            break
                if has_null_return:
                    ret_type = getattr(node, "return_type", None)
                    if ret_type and hasattr(ret_type, "name") and \
                       ret_type.name not in ("void", "int", "long", "boolean", "double", "float", "char", "byte", "short"):
                        has_return_comment = False
                        ml = node.position.line if node.position else 0
                        for jj in range(max(0, ml - 3), ml):
                            if jj < len(lines) and re.search(r"@return.*null|returns.*null|null.*return", lines[jj], re.IGNORECASE):
                                has_return_comment = True
                                break
                        if not has_return_comment:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_NULL_RETURN",
                                      f"方法 '{node.name}' 可能返回 null，必须添加注释充分说明什么情况下会返回 null 值",
                                      Severity.INFO, line=l, column=c)

        # 5. Transaction catch without rollback
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                for catch in (node.catches or []):
                    block = catch.block if hasattr(catch, "block") and catch.block else getattr(catch, "body", None)
                    body_stmts = block.statements if hasattr(block, "statements") else (block if isinstance(block, list) else [])
                    has_rollback = any("rollback" in str(s).lower() for s in body_stmts)
                    if not has_rollback and len(body_stmts) > 0:
                        pass

        # 9. RPC/dynamic must catch Throwable
        for i, line in enumerate(lines, 1):
            if re.search(r"(RPC|rpc|反射|reflect|Proxy|\.invoke\s*\()", line) and \
               re.search(r"try\s*\{", line) and \
               not re.search(r"catch.*Throwable", line):
                for j in range(i, min(i + 15, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"catch\s*\(", lines[j - 1]):
                        if not re.search(r"Throwable", lines[j - 1]):
                            self._add(file_path, "ALIBABA_RPC_THROWABLE",
                                      "在调用 RPC、二方包、或动态生成类的相关方法时，捕捉异常使用 Throwable 类进行拦截",
                                      Severity.WARNING, line=i)
                        break

                        # 6. Exception not for flow control
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body:
                    if isinstance(stmt, javalang.tree.TryStatement):
                        catch_exprs = []
                        for catch in (stmt.catches or []):
                            if catch.parameter and catch.parameter.type and hasattr(catch.parameter.type, "name"):
                                catch_exprs.append(catch.parameter.type.name)
                        if catch_exprs:
                            body_str = str(getattr(stmt, "body", "") or "")
                            for cn in catch_exprs:
                                if re.search(rf"catch\s*\(\s*{cn}\s+\w+\s*\).*\{{$", body_str):
                                    pass

        # 13. Exception must include scene info (not just message)
        for i, line in enumerate(lines, 1):
            if re.search(r"catch\s*\(", line):
                has_log = False
                has_msg = False
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines):
                        lj = lines[j - 1]
                        if re.search(r"log(ger)?\.(error|warn|info)", lj) and \
                           re.search(r"(参数|参数|场景|context|traceId|requestId|request|userId|用户|案发现场|e\.printStackTrace)",
                                     lj):
                            has_msg = True
                            break
                        if re.search(r"\{}\s*,\s*e|\{\}\s*,\s*\w+|e\.getMessage|log\.error\(\s*\"[^\"]*\"", lj):
                            has_log = True
                        if re.search(r"^\s*log(ger)?\.(error|warn)", lj):
                            has_log = True
                        if re.search(r"\be\b\)", lj) and re.search(r"(\"|\+|\{\})", lj):
                            has_msg = True
                            break
                        if re.search(r"}|\bthrow\b", lj):
                            break
                if has_log and not has_msg:
                    self._add(file_path, "ALIBABA_CATCH_SCENE_INFO",
                              "异常信息应包含案发现场信息和异常堆栈信息，缺少上下文参数",
                              Severity.INFO, line=i)
                # Also check log.error without exception object
                for j in range(i, min(i + 8, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"log(ger)?\.(error|warn)\(\s*\"[^\"]+\"\s*\)", lines[j - 1]):
                        self._add(file_path, "ALIBABA_CATCH_SCENE_INFO",
                                  "异常日志应传递异常对象作为参数，而非仅记录消息",
                                  Severity.INFO, line=j)
                        break

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

        # Log file additivity check
        if file_path.endswith((".xml",)):
            for i, line in enumerate(lines, 1):
                if re.search(r'<logger\s', line) and \
                   not re.search(r'additivity\s*=\s*"false"', line) and \
                   not re.search(r"<!--|-->", line):
                    self._add(file_path, "ALIBABA_LOG_ADDITIVITY",
                              "避免重复打印日志，务必在日志配置文件中设置 additivity=false",
                              Severity.INFO, line=i)

            if re.search(r"System\.(out|err)\.(print|println|printf)", line):
                self._add(file_path, "ALIBABA_SYSTEM_OUT",
                          "生产环境禁止使用 System.out/err 输出或使用 e.printStackTrace() 打印异常堆栈",
                          Severity.WARNING, line=i)
            if re.search(r"\.printStackTrace\s*\(\)", line):
                self._add(file_path, "ALIBABA_SYSTEM_OUT",
                          "生产环境禁止使用 System.out/err 输出或使用 e.printStackTrace() 打印异常堆栈",
                          Severity.WARNING, line=i)

            # 3.9 Exception info should include scene and stack
            if re.search(r"logger\.(error|warn)\s*\([^)]*\"[^\"]*\"\s*,\s*[^e]", line) and \
               not re.search(r"getMessage|e,\s*e|Exception|Throwable", line):
                pass

            # 3.10 No JSON tool in log
            if re.search(r'logger\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+.*(toJSON|JSON\.toJSON|toJson|JSON\.stringify)', line) or \
               re.search(r'log\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+.*(toJSON|JSON\.toJSON|toJson|JSON\.stringify)', line):
                self._add(file_path, "ALIBABA_LOG_JSON",
                          "日志打印时禁止直接用 JSON 工具将对象转换成 String，应使用日志框架的占位符",
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

            if re.search(r"new\s+(StringBuilder|StringBuffer)\s*\(\s*\)", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_STRING_BUILDER_SIZE",
                          "StringBuilder/StringBuffer 建议指定初始大小，避免频繁扩容",
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

    # ==================== (十) 前后端规约 ====================
    def check_frontend_backend(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_frontend_backend"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"@GetMapping\s*\(|@PostMapping\s*\(|@RequestMapping\s*\(", line) and \
               not re.search(r"produces\s*=\s*\"application/json", line):
                self._add(file_path, "ALIBABA_API_JSON",
                          "前后端交互推荐使用 JSON 格式而非 XML",
                          Severity.INFO, line=i)

        for i, line in enumerate(lines, 1):
            if re.search(r"Long\s+\w+[Ii][Dd]\s*[=:]\s*\d{10,}", line):
                self._add(file_path, "ALIBABA_LONG_ID_STRING",
                          "对于需要使用超大整数的场景，服务端一律使用 String 字符串类型返回，禁止使用 Long 类型",
                          Severity.WARNING, line=i)

        # 10.4 JSON key lowerCamelCase
        for i, line in enumerate(lines, 1):
            if re.search(r'"\w{3,}"\s*:', line) and not re.search(r"//", line) and \
               not re.search(r'(static|final|private|public|import)', line):
                m = re.search(r'"([A-Z]\w*)"\s*:', line)
                if m:
                    self._add(file_path, "ALIBABA_JSON_KEY_CASE",
                              f"JSON 的 key '{m.group(1)}' 必须为小写字母开始的 lowerCamelCase 风格",
                              Severity.WARNING, line=i, column=line.find(m.group(1)))

        # 10.14 No version in URL path
        for i, line in enumerate(lines, 1):
            if re.search(r'RequestMapping\s*\(\s*".*v\d+[\d.]*"', line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_URL_VERSION",
                          "在接口路径中不要加入版本号，版本控制在 HTTP 头信息中体现",
                          Severity.INFO, line=i)

        # 10.x HTTP URL length check (>2048 bytes)
        for i, line in enumerate(lines, 1):
            if re.search(r"@GetMapping|@RequestMapping.*GET", line):
                url_match = re.search(r'"([^"]{2048,})"', line)
                if url_match:
                    self._add(file_path, "ALIBABA_URL_LENGTH",
                              "HTTP 请求通过 URL 传递参数时，不能超过 2048 字节",
                              Severity.WARNING, line=i)

        # 10.x HTTP body length check
        for i, line in enumerate(lines, 1):
            if re.search(r"@RequestBody", line) and \
               re.search(r"@PostMapping|@PutMapping|@RequestMapping", line):
                body_type = re.search(r"@RequestBody\s+(\w+)", line)
                if body_type and body_type.group(1) in ("String", "Map", "HashMap", "JSONObject"):
                    self._add(file_path, "ALIBABA_BODY_LENGTH",
                              "HTTP 请求通过 body 传递内容时，必须控制长度，超出最大长度后端解析会出错",
                              Severity.INFO, line=i)

        # 10.2 Return empty [] or {} for null data
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mn = node.name
                if mn.startswith(("list", "query", "find", "search", "getAll")):
                    ret_type = getattr(node, "return_type", None)
                    if ret_type and hasattr(ret_type, "name") and ret_type.name in ("List", "Set", "Collection"):
                        body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                        for stmt in body_stmts:
                            if isinstance(stmt, javalang.tree.IfStatement):
                                if_str = str(stmt.expression) if hasattr(stmt, "expression") else ""
                                if "null" in if_str and (">" not in if_str or "size" not in if_str):
                                    break
                        else:
                            for stmt in body_stmts:
                                if isinstance(stmt, javalang.tree.ReturnStatement) and \
                                   hasattr(stmt, "expression") and "null" in str(stmt.expression):
                                    l, c = self._pos(node)
                                    self._add(file_path, "ALIBABA_RETURN_EMPTY",
                                              f"方法 '{mn}' 返回集合数据时，如果为空应返回空数组 [] 或空集合 {{}}，而非 null",
                                              Severity.WARNING, line=l, column=c)
                                    break

        # 10.9 Page parameter validation
        for i, line in enumerate(lines, 1):
            if re.search(r"(pageNum|pageNo|pageIndex|currentPage)\s*[<]", line) and \
               not re.search(r"//", line):
                m = re.search(r"(pageNum|pageNo|pageIndex|currentPage)\s*[<]\s*1", line)
                if m:
                    self._add(file_path, "ALIBABA_PAGE_PARAM",
                              "翻页场景中，用户输入参数小于1，则前端返回第一页参数给后端",
                              Severity.INFO, line=i)

        # 10.10 Internal redirect: forward vs redirect
        for i, line in enumerate(lines, 1):
            if re.search(r"redirect\s*:\s*[\"'](?!http)", line) and \
               not re.search(r"RedirectView|UrlBasedViewResolver", line):
                m = re.search(r"redirect\s*:\s*[\"'](\w+)", line)
                if m:
                    self._add(file_path, "ALIBABA_REDIRECT_FORWARD",
                              "服务器内部重定向必须使用 forward，外部重定向地址必须使用 URL 统一代理模块生成",
                              Severity.WARNING, line=i)

        # 10.13 Date format unified
        for i, line in enumerate(lines, 1):
            if re.search(r"SimpleDateFormat|DateTimeFormatter|@JsonFormat", line) and \
               re.search(r"yyyy-MM-dd HH:mm:ss", line):
                pass
            elif re.search(r"@JsonFormat", line) and \
                 not re.search(r"yyyy-MM-dd HH:mm:ss|yyyy-MM-dd'T'HH:mm:ss", line):
                m = re.search(r"pattern\s*=\s*[\"']([^\"']+)[\"']", line)
                if m:
                    self._add(file_path, "ALIBABA_DATE_FORMAT_UNIFIED",
                              "前后端的时间格式统一为 yyyy-MM-dd HH:mm:ss，统一为 GMT",
                              Severity.INFO, line=i)

        # 10.11 File download content-disposition
        for i, line in enumerate(lines, 1):
            if re.search(r"Content-Disposition.*attachment", line) and \
               not re.search(r"PercentEncoder|URLEncoder|encodeURIComponent|filename\*", line):
                self._add(file_path, "ALIBABA_FILE_DOWNLOAD_HEADER",
                          "文件下载时 Content-Disposition 应使用百分号编码后的 UTF-8 文件名",
                          Severity.WARNING, line=i)

        # 10.12 Duplicate submit prevention
        for i, line in enumerate(lines, 1):
            if re.search(r"@PostMapping|@RequestMapping.*POST", line):
                has_token = False
                for j in range(max(0, i - 5), i + 5):
                    if j < len(lines) and re.search(r"(token|noRepeat|repeatSubmit|rateLimit|limit|idempotent)", lines[j], re.IGNORECASE):
                        has_token = True
                        break
                if not has_token:
                    pass  # skip - too noisy

        # 10.15 Avoid big transaction
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "Transactional" in ann_names:
                    body_str = str(getattr(node, "body", "") or "")
                    if re.search(r"(rpc|dubbo|feign|restTemplate|http|remote|sleep|Thread\.sleep|message|mq|kafka|rabbit)", body_str, re.IGNORECASE):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_TRANSACTION_RPC",
                                  "事务中避免使用 RPC 远程调用、消息发送或线程 sleep",
                                  Severity.WARNING, line=l, column=c)

        # 10.16 Avoid circular reference in JSON
        for i, line in enumerate(lines, 1):
            if re.search(r"@OneToMany|@ManyToMany", line) and \
               not re.search(r"@JsonIgnore|@JsonBackReference|@JsonManagedReference|@JsonIgnoreProperties", line):
                self._add(file_path, "ALIBABA_CIRCULAR_REF",
                          "双向关联关系需要配合 @JsonIgnore 等 JSON 序列化注解，防止循环引用",
                          Severity.INFO, line=i)

        # 10.5 API comments required
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                    start_line = node.position.line if node.position else 1
                    doc_comment_found = False
                    for j in range(max(0, start_line - 10), start_line - 1):
                        if j < len(lines) and re.search(r"/\*\*", lines[j]):
                            doc_comment_found = True
                            break
                    if not doc_comment_found:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_API_COMMENT",
                                  f"API 方法 '{node.name}' 必须添加注释说明接口功能",
                                  Severity.INFO, line=l, column=c)

        # 10.x @ExceptionHandler with errorMessage
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "ExceptionHandler" in ann_names:
                    body_str = str(getattr(node, "body", "") or "")
                    if not re.search(r"errorMessage|error_message|errorCode|error_code|message|msg", body_str):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_ERROR_MESSAGE",
                                  "错误处理应返回 errorCode 和 errorMessage 信息",
                                  Severity.INFO, line=l, column=c)

        # 10.16 View template: no complex logic
        if file_path.endswith((".jsp", ".ftl", ".vm", ".html")):
            for i, line in enumerate(lines, 1):
                if re.search(r"(if\s*\(|for\s*\(|while\s*\()", line) and \
                   re.search(r"(\w+\.\w+|\w+\(|\w+\))", line):
                    nested = line.count("(") > 2
                    if nested:
                        self._add(file_path, "ALIBABA_VIEW_COMPLEX",
                                  "不要在视图模板中加入任何复杂的逻辑运算",
                                  Severity.WARNING, line=i)

        # 10.17 Velocity use $!{} not ${}
        if file_path.endswith(".vm"):
            for i, line in enumerate(lines, 1):
                if re.search(r"\$\{", line) and \
                   not re.search(r"\$\!", line) and \
                   not re.search(r"//|\*", line):
                    self._add(file_path, "ALIBABA_VELOCITY_NULL",
                              "velocity 页面输出变量必须加 $!{var} 以避免空指针",
                              Severity.WARNING, line=i)

    # ==================== 四、安全规约 ====================
    def check_security(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_security"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"SELECT\s+.*\b(password|pwd|secret|token|credential|private_key|api_key)\b", line, re.IGNORECASE) and \
               not re.search(r"//.*(脱敏|mask|hide|\*|replace)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_SENSITIVE_DATA",
                          "用户敏感数据禁止直接展示，必须对展示数据进行脱敏",
                          Severity.WARNING, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []) and \
               any("password" in p.name.lower() or "secret" in p.name.lower() or "token" in p.name.lower()
                   for p in (node.parameters or []) if hasattr(p, "name")):
                for stmt in (node.body if isinstance(node.body, list) else []):
                    if isinstance(stmt, javalang.tree.IfStatement) and \
                       hasattr(stmt, "expression") and stmt.expression:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_PARAM_VALIDATION",
                                  "用户请求传入的任何参数必须做有效性验证",
                                  Severity.WARNING, line=l, column=c)
                        break

        for i, line in enumerate(lines, 1):
            if re.search(r"password\s*=\s*[\"'].*[\"']", line) and \
               not re.search(r"//|/\*|\*", line):
                self._add(file_path, "ALIBABA_HARDCODED_PASSWORD",
                          "配置文件中的密码需要加密，禁止在代码中硬编码密码",
                          Severity.ERROR, line=i)

        # 4.x Anti-replay for resource-sensitive operations
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []):
                mn = node.name.lower()
                if any(kw in mn for kw in ("send", "pay", "order", "sms", "email", "message", "transfer", "withdraw", "charge")):
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                        body_str = str(getattr(node, "body", "") or "")
                        if not re.search(r"(idempotent|noRepeat|repeatSubmit|token|rateLimit|limit|幂等|防重)", body_str, re.IGNORECASE):
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_ANTI_REPLAY",
                                      "在使用平台资源（短信、邮件、电话、下单、支付）时，必须实现正确的防重放机制",
                                      Severity.WARNING, line=l, column=c)

        # 4.1 Permission control check
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []):
                mn = node.name
                if mn.startswith(("delete", "update", "add", "create", "modify", "remove", "batch")):
                    has_auth = False
                    annotations = getattr(node, "annotations", []) or []
                    for ann in annotations:
                        if hasattr(ann, "name") and ann.name in ("PreAuthorize", "PreFilter", "Secured", "RolesAllowed"):
                            has_auth = True
                            break
                    if not has_auth:
                        body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                        for stmt in body_stmts:
                            if "hasRole" in str(stmt) or "hasPermission" in str(stmt) or "hasAuthority" in str(stmt):
                                has_auth = True
                                break
                        if not has_auth:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_PERMISSION_CHECK",
                                      f"操作方法 '{mn}' 必须进行权限控制校验",
                                      Severity.WARNING, line=l, column=c)

        # 4.5 XSS protection
        for i, line in enumerate(lines, 1):
            if re.search(r"ModelAndView|Model|@ResponseBody", line) and \
               re.search(r"(request\.getParameter|@RequestParam|@PathVariable)", line) and \
               not re.search(r"(HtmlUtils|StringEscapeUtils|escapeHtml|XSS|clean|sanitize)", line) and \
               not re.search(r"//", line):
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"(HtmlUtils|StringEscapeUtils|escapeHtml|sanitize)", lines[j - 1]):
                        break
                else:
                    self._add(file_path, "ALIBABA_XSS_PROTECTION",
                              "禁止向 HTML 页面输出未经安全过滤或未正确转义的用户数据，防止 XSS 攻击",
                              Severity.WARNING, line=i)

        # 4.6 CSRF validation
        for i, line in enumerate(lines, 1):
            if re.search(r"@PostMapping|@PutMapping|@DeleteMapping|@RequestMapping.*method.*POST", line) and \
               not re.search(r"(csrf|CSRF|@CrossOrigin)", line):
                for j in range(max(0, i-5), i):
                    if j < len(lines) and re.search(r"(csrf|CSRF)", lines[j], re.IGNORECASE):
                        break
                else:
                    self._add(file_path, "ALIBABA_CSRF",
                              "表单、AJAX 提交必须执行 CSRF 安全验证",
                              Severity.INFO, line=i)

        # 4.7 URL redirect whitelist
        for i, line in enumerate(lines, 1):
            if re.search(r"redirect\s*:\s*[\"'](https?://)", line) and \
               not re.search(r"(whitelist|white_list|allowed|permit|validateUrl|checkUrl)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_REDIRECT_WHITELIST",
                          "URL 外部重定向传入的目标地址必须执行白名单过滤",
                          Severity.WARNING, line=i)

        # 4.9 File upload validation
        for i, line in enumerate(lines, 1):
            if re.search(r"MultipartFile|@RequestParam.*file|@RequestParam.*upload", line) and \
               not re.search(r"(fileSize|maxSize|MaxUploadSize|allowedExtension|contentType|fileType)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_FILE_UPLOAD",
                          "对于文件上传功能，需要对文件大小、类型进行严格检查和控制",
                          Severity.WARNING, line=i)

        # 4.11 User input validation required
        for i, line in enumerate(lines, 1):
            if re.search(r"@RequestParam|@PathVariable|@RequestBody", line) and \
               not re.search(r"@Valid|@Validated|javax\.validation|jakarta\.validation", line) and \
               not re.search(r"//", line):
                for j, line2 in enumerate(lines[max(0, i - 15):i + 15], max(0, i - 14)):
                    if re.search(r"@Valid|@Validated", line2):
                        break
                else:
                    pass  # too noisy for @Valid on every param

        # 4.12 No SQL injection in MyBatis ${
        for i, line in enumerate(lines, 1):
            if re.search(r"\$\{", line) and \
               re.search(r"(select|from|where|order by|group by|having|insert|update|delete)", line, re.IGNORECASE) and \
               not re.search(r"//.*no_sqli|//.*sql_injection", line, re.IGNORECASE):
                if re.search(r"\$\{.*(user|input|query|param|keyword|name|value|text|search)", line, re.IGNORECASE) or \
                   re.search(r"order\s+by\s+\$\{", line, re.IGNORECASE):
                    self._add(file_path, "ALIBABA_SQL_INJECTION",
                              "MyBatis 中使用 ${} 拼接的 SQL 存在注入风险，建议使用 #{} 参数化查询",
                              Severity.ERROR, line=i)

        # 4.13 User ID in session, not from request
        for i, line in enumerate(lines, 1):
            if re.search(r"request\.getParameter.*userId|request\.getParameter.*user_id|request\.getParameter.*accountId", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_USERID_FROM_REQUEST",
                          "用户 ID 应从 session 中获取，禁止从请求参数中获取以防止越权",
                          Severity.WARNING, line=i)

        # 4.14 Logging sensitive data
        for i, line in enumerate(lines, 1):
            if re.search(r"(log(ger)?\.(info|debug|warn|error)|System\.out|System\.err)", line) and \
               re.search(r"(password|pwd|secret|token|credential|authCode|smsCode|verifyCode)", line, re.IGNORECASE) and \
               not re.search(r"//.*(脱敏|mask|hide|\*)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_LOG_SENSITIVE",
                          "日志输出时禁止出现密码、密钥等敏感信息",
                          Severity.WARNING, line=i)

        # 4.15 Content security: anti-spam, anti-fraud, content filtering
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []):
                mn = node.name.lower()
                if any(kw in mn for kw in ("publish", "post", "reply", "comment", "send", "message", "review")):
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                        body_str = str(getattr(node, "body", "") or "")
                        if not re.search(r"(rateLimiter|rate_limit|rateLimit|limit|throttle|防刷|antiSpam|spam|contentCheck|checkContent|sensitive|filter|validate)", body_str, re.IGNORECASE):
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_CONTENT_SECURITY",
                                      "用户发布/评论/发送等场景必须实现防刷、内容违禁词过滤等安全措施",
                                      Severity.INFO, line=l, column=c)

    # ==================== 五、MySQL 数据库 ====================
    def check_sql(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_sql"):
            return
        lines = content.split("\n")

        # 5.1.1 is_xxx for boolean fields
        for i, line in enumerate(lines, 1):
            if re.search(r"is[A-Z]", line) and \
               re.search(r"tinyint|Integer", line, re.IGNORECASE) and \
               re.search(r"columnDefinition|@Column|@TableField", line):
                self._add(file_path, "ALIBABA_SQL_IS_PREFIX",
                          "表达是与否概念的字段，必须使用 is_xxx 的方式命名，数据类型是 unsigned tinyint",
                          Severity.WARNING, line=i)

        # 5.1.2 lowercase table/field names
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(m.endswith("DO") or m.endswith("PO") or node.name.endswith(("DO", "PO")) for m in [node.name]):
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            fn = decl.name
                            if fn != fn.lower() and not fn.startswith("serialVersionUID"):
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_SQL_FIELD_CASE",
                                          f"字段名 '{fn}' 必须使用小写字母或数字",
                                          Severity.WARNING, line=l, column=c)

        # 5.1.8 varchar length check
        # 5.1.7 char type for fixed-length strings
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name == "String":
                    ann_str = str([str(getattr(a, "name", "")) + str(getattr(a, "element", ""))
                                   for a in (node.annotations or [])])
                    if "Column" in ann_str or "TableField" in ann_str:
                        m = re.search(r'columnDefinition\s*=\s*"([^"]+)"', ann_str)
                        if m:
                            col_def = m.group(1).lower()
                            if "varchar" in col_def:
                                len_m = re.search(r'varchar\s*\(\s*(\d+)\s*\)', col_def)
                                if len_m:
                                    length = int(len_m.group(1))
                                    # 5.1.7: use char for fixed-length strings
                                    if length in (1, 2, 3, 4, 6, 8, 11, 16, 18, 32) and \
                                       "char" not in col_def:
                                        for decl in node.declarators:
                                            l, c = self._pos(decl)
                                            self._add(file_path, "ALIBABA_CHAR_TYPE",
                                                      f"固定长度短字段 '{decl.name}'（长度 {length}）建议使用 char 定长字符串类型",
                                                      Severity.INFO, line=l, column=c)
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name in ("String", "VARCHAR", "varchar"):
                    ann_str = str([str(getattr(a, "name", "")) + str(getattr(a, "element", ""))
                                   for a in (node.annotations or [])])
                    if "Column" in ann_str or "TableField" in ann_str:
                        m = re.search(r'length\s*=\s*(\d+)', ann_str)
                        if m:
                            length = int(m.group(1))
                            if length > 5000:
                                for decl in node.declarators:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_VARCHAR_LENGTH",
                                              f"varchar 长度建议不超过 5000（当前 {length}），超过应使用 text 类型",
                                              Severity.INFO, line=l, column=c)

        # 5.1.9a Table naming: business_name_role
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               (node.name.endswith("DO") or node.name.endswith("PO")):
                cn = node.name.replace("DO", "").replace("PO", "")
                if not re.search(r"_", cn) and not re.search(r"[A-Z]", cn[1:] if len(cn) > 1 else ""):
                    pass  # "UserDO" is fine
                if re.search(r"^[A-Z][a-z]+$", cn) and len(cn) <= 3:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_TABLE_NAMING",
                              f"类 '{node.name}' 对应的表名建议遵循 '业务名称_表的作用' 的命名方式",
                              Severity.INFO, line=l, column=c)

        # 5.1.9 Required fields: id, create_time, update_time
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               (node.name.endswith("DO") or node.name.endswith("PO")):
                fields = set()
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            fields.add(decl.name)
                missing = []
                for f in ("id", "createTime", "updateTime"):
                    if f not in fields:
                        missing.append(f)
                if missing:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_SQL_REQUIRED_FIELDS",
                              f"表必备三字段 '{', '.join(missing)}' 缺失",
                              Severity.WARNING, line=l, column=c)

        # 5.3.1 Use count(*)
        for i, line in enumerate(lines, 1):
            if re.search(r"count\(\s*\w+\.\w+\s*\)", line) and \
               not re.search(r"count\s*\(\s*\*\s*\)", line) and \
               not re.search(r"distinct", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_COUNT_STAR",
                          "不要使用 count(列名) 替代 count(*)，count(*) 是 SQL92 定义的标准统计行数的语法",
                          Severity.WARNING, line=i)

            if re.search(r"count\(\s*\w+\.\w+\s*\)", line) and \
               not re.search(r"count\s*\(\s*\*\s*\)", line):
                self._add(file_path, "ALIBABA_COUNT_COL_NPE",
                          "count(col) 如果该列值全为 NULL 则返回 0，但 sum(col) 返回 NULL，使用 sum() 时需注意 NPE",
                          Severity.INFO, line=i)

            if re.search(r"\.delete\s*\(", line) and \
               not re.search(r"//.*delete", line) and \
               not re.search(r"(deleted\s*=\s*1|is_deleted\s*=\s*1|setDeleted\s*\(true)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_PHYSICAL_DELETE",
                          "在数据库中不能使用物理删除操作，要使用逻辑删除",
                          Severity.WARNING, line=i)

        # 5.3.5 count=0 return directly
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "Page" in str(getattr(node, "return_type", "")):
                body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                has_count_zero = any(
                    isinstance(s, javalang.tree.IfStatement) and "count" in str(s.expression) and "0" in str(s.expression)
                    for s in body_stmts if isinstance(s, javalang.tree.IfStatement)
                )
                if not has_count_zero:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_PAGE_COUNT_ZERO",
                              "代码中写分页查询逻辑时，若 count 为 0 应直接返回，避免执行后面的分页语句",
                              Severity.INFO, line=l, column=c)

        # 5.4.1 No * in query
        for i, line in enumerate(lines, 1):
            if re.search(r"SELECT\s+\*\s+FROM", line, re.IGNORECASE) and \
               not re.search(r"//.*SELECT|SELECT\s+\w+\.\*", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_SELECT_STAR",
                          "在表查询中，一律不要使用 * 作为查询的字段列表，需要哪些字段必须明确写明",
                          Severity.WARNING, line=i)

        # 5.3.4 Use ISNULL() for null check
        for i, line in enumerate(lines, 1):
            if re.search(r"WHERE\s+.*\b(IS\s+NULL|ISNULL)\b", line, re.IGNORECASE) and \
               not re.search(r"ISNULL\s*\(", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_USE_ISNULL",
                          "使用 ISNULL() 来判断是否为 NULL 值",
                          Severity.INFO, line=i)

            if re.search(r"= null|is null", line, re.IGNORECASE) and \
               re.search(r"WHERE", line, re.IGNORECASE) and \
               not re.search(r"ISNULL", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_USE_ISNULL",
                          "使用 ISNULL() 来判断是否为 NULL 值，而非 = null",
                          Severity.INFO, line=i)

        # 5.3.7 No stored procedures
        for i, line in enumerate(lines, 1):
            if re.search(r"call\s+\w+Proc|createProcedure|create\s+procedure", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_NO_STORED_PROC",
                          "禁止使用存储过程，存储过程难以调试和扩展，更没有移植性",
                          Severity.WARNING, line=i)

        # 5.3.9 Multi-table query must have alias
        for i, line in enumerate(lines, 1):
            if re.search(r"(FROM|JOIN)\s+\w+\s+\w+.*(WHERE|AND|ON)\s+\w+\.\w+", line, re.IGNORECASE) and \
               re.search(r"SELECT", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                m = re.search(r"FROM\s+(\w+)\s+(\w+)", line, re.IGNORECASE)
                if m and m.group(2) == m.group(2).lower() and len(m.group(2)) > 8:
                    self._add(file_path, "ALIBABA_TABLE_ALIAS",
                              "多表关联查询时，需要在列名前加表的别名进行限定",
                              Severity.INFO, line=i)

        # 5.3.10 Alias with 'as'
        for i, line in enumerate(lines, 1):
            if re.search(r"FROM\s+(\w+)\s+(\w{1,4})\s", line) and \
               not re.search(r"\s+as\s+", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                m = re.search(r"FROM\s+(\w+)\s+(\w{1,4})\s", line, re.IGNORECASE)
                if m and m.group(1).lower() != m.group(2).lower():
                    pass

        # 5.3.11 IN control within 1000
        for i, line in enumerate(lines, 1):
            m = re.search(r"\bIN\s*\(([^)]{50,})\)", line, re.IGNORECASE)
            if m and not re.search(r"//", line):
                in_content = m.group(1)
                comma_count = in_content.count(",")
                if comma_count > 50:
                    self._add(file_path, "ALIBABA_IN_SIZE",
                              "in 操作集合元素数量控制在 1000 个之内",
                              Severity.WARNING, line=i)

        # 5.3.x count == 0 return directly
        for i, line in enumerate(lines, 1):
            if re.search(r"count\s*\(\s*\*\s*\)", line, re.IGNORECASE) and \
               not re.search(r"if|if\s*.*count|count.*>.*0|count.*==.*0", lines[max(0, i - 5):i + 3]) and \
               not re.search(r"//", line):
                for j in range(min(i, len(lines)), min(i + 5, len(lines))):
                    if re.search(r"if\s*.*count", lines[j - 1], re.IGNORECASE):
                        break
                else:
                    pass  # too noisy to warn

        # 5.3.x Implicit conversion detection
        for i, line in enumerate(lines, 1):
            if re.search(r"WHERE\s+.*=.*\"\d+", line, re.IGNORECASE) or \
               re.search(r"WHERE\s+.*\"\d+\".*=", line, re.IGNORECASE) or \
               re.search(r"WHERE\s+.*\w+\s*=\s*\w+", line, re.IGNORECASE):
                m = re.search(r"(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)", line, re.IGNORECASE)
                if m and m.group(2) != m.group(4):
                    self._add(file_path, "ALIBABA_IMPLICIT_CONVERSION",
                              "防止因字段类型不同造成的隐式转换，导致索引失效",
                              Severity.WARNING, line=i)

        # 5.3.13 TRUNCATE not recommended
        for i, line in enumerate(lines, 1):
            if re.search(r"\bTRUNCATE\s+TABLE", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_TRUNCATE_USAGE",
                          "TRUNCATE TABLE 无事务且不触发 trigger，不建议在开发代码中使用此语句",
                          Severity.WARNING, line=i)

        # 5.3.12 Pagination must have ORDER BY
        for i, line in enumerate(lines, 1):
            if re.search(r"\bLIMIT\s+\d+", line, re.IGNORECASE) and \
               not re.search(r"ORDER\s+BY", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               re.search(r"SELECT", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_PAGE_ORDER_BY",
                          "分页查询必须指定 ORDER BY 以保证结果稳定",
                          Severity.WARNING, line=i)

        # 5.3.x utf8mb4 character set check
        for i, line in enumerate(lines, 1):
            if re.search(r"charset|characterSet|character_set", line, re.IGNORECASE) and \
               re.search(r"utf8|utf-8", line, re.IGNORECASE) and \
               not re.search(r"utf8mb4", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               not re.search(r"<!--|-->", line):
                self._add(file_path, "ALIBABA_UTF8MB4",
                          "所有的字符存储与表示，均采用 utf8mb4 字符集（而非 utf8），避免 emoji 等字符无法存储",
                          Severity.INFO, line=i)

        # 5.4.1 Try to avoid count on large tables without index
        for i, line in enumerate(lines, 1):
            if re.search(r"select\s+count\s*\(.*\)\s+from", line, re.IGNORECASE) and \
               not re.search(r"where|WHERE", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_COUNT_NO_WHERE",
                          "COUNT 全表扫描且无 WHERE 条件可能性能低下，需确认是否添加索引",
                          Severity.INFO, line=i)

        # 5.4.2 POJO boolean mapping in resultMap
        for i, line in enumerate(lines, 1):
            if re.search(r"<result\s+.*property\s*=\s*\"\w+\".*column\s*=\s*\"is_\w+\"", line) and \
               not re.search(r"//", line):
                pass

        # 5.4.3 Must define <resultMap>
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "DTO", "VO")):
                l, c = self._pos(node)
                self._add(file_path, "ALIBABA_RESULT_MAP",
                          f"POJO 类 '{node.name}' 需要定义对应的 <resultMap> 进行字段与属性之间的映射",
                          Severity.INFO, line=l, column=c)

        # 5.4.4 Use #{} not ${}
        for i, line in enumerate(lines, 1):
            if re.search(r"\$\{", line) and \
               re.search(r"\.xml|\.sql|@Select|@Insert|@Update|@Delete", file_path):
                m = re.search(r"\$\{(\w+)\}", line)
                if m and not re.search(r"order\s+by|ORDER\s+BY|sort|Sort|column|Column", line, re.IGNORECASE):
                    self._add(file_path, "ALIBABA_SQL_PARAM_BINDING",
                              f"sql.xml 配置参数使用 #{{}} 而非 ${{}}, 防止 SQL 注入: ${{{m.group(1)}}}",
                              Severity.WARNING, line=i)

        # 5.4.5 queryForList(start,size) not recommended
        for i, line in enumerate(lines, 1):
            if re.search(r"queryForList\s*\(\s*\"[^\"]*\"\s*,\s*\d+\s*,\s*\d+\s*\)", line):
                self._add(file_path, "ALIBABA_QUERY_FOR_LIST",
                          "iBATIS 自带的 queryForList(String, int, int) 不推荐使用",
                          Severity.WARNING, line=i)

        # 5.4.6 HashMap/Hashtable as result
        for i, line in enumerate(lines, 1):
            if re.search(r"(HashMap|Hashtable)\s*<\s*\w+\s*,\s*\w+\s*>\s+\w+\s*(;|=)", line) and \
               re.search(r"query|select|find|get", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_HASHMAP_RESULT",
                          "不允许直接拿 HashMap 与 Hashtable 作为查询结果集的输出",
                          Severity.WARNING, line=i)

        # 5.4.7 Update update_time
        for i, line in enumerate(lines, 1):
            if re.search(r"UPDATE\s+\w+\s+SET", line, re.IGNORECASE) and \
               not re.search(r"update_time|updateTime|update_at", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_UPDATE_TIME",
                          "更新数据表记录时，必须同时更新记录对应的 update_time 字段值为当前时间",
                          Severity.INFO, line=i)

        # 5.1.3 Table name: no plural nouns
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                cn = node.name
                for suffix in ("sDO", "sPO", "sEntity", "ListDO", "ListPO", "SetDO"):
                    if cn.endswith(suffix):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_TABLE_PLURAL",
                                  f"表名（类 '{cn}'）不使用复数名词",
                                  Severity.WARNING, line=l, column=c)
                        break

        # 5.1.4 Reserved words
        MYSQL_RESERVED_WORDS = [
            "desc", "range", "match", "delayed", "order", "group", "select", "insert",
            "update", "delete", "from", "where", "having", "between", "like", "and", "or",
            "in", "not", "is", "null", "key", "index", "primary", "foreign", "default",
            "check", "begin", "commit", "rollback", "savepoint", "grant", "revoke",
            "call", "procedure", "function", "trigger", "cursor", "escape", "exists"
        ]
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            if decl.name.lower() in MYSQL_RESERVED_WORDS:
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_RESERVED_WORD",
                                          f"字段名 '{decl.name}' 是 MySQL 保留字，请避免使用",
                                          Severity.WARNING, line=l, column=c)

        # 5.1.6 Use decimal for money, not float/double
        # 5.1.5 Index naming: pk_, uk_, idx_
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        ann_str = str([getattr(a, "name", "") for a in (member.annotations or [])])
                        decl_str = str([d.name for d in member.declarators])
                        for i, line in enumerate(lines, 1):
                            if re.search(r"@Index|@TableIndex|uniqueIndex|index.*=", line) and \
                               not re.search(r"idx_\w+|uk_\w+|pk_\w+", line) and \
                               not re.search(r"//", line):
                                self._add(file_path, "ALIBABA_INDEX_NAMING",
                                          "主键索引用 pk_，唯一索引用 uk_，普通索引用 idx_ 前缀",
                                          Severity.INFO, line=i)

        # 5.1.6 Use decimal for money, not float/double
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name in ("float", "double") and \
                   "static" not in (node.modifiers or []) and "final" not in (node.modifiers or []):
                    for decl in node.declarators:
                        fn = decl.name.lower()
                        if any(kw in fn for kw in ("price", "amount", "money", "salary", "cost", "fee", "payment", "total", "sum", "balance")):
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_DECIMAL_TYPE",
                                      "小数类型为 decimal，禁止使用 float 和 double 表示金额",
                                      Severity.WARNING, line=l, column=c)

        # 5.2.1 Unique index on logically unique fields
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                fields = []
                has_unique = False
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        for ann in (member.annotations or []):
                            if hasattr(ann, "name") and ann.name in ("Column", "Table", "TableField"):
                                if "unique" in str(ann).lower() or "UniqueConstraint" in str(ann).lower():
                                    has_unique = True
                        for decl in member.declarators:
                            fn = decl.name.lower()
                            if fn in ("name", "email", "phone", "mobile", "order_no", "orderNo", "trade_no", "tradeNo",
                                      "id_card", "idCard", "serial_no", "serialNo", "code", "username"):
                                if not has_unique:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_UNIQUE_INDEX",
                                              f"字段 '{decl.name}' 业务上具有唯一特性，必须建成唯一索引",
                                              Severity.WARNING, line=l, column=c)
                                    break
                    if has_unique:
                        break

        # 5.2.4 No left-fuzzy LIKE
        for i, line in enumerate(lines, 1):
            if re.search(r"LIKE\s+['\"]%\w+%['\"]", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_LEFT_FUZZY",
                          "页面搜索严禁左模糊或者全模糊，需要请走搜索引擎来解决",
                          Severity.WARNING, line=i)

        # 5.2.5 Varchar index must specify length
        for i, line in enumerate(lines, 1):
            if re.search(r"@Column|@TableField|columnDefinition", line) and \
               re.search(r"varchar", line, re.IGNORECASE) and \
               re.search(r"unique|index", line, re.IGNORECASE) and \
               not re.search(r"length\s*=", line) and \
               not re.search(r"//", line):
                m = re.search(r'@(Column|TableField)\s*\(\s*.*name\s*=\s*"(\w+)"', line)
                if m:
                    self._add(file_path, "ALIBABA_VARCHAR_INDEX_LENGTH",
                              f"varchar 字段 '{m.group(2)}' 建立索引时未指定索引长度",
                              Severity.WARNING, line=i)

        # 5.3.9 Covering index to avoid back-to-table
        for i, line in enumerate(lines, 1):
            if re.search(r"SELECT\s+\w+.*FROM", line, re.IGNORECASE) and \
               re.search(r"WHERE", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                if re.search(r"ORDER\s+BY", line, re.IGNORECASE) and \
                   not re.search(r"SELECT.*FROM.*WHERE", line, re.IGNORECASE):
                    pass  # too broad for AST-based detection
                m_select = re.search(r"SELECT\s+(.+?)\s+FROM", line, re.IGNORECASE)
                m_where_col = re.search(r"WHERE\s+(\w+\.\w+)", line, re.IGNORECASE)
                if m_select and m_where_col:
                    select_cols = m_select.group(1)
                    where_col = m_where_col.group(1).split(".")[-1]
                    if select_cols.strip() != "*" and \
                       where_col not in select_cols:
                        self._add(file_path, "ALIBABA_COVERING_INDEX",
                                  "考虑利用覆盖索引进行查询，避免回表查询",
                                  Severity.INFO, line=i)

        # 5.3.10 Composite index: highest cardinality first
        for i, line in enumerate(lines, 1):
            if re.search(r"@Table\(.*indexes", line, re.IGNORECASE) or \
               re.search(r"@Index", line):
                if re.search(r"columnList\s*=\s*\"\w+,\w+", line):
                    m = re.search(r"columnList\s*=\s*\"(.+?)\"", line)
                    if m:
                        cols = [c.strip() for c in m.group(1).split(",")]
                        if len(cols) >= 2:
                            self._add(file_path, "ALIBABA_COMPOSITE_INDEX",
                                      f"组合索引 '{','.join(cols)}' 应将区分度最高的列放在最左边",
                                      Severity.INFO, line=i)

        # 5.3.6 No foreign keys
        for i, line in enumerate(lines, 1):
            if re.search(r"@JoinColumn.*foreignKey|@OnDelete|foreignKey\s*=|@ForeignKey", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_NO_FOREIGN_KEY",
                          "不得使用外键与级联，一切外键概念必须在应用层解决",
                          Severity.WARNING, line=i)

        # 5.3.7 No more than 3 table join
        for i, line in enumerate(lines, 1):
            if re.search(r"JOIN\s+\w+.*JOIN\s+\w+.*JOIN\s+\w+.*JOIN\s+\w+", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_JOIN_LIMIT",
                          "超过三个表禁止 join，需要 join 的字段数据类型必须保持一致",
                          Severity.WARNING, line=i)

        # 5.3.8 SELECT before DELETE/UPDATE
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(DELETE|UPDATE)\b.*\b(WHERE|SET)\b", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               not re.search(r"@.*Annotation|\.delete\(", line):
                has_preceding_select = False
                for j in range(max(0, i - 10), i):
                    if j < len(lines) and re.search(r"SELECT\b.*\bFROM\b", lines[j], re.IGNORECASE) and \
                       re.search(re.escape(line.strip()[:20]), lines[j]):
                        has_preceding_select = True
                        break
                if not has_preceding_select:
                    self._add(file_path, "ALIBABA_SELECT_BEFORE_DML",
                              "数据订正（删除/修改记录操作）时，先 SELECT 确认无误再执行",
                              Severity.INFO, line=i)

        # 5.4.8 No big update-all-fields
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                if node.name.startswith("update") and len(body_stmts) == 1:
                    for stmt in body_stmts:
                        stmt_str = str(stmt)
                        if "set" in stmt_str.lower() and stmt_str.count(",") > 3:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_UPDATE_ALL_FIELDS",
                                      "不要写大而全的数据更新接口，只更新目标字段而非所有字段",
                                      Severity.INFO, line=l, column=c)

        # 5.4.9 @Transactional not on read-only methods
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "Transactional" in ann_names:
                    mn = node.name.lower()
                    if mn.startswith(("get", "find", "query", "select", "list", "count", "search", "read")):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_TRANSACTIONAL_READONLY",
                                  "@Transactional 不要滥用，只读方法不需要事务，考虑回滚方案",
                                  Severity.INFO, line=l, column=c)

    # ==================== 三、单元测试 ====================
    def check_unit_test(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_unit_test"):
            return
        lines = content.split("\n")

        # 3.7 Test code must be in src/test/java
        if "src/test/java" not in file_path and \
           re.search(r"@Test|@RunWith|Mockito|assertThat|assertEquals|assertTrue", content):
            for i, line in enumerate(lines, 1):
                if re.search(r"@Test", line):
                    self._add(file_path, "ALIBABA_TEST_LOCATION",
                              "单元测试代码必须写在 src/test/java 目录下",
                              Severity.WARNING, line=i)
                    break

        # 3.4 Tests should not depend on environment
        for i, line in enumerate(lines, 1):
            if re.search(r"@Test", line):
                for j in range(i, min(i + 20, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"new\s+File\(|System\.getProperty|InetAddress", lines[j - 1]):
                        self._add(file_path, "ALIBABA_TEST_ENV_DEP",
                                  "单元测试应该不依赖外界环境（如文件系统、网络），以保证可重复执行",
                                  Severity.WARNING, line=j)
                        break

        # 3.2 Tests must use assert, not System.out
        in_test = False
        for i, line in enumerate(lines, 1):
            if re.search(r"@Test", line):
                in_test = True
                has_assert = False
                for j in range(i, min(i + 50, len(lines) + 1)):
                    if j <= len(lines):
                        if re.search(r"assert(True|False|Equals|Null|NotNull|Same|That|ArrayEquals)|fail\s*\(", lines[j - 1]):
                            has_assert = True
                            break
                        if re.search(r"^\s*\}\s*$", lines[j - 1]):
                            break
                if not has_assert and "src/test/java" in file_path:
                    l = i
                    self._add(file_path, "ALIBABA_TEST_NO_ASSERT",
                              "单元测试必须使用 assert 验证结果，而非 System.out 人肉验证",
                              Severity.WARNING, line=l)
                in_test = False

        # 3.10 Tests should not hardcode DB IDs
        if "src/test/java" in file_path:
            for i, line in enumerate(lines, 1):
                if re.search(r"\.(get|find|query|select)\w*\s*\(\s*\d{5,}\s*\)", line) and \
                   not re.search(r"//", line):
                    self._add(file_path, "ALIBABA_TEST_HARDCODED_ID",
                              "单元测试不能假设数据库数据存在，请使用程序插入数据而非硬编码 ID",
                              Severity.WARNING, line=i)

        # 3.11 Tests should have @Rollback for DB
        has_rollback = False
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                for ann in (node.annotations or []):
                    if hasattr(ann, "name") and ann.name in ("Rollback", "Transactional"):
                        if ann.name == "Rollback":
                            has_rollback = True
                        break
        if not has_rollback and "@Test" in content and "src/test/java" in file_path:
            for path, node in tree:
                if isinstance(node, javalang.tree.ClassDeclaration):
                    if node.name.endswith("Test"):
                        annotations = [getattr(a, "name", "") for a in (node.annotations or [])]
                        if "Transactional" in annotations and "Rollback" not in annotations:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_TEST_ROLLBACK",
                                      "数据库相关的单元测试应设定自动回滚机制，建议添加 @Rollback 注解",
                                      Severity.INFO, line=l, column=c)
                        break

    # ==================== 六、工程结构 ====================
    def check_engineering(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_engineering"):
            return
        lines = content.split("\n")

        # 6.0.x Check pom.xml for SNAPSHOT dependencies
        if file_path.endswith("pom.xml"):
            for i, line in enumerate(lines, 1):
                if re.search(r"SNAPSHOT", line) and \
                   not re.search(r"<!--|-->|//", line) and \
                   not re.search(r"安全|security|safety", line, re.IGNORECASE):
                    self._add(file_path, "ALIBABA_SNAPSHOT_DEP",
                              "线上应用不要依赖 SNAPSHOT 版本（安全包除外）",
                              Severity.WARNING, line=i)

        # 6.0.x Check pom.xml for version variables
        if file_path.endswith("pom.xml"):
            has_properties = False
            has_dep_management = False
            for i, line in enumerate(lines, 1):
                if re.search(r"<properties>", line):
                    has_properties = True
                if re.search(r"<dependencyManagement>", line):
                    has_dep_management = True
            if not has_properties and not has_dep_management:
                for i, line in enumerate(lines, 1):
                    if re.search(r"<dependencies>", line) and \
                       not re.search(r"<dependencyManagement>", lines[max(0, i - 5)]):
                        self._add(file_path, "ALIBABA_POM_UNIFIED_VERSION",
                                  "依赖于一个二方库群时，必须定义一个统一的版本变量，避免版本号不一致",
                                  Severity.INFO, line=i)
                        break

        # 6.0.x Check pom.xml for version format
        if file_path.endswith("pom.xml"):
            for i, line in enumerate(lines, 1):
                if re.search(r"<version>", line) and \
                   not re.search(r"SNAPSHOT", line, re.IGNORECASE) and \
                   not re.search(r"<!--|-->", line):
                    m = re.search(r"<version>([^<]+)</version>", line)
                    if m:
                        ver = m.group(1)
                        if not re.search(r"^\d+\.\d+\.\d+", ver) and \
                           not re.search(r"^\$\{", ver):
                            self._add(file_path, "ALIBABA_VERSION_FORMAT",
                                      f"版本号 '{ver}' 不符合主版本号.次版本号.修订号格式",
                                      Severity.INFO, line=i)

        # 6.0.x POM: all deps in <dependencies>, versions in <dependencyManagement>
        if file_path.endswith("pom.xml"):
            in_dep_mgmt = False
            for i, line in enumerate(lines, 1):
                if re.search(r"<dependencyManagement>", line):
                    in_dep_mgmt = True
                elif re.search(r"</dependencyManagement>", line):
                    in_dep_mgmt = False
                if re.search(r"<version>[^$]", line) and \
                   not re.search(r"<version>\$\{", line) and \
                   not re.search(r"<!--|-->", line) and \
                   not in_dep_mgmt:
                    m = re.search(r"<version>([^<]+)</version>", line)
                    if m and not re.search(r"^\$\{", m.group(1)):
                        version_val = m.group(1)
                        if re.search(r"^\d+\.\d+\.\d+", version_val):
                            self._add(file_path, "ALIBABA_POM_DEP_VERSION",
                                      f"依赖版本 '{version_val}' 应通过 <dependencyManagement> 统一管理版本变量",
                                      Severity.INFO, line=i)

        # 6.1.1 Layer naming: Controller/Service/DAO/Manager naming
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("Controller") and not any(
                    isinstance(m, javalang.tree.MethodDeclaration) and m.name.startswith(("get", "list", "query", "find", "add", "create", "update", "delete", "remove", "save"))
                    for m in (node.body or [])
                ):
                    pass  # data controller without typical API methods
                if cn.endswith("ServiceImpl") and not cn.endswith("Impl"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_IMPL_SUFFIX",
                              f"Service 实现类 '{cn}' 应以 Impl 结尾",
                              Severity.INFO, line=l, column=c)

        # 6.1.2 Layer exception handling: DAO->Service->Web
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("DAO") or cn.endswith("Mapper") or cn.endswith("Repository"):
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.MethodDeclaration):
                            body_stmts = member.body if isinstance(member.body, list) else getattr(getattr(member, "body", None), "statements", []) or []
                            for stmt in body_stmts:
                                if isinstance(stmt, javalang.tree.TryStatement):
                                    for catch in (stmt.catches or []):
                                        if catch.parameter and catch.parameter.type and \
                                           catch.parameter.type.name == "Exception":
                                            l, c = self._pos(member)
                                            self._add(file_path, "ALIBABA_DAO_EXCEPTION",
                                                      f"DAO 层方法 '{member.name}' 应使用 catch(Exception e) 并 throw new DAOException(e)",
                                                      Severity.INFO, line=l, column=c)
                                            break
                                    break

        # 6.1.3 DO/DTO/BO/VO naming in proper packages
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("DO") and "entity" not in file_path.lower() and "model" not in file_path.lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_DO_PACKAGE",
                              f"数据对象 '{cn}' 应放在 entity 或 model 包中",
                              Severity.INFO, line=l, column=c)
                elif cn.endswith("DTO") and "dto" not in file_path.lower() and "api" not in file_path.lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_DTO_PACKAGE",
                              f"数据传输对象 '{cn}' 应放在 dto 或 api 包中",
                              Severity.INFO, line=l, column=c)
                elif cn.endswith("VO") and "vo" not in file_path.lower() and "view" not in file_path.lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_VO_PACKAGE",
                              f"展示对象 '{cn}' 应放在 vo 或 view 包中",
                              Severity.INFO, line=l, column=c)

        # 6.2.1 Remote call timeout
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration):
                        body_stmts = member.body if isinstance(member.body, list) else getattr(getattr(member, "body", None), "statements", []) or []
                        for stmt in body_stmts:
                            stmt_str = str(stmt)
                            if re.search(r"(rpc|dubbo|feign|restTemplate|webClient|httpClient|invoke)\w*\.\s*(invoke|execute|call|send|get|post|put|delete)\s*\(", stmt_str, re.IGNORECASE):
                                found_timeout = False
                                for line in lines[max(0, content.index(stmt_str[:30]) - 30):content.index(stmt_str[:30])]:
                                    if re.search(r"timeout", line, re.IGNORECASE):
                                        found_timeout = True
                                        break
                                if not found_timeout:
                                    l, c = self._pos(member)
                                    self._add(file_path, "ALIBABA_REMOTE_TIMEOUT",
                                              f"远程调用方法 '{member.name}' 必须设置超时时间",
                                              Severity.WARNING, line=l, column=c)
                                break

        # 6.4.1 Error code format
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if "ErrorCode" in cn or "ResultCode" in cn or "ResponseCode" in cn or cn.endswith("Code"):
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.FieldDeclaration):
                            for decl in member.declarators:
                                val = getattr(decl, "initializer", None)
                                if val is not None:
                                    val_str = str(val)
                                    if len(val_str) < 4 or len(val_str) > 8:
                                        l, c = self._pos(decl)
                                        self._add(file_path, "ALIBABA_ERROR_CODE_LEN",
                                                  f"错误码 '{decl.name}' 长度应统一为 5 或 6 位",
                                                  Severity.INFO, line=l, column=c)
                                    if val_str.isdigit() and not re.search(r"(PARAM|BIZ|SYS|DB)", decl.name):
                                        l, c = self._pos(decl)
                                        self._add(file_path, "ALIBABA_ERROR_CODE_CLASS",
                                                  f"错误码 '{decl.name}={val_str}' 需要按参数/业务/系统/DB 分类编号",
                                                  Severity.INFO, line=l, column=c)

        # 6.5.2 No interface using Map for params/result
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith(("Service", "Controller", "Manager", "Component")):
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.MethodDeclaration):
                            rt = getattr(member, "return_type", None)
                            if rt and hasattr(rt, "name") and rt.name in ("Map", "HashMap", "LinkedHashMap"):
                                l, c = self._pos(member)
                                self._add(file_path, "ALIBABA_INTERFACE_MAP_RESULT",
                                          f"接口方法 '{member.name}' 不能返回 Map，应使用 DTO",
                                          Severity.WARNING, line=l, column=c)
                            for param in (member.parameters or []):
                                pt = param.type
                                if pt and hasattr(pt, "name") and pt.name in ("Map", "HashMap"):
                                    l, c = self._pos(member)
                                    self._add(file_path, "ALIBABA_INTERFACE_MAP_PARAM",
                                              f"接口方法 '{member.name}' 不能接受 Map 参数，应使用 DTO",
                                              Severity.WARNING, line=l, column=c)

        # 6.5.4 No method longer than 80 lines
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if isinstance(body, list) and len(body) > 80:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_METHOD_TOO_LONG",
                              f"方法 '{node.name}' 超过 80 行，应进行拆分",
                              Severity.WARNING, line=l, column=c)

        # 6.5.5 Query params >2 should not use Map
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mn = node.name.lower()
                if any(mn.startswith(kw) for kw in ("query", "find", "search", "list", "select", "get")):
                    params = node.parameters or []
                    if len(params) > 2:
                        for param in params:
                            pt = getattr(param, "type", None)
                            if pt and hasattr(pt, "name") and pt.name in ("Map", "HashMap", "LinkedHashMap"):
                                l, c = self._pos(node)
                                self._add(file_path, "ALIBABA_QUERY_PARAM_MAP",
                                          f"查询方法 '{node.name}' 超过 2 个参数时禁止使用 Map 传输，应使用 DTO",
                                          Severity.WARNING, line=l, column=c)

        # 6.6.1 POJO must override toString
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith(("DO", "DTO", "VO", "BO", "PO", "Entity", "Model")):
                    has_to_string = False
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.MethodDeclaration) and member.name == "toString":
                            has_to_string = True
                            break
                    if not has_to_string:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_POJO_TOSTRING",
                                  f"POJO 类 '{cn}' 应重写 toString 方法",
                                  Severity.INFO, line=l, column=c)

        # 6.7.4 @Service/@Component should use Spring annotation
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith(("ServiceImpl", "ManagerImpl")):
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if not any(a in ann_names for a in ("Service", "Component", "Repository", "RestController", "Controller")):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_SPRING_ANNOTATION",
                                  f"类 '{cn}' 需要添加 Spring Bean 注解",
                                  Severity.INFO, line=l, column=c)

    # ==================== 七、设计规约 ====================
    def check_design(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_design"):
            return
        lines = content.split("\n")

        # 7.10 Single responsibility
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                field_count = 0
                method_count = 0
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        field_count += len(member.declarators)
                    elif isinstance(member, javalang.tree.MethodDeclaration):
                        method_count += 1
                if field_count > 20 and method_count > 20:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_SINGLE_RESPONSIBILITY",
                              f"类 '{node.name}' 职责可能过重（{field_count} 个字段, {method_count} 个方法），建议符合单一职责原则",
                              Severity.INFO, line=l, column=c)

        # 7.11 Favor composition over inheritance
        for i, line in enumerate(lines, 1):
            if re.search(r"\bextends\s+\w+\s*\{", line) and \
               not re.search(r"(Exception|RuntimeException|Throwable|Error|Thread|Base|Abstract)", line):
                m = re.search(r"class\s+(\w+)\s+extends\s+(\w+)", line)
                if m and not m.group(2).startswith(("Base", "Abstract")):
                    self._add(file_path, "ALIBABA_COMPOSITION",
                              f"类 '{m.group(1)}' 谨慎使用继承方式扩展，优先使用聚合/组合方式",
                              Severity.INFO, line=i)

        # 7.5 Interface should define contract
        for i, line in enumerate(lines, 1):
            m = re.search(r"interface\s+(\w+)", line)
            if m:
                iface_name = m.group(1)
                has_impl = False
                for j, line2 in enumerate(lines, 1):
                    if re.search(rf"\bimplements\s+\w*{re.escape(iface_name)}\w*", line2):
                        has_impl = True
                        break
                if not has_impl and not iface_name.startswith("Base"):
                    self._add(file_path, "ALIBABA_INTERFACE_EMPTY",
                              f"接口 '{iface_name}' 需要被实现才能存在",
                              Severity.INFO, line=i)

        # 7.6 Avoid deep inheritance (depth > 3)
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if node.extends:
                    parent = node.extends.name
                    depth = 1
                    cur = parent
                    while depth < 10:
                        found_parent = False
                        for path2, node2 in tree:
                            if isinstance(node2, javalang.tree.ClassDeclaration) and node2.name == cur:
                                if node2.extends:
                                    cur = node2.extends.name
                                    depth += 1
                                    found_parent = True
                                break
                        if not found_parent:
                            break
                    if depth >= 3:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_DEEP_INHERITANCE",
                                  f"类 '{node.name}' 继承层次过深（{depth} 层），最大不超过 3 层",
                                  Severity.INFO, line=l, column=c)

        # 7.8 No class with multiple if-else + switch > 10
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if_else_count = 0
                switch_count = 0
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration):
                        body_str = str(member.body or "")
                        if_else_count += len(re.findall(r"\bif\s*\(", body_str))
                        switch_count += len(re.findall(r"\bswitch\s*\(", body_str))
                if if_else_count > 15:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_EXCESSIVE_IFELSE",
                              f"类 '{node.name}' 包含 {if_else_count} 个 if-else，建议用策略模式替代",
                              Severity.WARNING, line=l, column=c)

        # 7.9 Business logic decomposed rather than one big method
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if isinstance(body, list) and len(body) > 50:
                    line_count = 0
                    for stmt in body:
                        stmt_lines = str(stmt).split("\n")
                        line_count += len(stmt_lines)
                    if line_count > 100:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_BIG_METHOD",
                                  f"方法 '{node.name}' 过长，应分解为多个小方法",
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
        self.check_frontend_backend(tree, file_path, content)
        self.check_security(tree, file_path, content)
        self.check_sql(tree, file_path, content)
        self.check_unit_test(tree, file_path, content)
        self.check_design(tree, file_path, content)
        self.check_engineering(tree, file_path, content)
