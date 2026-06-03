import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker, RACIST_PATTERNS, CHINESE_PATTERN, INSULT_PATTERNS


class NamingChecker(BaseChecker):

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
