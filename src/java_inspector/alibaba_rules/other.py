"""其他 — 8 条规则：正则编译、BeanUtils、SQL 注入"""
import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class OtherChecker(BaseChecker):

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
