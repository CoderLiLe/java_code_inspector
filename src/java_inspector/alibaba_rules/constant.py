import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class ConstantChecker(BaseChecker):

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
