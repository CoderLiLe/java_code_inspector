"""注释规范 — 11 条规则：Javadoc、TODO/FIXME、注释代码"""
import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class CommentChecker(BaseChecker):

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

        # 9.4b Multi-line comments must use /* */ not consecutive //
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ml = node.position.line if node.position else 0
                method_end = ml
                body = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                if body and hasattr(body[-1], "position") and body[-1].position:
                    method_end = body[-1].position.line + 1
                for j in range(ml, min(method_end, len(lines))):
                    if j + 2 <= len(lines) and \
                       re.search(r"^\s*//", lines[j - 1]) and \
                       re.search(r"^\s*//", lines[j]) and \
                       re.search(r"^\s*//", lines[j + 1]) and \
                       not re.search(r"TODO|FIXME|http", lines[j - 1], re.IGNORECASE) and \
                       not re.search(r"TODO|FIXME|http", lines[j], re.IGNORECASE) and \
                       not re.search(r"TODO|FIXME|http", lines[j + 1], re.IGNORECASE):
                        self._add(file_path, "ALIBABA_MULTILINE_COMMENT",
                                  "方法内超过 3 行连续 // 注释应改用 /* */ 多行注释格式",
                                  Severity.INFO, line=j)
                        break

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
