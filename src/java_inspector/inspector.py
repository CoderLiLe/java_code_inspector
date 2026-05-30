import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

import javalang

from java_inspector.models import CodeIssue, CodeMetrics, Severity
from java_inspector.config import InspectionConfig


class JavaCodeInspector:
    def __init__(self, config: InspectionConfig = None):
        self.issues: List[CodeIssue] = []
        self.metrics: Dict[str, CodeMetrics] = {}
        self.config = config or InspectionConfig()
        self.duplicate_blocks: Dict[str, List[Tuple[int, int]]] = {}

    def inspect_file(self, file_path: str) -> List[CodeIssue]:
        self.issues.clear()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = javalang.parse.parse(content)

            self._check_unused_imports(tree, file_path, content)
            self._check_naming_conventions(tree, file_path)
            self._check_code_style(tree, file_path, content)
            self._check_method_complexity(tree, file_path, content)
            self._check_class_design(tree, file_path)
            self._check_best_practices(tree, file_path, content)
            self._check_empty_methods(tree, file_path)
            self._check_exception_handling(tree, file_path, content)
            self._check_magic_numbers(tree, file_path, content)
            self._check_alibaba_naming(tree, file_path, content)
            self._check_alibaba_oop(tree, file_path, content)
            self._check_alibaba_control(tree, file_path, content)
            self._check_alibaba_collection(tree, file_path, content)
            self._check_alibaba_constant(tree, file_path, content)
            self._check_alibaba_method_length(tree, file_path, content)

            self._calculate_metrics(tree, file_path, content)

        except Exception as e:
            self.issues.append(
                CodeIssue(
                    file_path=file_path,
                    line=0,
                    column=0,
                    message=f"解析文件失败: {str(e)}",
                    severity=Severity.ERROR,
                    rule_id="PARSE_ERROR",
                    category="PARSING",
                )
            )

        return self.issues

    def inspect_directory(self, directory_path: str) -> Dict[str, List[CodeIssue]]:
        results = {}

        if self.config.is_rule_enabled("duplicate_code"):
            self._check_duplicate_code(directory_path)

        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    if self._is_excluded(file_path):
                        continue
                    issues = self.inspect_file(file_path)
                    results[file_path] = list(issues)

        return results

    def _is_excluded(self, file_path: str) -> bool:
        for pattern in self.config.config["exclude_patterns"]:
            if Path(file_path).match(pattern):
                return True
        return False

    def _check_unused_imports(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("unused_imports"):
            return

        used_names = set()
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation):
                used_names.add(node.member)
            elif isinstance(node, javalang.tree.ClassReference):
                used_names.add(
                    node.type.name if hasattr(node.type, "name") else str(node.type)
                )

        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                if node.wildcard:
                    continue
                import_name = node.path or ""
                if not import_name:
                    continue
                simple_name = import_name.split(".")[-1]
                if simple_name not in used_names:
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"未使用的导入: {import_name}",
                            severity=Severity.INFO,
                            rule_id="UNUSED_IMPORT",
                            category="STYLE",
                            fixable=True,
                            fix_suggestion=f"删除未使用的导入: {import_name}",
                        )
                    )

    def _check_naming_conventions(self, tree, file_path: str):
        if not self.config.is_rule_enabled("naming_conventions"):
            return

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if node.name and node.name[0].islower():
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"类名 '{node.name}' 应以大写字母开头",
                            severity=Severity.WARNING,
                            rule_id="CLASS_NAMING",
                            category="STYLE",
                            fixable=True,
                            fix_suggestion=(
                                f"重命名类为 '{node.name[0].upper() + node.name[1:]}'"
                            ),
                        )
                    )
            elif isinstance(node, javalang.tree.MethodDeclaration):
                if (
                    node.name
                    and node.name[0].isupper()
                    and node.name != node.name.upper()
                ):
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"方法名 '{node.name}' 应以小写字母开头",
                            severity=Severity.WARNING,
                            rule_id="METHOD_NAMING",
                            category="STYLE",
                            fixable=True,
                            fix_suggestion=(
                                f"重命名方法为 '{node.name[0].lower() + node.name[1:]}'"
                            ),
                        )
                    )
            elif isinstance(node, javalang.tree.FieldDeclaration):
                is_constant = "static" in node.modifiers and "final" in node.modifiers
                for declarator in node.declarators:
                    if is_constant:
                        if not all(
                            c.isupper() or c == "_" for c in declarator.name
                        ):
                            self.issues.append(
                                CodeIssue(
                                    file_path=file_path,
                                    line=(
                                        declarator.position.line
                                        if declarator.position
                                        else 0
                                    ),
                                    column=(
                                        declarator.position.column
                                        if declarator.position
                                        else 0
                                    ),
                                    message=(
                                        f"常量 '{declarator.name}'"
                                        " 应使用 CONSTANT_CASE（全大写+下划线）"
                                    ),
                                    severity=Severity.WARNING,
                                    rule_id="CONSTANT_NAMING",
                                    category="STYLE",
                                )
                            )
                    elif (
                        declarator.name
                        and declarator.name[0].isupper()
                        and not all(
                            c.isupper() or c == "_" for c in declarator.name
                        )
                    ):
                        self.issues.append(
                            CodeIssue(
                                file_path=file_path,
                                line=(
                                    declarator.position.line
                                    if declarator.position
                                    else 0
                                ),
                                column=(
                                    declarator.position.column
                                    if declarator.position
                                    else 0
                                ),
                                message=f"字段名 '{declarator.name}' 应以小写字母开头",
                                severity=Severity.WARNING,
                                rule_id="FIELD_NAMING",
                                category="STYLE",
                            )
                        )

    def _check_code_style(self, tree, file_path: str, content: str):
        max_length = self.config.get_rule_config("line_length").get("max_length", 120)
        check_length = self.config.is_rule_enabled("line_length")
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if check_length and len(line) > max_length:
                self.issues.append(
                    CodeIssue(
                        file_path=file_path,
                        line=i,
                        column=max_length,
                        message=f"行过长: {len(line)} 字符 (建议 ≤{max_length})",
                        severity=Severity.WARNING,
                        rule_id="LINE_LENGTH",
                        category="STYLE",
                        fixable=True,
                        fix_suggestion="拆分长行为多行",
                    )
                )
            if line != line.rstrip():
                self.issues.append(
                    CodeIssue(
                        file_path=file_path,
                        line=i,
                        column=len(line.rstrip()),
                        message="行尾存在多余空格",
                        severity=Severity.INFO,
                        rule_id="TRAILING_WHITESPACE",
                        category="STYLE",
                        fixable=True,
                        fix_suggestion="删除行尾空格",
                    )
                )

    def _check_method_complexity(self, tree, file_path: str, content: str):
        max_method = self.config.get_rule_config("method_complexity").get(
            "max_complexity", 10
        )
        max_cyclo = self.config.get_rule_config("cyclomatic_complexity").get(
            "max_complexity", 15
        )
        check_method = self.config.is_rule_enabled("method_complexity")
        check_cyclo = self.config.is_rule_enabled("cyclomatic_complexity")
        if not check_method and not check_cyclo:
            return

        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            branch_count = 0
            cyclo = 1

            def walk(node, _branch_count, _cyclo):
                try:
                    if isinstance(
                        node,
                        (
                            javalang.tree.IfStatement,
                            javalang.tree.WhileStatement,
                            javalang.tree.ForStatement,
                        ),
                    ):
                        _branch_count += 1
                    if isinstance(
                        node,
                        (
                            javalang.tree.IfStatement,
                            javalang.tree.WhileStatement,
                            javalang.tree.ForStatement,
                            javalang.tree.SwitchStatement,
                            javalang.tree.CatchClause,
                            javalang.tree.TernaryExpression,
                        ),
                    ):
                        _cyclo += 1
                    children = getattr(node, "children", None) or []
                    for child in children:
                        if isinstance(child, (list, tuple)):
                            for item in child:
                                if hasattr(item, "children"):
                                    _branch_count, _cyclo = walk(
                                        item, _branch_count, _cyclo
                                    )
                        elif hasattr(child, "children"):
                            _branch_count, _cyclo = walk(
                                child, _branch_count, _cyclo
                            )
                except Exception:
                    pass
                return _branch_count, _cyclo

            try:
                branch_count, cyclo = walk(method, branch_count, cyclo)
            except Exception:
                pass

            if check_method and branch_count > max_method:
                self.issues.append(
                    CodeIssue(
                        file_path=file_path,
                        line=method.position.line if method.position else 0,
                        column=method.position.column if method.position else 0,
                        message=f"方法圈复杂度: {branch_count} (建议 ≤{max_method})",
                        severity=Severity.WARNING,
                        rule_id="METHOD_COMPLEXITY",
                        category="COMPLEXITY",
                        fixable=True,
                        fix_suggestion="考虑重构方法，降低复杂度",
                    )
                )
            if check_cyclo and cyclo > max_cyclo:
                self.issues.append(
                    CodeIssue(
                        file_path=file_path,
                        line=method.position.line if method.position else 0,
                        column=method.position.column if method.position else 0,
                        message=f"圈复杂度过高: {cyclo} (建议 ≤{max_cyclo})",
                        severity=Severity.WARNING,
                        rule_id="HIGH_CYCLOMATIC_COMPLEXITY",
                        category="COMPLEXITY",
                    )
                )

    def _check_class_design(self, tree, file_path: str):
        if not self.config.is_rule_enabled("comments_ratio"):
            return

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                if len(node.name) > 40:
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"类名过长: {len(node.name)} 字符",
                            severity=Severity.INFO,
                            rule_id="LONG_CLASS_NAME",
                            category="DESIGN",
                        )
                    )

    def _check_best_practices(self, tree, file_path: str, content: str):
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"System\.(out|err)\.(print|println|printf)", line):
                self.issues.append(
                    CodeIssue(
                        file_path=file_path,
                        line=i,
                        column=line.find("System."),
                        message="避免直接使用 System.out/err，建议使用日志框架",
                        severity=Severity.INFO,
                        rule_id="AVOID_SYSTEM_OUT",
                        category="BEST_PRACTICE",
                        fixable=True,
                        fix_suggestion="使用 Logger 替代 System.out/err",
                    )
                )

    def _calculate_metrics(self, tree, file_path: str, content: str):
        metrics = CodeMetrics()
        lines = content.split("\n")
        metrics.total_lines = len(lines)

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("//", "*", "/*")):
                metrics.comment_lines += 1
            else:
                metrics.code_lines += 1

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                metrics.class_count += 1
            elif isinstance(node, javalang.tree.MethodDeclaration):
                metrics.method_count += 1

        self.metrics[file_path] = metrics

    def _check_empty_methods(self, tree, file_path: str):
        if not self.config.is_rule_enabled("empty_methods"):
            return

        for type_decl in tree.types:
            for decl in type_decl.body:
                if isinstance(decl, javalang.tree.MethodDeclaration):
                    body = decl.body
                    is_empty = body is None
                    if not is_empty:
                        if isinstance(body, list):
                            statements = body
                        else:
                            statements = getattr(body, "statements", None)
                        is_empty = statements is None or len(statements) == 0
                    if is_empty:
                        self.issues.append(
                            CodeIssue(
                                file_path=file_path,
                                line=decl.position.line if decl.position else 0,
                                column=decl.position.column if decl.position else 0,
                                message=f"空方法: {decl.name}",
                                severity=Severity.WARNING,
                                rule_id="EMPTY_METHOD",
                                category="DESIGN",
                                fixable=True,
                                fix_suggestion="删除空方法或添加实现",
                            )
                        )

    def _check_exception_handling(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("exception_handling"):
            return

        pattern = re.compile(r"catch\s*\([^)]+\)\s*\{[\s\n]*\}", re.DOTALL)
        for match in pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            self.issues.append(
                CodeIssue(
                    file_path=file_path,
                    line=line_num,
                    column=0,
                    message="空的catch块，应该至少记录异常",
                    severity=Severity.WARNING,
                    rule_id="EMPTY_CATCH",
                    category="EXCEPTION",
                    fixable=True,
                    fix_suggestion="添加异常处理逻辑",
                )
            )

    def _check_magic_numbers(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("magic_numbers"):
            return

        magic_number_pattern = r"\b([0-9]{2,}|[0-9]\.[0-9]+)\b"
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            numbers = re.findall(magic_number_pattern, line)
            for number in numbers:
                if number not in ["0", "1", "-1", "0.0", "1.0"]:
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=line.find(number),
                            message=f"魔法数字: {number}，建议定义为常量",
                            severity=Severity.INFO,
                            rule_id="MAGIC_NUMBER",
                            category="STYLE",
                            fixable=True,
                            fix_suggestion=(
                                f"定义常量: public static final int"
                                f" NUMBER_{number} = {number};"
                            ),
                        )
                    )

    def _check_duplicate_code(self, directory_path: str):
        if not self.config.is_rule_enabled("duplicate_code"):
            return

        min_tokens = self.config.get_rule_config("duplicate_code").get("min_tokens", 50)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            java_files = []
            for root, _, files in os.walk(directory_path):
                for file in files:
                    if file.endswith(".java") and not self._is_excluded(
                        os.path.join(root, file)
                    ):
                        java_files.append(os.path.join(root, file))

            self._simple_duplicate_detection(java_files, min_tokens)

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _simple_duplicate_detection(self, java_files: List[str], min_tokens: int):
        code_blocks = {}

        for file_path in java_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                methods = re.findall(r"(\b\w+\s+[^{]+\{[^}]+\})", content, re.DOTALL)
                for method in methods:
                    code_hash = hashlib.md5(method.strip().encode()).hexdigest()
                    if code_hash in code_blocks:
                        code_blocks[code_hash].append((file_path, method))
                    else:
                        code_blocks[code_hash] = [(file_path, method)]

            except Exception as e:
                print(f"分析文件 {file_path} 时出错: {e}")

        for code_hash, occurrences in code_blocks.items():
            if len(occurrences) > 1 and len(occurrences[0][1].split()) >= min_tokens:
                for file_path, method in occurrences:
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=0,
                            column=0,
                            message=f"重复代码块 ({len(occurrences)} 处重复)",
                            severity=Severity.WARNING,
                            rule_id="DUPLICATE_CODE",
                            category="QUALITY",
                        )
                    )

    def _check_alibaba_naming(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_naming"):
            return

        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                modifiers = node.modifiers or []
                is_abstract = "abstract" in modifiers
                class_name = node.name
                if is_abstract and not class_name.startswith(("Abstract", "Base")):
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"【阿里规约】抽象类 '{class_name}' 命名应以 Abstract 或 Base 开头",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_ABSTRACT_NAMING",
                            category="ALIBABA",
                        )
                    )

            elif isinstance(node, javalang.tree.ClassDeclaration):
                if node.name.endswith("Exception") and "extends" not in str(node):
                    pass

            elif isinstance(node, javalang.tree.EnumDeclaration):
                if node.name and not node.name.endswith("Enum"):
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"【阿里规约】枚举类 '{node.name}' 命名应以 Enum 结尾",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_ENUM_NAMING",
                            category="ALIBABA",
                        )
                    )

        for path, node in tree:
            if isinstance(node, javalang.tree.PackageDeclaration):
                if node.name != node.name.lower():
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=node.position.line if node.position else 0,
                            column=node.position.column if node.position else 0,
                            message=f"【阿里规约】包名 '{node.name}' 必须全部小写",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_PACKAGE_NAME",
                            category="ALIBABA",
                        )
                    )

        for i, line in enumerate(lines, 1):
            if re.search(r"(int|byte|short|long|float|double|char|boolean)\s+\w+\s*\[\]", line):
                self.issues.append(
                    CodeIssue(
                        file_path=file_path,
                        line=i,
                        column=0,
                        message="【阿里规约】类型与中括号应紧挨相连来定义数组，如 int[] arrayDemo",
                        severity=Severity.WARNING,
                        rule_id="ALIBABA_ARRAY_STYLE",
                        category="ALIBABA",
                    )
                )

        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                for declarator in node.declarators:
                    if declarator.name.lower().startswith("is") and len(declarator.name) > 2:
                        type_name = ""
                        if hasattr(node, "type") and hasattr(node.type, "name"):
                            type_name = node.type.name
                        if type_name.lower() in ("boolean", "bool"):
                            self.issues.append(
                                CodeIssue(
                                    file_path=file_path,
                                    line=declarator.position.line if declarator.position else 0,
                                    column=declarator.position.column if declarator.position else 0,
                                    message=f"【阿里规约】POJO 类中布尔类型变量 '{declarator.name}' 不应加 is 前缀",
                                    severity=Severity.WARNING,
                                    rule_id="ALIBABA_BOOLEAN_PREFIX",
                                    category="ALIBABA",
                                )
                            )

    def _check_alibaba_oop(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_oop"):
            return

        lines = content.split("\n")
        has_to_string = False
        is_pojo = False
        class_name = ""

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                if node.name == "toString":
                    has_to_string = True
                if node.name == "equals":
                    has_to_string = True

        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                class_name = node.name
                if not class_name.endswith(("Controller", "Service", "Repository", "Application", "Utils", "Util")):
                    is_pojo = True

        if is_pojo and class_name and not has_to_string:
            for path, node in tree:
                if isinstance(node, javalang.tree.ClassDeclaration):
                    if node.name == class_name:
                        self.issues.append(
                            CodeIssue(
                                file_path=file_path,
                                line=node.position.line if node.position else 0,
                                column=node.position.column if node.position else 0,
                                message=f"【阿里规约】POJO 类 '{class_name}' 必须写 toString 方法",
                                severity=Severity.WARNING,
                                rule_id="ALIBABA_TO_STRING",
                                category="ALIBABA",
                            )
                        )
                        break

        for i, line in enumerate(lines, 1):
            equals_match = re.search(r'(\w+)\.equals\(', line)
            if equals_match:
                var_name = equals_match.group(1)
                if var_name[0].islower() and var_name not in ("this", "super"):
                    if not re.search(r'["\'].+["\']\.equals\(', line):
                        self.issues.append(
                            CodeIssue(
                                file_path=file_path,
                                line=i,
                                column=line.find(var_name + ".equals("),
                                message=f"【阿里规约】Object 的 equals 方法应使用常量或确定有值的对象来调用，"
                                        f"建议: \"constant\".equals({var_name})",
                                severity=Severity.INFO,
                                rule_id="ALIBABA_EQUALS_STYLE",
                                category="ALIBABA",
                            )
                        )

            if re.search(r'\b(Integer|Long|Short|Byte)\s+\w+\s*[=!]=\s*\w+', line):
                if ".intValue()" not in line and ".longValue()" not in line:
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=0,
                            message="【阿里规约】整型包装类对象之间值的比较，全部使用 equals 方法比较",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_INTEGER_COMPARE",
                            category="ALIBABA",
                        )
                    )

            if re.search(r'@Override', line):
                pass

        in_loop = False
        for i, line in enumerate(lines, 1):
            if re.search(r'\b(for|while)\s*\(', line):
                in_loop = True
            if in_loop:
                if re.search(r'\bstr\b.*\+=', line) or re.search(r'\bString\s+\w+\s*=\s*["\']', line):
                    next_lines = lines[i:min(i + 5, len(lines))]
                    for j, nl in enumerate(next_lines):
                        if re.search(r'\+\=', nl) and i + j > i:
                            self.issues.append(
                                CodeIssue(
                                    file_path=file_path,
                                    line=i + j + 1,
                                    column=0,
                                    message="【阿里规约】循环体内字符串连接应使用 StringBuilder 的 append 方法",
                                    severity=Severity.INFO,
                                    rule_id="ALIBABA_STRING_BUILDER",
                                    category="ALIBABA",
                                )
                            )
                            break
                if re.search(r'^\s*\}', line):
                    in_loop = False

    def _check_alibaba_control(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_control"):
            return

        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.SwitchStatement):
                has_default = False
                for child in node.cases:
                    if child.case is None:
                        has_default = True
                        break
                if not has_default:
                    line_num = node.position.line if node.position else 0
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=line_num,
                            column=node.position.column if node.position else 0,
                            message="【阿里规约】switch 块内必须包含一个 default 语句",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_SWITCH_DEFAULT",
                            category="ALIBABA",
                        )
                    )

        for i, line in enumerate(lines, 1):
            if re.search(r'\b(if|else\s+if|for|while|do)\s*\([^)]*\)\s*[^\s{;]', line):
                if not re.search(r'\{\s*$', line):
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=0,
                            message="【阿里规约】if/else/for/while/do 语句中必须使用大括号",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_REQUIRE_BRACES",
                            category="ALIBABA",
                        )
                    )

    def _check_alibaba_collection(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_collection"):
            return

        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            if re.search(r'\.size\(\)\s*==\s*0', line):
                if not re.search(r'//.*\.size\(\)', line):
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=line.find(".size()"),
                            message="【阿里规约】判断集合是否为空应使用 isEmpty() 方法，而不是 size() == 0",
                            severity=Severity.INFO,
                            rule_id="ALIBABA_IS_EMPTY",
                            category="ALIBABA",
                        )
                    )

            if re.search(r'for\s*\([^:]+:\s*\w+\)', line):
                if re.search(r'\.remove\(', lines[i] if i < len(lines) else "") or \
                   re.search(r'\.remove\(', lines[i-2] if i >= 2 else ""):
                    pass
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines) and re.search(r'\.remove\(', lines[j-1]):
                        self.issues.append(
                            CodeIssue(
                                file_path=file_path,
                                line=j,
                                column=0,
                                message="【阿里规约】不要在 foreach 循环里进行元素的 remove 操作，请使用 iterator 方式",
                                severity=Severity.WARNING,
                                rule_id="ALIBABA_FOREACH_REMOVE",
                                category="ALIBABA",
                            )
                        )
                        break
                    if j <= len(lines) and re.search(r'^\s*\}', lines[j-1]):
                        break

    def _check_alibaba_constant(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_constant"):
            return

        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            for match in re.finditer(r'(\d+)[lL]\s*[;,]', line):
                number = match.group(1)
                suffix = line[match.start(1) + len(number):match.start(1) + len(number) + 1]
                if suffix == 'l':
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=match.start(),
                            message=f"【阿里规约】long 赋值时数值后的 L 应大写，不能是小写 l",
                            severity=Severity.INFO,
                            rule_id="ALIBABA_LONG_SUFFIX",
                            category="ALIBABA",
                        )
                    )

            for match in re.finditer(r'(\d+\.\d+)[fFdD]', line):
                number = match.group(1)
                suffix = line[match.end(1):match.end(1) + 1]
                if suffix.lower() == suffix and suffix in ('f', 'd'):
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=match.start(),
                            message=f"【阿里规约】浮点数类型的数值后缀应统一为大写的 D 或 F",
                            severity=Severity.INFO,
                            rule_id="ALIBABA_FLOAT_SUFFIX",
                            category="ALIBABA",
                        )
                    )

    def _check_alibaba_method_length(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_method_length"):
            return

        max_lines = self.config.get_rule_config("alibaba_method_length").get("max_lines", 80)
        lines = content.split("\n")

        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            if method.position:
                start_line = method.position.line
                end_line = start_line
                body_lines = 0

                if method.body:
                    body = method.body
                    if isinstance(body, list):
                        statements = body
                    else:
                        statements = getattr(body, "statements", [])
                    if statements:
                        last_stmt = statements[-1]
                        if hasattr(last_stmt, "position") and last_stmt.position:
                            end_line = last_stmt.position.line
                        body_lines = end_line - start_line

                if body_lines > max_lines:
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=start_line,
                            column=method.position.column,
                            message=f"【阿里规约】方法 '{method.name}' 总行数 {body_lines} 超过建议值 {max_lines} 行",
                            severity=Severity.WARNING,
                            rule_id="ALIBABA_METHOD_LENGTH",
                            category="ALIBABA",
                        )
                    )

    def auto_fix_issues(self, file_path: str) -> List[CodeIssue]:
        fixed_issues = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            lines = content.split("\n")
            modified = False

            issues = self.inspect_file(file_path)
            fixable_issues = [issue for issue in issues if issue.fixable]

            fixable_issues.sort(key=lambda x: x.line, reverse=True)
            for issue in fixable_issues:
                if issue.rule_id == "UNUSED_IMPORT" and self.config.config[
                    "auto_fix"
                ].get("unused_imports", False):
                    line_to_remove = issue.line - 1
                    if 0 <= line_to_remove < len(lines):
                        lines.pop(line_to_remove)
                        modified = True
                        fixed_issues.append(issue)

            if modified:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))

                print(f"已自动修复 {len(fixed_issues)} 个问题在文件 {file_path}")

        except Exception as e:
            print(f"自动修复失败: {e}")

        return fixed_issues
