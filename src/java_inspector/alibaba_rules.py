import re
from typing import List

import javalang

from java_inspector.models import CodeIssue, Severity
from java_inspector.config import InspectionConfig


class AlibabaRulesChecker:
    def __init__(self, config: InspectionConfig, issues: List[CodeIssue]):
        self.config = config
        self.issues = issues

    def check_naming(self, tree, file_path: str, content: str):
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

    def check_oop(self, tree, file_path: str, content: str):
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

    def check_control(self, tree, file_path: str, content: str):
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

    def check_collection(self, tree, file_path: str, content: str):
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
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines) and re.search(r'\.remove\(', lines[j - 1]):
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
                    if j <= len(lines) and re.search(r'^\s*\}', lines[j - 1]):
                        break

    def check_constant(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_constant"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            for match in re.finditer(r'(\d+)[lL]\s*[;,]', line):
                suffix = line[match.start(1) + len(match.group(1)):match.start(1) + len(match.group(1)) + 1]
                if suffix == 'l':
                    self.issues.append(
                        CodeIssue(
                            file_path=file_path,
                            line=i,
                            column=match.start(),
                            message="【阿里规约】long 赋值时数值后的 L 应大写，不能是小写 l",
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
                            message="【阿里规约】浮点数类型的数值后缀应统一为大写的 D 或 F",
                            severity=Severity.INFO,
                            rule_id="ALIBABA_FLOAT_SUFFIX",
                            category="ALIBABA",
                        )
                    )

    def check_method_length(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_method_length"):
            return
        max_lines = self.config.get_rule_config("alibaba_method_length").get("max_lines", 80)
        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            if method.position:
                start_line = method.position.line
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
                            body_lines = last_stmt.position.line - start_line
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

    def run_all(self, tree, file_path: str, content: str):
        self.check_naming(tree, file_path, content)
        self.check_oop(tree, file_path, content)
        self.check_control(tree, file_path, content)
        self.check_collection(tree, file_path, content)
        self.check_constant(tree, file_path, content)
        self.check_method_length(tree, file_path, content)
