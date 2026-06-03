"""集合处理 — 22 条规则：toMap、subList、foreach、初始化容量"""
import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class CollectionChecker(BaseChecker):

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
