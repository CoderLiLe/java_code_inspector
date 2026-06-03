"""单元测试 — 5 条规则：测试位置、断言、环境依赖"""
import re
from typing import List

import javalang

from java_inspector.alibaba_rules.base import BaseChecker


class UnitTestChecker(BaseChecker):
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
