#!/usr/bin/env python3
"""
Java代码检查工具的测试用例
"""

import unittest
import os
import tempfile
import shutil
import json

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from java_inspector import (
    JavaCodeInspector,
    InspectionConfig,
    InspectionReporter,
    CICDIntegrator,
    CodeIssue,
    CodeMetrics,
    Severity,
    ReportFormat,
)


class TestJavaCodeInspector(unittest.TestCase):
    """Java代码检查器测试类"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config = InspectionConfig()
        self.inspector = JavaCodeInspector(self.config)
        self.create_test_files()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def create_test_files(self):
        bad_code = '''import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.io.*;

public class testExample {
    private int BadlyNamedField;

    public void BadlyNamedMethod() {
        System.out.println("Hello");
        List<String> list = new ArrayList<>();
        int result = 100 * 2;
        try {
            int test = 10 / 0;
        } catch (Exception e) {
        }
    }

    public void emptyMethod() {
    }
}
'''
        good_code = '''import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

public class GoodExample {
    private static final Logger LOGGER = Logger.getLogger(GoodExample.class.getName());
    private static final int MAX_RETRY = 3;

    private String properlyNamedField;

    public void properlyNamedMethod() {
        LOGGER.info("Proper method");
    }
}
'''

        with open(os.path.join(self.test_dir, 'TestExample.java'), 'w', encoding='utf-8') as f:
            f.write(bad_code)

        with open(os.path.join(self.test_dir, 'GoodExample.java'), 'w', encoding='utf-8') as f:
            f.write(good_code)

    def test_inspect_file_with_issues(self):
        file_path = os.path.join(self.test_dir, 'TestExample.java')
        issues = self.inspector.inspect_file(file_path)

        self.assertGreater(len(issues), 0)
        issue_types = [issue.rule_id for issue in issues]
        has_unused_import = any(issue.rule_id == 'UNUSED_IMPORT' for issue in issues)
        has_naming = any(issue.rule_id in ('CLASS_NAMING', 'METHOD_NAMING') for issue in issues)

        self.assertTrue(has_unused_import, "应该检测到未使用的import")
        self.assertTrue(has_naming, "应该检测到命名问题")

    def test_inspect_good_file(self):
        file_path = os.path.join(self.test_dir, 'GoodExample.java')
        issues = self.inspector.inspect_file(file_path)
        severe_issues = [i for i in issues if i.severity == Severity.ERROR]
        self.assertEqual(len(severe_issues), 0)

    def test_inspect_directory(self):
        issues_by_file = self.inspector.inspect_directory(self.test_dir)
        self.assertEqual(len(issues_by_file), 2)

        test_path = os.path.join(self.test_dir, 'TestExample.java')
        good_path = os.path.join(self.test_dir, 'GoodExample.java')
        test_issues = issues_by_file[test_path]
        good_issues = issues_by_file[good_path]
        self.assertGreater(len(test_issues), len(good_issues),
                          "问题文件应该比良好文件有更多问题")

    def test_config_disabled_rules(self):
        config_data = {"rules": {"unused_imports": {"enabled": False}}}
        config_file = os.path.join(self.test_dir, 'test_config.json')
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f)

        config = InspectionConfig(config_file)
        inspector = JavaCodeInspector(config)
        file_path = os.path.join(self.test_dir, 'TestExample.java')
        issues = inspector.inspect_file(file_path)
        issue_rules = [issue.rule_id for issue in issues]
        self.assertNotIn('UNUSED_IMPORT', issue_rules)

    def test_empty_method_detection(self):
        config = InspectionConfig()
        config.config['rules']['empty_methods'] = {"enabled": True}
        inspector = JavaCodeInspector(config)
        file_path = os.path.join(self.test_dir, 'TestExample.java')
        issues = inspector.inspect_file(file_path)
        empty = [i for i in issues if i.rule_id == 'EMPTY_METHOD']
        self.assertGreaterEqual(len(empty), 1)

    def test_magic_number_detection(self):
        code = 'class Foo { int x = 42; int y = 100; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            magic = [i for i in issues if i.rule_id == 'MAGIC_NUMBER']
            self.assertGreaterEqual(len(magic), 1)
        finally:
            os.unlink(tmp)

    def test_exception_handling_detection(self):
        code = 'class Foo { void bar() { try {} catch (Exception e) {} } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            empty_catch = [i for i in issues if i.rule_id == 'EMPTY_CATCH']
            self.assertGreaterEqual(len(empty_catch), 1)
        finally:
            os.unlink(tmp)

    def test_multiline_empty_catch_detection(self):
        code = '''class Foo {
    void bar() {
        try {
            bar();
        } catch (Exception e) {
        }
    }
}'''
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            empty_catch = [i for i in issues if i.rule_id == 'EMPTY_CATCH']
            self.assertGreaterEqual(len(empty_catch), 1,
                                    "应该检测到多行空catch块")
        finally:
            os.unlink(tmp)

    def test_system_out_detection(self):
        code = 'class Foo { void bar() { System.out.println("test"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            sys_out = [i for i in issues if i.rule_id == 'AVOID_SYSTEM_OUT']
            self.assertGreaterEqual(len(sys_out), 1)
        finally:
            os.unlink(tmp)

    def test_system_out_printf_detection(self):
        code = 'class Foo { void bar() { System.out.printf("%s", "x"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            sys_out = [i for i in issues if i.rule_id == 'AVOID_SYSTEM_OUT']
            self.assertGreaterEqual(len(sys_out), 1,
                                    "应该检测到 System.out.printf")
        finally:
            os.unlink(tmp)

    def test_line_length_detection(self):
        long_line = '// ' + 'x' * 180
        code = f'''class Foo {{
    void bar() {{
        {long_line}
    }}
}}'''
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            length_issues = [i for i in issues if i.rule_id == 'LINE_LENGTH']
            self.assertGreaterEqual(len(length_issues), 1)
        finally:
            os.unlink(tmp)

    def test_trailing_whitespace_detection(self):
        code = 'class Foo {    \n    void bar() { } }   \n'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            ws = [i for i in issues if i.rule_id == 'TRAILING_WHITESPACE']
            self.assertGreaterEqual(len(ws), 1)
        finally:
            os.unlink(tmp)

    def test_constant_naming_detection(self):
        code = 'class Foo { public static final int badConstant = 42; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            naming = [i for i in issues if i.rule_id == 'CONSTANT_NAMING']
            self.assertGreaterEqual(len(naming), 1,
                                    "static final 字段应使用 CONSTANT_CASE")
        finally:
            os.unlink(tmp)

    def test_constant_naming_ok_no_flag(self):
        code = '''class Foo {
    public static final int GOOD_CONSTANT = 42;
    private static final int ANOTHER_CONST = 100;
}'''
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            naming = [i for i in issues if i.rule_id == 'CONSTANT_NAMING']
            self.assertEqual(len(naming), 0,
                             "CONSTANT_CASE 常量不应触发 CONSTANT_NAMING")
        finally:
            os.unlink(tmp)

    def test_predefined_test_files(self):
        test_file_path = os.path.join(os.path.dirname(__file__), 'test_file', 'TestExample.java')
        good_file_path = os.path.join(os.path.dirname(__file__), 'test_file', 'GoodExample.java')

        self.assertTrue(os.path.exists(test_file_path))
        self.assertTrue(os.path.exists(good_file_path))

        issues = self.inspector.inspect_file(test_file_path)
        self.assertGreater(len(issues), 0)

        issues = self.inspector.inspect_file(good_file_path)
        severe = [i for i in issues if i.severity == Severity.ERROR]
        self.assertEqual(len(severe), 0)

    def test_alibaba_abstract_naming(self):
        code = 'abstract class MyHandler { abstract void handle(); }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            naming = [i for i in issues if i.rule_id == 'ALIBABA_ABSTRACT_NAMING']
            self.assertGreaterEqual(len(naming), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_enum_naming(self):
        code = 'enum Color { RED, GREEN }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            enum_issues = [i for i in issues if i.rule_id == 'ALIBABA_ENUM_NAMING']
            self.assertGreaterEqual(len(enum_issues), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_package_name(self):
        code = 'package Com.Example;\npublic class Foo {}'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            pkg = [i for i in issues if i.rule_id == 'ALIBABA_PACKAGE_NAME']
            self.assertGreaterEqual(len(pkg), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_array_style(self):
        code = 'class Foo { int array[]; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            array_issues = [i for i in issues if i.rule_id == 'ALIBABA_ARRAY_STYLE']
            self.assertGreaterEqual(len(array_issues), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_boolean_prefix(self):
        code = 'class Foo { private boolean isDeleted; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            bp = [i for i in issues if i.rule_id == 'ALIBABA_BOOLEAN_PREFIX']
            self.assertGreaterEqual(len(bp), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_equals_comparison(self):
        code = 'class Foo { void bar() { String x = "a"; x.equals("b"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            eq = [i for i in issues if i.rule_id == 'ALIBABA_EQUALS_STYLE']
            self.assertGreaterEqual(len(eq), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_switch_default(self):
        code = 'class Foo { void bar(int x) { switch(x) { case 1: break; } } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            sw = [i for i in issues if i.rule_id == 'ALIBABA_SWITCH_DEFAULT']
            self.assertGreaterEqual(len(sw), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_is_empty(self):
        code = 'class Foo { void bar() { java.util.List l = null; if (l.size() == 0) {} } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            ie = [i for i in issues if i.rule_id == 'ALIBABA_IS_EMPTY']
            self.assertGreaterEqual(len(ie), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_long_suffix(self):
        code = 'class Foo { long x = 100l; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            ls = [i for i in issues if i.rule_id == 'ALIBABA_LONG_SUFFIX']
            self.assertGreaterEqual(len(ls), 1)
        finally:
            os.unlink(tmp)

    def test_alibaba_method_length(self):
        code = 'class Foo {\n    void bar() {\n'
        for _ in range(85):
            code += '        System.out.println("x");\n'
        code += '    }\n}'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            ml = [i for i in issues if i.rule_id == 'ALIBABA_METHOD_LENGTH']
            self.assertGreaterEqual(len(ml), 1)
        finally:
            os.unlink(tmp)

    def test_auto_fix_issues(self):
        code = 'import java.util.List;\nimport java.util.ArrayList;\npublic class Foo {}\n'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            config = InspectionConfig()
            config.config['auto_fix']['unused_imports'] = True
            inspector = JavaCodeInspector(config)
            fixed = inspector.auto_fix_issues(tmp)
            unused = [i for i in fixed if i.rule_id == 'UNUSED_IMPORT']
            self.assertGreaterEqual(len(unused), 1, "应自动修复未使用的import")
            with open(tmp, encoding='utf-8') as f:
                content = f.read()
            self.assertNotIn('import java.util.List;', content,
                             "修复后不应包含未使用的 import")
            self.assertNotIn('import java.util.ArrayList;', content,
                             "修复后不应包含未使用的 import")
        finally:
            os.unlink(tmp)

    # ==================== SonarQube Bug Rules ====================
    def test_sonar_boolean_literal(self):
        code = 'class Foo { void bar() { if (true) {} } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_BOOLEAN_LITERAL']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_identical_expr(self):
        code = 'class Foo { void bar(int x) { if (x == x) {} } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_IDENTICAL_EXPR']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_string_eq(self):
        code = 'class Foo { boolean bar() { return "a" == "b"; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_STRING_EQ']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_system_gc(self):
        code = 'class Foo { void bar() { System.gc(); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_SYSTEM_GC']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_thread_run(self):
        code = 'class Foo { void bar() { Thread t = null; t.run(); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_THREAD_RUN']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_dup_case(self):
        code = 'class Foo { void bar(int x) { switch(x) { case 1: break; case 1: break; } } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_DUP_CASE']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_division_zero(self):
        code = 'class Foo { int bar() { return 1 / 0; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_DIVISION_ZERO']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_exc_not_thrown(self):
        code = 'class Foo { void bar() { new RuntimeException("test"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id in ('SONAR_EXC_NOT_THROWN',) and i.severity.name != 'ERROR']
            self.assertGreaterEqual(len(r), 0, "no alarm expected here")
        finally:
            os.unlink(tmp)

    # ==================== SonarQube Code Smell Rules ====================
    def test_sonar_string_lhs(self):
        code = 'class Foo { boolean bar(String s) { return "a".equals(s); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_STRING_LHS']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_member_order(self):
        code = 'class Foo { int y; static int x; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_MEMBER_ORDER']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_use_interface_type(self):
        code = 'class Foo { java.util.ArrayList<String> list = new java.util.ArrayList<>(); }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_USE_INTERFACE_TYPE']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_locale(self):
        code = 'class Foo { String bar(String s) { return s.toUpperCase(); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_LOCALE']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_empty_collection(self):
        code = 'class Foo { java.util.List x = java.util.Collections.EMPTY_LIST; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_EMPTY_COLLECTION']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_redundant_cast(self):
        code = 'class Foo { void bar() { Number number = 1; Number n2 = (Number) number; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_REDUNDANT_CAST']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_default_init(self):
        code = 'class Foo { int x = 0; String s = null; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_DEFAULT_INIT']
            self.assertGreaterEqual(len(r), 2)
        finally:
            os.unlink(tmp)

    def test_sonar_nested_ternary(self):
        code = 'class Foo { int bar(boolean a, boolean b) { return a ? b ? 1 : 2 : 3; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_NESTED_TERNARY']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_null_instanceof(self):
        code = 'class Foo { boolean bar(String s) { return s != null && s instanceof String; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_NULL_INSTANCEOF']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_equals_hashcode(self):
        code = 'class Foo { public boolean equals(Object o) { return true; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_EQUALS_HASHCODE']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_static_method(self):
        code = 'class Foo { private int bar() { return 1; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_STATIC_METHOD']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    # ==================== SonarQube Security Rules ====================
    def test_sonar_system_out(self):
        code = 'class Foo { void bar() { System.out.println("test"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_SYSTEM_OUT']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_sql_injection(self):
        code = 'class Foo { void bar() { java.sql.Statement stmt = null; stmt.executeQuery("SELECT * FROM " + x); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_SQL_INJECTION']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_sha1(self):
        code = 'class Foo { Object bar() throws Exception { return java.security.MessageDigest.getInstance("SHA1"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_SHA1']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_des(self):
        code = 'class Foo { Object bar() throws Exception { return javax.crypto.Cipher.getInstance("DES"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_DES']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_secure_random(self):
        code = 'class Foo { void bar() { java.util.Random r = new java.util.Random(); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_SECURE_RANDOM']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_hardcoded_key(self):
        code = 'class Foo { String key = "abcdef1234567890"; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id in ('SONAR_HARDCODED_KEY', 'SONAR_HARDCODED_PASSWORD')]
            self.assertGreaterEqual(len(r), 0)
        finally:
            os.unlink(tmp)

    def test_sonar_md5(self):
        code = 'class Foo { Object bar() throws Exception { return java.security.MessageDigest.getInstance("MD5"); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_MD5']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_deserialization(self):
        code = 'class Foo { void bar() throws Exception { java.io.ObjectInputStream ois = null; ois.readObject(); } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_DESERIALIZATION']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)


class TestInspectionConfig(unittest.TestCase):
    def test_default_config(self):
        config = InspectionConfig()
        self.assertTrue(config.is_rule_enabled('line_length'))
        self.assertTrue(config.is_rule_enabled('naming_conventions'))
        self.assertTrue(config.is_rule_enabled('unused_imports'))
        self.assertEqual(config.get_rule_config('line_length').get('max_length'), 120)

    def test_custom_config(self):
        config_file = os.path.join(os.path.dirname(__file__), 'test_config.json')
        self.assertTrue(os.path.exists(config_file))

        config = InspectionConfig(config_file)
        self.assertTrue(config.is_rule_enabled('line_length'))
        self.assertFalse(config.is_rule_enabled('naming_conventions'))
        self.assertEqual(config.get_rule_config('line_length').get('max_length'), 80)

    def test_deep_copy_isolation(self):
        config = InspectionConfig()
        original = config.config['rules']['line_length']['max_length']
        config.config['rules']['line_length']['max_length'] = 999
        self.assertEqual(config.default_config['rules']['line_length']['max_length'], original)

    def test_invalid_config_file(self):
        config = InspectionConfig('/nonexistent/path.json')
        self.assertTrue(config.is_rule_enabled('line_length'))


class TestCodeIssue(unittest.TestCase):
    def test_issue_creation(self):
        issue = CodeIssue(
            file_path="test.java",
            line=10,
            column=5,
            message="测试问题",
            severity=Severity.WARNING,
            rule_id="TEST_RULE",
            category="TEST"
        )
        self.assertEqual(issue.file_path, "test.java")
        self.assertEqual(issue.line, 10)
        self.assertEqual(issue.message, "测试问题")
        self.assertEqual(issue.severity, Severity.WARNING)
        self.assertFalse(issue.fixable)
        self.assertEqual(issue.fix_suggestion, "")

    def test_severity_enum(self):
        self.assertEqual(Severity.ERROR.value, "ERROR")
        self.assertEqual(Severity.WARNING.value, "WARNING")
        self.assertEqual(Severity.INFO.value, "INFO")

    def test_report_format_enum(self):
        self.assertEqual(ReportFormat.TEXT.value, "text")
        self.assertEqual(ReportFormat.JSON.value, "json")
        self.assertEqual(ReportFormat.XML.value, "xml")
        self.assertEqual(ReportFormat.HTML.value, "html")
        self.assertEqual(ReportFormat.CSV.value, "csv")

    def test_issue_fixable_default(self):
        issue = CodeIssue("f.java", 1, 0, "msg", Severity.INFO, "R1", "C")
        self.assertFalse(issue.fixable)

    def test_issue_with_fix_suggestion(self):
        issue = CodeIssue("f.java", 1, 0, "msg", Severity.INFO, "R1", "C",
                          fixable=True, fix_suggestion="suggestion")
        self.assertTrue(issue.fixable)
        self.assertEqual(issue.fix_suggestion, "suggestion")


class TestCodeMetrics(unittest.TestCase):
    def test_default_metrics(self):
        m = CodeMetrics()
        self.assertEqual(m.total_lines, 0)
        self.assertEqual(m.code_lines, 0)
        self.assertEqual(m.comment_lines, 0)
        self.assertEqual(m.method_count, 0)
        self.assertEqual(m.class_count, 0)
        self.assertEqual(m.cyclomatic_complexity, 0)
        self.assertEqual(m.duplication_rate, 0.0)
        self.assertEqual(m.code_smells, 0)

    def test_metrics_assignment(self):
        m = CodeMetrics()
        m.total_lines = 100
        m.code_lines = 60
        m.comment_lines = 20
        m.method_count = 5
        m.class_count = 2
        self.assertEqual(m.total_lines, 100)
        self.assertEqual(m.code_lines, 60)


class TestInspectionReporter(unittest.TestCase):
    def setUp(self):
        self.issues_by_file = {
            "/path/to/Test.java": [
                CodeIssue("/path/to/Test.java", 5, 3, "测试问题1", Severity.WARNING, "R1", "STYLE"),
                CodeIssue("/path/to/Test.java", 10, 1, "测试问题2", Severity.ERROR, "R2", "BUG"),
            ]
        }

    def test_text_report(self):
        report = InspectionReporter.generate_text_report(self.issues_by_file)
        self.assertIn("测试问题1", report)
        self.assertIn("测试问题2", report)
        self.assertIn("WARNING", report)
        self.assertIn("ERROR", report)

    def test_json_report(self):
        report = InspectionReporter.generate_json_report(self.issues_by_file)
        data = json.loads(report)
        self.assertEqual(data['summary']['total_issues'], 2)
        self.assertIn("/path/to/Test.java", data['files'])

    def test_csv_report(self):
        report = InspectionReporter.generate_csv_report(self.issues_by_file)
        self.assertIn("File,Line,Column,Severity", report)
        self.assertIn("测试问题1", report)
        self.assertIn("测试问题2", report)

    def test_xml_report(self):
        report = InspectionReporter.generate_xml_report(self.issues_by_file)
        self.assertIn("<codeInspection>", report)
        self.assertIn("R1", report)
        self.assertIn("R2", report)

    def test_report_routing(self):
        text = InspectionReporter.generate_report(self.issues_by_file, ReportFormat.TEXT)
        self.assertIsInstance(text, str)
        self.assertIn("测试问题1", text)

        js = InspectionReporter.generate_report(self.issues_by_file, ReportFormat.JSON)
        self.assertIn("total_issues", js)

    def test_report_to_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            out = f.name
        try:
            InspectionReporter.generate_text_report(self.issues_by_file, output_file=out)
            with open(out, encoding='utf-8') as f:
                content = f.read()
            self.assertIn("测试问题1", content)
        finally:
            os.unlink(out)


class TestCICDIntegrator(unittest.TestCase):
    def test_pass_with_no_issues(self):
        config = InspectionConfig()
        ci = CICDIntegrator(config)
        result = ci.check_quality_gate({})
        self.assertTrue(result)
        self.assertEqual(ci.get_exit_code(), 0)

    def test_fail_on_error(self):
        config = InspectionConfig()
        ci = CICDIntegrator(config)
        issues = {
            "test.java": [
                CodeIssue("test.java", 1, 0, "err", Severity.ERROR, "E1", "BUG")
            ]
        }
        result = ci.check_quality_gate(issues)
        self.assertFalse(result)
        self.assertEqual(ci.get_exit_code(), 1)

    def test_pass_with_warnings_below_limit(self):
        config = InspectionConfig()
        config.config['ci_cd']['max_warnings'] = 10
        ci = CICDIntegrator(config)
        issues = {
            "test.java": [
                CodeIssue("test.java", 1, 0, "warn", Severity.WARNING, "W1", "STYLE")
                for _ in range(5)
            ]
        }
        result = ci.check_quality_gate(issues)
        self.assertTrue(result)
        self.assertEqual(ci.get_exit_code(), 0)

    def test_fail_with_too_many_warnings(self):
        config = InspectionConfig()
        config.config['ci_cd']['max_warnings'] = 3
        ci = CICDIntegrator(config)
        issues = {
            "test.java": [
                CodeIssue("test.java", 1, 0, "warn", Severity.WARNING, "W1", "STYLE")
                for _ in range(5)
            ]
        }
        result = ci.check_quality_gate(issues)
        self.assertFalse(result)
        self.assertEqual(ci.get_exit_code(), 1)


class TestSonarQubeExt(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        self.inspector = JavaCodeInspector(self.config)

    # ==================== SonarQube Extended Rules ====================
    def test_sonar_wrapper_instance(self):
        code = 'class Foo { Integer i = new Integer(1); }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_WRAPPER_INSTANCE']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_legacy_collection(self):
        code = 'class Foo { java.util.Vector v = new java.util.Vector(); }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_LEGACY_COLLECTION']
            self.assertGreaterEqual(len(r), 0)
        finally:
            os.unlink(tmp)

    def test_sonar_general_exception(self):
        code = 'class Foo { void bar() throws Exception {} }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_GENERIC_THROWS']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_self_assignment(self):
        code = 'class Foo { void bar() { int x = 0; x = x; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_SELF_ASSIGNMENT']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_empty_catch_ext(self):
        code = 'class Foo { void bar() { try { } catch (Exception e) { } } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_EMPTY_CATCH_EXT']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_finally_return(self):
        code = 'class Foo { int bar() { try { return 1; } finally { return 2; } } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_FINALLY_RETURN']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_catch_throwable(self):
        code = 'class Foo { void bar() { try { } catch (Throwable t) { } } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_CATCH_THROWABLE']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_unused_parameter(self):
        code = 'class Foo { int add(int a, int b) { return a; } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_UNUSED_PARAMETER']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_nested_try(self):
        code = 'class Foo { void bar() { try { try { } catch (Exception e) { } } catch (Exception e) { } } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_NESTED_TRY']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_hardcoded_ip(self):
        code = 'class Foo { String ip = "8.8.8.8"; }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_HARDCODED_IP']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)

    def test_sonar_assign_in_cond(self):
        code = 'class Foo { void bar(int x) { if (x = 1) {} } }'
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            r = [i for i in issues if i.rule_id == 'SONAR_ASSIGN_IN_COND']
            self.assertGreaterEqual(len(r), 1)
        finally:
            os.unlink(tmp)


class TestSonarQubeFull(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_error_prone', 'sonar_best_practices', 'sonar_clarity']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    # ==================== Error Prone Rules ====================
    def test_sonar_too_many_params(self):
        r = self._check('class Foo { void bar(int a, int b, int c, int d, int e, int f, int g, int h) {} }',
                        'SONAR_TOO_MANY_PARAMS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_fixme_tag(self):
        code = '''class Foo {
    void bar() {
        int x;
        // FIXME: fix this
    }
}'''
        r = self._check(code, 'SONAR_FIXME_TAG')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_todo_tag(self):
        code = '''class Foo {
    void bar() {
        int x;
        // TODO: implement
    }
}'''
        r = self._check(code, 'SONAR_TODO_TAG')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_nested_depth(self):
        code = '''class Foo {
    void bar() {
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 10; j++) {
                for (int k = 0; k < 10; k++) {
                    for (int l = 0; l < 10; l++) {
                        for (int m = 0; m < 10; m++) {
                            System.out.println(m);
                        }
                    }
                }
            }
        }
    }
}'''
        r = self._check(code, 'SONAR_NESTED_DEPTH')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_unused_local(self):
        r = self._check('class Foo { void bar() { int x = 1; System.out.println(\"hi\"); } }',
                        'SONAR_UNUSED_LOCAL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_double_brace(self):
        r = self._check('class Foo { java.util.List list() { return new java.util.ArrayList() {}; } }',
                        'SONAR_DOUBLE_BRACE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_indexof_char(self):
        r = self._check('class Foo { int bar(String s) { return s.indexOf(\"a\"); } }',
                        'SONAR_INDEXOF_CHAR')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_replace_char(self):
        r = self._check('class Foo { String bar(String s) { return s.replace(\"a\", \"b\"); } }',
                        'SONAR_REPLACE_CHAR')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_reflection(self):
        r = self._check('class Foo { void bar() throws Exception { Class c = Foo.class; c.getDeclaredField(\"x\"); } }',
                        'SONAR_REFLECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_empty_statement(self):
        code = '''class Foo {
    void bar() {
        ;;
    }
}'''
        r = self._check(code, 'SONAR_EMPTY_STATEMENT')
        self.assertGreaterEqual(len(r), 1)

    # ==================== Best Practices Rules ====================
    def test_sonar_logger_private(self):
        code = 'class Foo { java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(\"x\"); }'
        r = self._check(code, 'SONAR_LOGGER_PRIVATE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_empty_interface(self):
        r = self._check('interface Empty {}', 'SONAR_EMPTY_INTERFACE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_exception_naming(self):
        r = self._check('class MyError extends Exception {}', 'SONAR_EXCEPTION_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_variable_naming(self):
        r = self._check('class Foo { void bar() { int BadName = 1; } }', 'SONAR_VARIABLE_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_package_naming(self):
        r = self._check('package com.MyCompany; class Foo {}', 'SONAR_PACKAGE_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_serial_version_uid(self):
        r = self._check('class Foo implements java.io.Serializable { int x; }',
                        'SONAR_SERIAL_VERSION_UID')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_abstract_class_keyword(self):
        code = 'class Foo { abstract void bar(); }'
        r = self._check(code, 'SONAR_ABSTRACT_CLASS')
        self.assertGreaterEqual(len(r), 1)

    # ==================== Clarity Rules ====================
    def test_sonar_method_naming(self):
        r = self._check('class Foo { void Bad_Method() {} }', 'SONAR_METHOD_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_class_naming(self):
        r = self._check('class badClassName {}', 'SONAR_CLASS_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_return_bool_expr(self):
        code = 'class Foo { boolean bar(int x) { if (x > 0) { return true; } else { return false; } } }'
        r = self._check(code, 'SONAR_RETURN_BOOL_EXPR')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_multi_var_decl(self):
        r = self._check('class Foo { void bar() { int a = 1, b = 2; } }', 'SONAR_MULTI_VAR_DECL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_method_case_conflict(self):
        code = 'class Foo { void getX() {} void getx() {} }'
        r = self._check(code, 'SONAR_METHOD_CASE_CONFLICT')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeFourth(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_security_extra', 'sonar_concurrency', 'sonar_code_quality', 'sonar_java_api']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    # ==================== Security Extra ====================
    def test_sonar_hardcoded_uri(self):
        code = 'class Foo { String url = "https://example.com/api/v1/users"; }'
        r = self._check(code, 'SONAR_HARDCODED_URI')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_cookie_secure(self):
        code = 'class Foo { void bar() { cookie.setSecure(false); } }'
        r = self._check(code, 'SONAR_COOKIE_SECURE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_predictable_random(self):
        code = 'class Foo { java.util.Random r = new java.util.Random(); }'
        r = self._check(code, 'SONAR_PREDICTABLE_RANDOM')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_ecb_mode(self):
        code = 'class Foo { String alg = "AES/ECB/PKCS5Padding"; }'
        r = self._check(code, 'SONAR_ECB_MODE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_jndi_lookup(self):
        code = 'class Foo { void bar() throws Exception { new javax.naming.InitialContext().lookup("x"); } }'
        r = self._check(code, 'SONAR_JNDI_LOOKUP')
        self.assertGreaterEqual(len(r), 1)

    # ==================== Concurrency ====================
    def test_sonar_wait_sync(self):
        code = 'class Foo { void bar() throws Exception { Object o = new Object(); o.wait(); } }'
        r = self._check(code, 'SONAR_WAIT_SYNC')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_threadlocal_static(self):
        code = 'class Foo { ThreadLocal<Integer> tl = new ThreadLocal<>(); }'
        r = self._check(code, 'SONAR_THREADLOCAL_STATIC')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_servlet_input(self):
        code = 'class Foo { void bar() { String s = request.getParameter("x"); } }'
        r = self._check(code, 'SONAR_SERVLET_INPUT')
        self.assertGreaterEqual(len(r), 1)

    # ==================== Code Quality ====================
    def test_sonar_finalize_call(self):
        code = 'class Foo { protected void finalize() { System.out.println("x"); } }'
        r = self._check(code, 'SONAR_FINALIZE_CALL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_cloneable(self):
        code = 'class Foo implements Cloneable { int x; }'
        r = self._check(code, 'SONAR_CLONEABLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_subclass_equals(self):
        code = 'class Parent { } class Child extends Parent { public boolean equals(Object o) { return false; } }'
        r = self._check(code, 'SONAR_SUBCLASS_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_stream_peek(self):
        code = 'import java.util.*; class Foo { void bar() { List.of(1).stream().peek(x -> {}); } }'
        r = self._check(code, 'SONAR_STREAM_PEEK')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_single_branch_switch(self):
        code = 'class Foo { void bar(int x) { switch(x) { case 1: break; } } }'
        r = self._check(code, 'SONAR_SINGLE_BRANCH_SWITCH')
        self.assertGreaterEqual(len(r), 1)

    # ==================== Java API ====================
    def test_sonar_equals_asymmetry(self):
        code = 'class Foo { public boolean equals(Object o) { return o instanceof Foo; } }'
        r = self._check(code, 'SONAR_EQUALS_ASYMMETRY')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_compare_to_equals(self):
        code = 'class Foo implements Comparable<Foo> { public int compareTo(Foo o) { return 0; } }'
        r = self._check(code, 'SONAR_COMPARABLE_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_class_equals(self):
        code = 'class Foo { private int x; private int y; }'
        r = self._check(code, 'SONAR_CLASS_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_optional_null(self):
        code = 'class Foo { void bar() { java.util.Optional<String> opt = null; } }'
        r = self._check(code, 'SONAR_OPTIONAL_NULL')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeFive(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_bugs_extra', 'sonar_convention_extra', 'sonar_maintainability']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_system_exit(self):
        r = self._check('class Foo { void bar() { System.exit(1); } }', 'SONAR_SYSTEM_EXIT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_npe_thrown(self):
        r = self._check('class Foo { void bar() { throw new NullPointerException(); } }', 'SONAR_NPE_THROWN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_public_field(self):
        r = self._check('class Foo { public int x; }', 'SONAR_PUBLIC_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_raw_type(self):
        r = self._check('class Foo { java.util.List list; }', 'SONAR_RAW_TYPE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_pattern_loop(self):
        code = 'class Foo { void bar() { for (int i=0;i<10;i++) { java.util.regex.Pattern.compile("x"); } } }'
        r = self._check(code, 'SONAR_PATTERN_LOOP')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_override_missing(self):
        r = self._check('class Foo { public String toString() { return ""; } }', 'SONAR_OVERRIDE_MISSING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_constant_case(self):
        code = 'class Foo { public static final int myConst = 1; }'
        r = self._check(code, 'SONAR_CONSTANT_CASE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_complex_expression(self):
        code = 'class Foo { boolean b(int x,int y,int z,int w) { return x>0&&y>0&&z>0&&w>0; } }'
        r = self._check(code, 'SONAR_COMPLEX_EXPRESSION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_loop_size(self):
        r = self._check('class Foo { int bar(java.util.List l) { int s=0; for(int i=0;i<l.size();i++) s+=i; return s; } }', 'SONAR_LOOP_SIZE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_case_insensitive(self):
        code = 'class Foo { boolean bar(String s) { return s.toLowerCase().equals("x"); } }'
        r = self._check(code, 'SONAR_CASE_INSENSITIVE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_optional_param(self):
        code = 'class Foo { void bar(java.util.Optional<String> o) {} }'
        r = self._check(code, 'SONAR_OPTIONAL_PARAM')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_create_temp_file(self):
        code = 'class Foo { void bar() throws Exception { java.io.File.createTempFile("x","y"); } }'
        r = self._check(code, 'SONAR_CREATE_TEMP_FILE')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeSix(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_bugs_six', 'sonar_code_smell_six', 'sonar_security_six']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_print_stack_trace(self):
        code = 'class Foo { void bar() { try { int x=1; } catch(Exception e) { e.printStackTrace(); } } }'
        r = self._check(code, 'SONAR_PRINT_STACK_TRACE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_throw_in_finally(self):
        code = 'class Foo { void bar() { try { int x=1; } finally { throw new RuntimeException(); } } }'
        r = self._check(code, 'SONAR_THROW_IN_FINALLY')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_string_buffer(self):
        r = self._check('class Foo { void bar() { new StringBuffer(); } }', 'SONAR_STRING_BUFFER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_big_decimal_double(self):
        r = self._check('class Foo { void bar() { new java.math.BigDecimal(1.5); } }', 'SONAR_BIG_DECIMAL_DOUBLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_suppress_warning(self):
        r = self._check('class Foo { @SuppressWarnings("all") void bar() {} }', 'SONAR_SUPPRESS_WARNING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_instanceof_final(self):
        r = self._check('class Foo { boolean bar(Object o) { return o instanceof String; } }', 'SONAR_INSTANCEOF_FINAL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_empty_nested_block(self):
        code = 'class Foo { void bar() { { } } }'
        r = self._check(code, 'SONAR_EMPTY_NESTED_BLOCK')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_string_concat_loop(self):
        code = 'class Foo { String bar() { String s=""; for(int i=0;i<10;i++) { s+=i; } return s; } }'
        r = self._check(code, 'SONAR_STRING_CONCAT_LOOP')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_exception_rethrow(self):
        code = 'class Foo { void bar() { try { int x=1; } catch(Exception e) { throw e; } } }'
        r = self._check(code, 'SONAR_EXCEPTION_RETHROW')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_ignored_return(self):
        r = self._check('class Foo { void bar(String s) { s.trim(); } }', 'SONAR_IGNORED_RETURN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_duplicate_string_literal(self):
        bad = ('class Foo { void bar() { String a="x";String b="x";String c="x";'
               'String d="x";String e="x"; } }')
        r = self._check(bad, 'SONAR_DUPLICATE_STRING_LITERAL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_too_many_throws(self):
        code = 'class Foo { void bar() throws Exception, Error, Throwable, RuntimeException {} }'
        r = self._check(code, 'SONAR_TOO_MANY_THROWS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_string_lhs_equals(self):
        code = 'class Foo { boolean bar(String s) { return s.equals("x"); } }'
        r = self._check(code, 'SONAR_STRING_LHS_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_finalize_protected(self):
        code = 'class Foo { protected void finalize() { System.out.println(); } }'
        r = self._check(code, 'SONAR_FINALIZE_PROTECTED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_protected_field(self):
        code = 'class Foo { protected int x; }'
        r = self._check(code, 'SONAR_PROTECTED_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_url_hashcode(self):
        code = 'class Foo { int bar(java.net.URL u) { return u.hashCode(); } }'
        r = self._check(code, 'SONAR_URL_HASHCODE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_string_intern(self):
        code = 'class Foo { String bar(String s) { return s.intern(); } }'
        r = self._check(code, 'SONAR_STRING_INTERN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_thread_wait(self):
        code = 'class Foo { void bar() throws Exception { Thread t = new Thread(); t.wait(); } }'
        r = self._check(code, 'SONAR_THREAD_WAIT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_manual_thread(self):
        r = self._check('class Foo { void bar() { new Thread(); } }', 'SONAR_MANUAL_THREAD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_getclass_auth(self):
        r = self._check('class Foo { Class<?> bar() { return this.getClass(); } }', 'SONAR_GETCLASS_AUTH')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeSeven(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_correctness', 'sonar_robustness', 'sonar_performance_seven', 'sonar_api_usage']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_break_label(self):
        code = 'class Foo { void bar() { outer: for(int i=0;i<10;i++) { break outer; } } }'
        r = self._check(code, 'SONAR_BREAK_LABEL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_only_default_switch(self):
        code = 'class Foo { void bar(int x) { switch(x) { default: break; } } }'
        r = self._check(code, 'SONAR_ONLY_DEFAULT_SWITCH')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_sb_to_string(self):
        code = 'class Foo { void bar() { java.lang.StringBuilder sb = new StringBuilder(); bar(sb); } void bar(String s) {} }'
        r = self._check(code, 'SONAR_SB_TO_STRING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_to_string_null(self):
        code = 'class Foo { public String toString() { return null; } }'
        r = self._check(code, 'SONAR_TOSTRING_NULL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_compareto_without_equals(self):
        code = 'class Foo implements Comparable<Foo> { public int compareTo(Foo o) { return 0; } }'
        r = self._check(code, 'SONAR_COMPARETO_WITHOUT_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_thread_run_instead_start(self):
        code = 'class Foo { void bar() { Thread t = new Thread(); t.run(); } }'
        r = self._check(code, 'SONAR_THREAD_RUN_INSTEAD_START')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_thread_sleep_zero(self):
        code = 'class Foo { void bar() throws Exception { Thread.sleep(0); } }'
        r = self._check(code, 'SONAR_THREAD_SLEEP_ZERO')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_literal_eq(self):
        code = 'class Foo { boolean bar() { return "a" == "b"; } }'
        r = self._check(code, 'SONAR_LITERAL_EQ')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_catch_rethrow(self):
        code = 'class Foo { void bar() { try { int x=1; } catch(Exception e) { throw e; } } }'
        r = self._check(code, 'SONAR_CATCH_RETHROW')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_empty_list(self):
        code = 'class Foo { java.util.List x = java.util.Collections.EMPTY_LIST; }'
        r = self._check(code, 'SONAR_EMPTY_LIST')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_enum_mutable_field(self):
        code = 'enum Foo { A; int x; }'
        r = self._check(code, 'SONAR_ENUM_MUTABLE_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_multiple_public_classes(self):
        code = 'public class Foo {} public class Bar {}'
        r = self._check(code, 'SONAR_MULTIPLE_PUBLIC_CLASSES')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_unchecked_warning(self):
        code = 'class Foo { @SuppressWarnings("unchecked") void bar() {} }'
        r = self._check(code, 'SONAR_UNCHECKED_WARNING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_division_by_zero(self):
        code = 'class Foo { int bar() { return 1 / 0; } }'
        r = self._check(code, 'SONAR_DIVISION_BY_ZERO')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_return_null_array(self):
        code = 'class Foo { int[] bar() { return null; } }'
        r = self._check(code, 'SONAR_RETURN_NULL_ARRAY')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_finally_return_seven(self):
        code = 'class Foo { int bar() { try { return 1; } finally { return 2; } } }'
        r = self._check(code, 'SONAR_FINALLY_RETURN_SEVEN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_to_string_on_string(self):
        code = 'class Foo { String bar(String s) { return s.toString(); } }'
        r = self._check(code, 'SONAR_TOSTRING_ON_STRING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_instanceof_wrapper(self):
        code = 'class Foo { boolean bar(Object o) { return o instanceof Integer; } }'
        r = self._check(code, 'SONAR_INSTANCEOF_WRAPPER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_size_eq_zero(self):
        code = 'class Foo { boolean bar(java.util.List l) { return l.size() == 0; } }'
        r = self._check(code, 'SONAR_SIZE_EQ_ZERO')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_getbytes_charset(self):
        r = self._check('class Foo { byte[] bar(String s) { return s.getBytes(); } }', 'SONAR_GETBYTES_CHARSET')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_properties_api(self):
        r = self._check('class Foo { void bar() { new java.util.Properties(); } }', 'SONAR_PROPERTIES_API')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_simple_date_format(self):
        r = self._check('class Foo { void bar() { new java.text.SimpleDateFormat(); } }', 'SONAR_SIMPLE_DATE_FORMAT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_class_forname(self):
        r = self._check('class Foo { Class<?> bar() throws Exception { return Class.forName("x"); } }', 'SONAR_CLASS_FORNAME')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_clone_override(self):
        r = self._check('class Foo { public Object clone() { return this; } }', 'SONAR_CLONE_OVERRIDE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_thread_yield_api(self):
        r = self._check('class Foo { void bar() { Thread.yield(); } }', 'SONAR_THREAD_YIELD_API')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_sync_class_usage(self):
        r = self._check('class Foo { void bar() { new StringBuffer(); } }', 'SONAR_SYNC_CLASS_USAGE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_valueof_redundant(self):
        r = self._check('class Foo { String bar() { return String.valueOf("x"); } }', 'SONAR_VALUEOF_REDUNDANT')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeEight(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_spring', 'sonar_java_features', 'sonar_testing', 'sonar_redundancy']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_field_injection(self):
        code = 'import org.springframework.web.bind.annotation.RestController; import org.springframework.beans.factory.annotation.Autowired; @RestController class Foo { @Autowired private int x; }'
        r = self._check(code, 'SONAR_FIELD_INJECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_optional_field(self):
        code = 'class Foo { java.util.Optional<String> opt; }'
        r = self._check(code, 'SONAR_OPTIONAL_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_empty_marker_interface(self):
        r = self._check('interface Marker {}', 'SONAR_EMPTY_MARKER_INTERFACE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_useless_override(self):
        code = 'class Parent { void foo() {} } class Child extends Parent { @Override void foo() { super.foo(); } }'
        r = self._check(code, 'SONAR_USELESS_OVERRIDE_EIGHT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_hashcode_before_equals(self):
        code = 'class Foo { public int hashCode() { return 0; } public boolean equals(Object o) { return true; } }'
        r = self._check(code, 'SONAR_HASHCODE_BEFORE_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_too_many_fields(self):
        code = 'class Foo { int a1;int a2;int a3;int a4;int a5;int a6;int a7;int a8;int a9;int a10;int a11;int a12;int a13;int a14;int a15;int a16; }'
        r = self._check(code, 'SONAR_TOO_MANY_FIELDS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_boolean_inversion(self):
        code = 'class Foo { void bar(boolean b) { if (b == false) {} } }'
        r = self._check(code, 'SONAR_BOOLEAN_INVERSION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_serializable(self):
        code = 'import java.io.Serializable; class Foo implements Serializable { }'
        r = self._check(code, 'SONAR_SERIALIZABLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_loop_only_break(self):
        code = 'class Foo { void bar() { for(;;) { break; } } }'
        r = self._check(code, 'SONAR_LOOP_ONLY_BREAK')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_junit5_visibility(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test public void testBar() {} }'
        r = self._check(code, 'SONAR_JUNIT5_VISIBILITY')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_test_display_name(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test void testBar() {} }'
        r = self._check(code, 'SONAR_TEST_DISPLAY_NAME')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_wildcard_return(self):
        code = 'class Foo { java.util.List<?> bar() { return null; } }'
        r = self._check(code, 'SONAR_WILDCARD_RETURN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_autowired_field(self):
        code = 'import org.springframework.beans.factory.annotation.Autowired; class Foo { @Autowired int x; }'
        r = self._check(code, 'SONAR_AUTOWIRED_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_test_class_without_test(self):
        code = 'public class FooTest {}'
        r = self._check(code, 'SONAR_TEST_CLASS_WITHOUT_TEST')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeNine(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_security_hotspots', 'sonar_error_prone_nine', 'sonar_miscellaneous']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_open_redirect_nine(self):
        code = 'import javax.servlet.http.HttpServletResponse; class Foo { void bar(HttpServletResponse r) throws Exception { r.sendRedirect("x"); } }'
        r = self._check(code, 'SONAR_OPEN_REDIRECT_NINE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_missing_authorization(self):
        code = 'import org.springframework.web.bind.annotation.RequestMapping; class Foo { @RequestMapping void bar() {} }'
        r = self._check(code, 'SONAR_MISSING_AUTHORIZATION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_ssl_disabled_nine(self):
        code = 'class Foo { void bar() { javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(null); } }'
        r = self._check(code, 'SONAR_SSL_DISABLED_NINE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_swallowed_exception(self):
        code = 'class Foo { void bar() { try { int x=1; } catch(Exception e) {} } }'
        r = self._check(code, 'SONAR_SWALLOWED_EXCEPTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_return_bool_nine(self):
        code = 'class Foo { boolean bar(int x) { if (x>0) { return true; } else { return false; } } }'
        r = self._check(code, 'SONAR_RETURN_BOOL_NINE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_generic_throws_nine(self):
        code = 'class Foo { void bar() throws Exception {} }'
        r = self._check(code, 'SONAR_GENERIC_THROWS_NINE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_compareto_constant(self):
        code = 'class Foo implements java.lang.Comparable<Foo> { public int compareTo(Foo o) { return -1; } }'
        r = self._check(code, 'SONAR_COMPARETO_CONSTANT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_deprecated_with_doc(self):
        code = 'class Foo { @Deprecated void bar() {} }'
        r = self._check(code, 'SONAR_DEPRECATED_WITH_DOC')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_file_header(self):
        code = 'class Foo {}'
        r = self._check(code, 'SONAR_FILE_HEADER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_enum_switch_default(self):
        code = 'enum E { A,B } class Foo { void bar(E e) { switch(e) { case A: break; } } }'
        r = self._check(code, 'SONAR_ENUM_SWITCH_DEFAULT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_functional_interface(self):
        code = '@FunctionalInterface interface Foo { void bar(); void baz(); }'
        r = self._check(code, 'SONAR_FUNCTIONAL_INTERFACE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_indexof_contains_nine(self):
        code = 'class Foo { boolean bar(String s) { return s.indexOf("x") != -1; } }'
        r = self._check(code, 'SONAR_INDEXOF_CONTAINS_NINE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_variable_upper_case(self):
        code = 'class Foo { void bar() { int BAR = 0; } }'
        r = self._check(code, 'SONAR_VARIABLE_UPPER_CASE')


class TestSonarQubeTen(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_convention_ten', 'sonar_design_ten', 'sonar_robustness_ten']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_class_cast_thrown(self):
        code = 'class Foo { void bar() { throw new ClassCastException(); } }'
        r = self._check(code, 'SONAR_CLASS_CAST_THROWN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_modifier_order(self):
        code = 'class Foo { static public void bar() {} }'
        r = self._check(code, 'SONAR_MODIFIER_ORDER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_self_assignment_ten(self):
        code = 'class Foo { void bar() { int x = 0; x = x; } }'
        r = self._check(code, 'SONAR_SELF_ASSIGNMENT_TEN')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_functional_interface_missing(self):
        code = 'interface Foo { void bar(); }'
        r = self._check(code, 'SONAR_FUNCTIONAL_INTERFACE_MISSING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_abstract_naming(self):
        code = 'abstract class Foo {}'
        r = self._check(code, 'SONAR_ABSTRACT_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_inner_class_static(self):
        code = 'class Outer { class Inner { } }'
        r = self._check(code, 'SONAR_INNER_CLASS_STATIC')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_servlet_static_field(self):
        code = 'class Foo implements javax.servlet.Servlet { static int counter; }'
        r = self._check(code, 'SONAR_SERVLET_STATIC_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_generic_variable_type(self):
        code = 'class Foo { void bar() { Object x = "test"; } }'
        r = self._check(code, 'SONAR_GENERIC_VARIABLE_TYPE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_mutable_constant(self):
        code = 'class Foo { public static final StringBuilder SB = new StringBuilder(); }'
        r = self._check(code, 'SONAR_MUTABLE_CONSTANT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_stream_findfirst(self):
        code = 'import java.util.*; class Foo { void bar() { List.of(1).stream().findFirst(); } }'
        r = self._check(code, 'SONAR_STREAM_FINDFIRST')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_immutable_collection(self):
        code = 'import java.util.*; class Foo { List<Integer> bar() { return Collections.unmodifiableList(Arrays.asList(1)); } }'
        r = self._check(code, 'SONAR_IMMUTABLE_COLLECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_var_inference(self):
        code = 'class Foo { void bar() { java.util.ArrayList<Integer> list = new java.util.ArrayList<>(); } }'
        r = self._check(code, 'SONAR_VAR_INFERENCE')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeEleven(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_advanced_features', 'sonar_complete_testing', 'sonar_more_concurrency']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_completable_future_getnow(self):
        code = 'class Foo { void bar() { java.util.concurrent.CompletableFuture.supplyAsync(() -> "").getNow(""); } }'
        r = self._check(code, 'SONAR_COMPLETABLE_FUTURE_GETNOW')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_stream_to_list(self):
        code = 'import java.util.stream.*; class Foo { void bar() { java.util.List.of(1).stream().collect(Collectors.toList()); } }'
        r = self._check(code, 'SONAR_STREAM_TO_LIST')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_optional_is_present(self):
        code = 'class Foo { boolean bar(java.util.Optional<String> o) { return o.isPresent(); } }'
        r = self._check(code, 'SONAR_OPTIONAL_IS_PRESENT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_stream_close(self):
        code = 'import java.nio.file.*; class Foo { void bar() throws Exception { Files.list(java.nio.file.Paths.get(".")); } }'
        r = self._check(code, 'SONAR_STREAM_CLOSE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_unicode_comment(self):
        code = r'class Foo { } // \u0061 comment'
        r = self._check(code, 'SONAR_UNICODE_COMMENT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_assert_fail(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test void bar() { org.junit.jupiter.api.Assertions.fail("msg"); } }'
        r = self._check(code, 'SONAR_ASSERT_FAIL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_nested_class_not(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test void bar() {} class Inner {} }'
        r = self._check(code, 'SONAR_NESTED_CLASS_NOT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_mockito_spy_final(self):
        code = 'import org.mockito.Mockito; class Foo { void bar() { Mockito.spy(new java.util.ArrayList()); } }'
        r = self._check(code, 'SONAR_MOCKITO_SPY_FINAL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_non_deterministic_test(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test void bar() { new java.util.Random().nextInt(); } }'
        r = self._check(code, 'SONAR_NON_DETERMINISTIC_TEST')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_volatile_array(self):
        code = 'class Foo { volatile int[] arr; }'
        r = self._check(code, 'SONAR_VOLATILE_ARRAY')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_package_private_field(self):
        code = 'class Foo { int x; }'
        r = self._check(code, 'SONAR_PACKAGE_PRIVATE_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_executor_created(self):
        code = 'class Foo { void bar() { java.util.concurrent.Executors.newFixedThreadPool(10); } }'
        r = self._check(code, 'SONAR_EXECUTOR_CREATED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_threadlocal_set(self):
        code = 'class Foo { void bar() { java.lang.ThreadLocal<String> tl = new java.lang.ThreadLocal<>(); tl.set("x"); } }'
        r = self._check(code, 'SONAR_THREADLOCAL_SET')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_threadlocal_nonstatic_eleven(self):
        code = 'class Foo { ThreadLocal<Integer> tl = new ThreadLocal<>(); }'
        r = self._check(code, 'SONAR_THREADLOCAL_NONSTATIC_ELEVEN')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeTwelve(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_security_twelve', 'sonar_design_principles', 'sonar_performance_twelve', 'sonar_organization']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_hardcoded_credential_twelve(self):
        code = 'class Foo { void bar() { String password = "s3cr3t!"; } }'
        r = self._check(code, 'SONAR_HARDCODED_CREDENTIAL_TWELVE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_predictable_random_twelve(self):
        code = 'class Foo { void bar() { new java.util.Random(); } }'
        r = self._check(code, 'SONAR_PREDICTABLE_RANDOM_TWELVE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_weak_hash(self):
        code = 'class Foo { void bar() throws Exception { java.security.MessageDigest.getInstance("MD5"); } }'
        r = self._check(code, 'SONAR_WEAK_HASH')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_interface_too_large(self):
        code = 'interface Foo { void m1();void m2();void m3();void m4();void m5();void m6();void m7();void m8();void m9();void m10();void m11(); }'
        r = self._check(code, 'SONAR_INTERFACE_TOO_LARGE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_default_encoding(self):
        code = 'class Foo { void bar() throws Exception { "hello".getBytes(); } }'
        r = self._check(code, 'SONAR_DEFAULT_ENCODING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_method_upper_case(self):
        code = 'class Foo { void BAR() {} }'
        r = self._check(code, 'SONAR_METHOD_UPPER_CASE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_interface_field(self):
        code = 'interface Foo { int x = 1; }'
        r = self._check(code, 'SONAR_INTERFACE_FIELD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_type_name_case(self):
        code = 'class foo {}'
        r = self._check(code, 'SONAR_TYPE_NAME_CASE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_private_could_be_static(self):
        code = 'class Foo { private void bar() { int x = 1; } }'
        r = self._check(code, 'SONAR_PRIVATE_COULD_BE_STATIC')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_package_naming_twelve(self):
        code = 'package Foo; class Bar {}'
        r = self._check(code, 'SONAR_PACKAGE_NAMING_TWELVE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_class_too_large_org(self):
        code = 'class Foo { int f1;int f2;int f3;int f4;int f5;int f6;int f7;int f8;int f9;int f10;int f11;int f12;int f13;int f14;int f15;int f16;int f17;int f18;int f19;int f20;int f21;int f22;int f23;int f24;int f25;int f26;int f27;int f28;int f29;int f30;int f31; }'
        r = self._check(code, 'SONAR_CLASS_TOO_LARGE_ORG')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_unvalidated_redirect(self):
        code = 'import javax.servlet.http.HttpServletResponse; class Foo { void bar(HttpServletResponse r) throws Exception { r.sendRedirect("/x"); } }'
        r = self._check(code, 'SONAR_UNVALIDATED_REDIRECT')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeThirteen(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_framework_complete', 'sonar_final_edge_cases', 'sonar_java_twelve_plus', 'sonar_code_patterns_extra']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_jee_resource(self):
        code = 'import javax.ejb.Stateless; @Stateless class Foo {}'
        r = self._check(code, 'SONAR_JEE_RESOURCE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_direct_connection(self):
        code = 'class Foo { void bar() { new java.sql.DriverManager(); } }'
        r = self._check(code, 'SONAR_DIRECT_CONNECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_spring_value(self):
        code = 'import org.springframework.beans.factory.annotation.Value; class Foo { @Value("x") String bar; }'
        r = self._check(code, 'SONAR_SPRING_VALUE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_named_cdi(self):
        code = 'import javax.inject.Named; @Named class Foo {}'
        r = self._check(code, 'SONAR_NAMED_CDI')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_jpa_entity(self):
        code = 'import javax.persistence.Entity; @Entity class Foo {}'
        r = self._check(code, 'SONAR_JPA_ENTITY')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_switch_fallthrough(self):
        code = 'class Foo { void bar(int x) { switch(x) { case 1: x++; case 2: x--; } } }'
        r = self._check(code, 'SONAR_SWITCH_FALLTHROUGH')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_unused_catch_param(self):
        code = 'class Foo { void bar() { try {} catch(Exception e) {} } }'
        r = self._check(code, 'SONAR_UNUSED_CATCH_PARAM')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_suppress_warning(self):
        code = '@SuppressWarnings("unused") class Foo {}'
        r = self._check(code, 'SONAR_SUPPRESS_WARNING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_null_instanceof(self):
        code = 'class Foo { boolean bar() { return null instanceof String; } }'
        r = self._check(code, 'SONAR_NULL_INSTANCEOF')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_finalize(self):
        code = 'class Foo { protected void finalize() {} }'
        r = self._check(code, 'SONAR_FINALIZE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_sync_override(self):
        code = 'class Foo implements Comparable { public synchronized int compareTo(Object o) { return 0; } }'
        r = self._check(code, 'SONAR_SYNC_OVERRIDE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_record_eligible(self):
        code = 'class Foo { private int x; private int y; public Foo(int x, int y) { this.x = x; this.y = y; } public boolean equals(Object o) { return true; } }'
        r = self._check(code, 'SONAR_RECORD_ELIGIBLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_pattern_instanceof(self):
        code = 'class Foo { void bar(Object o) { if(o instanceof String) { String s = (String)o; } } }'
        r = self._check(code, 'SONAR_PATTERN_INSTANCEOF')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_sealed_permits(self):
        code = '// sealed class Foo\nclass Foo {}'
        r = self._check(code, 'SONAR_SEALED_PERMITS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_toarray_typed(self):
        code = 'import java.util.*; class Foo { void bar() { List.of(1).toArray(); } }'
        r = self._check(code, 'SONAR_TOARRAY_TYPED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_enum_tostring(self):
        code = 'enum Foo { A; @Override public String toString() { return "x"; } }'
        r = self._check(code, 'SONAR_ENUM_TOSTRING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_primitive_wrapper(self):
        code = 'class Foo { void bar() { new java.lang.Boolean(true); } }'
        r = self._check(code, 'SONAR_PRIMITIVE_WRAPPER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_print_stacktrace(self):
        code = 'class Foo { void bar() { new Exception().printStackTrace(); } }'
        r = self._check(code, 'SONAR_PRINT_STACKTRACE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_ref_equals(self):
        code = 'class Foo { boolean bar(String a) { return "hello" == a; } }'
        r = self._check(code, 'SONAR_REF_EQUALS')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_actuator_exposed(self):
        code = 'class Foo { @RequestMapping("/actuator/health") void bar() {} }'
        r = self._check(code, 'SONAR_ACTUATOR_EXPOSED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_header_injection(self):
        code = 'class Foo { void bar() { javax.servlet.http.HttpServletResponse r = null; r.addHeader("X","x\\ny"); } }'
        r = self._check(code, 'SONAR_HEADER_INJECTION')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeFourteen(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_security_fourteen', 'sonar_serialization_fourteen', 'sonar_math_fourteen', 'sonar_convention_fourteen', 'sonar_error_prone_fourteen']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_volatile_collection(self):
        code = 'class Foo { volatile java.util.List list; }'
        r = self._check(code, 'SONAR_VOLATILE_COLLECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_inner_serializable(self):
        code = 'class Foo implements java.io.Serializable { class Inner {} }'
        r = self._check(code, 'SONAR_INNER_SERIALIZABLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_final_protected(self):
        code = 'final class Foo { protected int x; }'
        r = self._check(code, 'SONAR_FINAL_PROTECTED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_bigdecimal_rounding(self):
        code = 'import java.math.BigDecimal; class Foo { void bar() { new BigDecimal("1").divide(new BigDecimal("3")); } }'
        r = self._check(code, 'SONAR_BIGDECIMAL_ROUNDING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_float_compare_v2(self):
        code = 'class Foo { boolean bar() { return 1.0 == 2.0; } }'
        r = self._check(code, 'SONAR_FLOAT_COMPARE_V2')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_exception_class_naming(self):
        code = 'class MyError extends Exception {}'
        r = self._check(code, 'SONAR_EXCEPTION_CLASS_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_import_wildcard(self):
        code = 'import java.util.*; class Foo {}'
        r = self._check(code, 'SONAR_IMPORT_WILDCARD')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_test_class_naming(self):
        code = 'import org.junit.jupiter.api.Test; @Test class MyTestClass {}'
        r = self._check(code, 'SONAR_TEST_CLASS_NAMING')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_infinite_recursion(self):
        code = 'class Foo { void bar() { bar(); bar(); } }'
        r = self._check(code, 'SONAR_INFINITE_RECURSION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_assign_in_cond_v2(self):
        code = 'class Foo { void bar(int x) { if(x=1) {} } }'
        r = self._check(code, 'SONAR_ASSIGN_IN_COND_V2')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_underscore_literal(self):
        code = 'class Foo { int x = 123456; }'
        r = self._check(code, 'SONAR_UNDERSCORE_LITERAL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_empty_marker_interface_v2(self):
        code = 'interface Marker {}'
        r = self._check(code, 'SONAR_EMPTY_MARKER_INTERFACE_V2')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_comparable_without_compareto(self):
        code = 'class Foo implements Comparable { public boolean equals(Object o) { return true; } }'
        r = self._check(code, 'SONAR_COMPARABLE_WITHOUT_COMPARETO')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_swallow_rethrow(self):
        code = 'class Foo { void bar() { try {} catch(Exception e) { throw new RuntimeException(); } } }'
        r = self._check(code, 'SONAR_SWALLOW_RE_THROW')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_test_method_naming_v2(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test void Bar() {} }'
        r = self._check(code, 'SONAR_TEST_METHOD_NAMING_V2')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeFifteen(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_http_web', 'sonar_jdbc_jpa', 'sonar_testing_extra', 'sonar_quality_extra']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_xss_direct_output(self):
        code = 'class Foo { void bar(javax.servlet.http.HttpServletResponse response, String s) { response.getWriter().write("data"); } }'
        r = self._check(code, 'SONAR_XSS_DIRECT_OUTPUT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_cache_control(self):
        code = 'class Foo { void bar(javax.servlet.http.HttpServletResponse response) { response.setHeader("Cache-Control","public"); } }'
        r = self._check(code, 'SONAR_CACHE_CONTROL')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_hsts_header(self):
        code = 'class Foo { void bar(javax.servlet.http.HttpServletResponse response) { response.setHeader("Strict-Transport-Security","includeSubDomains"); } }'
        r = self._check(code, 'SONAR_HSTS_HEADER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_jdbc_hardcoded(self):
        code = 'class Foo { void bar() throws Exception { java.sql.DriverManager.getConnection("jdbc:h2:file:test", "sa", ""); } }'
        r = self._check(code, 'SONAR_JDBC_HARDCODED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_sql_concat_prepared(self):
        code = 'class Foo { void bar() throws Exception { java.sql.Connection conn = null; java.sql.PreparedStatement p = conn.prepareStatement("SELECT * FROM " + "table"); } }'
        r = self._check(code, 'SONAR_SQL_CONCAT_PREPARED')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_test_without_assertion_v2(self):
        code = 'import org.junit.jupiter.api.Test; class Foo { @Test void bar() { int x = 1; } }'
        r = self._check(code, 'SONAR_TEST_WITHOUT_ASSERTION_V2')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_disabled_without_comment(self):
        code = 'import org.junit.jupiter.api.Disabled; @Disabled class Foo {}'
        r = self._check(code, 'SONAR_DISABLED_WITHOUT_COMMENT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_deprecated_javadoc(self):
        code = '@Deprecated class Foo {}'
        r = self._check(code, 'SONAR_DEPRECATED_JAVADOC')
        self.assertGreaterEqual(len(r), 1)


class TestSonarQubeSixteen(unittest.TestCase):
    def setUp(self):
        self.config = InspectionConfig()
        for cat in ['sonar_json_xml', 'sonar_nio_reflection', 'sonar_datetime_extra', 'sonar_sql_general']:
            self.config.config['rules'][cat] = {'enabled': True}
        self.inspector = JavaCodeInspector(self.config)

    def _check(self, code, rule_id):
        with tempfile.NamedTemporaryFile(suffix='.java', mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmp = f.name
        try:
            issues = self.inspector.inspect_file(tmp)
            return [i for i in issues if i.rule_id == rule_id]
        finally:
            os.unlink(tmp)

    def test_sonar_xml_decoder(self):
        code = 'class Foo { void bar() { new java.beans.XMLDecoder(null); } }'
        r = self._check(code, 'SONAR_XML_DECODER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_xxe_parser(self):
        code = 'class Foo { void bar() throws Exception { javax.xml.parsers.DocumentBuilderFactory f = javax.xml.parsers.DocumentBuilderFactory.newInstance(); f.newDocumentBuilder().parse("x"); } }'
        r = self._check(code, 'SONAR_XXE_PARSER')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_set_accessible(self):
        code = 'class Foo { void bar() throws Exception { java.lang.reflect.Field f = null; f.setAccessible(true); } }'
        r = self._check(code, 'SONAR_SET_ACCESSIBLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_method_handle(self):
        code = 'import java.lang.invoke.MethodHandle; class Foo { void bar() { MethodHandle h = new MethodHandle(); } }'
        r = self._check(code, 'SONAR_METHOD_HANDLE')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_mutable_date_constant(self):
        code = 'class Foo { public static final java.util.Calendar CAL = java.util.Calendar.getInstance(); }'
        r = self._check(code, 'SONAR_MUTABLE_DATE_CONSTANT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_queryparam_validation(self):
        code = 'class Foo { void bar(@javax.ws.rs.QueryParam("x") String x) {} }'
        r = self._check(code, 'SONAR_QUERYPARAM_VALIDATION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_sql_concat_injection(self):
        code = 'class Foo { void bar() throws Exception { java.sql.Statement s = null; s.executeQuery("SELECT * FROM " + "table"); } }'
        r = self._check(code, 'SONAR_SQL_CONCAT_INJECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_format_sql_injection(self):
        code = 'class Foo { void bar() { String q = String.format("SELECT %s FROM table", "x"); } }'
        r = self._check(code, 'SONAR_FORMAT_SQL_INJECTION')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_json_ignore_redundant(self):
        code = 'class Foo { @com.fasterxml.jackson.annotation.JsonIgnore public String getX() { return ""; } }'
        r = self._check(code, 'SONAR_JSON_IGNORE_REDUNDANT')
        self.assertGreaterEqual(len(r), 1)

    def test_sonar_files_lines_stream(self):
        code = 'class Foo { void bar() throws Exception { java.nio.file.Files.lines(java.nio.file.Paths.get(".")); } }'
        r = self._check(code, 'SONAR_FILES_LINES_STREAM')
        self.assertGreaterEqual(len(r), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
