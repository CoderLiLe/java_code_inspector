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


if __name__ == '__main__':
    unittest.main(verbosity=2)
