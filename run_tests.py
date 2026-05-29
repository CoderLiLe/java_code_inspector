#!/usr/bin/env python3
"""
测试运行脚本
"""

import unittest
import sys
import os


def run_tests():
    """运行所有测试"""
    # 添加src目录到Python路径
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

    # 发现并运行所有测试
    test_loader = unittest.TestLoader()

    # 直接指定测试目录
    start_dir = os.path.join(os.path.dirname(__file__), 'tests')
    test_suite = test_loader.discover(start_dir, pattern='test_*.py')

    # 运行测试
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)

    # 返回适当的退出代码
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    exit_code = run_tests()
    sys.exit(exit_code)
