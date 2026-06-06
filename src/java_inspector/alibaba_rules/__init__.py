"""AlibabaRulesChecker — 293 条规则的总入口，委派到 19 个模块检查器"""
from typing import List

from java_inspector.alibaba_rules.base import BaseChecker
from java_inspector.alibaba_rules.naming import NamingChecker
from java_inspector.alibaba_rules.constant import ConstantChecker
from java_inspector.alibaba_rules.code_style import CodeStyleChecker
from java_inspector.alibaba_rules.oop import OopChecker
from java_inspector.alibaba_rules.date import DateChecker
from java_inspector.alibaba_rules.collection import CollectionChecker
from java_inspector.alibaba_rules.control import ControlChecker
from java_inspector.alibaba_rules.concurrency import ConcurrencyChecker
from java_inspector.alibaba_rules.comment import CommentChecker
from java_inspector.alibaba_rules.exception import ExceptionChecker
from java_inspector.alibaba_rules.logging import LoggingChecker
from java_inspector.alibaba_rules.other import OtherChecker
from java_inspector.alibaba_rules.method_length import MethodLengthChecker
from java_inspector.alibaba_rules.frontend_backend import FrontendBackendChecker
from java_inspector.alibaba_rules.security import SecurityChecker
from java_inspector.alibaba_rules.sql import SqlChecker
from java_inspector.alibaba_rules.unit_test import UnitTestChecker
from java_inspector.alibaba_rules.engineering import EngineeringChecker
from java_inspector.alibaba_rules.design import DesignChecker
from java_inspector.models import CodeIssue
from java_inspector.config import InspectionConfig


checker_classes = [
    NamingChecker,
    ConstantChecker,
    CodeStyleChecker,
    OopChecker,
    DateChecker,
    CollectionChecker,
    ControlChecker,
    ConcurrencyChecker,
    CommentChecker,
    ExceptionChecker,
    LoggingChecker,
    OtherChecker,
    MethodLengthChecker,
    FrontendBackendChecker,
    SecurityChecker,
    SqlChecker,
    UnitTestChecker,
    EngineeringChecker,
    DesignChecker,
]


def get_checker_classes():
    """返回所有阿里规约检查器类的列表"""
    return list(checker_classes)


class AlibabaRulesChecker:
    def __init__(self, config: InspectionConfig, issues: List[CodeIssue]):
        self.config = config
        self.issues = issues
        self.checkers = [cls(config, issues) for cls in checker_classes]

    def run_all(self, tree, file_path: str, content: str):
        for checker in self.checkers:
            checker.run_all(tree, file_path, content)
