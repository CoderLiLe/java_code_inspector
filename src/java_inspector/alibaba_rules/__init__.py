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


class AlibabaRulesChecker:
    def __init__(self, config: InspectionConfig, issues: List[CodeIssue]):
        self.config = config
        self.issues = issues
        self.checkers = [cls(config, issues) for cls in checker_classes]

    def run_all(self, tree, file_path: str, content: str):
        for checker in self.checkers:
            method_name = self._get_method_name(checker)
            getattr(checker, method_name)(tree, file_path, content)

    @staticmethod
    def _get_method_name(checker):
        cls_name = type(checker).__name__
        mapping = {
            "NamingChecker": "check_naming",
            "ConstantChecker": "check_constant",
            "CodeStyleChecker": "check_code_style",
            "OopChecker": "check_oop",
            "DateChecker": "check_date",
            "CollectionChecker": "check_collection",
            "ControlChecker": "check_control",
            "ConcurrencyChecker": "check_concurrency",
            "CommentChecker": "check_comment",
            "ExceptionChecker": "check_exception",
            "LoggingChecker": "check_logging",
            "OtherChecker": "check_other",
            "MethodLengthChecker": "check_method_length",
            "FrontendBackendChecker": "check_frontend_backend",
            "SecurityChecker": "check_security",
            "SqlChecker": "check_sql",
            "UnitTestChecker": "check_unit_test",
            "EngineeringChecker": "check_engineering",
            "DesignChecker": "check_design",
        }
        return mapping.get(cls_name, "")
