"""BaseChecker — 所有检查器的基类，提供 _add、_pos 方法及通用正则模式"""
import re
from typing import List

import javalang

from java_inspector.models import CodeIssue, Severity
from java_inspector.config import InspectionConfig


RACIST_PATTERNS = re.compile(
    r"\b(blackList|black_list|whiteList|white_list|slave|master)\b", re.IGNORECASE
)
CHINESE_PATTERN = re.compile(r"[\u4e00-\u9fff]")
INSULT_PATTERNS = re.compile(r"\b(SB|WTF|TMD|NMD|MDZZ)\b")


class BaseChecker:
    ABBREV_PATTERN = re.compile(r"\b[a-z]{1,2}\b")
    # 子类覆盖此属性以指定检查方法名，默认为 run_all
    _check_method: str = ""

    def __init__(self, config: InspectionConfig, issues: List[CodeIssue]):
        self.config = config
        self.issues = issues

    @staticmethod
    def _pos(node):
        if node is not None and hasattr(node, "position") and node.position:
            return node.position.line, node.position.column
        return 0, 0

    def _add(self, file_path, rule_id, message, severity=Severity.WARNING, line=0, column=0, fix_suggestion=""):
        self.issues.append(CodeIssue(
            file_path=file_path,
            line=line,
            column=column,
            message=f"【阿里规约】{message}",
            severity=severity,
            rule_id=rule_id,
            category="ALIBABA",
            fix_suggestion=fix_suggestion,
        ))

    def run_all(self, tree, file_path: str, content: str):
        """子类可通过 _check_method 指定方法名，或覆盖此方法。若无 _check_method 则自动按命名约定查找。"""
        if self._check_method:
            getattr(self, self._check_method)(tree, file_path, content)
            return
        # 自动推断：ClassName → method_name
        cls_name = type(self).__name__
        suffix = "Checker"
        if cls_name.endswith(suffix):
            base = cls_name[:-len(suffix)]
            snake = re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', base).lower()
            method_name = f"check_{snake}"
            if hasattr(self, method_name):
                getattr(self, method_name)(tree, file_path, content)
                return
        # 兜底：尝试调用 run_all（子类覆盖的）
        pass
