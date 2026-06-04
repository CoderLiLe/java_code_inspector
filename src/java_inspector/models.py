"""数据模型 — CodeIssue、CodeMetrics 等核心类型定义"""
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ReportFormat(Enum):
    TEXT = "text"
    JSON = "json"
    XML = "xml"
    HTML = "html"
    CSV = "csv"


@dataclass
class CodeIssue:
    file_path: str
    line: int
    column: int
    message: str
    severity: Severity
    rule_id: str
    category: str
    fixable: bool = False
    fix_suggestion: str = ""


class CodeMetrics:
    def __init__(self):
        self.total_lines: int = 0
        self.code_lines: int = 0
        self.comment_lines: int = 0
        self.method_count: int = 0
        self.class_count: int = 0
        self.cyclomatic_complexity: int = 0
        self.duplication_rate: float = 0.0
        self.code_smells: int = 0
