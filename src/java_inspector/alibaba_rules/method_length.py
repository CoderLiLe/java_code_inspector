"""方法长度 — 1 条规则：方法行数不超过 80 行"""
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class MethodLengthChecker(BaseChecker):

    def check_method_length(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_method_length"):
            return
        max_lines = self.config.get_rule_config("alibaba_method_length").get("max_lines", 80)
        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            if method.position:
                start_line = method.position.line
                body_lines = 0
                if method.body:
                    stmts = method.body if isinstance(method.body, list) else getattr(method.body, "statements", [])
                    if stmts:
                        last = stmts[-1]
                        if hasattr(last, "position") and last.position:
                            body_lines = last.position.line - start_line
                if body_lines > max_lines:
                    l, c = self._pos(method)
                    self._add(file_path, "ALIBABA_METHOD_LENGTH",
                              f"方法 '{method.name}' 总行数 {body_lines} 超过建议值 {max_lines} 行",
                              Severity.WARNING, line=l, column=c)
