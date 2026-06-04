"""CI/CD 集成 — 质量门禁与退出码控制"""
from typing import Dict, List

from java_inspector.models import CodeIssue, Severity
from java_inspector.config import InspectionConfig


class CICDIntegrator:
    def __init__(self, config: InspectionConfig):
        self.config = config
        self.exit_code = 0

    def check_quality_gate(self, issues_by_file: Dict[str, List[CodeIssue]]) -> bool:
        ci_config = self.config.config["ci_cd"]
        total_errors = 0
        total_warnings = 0

        for issues in issues_by_file.values():
            for issue in issues:
                if issue.severity == Severity.ERROR:
                    total_errors += 1
                elif issue.severity == Severity.WARNING:
                    total_warnings += 1

        if ci_config["fail_on_error"] and total_errors > 0:
            print(f"CI/CD检查失败: 发现 {total_errors} 个错误")
            self.exit_code = 1
            return False

        if total_warnings > ci_config["max_warnings"]:
            print(
                f"CI/CD检查失败: 警告数量 {total_warnings} 超过限制 {ci_config['max_warnings']}"
            )
            self.exit_code = 1
            return False

        print(f"CI/CD检查通过: 错误 {total_errors}, 警告 {total_warnings}")
        return True

    def get_exit_code(self) -> int:
        return self.exit_code
