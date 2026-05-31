import copy
import json
import os
from typing import Dict


class InspectionConfig:
    def __init__(self, config_file: str = None):
        self.default_config = {
            "rules": {
                "line_length": {"enabled": True, "max_length": 120},
                "naming_conventions": {"enabled": True},
                "unused_imports": {"enabled": True},
                "method_complexity": {"enabled": True, "max_complexity": 10},
                "empty_methods": {"enabled": True},
                "duplicate_code": {"enabled": True, "min_tokens": 50},
                "exception_handling": {"enabled": True},
                "magic_numbers": {"enabled": True},
                "comments_ratio": {"enabled": True, "min_ratio": 0.2},
                "cyclomatic_complexity": {"enabled": True, "max_complexity": 15},
                "alibaba_naming": {"enabled": True},
                "alibaba_oop": {"enabled": True},
                "alibaba_control": {"enabled": True},
                "alibaba_collection": {"enabled": True},
                "alibaba_constant": {"enabled": True},
                "alibaba_method_length": {"enabled": True, "max_lines": 80},
                "alibaba_code_style": {"enabled": True},
                "alibaba_date": {"enabled": True},
                "alibaba_comment": {"enabled": True},
                "alibaba_concurrency": {"enabled": True},
                "alibaba_exception": {"enabled": True},
                "alibaba_logging": {"enabled": True},
                "alibaba_other": {"enabled": True},
                "sonar_bugs": {"enabled": True},
                "sonar_code_smell": {"enabled": True},
                "sonar_security": {"enabled": True},
                "sonar_performance": {"enabled": True},
                "sonar_reliability": {"enabled": True},
                "sonar_design": {"enabled": True},
            },
            "auto_fix": {"unused_imports": True, "naming_conventions": False},
            "exclude_patterns": ["**/test/**", "**/generated/**"],
            "ci_cd": {"fail_on_error": True, "max_warnings": 50, "quality_gate": 0.8},
        }

        self.config = copy.deepcopy(self.default_config)
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)

    def load_config(self, config_file: str):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                self._deep_update(self.config, user_config)
        except Exception as e:
            print(f"加载配置文件失败: {e}")

    def _deep_update(self, base: Dict, update: Dict):
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value

    def is_rule_enabled(self, rule_id: str) -> bool:
        return self.config["rules"].get(rule_id, {}).get("enabled", False)

    def get_rule_config(self, rule_id: str) -> Dict:
        return self.config["rules"].get(rule_id, {})
