"""配置管理 — 加载合并 JSON 配置与默认值，支持环境变量覆盖"""
import copy
import json
import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)


_ENV_PREFIX = "JAVA_INSPECTOR_"


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
                "alibaba_frontend_backend": {"enabled": True},
                "alibaba_security": {"enabled": True},
                "alibaba_sql": {"enabled": True},
                "alibaba_unit_test": {"enabled": True},
                "alibaba_design": {"enabled": True},
                "alibaba_engineering": {"enabled": True},
                "sonar_bugs": {"enabled": True},
                "sonar_code_smell": {"enabled": True},
                "sonar_security": {"enabled": True},
                "sonar_performance": {"enabled": True},
                "sonar_reliability": {"enabled": True},
                "sonar_design": {"enabled": True},
                "sonar_error_prone": {"enabled": True},
                "sonar_best_practices": {"enabled": True},
                "sonar_clarity": {"enabled": True},
                "sonar_security_extra": {"enabled": True},
                "sonar_concurrency": {"enabled": True},
                "sonar_code_quality": {"enabled": True},
                "sonar_java_api": {"enabled": True},
                "sonar_bugs_extra": {"enabled": True},
                "sonar_convention_extra": {"enabled": True},
                "sonar_maintainability": {"enabled": True},
                "sonar_bugs_six": {"enabled": True},
                "sonar_code_smell_six": {"enabled": True},
                "sonar_security_six": {"enabled": True},
                "sonar_correctness": {"enabled": True},
                "sonar_robustness": {"enabled": True},
                "sonar_performance_seven": {"enabled": True},
                "sonar_api_usage": {"enabled": True},
                "sonar_spring": {"enabled": True},
                "sonar_java_features": {"enabled": True},
                "sonar_testing": {"enabled": True},
                "sonar_redundancy": {"enabled": True},
                "sonar_security_hotspots": {"enabled": True},
                "sonar_error_prone_nine": {"enabled": True},
                "sonar_miscellaneous": {"enabled": True},
                "sonar_convention_ten": {"enabled": True},
                "sonar_design_ten": {"enabled": True},
                "sonar_robustness_ten": {"enabled": True},
                "sonar_advanced_features": {"enabled": True},
                "sonar_complete_testing": {"enabled": True},
                "sonar_more_concurrency": {"enabled": True},
                "sonar_security_twelve": {"enabled": True},
                "sonar_design_principles": {"enabled": True},
                "sonar_performance_twelve": {"enabled": True},
                "sonar_organization": {"enabled": True},
                "sonar_framework_complete": {"enabled": True},
                "sonar_final_edge_cases": {"enabled": True},
                "sonar_java_twelve_plus": {"enabled": True},
                "sonar_code_patterns_extra": {"enabled": True},
                "sonar_security_fourteen": {"enabled": True},
                "sonar_serialization_fourteen": {"enabled": True},
                "sonar_math_fourteen": {"enabled": True},
                "sonar_convention_fourteen": {"enabled": True},
                "sonar_error_prone_fourteen": {"enabled": True},
                "sonar_http_web": {"enabled": True},
                "sonar_jdbc_jpa": {"enabled": True},
                "sonar_testing_extra": {"enabled": True},
                "sonar_quality_extra": {"enabled": True},
                "sonar_json_xml": {"enabled": True},
                "sonar_nio_reflection": {"enabled": True},
                "sonar_datetime_extra": {"enabled": True},
                "sonar_sql_general": {"enabled": True},
                "sonar_cdi_injection": {"enabled": True},
                "sonar_lambda_stream": {"enabled": True},
                "sonar_generics_types": {"enabled": True},
                "sonar_enums_annotations": {"enabled": True},
                "sonar_misc_seventeen": {"enabled": True},
            },
            "auto_fix": {"unused_imports": True, "naming_conventions": False},
            "exclude_patterns": ["**/test/**", "**/generated/**"],
            "ci_cd": {"fail_on_error": True, "max_warnings": 50, "quality_gate": 0.8},
        }

        self.config = copy.deepcopy(self.default_config)
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
        self._apply_env_overrides()

    def load_config(self, config_file: str):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                self._deep_update(self.config, user_config)
        except Exception as e:
            logger.warning("加载配置文件失败: %s", e)

    @staticmethod
    def _deep_update(base: Dict, update: Dict):
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                InspectionConfig._deep_update(base[key], value)
            else:
                base[key] = value

    def _apply_env_overrides(self):
        for env_key, env_val in os.environ.items():
            if not env_key.startswith(_ENV_PREFIX):
                continue
            config_path = env_key[len(_ENV_PREFIX):].lower()
            parts = config_path.split("__")

            # 沿 parts 路径深入配置字典
            target = self.config
            for i, part in enumerate(parts[:-1]):
                if part in target and isinstance(target[part], dict):
                    target = target[part]
                else:
                    target = None
                    break

            if target is not None and parts[-1] in target:
                target[parts[-1]] = self._parse_env_value(env_val)

    @staticmethod
    def _parse_env_value(val: str):
        lower = val.lower()
        if lower in ("true", "yes", "1"):
            return True
        if lower in ("false", "no", "0"):
            return False
        try:
            return int(val)
        except ValueError:
            try:
                return float(val)
            except ValueError:
                return val

    def is_rule_enabled(self, rule_id: str) -> bool:
        return self.config["rules"].get(rule_id, {}).get("enabled", False)

    def get_rule_config(self, rule_id: str) -> Dict:
        return self.config["rules"].get(rule_id, {})
