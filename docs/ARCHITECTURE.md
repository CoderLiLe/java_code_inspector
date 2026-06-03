# Architecture

## Module Overview

```
__main__.py           CLI entry point (python -m java_inspector)
    │
    v
cli.py                Argument parsing, orchestration
    │
    ├──> config.py           InspectionConfig — rule toggles, thresholds, excludes
    ├──> inspector.py        JavaCodeInspector — core engine, built-in checks
    │       │
    │       ├──> alibaba_rules.py         Re-exports AlibabaRulesChecker
    │       │       │
    │       │       └──> alibaba_rules/   293 rules, 19 categories, 21 files
    │       │               ├── __init__.py   AlibabaRulesChecker (facade)
    │       │               ├── base.py       BaseChecker
    │       │               ├── naming.py     (27 rules)
    │       │               ├── oop.py        (41 rules)
    │       │               ├── sql.py        (40 rules)
    │       │               └── ... 14 more
    │       │
    │       ├──> sonarqube_rules.py     SonarQube checker base
    │       └──> sonarqube_rules_*.py   16 extension checkers
    │
    ├──> reporter.py        InspectionReporter — text/json/xml/html/csv output
    ├──> ci_cd.py           CICDIntegrator — quality gate enforcement
    └──> hooks.py           Git pre-commit hook installer
```

## Data Flow

1. **Config loading**: `InspectionConfig` merges hardcoded defaults with user JSON file
2. **Parsing**: `JavaCodeInspector` reads `.java` files, parses with `javalang` into AST
3. **Checks**: Built-in checks + `AlibabaRulesChecker` + `SonarQubeChecker`(×17) each append `CodeIssue` objects to a shared list
4. **Reporting**: `InspectionReporter` groups issues by file and renders in chosen format
5. **CI/CD**: `CICDIntegrator` checks error/warning counts against configured thresholds

## Key Classes

| Class | File | Role |
|-------|------|------|
| `InspectionConfig` | `config.py` | All configuration state |
| `JavaCodeInspector` | `inspector.py` | Core inspection engine |
| `AlibabaRulesChecker` | `alibaba_rules/__init__.py` | 293 Alibaba rules (19 categories, 21 files) |
| `InspectionReporter` | `reporter.py` | Multi-format report generation |
| `CICDIntegrator` | `ci_cd.py` | Quality gate enforcement |
| `CodeIssue` (dataclass) | `models.py` | Single issue: file, line, id, severity, message |
| `CodeMetrics` | `models.py` | Cyclomatic complexity, duplication, etc. |

## AlibabaRulesChecker — 19 Check Methods

| # | Method | Category | Config Key |
|---|--------|----------|------------|
| 1 | `check_naming` | 命名风格 | `alibaba_naming` |
| 2 | `check_code_style` | 代码风格 | `alibaba_code_style` |
| 3 | `check_oop` | 面向对象 | `alibaba_oop` |
| 4 | `check_date` | 日期时间 | `alibaba_date` |
| 5 | `check_collection` | 集合处理 | `alibaba_collection` |
| 6 | `check_control` | 控制语句 | `alibaba_control` |
| 7 | `check_concurrency` | 并发处理 | `alibaba_concurrency` |
| 8 | `check_comment` | 注释规范 | `alibaba_comment` |
| 9 | `check_constant` | 常量定义 | `alibaba_constant` |
| 10 | `check_exception` | 异常处理 | `alibaba_exception` |
| 11 | `check_logging` | 日志规约 | `alibaba_logging` |
| 12 | `check_other` | 其他 | `alibaba_other` |
| 13 | `check_method_length` | 方法长度 | `alibaba_method_length` |
| 14 | `check_frontend_backend` | 前后端规约 | `alibaba_frontend_backend` |
| 15 | `check_security` | 安全规约 | `alibaba_security` |
| 16 | `check_sql` | MySQL 数据库 | `alibaba_sql` |
| 17 | `check_unit_test` | 单元测试 | `alibaba_unit_test` |
| 18 | `check_design` | 设计规约 | `alibaba_design` |
| 19 | `check_engineering` | 工程结构 | `alibaba_engineering` |

All methods are called sequentially from `run_all()` and guarded by `self.config.is_rule_enabled(...)`.

## Extensibility

Add a new rule set by:

1. Create a checker class extending `BaseChecker` in `alibaba_rules/` with a `check_*` method
2. Register the checker class in the `checker_classes` list in `alibaba_rules/__init__.py`
3. Add the method name mapping in `AlibabaRulesChecker._get_method_name()`
4. Add a corresponding toggle in `config.py` defaults and `java_inspector_config.json`
