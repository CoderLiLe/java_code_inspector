# Architecture

## Module Overview

```
__main__.py           CLI entry point (python -m java_inspector)
    │
    v
cli.py                Argument parsing, orchestration, logging config
    │
    ├──> config.py           InspectionConfig — rule toggles, thresholds, env var overrides
    ├──> inspector.py        JavaCodeInspector — core engine, per-checker error isolation
    │       │
    │       ├──> alibaba_rules.py         Re-exports AlibabaRulesChecker
    │       │       │
    │       │       └──> alibaba_rules/   293 rules, 19 categories, 20 files
    │       │               ├── __init__.py   AlibabaRulesChecker + get_checker_classes()
    │       │               ├── base.py       BaseChecker (shared _pos, _add, run_all)
    │       │               ├── naming.py     (27 rules)
    │       │               ├── oop.py        (41 rules)
    │       │               ├── sql.py        (40 rules)
    │       │               └── ... 14 more
    │       │
    │       ├──> sonarqube_rules.py         Re-exports all SonarQubeChecker classes
    │       │       │
    │       │       └──> sonarqube/         17 checkers + 1 base, 18 files
    │       │               ├── __init__.py       All 17 checker re-exports + get_checker_classes()
    │       │               ├── base.py           BaseSonarChecker (shared _pos, _add, sq_severity)
    │       │               ├── sonarqube_rules.py          SonarQubeChecker (main)
    │       │               ├── sonarqube_rules_ext.py      SonarQubeCheckerExt
    │       │               ├── sonarqube_rules_full.py     SonarQubeCheckerFull
    │       │               └── ... 14 more extension checkers
    │       │
    │       ├──> reporter.py        InspectionReporter — text/json/xml/html/csv output
    │       ├──> ci_cd.py           CICDIntegrator — quality gate enforcement
    │       └──> hooks.py           Git pre-commit hook installer
```

## Data Flow

1. **Config loading**: `InspectionConfig` merges hardcoded defaults → user JSON file → `JAVA_INSPECTOR_*` environment variables
2. **Parsing**: `JavaCodeInspector` reads `.java` files, parses with `javalang` into AST
3. **Checks**: Built-in checks + Alibaba checkers (19) + SonarQube checkers (17), each with per-checker error isolation — a single checker failure does not abort the rest
4. **Reporting**: `InspectionReporter` groups issues by file and renders in chosen format
5. **CI/CD**: `CICDIntegrator` checks error/warning counts against configured thresholds

## Key Classes

| Class | File | Role |
|-------|------|------|
| `InspectionConfig` | `config.py` | All configuration state, env var overrides |
| `JavaCodeInspector` | `inspector.py` | Core inspection engine, parallel file processing |
| `BaseChecker` | `alibaba_rules/base.py` | Alibaba checker base class — shared `_pos`, `_add`, `run_all` |
| `BaseSonarChecker` | `sonarqube/base.py` | SonarQube checker base class — shared `_pos`, `_add`, `sq_severity`, `_METHOD_BLACKLIST` |
| `AlibabaRulesChecker` | `alibaba_rules/__init__.py` | 293 Alibaba rules facade (19 categories) |
| `SonarQubeChecker` (×17) | `sonarqube/` | 17 SonarQube checker classes (all inherit `BaseSonarChecker`) |
| `InspectionReporter` | `reporter.py` | Multi-format report generation (text/json/csv/xml/html) |
| `CICDIntegrator` | `ci_cd.py` | Quality gate enforcement with logging |
| `CodeIssue` (dataclass) | `models.py` | Single issue: file, line, id, severity, message |
| `CodeMetrics` (dataclass) | `models.py` | Cyclomatic complexity, duplication, etc. |

## Checker Loading — Registry Pattern

Rather than hardcoding individual checker imports, `inspector.py` uses a dynamic registry:

```python
from java_inspector.alibaba_rules import get_checker_classes as get_alibaba_checkers
from java_inspector.sonarqube import get_checker_classes as get_sonar_checkers
```

Both `get_checker_classes()` functions return a list of checker classes from `_CHECKER_CLASSES` lists in their respective `__init__.py`. The inspector lazily instantiates all checkers once and calls `run_all()` on each.

## BaseSonarChecker — Shared Code Elimination

All 17 SonarQube checker files inherit from `BaseSonarChecker` (in `sonarqube/base.py`), which provides:

| Member | Description |
|--------|-------------|
| `__init__(config, issues)` | Constructor — stores config ref and shared issues list |
| `_pos(node)` | Extracts (line, column) from AST node position |
| `_add(file_path, rule_id, message, ...)` | Appends a `CodeIssue` to the shared issues list |
| `sq_severity(sonar_sev)` | Maps SonarQube severity strings to `Severity` enum |
| `_METHOD_BLACKLIST` | Common method names excluded from naming checks |

Each checker file now contains only:
1. Import of `BaseSonarChecker` and `sq_severity` from `sonarqube.base`
2. Class definition inheriting `BaseSonarChecker`
3. `run_all()` method dispatching to category-specific check methods
4. Actual rule-checking logic

## AlibabaRulesChecker — 19 Checkers

Each Alibaba checker extends `BaseChecker` and implements a `check_*` method. The `BaseChecker.run_all()` method automatically infers the method name from the class name (e.g., `NamingChecker` → `check_naming`), eliminating the old 19-item `_get_method_name()` mapping table.

| # | Class | Method | Category | Config Key |
|---|-------|--------|----------|------------|
| 1 | `NamingChecker` | `check_naming` | 命名风格 | `alibaba_naming` |
| 2 | `CodeStyleChecker` | `check_code_style` | 代码风格 | `alibaba_code_style` |
| 3 | `OopChecker` | `check_oop` | 面向对象 | `alibaba_oop` |
| 4 | `DateChecker` | `check_date` | 日期时间 | `alibaba_date` |
| 5 | `CollectionChecker` | `check_collection` | 集合处理 | `alibaba_collection` |
| 6 | `ControlChecker` | `check_control` | 控制语句 | `alibaba_control` |
| 7 | `ConcurrencyChecker` | `check_concurrency` | 并发处理 | `alibaba_concurrency` |
| 8 | `CommentChecker` | `check_comment` | 注释规范 | `alibaba_comment` |
| 9 | `ConstantChecker` | `check_constant` | 常量定义 | `alibaba_constant` |
| 10 | `ExceptionChecker` | `check_exception` | 异常处理 | `alibaba_exception` |
| 11 | `LoggingChecker` | `check_logging` | 日志规约 | `alibaba_logging` |
| 12 | `OtherChecker` | `check_other` | 其他 | `alibaba_other` |
| 13 | `MethodLengthChecker` | `check_method_length` | 方法长度 | `alibaba_method_length` |
| 14 | `FrontendBackendChecker` | `check_frontend_backend` | 前后端规约 | `alibaba_frontend_backend` |
| 15 | `SecurityChecker` | `check_security` | 安全规约 | `alibaba_security` |
| 16 | `SqlChecker` | `check_sql` | MySQL 数据库 | `alibaba_sql` |
| 17 | `UnitTestChecker` | `check_unit_test` | 单元测试 | `alibaba_unit_test` |
| 18 | `DesignChecker` | `check_design` | 设计规约 | `alibaba_design` |
| 19 | `EngineeringChecker` | `check_engineering` | 工程结构 | `alibaba_engineering` |

## Error Isolation

Per-checker error isolation ensures a single failing checker does not abort the entire inspection:

- **Built-in checks**: Each of the 9 built-in check methods is wrapped in its own try/except
- **Alibaba/SonarQube checkers**: Each checker's `run_all()` call is individually guarded
- **File-level**: File read errors and parse errors are caught and reported as `FILE_READ_ERROR` / `PARSE_ERROR` issues
- **Parallel mode**: Worker exceptions are caught and reported per-file, never crashing the main process

## Logging

Uses Python `logging` module throughout:
- `logger.warning` for non-fatal errors (checker failures, config issues)
- `logger.error` for CI/CD quality gate failures
- `logger.info` for status messages
- CLI controls logging level via `--verbose` (DEBUG) / `--quiet` (ERROR)

## Parallel Inspection

`inspect_directory()` uses `concurrent.futures.ThreadPoolExecutor` to inspect multiple files concurrently:

- Each worker creates a fresh `JavaCodeInspector` instance to avoid shared state issues
- Thread count defaults to `min(os.cpu_count(), 8)` and can be overridden via `--workers`
- Falls back to sequential processing for single files or `max_workers=1`

## Extensibility

### Adding an Alibaba Rule Category

1. Create a checker class extending `BaseChecker` in `alibaba_rules/` with a `check_*` method
2. Register the class in the `checker_classes` list in `alibaba_rules/__init__.py`
3. Add a corresponding `alibaba_*` config key in `config.py` defaults

### Adding a SonarQube Rule Checker

1. Create a checker class extending `BaseSonarChecker` in `sonarqube/`
2. Implement `run_all()` dispatching to category-specific check methods
3. Register the class in `_CHECKER_CLASSES` in `sonarqube/__init__.py`
4. Add corresponding `sonar_*` config keys in `config.py` defaults
