# Configuration Reference

## File: `java_inspector_config.json`

```json
{
  "rules": {
    "line_length":              { "enabled": true, "max_length": 120 },
    "naming_conventions":       { "enabled": true },
    "unused_imports":           { "enabled": true },
    "method_complexity":        { "enabled": true, "max_complexity": 10 },
    "empty_methods":            { "enabled": true },
    "duplicate_code":           { "enabled": true, "min_tokens": 50 },
    "exception_handling":       { "enabled": true },
    "magic_numbers":            { "enabled": true },
    "comments_ratio":           { "enabled": false, "min_ratio": 0.2 },
    "cyclomatic_complexity":    { "enabled": true, "max_complexity": 15 },

    "alibaba_naming":           { "enabled": true },
    "alibaba_code_style":       { "enabled": true },
    "alibaba_oop":              { "enabled": true },
    "alibaba_date":             { "enabled": true },
    "alibaba_collection":       { "enabled": true },
    "alibaba_control":          { "enabled": true },
    "alibaba_concurrency":      { "enabled": true },
    "alibaba_comment":          { "enabled": true },
    "alibaba_constant":         { "enabled": true },
    "alibaba_exception":        { "enabled": true },
    "alibaba_logging":          { "enabled": true },
    "alibaba_other":            { "enabled": true },
    "alibaba_method_length":    { "enabled": true, "max_lines": 80 },
    "alibaba_frontend_backend": { "enabled": true },
    "alibaba_security":         { "enabled": true },
    "alibaba_sql":              { "enabled": true },
    "alibaba_unit_test":        { "enabled": true },
    "alibaba_design":           { "enabled": true },
    "alibaba_engineering":      { "enabled": true },

    "sonar_bugs":               { "enabled": true },
    "sonar_code_smell":         { "enabled": true },
    "sonar_security":           { "enabled": true },
    "sonar_performance":        { "enabled": true },
    "sonar_reliability":        { "enabled": true },
    "sonar_design":             { "enabled": true },
    "sonar_error_prone":        { "enabled": true },
    "sonar_best_practices":     { "enabled": true },
    "sonar_clarity":            { "enabled": true },
    "sonar_security_extra":     { "enabled": true },
    "sonar_concurrency":        { "enabled": true },
    "sonar_code_quality":       { "enabled": true },
    "sonar_java_api":           { "enabled": true },
    "sonar_bugs_extra":         { "enabled": true },
    "sonar_convention_extra":   { "enabled": true },
    "sonar_maintainability":    { "enabled": true },
    "sonar_correctness":        { "enabled": true },
    "sonar_robustness":         { "enabled": true },
    "sonar_api_usage":          { "enabled": true },
    "sonar_spring":             { "enabled": true },
    "sonar_java_features":      { "enabled": true },
    "sonar_testing":            { "enabled": true },
    "sonar_redundancy":         { "enabled": true },
    "sonar_security_hotspots":  { "enabled": true },
    "sonar_error_prone_nine":   { "enabled": true },
    "sonar_miscellaneous":      { "enabled": true },
    "sonar_advanced_features":  { "enabled": true },
    "sonar_more_concurrency":   { "enabled": true },
    "sonar_design_principles":  { "enabled": true },
    "sonar_organization":       { "enabled": true },
    "sonar_framework_complete": { "enabled": true },
    "sonar_final_edge_cases":   { "enabled": true },
    "sonar_security_fourteen":  { "enabled": true },
    "sonar_serialization_fourteen": { "enabled": true },
    "sonar_math_fourteen":      { "enabled": true },
    "sonar_convention_fourteen":{ "enabled": true },
    "sonar_error_prone_fourteen":{ "enabled": true },
    "sonar_http_web":           { "enabled": true },
    "sonar_jdbc_jpa":           { "enabled": true },
    "sonar_testing_extra":      { "enabled": true },
    "sonar_quality_extra":      { "enabled": true },
    "sonar_json_xml":           { "enabled": true },
    "sonar_nio_reflection":     { "enabled": true },
    "sonar_datetime_extra":     { "enabled": true },
    "sonar_sql_general":        { "enabled": true },
    "sonar_cdi_injection":      { "enabled": true },
    "sonar_lambda_stream":      { "enabled": true },
    "sonar_generics_types":     { "enabled": true },
    "sonar_enums_annotations":  { "enabled": true },
    "sonar_misc_seventeen":     { "enabled": true }
  },

  "auto_fix": {
    "unused_imports": true,
    "naming_conventions": false
  },

  "exclude_patterns": [
    "**/test/**",
    "**/generated/**",
    "**/target/**"
  ],

  "ci_cd": {
    "fail_on_error": true,
    "max_warnings": 50,
    "quality_gate": 0.8
  }
}
```

## Environment Variable Overrides

All config values can be overridden via environment variables with the `JAVA_INSPECTOR_` prefix.
Use `__` (double underscore) to traverse nested keys:

```bash
# Disable a rule
export JAVA_INSPECTOR_RULES__LINE_LENGTH__ENABLED=false

# Change a threshold
export JAVA_INSPECTOR_RULES__LINE_LENGTH__MAX_LENGTH=150
export JAVA_INSPECTOR_RULES__METHOD_COMPLEXITY__MAX_COMPLEXITY=15

# CI/CD settings
export JAVA_INSPECTOR_CI_CD__MAX_WARNINGS=100
export JAVA_INSPECTOR_CI_CD__FAIL_ON_ERROR=false

# Auto-fix settings
export JAVA_INSPECTOR_AUTO_FIX__UNUSED_IMPORTS=false

# Top-level keys
export JAVA_INSPECTOR_EXCLUDE_PATTERNS='["**/test/**"]'  # Note: arrays must be in JSON config file
```

### Naming Convention

```
JAVA_INSPECTOR_<section>__<key>__<subkey>=<value>
```

### Value Type Parsing

| Input | Parsed As |
|-------|-----------|
| `true`, `yes`, `1` | `True` (bool) |
| `false`, `no`, `0` | `False` (bool) |
| `123` | `123` (int) |
| `3.14` | `3.14` (float) |
| anything else | string |

### Priority

Configuration is merged in this order (later overrides earlier):

1. Hardcoded defaults in `InspectionConfig.default_config`
2. User JSON config file (`--config` / `-c`)
3. Environment variables (`JAVA_INSPECTOR_*`)

## Alibaba Rule Config Keys

Prefix `alibaba_` rules map to `AlibabaRulesChecker` check methods (defined in `alibaba_rules/` package, 19 modules). Set `"enabled": false` to skip an entire category.

| Config Key | Source Module | Rules |
|---|---|---|
| `alibaba_naming` | `alibaba_rules/naming.py` | Class/method/field/constant naming conventions |
| `alibaba_code_style` | `alibaba_rules/code_style.py` | Indentation, line length, spacing |
| `alibaba_oop` | `alibaba_rules/oop.py` | POJO, equals/hashCode, BigDecimal, money types |
| `alibaba_date` | `alibaba_rules/date.py` | Date format, JDK8 time, calendar usage |
| `alibaba_collection` | `alibaba_rules/collection.py` | toMap, subList, foreach, init capacity |
| `alibaba_control` | `alibaba_rules/control.py` | switch, if-else depth, braces |
| `alibaba_concurrency` | `alibaba_rules/concurrency.py` | Thread pool, ThreadLocal, locks |
| `alibaba_comment` | `alibaba_rules/comment.py` | TODO/FIXME, inline comments, Javadoc |
| `alibaba_constant` | `alibaba_rules/constant.py` | Long suffix, float suffix, magic values |
| `alibaba_exception` | `alibaba_rules/exception.py` | Catch handling, finally, NPE |
| `alibaba_logging` | `alibaba_rules/logging.py` | SLF4J facade, log level checks, System.out |
| `alibaba_other` | `alibaba_rules/other.py` | Pattern compile, BeanUtils, SQL injection |
| `alibaba_method_length` | `alibaba_rules/method_length.py` | Method line count (default 80) |
| `alibaba_frontend_backend` | `alibaba_rules/frontend_backend.py` | API JSON, pagination, versioning, templates |
| `alibaba_security` | `alibaba_rules/security.py` | XSS, CSRF, SQL injection, file upload, password |
| `alibaba_sql` | `alibaba_rules/sql.py` | MySQL table design, index, query optimization |
| `alibaba_unit_test` | `alibaba_rules/unit_test.py` | Test location, assert usage, env dependency |
| `alibaba_design` | `alibaba_rules/design.py` | Single responsibility, composition, inheritance |
| `alibaba_engineering` | `alibaba_rules/engineering.py` | Layer exceptions, package naming, remote timeout |

## SonarQube Rule Config Keys

Prefix `sonar_` rules map to `SonarQubeChecker` classes (17 checkers in `sonarqube/` package, all extending `BaseSonarChecker`). Set `"enabled": false` to skip a checker's entire category.

| Config Key | Checker Class | Check Methods |
|---|---|---|
| `sonar_bugs` | `SonarQubeChecker` | `check_bugs` |
| `sonar_code_smell` | `SonarQubeChecker` | `check_code_smell` |
| `sonar_security` | `SonarQubeChecker` | `check_security` |
| `sonar_performance` | `SonarQubeCheckerExt` | `check_performance` |
| `sonar_reliability` | `SonarQubeCheckerExt` | `check_reliability` |
| `sonar_design` | `SonarQubeCheckerExt` | `check_design` |
| `sonar_error_prone` | `SonarQubeCheckerFull` | `check_error_prone` |
| `sonar_best_practices` | `SonarQubeCheckerFull` | `check_best_practices` |
| `sonar_clarity` | `SonarQubeCheckerFull` | `check_clarity` |
| `sonar_security_extra` | `SonarQubeCheckerExt` | `check_security_ext` |
| `sonar_concurrency` | `SonarQubeCheckerSix` | `check_concurrency` |
| `sonar_code_quality` | `SonarQubeCheckerSix` | `check_code_quality` |
| `sonar_bugs_extra` | `SonarQubeCheckerExt` | `check_bugs_ext` |
| `sonar_convention_extra` | `SonarQubeCheckerSeven` | `check_convention_extra` |
| `sonar_maintainability` | `SonarQubeCheckerSeven` | `check_maintainability` |
| `sonar_correctness` | `SonarQubeCheckerSeven` | `check_correctness` |
| `sonar_robustness` | `SonarQubeCheckerSeven` | `check_robustness` |
| `sonar_api_usage` | `SonarQubeCheckerSeven` | `check_api_usage` |
| `sonar_spring` | `SonarQubeCheckerEight` | `check_spring` |
| `sonar_java_features` | `SonarQubeCheckerEight` | `check_java_features` |
| `sonar_testing` | `SonarQubeCheckerEight` | `check_testing` |
| `sonar_redundancy` | `SonarQubeCheckerEight` | `check_redundancy` |

Additional keys exist for checkers Nine through Seventeen. See `sonarqube/__init__.py` for the complete `_CHECKER_CLASSES` registry.

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `path` | `.` | File or directory to inspect |
| `-c, --config` | — | Path to config JSON file |
| `-o, --output` | — | Output file path |
| `-f, --format` | `text` | Report format: `text`, `json`, `csv`, `xml`, `html` |
| `--fix` | `false` | Auto-fix fixable issues (unused imports) |
| `--ci-cd` | `false` | Enable CI/CD mode (non-zero exit on quality failure) |
| `--install-hook` | `false` | Install Git pre-commit hook |
| `-w, --workers` | `auto` | Number of parallel worker threads |
| `-v, --verbose` | `false` | Show detailed debug logs |
| `-q, --quiet` | `false` | Show only error messages |

## Exclude Patterns

Uses glob matching. Default excludes:

- `**/test/**`
- `**/generated/**`
- `**/target/**`

Add additional patterns to `"exclude_patterns"` array.

## CI/CD Settings

| Key | Default | Description |
|-----|---------|-------------|
| `fail_on_error` | `true` | Fail CI if any ERROR severity issue exists |
| `max_warnings` | `50` | Max allowed WARNING issues before failure |
| `quality_gate` | `0.8` | Minimum quality score (reserved for future use) |
