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
    "alibaba_engineering":      { "enabled": true }
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
| `quality_gate` | `0.8` | Minimum quality score (unused, reserved) |
