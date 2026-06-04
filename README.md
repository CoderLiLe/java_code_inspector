## 工具概述

Java代码检查工具是一个基于Python开发的静态代码分析工具，用于检查Java代码质量、规范性和潜在问题。使用 `javalang` 库解析Java源代码AST，支持多种报告格式输出和自动修复。

## 主要功能

| 功能 | 说明 |
|------|------|
| ✅ 未使用的import检查 | 检测并自动修复未使用的导入语句 |
| ✅ 命名规范检查 | 检查类名、方法名、字段名、常量命名是否符合规范 |
| ✅ 代码风格检查 | 检查行长度、尾随空格等 |
| ✅ 方法复杂度分析 | 检测圈复杂度过高的方法 |
| ✅ 空方法检测 | 检测空方法体 |
| ✅ 魔法数字检测 | 检测代码中的魔法数字 |
| ✅ 异常处理检查 | 检测空的catch块、过于宽泛的异常捕获 |
| ✅ 重复代码检测 | 检测重复的代码片段 |
| ✅ System.out检测 | 检测System.out.print/printf调用 |
| ✅ 多种报告格式输出 | 支持text/json/csv/xml/html |
| ✅ 自动修复功能 | 支持自动移除未使用的import |
| ✅ CI/CD集成支持 | 质量门禁、退出码控制、GitHub Actions工作流 |
| ✅ 阿里Java规约 | 集成《Java开发手册(黄山版)》293条规约，覆盖19个类别（命名/OOP/集合/并发/SQL等） |
| ✅ SonarQube规则 | 集成SonarQube代码质量规则，覆盖Bugs/Code Smell/Security三大类，17个检查器 |

## 项目结构

```
java_code_inspector/
├── src/
│   └── java_inspector/           # Python包
│       ├── __init__.py
│       ├── cli.py                # 命令行入口
│       ├── config.py             # 配置加载
│       ├── hooks.py              # Git钩子安装
│       ├── inspector.py          # 核心检查引擎
│       ├── models.py             # 数据模型
│       ├── reporter.py           # 报告生成器
│       ├── alibaba_rules.py      # 阿里规约入口（委派到 alibaba_rules/ 包）
│       └── alibaba_rules/        # 阿里规约检查器包（19个模块）
│           ├── __init__.py       # AlibabaRulesChecker 类
│           ├── base.py           # BaseChecker 基类
│           ├── naming.py         # 命名风格 (27 条)
│           ├── constant.py       # 常量定义 (5 条)
│           ├── code_style.py     # 代码风格 (14 条)
│           ├── oop.py            # 面向对象 (41 条)
│           ├── date.py           # 日期时间 (11 条)
│           ├── collection.py     # 集合处理 (22 条)
│           ├── control.py        # 控制语句 (15 条)
│           ├── concurrency.py    # 并发处理 (20 条)
│           ├── comment.py        # 注释规范 (11 条)
│           ├── exception.py      # 异常处理 (15 条)
│           ├── logging.py        # 日志规约 (6 条)
│           ├── other.py          # 其他 (8 条)
│           ├── method_length.py  # 方法长度 (1 条)
│           ├── frontend_backend.py # 前后端规约 (17 条)
│           ├── security.py       # 安全规约 (13 条)
│           ├── sql.py            # MySQL 数据库 (40 条)
│           ├── unit_test.py      # 单元测试 (5 条)
│           ├── engineering.py    # 工程结构 (18 条)
│           └── design.py         # 设计规约 (6 条)
│       ├── sonarqube_rules.py    # SonarQube 规则入口（委派到 sonarqube/ 包）
│       └── sonarqube/            # SonarQube 规则检查器包（17个模块）
│           ├── __init__.py       # 所有 SonarQubeChecker 类的导出
│           ├── sonarqube_rules.py          # 主检查器 (Bugs / Code Smell / Security)
│           ├── sonarqube_rules_ext.py      # 扩展检查器
│           ├── sonarqube_rules_full.py     # 完整规则集
│           ├── sonarqube_rules_fourth.py   # 第四批规则
│           ├── sonarqube_rules_five.py     # 第五批规则
│           ├── sonarqube_rules_six.py      # 第六批规则
│           ├── sonarqube_rules_seven.py    # 第七批规则
│           ├── sonarqube_rules_eight.py    # 第八批规则
│           ├── sonarqube_rules_nine.py     # 第九批规则
│           ├── sonarqube_rules_ten.py      # 第十批规则
│           ├── sonarqube_rules_eleven.py   # 第十一批规则
│           ├── sonarqube_rules_twelve.py   # 第十二批规则
│           ├── sonarqube_rules_thirteen.py # 第十三批规则
│           ├── sonarqube_rules_fourteen.py # 第十四批规则
│           ├── sonarqube_rules_fifteen.py  # 第十五批规则
│           ├── sonarqube_rules_sixteen.py  # 第十六批规则
│           └── sonarqube_rules_seventeen.py# 第十七批规则
├── tests/
│   ├── __init__.py
│   ├── test_config.json
│   ├── test_java_inspector.py    # 测试套件
│   └── test_file/
│       ├── GoodExample.java
│       └── TestExample.java
├── docs/                         # 文档目录
│   ├── ALIBABA_RULES.md          # 阿里规约规则总表（293条）
│   ├── JAVA_MANUAL.md            # 《Java开发手册(黄山版)》全文（1946行）
│   ├── ARCHITECTURE.md           # 架构说明
│   └── CONFIG.md                 # 配置参考
├── java_inspector_config.json    # 默认配置文件
├── java-code-check.yaml          # GitHub Actions工作流
├── run_tests.py                  # 测试运行脚本
└── requirements.txt              # Python依赖
```

## 安装

```bash
# 克隆项目
git clone <repo_url>
cd java_code_inspector

# 安装依赖
pip install -r requirements.txt
```

## 运行测试

```bash
# 运行所有测试
python run_tests.py

# 或直接使用unittest
python -m unittest discover -s tests -v

# 运行特定测试文件
python -m unittest tests.test_java_inspector -v

# 运行特定测试方法
python -m unittest tests.test_java_inspector.TestJavaCodeInspector.test_inspect_file_with_issues -v
```

## 使用方法

```bash
# 检查当前目录下的Java文件
python -m java_inspector

# 检查指定目录
python -m java_inspector /path/to/java/project

# 检查单个文件
python -m java_inspector /path/to/File.java

# 使用自定义配置
python -m java_inspector /path/to/project --config /path/to/config.json

# 生成HTML报告
python -m java_inspector /path/to/project --format html --output report.html

# 自动修复可修复的问题（目前支持未使用的import）
python -m java_inspector /path/to/File.java --fix

# CI/CD模式，质量问题返回非零退出码
python -m java_inspector /path/to/project --ci-cd

# 安装Git预提交钩子
python -m java_inspector --install-hook
```

## 配置文件

配置文件为JSON格式，支持以下规则配置 (`java_inspector_config.json`)：

```json
{
  "rules": {
    "line_length": { "enabled": true, "max_length": 120 },
    "naming_conventions": { "enabled": true },
    "unused_imports": { "enabled": true },
    "method_complexity": { "enabled": true, "max_complexity": 10 },
    "empty_methods": { "enabled": true },
    "duplicate_code": { "enabled": true, "min_tokens": 50 },
    "exception_handling": { "enabled": true },
    "magic_numbers": { "enabled": true },
    "cyclomatic_complexity": { "enabled": true, "max_complexity": 15 },
    "comments_ratio": { "enabled": false, "min_ratio": 0.2 }
  },
  "auto_fix": {
    "unused_imports": true,
    "naming_conventions": false
  },
  "exclude_patterns": ["**/test/**", "**/generated/**", "**/target/**"],
  "ci_cd": {
    "fail_on_error": true,
    "max_warnings": 50,
    "quality_gate": 0.8
  }
}
```

## 报告格式

支持 5 种输出格式：

| 格式 | 说明 |
|------|------|
| text | 控制台文本输出（默认） |
| json | JSON格式，适合程序处理 |
| csv | CSV表格格式 |
| xml | XML格式 |
| html | HTML报告，带样式 |

## CI/CD集成

### GitHub Actions

项目内置了 GitHub Actions 工作流 (`java-code-check.yaml`)，在推送或PR时自动运行代码质量检查。

### 命令行集成

```bash
# CI/CD模式：质量问题时退出码非0
python -m java_inspector src/ --ci-cd

# 先自动修复，再检查
python -m java_inspector src/ --fix
python -m java_inspector src/ --ci-cd
```

### Maven集成

```xml
<build>
  <plugins>
    <plugin>
      <groupId>org.codehaus.mojo</groupId>
      <artifactId>exec-maven-plugin</artifactId>
      <version>3.0.0</version>
      <executions>
        <execution>
          <phase>verify</phase>
          <goals><goal>exec</goal></goals>
          <configuration>
            <executable>python</executable>
            <arguments>
              <argument>-m</argument>
              <argument>java_inspector</argument>
              <argument>src/main/java</argument>
              <argument>--ci-cd</argument>
              <argument>--config</argument>
              <argument>java_inspector_config.json</argument>
            </arguments>
          </configuration>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

### Gradle集成

```groovy
task codeQualityCheck(type: Exec) {
    commandLine 'python', '-m', 'java_inspector', 'src/main/java', '--ci-cd', '--config', 'java_inspector_config.json'
    ignoreExitValue true
    doLast {
        if (execResult.exitValue != 0) {
            throw new GradleException('代码质量检查失败！')
        }
    }
}
check.dependsOn codeQualityCheck
```

## Git钩子集成

```bash
# 自动安装pre-commit钩子
python -m java_inspector --install-hook

# 或手动创建 .git/hooks/pre-commit
# 内容：
#   #!/bin/bash
#   python -m java_inspector src/ --ci-cd
#   if [ $? -ne 0 ]; then
#       echo "代码检查失败，请修复问题后再提交"
#       exit 1
#   fi
```

## Docker

### Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ src/
COPY java_inspector_config.json .

ENTRYPOINT ["python", "-m", "java_inspector"]
CMD ["--help"]
```

### 使用Docker运行

```bash
# 构建镜像
docker build -t java-code-inspector .

# 检查项目
docker run -v $(pwd):/project java-code-inspector /project/src --ci-cd

# 生成HTML报告
docker run -v $(pwd):/project java-code-inspector /project/src --format html --output /project/report.html
```

## 自动化脚本示例

```python
#!/usr/bin/env python3
"""自动化代码检查脚本"""

import subprocess
import sys
import os
from datetime import datetime

def run_code_inspection(project_path, config_path=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/code_quality_{timestamp}.html"
    os.makedirs("reports", exist_ok=True)

    cmd = ["python", "-m", "java_inspector", project_path,
           "--format", "html", "--output", report_file]
    if config_path and os.path.exists(config_path):
        cmd.extend(["--config", config_path])
    cmd.append("--ci-cd")

    print(f"运行命令: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    print(f"退出代码: {result.returncode}")
    return result.returncode, report_file

if __name__ == "__main__":
    project_path = sys.argv[1] if len(sys.argv) > 1 else "."
    config_path = sys.argv[2] if len(sys.argv) > 2 else None
    exit_code, _ = run_code_inspection(project_path, config_path)
    sys.exit(exit_code)
```
