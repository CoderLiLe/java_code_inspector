## 工具概述
Java代码检查工具是一个基于Python开发的静态代码分析工具，用于检查Java代码质量、规范性和潜在问题。

## 主要功能
✅ 未使用的import检查

✅ 命名规范检查

✅ 代码风格检查

✅ 方法复杂度分析

✅ 空方法检测

✅ 魔法数字检测

✅ 异常处理检查

✅ 重复代码检测

✅ 多种报告格式输出

✅ 自动修复功能

✅ CI/CD集成支持

## 项目结构
```
java_code_inspector/
├── src/
│   └── java_inspector.py
├── tests/
│   ├── __init__.py
│   ├── test_java_inspector.py
│   ├── test_file/
│   │   ├── TestExample.java
│   │   └── GoodExample.java
│   └── test_config.json
├── run_tests.py
└── requirements.txt
```

## 运行测试命令
```
# 进入项目目录
cd java_code_inspector

# 安装依赖
pip3 install -r requirements.txt

# 运行测试
python3 run_tests.py

# 或者直接运行unittest
python3 -m unittest discover -s tests -v

# 运行特定测试文件
python3 -m unittest tests.test_java_inspector -v

# 运行特定测试方法
python3 -m unittest tests.test_java_inspector.TestJavaCodeInspector.test_inspect_file_with_issues -v
```

## 运行脚本检查Java代码
```
# 进入项目目录
cd java_code_inspector

# 运行脚本
python3 src/java_inspector.py tests/test_file/

# 使用自定义配置
python3 src/java_inspector.py tests/test_file/ --config config/project_rules.json

# 生成HTML报告
python3 src/java_inspector.py tests/test_file/ --format html --output reports/code_quality.html

# 生成JSON和CSV报告
python3 src/java_inspector.py tests/test_file/ --format json --output reports/issues.json
python3 src/java_inspector.py tests/test_file/ --format csv --output reports/issues.csv
```

## 集成到CI/CD流程
```
# CI/CD模式，如果发现问题会返回非零退出码
python3 java_inspector.py src/ --ci-cd

# 结合自动修复
python3 java_inspector.py src/ --fix  # 先自动修复可修复的问题
python3 java_inspector.py src/ --ci-cd  # 然后检查剩余问题
```

### 运行脚本
check_java.sh

```bash
#!/bin/bash
# Java代码检查脚本

PROJECT_DIR=${1:-"."}
CONFIG_FILE=${2:-"java_inspector_config.json"}
OUTPUT_FILE=${3:-"code_quality_report.html"}

echo "开始检查Java代码质量..."
echo "项目目录: $PROJECT_DIR"
echo "配置文件: $CONFIG_FILE"
echo "输出文件: $OUTPUT_FILE"

# 运行检查
python java_inspector.py "$PROJECT_DIR" \
    --config "$CONFIG_FILE" \
    --format html \
    --output "$OUTPUT_FILE" \
    --ci-cd

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ 代码检查通过"
    echo "报告已生成: $OUTPUT_FILE"
else
    echo "✗ 代码检查失败，请查看报告修复问题"
    echo "报告: $OUTPUT_FILE"
    exit $EXIT_CODE
fi
```

### 使用方式
```bash
# 给脚本执行权限
chmod +x check_java.sh

# 检查当前目录
./check_java.sh

# 检查指定目录
./check_java.sh /path/to/project

# 使用指定配置
./check_java.sh . my_custom_config.json custom_report.html
```

## 集成到构建工具中

### Maven集成 (pom.xml)
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
                    <goals>
                        <goal>exec</goal>
                    </goals>
                    <configuration>
                        <executable>python</executable>
                        <arguments>
                            <argument>java_inspector.py</argument>
                            <argument>src/main/java</argument>
                            <argument>--ci-cd</argument>
                            <argument>--config</argument>
                            <argument>code_quality_config.json</argument>
                        </arguments>
                    </configuration>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

### Gradle集成 (build.gradle)
```groovy
task codeQualityCheck(type: Exec) {
    commandLine 'python', 'java_inspector.py', 'src/main/java', '--ci-cd', '--config', 'code_quality_config.json'
    
    // 只在代码质量检查失败时使构建失败
    ignoreExitValue true
    doLast {
        if (execResult.exitValue != 0) {
            throw new GradleException('代码质量检查失败！请修复报告中的问题。')
        }
    }
}

check.dependsOn codeQualityCheck
```

## Git钩子集成

### 安装Git预提交钩子

```bash
# 安装钩子
python java_inspector.py --install-hook

# 或者手动创建 .git/hooks/pre-commit
#!/bin/bash
echo "运行Java代码检查..."
python java_inspector.py src/ --ci-cd
if [ $? -ne 0 ]; then
    echo "代码检查失败，请修复问题后再提交"
    exit 1
fi
echo "代码检查通过"
```

## Docker容器中运行
### Dockerfile
```bash
FROM python:3.9-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install -r requirements.txt

# 复制代码检查工具
COPY java_inspector.py .
COPY java_inspector_config.json .

# 设置入口点
ENTRYPOINT ["python", "java_inspector.py"]
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

## 实际项目中的使用示例
假设您有一个Spring Boot项目结构：
```
my-spring-app/
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── example/
│                   ├── Application.java
│                   ├── controller/
│                   ├── service/
│                   └── repository/
├── config/
│   └── java_inspector_config.json
└── reports/
```

### 运行检查：
```bash
# 检查整个项目
python java_inspector.py src/main/java/ --config config/java_inspector_config.json

# 或者只检查特定包
python java_inspector.py src/main/java/com/example/controller/

# 生成详细报告
python java_inspector.py src/main/java/ \
    --format html \
    --output reports/code_quality_$(date +%Y%m%d_%H%M%S).html \
    --ci-cd
```

## 自动化脚本示例
auto_check.py
```python
#!/usr/bin/env python3
"""
自动化代码检查脚本
"""

import subprocess
import sys
import os
from datetime import datetime

def run_code_inspection(project_path, config_path=None):
    """运行代码检查"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/code_quality_{timestamp}.html"
    
    # 创建报告目录
    os.makedirs("reports", exist_ok=True)
    
    # 构建命令
    cmd = ["python", "java_inspector.py", project_path, "--format", "html", "--output", report_file]
    
    if config_path and os.path.exists(config_path):
        cmd.extend(["--config", config_path])
    
    cmd.append("--ci-cd")
    
    print(f"运行命令: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # 输出结果
    print("STDOUT:", result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    print(f"退出代码: {result.returncode}")
    print(f"报告文件: {report_file}")
    
    return result.returncode, report_file

if __name__ == "__main__":
    project_path = sys.argv[1] if len(sys.argv) > 1 else "."
    config_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    exit_code, report_file = run_code_inspection(project_path, config_path)
    sys.exit(exit_code)
```
### 使用这个脚本：
```bash
python3 auto_check.py /path/to/java/project
```

这样您就可以灵活地运行Java代码检查工具来检查任何目录下的Java文件了。
