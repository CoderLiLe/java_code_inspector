"""日志规约 — 6 条规则：SLF4J 门面、日志级别、占位符"""
import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class LoggingChecker(BaseChecker):

    def check_logging(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_logging"):
            return
        lines = content.split("\n")

        uses_log4j = False
        uses_slf4j = False
        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                ip = node.path or ""
                if "org.apache.log4j" in ip or "org.apache.logging" in ip:
                    uses_log4j = True
                if "org.slf4j" in ip:
                    uses_slf4j = True

        if uses_log4j and not uses_slf4j:
            for path, node in tree:
                if isinstance(node, javalang.tree.Import) and \
                   ("org.apache.log4j" in (node.path or "") or "org.apache.logging" in (node.path or "")):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_LOG_FACADE",
                              "应使用 SLF4J 门面模式的日志框架，而非直接使用 Log4j/Logback API",
                              Severity.WARNING, line=l, column=c)
                    break

        for i, line in enumerate(lines, 1):
            if re.search(r'logger\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+', line) or \
               re.search(r'log\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+', line):
                self._add(file_path, "ALIBABA_LOG_PLACEHOLDER",
                          "日志字符串拼接应使用占位符 {} 方式，如 logger.info(\"msg {}\", var)",
                          Severity.INFO, line=i)

            if re.search(r'logger\.(debug|trace)\s*\(', line) and \
               not re.search(r'is(Debug|Trace)Enabled', line):
                self._add(file_path, "ALIBABA_LOG_LEVEL_CHECK",
                          "trace/debug 级别日志输出必须进行级别开关判断",
                          Severity.INFO, line=i)

        # Log file additivity check
        if file_path.endswith((".xml",)):
            for i, line in enumerate(lines, 1):
                if re.search(r'<logger\s', line) and \
                   not re.search(r'additivity\s*=\s*"false"', line) and \
                   not re.search(r"<!--|-->", line):
                    self._add(file_path, "ALIBABA_LOG_ADDITIVITY",
                              "避免重复打印日志，务必在日志配置文件中设置 additivity=false",
                              Severity.INFO, line=i)

            if re.search(r"System\.(out|err)\.(print|println|printf)", line):
                self._add(file_path, "ALIBABA_SYSTEM_OUT",
                          "生产环境禁止使用 System.out/err 输出或使用 e.printStackTrace() 打印异常堆栈",
                          Severity.WARNING, line=i)
            if re.search(r"\.printStackTrace\s*\(\)", line):
                self._add(file_path, "ALIBABA_SYSTEM_OUT",
                          "生产环境禁止使用 System.out/err 输出或使用 e.printStackTrace() 打印异常堆栈",
                          Severity.WARNING, line=i)

            # 3.9 Exception info should include scene and stack
            if re.search(r"logger\.(error|warn)\s*\([^)]*\"[^\"]*\"\s*,\s*[^e]", line) and \
               not re.search(r"getMessage|e,\s*e|Exception|Throwable", line):
                pass

            # 3.10 No JSON tool in log
            if re.search(r'logger\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+.*(toJSON|JSON\.toJSON|toJson|JSON\.stringify)', line) or \
               re.search(r'log\.(info|debug|trace|warn|error)\s*\(\s*"[^"]*"\s*\+.*(toJSON|JSON\.toJSON|toJson|JSON\.stringify)', line):
                self._add(file_path, "ALIBABA_LOG_JSON",
                          "日志打印时禁止直接用 JSON 工具将对象转换成 String，应使用日志框架的占位符",
                          Severity.WARNING, line=i)
