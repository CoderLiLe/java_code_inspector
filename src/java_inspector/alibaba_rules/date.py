import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class DateChecker(BaseChecker):

    def check_date(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_date"):
            return
        lines = content.split("\n")
        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                ip = node.path or ""
                if ip in ("java.sql.Date", "java.sql.Time", "java.sql.Timestamp"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_NO_SQL_DATE",
                              f"禁止使用 {ip}，应使用 java.util.Date 或 JDK8 时间类",
                              Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+Date\(\)\.getTime\(\)", line):
                self._add(file_path, "ALIBABA_CURRENT_TIME_MILLIS",
                          "获取当前毫秒数应使用 System.currentTimeMillis() 而不是 new Date().getTime()",
                          Severity.INFO, line=i)
            if re.search(r"YYYY", line) and not re.search(r"//\s*", line):
                self._add(file_path, "ALIBABA_DATE_FORMAT_YEAR",
                          "日期格式化时表示年份应使用小写 yyyy，大写 YYYY 表示 week in which year",
                          Severity.WARNING, line=i)

            if re.search(r"SimpleDateFormat.*\"", line):
                m = re.search(r"SimpleDateFormat.*\"([^\"]+)\"", line)
                if m:
                    fmt = m.group(1)
                    has_valid = False
                    if "M" in fmt and "m" in fmt:
                        self._add(file_path, "ALIBABA_DATE_FORMAT_CASE",
                                  "日期格式中月份为大写 M，分钟为小写 m，请勿混淆",
                                  Severity.WARNING, line=i)
                        has_valid = True
                    if "H" in fmt and "h" in fmt:
                        self._add(file_path, "ALIBABA_DATE_FORMAT_CASE",
                                  "日期格式中 24 小时制为大写 H，12 小时制为小写 h，请确认意图",
                                  Severity.WARNING, line=i)
                        has_valid = True
                    if re.search(r"[Mm]{3,}", fmt):
                        self._add(file_path, "ALIBABA_DATE_FORMAT_CASE",
                                  "月份格式 MMM/MMMM 可能不符合预期，推荐使用 MM",
                                  Severity.INFO, line=i)

            if re.search(r"365", line) and re.search(r"(day|year|date|DAYS|Calendar)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_HARDCODED_365",
                          "禁止在程序中写死一年为 365 天，应使用 LocalDate.lengthOfYear() 等方式",
                          Severity.WARNING, line=i)

            # 5.7 Use enum for months
            if re.search(r"\b(Calendar\.|new\s+GregorianCalendar\s*\()", line) and \
               re.search(r"\b(JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER)", line, re.IGNORECASE):
                pass

            if re.search(r"\b(1[0-2]|[1-9])\b.*\b(month|MONTH|Month)\b", line) and \
               not re.search(r"//", line) and \
               not re.search(r"Calendar\.", line):
                m = re.search(r"\b(1[0-2]|[1-9])\b", line)
                if m:
                    self._add(file_path, "ALIBABA_MONTH_ENUM",
                              "建议使用枚举值来指代月份，而非使用数字字面量",
                              Severity.INFO, line=i)

        # 1.8 Use JDK8 time API instead of java.util.Date/Calendar
        for path, node in tree:
            if isinstance(node, javalang.tree.Import):
                ip = node.path or ""
                if ip in ("java.util.Date", "java.util.Calendar", "java.text.SimpleDateFormat"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_USE_LOCALDATETIME",
                              f"避免使用 {ip}，推荐使用 JDK8 新时间 API（LocalDate/LocalTime/LocalDateTime/Instant）",
                              Severity.INFO, line=l, column=c)

        # 1.9 Time should always carry time zone
        for i, line in enumerate(lines, 1):
            if re.search(r"@JsonFormat", line) and \
               not re.search(r"timezone|TimeZone|GMT|UTC|Asia/Shanghai", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_TIME_ZONE",
                          "序列化日期时建议指定 timezone 参数",
                          Severity.INFO, line=i)

        # 1.12 Do not use int for timestamp
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name == "int" and not ft.name == "long":
                    for decl in node.declarators:
                        fn = decl.name.lower()
                        if any(kw in fn for kw in ("timestamp", "create_time", "update_time", "createTime", "updateTime", "expire_time")):
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_TIMESTAMP_INT",
                                      f"时间戳字段 '{decl.name}' 使用 long 而非 int",
                                      Severity.WARNING, line=l, column=c)

        # 1.5 Do not use Calendar.get() with magic numbers
        for i, line in enumerate(lines, 1):
            if re.search(r"Calendar\.get\(", line) and \
               re.search(r"\b(0|7|8|9|10|11|12)\b", line) and \
               not re.search(r"Calendar\.(YEAR|MONTH|DATE|HOUR|MINUTE|SECOND|MILLISECOND)", line):
                self._add(file_path, "ALIBABA_CALENDAR_MAGIC",
                          "Calendar 获取值请使用常量如 Calendar.DAY_OF_MONTH 而非数字",
                          Severity.INFO, line=i)

        # 1.6 Leap year: 2/29 hardcoded
        for i, line in enumerate(lines, 1):
            if re.search(r"(02-29|02/29|2-29|2/29|\"Feb 29\"|'Feb 29'|February 29|2月29)", line) and \
               not re.search(r"//.*闰年|//.*leap|//.*valid", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_LEAP_YEAR_FEB29",
                          "避免硬编码 2 月 29 日，闰年 2 月 29 日需要特殊处理",
                          Severity.INFO, line=i)
