import re

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class CodeStyleChecker(BaseChecker):

    def check_code_style(self, tree, file_path: str, content: str):
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            # 3.2 Left brace spacing
            if re.search(r"(if|for|while|do|switch|try|catch|synchronized)\s*\([^)]*\)\s*[^\s{]", line) and \
               not re.search(r"\(\s*\)\s*;|\)\s*\{", line) and \
               not re.search(r"\{\s*$", line):
                pass

            if re.search(r"\b(if|while|for|switch|catch|synchronized)\(", line) and \
               not re.search(r"\b(if|while|for|switch|catch|synchronized)\s\(", line):
                kw = re.search(r"\b(if|while|for|switch|catch|synchronized)\(", line)
                if kw:
                    self._add(file_path, "ALIBABA_KEYWORD_SPACING",
                              f"'{kw.group(1)}' 关键字与括号之间必须加空格",
                              Severity.INFO, line=i)

            # 3.4 Operator spacing
            if re.search(r"\w(==|!=|<=|>=|&&|\|\|)\w", line) and \
               not re.search(r"[\"'].*[\+\-*/%=<>!&|].*[\"']", line) and \
               not re.search(r"import\s", line) and \
               not re.search(r"//", line):
                m = re.search(r"(\w)(==|!=|<=|>=|&&|\|\|)(\w)", line)
                if m and m.group(1)[-1].isalnum() and m.group(3)[0].isalnum():
                    if not re.search(re.escape(m.group(1)) + r"\s+" + re.escape(m.group(2)) + r"\s+" + re.escape(m.group(3)), line):
                        self._add(file_path, "ALIBABA_OPERATOR_SPACING",
                                  f"二目运算符 '{m.group(2)}' 左右两边都需要加一个空格",
                                  Severity.INFO, line=i)

            if re.search(r"\/\/[^\s]", line) and not re.search(r"https?://", line):
                self._add(file_path, "ALIBABA_COMMENT_SPACING",
                          "// 注释的 // 后应紧跟一个空格",
                          Severity.INFO, line=i)

            if "\t" in line:
                self._add(file_path, "ALIBABA_NO_TABS",
                          "代码换行缩进禁止使用 Tab，请使用空格代替",
                          Severity.INFO, line=i)

            if re.search(r"[a-z]\)[a-z]", line):
                self._add(file_path, "ALIBABA_RPAREN_SPACING",
                          "右括号 ')' 后面应加空格",
                          Severity.INFO, line=i)

            # 3.8 Line length 120
            if len(line.rstrip('\n')) > 120 and not re.match(r"^\s*(//|\*)", line) and \
               not re.search(r"https?://", line):
                self._add(file_path, "ALIBABA_LINE_LENGTH",
                          "单行字符数限制不超过 120 个，超出需要换行",
                          Severity.INFO, line=i)

            if re.search(r"\)\)\s+\w", line):
                m = re.search(r"\(\((\w+)\)\)\s+(\w+)", line)
                if m:
                    self._add(file_path, "ALIBABA_CAST_SPACING",
                              "强制转换的右括号后不加空格，如：(String)a",
                              Severity.INFO, line=i)

            if re.search(r",\S", line) and not re.search(r"[\"'].*,\S.*[\"']", line):
                m = re.search(r",(\S)", line)
                if m and m.group(1) not in (")", "]"):
                    self._add(file_path, "ALIBABA_COMMA_SPACING",
                              "逗号后必须加空格",
                              Severity.INFO, line=i)
            if re.search(r"//\S", line):
                self._add(file_path, "ALIBABA_COMMENT_SPACE",
                          "注释的双斜线与注释内容之间应有且仅有一个空格",
                          Severity.INFO, line=i)
            stripped = line.strip()
            if stripped and "\t" in line[:line.index(stripped[0])]:
                self._add(file_path, "ALIBABA_NO_TAB",
                          "禁止使用 Tab 字符缩进，请使用 4 个空格",
                          Severity.WARNING, line=i)
            if re.search(r"catch\s*\([^)]+\)\s*\{\s*\}", line):
                    self._add(file_path, "ALIBABA_EMPTY_CATCH_BRACE",
                              "大括号内为空时应简洁地写成 {}",
                              Severity.INFO, line=i)
            # 3.1 Brace format: left brace at end of line, right brace on new line
            m = re.search(r"^\s*\}\s*(\S)", line)
            if m and m.group(1) not in ("e", "c", "f", ")"):  # else, catch, finally, )
                self._add(file_path, "ALIBABA_BRACE_FORMAT",
                          "右大括号后除了 else/catch/finally 外必须换行",
                          Severity.INFO, line=i)
            m = re.search(r"^\s*\{", line)
            if m and i > 1 and not re.search(r"^\s*//", lines[i-2]) if i >= 2 else False:
                prev_line = lines[i-2].strip()
                if prev_line and not prev_line.endswith(("{", "(", ")", ";")) and \
                   not prev_line.startswith("//") and not prev_line.startswith("/*"):
                    pass  # too noisy for left brace on own line

        # 3.10 UTF-8 / Unix line endings
        if "\r\n" in content:
            self._add(file_path, "ALIBABA_LINE_ENDING",
                      "文件中使用了 Windows 格式换行符（CRLF），应使用 Unix 格式（LF）",
                      Severity.INFO, line=0)

        # 3.13 Blank lines between sections
        consecutive_blank = 0
        for i, line in enumerate(lines, 1):
            if line.strip() == "":
                consecutive_blank += 1
            else:
                if consecutive_blank > 2:
                    self._add(file_path, "ALIBABA_TOO_MANY_BLANKS",
                              "代码中不应出现连续超过 2 个空行",
                              Severity.INFO, line=i)
                consecutive_blank = 0
