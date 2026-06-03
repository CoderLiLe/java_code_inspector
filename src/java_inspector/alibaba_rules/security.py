import re
from typing import List

import javalang

from java_inspector.alibaba_rules.base import BaseChecker


class SecurityChecker(BaseChecker):
    def check_security(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_security"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"SELECT\s+.*\b(password|pwd|secret|token|credential|private_key|api_key)\b", line, re.IGNORECASE) and \
               not re.search(r"//.*(脱敏|mask|hide|\*|replace)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_SENSITIVE_DATA",
                          "用户敏感数据禁止直接展示，必须对展示数据进行脱敏",
                          Severity.WARNING, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []) and \
               any("password" in p.name.lower() or "secret" in p.name.lower() or "token" in p.name.lower()
                   for p in (node.parameters or []) if hasattr(p, "name")):
                for stmt in (node.body if isinstance(node.body, list) else []):
                    if isinstance(stmt, javalang.tree.IfStatement) and \
                       hasattr(stmt, "expression") and stmt.expression:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_PARAM_VALIDATION",
                                  "用户请求传入的任何参数必须做有效性验证",
                                  Severity.WARNING, line=l, column=c)
                        break

        for i, line in enumerate(lines, 1):
            if re.search(r"password\s*=\s*[\"'].*[\"']", line) and \
               not re.search(r"//|/\*|\*", line):
                self._add(file_path, "ALIBABA_HARDCODED_PASSWORD",
                          "配置文件中的密码需要加密，禁止在代码中硬编码密码",
                          Severity.ERROR, line=i)

        # 4.x Anti-replay for resource-sensitive operations
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []):
                mn = node.name.lower()
                if any(kw in mn for kw in ("send", "pay", "order", "sms", "email", "message", "transfer", "withdraw", "charge")):
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                        body_str = str(getattr(node, "body", "") or "")
                        if not re.search(r"(idempotent|noRepeat|repeatSubmit|token|rateLimit|limit|幂等|防重)", body_str, re.IGNORECASE):
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_ANTI_REPLAY",
                                      "在使用平台资源（短信、邮件、电话、下单、支付）时，必须实现正确的防重放机制",
                                      Severity.WARNING, line=l, column=c)

        # 4.1 Permission control check
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []):
                mn = node.name
                if mn.startswith(("delete", "update", "add", "create", "modify", "remove", "batch")):
                    has_auth = False
                    annotations = getattr(node, "annotations", []) or []
                    for ann in annotations:
                        if hasattr(ann, "name") and ann.name in ("PreAuthorize", "PreFilter", "Secured", "RolesAllowed"):
                            has_auth = True
                            break
                    if not has_auth:
                        body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                        for stmt in body_stmts:
                            if "hasRole" in str(stmt) or "hasPermission" in str(stmt) or "hasAuthority" in str(stmt):
                                has_auth = True
                                break
                        if not has_auth:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_PERMISSION_CHECK",
                                      f"操作方法 '{mn}' 必须进行权限控制校验",
                                      Severity.WARNING, line=l, column=c)

        # 4.5 XSS protection
        for i, line in enumerate(lines, 1):
            if re.search(r"ModelAndView|Model|@ResponseBody", line) and \
               re.search(r"(request\.getParameter|@RequestParam|@PathVariable)", line) and \
               not re.search(r"(HtmlUtils|StringEscapeUtils|escapeHtml|XSS|clean|sanitize)", line) and \
               not re.search(r"//", line):
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"(HtmlUtils|StringEscapeUtils|escapeHtml|sanitize)", lines[j - 1]):
                        break
                else:
                    self._add(file_path, "ALIBABA_XSS_PROTECTION",
                              "禁止向 HTML 页面输出未经安全过滤或未正确转义的用户数据，防止 XSS 攻击",
                              Severity.WARNING, line=i)

        # 4.6 CSRF validation
        for i, line in enumerate(lines, 1):
            if re.search(r"@PostMapping|@PutMapping|@DeleteMapping|@RequestMapping.*method.*POST", line) and \
               not re.search(r"(csrf|CSRF|@CrossOrigin)", line):
                for j in range(max(0, i-5), i):
                    if j < len(lines) and re.search(r"(csrf|CSRF)", lines[j], re.IGNORECASE):
                        break
                else:
                    self._add(file_path, "ALIBABA_CSRF",
                              "表单、AJAX 提交必须执行 CSRF 安全验证",
                              Severity.INFO, line=i)

        # 4.7 URL redirect whitelist
        for i, line in enumerate(lines, 1):
            if re.search(r"redirect\s*:\s*[\"'](https?://)", line) and \
               not re.search(r"(whitelist|white_list|allowed|permit|validateUrl|checkUrl)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_REDIRECT_WHITELIST",
                          "URL 外部重定向传入的目标地址必须执行白名单过滤",
                          Severity.WARNING, line=i)

        # 4.9 File upload validation
        for i, line in enumerate(lines, 1):
            if re.search(r"MultipartFile|@RequestParam.*file|@RequestParam.*upload", line) and \
               not re.search(r"(fileSize|maxSize|MaxUploadSize|allowedExtension|contentType|fileType)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_FILE_UPLOAD",
                          "对于文件上传功能，需要对文件大小、类型进行严格检查和控制",
                          Severity.WARNING, line=i)

        # 4.11 User input validation required
        for i, line in enumerate(lines, 1):
            if re.search(r"@RequestParam|@PathVariable|@RequestBody", line) and \
               not re.search(r"@Valid|@Validated|javax\.validation|jakarta\.validation", line) and \
               not re.search(r"//", line):
                for j, line2 in enumerate(lines[max(0, i - 15):i + 15], max(0, i - 14)):
                    if re.search(r"@Valid|@Validated", line2):
                        break
                else:
                    pass  # too noisy for @Valid on every param

        # 4.12 No SQL injection in MyBatis ${
        for i, line in enumerate(lines, 1):
            if re.search(r"\$\{", line) and \
               re.search(r"(select|from|where|order by|group by|having|insert|update|delete)", line, re.IGNORECASE) and \
               not re.search(r"//.*no_sqli|//.*sql_injection", line, re.IGNORECASE):
                if re.search(r"\$\{.*(user|input|query|param|keyword|name|value|text|search)", line, re.IGNORECASE) or \
                   re.search(r"order\s+by\s+\$\{", line, re.IGNORECASE):
                    self._add(file_path, "ALIBABA_SQL_INJECTION",
                              "MyBatis 中使用 ${} 拼接的 SQL 存在注入风险，建议使用 #{} 参数化查询",
                              Severity.ERROR, line=i)

        # 4.13 User ID in session, not from request
        for i, line in enumerate(lines, 1):
            if re.search(r"request\.getParameter.*userId|request\.getParameter.*user_id|request\.getParameter.*accountId", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_USERID_FROM_REQUEST",
                          "用户 ID 应从 session 中获取，禁止从请求参数中获取以防止越权",
                          Severity.WARNING, line=i)

        # 4.14 Logging sensitive data
        for i, line in enumerate(lines, 1):
            if re.search(r"(log(ger)?\.(info|debug|warn|error)|System\.out|System\.err)", line) and \
               re.search(r"(password|pwd|secret|token|credential|authCode|smsCode|verifyCode)", line, re.IGNORECASE) and \
               not re.search(r"//.*(脱敏|mask|hide|\*)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_LOG_SENSITIVE",
                          "日志输出时禁止出现密码、密钥等敏感信息",
                          Severity.WARNING, line=i)

        # 4.15 Content security: anti-spam, anti-fraud, content filtering
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "public" in (node.modifiers or []):
                mn = node.name.lower()
                if any(kw in mn for kw in ("publish", "post", "reply", "comment", "send", "message", "review")):
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                        body_str = str(getattr(node, "body", "") or "")
                        if not re.search(r"(rateLimiter|rate_limit|rateLimit|limit|throttle|防刷|antiSpam|spam|contentCheck|checkContent|sensitive|filter|validate)", body_str, re.IGNORECASE):
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_CONTENT_SECURITY",
                                      "用户发布/评论/发送等场景必须实现防刷、内容违禁词过滤等安全措施",
                                      Severity.INFO, line=l, column=c)
