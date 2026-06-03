"""前后端规约 — 17 条规则：API JSON、分页、版本、安全"""
import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class FrontendBackendChecker(BaseChecker):

    def check_frontend_backend(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_frontend_backend"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"@GetMapping\s*\(|@PostMapping\s*\(|@RequestMapping\s*\(", line) and \
               not re.search(r"produces\s*=\s*\"application/json", line):
                self._add(file_path, "ALIBABA_API_JSON",
                          "前后端交互推荐使用 JSON 格式而非 XML",
                          Severity.INFO, line=i)

        for i, line in enumerate(lines, 1):
            if re.search(r"Long\s+\w+[Ii][Dd]\s*[=:]\s*\d{10,}", line):
                self._add(file_path, "ALIBABA_LONG_ID_STRING",
                          "对于需要使用超大整数的场景，服务端一律使用 String 字符串类型返回，禁止使用 Long 类型",
                          Severity.WARNING, line=i)

        # 10.4 JSON key lowerCamelCase
        for i, line in enumerate(lines, 1):
            if re.search(r'"\w{3,}"\s*:', line) and not re.search(r"//", line) and \
               not re.search(r'(static|final|private|public|import)', line):
                m = re.search(r'"([A-Z]\w*)"\s*:', line)
                if m:
                    self._add(file_path, "ALIBABA_JSON_KEY_CASE",
                              f"JSON 的 key '{m.group(1)}' 必须为小写字母开始的 lowerCamelCase 风格",
                              Severity.WARNING, line=i, column=line.find(m.group(1)))

        # 10.14 No version in URL path
        for i, line in enumerate(lines, 1):
            if re.search(r'RequestMapping\s*\(\s*".*v\d+[\d.]*"', line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_URL_VERSION",
                          "在接口路径中不要加入版本号，版本控制在 HTTP 头信息中体现",
                          Severity.INFO, line=i)

        # 10.x HTTP URL length check (>2048 bytes)
        for i, line in enumerate(lines, 1):
            if re.search(r"@GetMapping|@RequestMapping.*GET", line):
                url_match = re.search(r'"([^"]{2048,})"', line)
                if url_match:
                    self._add(file_path, "ALIBABA_URL_LENGTH",
                              "HTTP 请求通过 URL 传递参数时，不能超过 2048 字节",
                              Severity.WARNING, line=i)

        # 10.x HTTP body length check
        for i, line in enumerate(lines, 1):
            if re.search(r"@RequestBody", line) and \
               re.search(r"@PostMapping|@PutMapping|@RequestMapping", line):
                body_type = re.search(r"@RequestBody\s+(\w+)", line)
                if body_type and body_type.group(1) in ("String", "Map", "HashMap", "JSONObject"):
                    self._add(file_path, "ALIBABA_BODY_LENGTH",
                              "HTTP 请求通过 body 传递内容时，必须控制长度，超出最大长度后端解析会出错",
                              Severity.INFO, line=i)

        # 10.2 Return empty [] or {} for null data
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mn = node.name
                if mn.startswith(("list", "query", "find", "search", "getAll")):
                    ret_type = getattr(node, "return_type", None)
                    if ret_type and hasattr(ret_type, "name") and ret_type.name in ("List", "Set", "Collection"):
                        body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                        for stmt in body_stmts:
                            if isinstance(stmt, javalang.tree.IfStatement):
                                if_str = str(stmt.expression) if hasattr(stmt, "expression") else ""
                                if "null" in if_str and (">" not in if_str or "size" not in if_str):
                                    break
                        else:
                            for stmt in body_stmts:
                                if isinstance(stmt, javalang.tree.ReturnStatement) and \
                                   hasattr(stmt, "expression") and "null" in str(stmt.expression):
                                    l, c = self._pos(node)
                                    self._add(file_path, "ALIBABA_RETURN_EMPTY",
                                              f"方法 '{mn}' 返回集合数据时，如果为空应返回空数组 [] 或空集合 {{}}，而非 null",
                                              Severity.WARNING, line=l, column=c)
                                    break

        # 10.9 Page parameter validation
        for i, line in enumerate(lines, 1):
            if re.search(r"(pageNum|pageNo|pageIndex|currentPage)\s*[<]", line) and \
               not re.search(r"//", line):
                m = re.search(r"(pageNum|pageNo|pageIndex|currentPage)\s*[<]\s*1", line)
                if m:
                    self._add(file_path, "ALIBABA_PAGE_PARAM",
                              "翻页场景中，用户输入参数小于1，则前端返回第一页参数给后端",
                              Severity.INFO, line=i)

        # 10.10 Internal redirect: forward vs redirect
        for i, line in enumerate(lines, 1):
            if re.search(r"redirect\s*:\s*[\"'](?!http)", line) and \
               not re.search(r"RedirectView|UrlBasedViewResolver", line):
                m = re.search(r"redirect\s*:\s*[\"'](\w+)", line)
                if m:
                    self._add(file_path, "ALIBABA_REDIRECT_FORWARD",
                              "服务器内部重定向必须使用 forward，外部重定向地址必须使用 URL 统一代理模块生成",
                              Severity.WARNING, line=i)

        # 10.13 Date format unified
        for i, line in enumerate(lines, 1):
            if re.search(r"SimpleDateFormat|DateTimeFormatter|@JsonFormat", line) and \
               re.search(r"yyyy-MM-dd HH:mm:ss", line):
                pass
            elif re.search(r"@JsonFormat", line) and \
                 not re.search(r"yyyy-MM-dd HH:mm:ss|yyyy-MM-dd'T'HH:mm:ss", line):
                m = re.search(r"pattern\s*=\s*[\"']([^\"']+)[\"']", line)
                if m:
                    self._add(file_path, "ALIBABA_DATE_FORMAT_UNIFIED",
                              "前后端的时间格式统一为 yyyy-MM-dd HH:mm:ss，统一为 GMT",
                              Severity.INFO, line=i)

        # 10.11 File download content-disposition
        for i, line in enumerate(lines, 1):
            if re.search(r"Content-Disposition.*attachment", line) and \
               not re.search(r"PercentEncoder|URLEncoder|encodeURIComponent|filename\*", line):
                self._add(file_path, "ALIBABA_FILE_DOWNLOAD_HEADER",
                          "文件下载时 Content-Disposition 应使用百分号编码后的 UTF-8 文件名",
                          Severity.WARNING, line=i)

        # 10.12 Duplicate submit prevention
        for i, line in enumerate(lines, 1):
            if re.search(r"@PostMapping|@RequestMapping.*POST", line):
                has_token = False
                for j in range(max(0, i - 5), i + 5):
                    if j < len(lines) and re.search(r"(token|noRepeat|repeatSubmit|rateLimit|limit|idempotent)", lines[j], re.IGNORECASE):
                        has_token = True
                        break
                if not has_token:
                    pass  # skip - too noisy

        # 10.15 Avoid big transaction
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "Transactional" in ann_names:
                    body_str = str(getattr(node, "body", "") or "")
                    if re.search(r"(rpc|dubbo|feign|restTemplate|http|remote|sleep|Thread\.sleep|message|mq|kafka|rabbit)", body_str, re.IGNORECASE):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_TRANSACTION_RPC",
                                  "事务中避免使用 RPC 远程调用、消息发送或线程 sleep",
                                  Severity.WARNING, line=l, column=c)

        # 10.16 Avoid circular reference in JSON
        for i, line in enumerate(lines, 1):
            if re.search(r"@OneToMany|@ManyToMany", line) and \
               not re.search(r"@JsonIgnore|@JsonBackReference|@JsonManagedReference|@JsonIgnoreProperties", line):
                self._add(file_path, "ALIBABA_CIRCULAR_REF",
                          "双向关联关系需要配合 @JsonIgnore 等 JSON 序列化注解，防止循环引用",
                          Severity.INFO, line=i)

        # 10.5 API comments required
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                    start_line = node.position.line if node.position else 1
                    doc_comment_found = False
                    for j in range(max(0, start_line - 10), start_line - 1):
                        if j < len(lines) and re.search(r"/\*\*", lines[j]):
                            doc_comment_found = True
                            break
                    if not doc_comment_found:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_API_COMMENT",
                                  f"API 方法 '{node.name}' 必须添加注释说明接口功能",
                                  Severity.INFO, line=l, column=c)

        # 10.x @ExceptionHandler with errorMessage
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "ExceptionHandler" in ann_names:
                    body_str = str(getattr(node, "body", "") or "")
                    if not re.search(r"errorMessage|error_message|errorCode|error_code|message|msg", body_str):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_ERROR_MESSAGE",
                                  "错误处理应返回 errorCode 和 errorMessage 信息",
                                  Severity.INFO, line=l, column=c)

        # 10.16 View template: no complex logic
        if file_path.endswith((".jsp", ".ftl", ".vm", ".html")):
            for i, line in enumerate(lines, 1):
                if re.search(r"(if\s*\(|for\s*\(|while\s*\()", line) and \
                   re.search(r"(\w+\.\w+|\w+\(|\w+\))", line):
                    nested = line.count("(") > 2
                    if nested:
                        self._add(file_path, "ALIBABA_VIEW_COMPLEX",
                                  "不要在视图模板中加入任何复杂的逻辑运算",
                                  Severity.WARNING, line=i)

        # 10.17 Velocity use $!{} not ${}
        if file_path.endswith(".vm"):
            for i, line in enumerate(lines, 1):
                if re.search(r"\$\{", line) and \
                   not re.search(r"\$\!", line) and \
                   not re.search(r"//|\*", line):
                    self._add(file_path, "ALIBABA_VELOCITY_NULL",
                              "velocity 页面输出变量必须加 $!{var} 以避免空指针",
                              Severity.WARNING, line=i)
