import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class ExceptionChecker(BaseChecker):

    def check_exception(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_exception"):
            return
        lines = content.split("\n")

        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                for catch in (node.catches or []):
                    block = catch.block if hasattr(catch, "block") and catch.block else \
                            getattr(catch, "body", None)
                    body_stmts = block.statements if hasattr(block, "statements") else \
                                 (block if isinstance(block, list) else [])
                    non_comment_stmts = [s for s in body_stmts if not isinstance(s, javalang.tree.StatementExpression)]
                    if not non_comment_stmts:
                        cl = catch.parameter.position.line if catch.parameter and catch.parameter.position else 0
                        self._add(file_path, "ALIBABA_EMPTY_CATCH",
                                  "捕获异常是为了处理它，不要捕获了却什么都不处理而抛弃之",
                                  Severity.WARNING, line=cl)

        # 6 - Close resources in finally / use try-with-resources
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+(File(Input|Output)Stream|FileReader|FileWriter|BufferedReader|BufferedWriter"
                         r"|InputStreamReader|OutputStreamWriter)", line):
                for j in range(i, min(i + 30, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"\.close\s*\(\)", lines[j - 1]):
                        break
                else:
                    close_seen = False
                    for j in range(i, min(i + 30, len(lines) + 1)):
                        if j <= len(lines) and re.search(r"try\s*[({]|try\s*[\(]", lines[j - 1]):
                            parent_line = re.search(r"try\s*[(]?\s*[^)]*" + re.escape(line.strip()[:20]), lines[j - 1]) if j - 1 < len(lines) else None
                            break
                    self._add(file_path, "ALIBABA_STREAM_CLOSE",
                              "IO 流必须通过 finally 块 close 关闭或使用 try-with-resources 方式",
                              Severity.WARNING, line=i)

        # 11 - NPE from auto-unboxing
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ret_type = getattr(node, "return_type", None)
                if ret_type and hasattr(ret_type, "name") and ret_type.name in ("int", "long", "boolean", "double"):
                    for p2, n2 in tree:
                        if isinstance(n2, javalang.tree.ReturnStatement) and \
                           hasattr(n2, "expression") and n2.expression and \
                           hasattr(n2.expression, "qualifier") and \
                           isinstance(n2.expression.qualifier, javalang.tree.MemberReference):
                            pass
                        elif isinstance(n2, javalang.tree.ReturnStatement) and \
                             hasattr(n2, "expression") and n2.expression and \
                             hasattr(n2.expression, "prefix_operators") and \
                             "(" in str(getattr(n2.expression, "selectors", [])):
                            pass

        for i, line in enumerate(lines, 1):
            if re.search(r"\breturn\s+(Integer|Long|Boolean|Double|Float)\.valueOf\(", line) and \
               re.search(r"(int|long|boolean|double|float)\s+\w+\s*=", line):
                self._add(file_path, "ALIBABA_NPE_AUTOBOX",
                          "注意自动拆箱可能产生 NPE，返回包装类型对象给基本类型时可能为 null",
                          Severity.WARNING, line=i)

        for i, line in enumerate(lines, 1):
            if re.search(r"catch\s*\(\s*(NullPointerException|IndexOutOfBoundsException|"
                         r"ArithmeticException|ClassCastException)", line):
                self._add(file_path, "ALIBABA_CATCH_RUNTIME",
                          "可通过预检查规避的 RuntimeException 不应通过 catch 方式处理",
                          Severity.WARNING, line=i)

        in_finally = False
        for i, line in enumerate(lines, 1):
            if re.search(r"finally\s*\{", line):
                in_finally = True
                continue
            if in_finally:
                if re.search(r"\breturn\b", line) and not re.search(r"//.*return", line):
                    self._add(file_path, "ALIBABA_FINALLY_RETURN",
                              "不要在 finally 块中使用 return，会丢弃 try 块中的返回值",
                              Severity.WARNING, line=i)
                    in_finally = False
                if re.search(r"^\s*\}", line):
                    in_finally = False

        # 12 - Don't throw raw RuntimeException/Exception
        for i, line in enumerate(lines, 1):
            if re.search(r"throw\s+new\s+(RuntimeException|Exception)\s*\(", line) and \
               not re.search(r"//.*throw", line):
                self._add(file_path, "ALIBABA_RAW_EXCEPTION",
                          "禁止直接抛出 RuntimeException 或 Exception，应使用有业务含义的自定义异常",
                          Severity.WARNING, line=i)
            if re.search(r"catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)", line) and \
               not re.search(r"(RPC|反射|reflect|Proxy|动态)", content, re.IGNORECASE):
                self._add(file_path, "ALIBABA_CATCH_GENERIC",
                          "catch 时应尽可能区分异常类型，避免使用 Exception/Throwable 捕获所有异常",
                          Severity.INFO, line=i)

        # Transaction rollback check in catch
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "Transactional" in ann_names:
                    for stmt in (node.body if isinstance(node.body, list) else []):
                        if isinstance(stmt, javalang.tree.TryStatement):
                            for catch in (stmt.catches or []):
                                block_str = str(catch.block if hasattr(catch, "block") else "")
                                if "TransactionAspectSupport" not in block_str and \
                                   "rollback" not in block_str.lower() and \
                                   "setRollbackOnly" not in block_str:
                                    l = catch.parameter.position.line if catch.parameter and catch.parameter.position else 0
                                    self._add(file_path, "ALIBABA_TRANSACTION_ROLLBACK",
                                              "事务场景中捕获异常后需要回滚事务，注意手动回滚或重新抛出",
                                              Severity.WARNING, line=l)

        # Open API should use error codes (not just exception)
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if any(a in ann_names for a in ("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping")):
                    body_str = str(getattr(node, "body", "") or "")
                    if re.search(r"throw new (RuntimeException|Exception)\(", body_str) and \
                       not re.search(r"Result|Response|ErrorCode|errorCode|error_code|ApiResult|ApiResponse", body_str):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_OPEN_API_ERRORCODE",
                                  "开放接口必须使用错误码，不推荐内部异常直接抛出",
                                  Severity.INFO, line=l, column=c)

        # 8. Exceptions not for flow control
        for i, line in enumerate(lines, 1):
            if re.search(r"try\s*\{", line) and \
               re.search(r"(if|while|for)\s*\(", lines[i] if i < len(lines) else ""):
                pass

        # 9. Exception used as flow control
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                body_stmts = node.block if hasattr(node, "block") and isinstance(node.block, list) else \
                            getattr(getattr(node, "block", None), "statements", []) or []
                if not body_stmts:
                    continue
                for s in body_stmts:
                    s_str = str(s)
                    if "return" in s_str and any(
                        kw in s_str for kw in ("null", "false", "-1", "0")
                    ):
                        for catch in (node.catches or []):
                            if catch.parameter and catch.parameter.types and \
                               any(t in ("Exception", "RuntimeException") for t in catch.parameter.types):
                                l = catch.parameter.position.line if catch.parameter.position else 0
                                self._add(file_path, "ALIBABA_EXCEPTION_FLOW",
                                          "异常捕获后不要用来做流程控制，不应通过异常控制业务分支",
                                          Severity.WARNING, line=l)
                                break

        # 10. Exception type matching
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                for catch in (node.catches or []):
                    cp = catch.parameter if hasattr(catch, "parameter") else None
                    if cp and hasattr(cp, "type") and cp.type:
                        caught_type = cp.type.name
                        caught_super = {"Exception": ("RuntimeException", "IOException", "SQLException"),
                                        "RuntimeException": ("IllegalArgumentException", "NullPointerException",
                                                             "IndexOutOfBoundsException", "IllegalStateException",
                                                             "UnsupportedOperationException")}
                        for stmt in (catch.block.statements if hasattr(catch.block, "statements") else []):
                            if isinstance(stmt, javalang.tree.ThrowStatement) and \
                               hasattr(stmt, "expression") and stmt.expression and \
                               hasattr(stmt.expression, "type") and stmt.expression.type:
                                thrown_type = stmt.expression.type.name
                                if thrown_type not in (caught_type, "Exception", "RuntimeException", "Throwable"):
                                    l = stmt.position.line if stmt.position else 0
                                    self._add(file_path, "ALIBABA_EXCEPTION_TYPE_MISMATCH",
                                              f"catch 捕获 '{caught_type}' 但抛出不兼容类型 '{thrown_type}'，应匹配或为父类",
                                              Severity.WARNING, line=l)

        # 11. Distinguish stable vs non-stable code in catch
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                if len(node.catches or []) == 1:
                    catch = node.catches[0]
                    if catch.parameter and catch.parameter.types and \
                       "Exception" in catch.parameter.types:
                        body_stmts = node.block if hasattr(node, "block") and isinstance(node.block, list) else \
                                    getattr(getattr(node, "block", None), "statements", []) or []
                        invocations = [s for s in body_stmts
                                       if isinstance(s, (javalang.tree.MethodInvocation,
                                                         javalang.tree.StatementExpression))]
                        if len(invocations) >= 3 and len(node.catches) == 1:
                            l = catch.parameter.position.line if catch.parameter.position else 0
                            self._add(file_path, "ALIBABA_CATCH_TYPE_DISTINGUISH",
                                      "catch 需分清稳定代码与非稳定代码，多个可能异常的方法建议分开 try-catch 处理",
                                      Severity.INFO, line=l)

        # 10. Return null with annotation check
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                has_null_return = False
                if node.body:
                    stmts = node.body if isinstance(node.body, list) else getattr(node.body, "statements", [])
                    for stmt in stmts:
                        if isinstance(stmt, javalang.tree.ReturnStatement) and \
                           hasattr(stmt, "expression") and \
                           str(stmt.expression) == "null":
                            has_null_return = True
                            break
                if has_null_return:
                    ret_type = getattr(node, "return_type", None)
                    if ret_type and hasattr(ret_type, "name") and \
                       ret_type.name not in ("void", "int", "long", "boolean", "double", "float", "char", "byte", "short"):
                        has_return_comment = False
                        ml = node.position.line if node.position else 0
                        for jj in range(max(0, ml - 3), ml):
                            if jj < len(lines) and re.search(r"@return.*null|returns.*null|null.*return", lines[jj], re.IGNORECASE):
                                has_return_comment = True
                                break
                        if not has_return_comment:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_NULL_RETURN",
                                      f"方法 '{node.name}' 可能返回 null，必须添加注释充分说明什么情况下会返回 null 值",
                                      Severity.INFO, line=l, column=c)

        # 5. Transaction catch without rollback
        for path, node in tree:
            if isinstance(node, javalang.tree.TryStatement):
                for catch in (node.catches or []):
                    block = catch.block if hasattr(catch, "block") and catch.block else getattr(catch, "body", None)
                    body_stmts = block.statements if hasattr(block, "statements") else (block if isinstance(block, list) else [])
                    has_rollback = any("rollback" in str(s).lower() for s in body_stmts)
                    if not has_rollback and len(body_stmts) > 0:
                        pass

        # 9. RPC/dynamic must catch Throwable
        for i, line in enumerate(lines, 1):
            if re.search(r"(RPC|rpc|反射|reflect|Proxy|\.invoke\s*\()", line) and \
               re.search(r"try\s*\{", line) and \
               not re.search(r"catch.*Throwable", line):
                for j in range(i, min(i + 15, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"catch\s*\(", lines[j - 1]):
                        if not re.search(r"Throwable", lines[j - 1]):
                            self._add(file_path, "ALIBABA_RPC_THROWABLE",
                                      "在调用 RPC、二方包、或动态生成类的相关方法时，捕捉异常使用 Throwable 类进行拦截",
                                      Severity.WARNING, line=i)
                        break

                        # 6. Exception not for flow control
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body:
                    if isinstance(stmt, javalang.tree.TryStatement):
                        catch_exprs = []
                        for catch in (stmt.catches or []):
                            if catch.parameter and catch.parameter.types:
                                catch_exprs.extend(catch.parameter.types)
                        if catch_exprs:
                            body_str = str(getattr(stmt, "body", "") or "")
                            for cn in catch_exprs:
                                if re.search(rf"catch\s*\(\s*{cn}\s+\w+\s*\).*\{{$", body_str):
                                    pass

        # 13. Exception must include scene info (not just message)
        for i, line in enumerate(lines, 1):
            if re.search(r"catch\s*\(", line):
                has_log = False
                has_msg = False
                for j in range(i, min(i + 10, len(lines) + 1)):
                    if j <= len(lines):
                        lj = lines[j - 1]
                        if re.search(r"log(ger)?\.(error|warn|info)", lj) and \
                           re.search(r"(参数|参数|场景|context|traceId|requestId|request|userId|用户|案发现场|e\.printStackTrace)",
                                     lj):
                            has_msg = True
                            break
                        if re.search(r"\{}\s*,\s*e|\{\}\s*,\s*\w+|e\.getMessage|log\.error\(\s*\"[^\"]*\"", lj):
                            has_log = True
                        if re.search(r"^\s*log(ger)?\.(error|warn)", lj):
                            has_log = True
                        if re.search(r"\be\b\)", lj) and re.search(r"(\"|\+|\{\})", lj):
                            has_msg = True
                            break
                        if re.search(r"}|\bthrow\b", lj):
                            break
                if has_log and not has_msg:
                    self._add(file_path, "ALIBABA_CATCH_SCENE_INFO",
                              "异常信息应包含案发现场信息和异常堆栈信息，缺少上下文参数",
                              Severity.INFO, line=i)
                # Also check log.error without exception object
                for j in range(i, min(i + 8, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"log(ger)?\.(error|warn)\(\s*\"[^\"]+\"\s*\)", lines[j - 1]):
                        self._add(file_path, "ALIBABA_CATCH_SCENE_INFO",
                                  "异常日志应传递异常对象作为参数，而非仅记录消息",
                                  Severity.INFO, line=j)
                        break
