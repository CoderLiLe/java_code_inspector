import re
from typing import List

import javalang

from java_inspector.alibaba_rules.base import BaseChecker


class EngineeringChecker(BaseChecker):
    def check_engineering(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_engineering"):
            return
        lines = content.split("\n")

        # 6.0.x Check pom.xml for SNAPSHOT dependencies
        if file_path.endswith("pom.xml"):
            for i, line in enumerate(lines, 1):
                if re.search(r"SNAPSHOT", line) and \
                   not re.search(r"<!--|-->|//", line) and \
                   not re.search(r"安全|security|safety", line, re.IGNORECASE):
                    self._add(file_path, "ALIBABA_SNAPSHOT_DEP",
                              "线上应用不要依赖 SNAPSHOT 版本（安全包除外）",
                              Severity.WARNING, line=i)

        # 6.0.x Check pom.xml for version variables
        if file_path.endswith("pom.xml"):
            has_properties = False
            has_dep_management = False
            for i, line in enumerate(lines, 1):
                if re.search(r"<properties>", line):
                    has_properties = True
                if re.search(r"<dependencyManagement>", line):
                    has_dep_management = True
            if not has_properties and not has_dep_management:
                for i, line in enumerate(lines, 1):
                    if re.search(r"<dependencies>", line) and \
                       not re.search(r"<dependencyManagement>", lines[max(0, i - 5)]):
                        self._add(file_path, "ALIBABA_POM_UNIFIED_VERSION",
                                  "依赖于一个二方库群时，必须定义一个统一的版本变量，避免版本号不一致",
                                  Severity.INFO, line=i)
                        break

        # 6.0.x Check pom.xml for version format
        if file_path.endswith("pom.xml"):
            for i, line in enumerate(lines, 1):
                if re.search(r"<version>", line) and \
                   not re.search(r"SNAPSHOT", line, re.IGNORECASE) and \
                   not re.search(r"<!--|-->", line):
                    m = re.search(r"<version>([^<]+)</version>", line)
                    if m:
                        ver = m.group(1)
                        if not re.search(r"^\d+\.\d+\.\d+", ver) and \
                           not re.search(r"^\$\{", ver):
                            self._add(file_path, "ALIBABA_VERSION_FORMAT",
                                      f"版本号 '{ver}' 不符合主版本号.次版本号.修订号格式",
                                      Severity.INFO, line=i)

        # 6.0.x POM: all deps in <dependencies>, versions in <dependencyManagement>
        if file_path.endswith("pom.xml"):
            in_dep_mgmt = False
            for i, line in enumerate(lines, 1):
                if re.search(r"<dependencyManagement>", line):
                    in_dep_mgmt = True
                elif re.search(r"</dependencyManagement>", line):
                    in_dep_mgmt = False
                if re.search(r"<version>[^$]", line) and \
                   not re.search(r"<version>\$\{", line) and \
                   not re.search(r"<!--|-->", line) and \
                   not in_dep_mgmt:
                    m = re.search(r"<version>([^<]+)</version>", line)
                    if m and not re.search(r"^\$\{", m.group(1)):
                        version_val = m.group(1)
                        if re.search(r"^\d+\.\d+\.\d+", version_val):
                            self._add(file_path, "ALIBABA_POM_DEP_VERSION",
                                      f"依赖版本 '{version_val}' 应通过 <dependencyManagement> 统一管理版本变量",
                                      Severity.INFO, line=i)

        # 6.1.1 Layer naming: Controller/Service/DAO/Manager naming
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("Controller") and not any(
                    isinstance(m, javalang.tree.MethodDeclaration) and m.name.startswith(("get", "list", "query", "find", "add", "create", "update", "delete", "remove", "save"))
                    for m in (node.body or [])
                ):
                    pass  # data controller without typical API methods
                if cn.endswith("ServiceImpl") and not cn.endswith("Impl"):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_IMPL_SUFFIX",
                              f"Service 实现类 '{cn}' 应以 Impl 结尾",
                              Severity.INFO, line=l, column=c)

        # 6.1.2 Layer exception handling: DAO->Service->Web
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("DAO") or cn.endswith("Mapper") or cn.endswith("Repository"):
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.MethodDeclaration):
                            body_stmts = member.body if isinstance(member.body, list) else getattr(getattr(member, "body", None), "statements", []) or []
                            for stmt in body_stmts:
                                if isinstance(stmt, javalang.tree.TryStatement):
                                    for catch in (stmt.catches or []):
                                        if catch.parameter and catch.parameter.types and \
                                           "Exception" in catch.parameter.types:
                                            l, c = self._pos(member)
                                            self._add(file_path, "ALIBABA_DAO_EXCEPTION",
                                                      f"DAO 层方法 '{member.name}' 应使用 catch(Exception e) 并 throw new DAOException(e)",
                                                      Severity.INFO, line=l, column=c)
                                            break
                                    break

        # 6.1.3 DO/DTO/BO/VO naming in proper packages
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith("DO") and "entity" not in file_path.lower() and "model" not in file_path.lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_DO_PACKAGE",
                              f"数据对象 '{cn}' 应放在 entity 或 model 包中",
                              Severity.INFO, line=l, column=c)
                elif cn.endswith("DTO") and "dto" not in file_path.lower() and "api" not in file_path.lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_DTO_PACKAGE",
                              f"数据传输对象 '{cn}' 应放在 dto 或 api 包中",
                              Severity.INFO, line=l, column=c)
                elif cn.endswith("VO") and "vo" not in file_path.lower() and "view" not in file_path.lower():
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_VO_PACKAGE",
                              f"展示对象 '{cn}' 应放在 vo 或 view 包中",
                              Severity.INFO, line=l, column=c)

        # 6.2.1 Remote call timeout
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.MethodDeclaration):
                        body_stmts = member.body if isinstance(member.body, list) else getattr(getattr(member, "body", None), "statements", []) or []
                        for stmt in body_stmts:
                            stmt_str = str(stmt)
                            if re.search(r"(rpc|dubbo|feign|restTemplate|webClient|httpClient|invoke)\w*\.\s*(invoke|execute|call|send|get|post|put|delete)\s*\(", stmt_str, re.IGNORECASE):
                                found_timeout = False
                                for line in lines[max(0, content.index(stmt_str[:30]) - 30):content.index(stmt_str[:30])]:
                                    if re.search(r"timeout", line, re.IGNORECASE):
                                        found_timeout = True
                                        break
                                if not found_timeout:
                                    l, c = self._pos(member)
                                    self._add(file_path, "ALIBABA_REMOTE_TIMEOUT",
                                              f"远程调用方法 '{member.name}' 必须设置超时时间",
                                              Severity.WARNING, line=l, column=c)
                                break

        # 6.4.1 Error code format
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if "ErrorCode" in cn or "ResultCode" in cn or "ResponseCode" in cn or cn.endswith("Code"):
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.FieldDeclaration):
                            for decl in member.declarators:
                                val = getattr(decl, "initializer", None)
                                if val is not None:
                                    val_str = str(val)
                                    if len(val_str) < 4 or len(val_str) > 8:
                                        l, c = self._pos(decl)
                                        self._add(file_path, "ALIBABA_ERROR_CODE_LEN",
                                                  f"错误码 '{decl.name}' 长度应统一为 5 或 6 位",
                                                  Severity.INFO, line=l, column=c)
                                    if val_str.isdigit() and not re.search(r"(PARAM|BIZ|SYS|DB)", decl.name):
                                        l, c = self._pos(decl)
                                        self._add(file_path, "ALIBABA_ERROR_CODE_CLASS",
                                                  f"错误码 '{decl.name}={val_str}' 需要按参数/业务/系统/DB 分类编号",
                                                  Severity.INFO, line=l, column=c)

        # 6.5.2 No interface using Map for params/result
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith(("Service", "Controller", "Manager", "Component")):
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.MethodDeclaration):
                            rt = getattr(member, "return_type", None)
                            if rt and hasattr(rt, "name") and rt.name in ("Map", "HashMap", "LinkedHashMap"):
                                l, c = self._pos(member)
                                self._add(file_path, "ALIBABA_INTERFACE_MAP_RESULT",
                                          f"接口方法 '{member.name}' 不能返回 Map，应使用 DTO",
                                          Severity.WARNING, line=l, column=c)
                            for param in (member.parameters or []):
                                pt = param.type
                                if pt and hasattr(pt, "name") and pt.name in ("Map", "HashMap"):
                                    l, c = self._pos(member)
                                    self._add(file_path, "ALIBABA_INTERFACE_MAP_PARAM",
                                              f"接口方法 '{member.name}' 不能接受 Map 参数，应使用 DTO",
                                              Severity.WARNING, line=l, column=c)

        # 6.5.4 No method longer than 80 lines
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body = getattr(node, "body", None)
                if isinstance(body, list) and len(body) > 80:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_METHOD_TOO_LONG",
                              f"方法 '{node.name}' 超过 80 行，应进行拆分",
                              Severity.WARNING, line=l, column=c)

        # 6.5.5 Query params >2 should not use Map
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                mn = node.name.lower()
                if any(mn.startswith(kw) for kw in ("query", "find", "search", "list", "select", "get")):
                    params = node.parameters or []
                    if len(params) > 2:
                        for param in params:
                            pt = getattr(param, "type", None)
                            if pt and hasattr(pt, "name") and pt.name in ("Map", "HashMap", "LinkedHashMap"):
                                l, c = self._pos(node)
                                self._add(file_path, "ALIBABA_QUERY_PARAM_MAP",
                                          f"查询方法 '{node.name}' 超过 2 个参数时禁止使用 Map 传输，应使用 DTO",
                                          Severity.WARNING, line=l, column=c)

        # 6.6.1 POJO must override toString
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith(("DO", "DTO", "VO", "BO", "PO", "Entity", "Model")):
                    has_to_string = False
                    for member in (node.body or []):
                        if isinstance(member, javalang.tree.MethodDeclaration) and member.name == "toString":
                            has_to_string = True
                            break
                    if not has_to_string:
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_POJO_TOSTRING",
                                  f"POJO 类 '{cn}' 应重写 toString 方法",
                                  Severity.INFO, line=l, column=c)

        # 6.7.4 @Service/@Component should use Spring annotation
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration):
                cn = node.name
                if cn.endswith(("ServiceImpl", "ManagerImpl")):
                    ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                    if not any(a in ann_names for a in ("Service", "Component", "Repository", "RestController", "Controller")):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_SPRING_ANNOTATION",
                                  f"类 '{cn}' 需要添加 Spring Bean 注解",
                                  Severity.INFO, line=l, column=c)
