import re
from typing import List

import javalang

from java_inspector.alibaba_rules.base import BaseChecker


class SqlChecker(BaseChecker):
    def check_sql(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_sql"):
            return
        lines = content.split("\n")

        # 5.1.1 is_xxx for boolean fields
        for i, line in enumerate(lines, 1):
            if re.search(r"is[A-Z]", line) and \
               re.search(r"tinyint|Integer", line, re.IGNORECASE) and \
               re.search(r"columnDefinition|@Column|@TableField", line):
                self._add(file_path, "ALIBABA_SQL_IS_PREFIX",
                          "表达是与否概念的字段，必须使用 is_xxx 的方式命名，数据类型是 unsigned tinyint",
                          Severity.WARNING, line=i)

        # 5.1.2 lowercase table/field names
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(m.endswith("DO") or m.endswith("PO") or node.name.endswith(("DO", "PO")) for m in [node.name]):
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            fn = decl.name
                            if fn != fn.lower() and not fn.startswith("serialVersionUID"):
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_SQL_FIELD_CASE",
                                          f"字段名 '{fn}' 必须使用小写字母或数字",
                                          Severity.WARNING, line=l, column=c)

        # 5.1.8 varchar length check
        # 5.1.7 char type for fixed-length strings
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name == "String":
                    ann_str = str([str(getattr(a, "name", "")) + str(getattr(a, "element", ""))
                                   for a in (node.annotations or [])])
                    if "Column" in ann_str or "TableField" in ann_str:
                        m = re.search(r'columnDefinition\s*=\s*"([^"]+)"', ann_str)
                        if m:
                            col_def = m.group(1).lower()
                            if "varchar" in col_def:
                                len_m = re.search(r'varchar\s*\(\s*(\d+)\s*\)', col_def)
                                if len_m:
                                    length = int(len_m.group(1))
                                    # 5.1.7: use char for fixed-length strings
                                    if length in (1, 2, 3, 4, 6, 8, 11, 16, 18, 32) and \
                                       "char" not in col_def:
                                        for decl in node.declarators:
                                            l, c = self._pos(decl)
                                            self._add(file_path, "ALIBABA_CHAR_TYPE",
                                                      f"固定长度短字段 '{decl.name}'（长度 {length}）建议使用 char 定长字符串类型",
                                                      Severity.INFO, line=l, column=c)
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name in ("String", "VARCHAR", "varchar"):
                    ann_str = str([str(getattr(a, "name", "")) + str(getattr(a, "element", ""))
                                   for a in (node.annotations or [])])
                    if "Column" in ann_str or "TableField" in ann_str:
                        m = re.search(r'length\s*=\s*(\d+)', ann_str)
                        if m:
                            length = int(m.group(1))
                            if length > 5000:
                                for decl in node.declarators:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_VARCHAR_LENGTH",
                                              f"varchar 长度建议不超过 5000（当前 {length}），超过应使用 text 类型",
                                              Severity.INFO, line=l, column=c)

        # 5.1.9a Table naming: business_name_role
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               (node.name.endswith("DO") or node.name.endswith("PO")):
                cn = node.name.replace("DO", "").replace("PO", "")
                if not re.search(r"_", cn) and not re.search(r"[A-Z]", cn[1:] if len(cn) > 1 else ""):
                    pass  # "UserDO" is fine
                if re.search(r"^[A-Z][a-z]+$", cn) and len(cn) <= 3:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_TABLE_NAMING",
                              f"类 '{node.name}' 对应的表名建议遵循 '业务名称_表的作用' 的命名方式",
                              Severity.INFO, line=l, column=c)

        # 5.1.9 Required fields: id, create_time, update_time
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               (node.name.endswith("DO") or node.name.endswith("PO")):
                fields = set()
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            fields.add(decl.name)
                missing = []
                for f in ("id", "createTime", "updateTime"):
                    if f not in fields:
                        missing.append(f)
                if missing:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_SQL_REQUIRED_FIELDS",
                              f"表必备三字段 '{', '.join(missing)}' 缺失",
                              Severity.WARNING, line=l, column=c)

        # 5.3.1 Use count(*)
        for i, line in enumerate(lines, 1):
            if re.search(r"count\(\s*\w+\.\w+\s*\)", line) and \
               not re.search(r"count\s*\(\s*\*\s*\)", line) and \
               not re.search(r"distinct", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_COUNT_STAR",
                          "不要使用 count(列名) 替代 count(*)，count(*) 是 SQL92 定义的标准统计行数的语法",
                          Severity.WARNING, line=i)

            if re.search(r"count\(\s*\w+\.\w+\s*\)", line) and \
               not re.search(r"count\s*\(\s*\*\s*\)", line):
                self._add(file_path, "ALIBABA_COUNT_COL_NPE",
                          "count(col) 如果该列值全为 NULL 则返回 0，但 sum(col) 返回 NULL，使用 sum() 时需注意 NPE",
                          Severity.INFO, line=i)

            if re.search(r"\.delete\s*\(", line) and \
               not re.search(r"//.*delete", line) and \
               not re.search(r"(deleted\s*=\s*1|is_deleted\s*=\s*1|setDeleted\s*\(true)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_PHYSICAL_DELETE",
                          "在数据库中不能使用物理删除操作，要使用逻辑删除",
                          Severity.WARNING, line=i)

        # 5.3.5 count=0 return directly
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               "Page" in str(getattr(node, "return_type", "")):
                body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                has_count_zero = any(
                    isinstance(s, javalang.tree.IfStatement) and "count" in str(s.expression) and "0" in str(s.expression)
                    for s in body_stmts if isinstance(s, javalang.tree.IfStatement)
                )
                if not has_count_zero:
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_PAGE_COUNT_ZERO",
                              "代码中写分页查询逻辑时，若 count 为 0 应直接返回，避免执行后面的分页语句",
                              Severity.INFO, line=l, column=c)

        # 5.4.1 No * in query
        for i, line in enumerate(lines, 1):
            if re.search(r"SELECT\s+\*\s+FROM", line, re.IGNORECASE) and \
               not re.search(r"//.*SELECT|SELECT\s+\w+\.\*", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_SELECT_STAR",
                          "在表查询中，一律不要使用 * 作为查询的字段列表，需要哪些字段必须明确写明",
                          Severity.WARNING, line=i)

        # 5.3.4 Use ISNULL() for null check
        for i, line in enumerate(lines, 1):
            if re.search(r"WHERE\s+.*\b(IS\s+NULL|ISNULL)\b", line, re.IGNORECASE) and \
               not re.search(r"ISNULL\s*\(", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_USE_ISNULL",
                          "使用 ISNULL() 来判断是否为 NULL 值",
                          Severity.INFO, line=i)

            if re.search(r"= null|is null", line, re.IGNORECASE) and \
               re.search(r"WHERE", line, re.IGNORECASE) and \
               not re.search(r"ISNULL", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_USE_ISNULL",
                          "使用 ISNULL() 来判断是否为 NULL 值，而非 = null",
                          Severity.INFO, line=i)

        # 5.3.7 No stored procedures
        for i, line in enumerate(lines, 1):
            if re.search(r"call\s+\w+Proc|createProcedure|create\s+procedure", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_NO_STORED_PROC",
                          "禁止使用存储过程，存储过程难以调试和扩展，更没有移植性",
                          Severity.WARNING, line=i)

        # 5.3.9 Multi-table query must have alias
        for i, line in enumerate(lines, 1):
            if re.search(r"(FROM|JOIN)\s+\w+\s+\w+.*(WHERE|AND|ON)\s+\w+\.\w+", line, re.IGNORECASE) and \
               re.search(r"SELECT", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                m = re.search(r"FROM\s+(\w+)\s+(\w+)", line, re.IGNORECASE)
                if m and m.group(2) == m.group(2).lower() and len(m.group(2)) > 8:
                    self._add(file_path, "ALIBABA_TABLE_ALIAS",
                              "多表关联查询时，需要在列名前加表的别名进行限定",
                              Severity.INFO, line=i)

        # 5.3.10 Alias with 'as'
        for i, line in enumerate(lines, 1):
            if re.search(r"(FROM|JOIN)\s+(\w+)\s+(\w{2,4})\s", line, re.IGNORECASE) and \
               not re.search(r"\s+as\s+", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               not re.search(r"\(\s*SELECT", line, re.IGNORECASE):
                m = re.search(r"(?:FROM|JOIN)\s+(\w+)\s+(\w{2,4})\s", line, re.IGNORECASE)
                if m and m.group(1).lower() != m.group(2).lower() and \
                   not re.search(r"^\d", m.group(2)):
                    self._add(file_path, "ALIBABA_ALIAS_AS",
                              f"SQL 语句中表别名前推荐加 as，如 '{m.group(1)} as {m.group(2)}'",
                              Severity.INFO, line=i)

        # 5.3.11 IN control within 1000
        for i, line in enumerate(lines, 1):
            m = re.search(r"\bIN\s*\(([^)]{50,})\)", line, re.IGNORECASE)
            if m and not re.search(r"//", line):
                in_content = m.group(1)
                comma_count = in_content.count(",")
                if comma_count > 50:
                    self._add(file_path, "ALIBABA_IN_SIZE",
                              "in 操作集合元素数量控制在 1000 个之内",
                              Severity.WARNING, line=i)

        # 5.3.x count == 0 return directly
        for i, line in enumerate(lines, 1):
            if re.search(r"count\s*\(\s*\*\s*\)", line, re.IGNORECASE) and \
               not re.search(r"if|if\s*.*count|count.*>.*0|count.*==.*0", lines[max(0, i - 5):i + 3]) and \
               not re.search(r"//", line):
                for j in range(min(i, len(lines)), min(i + 5, len(lines))):
                    if re.search(r"if\s*.*count", lines[j - 1], re.IGNORECASE):
                        break
                else:
                    pass  # too noisy to warn

        # 5.3.x Implicit conversion detection
        for i, line in enumerate(lines, 1):
            if re.search(r"WHERE\s+.*=.*\"\d+", line, re.IGNORECASE) or \
               re.search(r"WHERE\s+.*\"\d+\".*=", line, re.IGNORECASE) or \
               re.search(r"WHERE\s+.*\w+\s*=\s*\w+", line, re.IGNORECASE):
                m = re.search(r"(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)", line, re.IGNORECASE)
                if m and m.group(2) != m.group(4):
                    self._add(file_path, "ALIBABA_IMPLICIT_CONVERSION",
                              "防止因字段类型不同造成的隐式转换，导致索引失效",
                              Severity.WARNING, line=i)

        # 5.3.13 TRUNCATE not recommended
        for i, line in enumerate(lines, 1):
            if re.search(r"\bTRUNCATE\s+TABLE", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_TRUNCATE_USAGE",
                          "TRUNCATE TABLE 无事务且不触发 trigger，不建议在开发代码中使用此语句",
                          Severity.WARNING, line=i)

        # 5.3.12 Pagination must have ORDER BY
        for i, line in enumerate(lines, 1):
            if re.search(r"\bLIMIT\s+\d+", line, re.IGNORECASE) and \
               not re.search(r"ORDER\s+BY", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               re.search(r"SELECT", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_PAGE_ORDER_BY",
                          "分页查询必须指定 ORDER BY 以保证结果稳定",
                          Severity.WARNING, line=i)

        # 5.3.x utf8mb4 character set check
        for i, line in enumerate(lines, 1):
            if re.search(r"charset|characterSet|character_set", line, re.IGNORECASE) and \
               re.search(r"utf8|utf-8", line, re.IGNORECASE) and \
               not re.search(r"utf8mb4", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               not re.search(r"<!--|-->", line):
                self._add(file_path, "ALIBABA_UTF8MB4",
                          "所有的字符存储与表示，均采用 utf8mb4 字符集（而非 utf8），避免 emoji 等字符无法存储",
                          Severity.INFO, line=i)

        # 5.4.1 Try to avoid count on large tables without index
        for i, line in enumerate(lines, 1):
            if re.search(r"select\s+count\s*\(.*\)\s+from", line, re.IGNORECASE) and \
               not re.search(r"where|WHERE", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_COUNT_NO_WHERE",
                          "COUNT 全表扫描且无 WHERE 条件可能性能低下，需确认是否添加索引",
                          Severity.INFO, line=i)

        # 5.4.2 POJO boolean mapping in resultMap
        for i, line in enumerate(lines, 1):
            if re.search(r"<result\s+.*property\s*=\s*\"\w+\".*column\s*=\s*\"is_\w+\"", line) and \
               not re.search(r"//", line):
                pass

        # 5.4.3 Must define <resultMap>
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "DTO", "VO")):
                l, c = self._pos(node)
                self._add(file_path, "ALIBABA_RESULT_MAP",
                          f"POJO 类 '{node.name}' 需要定义对应的 <resultMap> 进行字段与属性之间的映射",
                          Severity.INFO, line=l, column=c)

        # 5.4.4 Use #{} not ${}
        for i, line in enumerate(lines, 1):
            if re.search(r"\$\{", line) and \
               re.search(r"\.xml|\.sql|@Select|@Insert|@Update|@Delete", file_path):
                m = re.search(r"\$\{(\w+)\}", line)
                if m and not re.search(r"order\s+by|ORDER\s+BY|sort|Sort|column|Column", line, re.IGNORECASE):
                    self._add(file_path, "ALIBABA_SQL_PARAM_BINDING",
                              f"sql.xml 配置参数使用 #{{}} 而非 ${{}}, 防止 SQL 注入: ${{{m.group(1)}}}",
                              Severity.WARNING, line=i)

        # 5.4.5 queryForList(start,size) not recommended
        for i, line in enumerate(lines, 1):
            if re.search(r"queryForList\s*\(\s*\"[^\"]*\"\s*,\s*\d+\s*,\s*\d+\s*\)", line):
                self._add(file_path, "ALIBABA_QUERY_FOR_LIST",
                          "iBATIS 自带的 queryForList(String, int, int) 不推荐使用",
                          Severity.WARNING, line=i)

        # 5.4.6 HashMap/Hashtable as result
        for i, line in enumerate(lines, 1):
            if re.search(r"(HashMap|Hashtable)\s*<\s*\w+\s*,\s*\w+\s*>\s+\w+\s*(;|=)", line) and \
               re.search(r"query|select|find|get", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_HASHMAP_RESULT",
                          "不允许直接拿 HashMap 与 Hashtable 作为查询结果集的输出",
                          Severity.WARNING, line=i)

        # 5.4.7 Update update_time
        for i, line in enumerate(lines, 1):
            if re.search(r"UPDATE\s+\w+\s+SET", line, re.IGNORECASE) and \
               not re.search(r"update_time|updateTime|update_at", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_UPDATE_TIME",
                          "更新数据表记录时，必须同时更新记录对应的 update_time 字段值为当前时间",
                          Severity.INFO, line=i)

        # 5.1.3 Table name: no plural nouns
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                cn = node.name
                for suffix in ("sDO", "sPO", "sEntity", "ListDO", "ListPO", "SetDO"):
                    if cn.endswith(suffix):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_TABLE_PLURAL",
                                  f"表名（类 '{cn}'）不使用复数名词",
                                  Severity.WARNING, line=l, column=c)
                        break

        # 5.1.4 Reserved words
        MYSQL_RESERVED_WORDS = [
            "desc", "range", "match", "delayed", "order", "group", "select", "insert",
            "update", "delete", "from", "where", "having", "between", "like", "and", "or",
            "in", "not", "is", "null", "key", "index", "primary", "foreign", "default",
            "check", "begin", "commit", "rollback", "savepoint", "grant", "revoke",
            "call", "procedure", "function", "trigger", "cursor", "escape", "exists"
        ]
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                for field in (node.body or []):
                    if isinstance(field, javalang.tree.FieldDeclaration):
                        for decl in field.declarators:
                            if decl.name.lower() in MYSQL_RESERVED_WORDS:
                                l, c = self._pos(decl)
                                self._add(file_path, "ALIBABA_RESERVED_WORD",
                                          f"字段名 '{decl.name}' 是 MySQL 保留字，请避免使用",
                                          Severity.WARNING, line=l, column=c)

        # 5.1.6 Use decimal for money, not float/double
        # 5.1.5 Index naming: pk_, uk_, idx_
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        ann_str = str([getattr(a, "name", "") for a in (member.annotations or [])])
                        decl_str = str([d.name for d in member.declarators])
                        for i, line in enumerate(lines, 1):
                            if re.search(r"@Index|@TableIndex|uniqueIndex|index.*=", line) and \
                               not re.search(r"idx_\w+|uk_\w+|pk_\w+", line) and \
                               not re.search(r"//", line):
                                self._add(file_path, "ALIBABA_INDEX_NAMING",
                                          "主键索引用 pk_，唯一索引用 uk_，普通索引用 idx_ 前缀",
                                          Severity.INFO, line=i)

        # 5.1.6 Use decimal for money, not float/double
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name in ("float", "double") and \
                   "static" not in (node.modifiers or []) and "final" not in (node.modifiers or []):
                    for decl in node.declarators:
                        fn = decl.name.lower()
                        if any(kw in fn for kw in ("price", "amount", "money", "salary", "cost", "fee", "payment", "total", "sum", "balance")):
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_DECIMAL_TYPE",
                                      "小数类型为 decimal，禁止使用 float 和 double 表示金额",
                                      Severity.WARNING, line=l, column=c)

        # 5.2.1 Unique index on logically unique fields
        for path, node in tree:
            if isinstance(node, javalang.tree.ClassDeclaration) and \
               any(node.name.endswith(s) for s in ("DO", "PO", "Entity")):
                fields = []
                has_unique = False
                for member in (node.body or []):
                    if isinstance(member, javalang.tree.FieldDeclaration):
                        for ann in (member.annotations or []):
                            if hasattr(ann, "name") and ann.name in ("Column", "Table", "TableField"):
                                if "unique" in str(ann).lower() or "UniqueConstraint" in str(ann).lower():
                                    has_unique = True
                        for decl in member.declarators:
                            fn = decl.name.lower()
                            if fn in ("name", "email", "phone", "mobile", "order_no", "orderNo", "trade_no", "tradeNo",
                                      "id_card", "idCard", "serial_no", "serialNo", "code", "username"):
                                if not has_unique:
                                    l, c = self._pos(decl)
                                    self._add(file_path, "ALIBABA_UNIQUE_INDEX",
                                              f"字段 '{decl.name}' 业务上具有唯一特性，必须建成唯一索引",
                                              Severity.WARNING, line=l, column=c)
                                    break
                    if has_unique:
                        break

        # 5.2.4 No left-fuzzy LIKE
        for i, line in enumerate(lines, 1):
            if re.search(r"LIKE\s+['\"]%\w+%['\"]", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_LEFT_FUZZY",
                          "页面搜索严禁左模糊或者全模糊，需要请走搜索引擎来解决",
                          Severity.WARNING, line=i)

        # 5.2.5 Varchar index must specify length
        for i, line in enumerate(lines, 1):
            if re.search(r"@Column|@TableField|columnDefinition", line) and \
               re.search(r"varchar", line, re.IGNORECASE) and \
               re.search(r"unique|index", line, re.IGNORECASE) and \
               not re.search(r"length\s*=", line) and \
               not re.search(r"//", line):
                m = re.search(r'@(Column|TableField)\s*\(\s*.*name\s*=\s*"(\w+)"', line)
                if m:
                    self._add(file_path, "ALIBABA_VARCHAR_INDEX_LENGTH",
                              f"varchar 字段 '{m.group(2)}' 建立索引时未指定索引长度",
                              Severity.WARNING, line=i)

        # 5.3.9 Covering index to avoid back-to-table
        for i, line in enumerate(lines, 1):
            if re.search(r"SELECT\s+\w+.*FROM", line, re.IGNORECASE) and \
               re.search(r"WHERE", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                if re.search(r"ORDER\s+BY", line, re.IGNORECASE) and \
                   not re.search(r"SELECT.*FROM.*WHERE", line, re.IGNORECASE):
                    pass  # too broad for AST-based detection
                m_select = re.search(r"SELECT\s+(.+?)\s+FROM", line, re.IGNORECASE)
                m_where_col = re.search(r"WHERE\s+(\w+\.\w+)", line, re.IGNORECASE)
                if m_select and m_where_col:
                    select_cols = m_select.group(1)
                    where_col = m_where_col.group(1).split(".")[-1]
                    if select_cols.strip() != "*" and \
                       where_col not in select_cols:
                        self._add(file_path, "ALIBABA_COVERING_INDEX",
                                  "考虑利用覆盖索引进行查询，避免回表查询",
                                  Severity.INFO, line=i)

        # 5.3.10 Composite index: highest cardinality first
        for i, line in enumerate(lines, 1):
            if re.search(r"@Table\(.*indexes", line, re.IGNORECASE) or \
               re.search(r"@Index", line):
                if re.search(r"columnList\s*=\s*\"\w+,\w+", line):
                    m = re.search(r"columnList\s*=\s*\"(.+?)\"", line)
                    if m:
                        cols = [c.strip() for c in m.group(1).split(",")]
                        if len(cols) >= 2:
                            self._add(file_path, "ALIBABA_COMPOSITE_INDEX",
                                      f"组合索引 '{','.join(cols)}' 应将区分度最高的列放在最左边",
                                      Severity.INFO, line=i)

        # 5.3.6 No foreign keys
        for i, line in enumerate(lines, 1):
            if re.search(r"@JoinColumn.*foreignKey|@OnDelete|foreignKey\s*=|@ForeignKey", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_NO_FOREIGN_KEY",
                          "不得使用外键与级联，一切外键概念必须在应用层解决",
                          Severity.WARNING, line=i)

        # 5.3.7 No more than 3 table join
        for i, line in enumerate(lines, 1):
            if re.search(r"JOIN\s+\w+.*JOIN\s+\w+.*JOIN\s+\w+.*JOIN\s+\w+", line, re.IGNORECASE) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_JOIN_LIMIT",
                          "超过三个表禁止 join，需要 join 的字段数据类型必须保持一致",
                          Severity.WARNING, line=i)

        # 5.3.8 SELECT before DELETE/UPDATE
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(DELETE|UPDATE)\b.*\b(WHERE|SET)\b", line, re.IGNORECASE) and \
               not re.search(r"//", line) and \
               not re.search(r"@.*Annotation|\.delete\(", line):
                has_preceding_select = False
                for j in range(max(0, i - 10), i):
                    if j < len(lines) and re.search(r"SELECT\b.*\bFROM\b", lines[j], re.IGNORECASE) and \
                       re.search(re.escape(line.strip()[:20]), lines[j]):
                        has_preceding_select = True
                        break
                if not has_preceding_select:
                    self._add(file_path, "ALIBABA_SELECT_BEFORE_DML",
                              "数据订正（删除/修改记录操作）时，先 SELECT 确认无误再执行",
                              Severity.INFO, line=i)

        # 5.4.8 No big update-all-fields
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                body_stmts = node.body if isinstance(node.body, list) else getattr(getattr(node, "body", None), "statements", []) or []
                if node.name.startswith("update") and len(body_stmts) == 1:
                    for stmt in body_stmts:
                        stmt_str = str(stmt)
                        if "set" in stmt_str.lower() and stmt_str.count(",") > 3:
                            l, c = self._pos(node)
                            self._add(file_path, "ALIBABA_UPDATE_ALL_FIELDS",
                                      "不要写大而全的数据更新接口，只更新目标字段而非所有字段",
                                      Severity.INFO, line=l, column=c)

        # 5.4.9 @Transactional not on read-only methods
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration):
                ann_names = [getattr(a, "name", "") for a in (node.annotations or [])]
                if "Transactional" in ann_names:
                    mn = node.name.lower()
                    if mn.startswith(("get", "find", "query", "select", "list", "count", "search", "read")):
                        l, c = self._pos(node)
                        self._add(file_path, "ALIBABA_TRANSACTIONAL_READONLY",
                                  "@Transactional 不要滥用，只读方法不需要事务，考虑回滚方案",
                                  Severity.INFO, line=l, column=c)
