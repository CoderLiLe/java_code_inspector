# Alibaba Java Coding Guidelines — 规则总表

共 **168** 条规则，覆盖《Java开发手册(黄山版)》全部 19 个章节。

## 命名风格 (6 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_DOLLAR_NAME` | 所有编程相关的命名均不能以美元符号开始或结束 | 🟡 WARNING |
| `ALIBABA_UNDERSCORE_NAME` | 命名不能以下划线开始或结束 | 🟡 WARNING |
| `ALIBABA_NO_CHINESE` | 命名中禁止使用中文或拼音 | 🟡 WARNING |
| `ALIBABA_NO_INSULT` | 避免使用侮辱性词语 | 🟡 WARNING |
| `ALIBABA_ARRAY_STYLE` | 类型与中括号应紧挨相连来定义数组，如 int[] arrayDemo | 🟡 WARNING |
| `ALIBABA_INTERFACE_MODIFIER` | 接口中的方法和属性不要加任何修饰符号（public 也不要加） | 🟡 WARNING |

## 代码风格 (11 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_NO_TAB` | 禁止使用 Tab 字符缩进，请使用 4 个空格 | 🟡 WARNING |
| `ALIBABA_NO_TABS` | 代码换行缩进禁止使用 Tab，请使用空格代替 | 🔵 INFO |
| `ALIBABA_LINE_LENGTH` | 单行字符数限制不超过 120 个，超出需要换行 | 🔵 INFO |
| `ALIBABA_LINE_ENDING` | 文件中使用了 Windows 格式换行符（CRLF），应使用 Unix 格式（LF） | 🔵 INFO |
| `ALIBABA_TOO_MANY_BLANKS` | 代码中不应出现连续超过 2 个空行 | 🔵 INFO |
| `ALIBABA_COMMA_SPACING` | 逗号后必须加空格 | 🔵 INFO |
| `ALIBABA_CAST_SPACING` | 强制转换的右括号后不加空格 | 🔵 INFO |
| `ALIBABA_RPAREN_SPACING` | 右括号 ')' 后面应加空格 | 🔵 INFO |
| `ALIBABA_EMPTY_CATCH_BRACE` | 大括号内为空时应简洁地写成 {} | 🔵 INFO |
| `ALIBABA_COMMENT_SPACE` | 注释的双斜线与注释内容之间应有且仅有一个空格 | 🔵 INFO |
| `ALIBABA_COMMENT_SPACING` | // 注释的 // 后应紧跟一个空格 | 🔵 INFO |

## 面向对象 (16 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_VARARGS_LAST` | 可变参数必须放置在参数列表的最后 | 🟡 WARNING |
| `ALIBABA_VARARGS_OBJECT` | 可变参数类型避免定义为 Object，应指定具体类型 | 🟡 WARNING |
| `ALIBABA_INTEGER_COMPARE` | 整型包装类对象之间值的比较，全部使用 equals 方法比较 | 🟡 WARNING |
| `ALIBABA_WRAPPER_EQUALS` | 包装类对象之间值的比较应使用 equals 方法而非 '==' | 🟡 WARNING |
| `ALIBABA_FLOAT_COMPARE` | 浮点等值判断，基本类型不能用 ==，包装类型不能用 equals | 🟡 WARNING |
| `ALIBABA_BIGDECIMAL_EQUALS` | BigDecimal 的等值比较应使用 compareTo()，而不是 equals() | 🟡 WARNING |
| `ALIBABA_BIGDECIMAL_DOUBLE` | 禁止使用 BigDecimal(double) 构造方法 | 🟡 WARNING |
| `ALIBABA_MONEY_TYPE` | 货币金额以最小货币单位整型存储，建议 Long 或 int | 🟡 WARNING |
| `ALIBABA_CONSTRUCTOR_LOGIC` | 构造方法中禁止加入业务逻辑 | 🟡 WARNING |
| `ALIBABA_CLONE_USAGE` | 慎用 Object 的 clone 方法，默认浅拷贝 | 🔵 INFO |
| `ALIBABA_CTOR_GROUPING` | 多个构造方法应顺序放置在一起 | 🔵 INFO |
| `ALIBABA_SPLIT_RESULT` | split 结果数组需做最后一个元素检查 | 🔵 INFO |
| `ALIBABA_STRING_BUILDER` | 循环体内字符串连接使用 StringBuilder | 🔵 INFO |
| `ALIBABA_STRING_CONCAT_LOOP` | 循环体内字符串连接使用 StringBuilder 的 append 方法 | 🟡 WARNING |
| `ALIBABA_TOSTRING_CATCH` | 异常后使用日志框架而非 toString | 🔵 INFO |
| `ALIBABA_MULTIPLE_INSTANCEOF` | 多个 instanceof 使用多态重构 | 🔵 INFO |

## 日期时间 (7 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_DATE_FORMAT_YEAR` | 年份用小写 yyyy，大写 YYYY 表示 week year | 🟡 WARNING |
| `ALIBABA_DATE_FORMAT_CASE` | 月份大写 M，分钟小写 m，请勿混淆 | 🟡 WARNING |
| `ALIBABA_CURRENT_TIME_MILLIS` | 使用 System.currentTimeMillis() 而非 new Date().getTime() | 🔵 INFO |
| `ALIBABA_HARDCODED_365` | 禁止写死一年为 365 天，使用 LocalDate.lengthOfYear() | 🟡 WARNING |
| `ALIBABA_MONTH_ENUM` | 使用枚举值指代月份 | 🔵 INFO |
| `ALIBABA_CALENDAR_MAGIC` | Calendar 获取值使用常量而非数字 | 🔵 INFO |
| `ALIBABA_TIME_ZONE` | 序列化日期时指定 timezone 参数 | 🔵 INFO |

## 集合处理 (20 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_HASHCODE_EQUALS` | 覆写 equals 时必须同时覆写 hashCode | 🟡 WARNING |
| `ALIBABA_TO_MAP_MERGE` | Collectors.toMap() 需传 mergeFunction | 🟡 WARNING |
| `ALIBABA_TO_MAP_NULL_VALUE` | toMap() 时 value 为 null 会抛 NPE | 🟡 WARNING |
| `ALIBABA_IS_EMPTY` | 使用 isEmpty() 而非 size() == 0 | 🔵 INFO |
| `ALIBABA_FOREACH_REMOVE` | foreach 中禁止 remove 元素 | 🟡 WARNING |
| `ALIBABA_TO_ARRAY` | toArray(T[]) 传入类型一致的空数组 | 🟡 WARNING |
| `ALIBABA_INIT_CAPACITY` | 集合初始化指定初始值大小 | 🔵 INFO |
| `ALIBABA_ASLIST_MODIFY` | Arrays.asList() 返回不可变列表，不能 add/remove | 🟡 WARNING |
| `ALIBABA_IMMUTABLE_COLLECTION` | emptyList()/singletonList() 不可修改 | 🟡 WARNING |
| `ALIBABA_DIAMOND_OP` | 使用菱形语法 <> | 🔵 INFO |
| `ALIBABA_SUBLIST_ARRAYLIST` | subList 不可强转 ArrayList | 🔵 INFO |
| `ALIBABA_SUBLIST_MODIFY` | 修改父集合导致子列表异常 | 🟡 WARNING |
| `ALIBABA_VIEW_ADD` | keySet/values/entrySet 不可添加元素 | 🟡 WARNING |
| `ALIBABA_MAP_NULL_VALUE` | Map value 不应存储 null | 🟡 WARNING |
| `ALIBABA_ADDALL_NPE` | addAll 前对参数进行 NPE 判断 | 🔵 INFO |
| `ALIBABA_WILDCARD_EXTENDS` | <? extends T> 集合不能用 add | 🔵 INFO |
| `ALIBABA_RAW_TYPE` | 无泛型集合赋值给泛型集合需 instanceof 判断 | 🔵 INFO |
| `ALIBABA_KEYSET_LOOP` | 遍历 Map 使用 entrySet 而非 keySet | 🔵 INFO |
| `ALIBABA_LIST_CONTAINS` | 去重用 Set，避免 List.contains() | 🔵 INFO |
| `ALIBABA_COMPARATOR_CONDITIONS` | Comparator 需满足自反性/传递性/对称性 | 🟡 WARNING |

## 控制语句 (12 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_REQUIRE_BRACES` | if/else/for/while/do 必须使用大括号 | 🟡 WARNING |
| `ALIBABA_SWITCH_DEFAULT` | switch 必须包含 default 语句 | 🟡 WARNING |
| `ALIBABA_SWITCH_BREAK` | 每个 case 必须用 break/return 终止 | 🟡 WARNING |
| `ALIBABA_SWITCH_STRING` | String 类型 switch 需先 null 判断 | 🔵 INFO |
| `ALIBABA_TERNARY_NPE` | 三目运算符注意自动拆箱 NPE | 🔵 INFO |
| `ALIBABA_ASSIGN_IN_CONDITION` | 条件表达式中禁止插入赋值语句 | 🟡 WARNING |
| `ALIBABA_COMPLEX_CONDITION` | 复杂条件赋值给有意义的布尔变量 | 🔵 INFO |
| `ALIBABA_IF_DEPTH` | if-else 超过 3 层使用卫语句/策略模式 | 🔵 INFO |
| `ALIBABA_AVOID_NOT` | 避免取反逻辑运算符 | 🔵 INFO |
| `ALIBABA_LOOP_OBJECT_CREATION` | 循环中对象定义移至循环体外 | 🔵 INFO |
| `ALIBABA_PARAM_VALIDATION` | 公开接口需要入参保护 | 🔵 INFO |
| `ALIBABA_RETURN_BLANK_LINE` | return/throw 右大括号后加空行 | 🔵 INFO |

## 并发处理 (20 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_NEW_THREAD` | 线程创建应使用线程池 | 🟡 WARNING |
| `ALIBABA_EXECUTORS_POOL` | 应使用 ThreadPoolExecutor 而非 Executors | 🟡 WARNING |
| `ALIBABA_CUSTOM_THREAD_POOL` | 线程池不允许使用 Executors 创建 | 🟡 WARNING |
| `ALIBABA_THREAD_NAME` | 创建线程/线程池时指定有意义名称 | 🔵 INFO |
| `ALIBABA_NAMED_THREAD` | 创建线程/线程池时指定有意义名称 | 🔵 INFO |
| `ALIBABA_THREAD_FACTORY` | 创建线程池必须指定 ThreadFactory | 🔵 INFO |
| `ALIBABA_SIMPLE_DATE_FORMAT` | SimpleDateFormat 线程不安全 | 🟡 WARNING |
| `ALIBABA_THREADLOCAL_STATIC` | ThreadLocal 对象使用 static | 🟡 WARNING |
| `ALIBABA_THREADLOCAL_CLEANUP` | ThreadLocal 变量在 finally 中 remove() | 🟡 WARNING |
| `ALIBABA_LOCK_IN_TRY` | lock() 必须在 try 前，finally 中 unlock() | 🟡 WARNING |
| `ALIBABA_TRYLOCK_CHECK` | tryLock() 后必须检查返回值 | 🟡 WARNING |
| `ALIBABA_MULTIPLE_LOCKS` | 多资源加锁需保持一致顺序 | 🟡 WARNING |
| `ALIBABA_CONCURRENT_UPDATE` | 并发修改需加锁避免更新丢失 | 🟡 WARNING |
| `ALIBABA_TIMER_TASK` | 使用 ScheduledExecutorService 替代 Timer | 🟡 WARNING |
| `ALIBABA_COUNTDOWN_AWAIT` | CountDownLatch 在 finally 中 countDown | 🟡 WARNING |
| `ALIBABA_RANDOM_INSTANCE` | 使用 ThreadLocalRandom 替代 Random | 🔵 INFO |
| `ALIBABA_DCL_VOLATILE` | 双重检查锁需声明 volatile | 🟡 WARNING |
| `ALIBABA_VOLATILE_ATOMIC` | volatile 多写需 Atomic 类或锁 | 🔵 INFO |
| `ALIBABA_SINGLETON_THREAD_SAFE` | 单例对象需保证线程安全 | 🟡 WARNING |
| `ALIBABA_HASHMAP_RESIZE` | 高并发避免 HashMap resize 死链 | 🔵 INFO |

## 注释规范 (4 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_INLINE_COMMENT` | 单行注释放在被注释语句上方 | 🔵 INFO |
| `ALIBABA_FIXME` | 存在 FIXME 标记 | 🔵 INFO |
| `ALIBABA_TODO` | 存在 TODO 标记 | 🔵 INFO |
| `ALIBABA_COMMENTED_CODE` | 删除被注释的代码 | 🔵 INFO |

## 常量定义 (3 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_LONG_SUFFIX` | long 后缀 L 大写 | 🔵 INFO |
| `ALIBABA_FLOAT_SUFFIX` | 浮点后缀统一大写 D 或 F | 🔵 INFO |
| `ALIBABA_MANY_CONSTANTS` | 不要使用一个常量类维护所有常量 | 🔵 INFO |

## 异常处理 (10 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_EMPTY_CATCH` | 不要捕获了却不处理 | 🟡 WARNING |
| `ALIBABA_CATCH_RUNTIME` | 可通过预检查规避的异常不应用 catch 处理 | 🟡 WARNING |
| `ALIBABA_CATCH_GENERIC` | 避免使用 Exception/Throwable 捕获所有异常 | 🔵 INFO |
| `ALIBABA_RAW_EXCEPTION` | 禁止直接抛出 RuntimeException/Exception | 🟡 WARNING |
| `ALIBABA_RPC_THROWABLE` | RPC 调用使用 Throwable 拦截 | 🟡 WARNING |
| `ALIBABA_FINALLY_RETURN` | finally 块中禁止使用 return | 🟡 WARNING |
| `ALIBABA_STREAM_CLOSE` | IO 流通过 finally 或 try-with-resources 关闭 | 🟡 WARNING |
| `ALIBABA_NPE_AUTOBOX` | 注意自动拆箱产生 NPE | 🟡 WARNING |
| `ALIBABA_TRANSACTION_ROLLBACK` | 事务中捕获异常需回滚 | 🟡 WARNING |
| `ALIBABA_OPEN_API_ERRORCODE` | 开放接口使用错误码 | 🔵 INFO |

## 日志规约 (4 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_LOG_FACADE` | 使用 SLF4J 门面而非直接 Log4j/Logback | 🟡 WARNING |
| `ALIBABA_LOG_JSON` | 禁止直接用 JSON 工具将对象转 String | 🟡 WARNING |
| `ALIBABA_LOG_LEVEL_CHECK` | trace/debug 输出需级别开关判断 | 🔵 INFO |
| `ALIBABA_SYSTEM_OUT` | 生产环境禁止 System.out/err | 🟡 WARNING |

## 其他 (5 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_PATTERN_COMPILE` | 正则表达式预编译为 static final 常量 | 🟡 WARNING |
| `ALIBABA_BEANUTILS` | 避免使用 Apache BeanUtils | 🟡 WARNING |
| `ALIBABA_BIGDECIMAL_CONSTRUCTOR` | 禁止 BigDecimal(double) | 🟡 WARNING |
| `ALIBABA_MATH_RANDOM` | 注意 Math.random() 返回范围 | 🔵 INFO |
| `ALIBABA_SQL_INJECTION` | 禁止字符串拼接 SQL | 🟡 WARNING |

## 前后端规约 (11 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_API_JSON` | 前后端交互使用 JSON 格式 | 🔵 INFO |
| `ALIBABA_LONG_ID_STRING` | 超大整数使用 String 类型返回 | 🟡 WARNING |
| `ALIBABA_DATE_FORMAT_UNIFIED` | 前后端时间格式统一为 yyyy-MM-dd HH:mm:ss | 🔵 INFO |
| `ALIBABA_URL_VERSION` | 接口路径中不加版本号 | 🔵 INFO |
| `ALIBABA_REDIRECT_FORWARD` | 内部重定向使用 forward | 🟡 WARNING |
| `ALIBABA_PAGE_PARAM` | 翻页参数小于 1 时返回第一页 | 🔵 INFO |
| `ALIBABA_VIEW_COMPLEX` | 视图模板中不加复杂逻辑 | 🟡 WARNING |
| `ALIBABA_VELOCITY_NULL` | Velocity 使用 $!{var} 避免空指针 | 🟡 WARNING |
| `ALIBABA_CIRCULAR_REF` | 双向关联使用 @JsonIgnore | 🔵 INFO |
| `ALIBABA_FILE_DOWNLOAD_HEADER` | 文件下载 Content-Disposition 编码文件名 | 🟡 WARNING |
| `ALIBABA_TRANSACTION_RPC` | 事务中避免 RPC 和 sleep | 🟡 WARNING |

## 安全规约 (9 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_HARDCODED_PASSWORD` | 禁止硬编码密码 | 🔴 ERROR |
| `ALIBABA_SENSITIVE_DATA` | 用户敏感数据脱敏展示 | 🟡 WARNING |
| `ALIBABA_PARAM_VALIDATION` | 用户请求参数做有效性验证 | 🟡 WARNING |
| `ALIBABA_SQL_INJECTION` | SQL 注入预防 | 🔴 ERROR |
| `ALIBABA_USERID_FROM_REQUEST` | 用户 ID 从 session 获取 | 🟡 WARNING |
| `ALIBABA_XSS_PROTECTION` | 防止 XSS 攻击 | 🟡 WARNING |
| `ALIBABA_CSRF` | 执行 CSRF 安全验证 | 🔵 INFO |
| `ALIBABA_REDIRECT_WHITELIST` | 外部重定向白名单过滤 | 🟡 WARNING |
| `ALIBABA_FILE_UPLOAD` | 文件上传大小、类型检查 | 🟡 WARNING |
| `ALIBABA_LOG_SENSITIVE` | 日志禁输出敏感信息 | 🟡 WARNING |
| `ALIBABA_CONTENT_SECURITY` | 发布/评论场景防刷过滤 | 🔵 INFO |

## MySQL 数据库 (25 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_SQL_IS_PREFIX` | 布尔字段使用 is_xxx 命名 | 🟡 WARNING |
| `ALIBABA_SQL_FIELD_CASE` | 字段名小写字母或数字 | 🟡 WARNING |
| `ALIBABA_TABLE_PLURAL` | 表名不使用复数名词 | 🟡 WARNING |
| `ALIBABA_RESERVED_WORD` | 禁用 MySQL 保留字作字段名 | 🟡 WARNING |
| `ALIBABA_DECIMAL_TYPE` | 小数使用 decimal，禁 float/double | 🟡 WARNING |
| `ALIBABA_SQL_REQUIRED_FIELDS` | 表必备 id/create_time/update_time | 🟡 WARNING |
| `ALIBABA_UNIQUE_INDEX` | 唯一性字段建成唯一索引 | 🟡 WARNING |
| `ALIBABA_LEFT_FUZZY` | 禁止左模糊/全模糊 LIKE | 🟡 WARNING |
| `ALIBABA_PAGE_ORDER_BY` | 分页查询指定 ORDER BY | 🟡 WARNING |
| `ALIBABA_COUNT_STAR` | 使用 count(*) 而非 count(列名) | 🟡 WARNING |
| `ALIBABA_COUNT_COL_NPE` | sum(col) 返回 NULL，需 NPE 判断 | 🔵 INFO |
| `ALIBABA_COUNT_NO_WHERE` | COUNT 无 WHERE 可能性能低下 | 🔵 INFO |
| `ALIBABA_USE_ISNULL` | 使用 ISNULL() 判断 NULL | 🔵 INFO |
| `ALIBABA_NO_FOREIGN_KEY` | 不得使用外键 | 🟡 WARNING |
| `ALIBABA_NO_STORED_PROC` | 禁止使用存储过程 | 🟡 WARNING |
| `ALIBABA_SELECT_BEFORE_DML` | 删除/修改前先 SELECT | 🔵 INFO |
| `ALIBABA_TABLE_ALIAS` | 多表查询加别名限定 | 🔵 INFO |
| `ALIBABA_IN_SIZE` | in 集合控制在 1000 内 | 🟡 WARNING |
| `ALIBABA_JOIN_LIMIT` | 不超过三表 join | 🟡 WARNING |
| `ALIBABA_IMPLICIT_CONVERSION` | 防止隐式转换导致索引失效 | 🟡 WARNING |
| `ALIBABA_PHYSICAL_DELETE` | 使用逻辑删除而非物理删除 | 🟡 WARNING |
| `ALIBABA_SELECT_STAR` | 禁止 SELECT * | 🟡 WARNING |
| `ALIBABA_TRUNCATE_USAGE` | 不推荐使用 TRUNCATE | 🟡 WARNING |
| `ALIBABA_QUERY_FOR_LIST` | 不推荐 queryForList(start,size) | 🟡 WARNING |
| `ALIBABA_HASHMAP_RESULT` | 禁止 HashMap 作查询结果输出 | 🟡 WARNING |
| `ALIBABA_UPDATE_TIME` | 更新时同时更新 update_time | 🔵 INFO |
| `ALIBABA_UPDATE_ALL_FIELDS` | 不写大而全的更新接口 | 🔵 INFO |
| `ALIBABA_TRANSACTIONAL_READONLY` | @Transactional 不滥用 | 🔵 INFO |
| `ALIBABA_INDEX_NAMING` | 索引用 pk_/uk_/idx_ 前缀 | 🔵 INFO |
| `ALIBABA_RESULT_MAP` | POJO 定义对应 <resultMap> | 🔵 INFO |

## 单元测试 (5 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_TEST_LOCATION` | 测试代码必须放在 src/test/java | 🟡 WARNING |
| `ALIBABA_TEST_ENV_DEP` | 单元测试不依赖外界环境 | 🟡 WARNING |
| `ALIBABA_TEST_NO_ASSERT` | 单元测试必须使用 assert | 🟡 WARNING |
| `ALIBABA_TEST_HARDCODED_ID` | 不硬编码数据库 ID | 🟡 WARNING |
| `ALIBABA_TEST_ROLLBACK` | DB 测试设定自动回滚 | 🔵 INFO |

## 工程结构 (15 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_DO_PACKAGE` | DO 放在 entity/model 包 | 🔵 INFO |
| `ALIBABA_DTO_PACKAGE` | DTO 放在 dto/api 包 | 🔵 INFO |
| `ALIBABA_VO_PACKAGE` | VO 放在 vo/view 包 | 🔵 INFO |
| `ALIBABA_DAO_EXCEPTION` | DAO 层抛 DAOException | 🔵 INFO |
| `ALIBABA_REMOTE_TIMEOUT` | 远程调用设置超时时间 | 🟡 WARNING |
| `ALIBABA_ERROR_CODE_LEN` | 错误码长度 5-6 位 | 🔵 INFO |
| `ALIBABA_ERROR_CODE_CLASS` | 错误码按类编号 | 🔵 INFO |
| `ALIBABA_INTERFACE_MAP_RESULT` | 接口不返回 Map | 🟡 WARNING |
| `ALIBABA_INTERFACE_MAP_PARAM` | 接口不接受 Map 参数 | 🟡 WARNING |
| `ALIBABA_METHOD_TOO_LONG` | 方法不超过 80 行 | 🟡 WARNING |
| `ALIBABA_POJO_TOSTRING` | POJO 重写 toString | 🔵 INFO |
| `ALIBABA_SPRING_ANNOTATION` | Impl 类添加 Spring Bean 注解 | 🔵 INFO |
| `ALIBABA_JAVADOC_AUTHOR` | 类缺少 @author 标记 | 🔵 INFO |
| `ALIBABA_JAVADOC_DATE` | 类缺少创建日期标记 | 🔵 INFO |
| `ALIBABA_UNUSED_PRIVATE_FIELD` | 未使用的私有字段应移除 | 🟡 WARNING |

## 设计规约 (6 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_SINGLE_RESPONSIBILITY` | 类职责过重，应单一职责 | 🔵 INFO |
| `ALIBABA_COMPOSITION` | 优先聚合/组合而非继承 | 🔵 INFO |
| `ALIBABA_INTERFACE_EMPTY` | 接口需要被实现 | 🔵 INFO |
| `ALIBABA_DEEP_INHERITANCE` | 继承层次不超过 3 层 | 🔵 INFO |
| `ALIBABA_EXCESSIVE_IFELSE` | 过多 if-else 用策略模式替代 | 🟡 WARNING |
| `ALIBABA_BIG_METHOD` | 长方法分解为小方法 | 🟡 WARNING |
