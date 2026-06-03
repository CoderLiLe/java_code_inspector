# Alibaba Java Coding Guidelines — 规则总表

共 **295** 条规则，覆盖《Java开发手册(黄山版)》全部 19 个章节。

## 命名风格 (29 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_DOLLAR_NAME` | 所有编程相关的命名均不能以美元符号开始或结束 | 🟡 WARNING |
| `ALIBABA_UNDERSCORE_NAME` | 命名不能以下划线开始或结束 | 🟡 WARNING |
| `ALIBABA_NO_CHINESE` | 命名中禁止使用中文或拼音 | 🟡 WARNING |
| `ALIBABA_NO_INSULT` | 避免使用侮辱性词语 | 🟡 WARNING |
| `ALIBABA_NO_RACIST` | 避免使用种族歧视性词语，建议使用 blockList/allowList/secondary | 🟡 WARNING |
| `ALIBABA_ARRAY_STYLE` | 类型与中括号应紧挨相连来定义数组，如 int[] arrayDemo | 🟡 WARNING |
| `ALIBABA_PACKAGE_NAME` | 包名必须全部小写 | 🟡 WARNING |
| `ALIBABA_PARAM_FIELD_CONFLICT` | 参数与成员变量同名，非 setter 方法应避免 | 🔵 INFO |
| `ALIBABA_UPPER_CAMEL` | 类名应使用 UpperCamelCase 风格（首字母大写） | 🟡 WARNING |
| `ALIBABA_LOWER_CAMEL_METHOD` | 方法名应使用 lowerCamelCase 风格（首字母小写） | 🟡 WARNING |
| `ALIBABA_LOWER_CAMEL_PARAM` | 参数名应使用 lowerCamelCase 风格（首字母小写） | 🟡 WARNING |
| `ALIBABA_LOWER_CAMEL_FIELD` | 成员变量应使用 lowerCamelCase 风格（首字母小写） | 🟡 WARNING |
| `ALIBABA_CONSTANT_NAMING` | 常量应全部大写，单词间用下划线隔开 | 🟡 WARNING |
| `ALIBABA_ABSTRACT_NAMING` | 抽象类命名应以 Abstract 或 Base 开头 | 🟡 WARNING |
| `ALIBABA_EXCEPTION_NAMING` | 异常类命名应以 Exception 结尾 | 🟡 WARNING |
| `ALIBABA_ENUM_NAMING` | 枚举类命名应以 Enum 结尾 | 🟡 WARNING |
| `ALIBABA_ENUM_MEMBER_NAMING` | 枚举成员应全部大写，单词间用下划线隔开 | 🟡 WARNING |
| `ALIBABA_INTERFACE_MODIFIER` | 接口中的方法和属性不要加任何修饰符号（public 也不要加） | 🟡 WARNING |
| `ALIBABA_BOOLEAN_PREFIX` | POJO 类中布尔类型变量不应加 is 前缀 | 🟡 WARNING |
| `ALIBABA_CRYPTIC_NAME` | 杜绝不规范的缩写，应使用完整单词组合来表达语义 | 🔵 INFO |
| `ALIBABA_BAD_ABBREVIATION` | 杜绝完全不规范的英文缩写，避免望文不知义 | 🟡 WARNING |
| `ALIBABA_SINGLE_LETTER_VAR` | 变量名过于简短，应使用完整的单词组合来表达语义 | 🔵 INFO |
| `ALIBABA_NAMING_CONFLICT` | 子类的成员变量不应与父类成员变量同名，避免混淆 | 🔵 INFO |
| `ALIBABA_TEST_NAMING` | 测试类命名应以被测试类名为前缀加 Test 结尾 | 🔵 INFO |
| `ALIBABA_IMPL_NAMING` | 实现类应实现对应的接口 | 🔵 INFO |
| `ALIBABA_PATTERN_NAME` | 包含设计模式名的类，建议将模式名放在类名末尾 | 🔵 INFO |
| `ALIBABA_TYPE_NOUN_SUFFIX` | 变量中类型名词建议放在变量名末尾以提升辨识度 | 🔵 INFO |
| `ALIBABA_LAYER_METHOD` | DAO/Service 方法命名应使用规范前缀（get/list/count/remove） | 🔵 INFO |
| `ALIBABA_LOCAL_VAR_CASE` | 局部变量应使用 lowerCamelCase 风格（首字母小写） | 🟡 WARNING |

## 代码风格 (14 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_BRACE_FORMAT` | 右大括号后除了 else/catch/finally 外必须换行 | 🔵 INFO |
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
| `ALIBABA_KEYWORD_SPACING` | 关键字与括号之间必须加空格 | 🔵 INFO |
| `ALIBABA_OPERATOR_SPACING` | 二目运算符左右两边都需要加一个空格 | 🔵 INFO |

## 面向对象 (39 条)

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
| `ALIBABA_TO_STRING` | POJO 类必须写 toString 方法 | 🟡 WARNING |
| `ALIBABA_POJO_WRAPPER` | POJO 类属性必须使用包装数据类型，而非基本类型 | 🟡 WARNING |
| `ALIBABA_POJO_DEFAULT` | POJO 类属性不要设定任何属性默认值 | 🟡 WARNING |
| `ALIBABA_SERIAL_VERSION_UID` | 实现 Serializable 的类应声明 serialVersionUID 字段 | 🟡 WARNING |
| `ALIBABA_OVERRIDE_ANNOTATION` | 覆写方法必须加 @Override 注解 | 🟡 WARNING |
| `ALIBABA_STATIC_ACCESS` | 应通过类名直接访问静态方法，而非通过实例对象 | 🟡 WARNING |
| `ALIBABA_DEPRECATED_METHOD` | 避免使用过时的方法 | 🟡 WARNING |
| `ALIBABA_UTILITY_CTOR` | 工具类不允许有 public 或 default 构造方法，构造方法应为 private | 🟡 WARNING |
| `ALIBABA_BOTH_IS_GET` | POJO 类中不能同时存在对应属性的 isXxx() 和 getXxx() 方法 | 🟡 WARNING |
| `ALIBABA_RPC_WRAPPER_RETURN` | RPC 接口方法返回值应使用包装数据类型 | 🟡 WARNING |
| `ALIBABA_RPC_WRAPPER_PARAM` | RPC 接口方法参数应使用包装数据类型 | 🟡 WARNING |
| `ALIBABA_INTERFACE_ENUM_RETURN` | 接口方法返回值禁止使用枚举类型 | 🟡 WARNING |
| `ALIBABA_INTERFACE_DEPRECATED` | 在 Javadoc 中已标注 @deprecated 但缺少 @Deprecated 注解 | 🟡 WARNING |
| `ALIBABA_EQUALS_STYLE` | equals 应使用常量调用，建议 "constant".equals(var) | 🔵 INFO |
| `ALIBABA_CLONE_USAGE` | 慎用 Object 的 clone 方法，默认浅拷贝 | 🔵 INFO |
| `ALIBABA_CTOR_GROUPING` | 多个构造方法应顺序放置在一起 | 🔵 INFO |
| `ALIBABA_SPLIT_RESULT` | split 结果数组需做最后一个元素检查 | 🔵 INFO |
| `ALIBABA_STRING_BUILDER` | 循环体内字符串连接使用 StringBuilder | 🔵 INFO |
| `ALIBABA_STRING_CONCAT_LOOP` | 循环体内字符串连接使用 StringBuilder 的 append 方法 | 🟡 WARNING |
| `ALIBABA_TOSTRING_CATCH` | 异常后使用日志框架而非 toString | 🔵 INFO |
| `ALIBABA_MULTIPLE_INSTANCEOF` | 多个 instanceof 使用多态重构 | 🔵 INFO |
| `ALIBABA_GETTER_LOGIC` | getter 方法不应包含业务逻辑，应仅做属性返回 | 🔵 INFO |
| `ALIBABA_SETTER_LOGIC` | setter 方法不应包含业务逻辑，应仅做属性赋值 | 🔵 INFO |
| `ALIBABA_SETTER_PARAM_NAME` | setter 参数名需与字段名一致 | 🔵 INFO |
| `ALIBABA_LOCAL_PRIMITIVE` | 局部变量建议使用基本类型而非包装类型 | 🔵 INFO |
| `ALIBABA_ACCESS_DEFAULT` | 字段缺少访问修饰符，建议使用 private | 🔵 INFO |
| `ALIBABA_ACCESS_DEFAULT_METHOD` | 方法缺少访问修饰符，建议明确指定 | 🔵 INFO |
| `ALIBABA_ACCESS_CTOR` | 类包含大量静态方法时构造方法应设为 private | 🔵 INFO |
| `ALIBABA_METHOD_ORDER` | 方法顺序不合理，建议按 public/protected/private/getter/setter 排列 | 🔵 INFO |
| `ALIBABA_DO_FIELD_TYPE_MISMATCH` | DO 字段类型应与数据库字段类型匹配（如 bigint 对应 Long） | 🟡 WARNING |

## 日期时间 (11 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_DATE_FORMAT_YEAR` | 年份用小写 yyyy，大写 YYYY 表示 week year | 🟡 WARNING |
| `ALIBABA_DATE_FORMAT_CASE` | 月份大写 M，分钟小写 m，请勿混淆 | 🟡 WARNING |
| `ALIBABA_NO_SQL_DATE` | 禁止使用 java.sql.Date/Time/Timestamp，应使用 java.util.Date 或 JDK8 时间类 | 🟡 WARNING |
| `ALIBABA_TIMESTAMP_INT` | 时间戳字段应使用 long 而非 int | 🟡 WARNING |
| `ALIBABA_CURRENT_TIME_MILLIS` | 使用 System.currentTimeMillis() 而非 new Date().getTime() | 🔵 INFO |
| `ALIBABA_HARDCODED_365` | 禁止写死一年为 365 天，使用 LocalDate.lengthOfYear() | 🟡 WARNING |
| `ALIBABA_MONTH_ENUM` | 使用枚举值指代月份 | 🔵 INFO |
| `ALIBABA_CALENDAR_MAGIC` | Calendar 获取值使用常量而非数字 | 🔵 INFO |
| `ALIBABA_TIME_ZONE` | 序列化日期时指定 timezone 参数 | 🔵 INFO |
| `ALIBABA_USE_LOCALDATETIME` | 避免使用 java.util.Date/Calendar，推荐 JDK8 新时间 API | 🔵 INFO |
| `ALIBABA_LEAP_YEAR_FEB29` | 避免硬编码 2 月 29 日，闰年需特殊处理 | 🔵 INFO |

## 集合处理 (22 条)

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
| `ALIBABA_WILDCARD_SUPER_GET` | <? super T> 集合不能安全使用 get 方法 | 🟡 WARNING |
| `ALIBABA_RAW_TYPE` | 无泛型集合赋值给泛型集合需 instanceof 判断 | 🔵 INFO |
| `ALIBABA_KEYSET_LOOP` | 遍历 Map 使用 entrySet 而非 keySet | 🔵 INFO |
| `ALIBABA_LIST_CONTAINS` | 去重用 Set，避免 List.contains() | 🔵 INFO |
| `ALIBABA_COMPARATOR_CONDITIONS` | Comparator 需满足自反性/传递性/对称性 | 🟡 WARNING |
| `ALIBABA_ENUM_FIXED_VALUE` | 固定范围值建议使用枚举类型定义 | 🔵 INFO |

## 控制语句 (15 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_REQUIRE_BRACES` | if/else/for/while/do 必须使用大括号 | 🟡 WARNING |
| `ALIBABA_SWITCH_DEFAULT` | switch 必须包含 default 语句 | 🟡 WARNING |
| `ALIBABA_SWITCH_FALLTHROUGH` | case 穿透必须注释说明为什么会继续执行到下一个 case | 🔵 INFO |
| `ALIBABA_SWITCH_BREAK` | 每个 case 必须用 break/return 终止 | 🟡 WARNING |
| `ALIBABA_SWITCH_STRING` | String 类型 switch 需先 null 判断 | 🔵 INFO |
| `ALIBABA_TERNARY_NPE` | 三目运算符注意自动拆箱 NPE | 🔵 INFO |
| `ALIBABA_ASSIGN_IN_CONDITION` | 条件表达式中禁止插入赋值语句 | 🟡 WARNING |
| `ALIBABA_COMPLEX_CONDITION` | 复杂条件赋值给有意义的布尔变量 | 🔵 INFO |
| `ALIBABA_IF_DEPTH` | if-else 超过 3 层使用卫语句/策略模式 | 🔵 INFO |
| `ALIBABA_LOOP_CONNECTION` | 数据库连接获取不应放在循环体内，应移至循环外 | 🔵 INFO |
| `ALIBABA_AVOID_NOT` | 避免取反逻辑运算符 | 🔵 INFO |
| `ALIBABA_LOOP_OBJECT_CREATION` | 循环中对象定义移至循环体外 | 🔵 INFO |
| `ALIBABA_PARAM_VALIDATION` | 公开接口需要入参保护 | 🔵 INFO |
| `ALIBABA_RETURN_BLANK_LINE` | return/throw 右大括号后加空行 | 🔵 INFO |
| `ALIBABA_HIGH_CONCURRENCY_EQUAL` | 高并发场景中避免使用等值判断(==)作为中断条件，建议用区间判断 | 🟡 WARNING |

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

## 注释规范 (8 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_CLASS_JAVADOC` | 类缺少 Javadoc 注释（创建者和创建日期） | 🔵 INFO |
| `ALIBABA_ABSTRACT_JAVADOC` | 抽象方法（接口方法）必须使用 Javadoc 注释 | 🔵 INFO |
| `ALIBABA_INLINE_COMMENT` | 单行注释放在被注释语句上方 | 🔵 INFO |
| `ALIBABA_MULTILINE_COMMENT` | 方法内超过 3 行连续 // 注释应改用 /* */ 多行注释格式 | 🔵 INFO |
| `ALIBABA_FIXME` | 存在 FIXME 标记 | 🔵 INFO |
| `ALIBABA_TODO` | 存在 TODO 标记 | 🔵 INFO |
| `ALIBABA_COMMENTED_CODE` | 删除被注释的代码 | 🔵 INFO |
| `ALIBABA_ENUM_COMMENT` | 枚举项缺少注释说明 | 🔵 INFO |

## 常量定义 (5 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_LONG_SUFFIX` | long 后缀 L 大写 | 🔵 INFO |
| `ALIBABA_FLOAT_SUFFIX` | 浮点后缀统一大写 D 或 F | 🔵 INFO |
| `ALIBABA_MANY_CONSTANTS` | 不要使用一个常量类维护所有常量 | 🔵 INFO |
| `ALIBABA_CONST_FINAL` | 常量应为 static final，缺少 final 修饰符 | 🟡 WARNING |
| `ALIBABA_MAGIC_NUMBER` | 魔法值应定义为类或接口常量，避免直接使用 | 🔵 INFO |

## 异常处理 (15 条)

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
| `ALIBABA_EXCEPTION_FLOW` | 异常捕获后不要用来做流程控制，不应通过异常控制业务分支 | 🟡 WARNING |
| `ALIBABA_EXCEPTION_TYPE_MISMATCH` | catch 捕获的类型与抛出类型不兼容，应匹配或为父类 | 🟡 WARNING |
| `ALIBABA_OPEN_API_ERRORCODE` | 开放接口使用错误码 | 🔵 INFO |
| `ALIBABA_CATCH_SCENE_INFO` | 异常信息应包含案发现场信息和异常堆栈信息，缺少上下文参数 | 🔵 INFO |
| `ALIBABA_CATCH_TYPE_DISTINGUISH` | catch 需分清稳定代码与非稳定代码，多个可能异常的方法建议分开 try-catch | 🔵 INFO |
| `ALIBABA_NULL_RETURN` | 方法可能返回 null，必须添加注释充分说明什么情况下会返回 null | 🔵 INFO |

## 日志规约 (6 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_LOG_FACADE` | 使用 SLF4J 门面而非直接 Log4j/Logback | 🟡 WARNING |
| `ALIBABA_LOG_JSON` | 禁止直接用 JSON 工具将对象转 String | 🟡 WARNING |
| `ALIBABA_LOG_LEVEL_CHECK` | trace/debug 输出需级别开关判断 | 🔵 INFO |
| `ALIBABA_LOG_PLACEHOLDER` | 日志字符串拼接应使用占位符 {} 方式，如 logger.info("msg {}", var) | 🔵 INFO |
| `ALIBABA_SYSTEM_OUT` | 生产环境禁止 System.out/err | 🟡 WARNING |
| `ALIBABA_LOG_ADDITIVITY` | 避免重复打印日志，务必在日志配置文件中设置 additivity=false | 🔵 INFO |

## 其他 (8 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_PATTERN_COMPILE` | 正则表达式预编译为 static final 常量 | 🟡 WARNING |
| `ALIBABA_BEANUTILS` | 避免使用 Apache BeanUtils | 🟡 WARNING |
| `ALIBABA_BIGDECIMAL_CONSTRUCTOR` | 禁止 BigDecimal(double) | 🟡 WARNING |
| `ALIBABA_ENUM_FIELD_VISIBILITY` | 枚举成员变量必须私有且不可变 | 🟡 WARNING |
| `ALIBABA_MATH_RANDOM` | 注意 Math.random() 返回范围 | 🔵 INFO |
| `ALIBABA_SQL_INJECTION` | 禁止字符串拼接 SQL | 🟡 WARNING |
| `ALIBABA_MAGIC_STRING` | 不允许魔法值（未经预先定义的常量）直接出现在代码中 | 🔵 INFO |
| `ALIBABA_STRING_BUILDER_SIZE` | StringBuilder/StringBuffer 建议指定初始大小，避免频繁扩容 | 🔵 INFO |

## 前后端规约 (17 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_API_JSON` | 前后端交互使用 JSON 格式 | 🔵 INFO |
| `ALIBABA_LONG_ID_STRING` | 超大整数使用 String 类型返回 | 🟡 WARNING |
| `ALIBABA_DATE_FORMAT_UNIFIED` | 前后端时间格式统一为 yyyy-MM-dd HH:mm:ss | 🔵 INFO |
| `ALIBABA_JSON_KEY_CASE` | JSON 的 key 必须为小写字母开始的 lowerCamelCase 风格 | 🟡 WARNING |
| `ALIBABA_URL_VERSION` | 接口路径中不加版本号 | 🔵 INFO |
| `ALIBABA_REDIRECT_FORWARD` | 内部重定向使用 forward | 🟡 WARNING |
| `ALIBABA_PAGE_PARAM` | 翻页参数小于 1 时返回第一页 | 🔵 INFO |
| `ALIBABA_VIEW_COMPLEX` | 视图模板中不加复杂逻辑 | 🟡 WARNING |
| `ALIBABA_VELOCITY_NULL` | Velocity 使用 $!{var} 避免空指针 | 🟡 WARNING |
| `ALIBABA_CIRCULAR_REF` | 双向关联使用 @JsonIgnore | 🔵 INFO |
| `ALIBABA_FILE_DOWNLOAD_HEADER` | 文件下载 Content-Disposition 编码文件名 | 🟡 WARNING |
| `ALIBABA_TRANSACTION_RPC` | 事务中避免 RPC 和 sleep | 🟡 WARNING |
| `ALIBABA_RETURN_EMPTY` | 返回集合数据时，如果为空应返回空数组 [] 或空集合 {}，而非 null | 🟡 WARNING |
| `ALIBABA_URL_LENGTH` | HTTP 请求通过 URL 传递参数时，不能超过 2048 字节 | 🟡 WARNING |
| `ALIBABA_API_COMMENT` | API 方法必须添加注释说明接口功能 | 🔵 INFO |
| `ALIBABA_ERROR_MESSAGE` | 错误处理应返回 errorCode 和 errorMessage 信息 | 🔵 INFO |
| `ALIBABA_BODY_LENGTH` | HTTP 请求通过 body 传递内容时，必须控制长度，超出最大长度后端解析会出错 | 🔵 INFO |

## 安全规约 (13 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_HARDCODED_PASSWORD` | 禁止硬编码密码 | 🔴 ERROR |
| `ALIBABA_SENSITIVE_DATA` | 用户敏感数据脱敏展示 | 🟡 WARNING |
| `ALIBABA_PARAM_VALIDATION` | 用户请求参数做有效性验证 | 🟡 WARNING |
| `ALIBABA_SQL_INJECTION` | SQL 注入预防，MyBatis 中使用 ${} 拼接 SQL 存在注入风险，建议使用 #{} | 🔴 ERROR |
| `ALIBABA_USERID_FROM_REQUEST` | 用户 ID 从 session 获取 | 🟡 WARNING |
| `ALIBABA_XSS_PROTECTION` | 防止 XSS 攻击 | 🟡 WARNING |
| `ALIBABA_CSRF` | 执行 CSRF 安全验证 | 🔵 INFO |
| `ALIBABA_REDIRECT_WHITELIST` | 外部重定向白名单过滤 | 🟡 WARNING |
| `ALIBABA_FILE_UPLOAD` | 文件上传大小、类型检查 | 🟡 WARNING |
| `ALIBABA_LOG_SENSITIVE` | 日志禁输出敏感信息 | 🟡 WARNING |
| `ALIBABA_CONTENT_SECURITY` | 发布/评论场景防刷过滤 | 🔵 INFO |
| `ALIBABA_ANTI_REPLAY` | 在使用平台资源（短信、邮件、电话、下单、支付）时，必须实现正确的防重放机制 | 🟡 WARNING |
| `ALIBABA_PERMISSION_CHECK` | 操作方法必须进行权限控制校验 | 🟡 WARNING |

## MySQL 数据库 (40 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_ALIAS_AS` | SQL 语句中表别名前推荐加 as，如 'table as alias' | 🔵 INFO |
| `ALIBABA_SQL_IS_PREFIX` | 布尔字段使用 is_xxx 命名 | 🟡 WARNING |
| `ALIBABA_SQL_FIELD_CASE` | 字段名小写字母或数字 | 🟡 WARNING |
| `ALIBABA_TABLE_PLURAL` | 表名不使用复数名词 | 🟡 WARNING |
| `ALIBABA_TABLE_NAMING` | 表名建议遵循业务名称_表的作用的命名方式 | 🔵 INFO |
| `ALIBABA_RESERVED_WORD` | 禁用 MySQL 保留字作字段名 | 🟡 WARNING |
| `ALIBABA_DECIMAL_TYPE` | 小数使用 decimal，禁 float/double | 🟡 WARNING |
| `ALIBABA_SQL_REQUIRED_FIELDS` | 表必备 id/create_time/update_time | 🟡 WARNING |
| `ALIBABA_CHAR_TYPE` | 固定长度短字段建议使用 char 定长字符串类型 | 🔵 INFO |
| `ALIBABA_VARCHAR_LENGTH` | varchar 长度建议不超过 5000，超过应使用 text 类型 | 🔵 INFO |
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
| `ALIBABA_VARCHAR_INDEX_LENGTH` | varchar 字段建立索引时需指定索引长度 | 🟡 WARNING |
| `ALIBABA_SQL_PARAM_BINDING` | sql.xml 配置参数使用 #{} 而非 ${}，防止 SQL 注入 | 🟡 WARNING |
| `ALIBABA_UTF8MB4` | 所有字符存储与表示均采用 utf8mb4 字符集（而非 utf8），避免 emoji 无法存储 | 🔵 INFO |
| `ALIBABA_COVERING_INDEX` | 考虑利用覆盖索引进行查询，避免回表查询 | 🔵 INFO |
| `ALIBABA_COMPOSITE_INDEX` | 组合索引应将区分度最高的列放在最左边 | 🔵 INFO |
| `ALIBABA_PAGE_COUNT_ZERO` | 分页查询时若 count 为 0 应直接返回，避免执行后面的分页语句 | 🔵 INFO |

## 单元测试 (5 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_TEST_LOCATION` | 测试代码必须放在 src/test/java | 🟡 WARNING |
| `ALIBABA_TEST_ENV_DEP` | 单元测试不依赖外界环境 | 🟡 WARNING |
| `ALIBABA_TEST_NO_ASSERT` | 单元测试必须使用 assert | 🟡 WARNING |
| `ALIBABA_TEST_HARDCODED_ID` | 不硬编码数据库 ID | 🟡 WARNING |
| `ALIBABA_TEST_ROLLBACK` | DB 测试设定自动回滚 | 🔵 INFO |

## 工程结构 (22 条)

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
| `ALIBABA_METHOD_LENGTH` | 方法总行数超过建议值，应进行拆分 | 🟡 WARNING |
| `ALIBABA_POJO_TOSTRING` | POJO 重写 toString | 🔵 INFO |
| `ALIBABA_SPRING_ANNOTATION` | Impl 类添加 Spring Bean 注解 | 🔵 INFO |
| `ALIBABA_JAVADOC_AUTHOR` | 类缺少 @author 标记 | 🔵 INFO |
| `ALIBABA_JAVADOC_DATE` | 类缺少创建日期标记 | 🔵 INFO |
| `ALIBABA_UNUSED_PRIVATE_FIELD` | 未使用的私有字段应移除 | 🟡 WARNING |
| `ALIBABA_IMPL_SUFFIX` | Service 实现类应以 Impl 结尾 | 🔵 INFO |
| `ALIBABA_QUERY_PARAM_MAP` | 查询方法超过 2 个参数时禁止使用 Map 传输，应使用 DTO | 🟡 WARNING |
| `ALIBABA_SNAPSHOT_DEP` | 线上应用不要依赖 SNAPSHOT 版本（安全包除外） | 🟡 WARNING |
| `ALIBABA_POM_UNIFIED_VERSION` | 依赖于一个二方库群时，必须定义一个统一的版本变量 | 🔵 INFO |
| `ALIBABA_POM_DEP_VERSION` | 依赖版本应通过 <dependencyManagement> 统一管理版本变量 | 🔵 INFO |
| `ALIBABA_VERSION_FORMAT` | 版本号不符合主版本号.次版本号.修订号格式 | 🔵 INFO |

## 设计规约 (6 条)

| 规则 ID | 说明 | 严重度 |
|---------|------|--------|
| `ALIBABA_SINGLE_RESPONSIBILITY` | 类职责过重，应单一职责 | 🔵 INFO |
| `ALIBABA_COMPOSITION` | 优先聚合/组合而非继承 | 🔵 INFO |
| `ALIBABA_INTERFACE_EMPTY` | 接口需要被实现 | 🔵 INFO |
| `ALIBABA_DEEP_INHERITANCE` | 继承层次不超过 3 层 | 🔵 INFO |
| `ALIBABA_EXCESSIVE_IFELSE` | 过多 if-else 用策略模式替代 | 🟡 WARNING |
| `ALIBABA_BIG_METHOD` | 长方法分解为小方法 | 🟡 WARNING |
