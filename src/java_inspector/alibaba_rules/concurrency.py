import re
import javalang

from java_inspector.models import Severity
from java_inspector.alibaba_rules.base import BaseChecker


class ConcurrencyChecker(BaseChecker):

    def check_concurrency(self, tree, file_path: str, content: str):
        if not self.config.is_rule_enabled("alibaba_concurrency"):
            return
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+Thread\s*\(\s*\)", line):
                self._add(file_path, "ALIBABA_THREAD_NAME",
                          "创建线程或线程池时请指定有意义的线程名称，方便出错时回溯",
                          Severity.INFO, line=i)
        for i, line in enumerate(lines, 1):
            if re.search(r"\bnew\s+Thread\b", line) and not re.search(r"new\s+Thread\s*\([^)]+\)\s*\{", line):
                self._add(file_path, "ALIBABA_NEW_THREAD",
                          "线程创建应使用线程池（ThreadPoolExecutor），避免显式 new Thread",
                          Severity.WARNING, line=i)
            if re.search(r"Executors\.new(Cached|Fixed|Single|Scheduled)Thread", line):
                self._add(file_path, "ALIBABA_EXECUTORS_POOL",
                          "应使用 ThreadPoolExecutor 创建线程池，而非 Executors 工具类",
                          Severity.WARNING, line=i)
            if re.search(r"new\s+T\w*imerTask\b", line) or \
               re.search(r"new\s+Timer\b", line):
                self._add(file_path, "ALIBABA_TIMER_TASK",
                          "Timer/TimerTask 应使用 ScheduledExecutorService 替代",
                          Severity.WARNING, line=i)
            if re.search(r"private\s+static\s+final\s+SimpleDateFormat\b", line):
                self._add(file_path, "ALIBABA_SIMPLE_DATE_FORMAT",
                          "SimpleDateFormat 是线程不安全的类，应使用 ThreadLocal 或 DateTimeFormatter",
                          Severity.WARNING, line=i)
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation):
                if node.member == "lock" and isinstance(getattr(node, "qualifier", None), javalang.tree.MemberReference):
                    l, c = self._pos(node)
                    self._add(file_path, "ALIBABA_LOCK_IN_TRY",
                              "Lock 的 lock() 方法调用必须紧跟 try 语句，并在 finally 中 unlock()",
                              Severity.WARNING, line=l, column=c)
                    break
        for i, line in enumerate(lines, 1):
            if re.search(r"tryLock\s*\([^)]*\)\s*;\s*$", line) or \
               re.search(r"tryLock\s*\([^)]*\)\s*\)\s*;", line):
                self._add(file_path, "ALIBABA_TRYLOCK_CHECK",
                          "tryLock() 调用后必须检查返回值",
                          Severity.WARNING, line=i)

        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "ThreadLocal" in vtype:
                    for decl in node.declarators:
                        after = content[decl.position.offset:decl.position.offset + 5000] if decl.position else ""
                        if ".remove()" not in after and ".set(null)" not in after:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_THREADLOCAL_CLEANUP",
                                      "必须回收自定义的 ThreadLocal 变量记录的当前线程值，应在 finally 中调用 remove()",
                                      Severity.WARNING, line=l, column=c)

        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "ThreadLocal" in vtype:
                    mods = node.modifiers or []
                    if "static" not in mods:
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_THREADLOCAL_STATIC",
                                      "ThreadLocal 对象必须使用 static 修饰",
                                      Severity.WARNING, line=l, column=c)

        for i, line in enumerate(lines, 1):
            if re.search(r"Random\s+\w+\s*=\s*new\s+Random\b", line) and \
               not re.search(r"//.*", line):
                self._add(file_path, "ALIBABA_RANDOM_INSTANCE",
                          "避免 Random 实例被多线程使用，推荐使用 ThreadLocalRandom",
                          Severity.INFO, line=i)

        # Thread pool should not use Executors
        for i, line in enumerate(lines, 1):
            if re.search(r"Executors\.new\w+Pool\s*\(", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_CUSTOM_THREAD_POOL",
                          "线程池不允许使用 Executors 去创建，而是通过 ThreadPoolExecutor 的方式",
                          Severity.WARNING, line=i)

        # Thread naming not specified
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+Thread\s*\(", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_NAMED_THREAD",
                          "创建线程或线程池时请指定有意义的线程名称，方便出错时回溯",
                          Severity.INFO, line=i)

        # ThreadPoolExecutor: check if named
        for i, line in enumerate(lines, 1):
            if re.search(r"new\s+ThreadPoolExecutor\s*\(", line) and \
               not re.search(r"ThreadFactory|threadFactory", line) and \
               not re.search(r"//", line):
                self._add(file_path, "ALIBABA_THREAD_FACTORY",
                          "创建线程池必须指定 ThreadFactory 以命名线程",
                          Severity.INFO, line=i)

        # 7.16 Double-checked locking without volatile
        for path, node in tree:
            if isinstance(node, javalang.tree.SynchronizedStatement):
                body_stmts = node.body if isinstance(node.body, list) else \
                            getattr(getattr(node, "body", None), "statements", []) or []
                for stmt in body_stmts:
                    if isinstance(stmt, javalang.tree.IfStatement) and \
                       hasattr(stmt, "expression") and stmt.expression:
                        if_str = str(stmt.expression)
                        if "null" in if_str and "==" in if_str:
                            l = node.position.line if node.position else 0
                            for p2, n2 in tree:
                                if isinstance(n2, javalang.tree.FieldDeclaration) and \
                                   "volatile" not in (n2.modifiers or []):
                                    for decl in n2.declarators:
                                        df = str(decl)
                                        if df.split("=")[0].strip() in if_str:
                                            ll, cc = self._pos(decl)
                                            self._add(file_path, "ALIBABA_DCL_VOLATILE",
                                                      "双重检查锁（double-checked locking）实现延迟初始化需要将目标属性声明为 volatile",
                                                      Severity.WARNING, line=ll, column=cc)
                                            break

        # 7.14 CountDownLatch without guaranteed countDown
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodInvocation) and \
               node.member == "await" and \
               hasattr(node, "qualifier") and "CountDownLatch" in str(node.qualifier):
                l = node.position.line if hasattr(node, "position") and node.position else 0
                for j in range(max(0, l - 2), l + 30):
                    if j < len(lines) and "countDown" not in lines[j] and \
                       j < len(lines) and "finally" in lines[j]:
                        break
                else:
                    if l > 0:
                        self._add(file_path, "ALIBABA_COUNTDOWN_AWAIT",
                                  "使用 CountDownLatch 进行异步转同步，每个线程退出前必须调用 countDown 方法，确保在 finally 中执行",
                                  Severity.WARNING, line=l)

        # 7.7/7.8 Lock performance and order
        for i, line in enumerate(lines, 1):
            if re.search(r"synchronized\s*\([^)]*\)\s*\{", line):
                for j in range(i, min(i + 5, len(lines) + 1)):
                    if j <= len(lines) and re.search(r"synchronized\s*\([^)]*\)\s*\{", lines[j - 1]) and \
                       j - 1 != i:
                        self._add(file_path, "ALIBABA_MULTIPLE_LOCKS",
                                  "对多个资源同时加锁时需要保持一致的加锁顺序，否则可能造成死锁",
                                  Severity.WARNING, line=i)
                        break

        # 7.11 Concurrent update without lock
        for i, line in enumerate(lines, 1):
            if re.search(r"UPDATE\s+\w+\s+SET\s+\w+\s*=\s*\w+\s*\+\s*1", line, re.IGNORECASE) and \
               not re.search(r"(version|optimistic|lock|for\s+update)", line, re.IGNORECASE):
                self._add(file_path, "ALIBABA_CONCURRENT_UPDATE",
                          "并发修改同一记录时避免更新丢失，需要加锁（应用层/缓存层/数据库乐观锁）",
                          Severity.WARNING, line=i)

        # 7.18 HashMap resize dead link (reference)
        for path, node in tree:
            if isinstance(node, javalang.tree.VariableDeclaration):
                vtype = str(getattr(node, "type", ""))
                if "HashMap" in vtype and "ConcurrentHashMap" not in vtype:
                    mods = node.modifiers or []
                    if "static" in mods and "final" in mods:
                        for decl in node.declarators:
                            l, c = self._pos(decl)
                            self._add(file_path, "ALIBABA_HASHMAP_RESIZE",
                                      "HashMap 在容量不够进行 resize 时由于高并发可能出现死链，导致 CPU 飙升，高并发场景建议使用 ConcurrentHashMap",
                                      Severity.INFO, line=l, column=c)
                            break

        # 7.1 Singleton thread safety
        for path, node in tree:
            if isinstance(node, javalang.tree.MethodDeclaration) and \
               node.name in ("getInstance", "getSingleton") and \
               "static" in (node.modifiers or []) and \
               not any("synchronized" in str(a) or "synchronized" in (node.modifiers or [])
                       for a in ([node.modifiers] if isinstance(node.modifiers, list) else [])):
                l, c = self._pos(node)
                self._add(file_path, "ALIBABA_SINGLETON_THREAD_SAFE",
                          "获取单例对象需要保证线程安全，建议使用 synchronized 或双重检查锁",
                          Severity.WARNING, line=l, column=c)

        # 7.17 volatile without atomic for multi-write
        for path, node in tree:
            if isinstance(node, javalang.tree.FieldDeclaration) and \
               "volatile" in (node.modifiers or []):
                ft = getattr(node, "type", None)
                if ft and hasattr(ft, "name") and ft.name in ("int", "long", "boolean", "double"):
                    for decl in node.declarators:
                        l, c = self._pos(decl)
                        self._add(file_path, "ALIBABA_VOLATILE_ATOMIC",
                                  "volatile 解决多线程内存不可见问题，一写多读可用；多写场景需使用 Atomic 类或锁",
                                  Severity.INFO, line=l, column=c)
