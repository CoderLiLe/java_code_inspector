"""Git 钩子 — 安装 pre-commit 钩子"""
import logging
import os
import subprocess

logger = logging.getLogger(__name__)


def install_git_hook():
    hook_content = """#!/bin/bash
# Java代码检查Git钩子
echo "运行Java代码检查..."
python -m java_inspector . --ci-cd
if [ $? -ne 0 ]; then
    echo "代码检查失败，请修复问题后再提交"
    exit 1
fi
echo "代码检查通过"
exit 0
"""

    git_dir = subprocess.run(
        ["git", "rev-parse", "--git-dir"], capture_output=True, text=True
    ).stdout.strip()
    hook_path = os.path.join(git_dir, "hooks", "pre-commit")

    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(hook_content)

    os.chmod(hook_path, 0o755)
    logger.info("Git预提交钩子安装完成")
