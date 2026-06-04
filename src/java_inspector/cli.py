"""命令行入口 — 参数解析与执行编排"""
import argparse
import os

from java_inspector.config import InspectionConfig
from java_inspector.inspector import JavaCodeInspector
from java_inspector.reporter import InspectionReporter
from java_inspector.ci_cd import CICDIntegrator
from java_inspector.hooks import install_git_hook
from java_inspector.models import ReportFormat


def main():
    parser = argparse.ArgumentParser(description="增强版Java代码质量检查工具")
    parser.add_argument(
        "path", nargs="?", default=".", help="要检查的Java文件或目录路径"
    )
    parser.add_argument("--config", "-c", help="配置文件路径")
    parser.add_argument("--output", "-o", help="输出报告文件")
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "xml", "html", "csv"],
        default="text",
        help="报告格式",
    )
    parser.add_argument("--fix", action="store_true", help="自动修复可修复的问题")
    parser.add_argument(
        "--ci-cd", action="store_true", help="CI/CD模式，会返回适当的退出代码"
    )
    parser.add_argument("--install-hook", action="store_true", help="安装Git预提交钩子")

    args = parser.parse_args()

    if args.install_hook:
        install_git_hook()
        return

    config = InspectionConfig(args.config)
    inspector = JavaCodeInspector(config)
    reporter = InspectionReporter()
    ci_cd = CICDIntegrator(config)

    if args.fix:
        if os.path.isfile(args.path) and args.path.endswith(".java"):
            fixed_issues = inspector.auto_fix_issues(args.path)
            print(f"修复了 {len(fixed_issues)} 个问题")
        else:
            print("自动修复目前只支持单个文件")
        return

    if os.path.isfile(args.path):
        if not args.path.endswith(".java"):
            print(f"警告: '{args.path}' 不是Java文件，尝试解析...")
        issues = inspector.inspect_file(args.path)
        issues_by_file = {args.path: issues}
    elif os.path.isdir(args.path):
        issues_by_file = inspector.inspect_directory(args.path)
        if not issues_by_file:
            print(f"警告: 目录 '{args.path}' 中没有找到Java文件")
            return
    else:
        print(f"错误: 路径不存在: {args.path}")
        return

    report = reporter.generate_report(
        issues_by_file, ReportFormat(args.format), args.output
    )

    if not args.output:
        print(report)

    if args.ci_cd:
        ci_cd.check_quality_gate(issues_by_file)
        exit(ci_cd.get_exit_code())
