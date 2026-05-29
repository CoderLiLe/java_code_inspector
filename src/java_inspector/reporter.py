import json
import xml.etree.ElementTree as ET
from dataclasses import asdict
from typing import Dict, List

try:
    from jinja2 import Template
except ImportError:
    Template = None

from java_inspector.models import CodeIssue, Severity, ReportFormat


class InspectionReporter:
    @staticmethod
    def generate_report(
        issues_by_file: Dict[str, List[CodeIssue]],
        format: ReportFormat = ReportFormat.TEXT,
        output_file: str = None,
    ) -> str:
        if format == ReportFormat.JSON:
            return InspectionReporter.generate_json_report(issues_by_file, output_file)
        elif format == ReportFormat.XML:
            return InspectionReporter.generate_xml_report(issues_by_file, output_file)
        elif format == ReportFormat.HTML:
            return InspectionReporter.generate_html_report(issues_by_file, output_file)
        elif format == ReportFormat.CSV:
            return InspectionReporter.generate_csv_report(issues_by_file, output_file)
        else:
            return InspectionReporter.generate_text_report(issues_by_file, output_file)

    @staticmethod
    def generate_text_report(
        issues_by_file: Dict[str, List[CodeIssue]], output_file: str = None
    ) -> str:
        report = []
        total_issues = 0
        severity_counts = {severity: 0 for severity in Severity}

        for file_path, issues in issues_by_file.items():
            if issues:
                report.append(f"\n{'='*80}")
                report.append(f"文件: {file_path}")
                report.append(f"{'='*80}")

                for issue in issues:
                    total_issues += 1
                    severity_counts[issue.severity] += 1
                    fixable = " [可修复]" if issue.fixable else ""
                    report.append(
                        f"{issue.severity.value}: {issue.message}{fixable}"
                        f" (行{issue.line}, 列{issue.column})"
                    )

        report.append(f"\n{'='*80}")
        report.append("统计信息:")
        report.append(f"总问题数: {total_issues}")
        for severity, count in severity_counts.items():
            report.append(f"{severity.value}: {count}")
        report.append(f"{'='*80}")

        report_text = "\n".join(report)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_text)

        return report_text

    @staticmethod
    def generate_json_report(
        issues_by_file: Dict[str, List[CodeIssue]], output_file: str = None
    ) -> str:
        report_data = {
            "summary": {
                "total_files": len(issues_by_file),
                "total_issues": sum(len(issues) for issues in issues_by_file.values()),
                "severity_counts": {severity.value: 0 for severity in Severity},
            },
            "files": {},
        }

        for file_path, issues in issues_by_file.items():
            report_data["files"][file_path] = []
            for issue in issues:
                issue_dict = asdict(issue)
                issue_dict["severity"] = issue.severity.value
                report_data["files"][file_path].append(issue_dict)
                report_data["summary"]["severity_counts"][issue.severity.value] += 1

        json_data = json.dumps(report_data, ensure_ascii=False, indent=2)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_data)

        return json_data

    @staticmethod
    def generate_xml_report(
        issues_by_file: Dict[str, List[CodeIssue]], output_file: str = None
    ) -> str:
        root = ET.Element("codeInspection")
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "totalFiles").text = str(len(issues_by_file))
        ET.SubElement(summary, "totalIssues").text = str(
            sum(len(issues) for issues in issues_by_file.values())
        )

        files_elem = ET.SubElement(root, "files")
        for file_path, issues in issues_by_file.items():
            file_elem = ET.SubElement(files_elem, "file")
            ET.SubElement(file_elem, "path").text = file_path
            issues_elem = ET.SubElement(file_elem, "issues")
            for issue in issues:
                issue_elem = ET.SubElement(issues_elem, "issue")
                ET.SubElement(issue_elem, "line").text = str(issue.line)
                ET.SubElement(issue_elem, "column").text = str(issue.column)
                ET.SubElement(issue_elem, "message").text = issue.message
                ET.SubElement(issue_elem, "severity").text = issue.severity.value
                ET.SubElement(issue_elem, "ruleId").text = issue.rule_id
                ET.SubElement(issue_elem, "category").text = issue.category

        xml_str = ET.tostring(root, encoding="unicode", method="xml")

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(xml_str)

        return xml_str

    @staticmethod
    def generate_html_report(
        issues_by_file: Dict[str, List[CodeIssue]], output_file: str = None
    ) -> str:
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Java代码检查报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
                .file { margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }
                .file-header { background: #e9e9e9; padding: 10px; font-weight: bold; }
                .issue { padding: 8px; border-bottom: 1px solid #eee; }
                .ERROR { background: #ffebee; border-left: 4px solid #f44336; }
                .WARNING { background: #fff8e1; border-left: 4px solid #ffc107; }
                .INFO { background: #e8f5e8; border-left: 4px solid #4caf50; }
            </style>
        </head>
        <body>
            <h1>Java代码检查报告</h1>
            <div class="summary">
                <h2>统计信息</h2>
                <p>总文件数: {{ total_files }}</p>
                <p>总问题数: {{ total_issues }}</p>
                {% for severity, count in severity_counts.items() %}
                <p>{{ severity }}: {{ count }}</p>
                {% endfor %}
            </div>

            {% for file_path, issues in files.items() %}
            <div class="file">
                <div class="file-header">{{ file_path }}</div>
                <div class="issues">
                    {% for issue in issues %}
                    <div class="issue {{ issue.severity }}">
                        <strong>{{ issue.severity }}</strong>: {{ issue.message }}<br>
                        <small>行: {{ issue.line }}, 列: {{ issue.column }}</small>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
        </body>
        </html>
        """

        total_issues = sum(len(issues) for issues in issues_by_file.values())
        severity_counts = {severity.value: 0 for severity in Severity}

        for issues in issues_by_file.values():
            for issue in issues:
                severity_counts[issue.severity.value] += 1

        template = Template(html_template)
        html_content = template.render(
            total_files=len(issues_by_file),
            total_issues=total_issues,
            severity_counts=severity_counts,
            files=issues_by_file,
        )

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content

    @staticmethod
    def generate_csv_report(
        issues_by_file: Dict[str, List[CodeIssue]], output_file: str = None
    ) -> str:
        csv_data = []
        headers = [
            "File",
            "Line",
            "Column",
            "Severity",
            "Rule",
            "Category",
            "Message",
            "Fixable",
        ]

        for file_path, issues in issues_by_file.items():
            for issue in issues:
                csv_data.append(
                    [
                        file_path,
                        issue.line,
                        issue.column,
                        issue.severity.value,
                        issue.rule_id,
                        issue.category,
                        issue.message,
                        "是" if issue.fixable else "否",
                    ]
                )

        csv_content = ",".join(headers) + "\n"
        for row in csv_data:
            escaped_row = [
                f'"{cell}"' if "," in str(cell) else str(cell) for cell in row
            ]
            csv_content += ",".join(escaped_row) + "\n"

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(csv_content)

        return csv_content
