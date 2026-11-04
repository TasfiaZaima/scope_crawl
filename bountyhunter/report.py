from datetime import datetime, timezone
from pathlib import Path

from .http import compact_json
from .models import TargetResult


def report_dict(scope_name: str, results: list[TargetResult]) -> dict:
    return {
        "program": scope_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [
            {
                "target": r.target,
                "urls": r.urls,
                "resolved_ips": r.resolved_ips,
                "observations": r.observations,
                "errors": r.errors,
                "findings": [f.__dict__ for f in r.findings],
            }
            for r in results
        ],
    }


def write_reports(directory: str | Path, scope_name: str, results: list[TargetResult]) -> tuple[Path, Path]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    payload = report_dict(scope_name, results)
    json_path = out / "report.json"
    md_path = out / "report.md"
    json_path.write_text(compact_json(payload) + "\n", encoding="utf-8")
    lines = [f"# ScopeCrawl report: {scope_name}", "", f"Generated: {payload['generated_at']}", "", "> Findings are hypotheses for manual verification on authorized targets.", ""]
    for target in payload["targets"]:
        lines += [f"## {target['target']}", "", f"- Resolved IPs: {', '.join(target['resolved_ips']) or 'none'}", f"- URLs checked: {', '.join(target['urls']) or 'none'}", ""]
        if target["errors"]:
            lines += ["### Errors", ""] + [f"- {e}" for e in target["errors"]] + [""]
        lines += ["### Findings", ""]
        if not target["findings"]:
            lines.append("No findings.")
        for finding in target["findings"]:
            lines += [f"#### [{finding['severity'].upper()}] {finding['title']}", "", f"- Check: `{finding['check']}`", f"- Confidence: {finding['confidence']}", f"- Target: `{finding['target']}`", f"- Evidence: `{finding['evidence']}`", f"- Remediation: {finding['remediation']}", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
