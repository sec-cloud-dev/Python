"""Command line entry point.

    python -m src.cli scan --fixture tests/fixtures/public_bucket.json --fail-on high
    python -m src.cli scan --fail-on high            # live Yandex Cloud, uses .env

Exit codes: 0 - ok, 1 - findings at or above --fail-on (or checks that could not complete), 2 - scan failed.
"""
import argparse
import json
import logging
import sys

from src.utils.models import FOLDER_SCOPE, SEVERITY_RANK, ScanResult, Severity

logger = logging.getLogger(__name__)

FAIL_ON_CHOICES = ("high", "medium", "low", "never")


def should_fail(result: ScanResult, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_RANK[Severity(fail_on)]
    return any(
        f.severity is Severity.UNKNOWN or SEVERITY_RANK[f.severity] >= threshold
        for f in result.findings
    )


def _format_text(result: ScanResult) -> str:
    lines = []
    for bucket, findings in result.buckets.items():
        lines.append(f"Бакет {bucket}")
        lines += [f"  {f.severity.value.upper():8} {f.rule_id:22} {f.message}" for f in findings]
    lines.append(f"Папка {result.folder_id} ({FOLDER_SCOPE}): IAM на уровне folder/cloud/organization, "
                 f"действует на все бакеты; bucket-level bindings не запрашивались")
    lines += [f"  {f.severity.value.upper():8} {f.rule_id:22} {f.message}" for f in result.folder_findings]
    totals = {s.value: 0 for s in Severity}
    for f in result.findings:
        totals[f.severity.value] += 1
    lines.append("Итого: " + " ".join(f"{name}={count}" for name, count in totals.items()))
    return "\n".join(lines)


def _run_scan(args: argparse.Namespace) -> ScanResult:
    from src.scanner import live_scan, scan

    if args.fixture:
        from src.fixture import load_fixture

        s3_client, inventory, bucket_names = load_fixture(args.fixture)
        return scan(s3_client, inventory, bucket_names)

    from src.config import cloud_id, folder_id, validate_configuration

    validate_configuration()
    return live_scan(str(folder_id), str(cloud_id))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bucket-scanner", description="Yandex Object Storage security scanner")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_cmd = commands.add_parser("scan", help="Просканировать бакеты")
    scan_cmd.add_argument("--fixture", help="JSON-fixture вместо живого Yandex Cloud API")
    scan_cmd.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="never",
                          help="Ненулевой код выхода при находках этого уровня и выше или незавершённых проверках")
    scan_cmd.add_argument("--format", choices=("text", "json"), default="text")
    scan_cmd.add_argument("-v", "--verbose", action="store_true", help="Подробные логи проверок")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.ERROR,
                        format="%(asctime)s - %(levelname)s - %(message)s", stream=sys.stderr)

    try:
        result = _run_scan(args)
    except Exception as exc:
        logger.error("Сканирование не выполнено: %s", exc)
        return 2

    if args.format == "json":
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str))
    else:
        print(_format_text(result))

    return 1 if should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
