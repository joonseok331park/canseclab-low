#!/usr/bin/env python3
"""Offline checks for cansec-detect --summary report output and option handling."""

from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import uuid


RULES = {
    "UNKNOWN_ID": "HIGH", "DLC_MISMATCH": "HIGH", "PERIOD_VIOLATION": "MEDIUM",
    "RATE_SPIKE": "HIGH", "FIXED_BYTE_VIOLATION": "MEDIUM", "REPLAY_BURST": "HIGH",
}
HEADINGS = ["Run Metadata", "Input Summary", "Alert Summary", "First Alerts",
            "Interpretation", "Limitations"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture_rules():
    return ("[global]\nwindow_ms=100\n[id:0x100]\nid_type=standard\nallowed_dlc=4\n"
            "periodic=0\nperiod_min_us=0\nperiod_max_us=0\nrate_limit_100ms=1000\n"
            "fixed_mask=00FF000000000000\nfixed_value=0010000000000000\n"
            "ignore_mask=0000000000000000\nmax_identical_payload_run=3\n")


def parse_report(path):
    """Parse report fields and sections from the Markdown text."""
    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith("# CANSecLab-Low Detection Report\n"):
        raise RuntimeError("missing report title")
    sections = {}
    for heading in HEADINGS:
        match = re.search(r"^## " + re.escape(heading) + r"\s*\n(.*?)(?=^## |\Z)",
                          text, re.MULTILINE | re.DOTALL)
        if match is None:
            raise RuntimeError("missing report section: " + heading)
        sections[heading] = match.group(1)
    fields = {}
    for line in text.splitlines():
        match = re.match(r"^- ([^:]+):\s*(.*)$", line)
        if match:
            key, value = match.groups()
            if key in fields:
                raise RuntimeError("duplicate report field: " + key)
            fields[key] = html.unescape(value.strip().strip("`"))
    counts = {}
    for line in sections["Alert Summary"].splitlines():
        cells = [html.unescape(cell.strip().strip("`")) for cell in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0] in RULES:
            rule, severity, count = cells
            if rule in counts or severity != RULES[rule] or not count.isdigit():
                raise RuntimeError("invalid or duplicate rule row: " + line)
            counts[rule] = int(count)
    if set(counts) != set(RULES):
        raise RuntimeError("the report must list all six rules, including zero counts")
    first = []
    for line in sections["First Alerts"].splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [html.unescape(cell.strip().strip("`")) for cell in line.strip().strip("|").split("|")]
        if cells and cells[0].isdigit():
            if len(cells) != 7 or not cells[1].isdigit() or cells[4] not in RULES:
                raise RuntimeError("invalid first-alert row: " + line)
            first.append(dict(zip(["capture_ts_us", "alert_ts_us", "id_type", "can_id",
                                   "rule", "severity", "detail"], cells)))
    if len(first) > 10:
        raise RuntimeError("report contains more than ten first-alert examples")
    return {"text": text, "sections": sections, "fields": fields,
            "counts": counts, "first_alerts": first}


def verify_report(path, expected_frames, expected_counts, mode, rules_hash,
                  unique_ids, first_timestamp=None, last_timestamp=None,
                  input_hash=None, jsonl_hash=None, termination=None):
    report = parse_report(path)
    fields = report["fields"]
    expected = {rule: expected_counts.get(rule, 0) for rule in RULES}
    if report["counts"] != expected:
        raise RuntimeError(f"rule counts differ: expected {expected}, observed {report['counts']}")
    total = sum(expected.values())
    for key, value in {"Total frames processed": expected_frames,
                       "Unique CAN IDs observed": unique_ids, "Total alerts": total}.items():
        if fields.get(key) != str(value):
            raise RuntimeError(f"{key}: expected {value}, observed {fields.get(key)!r}")
    if fields.get("Mode") != mode or fields.get("Rules SHA256") != rules_hash:
        raise RuntimeError("mode or rules SHA256 does not match the executed inputs")
    if re.fullmatch(r"[0-9a-fA-F]{64}", fields.get("Source SHA256", "")) is None:
        raise RuntimeError("source fingerprint is not a SHA256 value")
    for key in ("Run time", "Git commit", "Build type", "Compiler", "OS", "Kernel",
                "Interface", "Rules file", "Termination reason"):
        if not fields.get(key):
            raise RuntimeError("missing run metadata: " + key)
    if termination is not None and fields["Termination reason"] != termination:
        raise RuntimeError("wrong termination reason: " + fields["Termination reason"])
    for key, value in (("First frame timestamp", first_timestamp),
                       ("Last frame timestamp", last_timestamp)):
        if expected_frames == 0:
            if not fields.get(key, "").startswith("N/A"):
                raise RuntimeError("no-frame report invents a timestamp: " + key)
        elif value is not None:
            if fields.get(key) != str(value):
                raise RuntimeError(f"{key}: expected {value}, observed {fields.get(key)!r}")
        elif not fields.get(key, "").isdigit():
            raise RuntimeError("nonempty input is missing a numeric timestamp: " + key)
    if input_hash is not None:
        if fields.get("Input SHA256") != input_hash:
            raise RuntimeError("offline input SHA256 differs from the actual input bytes")
    elif mode == "live":
        for key in ("Input file", "Input SHA256"):
            if not fields.get(key, "").startswith("N/A"):
                raise RuntimeError("live report invents a source input file: " + key)
    if jsonl_hash is not None:
        if fields.get("Alerts JSONL SHA256") != jsonl_hash:
            raise RuntimeError("JSONL SHA256 differs from the saved alert output")
    elif mode == "offline":
        if not fields.get("Alerts JSONL SHA256", "").startswith("N/A"):
            raise RuntimeError("offline report invents a JSONL output hash")
    if len(report["first_alerts"]) != min(total, 10):
        raise RuntimeError("first-alert examples do not contain the first min(total,10) alerts")
    if not report["sections"]["Interpretation"].strip() or not report["sections"]["Limitations"].strip():
        raise RuntimeError("interpretation or limitations section is empty")
    return report


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_detect_report_cli.py DETECT_EXE OUTPUT_PARENT")
    executable = str(Path(sys.argv[1]).resolve())
    output_parent = Path(sys.argv[2]).resolve()
    output_parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="report-cli-", dir=output_parent))
    result = {"status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "python": sys.version, "run_directory": str(directory),
              "detect_path": executable, "detect_sha256": sha256(executable),
              "script_sha256": sha256(__file__), "checks": [], "commands": []}
    rules = directory / "rules.ini"
    rules.write_text(fixture_rules(), encoding="ascii", newline="\n")
    normal = directory / "normal.log"
    normal.write_text("".join(f"(1.{index * 10000:06d}) old0 100#{index:02X}100000\n"
                              for index in range(3)), encoding="ascii", newline="\n")
    protected = {rules: sha256(rules), normal: sha256(normal)}
    missing_interface = "cs" + uuid.uuid4().hex[:8]
    existing_alerts = directory / "existing.jsonl"
    existing_alerts.write_bytes(b"previous alert output must survive rejection\n")
    protected[existing_alerts] = sha256(existing_alerts)

    def check(name, action):
        item = {"name": name, "passed": False}
        result["checks"].append(item)
        try:
            action(item)
            for path, expected in protected.items():
                if sha256(path) != expected:
                    raise RuntimeError("protected input/output changed: " + str(path))
            item["passed"] = None if item.get("skipped") else True
        except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
            item["error"] = str(error)
        print(("SKIP " if item.get("skipped") else "PASS " if item["passed"] else "FAIL ") + name,
              flush=True)

    def invoke(name, args):
        command = [executable] + [str(arg) for arg in args]
        start = time.monotonic()
        process = subprocess.run(command, cwd=directory, capture_output=True, timeout=8)
        stdout = directory / (name + ".stdout.txt")
        stderr = directory / (name + ".stderr.txt")
        stdout.write_bytes(process.stdout)
        stderr.write_bytes(process.stderr)
        record = {"command": command, "cwd": str(directory), "returncode": process.returncode,
                  "stdout": stdout.name, "stdout_sha256": sha256(stdout), "stderr": stderr.name,
                  "stderr_sha256": sha256(stderr), "elapsed_seconds": round(time.monotonic() - start, 6)}
        result["commands"].append(record)
        return process

    def offline(log=normal, policy=rules):
        return ["--rules", policy, "--check-log", log]

    def live(summary):
        return ["--rules", rules, "--if", missing_interface, "--out", existing_alerts,
                "--max-frames", "1", "--summary", summary]

    def failure(name, args, preserved=(), diagnostic=None):
        before = {Path(path): sha256(path) for path in preserved}
        process = invoke(name, args)
        stderr = process.stderr.decode("utf-8", "replace")
        if process.returncode != 1 or process.stdout or "cansec-detect:" not in stderr:
            raise RuntimeError("rejected invocation did not fail cleanly with empty stdout")
        if "Processed " in stderr or "Detecting CAN frames" in stderr:
            raise RuntimeError("preflight failure reached live detection or printed success")
        if "SIOCGIFINDEX" in stderr or "Live detection requires Linux" in stderr:
            raise RuntimeError("invalid summary reached socket/platform startup")
        if diagnostic is not None and re.search(diagnostic, stderr, re.IGNORECASE) is None:
            raise RuntimeError("failure did not identify the expected error: " + stderr)
        for path, expected in before.items():
            if sha256(path) != expected:
                raise RuntimeError("rejection changed existing file: " + str(path))
        return stderr

    def success(item, name, log, frames, counts, timestamps, unique=1, first_rules=None):
        summary = directory / (name + ".md")
        summary.write_bytes(b"previous report\n")
        input_hash = sha256(log)
        process = invoke(name, offline(log) + ["--summary", summary])
        if process.returncode != 0 or process.stderr:
            raise RuntimeError("valid offline report invocation failed or wrote stderr")
        expected_tail = (f"Checked {frames} frames using {','.join(RULES)} only; "
                         f"{sum(counts.values())} alerts.\n").encode("ascii")
        # Windows stdout uses CRLF; normalize newlines only.
        if not process.stdout.replace(b"\r\n", b"\n").endswith(expected_tail):
            raise RuntimeError("existing offline stdout summary changed")
        report = verify_report(summary, frames, counts, "offline", sha256(rules), unique,
                               timestamps[0], timestamps[1], input_hash=input_hash,
                               termination="end_of_log")
        for label, original_path in (("Rules file", rules), ("Input file", log)):
            if report["fields"].get(label) != str(original_path):
                raise RuntimeError("reported Unicode path differs from the actual argument: " + label)
        if sha256(log) != input_hash:
            raise RuntimeError("offline input was modified")
        if first_rules is not None and [row["rule"] for row in report["first_alerts"]] != first_rules[:10]:
            raise RuntimeError("first-alert order differs from detection order")
        item.update({"report": summary.name, "report_sha256": sha256(summary),
                     "input_sha256": input_hash, "fields": report["fields"],
                     "rule_counts": report["counts"], "first_alerts": report["first_alerts"],
                     "reported_input_paths_match": True})

    check("offline_three_frames_zero_alerts", lambda item:
          success(item, "normal", normal, 3, {}, (1000000, 1020000)))
    multiple = directory / "multiple.log"
    multiple.write_text("".join(f"(1.{index * 10000:06d}) old0 100#00220000\n"
                                for index in range(4)), encoding="ascii", newline="\n")
    check("offline_one_frame_can_have_multiple_alerts", lambda item:
          success(item, "multiple", multiple, 4, {"FIXED_BYTE_VIOLATION": 4, "REPLAY_BURST": 1},
                  (1000000, 1030000), first_rules=["FIXED_BYTE_VIOLATION"] * 4 + ["REPLAY_BURST"]))
    many = directory / "many.log"
    many.write_text("".join(f"(2.{index * 1000:06d}) old0 555#{index:02X}\n"
                            for index in range(12)), encoding="ascii", newline="\n")

    def bounded_examples(item):
        success(item, "many", many, 12, {"UNKNOWN_ID": 12}, (2000000, 2011000),
                first_rules=["UNKNOWN_ID"] * 12)
        observed = [int(row["capture_ts_us"]) for row in item["first_alerts"]]
        if observed != [2000000 + index * 1000 for index in range(10)]:
            raise RuntimeError("first-alert table is not the first ten capture timestamps")

    check("first_alert_examples_are_capped_at_ten", bounded_examples)
    typed = directory / "typed.log"
    typed.write_text("(3.000000) old0 100#00100000\n(3.001000) old0 00000100#00100000\n",
                     encoding="ascii", newline="\n")
    check("standard_and_extended_same_number_are_distinct_ids", lambda item:
          success(item, "typed", typed, 2, {"UNKNOWN_ID": 1}, (3000000, 3001000), unique=2,
                  first_rules=["UNKNOWN_ID"]))

    def legacy(item):
        process = invoke("without-summary", offline())
        expected = f"Checked 3 frames using {','.join(RULES)} only; 0 alerts.\n".encode("ascii")
        if process.returncode != 0 or process.stderr or process.stdout.replace(b"\r\n", b"\n") != expected:
            raise RuntimeError("offline detection without --summary changed")
        item["summary_created"] = False

    check("summary_remains_optional", legacy)
    for name, content in [
        ("empty", "# no data frames\n\n"),
        ("malformed-tail", normal.read_text(encoding="ascii") + "not a CAN log\n"),
        ("backward-known-id", "(2.000000) old0 100#00100000\n(1.000000) old0 100#00220000\n"),
    ]:
        def invalid_log(item, name=name, content=content):
            log = directory / (name + ".log")
            log.write_text(content, encoding="ascii", newline="\n")
            summary = directory / (name + ".md")
            summary.write_bytes(b"previous report survives invalid input\n")
            failure(name, offline(log) + ["--summary", summary], [log, summary])
            item["preserved_report_sha256"] = sha256(summary)
        check(name + "_preserves_existing_report", invalid_log)

    def bad_rules(item):
        policy = directory / "invalid.ini"
        policy.write_text("[global]\nwindow_ms=99\n", encoding="ascii")
        summary = directory / "invalid-rules.md"
        summary.write_bytes(b"previous report\n")
        failure("invalid-rules", offline(policy=policy) + ["--summary", summary], [policy, summary])

    check("invalid_rules_preserve_report", bad_rules)
    untouched = directory / "rejected.md"
    untouched.write_bytes(b"previous summary must survive rejected options\n")
    protected[untouched] = sha256(untouched)
    invalid_variants = [
        ("missing-summary-value", offline() + ["--summary"], "requires"),
        ("empty-summary-value", offline() + ["--summary", ""], "requires"),
        ("option-as-summary-value", offline() + ["--summary", "--max-frames", "1"], "requires"),
        ("duplicate-summary", offline() + ["--summary", untouched, "--summary", untouched], "duplicate"),
        ("validate-plus-summary", ["--rules", rules, "--validate-rules", "--summary", untouched], "summary|combined"),
        ("mixed-offline-live", offline() + ["--summary", untouched, "--if", missing_interface,
                                           "--out", existing_alerts], "combined"),
        ("offline-live-zero-limit", offline() + ["--summary", untouched, "--max-frames", "0"], "combined"),
        ("summary-without-mode", ["--rules", rules, "--summary", untouched], "required"),
        ("missing-input", offline(directory / "absent.log") + ["--summary", untouched], None),
    ]
    for name, args, diagnostic in invalid_variants:
        check(name, lambda item, name=name, args=args, diagnostic=diagnostic:
              failure(name, args, [untouched, existing_alerts], diagnostic))

    if sys.platform == "linux":
        def nonregular_alerts(item):
            args = ["--rules", rules, "--if", missing_interface, "--out", "/dev/zero",
                    "--summary", untouched, "--max-seconds", "1"]
            failure("nonregular-alerts", args, [untouched], "regular")
            item["nonregular_path"] = "/dev/zero"
            item["must_fail_before_socket_and_hashing"] = True
        check("summary_rejects_nonregular_jsonl_before_hashing", nonregular_alerts)

        def stdout_failure(item):
            command = [executable] + [str(arg) for arg in offline() + ["--summary", untouched]]
            start = time.monotonic()
            with open("/dev/full", "wb") as sink:
                process = subprocess.run(command, cwd=directory, stdout=sink, stderr=subprocess.PIPE, timeout=8)
            stderr = directory / "stdout-failure.stderr.txt"
            stderr.write_bytes(process.stderr)
            result["commands"].append({"command": command, "cwd": str(directory),
                                       "returncode": process.returncode, "stdout_sink": "/dev/full",
                                       "stderr": stderr.name, "stderr_sha256": sha256(stderr),
                                       "elapsed_seconds": round(time.monotonic() - start, 6)})
            if process.returncode != 1 or b"cansec-detect:" not in process.stderr:
                raise RuntimeError("offline stdout write failure did not return failure")
            if sha256(untouched) != protected[untouched]:
                raise RuntimeError("offline stdout failure replaced the previous report")
            item["previous_report_sha256"] = sha256(untouched)
        check("offline_stdout_failure_preserves_report", stdout_failure)

    invalid_directory = directory / "directory-summary"
    invalid_directory.mkdir()
    missing_parent = directory / "missing-parent" / "report.md"
    for mode, args_for in [("offline", lambda summary: offline() + ["--summary", summary]), ("live", live)]:
        for label, summary in [("missing-parent", missing_parent), ("directory", invalid_directory)]:
            def invalid_target(item, mode=mode, args_for=args_for, label=label, summary=summary):
                failure(mode + "-" + label, args_for(summary), [existing_alerts])
                if missing_parent.parent.exists() or list(invalid_directory.iterdir()):
                    raise RuntimeError("invalid summary target created or changed directories")
            check(mode + "_invalid_summary_" + label, invalid_target)

    dotdir = directory / "dotdir"
    dotdir.mkdir()
    for target_name, target in [("rules", rules), ("input", normal), ("alerts", existing_alerts)]:
        for kind in ("same", "normalized", "hardlink", "symlink"):
            def alias(item, target_name=target_name, target=target, kind=kind):
                name = "alias-" + target_name + "-" + kind
                summary = target
                if kind == "normalized":
                    summary = dotdir / ".." / target.name
                elif kind in ("hardlink", "symlink"):
                    summary = directory / (name + ".md")
                    try:
                        if kind == "hardlink":
                            os.link(target, summary)
                        else:
                            summary.symlink_to(target.name)
                    except (NotImplementedError, OSError) as error:
                        item.update({"skipped": True, "reason": f"{kind} unavailable: {error}"})
                        return
                args = live(summary) if target_name == "alerts" else offline() + ["--summary", summary]
                failure(name, args, [target, summary, existing_alerts], "alias")
                item["preserved_sha256"] = sha256(target)
            check("summary_" + target_name + "_" + kind + "_alias", alias)

    def case_alias(item):
        if sys.platform != "win32":
            item.update({"skipped": True, "reason":
                         "on Linux this is covered by scripts/verify_report_linux.py"})
            return
        probe = directory / "CaseProbe"
        probe.write_bytes(b"case probe\n")
        if not (directory / "caseprobe").exists():
            item.update({"skipped": True, "reason": "fixture filesystem is case-sensitive"})
            return
        alerts = directory / "FreshAlerts.jsonl"
        summary = directory / "freshalerts.jsonl"
        args = ["--rules", rules, "--if", missing_interface, "--out", alerts,
                "--summary", summary, "--max-frames", "1"]
        failure("fresh-case-alias", args, diagnostic="alias")
        if alerts.exists() or summary.exists():
            raise RuntimeError("fresh case-variant output aliases created files")
        item["case_insensitive_filesystem"] = True

    check("fresh_case_variant_output_alias", case_alias)
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    result["checks_total"] = len(result["checks"])
    result["checks_passed"] = sum(item["passed"] is True for item in result["checks"])
    result["checks_skipped"] = sum(bool(item.get("skipped")) for item in result["checks"])
    failed = sum(item["passed"] is False for item in result["checks"])
    result["status"] = "failed" if failed else "passed"
    result["artifact_sha256"] = {path.name: sha256(path) for path in sorted(directory.iterdir())
                                 if path.is_file()}
    (directory / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                           encoding="utf-8", newline="\n")
    print(f"{result['checks_total']} report CLI checks; {failed} failure(s); "
          f"{result['checks_skipped']} skipped.")
    print("Results: " + str(directory / "result.json"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
