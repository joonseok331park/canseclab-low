#!/usr/bin/env python3
"""Verify live detection reports on an existing idle vcan (run as a non-root user)."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import stat
import struct
import sys
import tempfile
import time

from verify_detect_linux import execute, frame, require_vcan, sha256, write_json

# Reuse the report parser from the offline CLI test; expected values come from here.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from test_detect_report_cli import fixture_rules, verify_report  # noqa: E402


def verify(args, run_dir, result):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("run live report verification as an ordinary Linux user, not root")
    detect = Path(args.detect).resolve()
    if not detect.is_file() or not os.access(detect, os.X_OK):
        raise RuntimeError("--detect must name an executable Linux cansec-detect binary")
    ip_command = shutil.which("ip")
    if ip_command is None:
        raise RuntimeError("ip is required to verify the requested interface is vcan")
    interface = args.interface
    link = require_vcan(ip_command, interface, run_dir, result, "interface-before")
    result["interface_details"] = link
    rules = run_dir / "report-rules.ini"
    rules.write_text(fixture_rules(), encoding="ascii", newline="\n")
    rules_hash = sha256(rules)
    result["rules"] = {"path": rules.name, "sha256": rules_hash}

    def check(name, action):
        item = {"name": name, "passed": False}
        result["checks"].append(item)
        try:
            action(item)
            if sha256(rules) != rules_hash:
                raise RuntimeError("detection modified the baseline input")
            item["passed"] = True
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            item["error"] = str(error)
        print(("PASS " if item["passed"] else "FAIL ") + name, flush=True)

    def ready(alerts):
        return f"Detecting CAN frames from {interface} -> {alerts}\n"

    def command(alerts, summary, extra=()):
        return [str(detect), "--rules", str(rules), "--if", interface, "--out", str(alerts),
                "--summary", str(summary)] + list(extra)

    def send_frames(name, frames):
        requested = {"interface": interface, "initial_ifindex": link["ifindex"],
                     "expected_frames": frames, "sent_frames": []}
        manifest = run_dir / (name + ".frames.json")
        try:
            current = require_vcan(ip_command, interface, run_dir, result, name + "-interface-before-send")
            if current["ifindex"] != link["ifindex"]:
                raise RuntimeError("vcan interface identity changed before transmission")
            with socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as sender:
                sender.settimeout(1)
                sender.bind((interface,))
                for index, source in enumerate(frames):
                    if socket.if_nametoindex(interface) != link["ifindex"]:
                        raise RuntimeError("vcan interface identity changed during transmission")
                    packet = struct.pack("=IB3x8s", source["raw_id"], source["dlc"],
                                         bytes.fromhex(source["data"]).ljust(8, b"\0"))
                    measurement = {"index": index, "packet_hex": packet.hex().upper(),
                                   "packet_sha256": hashlib.sha256(packet).hexdigest(),
                                   "before_us": time.time_ns() // 1000,
                                   "before_monotonic_ns": time.monotonic_ns()}
                    count = sender.send(packet)
                    measurement.update({"after_us": time.time_ns() // 1000,
                                        "after_monotonic_ns": time.monotonic_ns(), "sent_bytes": count})
                    requested["sent_frames"].append(measurement)
                    if count != 16:
                        raise RuntimeError("incomplete Classical CAN transmission")
        finally:
            write_json(manifest, requested)
            result["inputs"].append({"path": manifest.name, "sha256": sha256(manifest)})

    def successful(completed, alerts, processed, expected_count):
        if completed["returncode"] != 0:
            raise RuntimeError("live detection failed with exit " + str(completed["returncode"]))
        if (run_dir / completed["stdout"]).read_bytes():
            raise RuntimeError("live detection unexpectedly wrote stdout")
        stderr = (run_dir / completed["stderr"]).read_text(encoding="utf-8")
        expected = f"Processed {processed} frame(s); {expected_count} alert(s).\n"
        if not stderr.startswith(ready(alerts)) or expected not in stderr:
            raise RuntimeError("live readiness or completion counts are incorrect")

    def alert_rows(alerts):
        content = alerts.read_bytes()
        if content and not content.endswith(b"\n"):
            raise RuntimeError("JSONL output has an incomplete last record")
        return [json.loads(line) for line in content.decode("utf-8").splitlines()]

    def inspect(item, name, alerts, summary, completed, processed, expected, termination):
        rows = alert_rows(alerts)
        actual = Counter(row["rule"] for row in rows)
        if actual != Counter(expected):
            raise RuntimeError(f"JSONL counts differ: expected {expected}, observed {dict(actual)}")
        for row in rows:
            capture, decision = row["capture_ts_us"], row["alert_ts_us"]
            if row["if"] != interface or type(capture) is not int or type(decision) is not int:
                raise RuntimeError("JSONL interface or timestamp types are incorrect")
            if not completed["started_us"] - 1000000 <= capture <= decision <= completed["finished_us"] + 1000000:
                raise RuntimeError("JSONL timestamps are outside the run or reversed")
        report = verify_report(summary, processed, expected, "live", rules_hash,
                               1 if processed else 0, jsonl_hash=sha256(alerts), termination=termination)
        fields = report["fields"]
        if fields["Interface"] != interface:
            raise RuntimeError("report interface differs from the verified vcan")
        if processed:
            first, last = int(fields["First frame timestamp"]), int(fields["Last frame timestamp"])
            if not completed["started_us"] - 1000000 <= first <= last <= completed["finished_us"] + 1000000:
                raise RuntimeError("report frame timestamps are outside the run's start/end time")
            if rows and (first > min(row["capture_ts_us"] for row in rows) or
                         last < max(row["capture_ts_us"] for row in rows)):
                raise RuntimeError("report timestamp range excludes an alert frame")
        if len(rows) != len(report["first_alerts"]):
            raise RuntimeError("small live fixture did not preserve every first-alert example")
        for example, row in zip(report["first_alerts"], rows):
            for key in ("capture_ts_us", "alert_ts_us", "id_type", "can_id", "rule", "severity", "detail"):
                if example[key] != str(row[key]):
                    raise RuntimeError("Markdown first-alert example differs from JSONL: " + key)
        item.update({"processed_frames": processed, "alert_count": len(rows), "rule_counts": dict(actual),
                     "alerts": alerts.name, "alerts_sha256": sha256(alerts), "report": summary.name,
                     "report_sha256": sha256(summary), "report_fields": fields,
                     "first_alerts_equal_jsonl": True, "termination": termination})

    def live_case(item, name, frames, expected, extra, termination, signal_after=False):
        alerts = run_dir / (name + ".jsonl")
        summary = run_dir / (name + ".md")
        summary.write_bytes(b"previous report replaced only on success\n")

        def after_ready(process):
            if frames:
                send_frames(name, frames)
            if signal_after:
                time.sleep(0.15)
                process.send_signal(signal.SIGTERM)

        completed = execute(command(alerts, summary, extra), name, run_dir, result,
                            ready(alerts), after_ready, timeout=8)
        successful(completed, alerts, len(frames), sum(expected.values()))
        inspect(item, name, alerts, summary, completed, len(frames), expected, termination)
        return completed

    def idle(item):
        completed = live_case(item, "idle", [], {}, ["--max-seconds", "1"], "max_seconds")
        if not 0.8 <= completed["elapsed_seconds"] <= 5:
            raise RuntimeError("one-second idle run took longer or shorter than expected")

    normal = [frame(0x100, payload) for payload in ("00100000", "01100000", "02100000")]
    changed = [frame(0x100, "00220000")] * 4
    check("zero_frames_timeout_has_na_timestamps", idle)
    check("three_benign_frames_zero_alerts", lambda item:
          live_case(item, "normal", normal, {}, ["--max-frames", "3"], "max_frames"))
    check("four_changed_frames_five_alerts_match_jsonl", lambda item:
          live_case(item, "multiple", changed, {"FIXED_BYTE_VIOLATION": 4, "REPLAY_BURST": 1},
                    ["--max-frames", "4"], "max_frames"))
    check("sigterm_after_readiness_publishes_report", lambda item:
          live_case(item, "signal", [], {}, [], "signal", signal_after=True))

    def failure(completed, startup_forbidden=True):
        stderr = (run_dir / completed["stderr"]).read_text(encoding="utf-8", errors="replace")
        if completed["returncode"] != 1 or "cansec-detect:" not in stderr:
            raise RuntimeError("failed detection did not return exit 1 with an error")
        if (run_dir / completed["stdout"]).read_bytes() or "Processed " in stderr:
            raise RuntimeError("failed detection emitted successful output")
        if startup_forbidden and "Detecting CAN frames" in stderr:
            raise RuntimeError("invalid summary reached live readiness")
        return stderr

    def invalid_summary(item, kind):
        name = "invalid-summary-" + kind
        alerts = run_dir / (name + ".jsonl")
        alerts.write_bytes(b"existing JSONL must survive invalid summary preflight\n")
        before = sha256(alerts)
        if kind == "parent":
            summary = run_dir / "absent-parent" / "report.md"
        elif kind == "directory":
            summary = run_dir / "summary-directory"
            summary.mkdir()
        elif kind == "rules-alias":
            summary = rules
        else:
            summary = alerts
        completed = execute(command(alerts, summary, ["--max-frames", "1"]), name, run_dir, result)
        failure(completed)
        if sha256(alerts) != before or sha256(rules) != rules_hash:
            raise RuntimeError("invalid summary preflight changed JSONL or baseline")
        item.update({"alerts": alerts.name, "before_sha256": before, "after_sha256": sha256(alerts),
                     "returncode": completed["returncode"]})

    for kind in ("parent", "directory", "rules-alias", "alerts-alias"):
        check("invalid_summary_" + kind + "_preserves_jsonl", lambda item, kind=kind: invalid_summary(item, kind))

    def fresh_case_alias(item):
        probe = run_dir / "CaseProbe"
        probe.write_bytes(b"case probe\n")
        if not (run_dir / "caseprobe").exists():
            item.update({"applicable": False, "reason": "output filesystem is case-sensitive"})
            return
        alerts = run_dir / "FreshAlerts.jsonl"
        summary = run_dir / "freshalerts.jsonl"
        completed = execute(command(alerts, summary, ["--max-seconds", "1"]), "fresh-case-alias",
                            run_dir, result)
        error = failure(completed)
        if "alias" not in error.lower():
            raise RuntimeError("fresh case alias was rejected for an unrelated reason")
        for path in (alerts, summary):
            if path.exists() and path.read_bytes():
                raise RuntimeError("fresh output alias was detected only after data was written")
        item.update({"applicable": True, "case_insensitive_filesystem": True,
                     "empty_jsonl_created_before_alias_recheck": alerts.exists(),
                     "returncode": completed["returncode"]})

    check("fresh_case_alias_rejected_before_receiving_frames", fresh_case_alias)

    def publish_failure(item):
        # Use /tmp so Unix mode bits apply even if --output-dir is on a filesystem
        # that ignores them. Permissions change after the ready line, before sending.
        with tempfile.TemporaryDirectory(prefix="cansec-report-publish-", dir="/tmp") as temporary:
            parent = Path(temporary)
            summary = parent / "report.md"
            previous = b"previous successful report must survive publication failure\n"
            summary.write_bytes(previous)
            previous_hash = sha256(summary)
            original_mode = stat.S_IMODE(parent.stat().st_mode)
            alerts = run_dir / "publication-failure.jsonl"
            source = frame(0x555, "AABB")

            def fail_publish(_process):
                parent.chmod(0o500)
                if os.access(parent, os.W_OK):
                    raise RuntimeError("publication fixture did not remove directory write permission")
                item["parent_read_only_before_transmit"] = True
                send_frames("publication-failure", [source])

            try:
                completed = execute(command(alerts, summary, ["--max-frames", "1"]), "publication-failure",
                                    run_dir, result, ready(alerts), fail_publish)
                error = failure(completed, startup_forbidden=False)
                if sha256(summary) != previous_hash or summary.read_bytes() != previous:
                    raise RuntimeError("failed publication destroyed the previous report")
                rows = alert_rows(alerts)
                if len(rows) != 1 or rows[0]["rule"] != "UNKNOWN_ID" or rows[0]["data"] != "AABB":
                    raise RuntimeError("publication failure did not retain the completed JSONL alert")
                preserved = run_dir / "publication-failure-preserved.md"
                preserved.write_bytes(summary.read_bytes())
                item.update({"temporary_summary_path": str(summary), "previous_sha256": previous_hash,
                             "preserved_summary": preserved.name, "after_sha256": sha256(preserved),
                             "alerts": alerts.name, "alerts_sha256": sha256(alerts),
                             "retained_alert_count": len(rows), "returncode": completed["returncode"],
                             "error": error, "temporary_files_before_permission_restore":
                                 sorted(path.name for path in parent.iterdir())})
            finally:
                parent.chmod(original_mode)

    check("publication_failure_preserves_previous_report_and_completed_jsonl", publish_failure)
    require_vcan(ip_command, interface, run_dir, result, "interface-after")
    return all(item["passed"] for item in result["checks"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detect", required=True)
    parser.add_argument("--interface", default="vcan0")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    output_root = Path(args.output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("report-%Y%m%dT%H%M%SZ-"),
                                    dir=output_root))
    sources = ["scripts/verify_report_linux.py", "scripts/verify_detect_linux.py",
               "tests/test_detect_report_cli.py", "CMakeLists.txt", "src/tools/main_detect.cpp",
               "src/common/report.cpp", "include/cansec/report.hpp", "include/cansec/build_info.hpp.in",
               "src/core/detector.cpp",
               "src/core/baseline.cpp", "src/common/sha256.cpp", "src/common/socketcan.cpp",
               "src/common/alert_json.cpp", "include/cansec/types.hpp"]
    result = {"status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "interface": args.interface, "invocation": [sys.executable] + sys.argv,
              "working_directory": str(Path.cwd()), "run_directory": str(run_dir),
              "environment": {"platform": platform.platform(), "python": sys.version,
                              "uname": platform.uname()._asdict(),
                              "uid": os.getuid() if hasattr(os, "getuid") else None},
              "detect_path": str(Path(args.detect).resolve()), "commands": [], "checks": [],
              "inputs": [], "source_sha256": {}, "artifact_sha256": {}}
    try:
        result["source_sha256"] = {name: sha256(ROOT / name) for name in sources}
        if Path(args.detect).is_file():
            result["detect_sha256"] = sha256(Path(args.detect))
        if verify(args, run_dir, result):
            result["status"] = "passed"
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result["checks_passed"] = sum(item["passed"] is True for item in result["checks"])
        result["checks_total"] = len(result["checks"])
        result["artifact_sha256"] = {path.name: sha256(path) for path in sorted(run_dir.iterdir())
                                     if path.is_file()}
        write_json(run_dir / "result.json", result)
        print("Results: " + str(run_dir / "result.json"))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
