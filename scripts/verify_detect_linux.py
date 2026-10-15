#!/usr/bin/env python3
"""Verify cansec-detect on an existing, idle Linux vcan interface."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
FIELDS = {"capture_ts_us", "alert_ts_us", "if", "rule", "severity", "can_id",
          "id_type", "dlc", "data", "detail"}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")


def execute(command, name, run_dir, result, ready_line=None, ready_action=None, timeout=5):
    """Run a child with saved logs; ready_action runs only after the exact ready line."""
    record = {"command": command, "stdout": name + ".stdout.txt",
              "stderr": name + ".stderr.txt", "timeout_seconds": timeout,
              "started_us": time.time_ns() // 1000}
    result["commands"].append(record)
    start = time.monotonic()
    process = None
    try:
        with (run_dir / record["stdout"]).open("xb") as stdout, \
                (run_dir / record["stderr"]).open("xb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, shell=False)
            if ready_line is not None:
                marker = ready_line.encode("utf-8")
                while marker not in (run_dir / record["stderr"]).read_bytes().splitlines(keepends=True):
                    if process.poll() is not None:
                        raise RuntimeError("detector exited before its exact ready message")
                    if time.monotonic() - start >= timeout:
                        raise TimeoutError("detector readiness timeout")
                    time.sleep(0.01)
                record["ready_message_observed"] = True
            if ready_action is not None:
                ready_action(process)
            process.wait(timeout=max(0.01, timeout - (time.monotonic() - start)))
    except (subprocess.TimeoutExpired, TimeoutError) as error:
        record["timed_out"] = True
        raise RuntimeError(str(error)) from error
    finally:
        # Only clean up the child started here; never kill by name.
        if process is not None:
            if process.poll() is None:
                record["cleanup_terminated_child"] = True
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    record["cleanup_killed_child"] = True
                    process.kill()
                    process.wait(timeout=2)
            record["returncode"] = process.returncode
        record["finished_us"] = time.time_ns() // 1000
        record["elapsed_seconds"] = round(time.monotonic() - start, 6)
        for stream in ("stdout", "stderr"):
            path = run_dir / record[stream]
            if path.is_file():
                record[stream + "_sha256"] = sha256(path)
    return record


def require_vcan(ip_command, interface, run_dir, result, name):
    completed = execute([ip_command, "-details", "-json", "link", "show", "dev", interface],
                        name, run_dir, result)
    if completed["returncode"] != 0:
        raise RuntimeError("ip could not inspect the requested interface")
    links = json.loads((run_dir / completed["stdout"]).read_text(encoding="utf-8"))
    if not isinstance(links, list) or len(links) != 1:
        raise RuntimeError("ip did not identify exactly one requested interface")
    link = links[0]
    if link.get("linkinfo", {}).get("info_kind") != "vcan":
        raise RuntimeError("interface is not verified as vcan; no frames will be sent")
    if link.get("ifname") != interface or "UP" not in link.get("flags", []):
        raise RuntimeError("requested vcan interface must already be UP")
    if type(link.get("ifindex")) is not int or link["ifindex"] <= 0:
        raise RuntimeError("ip did not return a valid vcan interface index")
    return link


def fixture_rules():
    sections = ["[global]\nwindow_ms=100\n"]
    for can_id, periodic, low, high, rate, mask, value, run in [
        (0x100, 0, 0, 0, 1000, "00FF000000000000", "0010000000000000", 3),
        (0x101, 1, 1000000, 2000000, 1000, "0000000000000000", "0000000000000000", 100),
        (0x102, 0, 0, 0, 3, "0000000000000000", "0000000000000000", 100),
    ]:
        sections.append(
            f"[id:0x{can_id:X}]\nid_type=standard\nallowed_dlc=4\nperiodic={periodic}\n"
            f"period_min_us={low}\nperiod_max_us={high}\nrate_limit_100ms={rate}\n"
            f"fixed_mask={mask}\nfixed_value={value}\nignore_mask=0000000000000000\n"
            f"max_identical_payload_run={run}\n")
    return "\n".join(sections)


def frame(can_id, data, extended=False, rtr=False, dlc=None):
    payload = bytes.fromhex(data)
    return {"can_id": can_id, "id_type": "extended" if extended else "standard",
            "raw_id": can_id | (CAN_EFF_FLAG if extended else 0) | (CAN_RTR_FLAG if rtr else 0),
            "rtr": rtr, "dlc": len(payload) if dlc is None else dlc,
            "data": payload.hex().upper()}


def verify(args, run_dir, result):
    if sys.platform != "linux":
        raise RuntimeError("Linux is required; no SocketCAN verification was executed")
    detect = Path(args.detect).resolve()
    if not detect.is_file() or not os.access(detect, os.X_OK):
        raise RuntimeError("--detect must name an executable Linux cansec-detect binary")
    ip_command = shutil.which("ip")
    if ip_command is None:
        raise RuntimeError("ip is required to verify that the interface is virtual CAN")
    interface = args.interface
    link = require_vcan(ip_command, interface, run_dir, result, "interface-before")
    result["interface_details"] = link
    rules = run_dir / "live-rules.ini"
    rules.write_text(fixture_rules(), encoding="ascii", newline="\n")
    rules_hash = sha256(rules)
    result["rules"] = {"path": rules.name, "sha256": rules_hash}

    def check(name, action):
        item = {"name": name, "passed": False}
        result["checks"].append(item)
        try:
            action(item)
            item["passed"] = None if item.get("skipped") else True
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            item["error"] = str(error)
        status = "SKIP " if item.get("skipped") else ("PASS " if item["passed"] else "FAIL ")
        print(status + name, flush=True)

    def ready(output):
        return f"Detecting CAN frames from {interface} -> {output}\n"

    def command(output, extra=(), policy=rules, device=interface):
        return [str(detect), "--rules", str(policy), "--if", device, "--out", str(output)] + list(extra)

    def send_frames(name, frames, delays=None):
        sent = []
        manifest = run_dir / (name + ".frames.json")
        manifest_data = {"requested_interface": interface, "initial_ifindex": link["ifindex"],
                         "expected_frames": frames, "delay_before_frame_seconds": delays or [],
                         "sent_frames": sent}
        try:
            with socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as sender:
                sender.settimeout(1)
                sender.bind((interface,))
                current = require_vcan(ip_command, interface, run_dir, result, name + "-interface-before-send")
                if current["ifindex"] != link["ifindex"] or socket.if_nametoindex(interface) != link["ifindex"]:
                    raise RuntimeError("vcan interface identity changed before transmission")
                for index, data in enumerate(frames):
                    if delays and delays[index]:
                        time.sleep(delays[index])
                    if socket.if_nametoindex(interface) != link["ifindex"]:
                        raise RuntimeError("vcan interface identity changed before transmission")
                    packet = struct.pack("=IB3x8s", data["raw_id"], data["dlc"],
                                         bytes.fromhex(data["data"]).ljust(8, b"\0"))
                    measurement = {"index": index, "packet_hex": packet.hex().upper(),
                                   "packet_sha256": hashlib.sha256(packet).hexdigest(),
                                   "before_us": time.time_ns() // 1000,
                                   "before_monotonic_ns": time.monotonic_ns()}
                    count = sender.send(packet)
                    measurement.update({"after_us": time.time_ns() // 1000,
                                        "after_monotonic_ns": time.monotonic_ns(), "sent_bytes": count})
                    sent.append(measurement)
                    if count != 16:
                        raise RuntimeError("incomplete Classical CAN frame transmission")
        finally:
            write_json(manifest, manifest_data)
            result["inputs"].append({"path": manifest.name, "sha256": sha256(manifest)})
        return sent

    def successful(completed, output, processed, alerts):
        if completed["returncode"] != 0:
            raise RuntimeError("detector failed: exit " + str(completed["returncode"]))
        if (run_dir / completed["stdout"]).read_bytes():
            raise RuntimeError("live detection unexpectedly wrote to stdout")
        expected = ready(output) + f"Processed {processed} frame(s); {alerts} alert(s).\n"
        if (run_dir / completed["stderr"]).read_bytes() != expected.encode("utf-8"):
            raise RuntimeError("ready/summary stderr differs from the live CLI contract")
        if sha256(rules) != rules_hash:
            raise RuntimeError("detector modified its baseline input")

    def read_alerts(output, completed, expected):
        content = output.read_bytes()
        if content and not content.endswith(b"\n"):
            raise RuntimeError("JSONL output must end every alert with a newline")
        lines = content.decode("utf-8").splitlines()
        if len(lines) != len(expected):
            raise RuntimeError(f"expected {len(expected)} alert lines, observed {len(lines)}")
        alerts = []
        previous_capture = 0
        for line, (source, rule, severity, detail) in zip(lines, expected):
            alert = json.loads(line)
            if not isinstance(alert, dict) or set(alert) != FIELDS:
                raise RuntimeError("JSONL alert field set differs from the required schema")
            for key in ("capture_ts_us", "alert_ts_us", "dlc"):
                if type(alert[key]) is not int:
                    raise RuntimeError(key + " is not a JSON integer")
            for key in FIELDS - {"capture_ts_us", "alert_ts_us", "dlc"}:
                if type(alert[key]) is not str:
                    raise RuntimeError(key + " is not a JSON string")
            expected_values = {"if": interface, "rule": rule, "severity": severity,
                               "can_id": f"0x{source['can_id']:X}", "id_type": source["id_type"],
                               "dlc": source["dlc"], "data": source["data"]}
            if any(alert[key] != value for key, value in expected_values.items()):
                raise RuntimeError("JSONL ID/type/DLC/payload/interface/rule/severity differs from the sent frame")
            if re.fullmatch(detail, alert["detail"]) is None:
                raise RuntimeError("alert detail does not match the expected pattern: " + alert["detail"])
            capture, emitted = alert["capture_ts_us"], alert["alert_ts_us"]
            if not completed["started_us"] - 1000000 <= capture <= emitted <= completed["finished_us"] + 1000000:
                raise RuntimeError("capture/alert timestamps are reversed or outside the run's start/end time")
            if capture < previous_capture:
                raise RuntimeError("JSONL capture timestamps are not nondecreasing")
            previous_capture = capture
            alerts.append(alert)
        return alerts

    def live_case(item, name, frames, expected, delays=None):
        output = run_dir / (name + ".jsonl")
        sent = []
        accepted_count = sum(not source["rtr"] for source in frames)

        def transmit(_process):
            sent.extend(send_frames(name, frames, delays))

        completed = execute(command(output, ["--max-frames", str(accepted_count)]), name,
                            run_dir, result, ready(output), transmit, timeout=8)
        successful(completed, output, accepted_count, len(expected))
        alerts = read_alerts(output, completed, expected)
        item.update({"processed_frames": accepted_count, "alerts": len(alerts),
                     "output": output.name, "output_sha256": sha256(output),
                     "run_window_us": [completed["started_us"], completed["finished_us"]]})
        if len(sent) > 1:
            item["send_span_us"] = (sent[-1]["before_monotonic_ns"] - sent[0]["before_monotonic_ns"]) // 1000
        return alerts

    def expect_unknown(source):
        detail = f"CAN ID 0x{source['can_id']:X} ({source['id_type']}) is absent from baseline"
        return source, "UNKNOWN_ID", "HIGH", re.escape(detail)

    normal = [frame(0x100, value) for value in ("00100000", "01100000", "02100000")]
    unknown = frame(0x555, "AABB")
    mismatch = frame(0x100, "0010")
    periodic = [frame(0x101, "01020304"), frame(0x101, "02020304")]
    rate = [frame(0x102, f"{index:02X}010203") for index in range(4)]
    fixed = frame(0x100, "00220000")
    fixed_detail = re.escape("fixed_byte_mismatches=[index=1 observed=0x22 expected=0x10 effective_mask=0xFF]")
    repeat_detail = re.escape("identical_payload_run=4 threshold=3")
    check("normal_frames_produce_no_alerts", lambda item: live_case(item, "normal", normal, []))
    check("unknown_id", lambda item: live_case(item, "unknown", [unknown], [expect_unknown(unknown)]))
    check("dlc_mismatch", lambda item: live_case(item, "dlc", [mismatch],
          [(mismatch, "DLC_MISMATCH", "HIGH", re.escape("observed_dlc=2 allowed_dlc=4"))]))

    def period_case(item):
        alerts = live_case(item, "period", periodic,
                          [(periodic[-1], "PERIOD_VIOLATION", "MEDIUM",
                            r"delta_us=[0-9]+ allowed_min_us=1000000 allowed_max_us=2000000")], [0, 0.02])
        delta = int(re.search(r"delta_us=([0-9]+)", alerts[0]["detail"]).group(1))
        if not 0 <= delta < 1000000 or item["send_span_us"] >= 1000000:
            raise RuntimeError("period fixture did not arrive below its one-second minimum")
        item["observed_delta_us"] = delta

    def rate_case(item):
        live_case(item, "rate", rate, [(rate[-1], "RATE_SPIKE", "HIGH", re.escape("count_100ms=4 threshold=3"))])
        if item["send_span_us"] >= 100000:
            raise RuntimeError("rate fixture took at least 100 ms; timing precondition was not met")

    check("period_violation", period_case)
    check("rate_spike", rate_case)
    check("fixed_byte_violation", lambda item: live_case(item, "fixed", [fixed],
          [(fixed, "FIXED_BYTE_VIOLATION", "MEDIUM", fixed_detail)]))
    check("replay_burst", lambda item: live_case(item, "replay", [normal[0]] * 4,
          [(normal[0], "REPLAY_BURST", "HIGH", repeat_detail)]))
    multiple = [(fixed, "FIXED_BYTE_VIOLATION", "MEDIUM", fixed_detail)] * 4
    multiple += [(fixed, "REPLAY_BURST", "HIGH", repeat_detail)]
    check("multiple_alerts_count_data_frames", lambda item: live_case(item, "multiple", [fixed] * 4, multiple))
    for name, source in [("low_extended_id", frame(0x100, "00100000", extended=True)),
                         ("empty_payload", frame(0x556, "")),
                         ("full_eight_byte_payload", frame(0x7AB, "0001027F80ABEFFF"))]:
        check(name, lambda item, name=name, source=source:
              live_case(item, name, [source], [expect_unknown(source)]))

    def idle_timeout(item):
        output = run_dir / "idle.jsonl"
        completed = execute(command(output, ["--max-seconds", "1"]), "idle", run_dir, result, ready(output))
        successful(completed, output, 0, 0)
        read_alerts(output, completed, [])
        if not 0.8 <= completed["elapsed_seconds"] <= 4:
            raise RuntimeError("--max-seconds 1 did not finish within 0.8 to 4 seconds")
        item.update({"elapsed_seconds": completed["elapsed_seconds"], "output": output.name,
                     "output_sha256": sha256(output)})

    check("idle_max_seconds", idle_timeout)
    check("rtr_not_counted_as_data", lambda item: live_case(item, "rtr",
          [frame(0x123, "", rtr=True, dlc=2), unknown], [expect_unknown(unknown)]))

    def graceful_signal(item, selected, explicit_zero):
        name = "signal-" + selected.name.lower()
        output = run_dir / (name + ".jsonl")
        extra = ["--max-frames", "0", "--max-seconds", "0"] if explicit_zero else []

        def stop(process):
            if explicit_zero:
                send_frames(name + "-before-stop", [unknown])
                deadline = time.monotonic() + 2
                while not output.read_bytes().endswith(b"\n"):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("alert was not saved before the termination signal")
                    time.sleep(0.01)
                item["alert_observed_before_signal"] = True
            # Exercise a signal while the next receive is waiting.
            time.sleep(0.15)
            process.send_signal(selected)

        completed = execute(command(output, extra), name, run_dir, result, ready(output), stop)
        expected = [expect_unknown(unknown)] if explicit_zero else []
        successful(completed, output, len(expected), len(expected))
        read_alerts(output, completed, expected)
        item.update({"signal": selected.name, "explicit_zero_limits": explicit_zero,
                     "processed_frames": len(expected), "alerts": len(expected),
                     "output": output.name, "output_sha256": sha256(output)})

    check("sigint_default_unbounded_idle", lambda item: graceful_signal(item, signal.SIGINT, False))
    check("sigterm_explicit_zero_preserves_alert", lambda item: graceful_signal(item, signal.SIGTERM, True))

    def failure(completed):
        stderr = (run_dir / completed["stderr"]).read_text(encoding="utf-8", errors="replace")
        if completed["returncode"] != 1 or "cansec-detect:" not in stderr:
            raise RuntimeError("invalid invocation did not report detector failure with exit 1")
        if "Processed " in stderr or (run_dir / completed["stdout"]).read_bytes():
            raise RuntimeError("failed invocation emitted success summary or stdout data")
        return stderr

    def preserves_output(item, name, policy=rules, device=interface):
        output = run_dir / (name + ".jsonl")
        output.write_bytes(b"existing output must survive rejected input\n")
        before = sha256(output)
        completed = execute(command(output, ["--max-frames", "1"], policy, device), name, run_dir, result)
        failure(completed)
        if sha256(output) != before:
            raise RuntimeError("failed invocation changed the existing output")
        item.update({"output": output.name, "before_sha256": before, "after_sha256": sha256(output)})

    def missing_interface(item):
        device = "cs" + str(os.getpid())[-8:] + "miss"
        try:
            socket.if_nametoindex(device)
        except OSError:
            pass
        else:
            raise RuntimeError("missing-interface fixture unexpectedly exists")
        preserves_output(item, "missing-interface", device=device)

    def malformed_rules(item):
        policy = run_dir / "malformed.ini"
        policy.write_text("[global]\nwindow_ms=100\n[id:0x100]\nallowed_dlc=9\n", encoding="ascii")
        before = sha256(policy)
        preserves_output(item, "malformed-rules", policy=policy)
        if sha256(policy) != before:
            raise RuntimeError("malformed baseline input was changed")
        item.update({"rules": policy.name, "rules_sha256": before})

    check("missing_interface_preserves_output", missing_interface)
    check("malformed_rules_preserve_output", malformed_rules)

    def alias_rejected(item, kind):
        policy = run_dir / (kind + "-rules.ini")
        policy.write_text(fixture_rules(), encoding="ascii", newline="\n")
        output = policy if kind == "same-path" else run_dir / (kind + "-alias.jsonl")
        before = sha256(policy)
        try:
            if kind == "symlink":
                output.symlink_to(policy.name)
            elif kind == "hardlink":
                os.link(policy, output)
        except (NotImplementedError, OSError) as error:
            item.update({"skipped": True, "reason": f"{kind} could not be created: {error}"})
            return
        completed = execute(command(output, ["--max-frames", "1"], policy), kind, run_dir, result)
        failure(completed)
        if sha256(policy) != before or sha256(output) != before:
            raise RuntimeError("rules/output alias rejection did not preserve the input")
        item.update({"rules": policy.name, "output": output.name,
                     "before_sha256": before, "after_sha256": sha256(policy)})

    for kind in ("same-path", "symlink", "hardlink"):
        check("rules_output_" + kind, lambda item, kind=kind: alias_rejected(item, kind))

    def directory_output(item):
        output = run_dir / "output-directory"
        output.mkdir()
        completed = execute(command(output, ["--max-frames", "1"]), "output-directory", run_dir, result)
        failure(completed)
        if not output.is_dir() or list(output.iterdir()):
            raise RuntimeError("directory output failure changed the fixture directory")
        item["returncode"] = completed["returncode"]

    def write_failure(item):
        output = Path("/dev/full")
        if not output.exists():
            raise RuntimeError("/dev/full is required for the output write failure check")
        completed = execute(command(output, ["--max-frames", "1"]), "write-failure", run_dir, result,
                            ready(output), lambda _process: send_frames("write-failure", [unknown]))
        failure(completed)
        item["returncode"] = completed["returncode"]

    check("output_directory_rejected", directory_output)
    check("output_write_failure", write_failure)

    def invalid_options(item):
        variants = []
        for option in ("--rules", "--if", "--out"):
            variants.append(("missing-" + option[2:], option, None, []))
        for option in ("--max-frames", "--max-seconds"):
            for label, value in (("negative", "-1"), ("fractional", "0.5"), ("trailing", "1junk"),
                                 ("overflow", "18446744073709551616"), ("empty", "")):
                variants.append((label + "-" + option[2:], None, None, [option, value]))
        variants += [("empty-interface", "--if", "", []),
                     ("oversized-interface", "--if", "v" * 16, []),
                     ("empty-rules", "--rules", "", []), ("empty-output", "--out", "", [])]
        item["variants"] = []
        for name, replace, value, extra in variants:
            output = run_dir / ("invalid-" + name + ".jsonl")
            options = {"--rules": str(rules), "--if": interface, "--out": str(output)}
            if replace is not None:
                if value is None:
                    del options[replace]
                else:
                    options[replace] = value
            invocation = [str(detect)]
            for key, option_value in options.items():
                invocation += [key, option_value]
            completed = execute(invocation + extra, "invalid-" + name, run_dir, result, timeout=3)
            failure(completed)
            if output.exists() or sha256(rules) != rules_hash:
                raise RuntimeError("invalid options opened output or modified rules: " + name)
            item["variants"].append({"name": name, "returncode": completed["returncode"]})

    check("missing_and_invalid_cli_options", invalid_options)
    return all(item["passed"] is True for item in result["checks"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detect", required=True, help="path to the Linux cansec-detect executable")
    parser.add_argument("--interface", default="vcan0", help="existing idle vcan interface (default: vcan0)")
    parser.add_argument("--output-dir", required=True, help="parent directory for run output")
    args = parser.parse_args()
    output_root = Path(args.output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("detect-%Y%m%dT%H%M%SZ-"),
                                    dir=output_root))
    root = Path(__file__).resolve().parent.parent
    sources = ["scripts/verify_detect_linux.py", "CMakeLists.txt", "src/tools/main_detect.cpp",
               "src/core/detector.cpp", "src/core/baseline.cpp", "src/common/socketcan.cpp",
               "src/common/alert_json.cpp", "include/cansec/socketcan.hpp", "include/cansec/detector.hpp",
               "include/cansec/baseline.hpp", "include/cansec/alert_json.hpp", "include/cansec/types.hpp"]
    result = {"status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "interface": args.interface, "invocation": [sys.executable] + sys.argv,
              "working_directory": str(Path.cwd()), "run_directory": str(run_dir),
              "environment": {"platform": platform.platform(), "python": sys.version,
                              "uname": platform.uname()._asdict(),
                              "uid": os.getuid() if hasattr(os, "getuid") else None},
              "detect_path": str(Path(args.detect).resolve()), "source_sha256": {},
              "commands": [], "checks": [], "inputs": [], "artifact_sha256": {}}
    try:
        result["source_sha256"] = {name: sha256(root / name) for name in sources}
        detect = Path(args.detect).resolve()
        if detect.is_file():
            result["detect_sha256"] = sha256(detect)
        if verify(args, run_dir, result):
            result["status"] = "passed"
        elif result["checks"] and all(item["passed"] or item.get("skipped") for item in result["checks"]):
            result["status"] = "incomplete"
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result["checks_passed"] = sum(item["passed"] is True for item in result["checks"])
        result["checks_skipped"] = sum(bool(item.get("skipped")) for item in result["checks"])
        result["checks_total"] = len(result["checks"])
        for path in sorted(run_dir.iterdir()):
            if path.is_file():
                result["artifact_sha256"][path.name] = sha256(path)
        write_json(run_dir / "result.json", result)
        print("Results: " + str(run_dir))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
