#!/usr/bin/env python3
"""Check that capture/detect record per-packet kernel timestamps for queued frames.

Stops the capture and detect processes it starts, queues 64 frames on an existing
idle vcan, then resumes them. Their timestamps must match an independent receiver.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import struct
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from smoke_v1 import FRAME_PATTERN, clock_stability, ensure, sample_clocks  # noqa: E402
from verify_replay_linux import LoggedChild, Receiver, require_vcan, sha256, write_json  # noqa: E402


FRAME_COUNT = 64


def stop_child(child):
    child.process.send_signal(signal.SIGSTOP)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        ensure(child.process.poll() is None, "child exited before it could be stopped")
        status = Path(f"/proc/{child.process.pid}/status").read_text(encoding="ascii")
        state = next((line for line in status.splitlines() if line.startswith("State:")), "")
        if state.split()[1:2] == ["T"]:
            child.record["stopped_before_send"] = True
            child.record["stopped_observed_monotonic_ns"] = time.monotonic_ns()
            return
        time.sleep(0.005)
    raise RuntimeError("child did not reach confirmed stopped state within two seconds")


def resume_child(child):
    if child.process is not None and child.process.poll() is None:
        try:
            child.process.send_signal(signal.SIGCONT)
            child.record["resumed_monotonic_ns"] = time.monotonic_ns()
        except ProcessLookupError:
            # It exited between poll and signal; there is no stopped child left.
            pass


def capture_rows(path, interface):
    content = path.read_bytes()
    ensure(not content or content.endswith(b"\n"), "capture output has an incomplete final line")
    frames = []
    for line in content.decode("ascii").splitlines():
        match = FRAME_PATTERN.fullmatch(line)
        ensure(match is not None, "unexpected capture log line format")
        seconds, micros, actual_interface, can_id, payload = match.groups()
        ensure(actual_interface == interface, "capture interface differs from requested vcan")
        frames.append({"timestamp_us": int(seconds) * 1000000 + int(micros), "can_id": int(can_id, 16),
                       "id_type": "extended" if len(can_id) == 8 else "standard",
                       "dlc": len(payload) // 2, "data": payload})
    return frames


def verify(args, directory, result):
    ensure(sys.platform == "linux" and os.geteuid() != 0, "run as an ordinary Linux user, not root")
    binaries = {name: Path(getattr(args, name)).resolve() for name in ("capture", "detect")}
    for name, binary in binaries.items():
        ensure(binary.is_file() and os.access(binary, os.X_OK), "missing executable: " + str(binary))
        result["binaries"][name] = {"path": str(binary), "sha256": sha256(binary)}
        fingerprint = binary.parent / "source-fingerprint.txt"
        if fingerprint.is_file():
            saved = directory / (name + "-build-source-fingerprint.txt")
            saved.write_bytes(fingerprint.read_bytes())
            result["binaries"][name]["build_fingerprint_file"] = saved.name
            result["binaries"][name]["build_fingerprint_file_sha256"] = sha256(saved)
    ip_command = shutil.which("ip")
    ensure(ip_command is not None, "ip is required to verify the requested interface is vcan")
    interface = args.interface
    initial = require_vcan(ip_command, interface, "interface-before", directory, result)
    result["interface_details"] = initial
    policy = directory / "timestamp-rules.ini"
    with policy.open("x", encoding="ascii", newline="\n") as output:
        output.write("[global]\nwindow_ms=100\n[id:0x100]\nid_type=standard\nallowed_dlc=2\n"
                     "periodic=0\nperiod_min_us=0\nperiod_max_us=0\nrate_limit_100ms=1000\n"
                     "fixed_mask=00FF000000000000\nfixed_value=0000000000000000\n"
                     "ignore_mask=0000000000000000\nmax_identical_payload_run=1000\n")
    expected = [{"can_id": 0x100, "id_type": "standard", "dlc": 2, "data": f"{index:02X}FF"}
                for index in range(FRAME_COUNT)]
    result["input"] = {"rules": policy.name, "rules_sha256": sha256(policy), "expected_frames": expected,
                       "expected_alerts": {"FIXED_BYTE_VIOLATION": FRAME_COUNT}}
    capture_log = directory / "queued-captured.log"
    alerts_log = directory / "queued-alerts.jsonl"
    children = []
    receiver = Receiver(interface)
    sent = []
    clocks = []
    try:
        ensure(not receiver.receive(wait=0.2), "vcan is not idle; no regression traffic sent")
        capture = LoggedChild([str(binaries["capture"]), "--if", interface, "--out", str(capture_log),
                               "--max-frames", str(FRAME_COUNT), "--max-seconds", "5"],
                              "queued-capture", directory, result, timeout=8)
        children.append(capture)
        capture.ready(f"Capturing CAN frames from {interface} -> {capture_log}\n")
        detect = LoggedChild([str(binaries["detect"]), "--rules", str(policy), "--if", interface,
                              "--out", str(alerts_log), "--max-frames", str(FRAME_COUNT), "--max-seconds", "5"],
                             "queued-detect", directory, result, timeout=8)
        children.append(detect)
        detect.ready(f"Detecting CAN frames from {interface} -> {alerts_log}\n")
        for child in children:
            stop_child(child)
        current = require_vcan(ip_command, interface, "interface-before-send", directory, result)
        ensure(current["ifindex"] == initial["ifindex"], "vcan interface identity changed")
        clocks.append(sample_clocks())
        with socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as sender:
            sender.settimeout(1)
            sender.bind((interface,))
            for index, frame in enumerate(expected):
                ensure(socket.if_nametoindex(interface) == initial["ifindex"], "vcan identity changed before send")
                packet = struct.pack("=IB3x8s", 0x100, 2, bytes.fromhex(frame["data"]).ljust(8, b"\0"))
                record = {"index": index, "packet_hex": packet.hex().upper(), "before_monotonic_ns": time.monotonic_ns()}
                record["sent_bytes"] = sender.send(packet)
                record["after_monotonic_ns"] = time.monotonic_ns()
                sent.append(record)
                ensure(record["sent_bytes"] == 16, "incomplete Classical CAN transmission")
        # Hold the queue for 20 ms so read time clearly differs from arrival time.
        time.sleep(0.02)
        clocks.append(sample_clocks())
        for child in children:
            resume_child(child)
        for child in children:
            child.wait(timeout=8)
        while receiver.receive(wait=0.1):
            ensure(len(receiver.frames) <= FRAME_COUNT, "independent receiver observed unexpected extra traffic")
        frames = capture_rows(capture_log, interface)
        rows = [json.loads(line) for line in alerts_log.read_text(encoding="utf-8").splitlines()]
        comparisons = []
        for index, observed in enumerate(receiver.frames):
            frame = frames[index] if index < len(frames) else None
            timestamp_ns = observed["kernel_realtime_ns"]
            associated_alerts = [row for row in rows if row.get("data") == observed["data"]]
            comparisons.append({"index": index, "data": observed["data"],
                                "capture_us": frame["timestamp_us"] if frame else None,
                                "observer_kernel_ns": timestamp_ns,
                                "capture_minus_observer_us": None if timestamp_ns is None or frame is None else frame["timestamp_us"] - timestamp_ns // 1000,
                                "detector_capture_us": [row["capture_ts_us"] for row in associated_alerts],
                                "detector_minus_observer_us": [] if timestamp_ns is None else
                                    [row["capture_ts_us"] - timestamp_ns // 1000 for row in associated_alerts]})
        comparison = {"capture_count": len(frames), "observer_count": len(receiver.frames), "alert_count": len(rows),
                      "capture_returncode": capture.process.returncode, "detect_returncode": detect.process.returncode,
                      "capture_stderr": capture.stderr().decode("utf-8", errors="replace"),
                      "detect_stderr": detect.stderr().decode("utf-8", errors="replace"),
                      "capture_timestamps_nondecreasing": [row["timestamp_us"] for row in frames] == sorted(row["timestamp_us"] for row in frames),
                      "frames": comparisons, "clock_stability": clock_stability(clocks)}
        write_json(directory / "timestamp-comparison.json", comparison)
        result["comparison"] = comparison
        ensure(comparison["clock_stability"]["status"] == "passed", "clock changed during the queued timestamp test")
        failures = []
        for name, child in (("capture", capture), ("detect", detect)):
            if child.process.returncode != 0:
                failures.append(f"{name} exited {child.process.returncode}: " + child.stderr().decode("utf-8", errors="replace").strip())
        ensure(not failures, "queued child failure (see timestamp-comparison.json): " + " | ".join(failures))
        ensure(len(frames) == len(receiver.frames) == FRAME_COUNT, "queued capture/observer counts differ")
        for frame, observed, wanted in zip(frames, receiver.frames, expected):
            ensure(all(frame[key] == wanted[key] and observed[key] == wanted[key] for key in wanted),
                   "queued ID/DLC/payload sequence differs from transmitted frames")
            ensure(not observed["rtr"] and not observed["error_frame"], "unexpected RTR/error frame")
        ensure(all(row["observer_kernel_ns"] is not None for row in comparisons), "independent kernel timestamps unavailable")
        ensure(comparison["capture_timestamps_nondecreasing"], "queued capture timestamps decreased")
        ensure(all(row["capture_minus_observer_us"] == 0 for row in comparisons),
               "queued capture timestamps do not equal the per-packet independent kernel timestamps")
        ensure(Counter(row["rule"] for row in rows) == {"FIXED_BYTE_VIOLATION": FRAME_COUNT},
               "queued detector did not return exactly one fixed-byte alert per frame")
        for index, (row, frame) in enumerate(zip(rows, frames)):
            ensure(row["capture_ts_us"] == frame["timestamp_us"] and row["data"] == expected[index]["data"] and
                   row["can_id"] == "0x100" and row["id_type"] == "standard" and row["dlc"] == 2 and
                   row["if"] == interface and row["severity"] == "MEDIUM", "queued detector alert/frame timestamp mismatch")
            ensure(row["alert_ts_us"] >= row["capture_ts_us"], "decision time precedes capture time")
        ensure(capture.stderr().endswith(f"Captured {FRAME_COUNT} frame(s).\n".encode()), "wrong capture completion total")
        ensure(detect.stderr().endswith(f"Processed {FRAME_COUNT} frame(s); {FRAME_COUNT} alert(s).\n".encode()),
               "wrong detector completion totals")
        ensure(not capture.stdout() and not detect.stdout(), "unexpected live stdout")
        ensure(sha256(policy) == result["input"]["rules_sha256"], "detector changed its input policy")
        result["checks"].append({"name": "queued_frames_have_per_packet_timestamps", "passed": True,
                                  "frames": FRAME_COUNT, "alerts": FRAME_COUNT, "capture_and_detector_equal_observer_us": True})
    finally:
        cleanup_errors = []
        for child in reversed(children):
            try:
                try:
                    resume_child(child)
                finally:
                    child.close()
            except Exception as error:
                cleanup_errors.append(str(error))
        receiver.close()
        write_json(directory / "sent-frames.json", sent)
        write_json(directory / "received-frames.json", receiver.frames)
        write_json(directory / "clock-observation.json", clock_stability(clocks))
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            raise RuntimeError("owned child cleanup failed: " + "; ".join(cleanup_errors))
    after = require_vcan(ip_command, interface, "interface-after", directory, result)
    ensure(after["ifindex"] == initial["ifindex"], "vcan identity changed after queued test")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--detect", required=True)
    parser.add_argument("--interface", default="vcan0")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--label", default="", help="optional label stored in result.json")
    args = parser.parse_args()
    parent = Path(args.output_dir).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("socketcan-ts-%Y%m%dT%H%M%SZ-"), dir=parent))
    result = {"status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(), "label": args.label,
              "invocation": [sys.executable] + sys.argv, "run_directory": str(directory), "interface": args.interface,
              "environment": {"platform": platform.platform(), "uname": platform.uname()._asdict(), "python": sys.version,
                              "uid": os.getuid() if hasattr(os, "getuid") else None},
              "binaries": {}, "commands": [], "checks": [],
              "verifier_source_sha256": {name: sha256(ROOT / name) for name in
                  ("scripts/verify_socketcan_timestamp_linux.py", "scripts/smoke_v1.py", "scripts/verify_replay_linux.py")}}
    code = 1
    try:
        verify(args, directory, result)
        result["status"] = "passed"
        code = 0
    except KeyboardInterrupt:
        result["error"] = "interrupted; owned stopped children were resumed before cleanup"
        code = 130
    except Exception as error:
        result["error"] = str(error)
        result["error_type"] = type(error).__name__
        print(str(error), file=sys.stderr, flush=True)
    finally:
        if result["status"] != "passed" and not result["checks"]:
            result["checks"].append({"name": "queued_frames_have_per_packet_timestamps", "passed": False,
                                      "error": result.get("error", "verification did not complete")})
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result["artifact_sha256"] = {path.relative_to(directory).as_posix(): sha256(path)
                                     for path in sorted(directory.rglob("*")) if path.is_file()}
        write_json(directory / "result.json", result)
        print("Results: " + str(directory / "result.json"), flush=True)
        print(result["status"].upper(), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
