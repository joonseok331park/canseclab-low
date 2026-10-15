#!/usr/bin/env python3
"""Verify cansec-capture on an existing, idle Linux vcan interface."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def execute(command, name, run_dir, result, ready_action=None, timeout=5):
    """Run a child with saved logs; ready_action runs only after capture is ready."""
    record = {"command": command, "stdout": name + ".stdout.txt",
              "stderr": name + ".stderr.txt", "timeout_seconds": timeout}
    result["commands"].append(record)
    start = time.monotonic()
    process = None
    try:
        with (run_dir / record["stdout"]).open("xb") as stdout, \
                (run_dir / record["stderr"]).open("xb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, shell=False)
            if ready_action is not None:
                marker = ("Capturing CAN frames from " + result["interface"] + " -> ").encode()
                while marker not in (run_dir / record["stderr"]).read_bytes():
                    if process.poll() is not None:
                        raise RuntimeError("capture exited before its ready message")
                    if time.monotonic() - start >= timeout:
                        raise TimeoutError("capture readiness timeout")
                    time.sleep(0.02)
                record["ready_message_observed"] = True
                ready_action()
            process.wait(timeout=max(0.01, timeout - (time.monotonic() - start)))
    except (subprocess.TimeoutExpired, TimeoutError) as error:
        record["timed_out"] = True
        raise RuntimeError(str(error)) from error
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            record["returncode"] = process.returncode
        record["elapsed_seconds"] = round(time.monotonic() - start, 6)
    return record


def require_vcan(ip_command, interface, run_dir, result, name):
    command = [ip_command, "-details", "-json", "link", "show", "dev", interface]
    completed = execute(command, name, run_dir, result)
    if completed["returncode"] != 0:
        raise RuntimeError("ip could not inspect the requested interface")
    links = json.loads((run_dir / completed["stdout"]).read_text(encoding="utf-8"))
    if len(links) != 1 or links[0].get("linkinfo", {}).get("info_kind") != "vcan":
        raise RuntimeError("interface is not verified as vcan; no frames will be sent")
    link = links[0]
    if link.get("ifname") != interface or "UP" not in link.get("flags", []):
        raise RuntimeError("requested vcan interface must already be UP")
    return link


def verify(args, run_dir, result):
    if sys.platform != "linux":
        raise RuntimeError("Linux is required; no SocketCAN verification was executed")
    capture = Path(args.capture).resolve()
    if not capture.is_file() or not os.access(capture, os.X_OK):
        raise RuntimeError("--capture must name an executable Linux cansec-capture binary")
    ip_command = shutil.which("ip")
    if ip_command is None:
        raise RuntimeError("ip is required to verify that the interface is virtual CAN")
    interface = args.interface
    link = require_vcan(ip_command, interface, run_dir, result, "interface-before")
    result["interface_details"] = link
    expected = [(0x123, False, b""), (0x7FF, False, bytes(range(8))),
                (0x123, True, bytes.fromhex("AABB")),
                (0x1FFFFFFF, True, bytes.fromhex("00FF55"))]
    result["expected_frames"] = [
        {"can_id": can_id, "extended": extended, "dlc": len(payload),
         "payload_hex": payload.hex().upper()} for can_id, extended, payload in expected]

    def check(name, action):
        item = {"name": name, "passed": False}
        result["checks"].append(item)
        try:
            action(item)
            item["passed"] = True
        except (OSError, RuntimeError, ValueError) as error:
            item["error"] = str(error)
        print(("PASS " if item["passed"] else "FAIL ") + name)

    def send_raw_frames(name, frames):
        with socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as sender:
            sender.settimeout(1)
            sender.bind((interface,))
            current = require_vcan(ip_command, interface, run_dir, result, name)
            if current["ifindex"] != link["ifindex"] or \
                    socket.if_nametoindex(interface) != link["ifindex"]:
                raise RuntimeError("vcan interface identity changed before transmission")
            for raw_id, dlc, payload in frames:
                packet = struct.pack("=IB3x8s", raw_id, dlc, payload.ljust(8, b"\0"))
                if sender.send(packet) != 16:
                    raise RuntimeError("incomplete Classical CAN frame transmission")

    def known_frames(item):
        output = run_dir / "known-frames.log"
        before_us = time.time_ns() // 1000

        def send_frames():
            send_raw_frames("interface-before-send", [
                (can_id | (0x80000000 if extended else 0), len(payload), payload)
                for can_id, extended, payload in expected])

        command = [str(capture), "--if", interface, "--out", str(output),
                   "--max-frames", str(len(expected))]
        completed = execute(command, "known-frames", run_dir, result, send_frames, timeout=10)
        after_us = time.time_ns() // 1000
        if completed["returncode"] != 0:
            raise RuntimeError("capture failed for known frames")
        lines = output.read_text(encoding="ascii").splitlines()
        if len(lines) != len(expected):
            raise RuntimeError("captured frame count differs from --max-frames")
        timestamps = []
        for line, (can_id, extended, payload) in zip(lines, expected):
            parsed = re.fullmatch(r"\(([0-9]+)\.([0-9]{6})\) (\S+) ([0-9A-F]{3}|[0-9A-F]{8})#([0-9A-F]*)", line)
            if parsed is None:
                raise RuntimeError("captured line has an invalid timestamp or CAN log format")
            seconds, micros, observed_if, observed_id, observed_payload = parsed.groups()
            timestamp = int(seconds) * 1000000 + int(micros)
            if observed_if != interface or observed_id != format(can_id, "08X" if extended else "03X") or \
                    observed_payload != payload.hex().upper() or len(observed_payload) // 2 != len(payload):
                raise RuntimeError("captured ID/type/DLC/payload/interface differs from sent frame")
            if not before_us - 1000000 <= timestamp <= after_us + 1000000:
                raise RuntimeError("capture timestamp is outside the measured session (1s tolerance)")
            timestamps.append(timestamp)
        if timestamps != sorted(timestamps):
            raise RuntimeError("captured timestamps are not nondecreasing")
        item.update({"captured_frames": len(lines), "log": output.name,
                     "log_sha256": sha256(output), "timestamp_range_us": [before_us, after_us]})

    def idle_timeout(item):
        output = run_dir / "idle-timeout.log"
        command = [str(capture), "--if", interface, "--out", str(output), "--max-seconds", "1"]
        completed = execute(command, "idle-timeout", run_dir, result, lambda: None)
        if completed["returncode"] != 0 or not 0.8 <= completed["elapsed_seconds"] <= 4:
            raise RuntimeError("--max-seconds 1 did not terminate successfully within 0.8 to 4 seconds")
        if output.read_bytes():
            raise RuntimeError("idle test received other traffic; an idle vcan interface is required")
        item.update({"elapsed_seconds": completed["elapsed_seconds"], "captured_frames": 0,
                     "log": output.name, "log_sha256": sha256(output)})

    def remote_frame_excluded(item):
        output = run_dir / "remote-frame.log"
        def send():
            send_raw_frames("interface-before-rtr", [(0x40000123, 2, b""),
                                                       (0x456, 2, bytes.fromhex("1122"))])
        completed = execute([str(capture), "--if", interface, "--out", str(output),
                             "--max-frames", "1"], "remote-frame", run_dir, result, send)
        lines = output.read_text(encoding="ascii").splitlines()
        if completed["returncode"] != 0 or len(lines) != 1 or not re.fullmatch(
                r"\([0-9]+\.[0-9]{6}\) " + re.escape(interface) + r" 456#1122", lines[0]):
            raise RuntimeError("RTR frame was recorded or counted as a data frame")
        item.update({"log": output.name, "log_sha256": sha256(output), "data_frames": 1})

    def missing_interface_preserves_log(item):
        nonexistent = "cs_missing_09"
        try:
            socket.if_nametoindex(nonexistent)
        except OSError:
            pass
        else:
            raise RuntimeError("missing-interface fixture unexpectedly exists")
        output = run_dir / "preserved-existing.log"
        output.write_bytes(b"existing log must survive a failed interface open\n")
        before = sha256(output)
        completed = execute([str(capture), "--if", nonexistent, "--out", str(output),
                             "--max-frames", "1"], "invalid-interface", run_dir, result)
        if completed["returncode"] == 0 or sha256(output) != before:
            raise RuntimeError("invalid interface was accepted or destroyed the existing log")
        item.update({"before_sha256": before, "after_sha256": sha256(output), "log": output.name})

    def write_failure(item):
        if not Path("/dev/full").exists():
            raise RuntimeError("/dev/full is required for the disk-full regression check")
        def send():
            send_raw_frames("interface-before-write-failure", [(0x123, 1, b"\xAA")])
        completed = execute([str(capture), "--if", interface, "--out", "/dev/full",
                             "--max-frames", "1"], "write-failure", run_dir, result, send)
        stderr = (run_dir / completed["stderr"]).read_text(encoding="utf-8", errors="replace")
        if completed["returncode"] == 0 or "cansec-capture error:" not in stderr or "Captured " in stderr:
            raise RuntimeError("output write failure was not reported as failure")
        item["returncode"] = completed["returncode"]

    check("known_frames_and_max_frames", known_frames)
    check("max_seconds_without_received_frames", idle_timeout)
    check("remote_frame_excluded_from_data_log", remote_frame_excluded)
    check("invalid_interface_preserves_existing_log", missing_interface_preserves_log)
    check("output_write_failure", write_failure)
    for name, invalid_args, expected_error in [
        ("negative-max-frames", ["--if", interface, "--max-frames", "-1"], "must be non-negative"),
        ("negative-max-seconds", ["--if", interface, "--max-seconds", "-1"], "must be non-negative"),
        ("fractional-max-seconds", ["--if", interface, "--max-seconds", "0.5"], "invalid integer"),
        ("trailing-max-seconds", ["--if", interface, "--max-seconds", "0junk"], "invalid integer"),
        ("trailing-max-frames", ["--if", interface, "--max-frames", "1junk"], "invalid integer"),
        ("overflow-max-frames", ["--if", interface, "--max-frames", "2147483648"], "invalid integer"),
        ("empty-max-frames", ["--if", interface, "--max-frames", ""], "invalid integer"),
        ("oversized-interface", ["--if", "v" * 16, "--max-frames", "1"], "interface name must contain"),
        ("missing-interface", ["--max-frames", "1"], "missing required option: --if"),
        ("missing-output", ["--if", interface, "--max-frames", "1"], "missing required option: --out"),
    ]:
        def reject(item, name=name, invalid_args=invalid_args, expected_error=expected_error):
            output = run_dir / (name + ".log")
            command = [str(capture)] + invalid_args
            if name != "missing-output":
                command += ["--out", str(output)]
            completed = execute(command, name, run_dir, result)
            stderr = (run_dir / completed["stderr"]).read_text(encoding="utf-8", errors="replace")
            if completed["returncode"] == 0 or expected_error not in stderr or output.exists():
                raise RuntimeError("invalid options were not rejected before opening the output")
            item["returncode"] = completed["returncode"]
        check(name, reject)
    return all(item["passed"] for item in result["checks"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, help="path to the Linux cansec-capture executable")
    parser.add_argument("--interface", default="vcan0", help="existing idle vcan interface (default: vcan0)")
    parser.add_argument("--output-dir", required=True, help="parent directory for run output")
    args = parser.parse_args()
    output_root = Path(args.output_dir).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("capture-%Y%m%dT%H%M%SZ-"),
                                    dir=output_root))
    root = Path(__file__).resolve().parent.parent
    source_files = ["scripts/verify_capture_linux.py", "CMakeLists.txt", "src/tools/main_capture.cpp",
                    "src/common/socketcan.cpp", "src/common/logio.cpp", "include/cansec/socketcan.hpp",
                    "include/cansec/logio.hpp", "include/cansec/types.hpp"]
    result = {"status": "failed", "started_utc": started, "interface": args.interface,
              "invocation": [sys.executable] + sys.argv, "working_directory": str(Path.cwd()),
              "environment": {"platform": platform.platform(), "python": sys.version,
                              "uname": platform.uname()._asdict()},
              "capture_path": str(Path(args.capture).resolve()), "source_sha256": {},
              "commands": [], "checks": []}
    try:
        result["source_sha256"] = {name: sha256(root / name) for name in source_files}
        capture = Path(args.capture).resolve()
        if capture.is_file():
            result["capture_sha256"] = sha256(capture)
        if verify(args, run_dir, result):
            result["status"] = "passed"
    except (OSError, RuntimeError, ValueError) as error:
        result["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        with (run_dir / "result.json").open("x", encoding="utf-8") as output:
            json.dump(result, output, ensure_ascii=False, indent=2)
            output.write("\n")
        print("Results: " + str(run_dir))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
