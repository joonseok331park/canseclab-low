#!/usr/bin/env python3
"""Verify replay modes and detector alerts with an independent idle-vcan receiver."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import select
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
CAN_ERR_FLAG = 0x20000000


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


class LoggedChild:
    """Run one child process with stdout/stderr saved to files in the run directory."""

    def __init__(self, command, name, run_dir, result, timeout=5):
        self.run_dir = run_dir
        self.start = time.monotonic()
        self.process = None
        self.handles = []
        self.record = {"command": command, "stdout": name + ".stdout.txt",
                       "stderr": name + ".stderr.txt", "timeout_seconds": timeout,
                       "started_us": time.time_ns() // 1000,
                       "started_monotonic_ns": time.monotonic_ns()}
        result["commands"].append(self.record)
        try:
            for stream in ("stdout", "stderr"):
                self.handles.append((run_dir / self.record[stream]).open("xb"))
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                            stdout=self.handles[0], stderr=self.handles[1], shell=False)
        except OSError:
            self.close()
            raise

    def stdout(self):
        return (self.run_dir / self.record["stdout"]).read_bytes()

    def stderr(self):
        return (self.run_dir / self.record["stderr"]).read_bytes()

    def wait(self, timeout=5):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.record["timed_out"] = True
            raise RuntimeError("child process timed out") from error

    def ready(self, line, timeout=5):
        deadline = time.monotonic() + timeout
        while line.encode("utf-8") not in self.stderr().splitlines(keepends=True):
            if self.process.poll() is not None:
                raise RuntimeError("child exited before its exact ready message")
            if time.monotonic() >= deadline:
                self.record["timed_out"] = True
                raise RuntimeError("child readiness timed out")
            time.sleep(0.01)
        self.record["ready_message_observed"] = True

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.record["cleanup_terminated_child"] = True
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.record["cleanup_killed_child"] = True
                    self.process.kill()
                    self.process.wait(timeout=2)
            self.record["returncode"] = self.process.returncode
        for handle in self.handles:
            handle.close()
        self.record["finished_us"] = time.time_ns() // 1000
        self.record["elapsed_seconds"] = round(time.monotonic() - self.start, 6)
        for stream in ("stdout", "stderr"):
            path = self.run_dir / self.record[stream]
            if path.is_file():
                self.record[stream + "_sha256"] = sha256(path)


def require_vcan(ip_command, interface, name, run_dir, result):
    child = LoggedChild([ip_command, "-details", "-json", "link", "show", "dev", interface],
                        name, run_dir, result)
    try:
        child.wait()
        if child.process.returncode != 0:
            raise RuntimeError("ip could not inspect the requested interface")
        links = json.loads(child.stdout())
    finally:
        child.close()
    if not isinstance(links, list) or len(links) != 1:
        raise RuntimeError("ip did not identify exactly one interface")
    link = links[0]
    if link.get("linkinfo", {}).get("info_kind") != "vcan":
        raise RuntimeError("interface is not verified as vcan; replay was not started")
    if link.get("ifname") != interface or "UP" not in link.get("flags", []):
        raise RuntimeError("requested vcan interface must already be UP")
    if type(link.get("ifindex")) is not int or link["ifindex"] <= 0:
        raise RuntimeError("invalid vcan interface index")
    return link


class Receiver:
    """Receive-only Classical CAN socket, with kernel timestamps when available."""

    def __init__(self, interface):
        self.frames = []
        self.socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.timestamp_option = getattr(socket, "SO_TIMESTAMPNS", None)
        self.timestamp_note = None
        # On 64-bit Linux the legacy timespec has two native 64-bit longs.
        if self.timestamp_option is None and struct.calcsize("@l") == 8:
            self.timestamp_option = 35  # Linux SO_TIMESTAMPNS_OLD.
        try:
            if self.timestamp_option is not None:
                try:
                    self.socket.setsockopt(socket.SOL_SOCKET, self.timestamp_option, 1)
                except OSError as error:
                    self.timestamp_note = "SO_TIMESTAMPNS unavailable: " + str(error)
                    self.timestamp_option = None
            else:
                self.timestamp_note = "SO_TIMESTAMPNS unavailable in this Python/Linux ABI"
            self.socket.bind((interface,))
            self.socket.setblocking(False)
        except OSError:
            self.socket.close()
            raise

    def receive(self, wait=0.01):
        if not select.select([self.socket], [], [], wait)[0]:
            return False
        raw, ancillary, flags, address = self.socket.recvmsg(16, socket.CMSG_SPACE(32))
        monotonic_ns = time.monotonic_ns()
        realtime_ns = time.time_ns()
        if len(raw) != 16 or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("receiver observed a truncated or non-Classical CAN frame")
        raw_id, dlc, data = struct.unpack("=IB3x8s", raw)
        if dlc > 8:
            raise RuntimeError("receiver observed an invalid Classical CAN DLC")
        kernel_ns = None
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == self.timestamp_option:
                if len(value) >= struct.calcsize("@ll"):
                    seconds, nanoseconds = struct.unpack("@ll", value[:struct.calcsize("@ll")])
                    if not 0 <= nanoseconds < 1000000000:
                        raise RuntimeError("invalid kernel receive timestamp")
                    kernel_ns = seconds * 1000000000 + nanoseconds
        extended = bool(raw_id & CAN_EFF_FLAG)
        self.frames.append({"raw_hex": raw.hex().upper(), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                            "raw_id": raw_id, "can_id": raw_id & (0x1FFFFFFF if extended else 0x7FF),
                            "id_type": "extended" if extended else "standard", "dlc": dlc,
                            "data": data[:dlc].hex().upper(), "rtr": bool(raw_id & CAN_RTR_FLAG),
                            "error_frame": bool(raw_id & CAN_ERR_FLAG), "interface": address[0],
                            "kernel_realtime_ns": kernel_ns, "receive_realtime_ns": realtime_ns,
                            "receive_monotonic_ns": monotonic_ns})
        return True

    def close(self):
        self.socket.close()


def frame(timestamp_us, can_id, data, extended=False):
    return {"timestamp_us": timestamp_us, "can_id": can_id,
            "id_type": "extended" if extended else "standard", "dlc": len(bytes.fromhex(data)),
            "data": data.upper()}


def verify(args, run_dir, result):
    if sys.platform != "linux":
        raise RuntimeError("Linux is required; no replay verification was executed")
    replay, detect = Path(args.replay).resolve(), Path(args.detect).resolve()
    for path in (replay, detect):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError("both executable arguments must name executable Linux files")
    ip_command = shutil.which("ip")
    if not ip_command:
        raise RuntimeError("ip is required to verify that the interface is virtual CAN")
    interface = args.interface
    initial = require_vcan(ip_command, interface, "interface-initial", run_dir, result)
    result["interface_details"] = initial
    fixture_interface_check = {"interface": "archived9", "query": "socket.if_nametoindex",
                               "required_absent": True, "observed_absent": False}
    result["fixture_interface_check"] = fixture_interface_check
    try:
        fixture_interface_check["observed_ifindex"] = socket.if_nametoindex("archived9")
    except OSError as error:
        fixture_interface_check.update({"observed_absent": True, "query_error": str(error),
                                        "query_errno": error.errno})
    else:
        raise RuntimeError("fixture interface archived9 already exists; no replay tests were started")

    def check(name, action):
        item = {"name": name, "passed": False}
        result["checks"].append(item)
        try:
            action(item)
            item["passed"] = True
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            item["error"] = str(error)
        print(("PASS " if item["passed"] else "FAIL ") + name, flush=True)

    def fixture(name, frames=None, text=None):
        path = run_dir / (name + ".log")
        if text is None:
            lines = ["# Interface names in this archived log are not replay destinations.", ""]
            for source in frames:
                seconds, micros = divmod(source["timestamp_us"], 1000000)
                can_id = format(source["can_id"], "08X" if source["id_type"] == "extended" else "03X")
                lines.append(f"({seconds}.{micros:06d}) archived9 {can_id}#{source['data']}")
            text = "\n".join(lines) + "\n"
        path.write_text(text, encoding="ascii", newline="\n")
        result["inputs"].append({"path": path.name, "sha256": sha256(path), "expected_frames": frames})
        return path

    def invocation(path, extra=(), device=interface):
        return [str(replay), "normal", "--if", device, "--in", str(path)] + list(extra)

    def run(name, argv, stop_signal=None, timeout=5, stop_after_ready=False):
        receiver = Receiver(interface)
        child = None
        try:
            current = require_vcan(ip_command, interface, name + "-interface", run_dir, result)
            if current["ifindex"] != initial["ifindex"] or socket.if_nametoindex(interface) != initial["ifindex"]:
                raise RuntimeError("vcan interface identity changed; replay was not started")
            if receiver.receive(0.02):
                raise RuntimeError("interface has unrelated traffic; an idle vcan is required")
            child = LoggedChild(argv, name, run_dir, result, timeout)
            exit_seen = None
            first_seen = None
            ready_seen = None
            ready_line = f"Replaying {argv[1]} CAN frames to {interface}\n".encode("utf-8") if len(argv) > 1 else None
            while True:
                receiver.receive(0.005)
                now = time.monotonic()
                if ready_seen is None and ready_line is not None and ready_line in child.stderr().splitlines(keepends=True):
                    ready_seen = now
                    child.record["ready_observed_monotonic_ns"] = time.monotonic_ns()
                if receiver.frames and first_seen is None:
                    first_seen = now
                signal_anchor = ready_seen if stop_after_ready else first_seen
                if stop_signal is not None and signal_anchor is not None and now - signal_anchor >= 0.1:
                    if child.process.poll() is not None:
                        raise RuntimeError("replay exited before its long-wait signal test")
                    child.process.send_signal(stop_signal)
                    child.record["sent_signal"] = stop_signal.name
                    child.record["signal_monotonic_ns"] = time.monotonic_ns()
                    stop_signal = None
                if child.process.poll() is not None:
                    if exit_seen is None:
                        exit_seen = now
                    if now - exit_seen >= 0.1:
                        break
                if now - child.start >= timeout:
                    child.record["timed_out"] = True
                    raise RuntimeError("replay timed out")
            child.record["process_exit_monotonic_ns"] = time.monotonic_ns()
        finally:
            if child is not None:
                child.close()
            receiver.close()
            received_path = run_dir / (name + ".received.json")
            write_json(received_path, {"frames": receiver.frames, "timestamp_option": receiver.timestamp_option,
                                       "timestamp_note": receiver.timestamp_note,
                                       "measurement": "kernel SO_TIMESTAMPNS when present; userspace realtime and monotonic also recorded"})
            result["received"].append({"path": received_path.name, "sha256": sha256(received_path),
                                       "frame_count": len(receiver.frames)})
        return child.record, receiver.frames

    def success(completed, received, expected, interrupted=False, mode="normal"):
        stdout = (run_dir / completed["stdout"]).read_bytes()
        stderr = (run_dir / completed["stderr"]).read_bytes()
        expected_stderr = f"Replaying {mode} CAN frames to {interface}\nSent {len(expected)} frame(s).\n"
        if interrupted:
            expected_stderr += "Interrupted by signal.\n"
        if completed["returncode"] != 0 or stdout or stderr != expected_stderr.encode("utf-8"):
            raise RuntimeError("replay exit/stdout/ready/summary differs from the CLI contract")
        if len(received) != len(expected):
            raise RuntimeError(f"expected {len(expected)} received frames; observed {len(received)}")
        for observed, source in zip(received, expected):
            if any(observed[key] != source[key] for key in ("can_id", "id_type", "dlc", "data")):
                raise RuntimeError("replay changed frame content, ID type, length, or order")
            raw_id = source["can_id"] | (CAN_EFF_FLAG if source["id_type"] == "extended" else 0)
            if observed["raw_id"] != raw_id or observed["rtr"] or observed["error_frame"] or observed["interface"] != interface:
                raise RuntimeError("replay changed raw CAN flags or destination interface")
            lower = completed["started_us"] * 1000 - 1000000000
            upper = completed["finished_us"] * 1000 + 1000000000
            if not lower <= observed["receive_realtime_ns"] <= upper:
                raise RuntimeError("receiver timestamp is outside the run's start/end time")
            if observed["kernel_realtime_ns"] is not None and not lower <= observed["kernel_realtime_ns"] <= upper:
                raise RuntimeError("kernel timestamp is outside the run's start/end time")

    def timing(item, received, offsets_us, interval_tolerance_us=None, span_tolerance_us=None):
        method = "kernel_realtime_ns" if all(source["kernel_realtime_ns"] is not None for source in received) else "receive_monotonic_ns"
        timestamps = [source[method] for source in received]
        expected = [later - earlier for earlier, later in zip(offsets_us, offsets_us[1:])]
        measured = [(later - earlier) / 1000 for earlier, later in zip(timestamps, timestamps[1:])]
        # This excludes a speed factor of two while allowing ordinary scheduler jitter.
        tolerances = [interval_tolerance_us if interval_tolerance_us is not None else
                      5000 + max(15000, interval * 0.20) for interval in expected]
        duration_expected = offsets_us[-1] - offsets_us[0]
        duration_observed = (timestamps[-1] - timestamps[0]) / 1000
        duration_tolerance = span_tolerance_us if span_tolerance_us is not None else \
            10000 + max(20000, duration_expected * 0.15)
        item.update({"timing_method": method, "expected_intervals_us": expected,
                     "observed_intervals_us": measured, "interval_tolerances_us": tolerances,
                     "expected_span_us": duration_expected, "observed_span_us": duration_observed,
                     "span_tolerance_us": duration_tolerance,
                     "userspace_receive_intervals_us": [
                         (later["receive_monotonic_ns"] - earlier["receive_monotonic_ns"]) / 1000
                         for earlier, later in zip(received, received[1:])]})
        if any(value < 0 or abs(value - target) > tolerance for value, target, tolerance in zip(measured, expected, tolerances)):
            raise RuntimeError("measured interval is outside the recorded tolerance")
        if abs(duration_observed - duration_expected) > duration_tolerance:
            raise RuntimeError("measured replay span is outside the recorded tolerance")

    def positive(item, name, sources, speed=1.0, loops=1, measure=True, default_options=False):
        path = fixture(name, sources)
        extra = [] if default_options else ["--speed", str(speed), "--loop", str(loops)]
        completed, received = run(name, invocation(path, extra))
        success(completed, received, sources * loops)
        item.update({"input": path.name, "received": name + ".received.json",
                     "frames": len(received), "speed": speed, "loops": loops})
        if measure and len(received) > 1:
            first, span = sources[0]["timestamp_us"], sources[-1]["timestamp_us"] - sources[0]["timestamp_us"]
            offsets = [(iteration * span + source["timestamp_us"] - first) / speed
                       for iteration in range(loops) for source in sources]
            timing(item, received, offsets)

    identity = [frame(1000000, 0x123, ""), frame(1050000, 0x7FF, "0001027F80ABEFFF"),
                frame(1100000, 0x123, "AABB", True), frame(1150000, 0x1FFFFFFF, "00FF55", True)]
    spaced = [frame(1000000 + index * 100000, 0x321, f"{index:02X}10AABB") for index in range(4)]
    check("frame_identity_order_and_cli_destination", lambda item: positive(item, "identity", identity, default_options=True))
    for name, speed in (("speed_one", 1.0), ("speed_two", 2.0), ("speed_half", 0.5)):
        check(name, lambda item, name=name, speed=speed: positive(item, name, spaced, speed))
    check("loop_two_without_added_gap", lambda item: positive(item, "loop-two", spaced[:3], loops=2))
    duplicates = [frame(1000000, 0x222, "01"), frame(1000000, 0x222, "02"), frame(1100000, 0x222, "03")]
    check("duplicate_timestamps_allowed", lambda item: positive(item, "duplicates", duplicates))
    check("single_frame_log", lambda item: positive(item, "single", [frame(7000000, 0x456, "1122")]))

    def rejected(item, name, path, argv=None):
        completed, received = run(name, invocation(path) if argv is None else argv, timeout=3)
        stderr = (run_dir / completed["stderr"]).read_bytes()
        if completed["returncode"] != 1 or not stderr or (run_dir / completed["stdout"]).read_bytes():
            raise RuntimeError("invalid replay input did not fail with exit 1, stderr, and empty stdout")
        if received:
            raise RuntimeError("invalid replay input sent CAN frames before being rejected")
        if b"Replaying " in stderr or b"Sent " in stderr:
            raise RuntimeError("invalid replay input emitted readiness or a success summary")
        item.update({"returncode": completed["returncode"], "received_frames": 0,
                     "received": name + ".received.json"})

    check("late_invalid_line_sends_nothing", lambda item: rejected(item, "late-invalid", fixture("late-invalid", text=
          "(1.000000) archived9 100#0010\n(1.100000) archived9 101#0110\ninvalid final line\n")))
    check("decreasing_timestamp_sends_nothing", lambda item: rejected(item, "decreasing", fixture("decreasing", text=
          "(1.000000) archived9 100#0010\n(1.100000) archived9 101#0110\n(1.050000) archived9 102#0210\n")))
    check("empty_log_sends_nothing", lambda item: rejected(item, "empty", fixture("empty", text="# No frames\n\n")))

    def bad_options(item):
        path = fixture("bad-cli-input", [frame(1000000, 0x100, "0010")])
        base = invocation(path)
        variants = [("missing-mode", [str(replay)]),
                    ("unknown-mode", [str(replay), "invalid-mode"]),
                    ("missing-if", [str(replay), "normal", "--in", str(path)]),
                    ("missing-in", [str(replay), "normal", "--if", interface]),
                    ("unknown-option", base + ["--invalid", "1"]),
                    ("duplicate-option", base + ["--loop", "1", "--loop", "2"]),
                    ("incomplete-option", base + ["--speed"])]
        for label, value in (("zero", "0"), ("negative", "-1"), ("nan", "nan"), ("infinity", "inf"),
                             ("trailing", "1junk"), ("empty", "")):
            variants.append(("speed-" + label, base + ["--speed", value]))
        for label, value in (("zero", "0"), ("negative", "-1"), ("fractional", "1.5"),
                             ("trailing", "1junk"), ("overflow", "18446744073709551616")):
            variants.append(("loop-" + label, base + ["--loop", value]))
        item["variants"] = []
        for name, argv in variants:
            detail = {"name": name}
            rejected(detail, "bad-cli-" + name, path, argv)
            item["variants"].append(detail)

    check("invalid_cli_options_send_nothing", bad_options)

    def missing_interface(item):
        device = "cs" + str(os.getpid())[-8:] + "miss"
        try:
            socket.if_nametoindex(device)
        except OSError:
            pass
        else:
            raise RuntimeError("missing-interface fixture unexpectedly exists")
        path = fixture("missing-if-input", [frame(1000000, 0x100, "0010")])
        rejected(item, "missing-interface", path, invocation(path, device=device))

    check("missing_interface_sends_nothing", missing_interface)

    def graceful_signal(item, selected):
        name = "signal-" + selected.name.lower()
        sources = [frame(1000000, 0x456, "1122"), frame(11000000, 0x456, "3344")]
        path = fixture(name, sources)
        completed, received = run(name, invocation(path), stop_signal=selected, timeout=3)
        success(completed, received, sources[:1], interrupted=True)
        if completed.get("sent_signal") != selected.name:
            raise RuntimeError("signal was not delivered during the long replay wait")
        elapsed = (completed["process_exit_monotonic_ns"] - completed["signal_monotonic_ns"]) / 1000000000
        if elapsed > 2:
            raise RuntimeError("signal did not interrupt the ten-second replay wait promptly")
        item.update({"signal": selected.name, "received_frames": 1, "post_signal_seconds": elapsed,
                     "unreached_source_wait_us": 10000000, "received": name + ".received.json"})

    check("sigint_interrupts_long_wait", lambda item: graceful_signal(item, signal.SIGINT))
    check("sigterm_interrupts_long_wait", lambda item: graceful_signal(item, signal.SIGTERM))

    def detector_integration(item):
        sources = [frame(1000000 + index * 100000, 0x100, f"{index:02X}100000") for index in range(3)]
        path = fixture("normal-with-detector", sources)
        policy = run_dir / "normal-rules.ini"
        policy.write_text("[global]\nwindow_ms=100\n[id:0x100]\nid_type=standard\nallowed_dlc=4\n"
                          "periodic=1\nperiod_min_us=50000\nperiod_max_us=150000\nrate_limit_100ms=3\n"
                          "fixed_mask=00FF000000000000\nfixed_value=0010000000000000\n"
                          "ignore_mask=0000000000000000\nmax_identical_payload_run=3\n", encoding="ascii")
        result["inputs"].append({"path": policy.name, "sha256": sha256(policy)})
        output = run_dir / "normal-alerts.jsonl"
        detector = LoggedChild([str(detect), "--rules", str(policy), "--if", interface,
                                "--out", str(output), "--max-frames", "3", "--max-seconds", "3"],
                               "normal-detector", run_dir, result)
        try:
            detector.ready(f"Detecting CAN frames from {interface} -> {output}\n")
            completed, received = run("normal-with-detector", invocation(path))
            success(completed, received, sources)
            detector.wait(4)
        finally:
            detector.close()
        expected = f"Detecting CAN frames from {interface} -> {output}\nProcessed 3 frame(s); 0 alert(s).\n"
        if detector.record["returncode"] != 0 or detector.stdout() or detector.stderr() != expected.encode("utf-8"):
            raise RuntimeError("normal replay did not produce detector processed=3, alerts=0")
        if output.read_bytes():
            raise RuntimeError("normal replay produced unexpected detector alerts")
        item.update({"processed_frames": 3, "alerts": 0, "output": output.name,
                     "output_sha256": sha256(output), "period_policy_us": [50000, 150000],
                     "received": "normal-with-detector.received.json"})
        timing(item, received, [0, 100000, 200000])

    check("normal_replay_detector_zero_alerts", detector_integration)

    def mode_command(mode, options):
        argv = [str(replay), mode, "--if", interface]
        for key, value in options.items():
            argv += [key, str(value)]
        return argv

    def request_fixture(name, argv, sources, offsets):
        path = run_dir / (name + ".request.json")
        write_json(path, {"command": argv, "expected_frames": sources,
                          "expected_relative_offsets_us": offsets})
        result["inputs"].append({"path": path.name, "sha256": sha256(path)})

    def first_delay(item, completed, received, expected_us):
        first = received[0]["receive_monotonic_ns"]
        from_launch = (first - completed["started_monotonic_ns"]) / 1000
        ready_ns = completed.get("ready_observed_monotonic_ns")
        from_ready = None if ready_ns is None else (first - ready_ns) / 1000
        item["initial_delay"] = {
            "expected_us": expected_us, "observed_launch_to_receive_us": from_launch,
            "observed_ready_to_receive_us": from_ready,
            "launch_tolerance_us": [-20000, 250000], "ready_tolerance_us": [-20000, 100000],
            "method": "userspace monotonic receive minus launch or first observed ready message"}
        if not expected_us - 20000 <= from_launch <= expected_us + 250000:
            raise RuntimeError("initial replay delay is outside the recorded launch-based tolerance")
        if from_ready is None or not expected_us - 20000 <= from_ready <= expected_us + 100000:
            raise RuntimeError("initial replay delay is outside the recorded readiness-based tolerance")

    def mode_positive(item, name, mode, options, sources, offsets, timing_limits=None):
        argv = mode_command(mode, options)
        request_fixture(name, argv, sources, offsets)
        completed, received = run(name, argv)
        success(completed, received, sources, mode=mode)
        item.update({"mode": mode, "frames": len(received), "received": name + ".received.json"})
        if len(received) > 1:
            timing(item, received, offsets, *(timing_limits or (None, None)))
        return completed, received

    def attack_policy(name, rate_limit, max_run):
        path = run_dir / (name + "-rules.ini")
        path.write_text(
            "[global]\nwindow_ms=100\n[id:0x100]\nid_type=standard\nallowed_dlc=4\n"
            "periodic=0\nperiod_min_us=0\nperiod_max_us=0\n"
            f"rate_limit_100ms={rate_limit}\nfixed_mask=00FF000000000000\n"
            "fixed_value=0010000000000000\nignore_mask=0000000000000000\n"
            f"max_identical_payload_run={max_run}\n", encoding="ascii", newline="\n")
        result["inputs"].append({"path": path.name, "sha256": sha256(path)})
        return path

    def attack_detector(item, name, mode, options, sources, offsets, expected_alerts,
                        rate_limit=1000, max_run=3, delay_us=None):
        policy = attack_policy(name, rate_limit, max_run)
        output = run_dir / (name + "-alerts.jsonl")
        expected_fields = {"capture_ts_us", "alert_ts_us", "if", "rule", "severity",
                           "can_id", "id_type", "dlc", "data", "detail"}
        oracle = [{"frame_index": index, "rule": rule, "severity": severity, "detail": detail,
                   "can_id": f"0x{sources[index]['can_id']:X}", "id_type": sources[index]["id_type"],
                   "dlc": sources[index]["dlc"], "data": sources[index]["data"]}
                  for index, rule, severity, detail in expected_alerts]
        oracle_path = run_dir / (name + ".expected-alerts.json")
        write_json(oracle_path, {"alerts_in_order": oracle,
                                 "policy": {"rate_limit_100ms": rate_limit, "max_identical_payload_run": max_run}})
        item.update({"expected_alerts": oracle_path.name, "expected_rule_counts": dict(Counter(row["rule"] for row in oracle)),
                     "rules": policy.name, "output": output.name})
        detector = LoggedChild([str(detect), "--rules", str(policy), "--if", interface, "--out", str(output),
                                "--max-frames", str(len(sources)), "--max-seconds", "3"],
                               name + "-detector", run_dir, result)
        try:
            detector.ready(f"Detecting CAN frames from {interface} -> {output}\n")
            # The 10 ms flood fixture must distinguish an incorrect 5 ms replay.
            limits = (4000, 10000) if mode == "flood" else None
            completed, received = mode_positive(item, name, mode, options, sources, offsets, timing_limits=limits)
            detector.wait(4)
        finally:
            detector.close()
        if delay_us is not None:
            first_delay(item, completed, received, delay_us)
        expected_stderr = (f"Detecting CAN frames from {interface} -> {output}\n"
                           f"Processed {len(sources)} frame(s); {len(oracle)} alert(s).\n")
        if detector.record["returncode"] != 0 or detector.stdout() or detector.stderr() != expected_stderr.encode("utf-8"):
            raise RuntimeError("attack replay detector exit or processed/alert summary is incorrect")
        raw = output.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise RuntimeError("attack alert JSONL has an unterminated line")
        alerts = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
        item.update({"output_sha256": sha256(output), "processed_frames": len(received), "alerts": len(alerts)})
        if len(alerts) != len(oracle):
            raise RuntimeError("JSONL line count differs from the expected alerts")
        timestamp_pairs = []
        previous_capture = 0
        for actual, expected in zip(alerts, oracle):
            if not isinstance(actual, dict) or set(actual) != expected_fields:
                raise RuntimeError("attack JSONL field set differs from the required schema")
            if any(type(actual[key]) is not int for key in ("capture_ts_us", "alert_ts_us", "dlc")) or \
                    any(type(actual[key]) is not str for key in expected_fields - {"capture_ts_us", "alert_ts_us", "dlc"}):
                raise RuntimeError("attack JSONL field types are incorrect")
            if actual["if"] != interface or any(actual[key] != value for key, value in expected.items() if key != "frame_index"):
                raise RuntimeError("attack alert rule, payload, ID, severity, or detail does not match its source frame")
            capture, emitted = actual["capture_ts_us"], actual["alert_ts_us"]
            if not detector.record["started_us"] - 1000000 <= capture <= emitted <= detector.record["finished_us"] + 1000000:
                raise RuntimeError("alert timestamps are reversed or outside the run's start/end time")
            if capture < previous_capture:
                raise RuntimeError("attack capture timestamps decreased")
            previous_capture = capture
            source = received[expected["frame_index"]]
            observed_ns = source["kernel_realtime_ns"] if source["kernel_realtime_ns"] is not None else source["receive_realtime_ns"]
            timestamp_pairs.append({"frame_index": expected["frame_index"], "rule": actual["rule"],
                                    "capture_ts_us": capture, "alert_ts_us": emitted,
                                    "independent_receive_ns": observed_ns,
                                    "capture_minus_independent_receive_us": capture - observed_ns / 1000})
        observed_counts = Counter(alert["rule"] for alert in alerts)
        if observed_counts != Counter(row["rule"] for row in oracle):
            raise RuntimeError("primary or secondary attack warning counts are incorrect")
        item.update({"observed_rule_counts": dict(observed_counts), "timestamp_pairs": timestamp_pairs})
        if mode == "flood":
            # All six frames must fall in one 100 ms window for the expected RATE_SPIKE count.
            method = "kernel_realtime_ns" if all(row["kernel_realtime_ns"] is not None for row in received) else "receive_monotonic_ns"
            measured_span = (received[-1][method] - received[0][method]) / 1000
            item["rate_oracle_receive_span_us"] = measured_span
            if not 0 <= measured_span < 100000:
                raise RuntimeError("flood frames did not fit in one 100 ms window")

    flood_sources = [frame(index * 10000, 0x100, "00100000") for index in range(6)]
    flood_options = {"--id": "0x100", "--data": "00100000", "--interval-us": 10000, "--count": 6}
    flood_alerts = [(index, "RATE_SPIKE", "HIGH", f"count_100ms={index + 1} threshold=3") for index in range(3, 6)]
    check("flood_rate_spike_matches_received_frames", lambda item: attack_detector(
          item, "flood-rate", "flood", flood_options, flood_sources, [index * 10000 for index in range(6)],
          flood_alerts, rate_limit=3, max_run=100))

    def range_replay(item):
        path = fixture("replay-selected", text=(
            "# Physical line 1\n(1.000000) archived9 777#AA\n\n"
            "(1.100000) archived9 100#01100000\n# Physical line 5\n"
            "(1.150000) archived9 100#01100000\n(1.250000) archived9 778#BB\n"))
        sources = [frame(offset, 0x100, "01100000") for offset in (0, 50000, 50000, 100000, 100000, 150000)]
        options = {"--in": path, "--start-line": 3, "--end-line": 6, "--delay-ms": 200, "--repeat": 3}
        alerts = [(index, "REPLAY_BURST", "HIGH", f"identical_payload_run={index + 1} threshold=3") for index in range(3, 6)]
        item.update({"selected_physical_lines": [4, 6], "requested_physical_range": [3, 6], "repeat": 3})
        attack_detector(item, "replay-burst", "replay", options, sources,
                        [0, 50000, 50000, 100000, 100000, 150000], alerts, delay_us=200000)

    check("selected_range_repeat_replay_burst_and_initial_delay", range_replay)
    fixed_detail = "fixed_byte_mismatches=[index=1 observed=0xEF expected=0x10 effective_mask=0xFF]"
    fuzz_sources = [frame(index * 50000, 0x100, "00EF0000") for index in range(4)]
    fuzz_options = {"--id": "100", "--base-data": "00100000", "--period-us": 50000,
                    "--count": 4, "--flip-mask": "00FF0000"}
    fuzz_alerts = [(index, "FIXED_BYTE_VIOLATION", "MEDIUM", fixed_detail) for index in range(4)]
    fuzz_alerts.append((3, "REPLAY_BURST", "HIGH", "identical_payload_run=4 threshold=3"))
    check("fuzz_fixed_and_secondary_replay_alerts", lambda item: attack_detector(
          item, "fuzz-fixed", "fuzz", fuzz_options, fuzz_sources, [0, 50000, 100000, 150000], fuzz_alerts))

    check("flood_extended_low_id_empty_payload", lambda item: mode_positive(
          item, "flood-empty-extended", "flood",
          {"--id": "00000123", "--data": "", "--interval-us": 50000, "--count": 3},
          [frame(index * 50000, 0x123, "", True) for index in range(3)], [0, 50000, 100000]))
    check("fuzz_extended_eight_byte_payload", lambda item: mode_positive(
          item, "fuzz-eight-extended", "fuzz",
          {"--id": "0x1ABCDE", "--base-data": "0001027F80ABEFFF", "--period-us": 50000,
           "--count": 3, "--flip-mask": "FF000000000000FF"},
          [frame(index * 50000, 0x1ABCDE, "FF01027F80ABEF00", True) for index in range(3)], [0, 50000, 100000]))

    def selected_identity(item):
        path = fixture("replay-identity", text=(
            "# Physical line 1\n(1.000000) archived9 555#DEAD\n\n"
            "(1.100000) archived9 00000123#AABB\n# Physical line 5\n"
            "(1.150000) archived9 7FF#\n(1.200000) archived9 100#0102030405060708\n"
            "(1.250000) archived9 666#BEEF\n"))
        sources = [frame(0, 0x123, "AABB", True), frame(50000, 0x7FF, ""), frame(100000, 0x100, "0102030405060708")]
        item.update({"selected_physical_lines": [4, 6, 7], "requested_physical_range": [3, 7]})
        mode_positive(item, "replay-identity", "replay",
                      {"--in": path, "--start-line": 3, "--end-line": 7, "--delay-ms": 0, "--repeat": 1},
                      sources, [0, 50000, 100000])

    check("replay_physical_lines_and_mixed_frame_identity", selected_identity)

    def entire_file_invalid(item):
        item["variants"] = []
        for name, last in (("syntax", "invalid trailing line"), ("backwards", "(0.500000) archived9 102#0210")):
            path = fixture("range-invalid-" + name, text=(
                "# Header\n(1.000000) archived9 100#0010\n(1.050000) archived9 101#0110\n# Tail\n" + last + "\n"))
            detail = {"name": name, "requested_physical_range": [2, 3], "invalid_physical_line": 5}
            argv = mode_command("replay", {"--in": path, "--start-line": 2, "--end-line": 3, "--delay-ms": 0, "--repeat": 1})
            rejected(detail, "range-invalid-" + name, path, argv)
            item["variants"].append(detail)

    check("replay_validates_unselected_file_tail_before_sending", entire_file_invalid)

    def invalid_range(item):
        path = fixture("range-error-input", [frame(1000000, 0x100, "0010"), frame(1050000, 0x100, "0110")])
        item["variants"] = []
        for name, start, end in (("empty-selection", 1, 2), ("end-beyond-eof", 3, 99), ("reversed-range", 4, 3)):
            detail = {"name": name, "requested_physical_range": [start, end]}
            argv = mode_command("replay", {"--in": path, "--start-line": start, "--end-line": end, "--delay-ms": 0, "--repeat": 1})
            rejected(detail, "range-error-" + name, path, argv)
            item["variants"].append(detail)

    check("invalid_replay_ranges_send_nothing", invalid_range)

    def attack_bad_options(item):
        path = fixture("attack-cli-input", [frame(1000000, 0x100, "0010"), frame(1050000, 0x100, "0110")])
        defaults = {
            "flood": {"--id": "100", "--data": "0010", "--interval-us": 10000, "--count": 3},
            "fuzz": {"--id": "100", "--base-data": "0010", "--period-us": 50000, "--count": 3, "--flip-mask": "00FF"},
            "replay": {"--in": path, "--start-line": 3, "--end-line": 4, "--delay-ms": 0, "--repeat": 1}}
        variants = [
            ("flood", "missing-data", "--data", None), ("flood", "zero-interval", "--interval-us", 0),
            ("flood", "zero-count", "--count", 0), ("flood", "large-id", "--id", "20000000"),
            ("flood", "odd-data", "--data", "123"), ("flood", "unknown-option", "--speed", "1"),
            ("fuzz", "missing-base", "--base-data", None), ("fuzz", "zero-period", "--period-us", 0),
            ("fuzz", "zero-count", "--count", 0), ("fuzz", "short-mask", "--flip-mask", "FF"),
            ("fuzz", "partial-mask", "--flip-mask", "0001"), ("fuzz", "long-data", "--base-data", "00" * 9),
            ("replay", "missing-delay", "--delay-ms", None), ("replay", "zero-repeat", "--repeat", 0),
            ("replay", "zero-start", "--start-line", 0), ("replay", "fractional-end", "--end-line", "4.5"),
            ("replay", "negative-delay", "--delay-ms", -1), ("replay", "duplicate-repeat", None, None)]
        item["variants"] = []
        for mode, name, key, value in variants:
            options = dict(defaults[mode])
            if key is not None:
                if value is None:
                    del options[key]
                else:
                    options[key] = value
            argv = mode_command(mode, options)
            if key is None:
                argv += ["--repeat", "2"]
            detail = {"mode": mode, "name": name}
            rejected(detail, "attack-cli-" + mode + "-" + name, path, argv)
            item["variants"].append(detail)

    check("attack_mode_invalid_options_send_nothing", attack_bad_options)

    def attack_signal(item, mode, selected):
        name = "attack-signal-" + mode
        if mode == "flood":
            options = {"--id": "100", "--data": "0010", "--interval-us": 10000000, "--count": 2}
            expected = [frame(0, 0x100, "0010")]
        elif mode == "fuzz":
            options = {"--id": "100", "--base-data": "0010", "--period-us": 10000000,
                       "--count": 2, "--flip-mask": "00FF"}
            expected = [frame(0, 0x100, "00EF")]
        else:
            path = fixture(name, [frame(1000000, 0x100, "0010")])
            options = {"--in": path, "--start-line": 3, "--end-line": 3, "--delay-ms": 10000, "--repeat": 1}
            expected = []
        argv = mode_command(mode, options)
        request_fixture(name, argv, expected, [0] if expected else [])
        completed, received = run(name, argv, stop_signal=selected, timeout=3, stop_after_ready=mode == "replay")
        success(completed, received, expected, interrupted=True, mode=mode)
        if completed.get("sent_signal") != selected.name:
            raise RuntimeError("attack-mode signal was not delivered during its long wait")
        elapsed = (completed["process_exit_monotonic_ns"] - completed["signal_monotonic_ns"]) / 1000000000
        if elapsed > 2:
            raise RuntimeError("signal did not interrupt the attack-mode wait promptly")
        item.update({"mode": mode, "signal": selected.name, "received_frames": len(received),
                     "post_signal_seconds": elapsed, "unreached_wait_us": 10000000,
                     "received": name + ".received.json"})

    check("flood_signal_interrupts_interval_wait", lambda item: attack_signal(item, "flood", signal.SIGINT))
    check("fuzz_signal_interrupts_period_wait", lambda item: attack_signal(item, "fuzz", signal.SIGTERM))
    check("replay_signal_interrupts_initial_delay_without_sending", lambda item: attack_signal(item, "replay", signal.SIGTERM))

    for item in result["inputs"]:
        if sha256(run_dir / item["path"]) != item["sha256"]:
            raise RuntimeError("replay or detector modified an input fixture: " + item["path"])
    return all(item["passed"] for item in result["checks"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", required=True, help="Linux cansec-replay executable")
    parser.add_argument("--detect", required=True, help="Linux cansec-detect executable")
    parser.add_argument("--interface", default="vcan0", help="existing idle vcan interface")
    parser.add_argument("--output-dir", required=True, help="parent directory for run output")
    args = parser.parse_args()
    parent = Path(args.output_dir).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("replay-%Y%m%dT%H%M%SZ-"), dir=parent))
    root = Path(__file__).resolve().parent.parent
    source_files = [root / "CMakeLists.txt", Path(__file__).resolve()]
    source_files += sorted((root / "src").rglob("*.cpp")) + sorted((root / "include").rglob("*.hpp"))
    result = {"status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "invocation": [sys.executable] + sys.argv, "working_directory": str(Path.cwd()),
              "run_directory": str(run_dir), "interface": args.interface,
              "environment": {"platform": platform.platform(), "python": sys.version,
                              "uname": platform.uname()._asdict(),
                              "uid": os.getuid() if hasattr(os, "getuid") else None},
              "executables": {}, "source_sha256": {}, "commands": [], "checks": [],
              "inputs": [], "received": [], "artifact_sha256": {}}
    try:
        result["source_sha256"] = {path.relative_to(root).as_posix(): sha256(path) for path in source_files}
        for key, argument in (("replay", args.replay), ("detect", args.detect)):
            path = Path(argument).resolve()
            result["executables"][key] = {"path": str(path), "sha256": sha256(path) if path.is_file() else None}
        if verify(args, run_dir, result):
            result["status"] = "passed"
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        result["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result["checks_passed"] = sum(item["passed"] for item in result["checks"])
        result["checks_total"] = len(result["checks"])
        result["artifact_sha256"] = {path.name: sha256(path) for path in sorted(run_dir.iterdir()) if path.is_file()}
        write_json(run_dir / "result.json", result)
        print("Results: " + str(run_dir))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
