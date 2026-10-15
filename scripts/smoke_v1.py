#!/usr/bin/env python3
"""End-to-end smoke test: capture -> profile -> replay modes -> live detect -> reports.

Run as a normal user on an existing, UP and idle vcan interface. The script does
not create or modify interfaces. Each run writes to a new output directory.
"""

import argparse
from collections import Counter
import configparser
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import sys
import tempfile
import time


# Keep __pycache__ out of the source tree.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from verify_replay_linux import LoggedChild, Receiver, require_vcan, sha256, write_json  # noqa: E402
from test_detect_report_cli import RULES, verify_report  # noqa: E402


CAN_ID = 0x100
TRAINING_COUNT = 40
TRAINING_INTERVAL_US = 50000
DEMO_POLICY = {
    "period_min_us": 5000,
    "period_max_us": 500000,
    "rate_limit_100ms": 6,
    "max_identical_payload_run": 3,
}
# Per-endpoint timestamp tolerance for this fixture. The resulting 2 ms interval
# error stays below the 4 ms gap between 1 ms flood intervals and the 5 ms
# minimum period.
TIMESTAMP_ASSOCIATION_US = 1000
CLOCK_PREFLIGHT_SECONDS = 2
CLOCK_PREFLIGHT_INTERVAL_SECONDS = 0.1
CLOCK_OFFSET_STEP_BUDGET_NS = 1000000
FRAME_PATTERN = re.compile(r"\((\d+)\.(\d{6})\) (\S+) ([0-9A-F]{3}|[0-9A-F]{8})#([0-9A-F]*)")


def ensure(condition, message):
    if not condition:
        raise RuntimeError(message)


def signature(frame):
    return frame["id_type"], frame["can_id"], frame["dlc"], frame["data"]


def source_frame(data):
    return {"id_type": "standard", "can_id": CAN_ID, "dlc": len(bytes.fromhex(data)), "data": data}


def sample_clocks():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return {"realtime_ns": realtime, "monotonic_ns": (before + after) // 2,
            "monotonic_before_ns": before, "monotonic_after_ns": after,
            "read_uncertainty_ns": (after - before + 1) // 2}


def clock_stability(samples):
    """Compare actual clock-offset changes, accounting for read uncertainty."""
    analysis = {"status": "passed", "offset_step_budget_ns": CLOCK_OFFSET_STEP_BUDGET_NS,
                "samples": samples, "comparisons": [], "errors": []}
    if len(samples) < 2:
        analysis["errors"].append("at least two clock samples are required to establish stability")
    for index, sample in enumerate(samples):
        if sample["monotonic_after_ns"] - sample["monotonic_before_ns"] > CLOCK_OFFSET_STEP_BUDGET_NS:
            analysis["errors"].append(f"clock read interval is too uncertain at sample {index + 1}")
    for index, (previous, current) in enumerate(zip(samples, samples[1:]), 1):
        realtime_delta = current["realtime_ns"] - previous["realtime_ns"]
        monotonic_delta = current["monotonic_ns"] - previous["monotonic_ns"]
        change = realtime_delta - monotonic_delta
        uncertainty = previous["read_uncertainty_ns"] + current["read_uncertainty_ns"]
        minimum, maximum = max(0, abs(change) - uncertainty), abs(change) + uncertainty
        analysis["comparisons"].append({"sample_index": index, "realtime_delta_ns": realtime_delta,
            "monotonic_delta_ns": monotonic_delta, "clock_offset_change_ns": change,
            "minimum_possible_absolute_change_ns": minimum, "maximum_possible_absolute_change_ns": maximum})
        if monotonic_delta <= 0:
            analysis["errors"].append(f"monotonic clock did not advance at sample {index + 1}")
        if maximum > CLOCK_OFFSET_STEP_BUDGET_NS:
            label = "clock discontinuity" if minimum > CLOCK_OFFSET_STEP_BUDGET_NS else "uncertain clock offset change"
            analysis["errors"].append(f"{label} at sample {index + 1}: realtime-minus-monotonic delta {change} ns")
    if analysis["errors"]:
        analysis["status"] = "failed"
    return analysis


def read_capture(path, interface):
    content = path.read_bytes()
    ensure(content.endswith(b"\n"), "capture output is empty or has an incomplete last line")
    frames = []
    for line in content.decode("ascii").splitlines():
        match = FRAME_PATTERN.fullmatch(line)
        ensure(match is not None, "unexpected capture log syntax: " + line)
        seconds, micros, actual_interface, can_id, payload = match.groups()
        ensure(actual_interface == interface, "capture recorded a different interface")
        ensure(len(payload) % 2 == 0 and len(payload) <= 16, "invalid captured payload length")
        frames.append({"timestamp_us": int(seconds) * 1000000 + int(micros),
                       "interface": actual_interface, "id_type": "extended" if len(can_id) == 8 else "standard",
                       "can_id": int(can_id, 16), "dlc": len(payload) // 2, "data": payload})
    ensure(all(a["timestamp_us"] <= b["timestamp_us"] for a, b in zip(frames, frames[1:])),
           "capture timestamp moved backwards")
    return frames


def expected_alerts(frames):
    """Expected alerts for the 0x100/DLC2 smoke fixture under DEMO_POLICY.

    Only handles this fixture; general rule coverage is in the detector unit tests.
    """
    expected = []
    consecutive = 0
    previous = None
    for index, current in enumerate(frames):
        ensure(current["id_type"] == "standard" and current["can_id"] == CAN_ID and current["dlc"] == 2,
               "observer received an unexpected frame")
        timestamp = current["timestamp_us"]
        if previous is not None:
            delta = timestamp - previous["timestamp_us"]
            ensure(delta >= 0, "observer timestamps went backwards")
            if not DEMO_POLICY["period_min_us"] <= delta <= DEMO_POLICY["period_max_us"]:
                expected.append((index, "PERIOD_VIOLATION"))
        # Count frames in the half-open 100 ms window directly (small fixture).
        rate = sum(0 <= timestamp - earlier["timestamp_us"] < 100000 for earlier in frames[:index + 1])
        if rate > DEMO_POLICY["rate_limit_100ms"]:
            expected.append((index, "RATE_SPIKE"))
        if bytes.fromhex(current["data"])[1] != 0:
            expected.append((index, "FIXED_BYTE_VIOLATION"))
        consecutive = consecutive + 1 if previous is not None and signature(previous) == signature(current) else 1
        if consecutive > DEMO_POLICY["max_identical_payload_run"]:
            expected.append((index, "REPLAY_BURST"))
        previous = current
    return expected


def require_unambiguous_timing(frames, uncertainty_us=TIMESTAMP_ASSOCIATION_US):
    """Fail if a period or rate verdict could flip within the timestamp tolerance.

    Each endpoint is +/- uncertainty_us, so an interval is +/- twice that.
    """
    bounds = []
    for index, frame in enumerate(frames):
        now = frame["timestamp_us"]
        item = {"index": index, "observer_timestamp_us": now}
        if index:
            delta = now - frames[index - 1]["timestamp_us"]
            ensure(delta >= 0, "observer timestamps moved backwards")
            low, high = max(0, delta - 2 * uncertainty_us), delta + 2 * uncertainty_us
            definitely_allowed = low >= DEMO_POLICY["period_min_us"] and high <= DEMO_POLICY["period_max_us"]
            definitely_outside = high < DEMO_POLICY["period_min_us"] or low > DEMO_POLICY["period_max_us"]
            ensure(definitely_allowed or definitely_outside,
                   f"period verdict is ambiguous within the fixture timestamp budget at frame {index + 1}")
            item.update({"period_range_us": [low, high], "period_violation": definitely_outside})
        minimum_count = maximum_count = 1  # The current frame always counts.
        for prior in frames[:index]:
            delta = now - prior["timestamp_us"]
            ensure(delta >= 0, "observer timestamps moved backwards")
            minimum_count += delta + 2 * uncertainty_us < 100000
            maximum_count += max(0, delta - 2 * uncertainty_us) < 100000
        threshold = DEMO_POLICY["rate_limit_100ms"]
        ensure((minimum_count > threshold) == (maximum_count > threshold),
               f"rate verdict is ambiguous within the fixture timestamp budget at frame {index + 1}")
        item.update({"rate_count_range": [minimum_count, maximum_count], "rate_spike": minimum_count > threshold})
        bounds.append(item)
    return bounds


def qualify_training(frames, observer_frames, clock_samples):
    """Check that the captured training stream is clean before it is profiled."""
    clock_analysis = clock_stability(clock_samples)
    ensure(clock_analysis["status"] == "passed", "training " + "; ".join(clock_analysis["errors"]))
    ensure(len(frames) == len(observer_frames) == len(clock_samples), "training measurement counts differ")
    timing_bounds = require_unambiguous_timing(observer_frames)
    capture_alerts, observer_alerts = expected_alerts(frames), expected_alerts(observer_frames)
    ensure(not capture_alerts and not observer_alerts,
           "training is not normal under the demo policy; no baseline was generated")
    interval_checks = []
    for index in range(1, len(frames)):
        sender_delta = (clock_samples[index]["monotonic_ns"] - clock_samples[index - 1]["monotonic_ns"]) / 1000
        capture_delta = frames[index]["timestamp_us"] - frames[index - 1]["timestamp_us"]
        observer_delta = observer_frames[index]["timestamp_us"] - observer_frames[index - 1]["timestamp_us"]
        interval_checks.append({"frame_index": index, "sender_monotonic_delta_us": sender_delta,
            "capture_delta_us": capture_delta, "observer_delta_us": observer_delta,
            "capture_minus_sender_delta_us": capture_delta - sender_delta,
            "observer_minus_sender_delta_us": observer_delta - sender_delta})
        ensure(abs(capture_delta - sender_delta) <= 2 * TIMESTAMP_ASSOCIATION_US and
               abs(observer_delta - sender_delta) <= 2 * TIMESTAMP_ASSOCIATION_US,
               f"training receive interval differs from the monotonic sender interval at frame {index + 1}; no baseline was generated")
    return {"status": "passed", "clock_stability": clock_analysis, "interval_checks": interval_checks,
            "timing_verdict_bounds": timing_bounds, "capture_and_observer_alert_counts": [0, 0]}


def timing_summary(frames, requested_offsets):
    actual = [frame["timestamp_us"] - frames[0]["timestamp_us"] for frame in frames]
    deltas = [b - a for a, b in zip(actual, actual[1:])]
    return {"requested_offsets_us": requested_offsets, "actual_capture_offsets_us": actual,
            "offset_errors_us": [a - b for a, b in zip(actual, requested_offsets)],
            "minimum_interval_us": min(deltas) if deltas else None,
            "maximum_interval_us": max(deltas) if deltas else None,
            "measurement": "receive timestamps; offsets relative to the first received frame"}


def invoke(command, name, directory, result):
    child = LoggedChild([str(value) for value in command], name, directory, result, timeout=10)
    try:
        child.wait(timeout=10)
        ensure(child.process.returncode == 0, name + " failed; see its stderr log")
        return child
    finally:
        child.close()


def inspect_build(bin_dir, result, directory):
    paths = {name: bin_dir / ("cansec-" + name) for name in ("capture", "profile", "replay", "detect")}
    for name, path in paths.items():
        ensure(path.is_file() and os.access(path, os.X_OK), "missing executable Linux binary: " + str(path))
    manifest = bin_dir / "source-fingerprint.txt"
    ensure(manifest.is_file(), "fresh CMake build must contain source-fingerprint.txt")
    text = manifest.read_text(encoding="utf-8")
    entries = {}
    for line in text.splitlines():
        relative, space, digest = line.rpartition(" ")
        ensure(space and re.fullmatch(r"[0-9a-f]{64}", digest) and relative not in entries,
               "invalid or duplicate build source-fingerprint entry")
        path = (ROOT / relative).resolve()
        ensure(path.is_relative_to(ROOT) and path.is_file(), "build fingerprint source is outside checkout or missing")
        ensure(sha256(path) == digest, "source differs from the supplied build fingerprint: " + relative)
        entries[relative] = digest
    required = {"CMakeLists.txt"}
    for folder in (ROOT / "src", ROOT / "include"):
        required.update(path.relative_to(ROOT).as_posix() for path in folder.rglob("*")
                        if path.is_file() and (path.name.endswith(".cpp") or path.name.endswith(".hpp") or
                                               path.name.endswith(".hpp.in")))
    ensure(set(entries) == required, "build fingerprint does not cover the current product source set")
    canonical = "".join(relative + " " + entries[relative] + "\n" for relative in sorted(entries))
    ensure(text == canonical, "build source-fingerprint entries are not canonical")
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    (directory / "build-source-fingerprint.txt").write_text(canonical, encoding="utf-8", newline="\n")
    helper_files = ["scripts/smoke_v1.py", "scripts/verify_replay_linux.py", "tests/test_detect_report_cli.py"]
    result["source_sha256"] = dict(entries)
    result["source_sha256"].update({name: sha256(ROOT / name) for name in helper_files})
    result["product_source_fingerprint"] = fingerprint
    result["binaries"] = {name: {"path": str(path), "sha256": sha256(path)} for name, path in paths.items()}
    return paths


def load_profile(path):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    with path.open(encoding="utf-8") as source:
        parser.read_file(source)
    ensure(parser.sections() == ["global", "id:0x100"], "profile must contain only global and the captured ID")
    return dict(parser["global"]), dict(parser["id:0x100"])


def verify_profile_statistics(values, frames):
    times = [frame["timestamp_us"] for frame in frames]
    deltas = sorted(b - a for a, b in zip(times, times[1:]))
    median = deltas[len(deltas) // 2] if len(deltas) % 2 else sum(deltas[len(deltas)//2 - 1:len(deltas)//2 + 1]) // 2
    p05, p95 = deltas[(len(deltas) - 1) * 5 // 100], deltas[(len(deltas) - 1) * 95 // 100]
    maximum = max(sum(0 <= timestamp - prior < 100000 for prior in times[:index + 1])
                  for index, timestamp in enumerate(times))
    expected = {"id_type": "standard", "frame_count": str(len(frames)), "allowed_dlc": "2",
                "first_timestamp_us": str(times[0]), "last_timestamp_us": str(times[-1]),
                "median_delta_us": str(median), "p05_delta_us": str(p05), "p95_delta_us": str(p95),
                "max_count_per_100ms": str(maximum), "fixed_mask": "00FF000000000000",
                "fixed_value": "0000000000000000", "ignore_mask": "0000000000000000"}
    for key, value in expected.items():
        ensure(values.get(key) == value, f"profile statistic {key}: expected {value}, observed {values.get(key)}")
    return {"observed": expected, "raw_expected_rate_limit": maximum + max(2, math.ceil(maximum * 0.2)),
            "periodic_heuristic": len(frames) >= 30 and median <= 200000 and p95 / max(p05, 1) <= 2.5}


def run_smoke(args, directory, result):
    ensure(sys.platform == "linux" and os.geteuid() != 0,
           "run as an ordinary Linux user, not root; no CAN transmission was started")
    bin_dir = Path(args.bin_dir).resolve()
    binaries = inspect_build(bin_dir, result, directory)
    ip_command = shutil.which("ip")
    ensure(ip_command is not None, "ip is required to verify the interface is virtual CAN")
    interface = args.interface
    initial = require_vcan(ip_command, interface, "interface-before", directory, result)
    result["interface_details"] = initial

    def check(name, action):
        item = {"name": name, "passed": False}
        result["checks"].append(item)
        try:
            action(item)
            item["passed"] = True
            print("PASS " + name, flush=True)
        except BaseException as error:
            item["error"] = str(error) or type(error).__name__
            print("FAIL " + name, flush=True)
            raise

    def interface_check(name):
        current = require_vcan(ip_command, interface, name, directory, result)
        ensure(current["ifindex"] == initial["ifindex"], "vcan interface identity changed during this run")

    def clock_preflight(item):
        samples = []
        start = time.monotonic_ns()
        count = round(CLOCK_PREFLIGHT_SECONDS / CLOCK_PREFLIGHT_INTERVAL_SECONDS)
        try:
            for index in range(count + 1):
                target = start + round(index * CLOCK_PREFLIGHT_INTERVAL_SECONDS * 1000000000)
                remaining = target - time.monotonic_ns()
                if remaining > 0:
                    time.sleep(remaining / 1000000000)
                samples.append(sample_clocks())
        finally:
            analysis = clock_stability(samples)
            span = samples[-1]["monotonic_ns"] - samples[0]["monotonic_ns"] if len(samples) > 1 else 0
            if len(samples) != count + 1 or span < CLOCK_PREFLIGHT_SECONDS * 1000000000 - CLOCK_OFFSET_STEP_BUDGET_NS:
                analysis["status"] = "failed"
                analysis["errors"].append("the required clock observation window did not complete")
            analysis["requested_observation_seconds"] = CLOCK_PREFLIGHT_SECONDS
            analysis["sample_span_seconds"] = span / 1000000000
            analysis["actual_observation_seconds"] = (time.monotonic_ns() - start) / 1000000000
            write_json(directory / "clock-preflight.json", analysis)
        item.update(analysis)
        ensure(analysis["status"] == "passed", "clock preflight: " + "; ".join(analysis["errors"]))

    check("clock_stability_preflight", clock_preflight)

    def idle_receiver(name):
        interface_check(name + "-interface")
        receiver = Receiver(interface)
        try:
            if receiver.receive(wait=0.2):
                write_json(directory / (name + "-unexpected-traffic.json"), receiver.frames)
                raise RuntimeError("vcan has unrelated traffic; stop other senders and start a new smoke run")
            return receiver
        except BaseException:
            receiver.close()
            raise

    def captured_results(name, capture, receiver, expected):
        while receiver.receive(wait=0.1):
            ensure(len(receiver.frames) <= len(expected), "independent receiver observed extra traffic")
        write_json(directory / (name + "-received.json"), receiver.frames)
        frames = read_capture(capture, interface)
        wanted = [signature(frame) for frame in expected]
        ensure([signature(frame) for frame in frames] == wanted, "capture ID/DLC/payload sequence differs from the input")
        ensure([signature(frame) for frame in receiver.frames] == wanted,
               "independent receiver sequence differs from the input")
        ensure(all(not frame["rtr"] and not frame["error_frame"] and frame["interface"] == interface
                   for frame in receiver.frames), "unexpected interface, RTR or error frame")
        ensure(all(frame["kernel_realtime_ns"] is not None for frame in receiver.frames),
               "kernel receive timestamps are not available")
        observer_frames = [dict(frame, timestamp_us=received["kernel_realtime_ns"] // 1000)
                           for frame, received in zip(frames, receiver.frames)]
        comparisons = [{"index": index, "capture_timestamp_us": frame["timestamp_us"],
                        "observer_timestamp_us": observed["timestamp_us"],
                        "capture_minus_observer_us": frame["timestamp_us"] - observed["timestamp_us"]}
                       for index, (frame, observed) in enumerate(zip(frames, observer_frames))]
        comparison = {"fixture_association_budget_us": TIMESTAMP_ASSOCIATION_US, "frames": comparisons,
                      "method": "capture uses per-packet kernel timestamps (SO_TIMESTAMPNS or SO_TIMESTAMP); the observer uses SO_TIMESTAMPNS"}
        write_json(directory / (name + "-timestamp-comparison.json"), comparison)
        ensure(all(abs(row["capture_minus_observer_us"]) <= TIMESTAMP_ASSOCIATION_US for row in comparisons),
               "capture/observer timestamp difference exceeds the fixture tolerance")
        return frames, observer_frames, comparison

    benign_log = directory / "benign-captured.log"
    benign_expected = [source_frame(f"{index:02X}00") for index in range(TRAINING_COUNT)]
    benign_frames = []

    def training(item):
        receiver = idle_receiver("training")
        child = None
        sent = []
        clock_samples = []
        qualified = False
        try:
            child = LoggedChild([str(binaries["capture"]), "--if", interface, "--out", str(benign_log),
                                 "--max-frames", str(TRAINING_COUNT), "--max-seconds", "8"],
                                "training-capture", directory, result, timeout=10)
            child.ready(f"Capturing CAN frames from {interface} -> {benign_log}\n")
            child.record["ready_observed_monotonic_ns"] = time.monotonic_ns()
            interface_check("training-before-send")
            with socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW) as sender:
                sender.settimeout(1)
                sender.bind((interface,))
                origin = time.monotonic_ns()
                for index, frame in enumerate(benign_expected):
                    deadline = origin + index * TRAINING_INTERVAL_US * 1000
                    remaining = deadline - time.monotonic_ns()
                    if remaining > 0:
                        time.sleep(remaining / 1000000000)
                    ensure(socket.if_nametoindex(interface) == initial["ifindex"], "vcan identity changed before seed send")
                    packet = struct.pack("=IB3x8s", CAN_ID, 2, bytes.fromhex(frame["data"]).ljust(8, b"\0"))
                    clocks = sample_clocks()
                    clock_samples.append(clocks)
                    measurement = {"index": index, "requested_offset_us": index * TRAINING_INTERVAL_US,
                                   "before_monotonic_ns": clocks["monotonic_ns"], "before_us": clocks["realtime_ns"] // 1000,
                                   "packet_hex": packet.hex().upper()}
                    measurement["sent_bytes"] = sender.send(packet)
                    measurement["after_monotonic_ns"] = time.monotonic_ns()
                    sent.append(measurement)
                    ensure(measurement["sent_bytes"] == 16, "seed sender wrote an incomplete CAN frame")
            child.wait(timeout=10)
            ensure(child.process.returncode == 0, "normal capture failed")
            ensure(child.stderr().endswith(f"Captured {TRAINING_COUNT} frame(s).\n".encode()), "wrong capture completion count")
            ensure(not child.stdout(), "capture unexpectedly wrote stdout")
            frames, observer_frames, comparison = captured_results("training", benign_log, receiver, benign_expected)
            qualification = qualify_training(frames, observer_frames, clock_samples)
            write_json(directory / "training-qualification.json", qualification)
            qualified = True
            benign_frames.extend(frames)
            item.update({"capture": benign_log.name, "capture_sha256": sha256(benign_log), "frames": len(frames),
                         "sequence_matches_seed_and_independent_receiver": True,
                         "timestamp_comparison": comparison,
                         "training_qualification": "training-qualification.json",
                         "timing": timing_summary(frames, [index * TRAINING_INTERVAL_US for index in range(TRAINING_COUNT)])})
        finally:
            if child is not None:
                child.close()
            partial = directory / "training-received.json"
            if not partial.exists():
                write_json(partial, receiver.frames)
            receiver.close()
            write_json(directory / "training-clock.json", clock_stability(clock_samples))
            qualification_path = directory / "training-qualification.json"
            if not qualification_path.exists():
                write_json(qualification_path, {"status": "failed", "baseline_generation_allowed": False,
                           "reason": "Training qualification did not complete; see the failed check and training-*.json."})
            write_json(directory / "training-sent.json", {"synthetic": True, "training_qualified": qualified,
                       "expected_frames": benign_expected, "sent_frames": sent,
                       "description": "standard ID 0x100, DLC 2, varying first byte and fixed second byte 00; requested 50 ms intervals"})

    check("capture_known_normal_stream", training)
    baseline = directory / "baseline-demo.ini"
    overrides = directory / "demo-tolerance-overrides.ini"
    raw_baseline = directory / "baseline-observed.ini"
    raw_summary = directory / "profile-observed.md"
    summary = directory / "profile-demo.md"

    def profile(item):
        invoke([binaries["profile"], "--in", benign_log, "--out", raw_baseline, "--summary", raw_summary],
               "profile-observed", directory, result)
        raw_global, raw_values = load_profile(raw_baseline)
        stats = verify_profile_statistics(raw_values, benign_frames)
        ensure(stats["periodic_heuristic"] and raw_values.get("periodic") == "1",
               "training traffic was not periodic enough to build a baseline")
        ensure(raw_values.get("rate_limit_100ms") == str(stats["raw_expected_rate_limit"]) and
               raw_values.get("max_identical_payload_run") == "1", "raw learned rate/repetition values differ from the sample")
        ensure(raw_global.get("benign_source_sha256") == sha256(benign_log), "raw baseline is not linked to captured bytes")
        ensure(raw_global.get("benign_source") == str(benign_log), "raw profile references a different capture")
        raw_hash = sha256(raw_baseline)
        with overrides.open("x", encoding="ascii", newline="\n") as output:
            output.write("# Demo tolerance for OS scheduling jitter; not a vehicle policy.\n"
                         "# The raw observed baseline is kept in a separate file.\n"
                         "# Periodic checking stays on: allow 5..500 ms around the requested 50 ms period.\n"
                         "# Warn above 6 frames/100 ms or more than 3 identical frames in a row.\n"
                         "[id:0x100]\n" + "".join(f"{key}={value}\n" for key, value in DEMO_POLICY.items()))
        invoke([binaries["profile"], "--in", benign_log, "--out", baseline, "--summary", summary,
                "--override", overrides], "profile-demo", directory, result)
        effective_global, effective_values = load_profile(baseline)
        verify_profile_statistics(effective_values, benign_frames)
        for key, value in raw_values.items():
            ensure(effective_values.get(key) == str(DEMO_POLICY.get(key, value)),
                   "demo override changed an unrequested policy/statistic: " + key)
        ensure(effective_global.get("benign_source_sha256") == sha256(benign_log) and
               effective_global.get("override_source_sha256") == sha256(overrides), "demo profile input hashes differ")
        ensure(sha256(raw_baseline) == raw_hash, "demo profiling modified the preserved raw baseline")
        for path in (raw_summary, summary):
            ensure(sha256(benign_log) in path.read_text(encoding="utf-8"), "profile summary lacks captured input hash")
        invoke([binaries["detect"], "--rules", baseline, "--validate-rules"], "validate-demo-baseline", directory, result)
        item.update({"captured_input_sha256": sha256(benign_log), "raw_baseline": raw_baseline.name,
                     "raw_baseline_sha256": raw_hash, "raw_summary": raw_summary.name,
                     "effective_baseline": baseline.name, "effective_baseline_sha256": sha256(baseline),
                     "effective_summary": summary.name, "override": overrides.name, "override_sha256": sha256(overrides),
                     "observed_statistics": stats, "explicit_demo_overrides": DEMO_POLICY})

    check("profile_actual_capture_and_preserve_demo_overrides", profile)
    baseline_hash = sha256(baseline)
    result["baseline_used_by_all_scenarios"] = {"path": baseline.name, "sha256": baseline_hash,
                                               "captured_input": benign_log.name, "captured_input_sha256": sha256(benign_log)}

    def scenario(item, name, arguments, expected, offsets):
        capture_path = directory / (name + "-captured.log")
        alerts_path = directory / (name + ".jsonl")
        report_path = directory / (name + ".md")
        receiver = idle_receiver(name)
        children = []
        try:
            capture = LoggedChild([str(binaries["capture"]), "--if", interface, "--out", str(capture_path),
                                   "--max-frames", str(len(expected)), "--max-seconds", "8"],
                                  name + "-capture", directory, result, timeout=10)
            children.append(capture)
            capture.ready(f"Capturing CAN frames from {interface} -> {capture_path}\n")
            capture.record["ready_observed_monotonic_ns"] = time.monotonic_ns()
            detect = LoggedChild([str(binaries["detect"]), "--rules", str(baseline), "--if", interface,
                                  "--out", str(alerts_path), "--summary", str(report_path),
                                  "--max-frames", str(len(expected)), "--max-seconds", "8"],
                                 name + "-detect", directory, result, timeout=10)
            children.append(detect)
            detect.ready(f"Detecting CAN frames from {interface} -> {alerts_path}\n")
            detect.record["ready_observed_monotonic_ns"] = time.monotonic_ns()
            interface_check(name + "-before-replay")
            replay = LoggedChild([str(binaries["replay"]), name, "--if", interface] + [str(value) for value in arguments],
                                 name + "-replay", directory, result, timeout=10)
            children.append(replay)
            replay.ready(f"Replaying {name} CAN frames to {interface}\n")
            for child in (replay, capture, detect):
                child.wait(timeout=10)
                ensure(child.process.returncode == 0, name + " child failed; see its logs")
                ensure(not child.stdout(), name + " child unexpectedly wrote stdout")
            ensure(replay.stderr() == f"Replaying {name} CAN frames to {interface}\nSent {len(expected)} frame(s).\n".encode(),
                   "replay did not report the expected send count")
            ensure(capture.stderr().endswith(f"Captured {len(expected)} frame(s).\n".encode()), "capture completion count differs")
            frames, observer_frames, comparison = captured_results(name, capture_path, receiver, expected)
            timing_bounds = require_unambiguous_timing(observer_frames)
            oracle = expected_alerts(frames)
            ensure(oracle == expected_alerts(observer_frames),
                   "capture and independent observer timestamps produce different rule verdicts")
            expected_counts = Counter(rule for _, rule in oracle)
            data = alerts_path.read_bytes()
            ensure(not data or data.endswith(b"\n"), "JSONL contains an incomplete last record")
            alerts = [json.loads(line) for line in data.decode("utf-8").splitlines()]
            actual_counts = Counter(alert["rule"] for alert in alerts)
            ensure(actual_counts == expected_counts and len(alerts) == len(oracle),
                   f"JSONL rule counts differ from the expected counts: {dict(actual_counts)} vs {dict(expected_counts)}")
            detected_timestamps = {}
            jsonl_timestamp_comparison = []
            for row, (index, rule) in zip(alerts, oracle):
                frame = frames[index]
                ensure(type(row["capture_ts_us"]) is int and
                       abs(row["capture_ts_us"] - observer_frames[index]["timestamp_us"]) <= TIMESTAMP_ASSOCIATION_US,
                       "JSONL capture timestamp is too far from the observer's timestamp")
                ensure(index not in detected_timestamps or detected_timestamps[index] == row["capture_ts_us"],
                       "alerts for one received frame have different capture timestamps")
                detected_timestamps[index] = row["capture_ts_us"]
                jsonl_timestamp_comparison.append({"frame_index": index, "rule": rule,
                    "capture_timestamp_us": frame["timestamp_us"], "detector_timestamp_us": row["capture_ts_us"],
                    "observer_timestamp_us": observer_frames[index]["timestamp_us"],
                    "detector_minus_observer_us": row["capture_ts_us"] - observer_frames[index]["timestamp_us"]})
                ensure(row["if"] == interface and
                       row["can_id"] == "0x100" and row["id_type"] == "standard" and row["dlc"] == 2 and
                       row["data"] == frame["data"] and row["rule"] == rule and row["severity"] == RULES[rule],
                       "JSONL alert does not match its independently captured frame/rule")
                ensure(type(row["alert_ts_us"]) is int and row["capture_ts_us"] <= row["alert_ts_us"] <= time.time_ns() // 1000,
                       "invalid decision timestamp")
            ensure(list(detected_timestamps.values()) == sorted(detected_timestamps.values()),
                   "detector capture timestamps moved backwards")
            if name == "normal":
                ensure(not alerts, "normal replay generated alerts under the demo policy")
            elif name == "flood":
                ensure(actual_counts["PERIOD_VIOLATION"] > 0 and actual_counts["RATE_SPIKE"] > 0 and
                       actual_counts["REPLAY_BURST"] == 9, "flood did not trigger the intended timing/rate/repetition checks")
            elif name == "replay":
                ensure(actual_counts["REPLAY_BURST"] == 0 and actual_counts["FIXED_BYTE_VIOLATION"] == 0,
                       "alternating A/B replay unexpectedly triggered a payload rule")
            elif name == "fuzz":
                ensure(actual_counts == Counter({"FIXED_BYTE_VIOLATION": 4, "REPLAY_BURST": 1}),
                       "fuzz expected four fixed-byte and one repeated-payload alerts")
                ensure([frame["data"] for frame in frames] == ["12FF"] * 4,
                       "fuzz did not send the same changed payload on every send")
            ensure(detect.stderr().endswith(f"Processed {len(frames)} frame(s); {len(alerts)} alert(s).\n".encode()),
                   "detect completion totals differ from actual captures/JSONL")
            report = verify_report(report_path, len(frames), expected_counts, "live", baseline_hash, 1,
                                   jsonl_hash=sha256(alerts_path), termination="max_frames")
            first_timestamp = int(report["fields"]["First frame timestamp"])
            last_timestamp = int(report["fields"]["Last frame timestamp"])
            ensure(first_timestamp <= last_timestamp and
                   abs(first_timestamp - observer_frames[0]["timestamp_us"]) <= TIMESTAMP_ASSOCIATION_US and
                   abs(last_timestamp - observer_frames[-1]["timestamp_us"]) <= TIMESTAMP_ASSOCIATION_US,
                   "report first/last timestamps are too far from the observer's timestamps")
            ensure(all(first_timestamp <= row["capture_ts_us"] <= last_timestamp for row in alerts),
                   "report timestamp range excludes its JSONL alert frames")
            for index, timestamp in ((0, first_timestamp), (len(frames) - 1, last_timestamp)):
                ensure(index not in detected_timestamps or detected_timestamps[index] == timestamp,
                       "report endpoint timestamp differs from JSONL for the same frame")
            ensure(report["fields"]["Source SHA256"] == result["product_source_fingerprint"],
                   "binary report source fingerprint differs from supplied build/current source")
            ensure(report["fields"]["Interface"] == interface and report["fields"]["Rules file"] == str(baseline),
                   "report references different live inputs")
            for example, row in zip(report["first_alerts"], alerts):
                ensure(all(example[key] == str(row[key]) for key in example), "report first alerts differ from JSONL")
            ensure(sha256(baseline) == baseline_hash, "a scenario modified its baseline input")
            item.update({"frames": len(frames), "capture": capture_path.name, "capture_sha256": sha256(capture_path),
                         "alerts": alerts_path.name, "alerts_sha256": sha256(alerts_path),
                         "report": report_path.name, "report_sha256": sha256(report_path),
                         "baseline_sha256": baseline_hash, "alert_count": len(alerts), "rule_counts": dict(actual_counts),
                         "expected_rules_per_capture_index": [{"index": index, "rule": rule} for index, rule in oracle],
                         "capture_and_receiver_sequence_match": True, "jsonl_and_report_match": True,
                         "timestamp_comparison": comparison, "jsonl_timestamp_comparison": jsonl_timestamp_comparison,
                         "timing_verdict_bounds": timing_bounds, "observer_rules_match": True,
                         "timing": timing_summary(frames, offsets), "report_fields": report["fields"]})
        finally:
            for child in reversed(children):
                child.close()
            # Keep partial receiver output even if the scenario failed.
            partial = directory / (name + "-received.json")
            if not partial.exists():
                write_json(partial, receiver.frames)
            receiver.close()

    captured_offsets = [frame["timestamp_us"] - benign_frames[0]["timestamp_us"] for frame in benign_frames]
    segment_duration = captured_offsets[1]
    scenarios = [
        ("normal", ["--in", benign_log], benign_expected, captured_offsets),
        ("flood", ["--id", "100", "--data", "1200", "--interval-us", "1000", "--count", "12"],
         [source_frame("1200")] * 12, [index * 1000 for index in range(12)]),
        ("replay", ["--in", benign_log, "--start-line", "1", "--end-line", "2", "--delay-ms", "50", "--repeat", "2"],
         benign_expected[:2] * 2, [0, segment_duration, segment_duration, segment_duration * 2]),
        ("fuzz", ["--id", "100", "--base-data", "1200", "--period-us", "50000", "--count", "4", "--flip-mask", "00FF"],
         [source_frame("12FF")] * 4, [0, 50000, 100000, 150000]),
    ]
    result["scenario_design"] = [{"mode": name, "replay_arguments": [str(value) for value in arguments],
                                  "expected_frames": expected, "requested_relative_offsets_us": offsets}
                                 for name, arguments, expected, offsets in scenarios]
    result["scenario_design_notes"] = {
        "normal": "replays the complete actual captured benign log; requires zero alerts",
        "flood": "12 identical frames at requested 1 ms; period/rate alerts required and repetition alerts on frames 4..12",
        "replay": "first two captured lines A/B twice; A/B/A/B resets repetition, but the zero-gap loop boundary can violate period",
        "fuzz": "1200 XOR 00FF is computed once: 12FF on each of four sends; four fixed-byte plus one repetition alert",
        "counts": "capture and observer timestamps must give the same verdicts; period/rate verdicts must be unambiguous within +/-1 ms per endpoint",
    }
    for name, arguments, expected, offsets in scenarios:
        check("live_" + name + "_capture_detect_report", lambda item, name=name, arguments=arguments, expected=expected, offsets=offsets:
              scenario(item, name, arguments, expected, offsets))
    interface_check("interface-after")
    for name, digest in result["source_sha256"].items():
        ensure(sha256(ROOT / name) == digest, "source changed during smoke run: " + name)
    for entry in result["binaries"].values():
        ensure(sha256(Path(entry["path"])) == entry["sha256"], "binary changed during smoke run")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, help="fresh Linux CMake build containing all four cansec executables")
    parser.add_argument("--interface", default="vcan0", help="already UP and idle virtual CAN interface (default: vcan0)")
    parser.add_argument("--output-dir", required=True, help="parent directory; a unique smoke-v1-* child is created")
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("smoke-v1-%Y%m%dT%H%M%SZ-"), dir=output))
    result = {"schema_version": 1, "status": "failed", "started_utc": datetime.now(timezone.utc).isoformat(),
              "invocation": [sys.executable] + sys.argv, "working_directory": str(Path.cwd()),
              "run_directory": str(directory), "interface": args.interface,
              "environment": {"platform": platform.platform(), "uname": platform.uname()._asdict(),
                              "python": sys.version, "uid": os.getuid() if hasattr(os, "getuid") else None},
              "commands": [], "checks": [], "source_sha256": {}, "binaries": {}}
    exit_code = 1
    try:
        run_smoke(args, directory, result)
        result["status"] = "passed"
        exit_code = 0
    except KeyboardInterrupt:
        result["error"] = "interrupted by user; started child processes were cleaned up"
        exit_code = 130
    except Exception as error:
        result["error"] = str(error)
        result["error_type"] = type(error).__name__
        print(str(error), file=sys.stderr, flush=True)
    finally:
        result["finished_utc"] = datetime.now(timezone.utc).isoformat()
        result["passed_checks"] = sum(check["passed"] for check in result["checks"])
        result["total_checks"] = len(result["checks"])
        result["artifact_sha256"] = {path.relative_to(directory).as_posix(): sha256(path)
                                     for path in sorted(directory.rglob("*")) if path.is_file()}
        write_json(directory / "result.json", result)
        print("Results: " + str(directory / "result.json"), flush=True)
        print(f"{result['status'].upper()}: {result['passed_checks']}/{result['total_checks']} checks", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
