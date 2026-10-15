"""Argument checks for flood/replay/fuzz that fail before anything is sent."""
from pathlib import Path
import hashlib
import json
import platform
import subprocess
import sys
import uuid

exe = str(Path(sys.argv[1]).resolve())
directory = Path(sys.argv[2]).resolve()
directory.mkdir(parents=True, exist_ok=True)
interface = "cs" + uuid.uuid4().hex[:8]
log = directory / "physical-lines.log"
log.write_text("# heading\n(1.000000) old0 100#AA10\n\n(1.020000) old1 00000100#BB10\n# end\n", encoding="ascii")
original_hash = hashlib.sha256(log.read_bytes()).hexdigest()
base = {
    "flood": ["flood", "--if", interface, "--id", "0x100", "--data", "AA10", "--interval-us", "1000", "--count", "3"],
    "replay": ["replay", "--if", interface, "--in", str(log), "--start-line", "2", "--end-line", "4", "--delay-ms", "0", "--repeat", "2"],
    "fuzz": ["fuzz", "--if", interface, "--id", "100", "--base-data", "AA10", "--period-us", "10000", "--count", "3", "--flip-mask", "00FF"],
}
results = []


def changed(args, key, value):
    result = list(args)
    result[result.index(key) + 1] = value
    return result


def failure(name, args, expected=None, startup=False):
    process = subprocess.run([exe] + args, capture_output=True, timeout=5)
    error = process.stderr.decode("utf-8", "replace")
    passed = process.returncode == 1 and process.stdout == b"" and "cansec-replay:" in error
    passed = passed and "Replaying " not in error and "Sent " not in error
    if expected is not None:
        passed = passed and expected in error
    if startup:
        passed = passed and (("SIOCGIFINDEX" in error or "socket(" in error) if platform.system() == "Linux" else "Replay requires Linux" in error)
    else:
        passed = passed and "SIOCGIFINDEX" not in error and "requires Linux" not in error
    passed = passed and hashlib.sha256(log.read_bytes()).hexdigest() == original_hash
    results.append({"name": name, "passed": passed, "args": args, "returncode": process.returncode, "stderr": error})
    print(("PASS " if passed else "FAIL ") + name)


for mode, args in base.items():
    failure(mode + "_valid_reaches_startup", args, startup=True)
    for key in args[1::2]:
        index = args.index(key)
        failure(mode + "_missing_" + key, args[:index] + args[index + 2:], "required:")
    failure(mode + "_duplicate", args + ["--if", interface], "duplicate")
    failure(mode + "_mixed_mode_option", args + ["--speed", "1"], "unsupported option")
    failure(mode + "_incomplete", args + ["--count"] if mode == "replay" else args[:-1])

for mode, keys in [("flood", ["--interval-us", "--count"]), ("replay", ["--start-line", "--end-line", "--repeat"]), ("fuzz", ["--period-us", "--count"])]:
    for key in keys:
        for value in ["0", "-1", "1.0", "1junk", " 1", "18446744073709551616"]:
            failure(mode + "_" + key + "_" + repr(value), changed(base[mode], key, value), "positive uint64 integer")
for value in ["-1", "1.5", "1junk", "18446744073709551616"]:
    failure("delay_" + value, changed(base["replay"], "--delay-ms", value), "non-negative uint64 integer")

for mode, key in [("flood", "--data"), ("fuzz", "--base-data"), ("fuzz", "--flip-mask")]:
    for value in [" ", " AA", "AA ", "AA BB", "\t", "AG", "A", "001122334455667788"]:
        failure(mode + "_" + key + "_" + repr(value), changed(base[mode], key, value))
for value in [" 100", "100 ", "10 0", "0x", "0x 100", "20000000", "000000100", "-100", "xyz"]:
    failure("bad_id_" + repr(value), changed(base["flood"], "--id", value))
for value in ["FF", "00FF00", "0100", "00FE"]:
    failure("bad_mask_" + value, changed(base["fuzz"], "--flip-mask", value))

for mode in ["flood", "fuzz"]:
    key = "--interval-us" if mode == "flood" else "--period-us"
    failure(mode + "_duration_overflow", changed(base[mode], key, "18446744073709551615"))
    args = changed(changed(base[mode], "--count", "1"), key, "18446744073709551615")
    failure(mode + "_count_one_zero_span", args, startup=True)

for name, start, end in [("reversed", "4", "2"), ("beyond_eof", "2", "6"), ("empty_selection", "3", "3")]:
    failure(name, changed(changed(base["replay"], "--start-line", start), "--end-line", end))
for name, content in [("late-invalid", log.read_text() + "broken\n"), ("outside-backwards", log.read_text() + "(0.000000) old0 100#AA10\n")]:
    path = directory / (name + ".log")
    path.write_text(content, encoding="ascii")
    failure(name, changed(base["replay"], "--in", str(path)))
failure("missing_input", changed(base["replay"], "--in", str(directory / "absent.log")))
failure("delay_conversion_overflow", changed(base["replay"], "--delay-ms", "18446744073709551615"))
failure("repeat_count_overflow", changed(base["replay"], "--repeat", "18446744073709551615"))
full_span = directory / "full-span.log"
full_span.write_text("(0.000000) old0 100#00\n(18446744073709.551615) old0 100#11\n", encoding="ascii")
args = changed(changed(changed(changed(base["replay"], "--in", str(full_span)), "--start-line", "1"), "--end-line", "2"), "--repeat", "1")
failure("delay_plus_duration_overflow", changed(args, "--delay-ms", "1"))

failure("flood_empty_payload", changed(base["flood"], "--data", ""), startup=True)
failure("fuzz_empty_payload_and_mask", changed(changed(base["fuzz"], "--base-data", ""), "--flip-mask", ""), startup=True)
failure("fuzz_zero_mask", changed(base["fuzz"], "--flip-mask", "0000"), startup=True)
failure("extended_low_id", changed(base["flood"], "--id", "0x00000100"), startup=True)
failure("maximum_extended_id", changed(base["flood"], "--id", "1FFFFFFF"), startup=True)
failure("single_selected_frame_repeated", changed(base["replay"], "--end-line", "2"), startup=True)

for mode in base:
    process = subprocess.run([exe, mode, "--help"], capture_output=True, timeout=5)
    passed = process.returncode == 0 and process.stdout == b"" and ("cansec-replay " + mode).encode() in process.stderr
    results.append({"name": mode + "_help", "passed": passed})
    print(("PASS " if passed else "FAIL ") + mode + "_help")

(directory / "result.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
failed = sum(not item["passed"] for item in results)
print(f"{len(results)} scenario CLI checks; {failed} failure(s).")
sys.exit(1 if failed else 0)
