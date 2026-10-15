#!/usr/bin/env python3
"""Check baseline.ini and profile_summary.md generated from the synthetic sample log."""
import argparse
import configparser
import hashlib
import json
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-dir", default="artifacts/sample")
    args = parser.parse_args()
    folder = Path(args.sample_dir)
    source = folder / "benign.log"
    ini = configparser.ConfigParser(interpolation=None)
    ini.read(folder / "baseline.ini", encoding="utf-8")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    require(ini["global"]["benign_source_sha256"] == source_hash, "Input SHA-256 differs")
    require(ini["global"]["window_ms"] == "100", "Window must be 100 ms")
    expected = {
        "0x100": (300, 10000, 10, 12, "00000000FFFFFFFF", "0000000000000000"),
        "0x101": (150, 20000, 5, 7, "00FFFF00FFFFFFFF", "0000010000000000"),
        "0x102": (30, 100000, 1, 3, "00FFFFFFFFFFFFFF", "0001000000000000"),
        "0x103": (60, 50000, 2, 4, "00FFFFFFFFFFFFFF", "0010000000000000"),
    }
    require(set(ini.sections()) == {"global", *("id:" + key for key in expected)}, "Unexpected ID sections")
    checked = {}
    for can_id, (count, period, window_count, rate, mask, value) in expected.items():
        actual = ini["id:" + can_id]
        fields = {
            "id_type": "standard", "frame_count": str(count), "allowed_dlc": "8",
            "first_timestamp_us": "1730960000000000",
            "last_timestamp_us": str(1730960000000000 + (count - 1) * period),
            "periodic": "1", "median_delta_us": str(period),
            "p05_delta_us": str(period), "p95_delta_us": str(period),
            "period_min_us": str(period * 4 // 5), "period_max_us": str(period * 6 // 5),
            "max_count_per_100ms": str(window_count), "rate_limit_100ms": str(rate),
            "fixed_mask": mask, "fixed_value": value, "ignore_mask": "0000000000000000",
            "max_identical_payload_run": "1",
        }
        for key, wanted in fields.items():
            require(actual.get(key) == wanted, f"{can_id}.{key}: expected {wanted}, got {actual.get(key)}")
        checked[can_id] = {"frames": count, "period_us": period, "rate_limit_100ms": rate}
    summary = (folder / "profile_summary.md").read_text(encoding="utf-8")
    require(source_hash in summary, "Summary is missing the source hash")
    for can_id in expected:
        require(can_id in summary, f"Summary is missing {can_id}")
    require(sum(1 for row in source.read_text(encoding="ascii").splitlines() if row and not row.startswith("#")) == 540,
            "Sample must contain 540 frames")
    print(json.dumps({"passed": True, "source_sha256": source_hash, "total_frames": 540, "ids": checked}, indent=2))


if __name__ == "__main__":
    main()
