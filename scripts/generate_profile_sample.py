#!/usr/bin/env python3
"""Write deterministic offline CAN data; this script does not transmit frames."""
import argparse
from pathlib import Path


def generate() -> str:
    rows = []
    start_us = 1730960000000000
    for can_id, period_us in ((0x100, 10000), (0x101, 20000), (0x102, 100000), (0x103, 50000)):
        for index, elapsed_us in enumerate(range(0, 3000000, period_us)):
            if can_id == 0x100:
                rpm = 3000 + (index % 20) * 10
                data = [index % 256, 30 + index % 4, rpm >> 8, rpm & 255, 0, 0, 0, 0]
            elif can_id == 0x101:
                data = [20 + index % 5, 0, 1, 44 + index % 10, 0, 0, 0, 0]
            elif can_id == 0x102:
                data = [index % 256, 1, 0, 0, 0, 0, 0, 0]
            else:
                data = [index % 256, 0x10, 0, 0, 0, 0, 0, 0]
            timestamp = start_us + elapsed_us
            payload = bytes(data).hex().upper()
            rows.append((timestamp, can_id, f"({timestamp // 1000000}.{timestamp % 1000000:06d}) vcan0 {can_id:03X}#{payload}\n"))
    rows.sort()
    return "# Deterministic synthetic offline sample: 3 s, 540 frames, no live capture\n" + "".join(row[2] for row in rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="artifacts/sample/benign.log")
    args = parser.parse_args()
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(generate().encode("ascii"))
    print(f"Wrote 540 synthetic frames: {path}")


if __name__ == "__main__":
    main()
