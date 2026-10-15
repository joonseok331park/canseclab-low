# CANSecLab-Low Baseline Profile Summary

## Metadata

- Created UTC: 2026-09-28T05:00:06Z
- Benign source: `artifacts/sample/benign.log`
- Benign source SHA-256: `94bb170c02c0145cd991787ccf2d9856196a6685104281ae69cf487bd764a443`
- Window: 100 ms
- Period margin ratio: 0.2
- Rate margin ratio: 0.2
- Unique CAN IDs: 4

## ID Summary

| CAN ID | Type | Frames | DLC | Periodic | Median Δ us | p05 Δ us | p95 Δ us | Rate Limit / 100ms | Fixed Mask | Max Identical Run |
|---|---|---:|---|---:|---:|---:|---:|---:|---|---:|
| 0x100 | standard | 300 | 8 | 1 | 10000 | 10000 | 10000 | 12 | 00000000FFFFFFFF | 1 |
| 0x101 | standard | 150 | 8 | 1 | 20000 | 20000 | 20000 | 7 | 00FFFF00FFFFFFFF | 1 |
| 0x102 | standard | 30 | 8 | 1 | 100000 | 100000 | 100000 | 3 | 00FFFFFFFFFFFFFF | 1 |
| 0x103 | standard | 60 | 8 | 1 | 50000 | 50000 | 50000 | 4 | 00FFFFFFFFFFFFFF | 1 |

## Effective Policy

| CAN ID | Period Min us | Period Max us | Observed Max / 100ms | Fixed Value | Ignore Mask |
|---|---:|---:|---:|---|---|
| 0x100 | 8000 | 12000 | 10 | 0000000000000000 | 0000000000000000 |
| 0x101 | 16000 | 24000 | 5 | 0000010000000000 | 0000000000000000 |
| 0x102 | 80000 | 120000 | 1 | 0001000000000000 | 0000000000000000 |
| 0x103 | 40000 | 60000 | 2 | 0010000000000000 | 0000000000000000 |

## Notes

- `periodic=1` means the ID passed the current periodicity heuristic.
- `fixed_mask` marks bytes that stayed constant across all benign frames for that CAN ID.
- Percentiles use the sorted delta at floor(p * (n - 1)); an even-sized median is rounded down.
- Rate counts use a half-open 100 ms window: frames exactly 100 ms apart are not counted together.
- Equal timestamps preserve input order for identical-payload runs; DLC is part of payload identity.
- `ignore_mask` defaults to zero. Explicit overrides change policy values, not observed statistics.
- This profile is generated from benign traffic only and should be treated as a validation baseline, not a production IDS policy.
