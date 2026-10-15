"""Parse emitted C++ JSON with Python and verify types and escaped content."""
import json
import subprocess
import sys

result = subprocess.run([sys.argv[1], '--emit-fixtures'], capture_output=True, check=True)
assert not result.stderr
lines = result.stdout.decode('utf-8').splitlines()
assert len(lines) == 2
first, second = [json.loads(line) for line in lines]
expected_fields = {'capture_ts_us', 'alert_ts_us', 'if', 'rule', 'severity',
                   'can_id', 'id_type', 'dlc', 'data', 'detail'}
for row in [first, second]:
    assert set(row) == expected_fields
    assert type(row['capture_ts_us']) is int and type(row['alert_ts_us']) is int
    assert type(row['dlc']) is int
    assert row['if'] == 'bus"\\\n'
    assert row['detail'] == 'nul\0tab\t한글'
    assert row['rule'] == 'FIXED_BYTE_VIOLATION' and row['severity'] == 'MEDIUM'
    assert row['can_id'] == '0x123'
    assert len(bytes.fromhex(row['data'])) == row['dlc']
assert first['id_type'] == 'standard' and first['data'] == '00AAFF'
assert first['capture_ts_us'] == 123456789 and first['alert_ts_us'] == 123456790
assert second['id_type'] == 'extended' and second['data'] == ''
assert second['capture_ts_us'] == 18446744073709551615
print('PASS: independent JSON parsing, escaped strings, typed IDs, payload lengths and exact uint64 timestamps')
