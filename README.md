# CANSecLab-Low

C++17과 Linux SocketCAN으로 만든 CAN 트래픽 검증 도구입니다. 정상 트래픽을 수집해 CAN ID별 기준(baseline)을 만들고, 새로 들어오는 프레임이 그 기준에서 벗어나는지 규칙으로 검사합니다. 저장된 로그를 원래 시간 간격대로 다시 보내거나 flood, replay, fuzz 형태의 시험 트래픽을 만들어 탐지 결과를 확인할 수 있습니다.

실험은 모두 Linux 가상 CAN 인터페이스(vcan)와 합성 데이터로 했고 실제 차량에는 연결하지 않았습니다.

## 구성

| 실행 파일 | 하는 일 |
|---|---|
| `cansec-capture` | SocketCAN 인터페이스에서 프레임을 받아 candump 형식 로그로 저장 (Linux 전용) |
| `cansec-profile` | 정상 로그로 ID별 기준 파일(`baseline.ini`)과 요약(Markdown) 생성 |
| `cansec-detect` | 저장된 로그나 실시간으로 받은 프레임을 기준과 비교해 검사하고 경고(JSONL)와 보고서(Markdown)를 남김 |
| `cansec-replay` | 로그 재생(normal)과 flood, replay, fuzz 시험 트래픽 송신 (Linux 전용) |

```
기준 만들기:  vcan0 -> cansec-capture -> benign.log -> cansec-profile -> baseline.ini
검사:         cansec-replay -> vcan0 -> cansec-detect (baseline.ini) -> alerts.jsonl, report.md
```

로그 한 줄은 `(1730960000.000000) vcan0 100#001E0BB800000000` 형식입니다. Classical CAN 데이터 프레임만 다루고 RTR/에러 프레임은 수집할 때 버립니다.

## 탐지 규칙

| 규칙 | 심각도 | 조건 |
|---|---|---|
| `UNKNOWN_ID` | HIGH | 기준에 없는 ID (11비트/29비트를 따로 구분) |
| `DLC_MISMATCH` | HIGH | 그 ID에서 허용되지 않은 데이터 길이 |
| `PERIOD_VIOLATION` | MEDIUM | 주기적인 ID의 수신 간격이 허용 범위를 벗어남 |
| `RATE_SPIKE` | HIGH | 100ms 구간 안의 프레임 수가 한도를 넘음 |
| `FIXED_BYTE_VIOLATION` | MEDIUM | 정상 로그에서 항상 같던 바이트가 달라짐 |
| `REPLAY_BURST` | HIGH | 같은 payload가 연속으로 한도보다 많이 반복됨 |

기준값은 정상 로그에서 계산합니다. 주기적이라고 판정된 ID는 수신 간격 5백분위의 80%부터 95백분위의 120%까지를 허용 주기로 씁니다(여유 비율 기본 0.2). 빈도 한도는 100ms 구간의 최대 프레임 수에 max(2, 최대값의 20% 올림)를 더한 값입니다. 필요하면 `--override` 파일로 ID별 값을 바꿀 수 있습니다(`configs/overrides_example.ini` 참고).

## 빌드

CMake 3.16 이상과 C++17 컴파일러가 필요합니다. GCC 11, 13에서 확인했습니다.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Windows(llvm-mingw clang)에서는 SocketCAN이 필요 없는 profile과 저장 로그 검사(`--check-log`)만 빌드해 쓸 수 있고 `cansec-capture`는 만들어지지 않습니다.

## 사용 예

### 1. 기준 만들기와 저장 로그 검사

`artifacts/sample/`에 합성 정상 로그(ID 4개, 3초, 540프레임)와 그 결과물이 들어 있습니다.

```bash
./build/cansec-profile --in artifacts/sample/benign.log \
    --out baseline.ini --summary profile_summary.md

./build/cansec-detect --rules baseline.ini --validate-rules
./build/cansec-detect --rules baseline.ini --check-log captures/test.log --summary report.md
```

`--check-log`는 경고를 표준 출력으로 보여 줍니다. 로그에 기준에 없는 ID 0x1A0 프레임을 하나 넣으면 이렇게 나옵니다.

```
UNKNOWN_ID HIGH (1730960000.005000) vcan0 1A0#0102 CAN ID 0x1A0 (standard) is absent from baseline
```

### 2. vcan에서 실시간 탐지

```bash
bash scripts/setup_vcan.sh          # vcan0 생성 후 UP (필요하면 sudo 사용)

# 터미널 1: 탐지
./build/cansec-detect --rules baseline.ini --if vcan0 --out alerts.jsonl \
    --max-seconds 10 --summary report.md

# 터미널 2: 시험 트래픽
./build/cansec-replay normal --if vcan0 --in artifacts/sample/benign.log
./build/cansec-replay flood  --if vcan0 --id 100 --data 1200 --interval-us 100 --count 12
./build/cansec-replay fuzz   --if vcan0 --id 100 --base-data 1200 --period-us 10000 --count 4 --flip-mask 00FF
```

경고는 한 줄에 하나씩 JSON으로 저장됩니다. 아래는 `smoke_v1.py`의 시연용 기준(허용 주기 5~500ms)으로 flood를 보냈을 때 나온 줄입니다.

```json
{"capture_ts_us":1792004613535396,"alert_ts_us":1792004613535480,"if":"vcan0","rule":"PERIOD_VIOLATION","severity":"MEDIUM","can_id":"0x100","id_type":"standard","dlc":2,"data":"1200","detail":"delta_us=74 allowed_min_us=5000 allowed_max_us=500000"}
```

`capture_ts_us`는 커널이 프레임을 받은 시각(`SO_TIMESTAMPNS`)이고 `alert_ts_us`는 규칙 검사가 끝난 시각입니다. 보고서에는 규칙별 경고 수, 처음 10개 경고, 기준 파일과 입력 로그(실시간이면 경고 파일)의 SHA-256, 빌드 정보가 들어갑니다.

### 3. 전체 흐름 한 번에 돌리기

`scripts/smoke_v1.py`는 정상 프레임 수집부터 기준 생성, 네 가지 재생 모드의 송신, 실시간 탐지와 보고서 확인까지 차례로 실행합니다. vcan0이 미리 올라가 있어야 하고 인터페이스를 직접 만들거나 바꾸지는 않습니다.

```bash
python3 scripts/smoke_v1.py --bin-dir build --interface vcan0 --output-dir runs
```

`scripts/verify_*_linux.py`는 수집, 탐지, 재생, 보고서, 수신 시각 처리를 각각 따로 시험하는 스크립트입니다.

## 테스트

단위 테스트와 CLI 테스트 19개를 CTest로 실행합니다. 파서, 기준 생성 계산(백분위, 100ms 구간 경계, 고정 바이트 마스크), 기준 파일 오류 처리, 각 규칙의 경계값, 재생 시간표와 overflow 처리, JSON/Markdown 출력이 포함됩니다.

vcan이 필요한 시험은 CTest와 분리해 `scripts/`에 두었습니다. Ubuntu 22.04(커널 6.8)에서 `smoke_v1.py` 7개 항목과 `verify_*_linux.py` 전체가 통과했습니다.

## 개발하면서 고친 문제

통합 시험 중 실시간 탐지가 "같은 ID의 시각이 거꾸로 갔다"는 오류로 멈춘 적이 있습니다. 첫 프레임의 시각이 실제 수신 시각보다 늦게 기록되면서 다음 프레임보다 뒤가 된 것이었습니다. 당시에는 `read()` 다음에 `ioctl(SIOCGSTAMP)`로 시각을 따로 가져오고, 실패하면 현재 시각으로 대신했습니다. 이렇게 프레임과 시각을 따로 읽으면 시각이 늦게 찍힐 수 있습니다. 지금은 소켓에 `SO_TIMESTAMPNS`(지원하지 않으면 `SO_TIMESTAMP`)를 켜고 `recvmsg()`로 프레임과 수신 시각을 함께 읽습니다. 시각 정보가 없으면 대체하지 않고 오류로 처리합니다. 수정 후에는 프로세스를 잠시 멈춰 64개 프레임을 버퍼에 쌓았다가 읽는 시험에서 모든 시각이 별도 수신기 기록과 일치했습니다.

## 한계

- Classical CAN(최대 8바이트)만 지원하고 CAN FD는 지원하지 않습니다.
- 가상 CAN과 합성 트래픽으로만 확인했습니다. 실차 데이터로 탐지율이나 오탐률을 잰 적은 없습니다.
- 규칙 기반이라 경고가 곧 공격을 뜻하지는 않고 경고가 없다고 안전하다는 뜻도 아닙니다.
- 주기 검사는 프레임이 도착할 때만 합니다. 프레임이 아예 안 오는 상황은 잡지 못합니다.
