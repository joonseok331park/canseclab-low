cmake_minimum_required(VERSION 3.16)
project(CANSecLabLow VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Library and tools
# ---------------------------------------------------------------------------
add_library(cansec_common
    src/common/alert_json.cpp
    src/common/logio.cpp
    src/common/report.cpp
    src/common/sha256.cpp
    src/core/baseline.cpp
    src/core/detector.cpp
    src/core/profile.cpp
    src/core/replay.cpp
)
target_include_directories(cansec_common PUBLIC include)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(cansec_common PRIVATE src/common/socketcan.cpp)
    add_executable(cansec-capture src/tools/main_capture.cpp)
    target_link_libraries(cansec-capture PRIVATE cansec_common)
else()
    message(STATUS "SocketCAN is Linux-only: building offline tools only")
endif()

add_executable(cansec-profile src/tools/main_profile.cpp)
add_executable(cansec-detect src/tools/main_detect.cpp)
add_executable(cansec-replay src/tools/main_replay.cpp)
foreach(tool cansec-profile cansec-detect cansec-replay)
    target_link_libraries(${tool} PRIVATE cansec_common)
endforeach()

# ---------------------------------------------------------------------------
# Build info for detection reports: a hash over the source files, plus the
# Git commit when building from a checkout.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE CANSEC_FINGERPRINT_FILES CONFIGURE_DEPENDS
    RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "include/*.hpp" "include/*.hpp.in" "src/*.cpp")
list(APPEND CANSEC_FINGERPRINT_FILES "CMakeLists.txt")
list(SORT CANSEC_FINGERPRINT_FILES)

set(CANSEC_SOURCE_ENTRIES "")
foreach(CANSEC_FILE IN LISTS CANSEC_FINGERPRINT_FILES)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${CANSEC_FILE}")
    file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/${CANSEC_FILE}" CANSEC_FILE_HASH)
    string(APPEND CANSEC_SOURCE_ENTRIES "${CANSEC_FILE} ${CANSEC_FILE_HASH}\n")
endforeach()
string(SHA256 CANSEC_SOURCE_SHA256 "${CANSEC_SOURCE_ENTRIES}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/source-fingerprint.txt" "${CANSEC_SOURCE_ENTRIES}")

set(CANSEC_GIT_COMMIT "unavailable (no local Git checkout)")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    find_package(Git QUIET)
    if(Git_FOUND)
        execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse HEAD
            OUTPUT_VARIABLE CANSEC_REV OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET RESULT_VARIABLE CANSEC_REV_STATUS)
        if(CANSEC_REV_STATUS EQUAL 0)
            set(CANSEC_GIT_COMMIT "${CANSEC_REV} (source SHA256 identifies the built files)")
        endif()
    endif()
endif()

configure_file(include/cansec/build_info.hpp.in generated/cansec/build_info.hpp @ONLY)
target_include_directories(cansec-detect PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
enable_testing()
find_package(Python3 QUIET COMPONENTS Interpreter)

# Unit tests
foreach(name
        test-log-parser test-profile test-baseline test-alert-json test-report
        test-detector-identity test-detector-timing test-detector-payload test-replay-schedule)
    string(REPLACE "-" "_" source "${name}")
    add_executable(${name} tests/${source}.cpp)
    target_link_libraries(${name} PRIVATE cansec_common)
    add_test(NAME ${name} COMMAND ${name})
endforeach()

# CLI tests written as CMake scripts
function(cansec_cli_test name script)
    add_test(NAME ${name}
        COMMAND ${CMAKE_COMMAND} ${ARGN}
            -DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/${name}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/${script})
endfunction()

set(SAMPLE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/artifacts/sample)
cansec_cli_test(test-profile-cli test_profile_cli.cmake
    -DPROFILE_EXE=$<TARGET_FILE:cansec-profile>)
cansec_cli_test(test-detect-rules-cli test_detect_rules_cli.cmake
    -DDETECT_EXE=$<TARGET_FILE:cansec-detect> -DPROFILE_EXE=$<TARGET_FILE:cansec-profile> -DSAMPLE_DIR=${SAMPLE_DIR})
cansec_cli_test(test-detect-log-cli test_detect_log_cli.cmake
    -DDETECT_EXE=$<TARGET_FILE:cansec-detect> -DSAMPLE_DIR=${SAMPLE_DIR})
cansec_cli_test(test-detect-timing-cli test_detect_timing_cli.cmake
    -DDETECT_EXE=$<TARGET_FILE:cansec-detect>)
cansec_cli_test(test-detect-payload-cli test_detect_payload_cli.cmake
    -DDETECT_EXE=$<TARGET_FILE:cansec-detect>)
cansec_cli_test(test-detect-live-options test_detect_live_options.cmake
    -DDETECT_EXE=$<TARGET_FILE:cansec-detect> -DSAMPLE_DIR=${SAMPLE_DIR})
cansec_cli_test(test-replay-options test_replay_options.cmake
    -DREPLAY_EXE=$<TARGET_FILE:cansec-replay>)

# CLI tests written in Python
if(Python3_Interpreter_FOUND)
    add_test(NAME test-detect-report-cli
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_detect_report_cli.py
            $<TARGET_FILE:cansec-detect> ${CMAKE_CURRENT_BINARY_DIR}/test-detect-report-cli)
    add_test(NAME test-replay-scenarios-cli
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_replay_scenarios_cli.py
            $<TARGET_FILE:cansec-replay> ${CMAKE_CURRENT_BINARY_DIR}/test-replay-scenarios-cli)
    add_test(NAME test-alert-json-roundtrip
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_alert_json_roundtrip.py
            $<TARGET_FILE:test-alert-json>)
    if(WIN32)
        add_test(NAME test-profile-output-transaction
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_profile_output_transaction.py
                $<TARGET_FILE:cansec-profile>)
    endif()
endif()
