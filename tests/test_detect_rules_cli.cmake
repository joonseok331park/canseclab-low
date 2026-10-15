if(NOT DEFINED DETECT_EXE OR NOT DEFINED PROFILE_EXE OR
   NOT DEFINED SAMPLE_DIR OR NOT DEFINED TEST_DIR)
    message(FATAL_ERROR "Missing test paths")
endif()

file(MAKE_DIRECTORY "${TEST_DIR}")
file(READ "${SAMPLE_DIR}/baseline.ini" sample)

function(expect_success name expected)
    execute_process(COMMAND "${DETECT_EXE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
    if(NOT result EQUAL 0 OR NOT output MATCHES "${expected}" OR NOT error STREQUAL "")
        message(FATAL_ERROR "${name}: exit=${result}, stdout=${output}, stderr=${error}")
    endif()
    message(STATUS "PASS ${name}")
endfunction()

function(expect_failure name expected)
    execute_process(COMMAND "${DETECT_EXE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
    if(NOT result EQUAL 1 OR NOT output STREQUAL "" OR NOT error MATCHES "${expected}")
        message(FATAL_ERROR "${name}: exit=${result}, stdout=${output}, stderr=${error}")
    endif()
    message(STATUS "PASS ${name}")
endfunction()

expect_success(help "Live detection requires Linux" --help)
expect_success(saved_sample "Baseline valid: 4 IDs, window_ms=100"
    --rules "${SAMPLE_DIR}/baseline.ini" --validate-rules)

# Verify the current producer and consumer agree on the format.
execute_process(COMMAND "${PROFILE_EXE}" --in "${SAMPLE_DIR}/benign.log"
    --out "${TEST_DIR}/generated.ini" --summary "${TEST_DIR}/generated.md"
    RESULT_VARIABLE profile_result OUTPUT_VARIABLE profile_output ERROR_VARIABLE profile_error)
if(NOT profile_result EQUAL 0)
    message(FATAL_ERROR "profile generation failed: ${profile_output} ${profile_error}")
endif()
expect_success(current_profile_roundtrip "Baseline valid: 4 IDs, window_ms=100"
    --validate-rules --rules "${TEST_DIR}/generated.ini")

file(WRITE "${TEST_DIR}/empty.ini" "")
string(REPLACE "allowed_dlc=8" "allowed_dlc=9" bad_dlc "${sample}")
file(WRITE "${TEST_DIR}/bad-dlc.ini" "${bad_dlc}")
file(SHA256 "${TEST_DIR}/bad-dlc.ini" before_hash)
expect_failure(bad_dlc "bad-dlc.ini.*(allowed_dlc|DLC)"
    --rules "${TEST_DIR}/bad-dlc.ini" --validate-rules)
file(SHA256 "${TEST_DIR}/bad-dlc.ini" after_hash)
if(NOT before_hash STREQUAL after_hash)
    message(FATAL_ERROR "Validation modified its input")
endif()
expect_failure(empty_file "empty.ini" --rules "${TEST_DIR}/empty.ini" --validate-rules)
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef missing_suffix)
expect_failure(missing_file "nonexistent" --rules "${TEST_DIR}/nonexistent-${missing_suffix}.ini" --validate-rules)
expect_failure(no_arguments "required:")
expect_failure(no_validation_flag "required:" --rules "${SAMPLE_DIR}/baseline.ini")
expect_failure(no_rules "required:" --validate-rules)
expect_failure(missing_path "requires a file path" --rules --validate-rules)
expect_failure(duplicate_rules "duplicate --rules" --rules one --rules two --validate-rules)
expect_failure(duplicate_mode "duplicate --validate-rules" --validate-rules --validate-rules)

# Failed live startup must preserve an existing output on every platform.
set(output_path "${TEST_DIR}/existing-alerts.jsonl")
file(WRITE "${output_path}" "keep-existing-alerts\n")
file(SHA256 "${output_path}" alerts_before)
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(live_error "(socket.*failed|SIOCGIFINDEX.*failed for interface)")
else()
    set(live_error "Live detection requires Linux")
endif()
string(RANDOM LENGTH 8 ALPHABET 0123456789abcdef interface_suffix)
expect_failure(live_startup_rejection "${live_error}"
    --rules "${SAMPLE_DIR}/baseline.ini" --if "cs${interface_suffix}" --out "${output_path}" --max-seconds 1)
file(SHA256 "${output_path}" alerts_after)
if(NOT alerts_before STREQUAL alerts_after)
    message(FATAL_ERROR "Failed live startup modified its output")
endif()
