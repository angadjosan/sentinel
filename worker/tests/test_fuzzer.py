from sentinel_worker.fuzzer import FuzzerTarget, HarnessParameter, generate_libfuzzer_harness


def test_generate_libfuzzer_harness_for_buffer_and_length():
    harness = generate_libfuzzer_harness(
        FuzzerTarget(
            function_name="parse_packet",
            header="parser.h",
            parameters=[
                HarnessParameter("data", "const uint8_t *", "data"),
                HarnessParameter("len", "size_t", "size"),
            ],
        )
    )

    assert '#include "parser.h"' in harness.source
    assert "parse_packet(data, len)" in harness.source
    assert "const uint8_t * data = (const uint8_t *)Data;" in harness.source
    assert "size_t len = (size_t)Size;" in harness.source
    assert harness.compile_command[:2] == ["clang", "-fsanitize=address,fuzzer"]
    assert "-print_coverage=1" in harness.run_command


def test_generate_libfuzzer_harness_decodes_integer_parameters():
    harness = generate_libfuzzer_harness(
        FuzzerTarget(
            function_name="set_flag",
            parameters=[HarnessParameter("flag", "uint32_t")],
        )
    )

    assert "uint32_t flag = 0;" in harness.source
    assert "__builtin_memcpy(&flag, Data + offset, sizeof(flag));" in harness.source
    assert "set_flag(flag)" in harness.source


def test_generate_afl_fallback_command():
    harness = generate_libfuzzer_harness(FuzzerTarget(function_name="target"))

    assert harness.afl_fallback_command == ["afl-fuzz", "-Q", "-i", "corpus/", "-o", "findings/", "--", "./target", "@@"]
