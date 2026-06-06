import pytest

from sentinel_worker.fuzzer import FuzzerHarness, FuzzerTarget, HarnessParameter, execute_fuzzer_harness, generate_libfuzzer_harness
from sentinel_worker.vm import CommandResult


class FakeFuzzerExecutor:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def run(self, argv, *, timeout_seconds=30):
        self.calls.append((argv, timeout_seconds))
        return self.results.pop(0)


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


@pytest.mark.asyncio
async def test_execute_fuzzer_harness_iterates_while_coverage_improves():
    harness = FuzzerHarness(
        source="",
        compile_command=["clang", "harness.c", "-o", "fuzzer"],
        run_command=["./fuzzer", "-max_total_time=300", "-print_coverage=1", "corpus/"],
        afl_fallback_command=[],
    )
    executor = FakeFuzzerExecutor(
        [
            CommandResult(argv=harness.compile_command, exit_code=0),
            CommandResult(argv=harness.run_command, exit_code=0, stderr="#1 INITED cov: 2 ft: 2"),
            CommandResult(argv=harness.run_command, exit_code=0, stderr="#2 NEW cov: 5 ft: 5"),
            CommandResult(argv=harness.run_command, exit_code=0, stderr="#3 DONE cov: 5 ft: 5"),
        ]
    )

    result = await execute_fuzzer_harness(harness, executor, run_timeout=9, max_iterations=3, stagnation_limit=1)

    assert len(result.iterations) == 3
    assert result.coverage_improved is True
    assert result.iterations[0].feedback.new_coverage_score == 2
    assert result.iterations[1].feedback.new_coverage_score == 3
    assert result.iterations[2].feedback.new_coverage_score == 0
    assert result.coverage_lines == ["#1 INITED cov: 2 ft: 2", "#2 NEW cov: 5 ft: 5", "#3 DONE cov: 5 ft: 5"]
    assert executor.calls[1][0][1] == "-max_total_time=3"
    assert executor.calls[1][1] == 3


@pytest.mark.asyncio
async def test_execute_fuzzer_harness_stops_on_sanitizer_output():
    harness = FuzzerHarness(
        source="",
        compile_command=["clang", "harness.c", "-o", "fuzzer"],
        run_command=["./fuzzer", "corpus/"],
        afl_fallback_command=[],
    )
    executor = FakeFuzzerExecutor(
        [
            CommandResult(argv=harness.compile_command, exit_code=0),
            CommandResult(argv=harness.run_command, exit_code=1, stderr="#1 cov: 4\nERROR: AddressSanitizer: heap-buffer-overflow"),
            CommandResult(argv=harness.run_command, exit_code=0, stderr="#2 cov: 8"),
        ]
    )

    result = await execute_fuzzer_harness(harness, executor, run_timeout=10, max_iterations=2)

    assert len(result.iterations) == 1
    assert "AddressSanitizer" in result.sanitizer_output
    assert result.run_result is not None
    assert result.run_result.exit_code == 1
    assert len(executor.calls) == 2
    assert executor.calls[1][0][-1] == "-max_total_time=5"
