from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .vm import CommandResult, SandboxExecutor


INTEGER_TYPES = {"int", "unsigned int", "uint32_t", "int32_t", "size_t", "uint64_t", "int64_t"}
BYTE_POINTER_TYPES = {"const uint8_t *", "uint8_t *", "const char *", "char *", "const unsigned char *", "unsigned char *"}
LENGTH_TYPES = {"size_t", "uint32_t", "int"}


@dataclass(frozen=True)
class HarnessParameter:
    name: str
    c_type: str
    role: str = "value"


@dataclass(frozen=True)
class FuzzerTarget:
    function_name: str
    header: str | None = None
    parameters: list[HarnessParameter] = field(default_factory=list)


@dataclass(frozen=True)
class FuzzerHarness:
    source: str
    compile_command: list[str]
    run_command: list[str]
    afl_fallback_command: list[str]


@dataclass(frozen=True)
class CoverageFeedback:
    iteration: int
    coverage_score: int
    new_coverage_score: int
    coverage_lines: list[str]


@dataclass(frozen=True)
class FuzzerIterationResult:
    result: CommandResult
    feedback: CoverageFeedback
    sanitizer_output: str


@dataclass(frozen=True)
class FuzzerExecutionResult:
    compile_result: CommandResult
    run_result: CommandResult | None
    coverage_lines: list[str]
    sanitizer_output: str
    iterations: list[FuzzerIterationResult] = field(default_factory=list)
    coverage_improved: bool = False


SANITIZER_RE = re.compile(r"(ERROR: AddressSanitizer|AddressSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-buffer-overflow|use-after-free|data race)", re.IGNORECASE)
COVERAGE_RE = re.compile(r"(?:COVERED|coverage|cov:|#\d+)", re.IGNORECASE)
COVERAGE_SCORE_RE = re.compile(r"(?:cov|coverage|edges|features|ft)\s*[:=]\s*(\d+)|#(\d+)", re.IGNORECASE)


async def execute_fuzzer_harness(
    harness: FuzzerHarness,
    executor: SandboxExecutor,
    *,
    compile_timeout: int = 120,
    run_timeout: int = 300,
    max_iterations: int = 3,
    stagnation_limit: int = 1,
) -> FuzzerExecutionResult:
    compile_result = await executor.run(harness.compile_command, timeout_seconds=compile_timeout)
    if compile_result.exit_code != 0:
        return FuzzerExecutionResult(compile_result=compile_result, run_result=None, coverage_lines=[], sanitizer_output=_sanitizer_text([compile_result]))
    iterations: list[FuzzerIterationResult] = []
    seen_coverage: set[str] = set()
    best_score = 0
    stale_iterations = 0
    iteration_budget = max(1, math.ceil(run_timeout / max(1, max_iterations)))
    for iteration in range(max(1, max_iterations)):
        command = _iteration_run_command(harness.run_command, iteration_budget)
        run_result = await executor.run(command, timeout_seconds=iteration_budget)
        lines = _coverage_lines(run_result)
        score = _coverage_score(lines)
        has_numeric_score = _has_numeric_coverage_score(lines)
        new_lines = [line for line in lines if line not in seen_coverage]
        seen_coverage.update(lines)
        new_score = max(0, score - best_score)
        if new_lines and new_score == 0 and not has_numeric_score:
            new_score = len(new_lines)
        feedback = CoverageFeedback(iteration=iteration + 1, coverage_score=score, new_coverage_score=new_score, coverage_lines=lines)
        sanitizer_output = _sanitizer_text([run_result])
        iterations.append(FuzzerIterationResult(result=run_result, feedback=feedback, sanitizer_output=sanitizer_output))
        if sanitizer_output:
            break
        if score > best_score or (new_lines and not has_numeric_score):
            best_score = max(best_score, score)
            stale_iterations = 0
        else:
            stale_iterations += 1
        if run_result.exit_code != 0 or stale_iterations >= stagnation_limit:
            break
    run_result = iterations[-1].result if iterations else None
    return FuzzerExecutionResult(
        compile_result=compile_result,
        run_result=run_result,
        coverage_lines=_merged_coverage_lines(iterations),
        sanitizer_output=_sanitizer_text([compile_result]) or "\n".join(iteration.sanitizer_output for iteration in iterations if iteration.sanitizer_output),
        iterations=iterations,
        coverage_improved=any(iteration.feedback.new_coverage_score > 0 for iteration in iterations),
    )


def generate_libfuzzer_harness(target: FuzzerTarget, *, output_name: str = "fuzzer", max_total_time: int = 300) -> FuzzerHarness:
    declarations: list[str] = []
    arguments: list[str] = []
    offset_var = "offset"

    for index, parameter in enumerate(target.parameters):
        name = _safe_identifier(parameter.name or f"arg{index}")
        c_type = parameter.c_type.strip()
        role = parameter.role
        if role == "data" or c_type in BYTE_POINTER_TYPES:
            declarations.append(f"  {c_type} {name} = ({c_type})Data;")
            arguments.append(name)
        elif role == "size" or c_type in LENGTH_TYPES and name.lower() in {"len", "length", "size", "n"}:
            declarations.append(f"  {c_type} {name} = ({c_type})Size;")
            arguments.append(name)
        elif c_type in INTEGER_TYPES:
            declarations.extend(
                [
                    f"  {c_type} {name} = 0;",
                    f"  if (Size >= {offset_var} + sizeof({name})) {{",
                    f"    __builtin_memcpy(&{name}, Data + {offset_var}, sizeof({name}));",
                    f"    {offset_var} += sizeof({name});",
                    "  }",
                ]
            )
            arguments.append(name)
        else:
            declarations.append(f"  /* Unsupported parameter {name}: {c_type}. Pass zero-initialized storage. */")
            declarations.append(f"  {c_type} {name} = ({c_type})0;")
            arguments.append(name)

    includes = ['#include <stdint.h>', '#include <stddef.h>', '#include <string.h>']
    if target.header:
        includes.append(f'#include "{target.header}"')

    source = "\n".join(
        [
            *includes,
            "",
            "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {",
            "  size_t offset = 0;",
            "  if (Data == 0) return 0;",
            *declarations,
            f"  (void){target.function_name}({', '.join(arguments)});",
            "  return 0;",
            "}",
            "",
        ]
    )
    return FuzzerHarness(
        source=source,
        compile_command=[
            "clang",
            "-fsanitize=address,fuzzer",
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            "fuzzer_harness.c",
            "target_lib.a",
            "-o",
            output_name,
        ],
        run_command=[f"./{output_name}", f"-max_total_time={max_total_time}", "-print_coverage=1", "corpus/"],
        afl_fallback_command=["afl-fuzz", "-Q", "-i", "corpus/", "-o", "findings/", "--", "./target", "@@"],
    )


def _safe_identifier(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char == "_" else "_" for char in value)
    if not cleaned or cleaned[0].isdigit():
        return f"arg_{cleaned}"
    return cleaned


def _coverage_lines(result: CommandResult) -> list[str]:
    lines = [line.strip() for line in f"{result.stdout}\n{result.stderr}".splitlines()]
    return [line for line in lines if line and COVERAGE_RE.search(line)][:200]


def _coverage_score(lines: list[str]) -> int:
    score = 0
    for line in lines:
        for match in COVERAGE_SCORE_RE.finditer(line):
            values = [group for group in match.groups() if group is not None]
            if values:
                score = max(score, int(values[0]))
    return score or len(set(lines))


def _has_numeric_coverage_score(lines: list[str]) -> bool:
    return any(COVERAGE_SCORE_RE.search(line) for line in lines)


def _iteration_run_command(run_command: list[str], max_total_time: int) -> list[str]:
    command: list[str] = []
    replaced = False
    for part in run_command:
        if part.startswith("-max_total_time="):
            command.append(f"-max_total_time={max_total_time}")
            replaced = True
        else:
            command.append(part)
    if not replaced:
        command.append(f"-max_total_time={max_total_time}")
    return command


def _merged_coverage_lines(iterations: list[FuzzerIterationResult]) -> list[str]:
    lines: list[str] = []
    seen: set[str] = set()
    for iteration in iterations:
        for line in iteration.feedback.coverage_lines:
            if line not in seen:
                seen.add(line)
                lines.append(line)
    return lines[:200]


def _sanitizer_text(results: list[CommandResult]) -> str:
    chunks: list[str] = []
    for result in results:
        text = f"{result.stdout}\n{result.stderr}".strip()
        if SANITIZER_RE.search(text):
            chunks.append(text)
    return "\n".join(chunks)
