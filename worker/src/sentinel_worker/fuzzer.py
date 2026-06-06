from __future__ import annotations

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
class FuzzerExecutionResult:
    compile_result: CommandResult
    run_result: CommandResult | None
    coverage_lines: list[str]
    sanitizer_output: str


SANITIZER_RE = re.compile(r"(ERROR: AddressSanitizer|AddressSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|runtime error:|heap-buffer-overflow|use-after-free|data race)", re.IGNORECASE)
COVERAGE_RE = re.compile(r"(?:COVERED|coverage|cov:|#\d+)", re.IGNORECASE)


async def execute_fuzzer_harness(harness: FuzzerHarness, executor: SandboxExecutor, *, compile_timeout: int = 120, run_timeout: int = 300) -> FuzzerExecutionResult:
    compile_result = await executor.run(harness.compile_command, timeout_seconds=compile_timeout)
    if compile_result.exit_code != 0:
        return FuzzerExecutionResult(compile_result=compile_result, run_result=None, coverage_lines=[], sanitizer_output=_sanitizer_text([compile_result]))
    run_result = await executor.run(harness.run_command, timeout_seconds=run_timeout)
    return FuzzerExecutionResult(
        compile_result=compile_result,
        run_result=run_result,
        coverage_lines=_coverage_lines(run_result),
        sanitizer_output=_sanitizer_text([compile_result, run_result]),
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


def _sanitizer_text(results: list[CommandResult]) -> str:
    chunks: list[str] = []
    for result in results:
        text = f"{result.stdout}\n{result.stderr}".strip()
        if SANITIZER_RE.search(text):
            chunks.append(text)
    return "\n".join(chunks)
