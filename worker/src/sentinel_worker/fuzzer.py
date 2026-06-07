from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field

import structlog

from .vm import CommandResult, SandboxExecutor

log = structlog.get_logger(__name__)

_FUZZER_AGENT_SYSTEM = """You are a security engineer directing a coverage-guided fuzzing campaign.
After each fuzzing iteration, you receive coverage data and sanitizer output.
Suggest how to mutate the fuzzer corpus or harness to reach uncovered code paths.
Return only JSON: {"strategy": "brief directive", "corpus_additions": ["hex_encoded_input1", ...], "should_continue": true|false}.
corpus_additions must be hex-encoded byte strings. Limit to 3 additions per round."""


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


async def execute_fuzzer_harness_with_agent(
    harness: FuzzerHarness,
    executor: SandboxExecutor,
    llm,  # SentinelLLMClient | None
    *,
    run_id: str | None = None,
    db=None,
    compile_timeout: int = 120,
    run_timeout: int = 300,
    max_iterations: int = 5,
    stagnation_limit: int = 2,
) -> FuzzerExecutionResult:
    """Coverage-guided fuzzing with LLM-directed corpus mutation between iterations.

    After each iteration, if coverage plateaus, the agent reads the coverage
    output and suggests corpus mutations to target uncovered branches.
    Falls back to plain execute_fuzzer_harness if llm is None.
    """
    if llm is None:
        return await execute_fuzzer_harness(
            harness, executor,
            compile_timeout=compile_timeout,
            run_timeout=run_timeout,
            max_iterations=max_iterations,
            stagnation_limit=stagnation_limit,
        )

    compile_result = await executor.run(harness.compile_command, timeout_seconds=compile_timeout)
    if compile_result.exit_code != 0:
        return FuzzerExecutionResult(
            compile_result=compile_result,
            run_result=None,
            coverage_lines=[],
            sanitizer_output=_sanitizer_text([compile_result]),
        )

    iterations: list[FuzzerIterationResult] = []
    seen_coverage: set[str] = set()
    best_score = 0
    stale_iterations = 0
    iteration_budget = max(1, math.ceil(run_timeout / max(1, max_iterations)))

    for iteration in range(max(1, max_iterations)):
        command = _iteration_run_command(harness.run_command, iteration_budget)
        run_result = await executor.run(command, timeout_seconds=iteration_budget + 10)
        lines = _coverage_lines(run_result)
        score = _coverage_score(lines)
        has_numeric_score = _has_numeric_coverage_score(lines)
        new_lines = [line for line in lines if line not in seen_coverage]
        seen_coverage.update(lines)
        new_score = max(0, score - best_score)
        if new_lines and new_score == 0 and not has_numeric_score:
            new_score = len(new_lines)

        feedback = CoverageFeedback(
            iteration=iteration + 1,
            coverage_score=score,
            new_coverage_score=new_score,
            coverage_lines=lines,
        )
        sanitizer_output = _sanitizer_text([run_result])
        iterations.append(FuzzerIterationResult(result=run_result, feedback=feedback, sanitizer_output=sanitizer_output))

        if sanitizer_output:
            log.info("fuzzer.agent.sanitizer_crash", iteration=iteration + 1, run_id=run_id)
            break

        coverage_improved = score > best_score or (new_lines and not has_numeric_score)
        if coverage_improved:
            best_score = max(best_score, score)
            stale_iterations = 0
        else:
            stale_iterations += 1

        if run_result.exit_code != 0:
            break

        if stale_iterations >= stagnation_limit and iteration < max_iterations - 1:
            # Coverage has plateaued — ask the agent for corpus mutation strategy
            agent_guidance = await _agent_corpus_guidance(
                llm=llm,
                coverage_lines=lines,
                sanitizer_output=sanitizer_output,
                iteration=iteration + 1,
                run_id=run_id,
                db=db,
            )
            if not agent_guidance.get("should_continue", True):
                log.info("fuzzer.agent.stop_directed", iteration=iteration + 1, run_id=run_id)
                break
            corpus_additions = agent_guidance.get("corpus_additions", [])
            if corpus_additions:
                await _write_corpus_additions(executor, corpus_additions)
                stale_iterations = 0
                log.info("fuzzer.agent.corpus_mutated", additions=len(corpus_additions), iteration=iteration + 1, run_id=run_id)

    run_result_final = iterations[-1].result if iterations else None
    return FuzzerExecutionResult(
        compile_result=compile_result,
        run_result=run_result_final,
        coverage_lines=_merged_coverage_lines(iterations),
        sanitizer_output=_sanitizer_text([compile_result]) or "\n".join(i.sanitizer_output for i in iterations if i.sanitizer_output),
        iterations=iterations,
        coverage_improved=any(i.feedback.new_coverage_score > 0 for i in iterations),
    )


async def _agent_corpus_guidance(
    *,
    llm,
    coverage_lines: list[str],
    sanitizer_output: str,
    iteration: int,
    run_id: str | None,
    db,
) -> dict:
    user_content = json.dumps({
        "iteration": iteration,
        "coverage_lines": coverage_lines[:50],
        "sanitizer_output": sanitizer_output[:500] if sanitizer_output else None,
        "plateau_detected": True,
    }, sort_keys=True)
    try:
        result = await llm.call(
            system=_FUZZER_AGENT_SYSTEM,
            user=user_content,
            component="fuzzer_agent",
            run_id=run_id,
            db=db,
        )
        return json.loads(result.content)
    except Exception as exc:
        log.warning("fuzzer.agent.guidance_failed", error=str(exc), run_id=run_id)
        return {"should_continue": True, "corpus_additions": []}


async def _write_corpus_additions(executor: SandboxExecutor, hex_inputs: list[str]) -> None:
    """Write agent-suggested corpus entries to the corpus/ directory in the sandbox."""
    for i, hex_input in enumerate(hex_inputs[:3]):
        try:
            bytes.fromhex(hex_input)  # validate hex
            argv = ["sh", "-c", f"printf '{hex_input}' | xxd -r -p > corpus/agent_{i:03d}.bin 2>/dev/null || true"]
            await executor.run(argv, timeout_seconds=5)
        except (ValueError, Exception):
            continue


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
