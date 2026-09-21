"""Budgeted recipe-unit reduction with revalidated, JSON-safe checkpoints."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Callable

MAX_TRACE_ENTRIES = 1024
CHECKPOINT_FORMAT = "plcman.gx-re-lab.reduction-checkpoint"


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Observation:
    valid: bool
    failure_class: str | None
    first_divergence: str | None


def _valid_observation(value: object) -> bool:
    return (type(value) is Observation and type(value.valid) is bool
            and all(item is None or (type(item) is str and item and len(item) <= 256
                                    and not any(0xD800 <= ord(c) <= 0xDFFF for c in item))
                    for item in (value.failure_class, value.first_divergence)))


def _signature(value: Observation) -> dict:
    return {"failure_class": value.failure_class, "first_divergence": value.first_divergence,
            "sha256": _digest([value.failure_class, value.first_divergence])}


def _checkpoint(units: list[str], target: Observation, current: list[int], phase: str,
                partitions: int, chunk_start: int, index: int, total_calls: int) -> dict:
    value = {"format": CHECKPOINT_FORMAT, "version": 1, "input_units_sha256": _digest(units),
             "target_signature": _signature(target), "retained_indices": current, "phase": phase,
             "cursor": {"partitions": partitions, "chunk_start": chunk_start, "index": index},
             "total_calls": total_calls}
    return {**value, "sha256": _digest(value)}


def _resume(checkpoint: object, units: list[str]) -> tuple[list[int], Observation, str, int, int, int, int]:
    if not isinstance(checkpoint, dict) or set(checkpoint) != {"format", "version", "input_units_sha256", "target_signature", "retained_indices", "phase", "cursor", "total_calls", "sha256"}:
        raise ValueError("invalid checkpoint")
    signature, cursor, indices = checkpoint["target_signature"], checkpoint["cursor"], checkpoint["retained_indices"]
    try:
        checkpoint_digest = _digest({key: value for key, value in checkpoint.items() if key != "sha256"})
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError("invalid checkpoint") from error
    if (checkpoint["format"] != CHECKPOINT_FORMAT or type(checkpoint["version"]) is not int or checkpoint["version"] != 1
            or type(checkpoint["sha256"]) is not str or checkpoint["sha256"] != checkpoint_digest
            or checkpoint["input_units_sha256"] != _digest(units) or not isinstance(signature, dict)
            or set(signature) != {"failure_class", "first_divergence", "sha256"}
            or not isinstance(indices, list) or checkpoint["phase"] not in ("chunk", "single", "complete")
            or not isinstance(cursor, dict) or set(cursor) != {"partitions", "chunk_start", "index"}
            or type(checkpoint["total_calls"]) is not int or checkpoint["total_calls"] < 0):
        raise ValueError("invalid checkpoint")
    target = Observation(True, signature["failure_class"], signature["first_divergence"])
    if (not _valid_observation(target) or target.failure_class is None or target.first_divergence is None
            or signature["sha256"] != _signature(target)["sha256"]
            or any(type(item) is not int or item < 0 or item >= len(units) for item in indices)
            or indices != sorted(set(indices))
            or any(type(cursor[key]) is not int or cursor[key] < 0 for key in cursor)
            or cursor["partitions"] < 2):
        raise ValueError("invalid checkpoint")
    return list(indices), target, checkpoint["phase"], cursor["partitions"], cursor["chunk_start"], cursor["index"], checkpoint["total_calls"]


def reduce_recipe(units: list[str], oracle: Callable[[list[str]], Observation], *, budget: int = 100,
                  repetitions: int = 2, checkpoint: dict | None = None) -> dict:
    """Return a candidate and a JSON-serializable continuation checkpoint.

    Resume never treats checkpoint observations as evidence: it first repeats the
    original baseline and retained candidate against the current oracle.
    """
    if (type(units) is not list or not units or len(units) > 4096
            or any(type(item) is not str or not item or len(item) > 256
                   or any(0xD800 <= ord(c) <= 0xDFFF for c in item) for item in units)
            or type(budget) is not int or not 2 <= budget <= 100000
            or type(repetitions) is not int or not 2 <= repetitions <= 10
            or budget < repetitions or not callable(oracle)):
        raise ValueError("invalid reduction input")
    trace: list[dict] = []
    run_calls = 0

    class Exhausted(Exception):
        pass

    class TraceFull(Exception):
        pass

    def observe(indices: list[int], target: Observation | None = None) -> Observation | None:
        nonlocal run_calls
        if run_calls + repetitions > budget:
            raise Exhausted
        if len(trace) >= MAX_TRACE_ENTRIES:
            raise TraceFull
        observed = []
        for _ in range(repetitions):
            run_calls += 1
            value = oracle([units[item] for item in indices])
            if not _valid_observation(value):
                raise ValueError("invalid oracle observation")
            observed.append(value)
        stable = all(value == observed[0] for value in observed)
        if target is None:
            value = observed[0]
            if not stable or not value.valid or value.failure_class is None or value.first_divergence is None:
                raise ValueError("original failure is not reproducible")
            target, preserved = value, True
        else:
            preserved = stable and observed[0] == target
        trace.append({"candidate_indices_sha256": _digest(indices), "retained_count": len(indices), "preserved": preserved,
                      "observations": [{"valid": value.valid, "signature_sha256": _signature(value)["sha256"]} for value in observed],
                      "valid_observations": sum(value.valid for value in observed), "calls": repetitions})
        return observed[0] if preserved else None

    total_prior = 0
    if checkpoint is None:
        current, phase, partitions, chunk_start, index = list(range(len(units))), "chunk", 2, 0, 0
        target = observe(current)
    else:
        if budget < repetitions * 2:
            raise ValueError("checkpoint revalidation exceeds budget")
        current, target, phase, partitions, chunk_start, index, total_prior = _resume(checkpoint, units)
        if observe(list(range(len(units))), target) != target:
            raise ValueError("checkpoint baseline drift")
        if observe(current, target) != target:
            raise ValueError("checkpoint retained candidate drift")
        # A stored chunk cursor is only an optimization hint. Fresh single-item
        # deletion checks are required before a minimality claim, even for complete.
        phase, index = "single", 0
    minimality, reason = "NOT_ESTABLISHED", "BUDGET_EXHAUSTED"
    try:
        while phase != "complete":
            if phase == "chunk":
                if len(current) < 2:
                    phase, index = "single", 0
                    continue
                partitions = min(max(2, partitions), len(current))
                size = (len(current) + partitions - 1) // partitions
                if chunk_start >= len(current):
                    if partitions >= len(current):
                        phase, index = "single", 0
                    else:
                        partitions, chunk_start = min(len(current), partitions * 2), 0
                    continue
                candidate = current[:chunk_start] + current[chunk_start + size:]
                if observe(candidate, target) == target:
                    current, partitions, chunk_start = candidate, max(2, partitions - 1), 0
                else:
                    chunk_start += size
            else:
                if index >= len(current):
                    phase, minimality, reason = "complete", "DELETION_1_MINIMAL_OBSERVED", "COMPLETED"
                    continue
                candidate = current[:index] + current[index + 1:]
                if observe(candidate, target) == target:
                    current, index = candidate, 0
                else:
                    index += 1
    except Exhausted:
        pass
    except TraceFull:
        reason = "TRACE_CAP"
    total_calls = total_prior + run_calls
    result = {"format": "plcman.gx-re-lab.reduction", "version": 1, "decision": "RECIPE_CANDIDATE", "lifecycle": "NOT_RUN",
              "reason": reason, "minimality": minimality, "original_count": len(units), "retained_indices": current,
              "input_units_sha256": _digest(units), "baseline_signature": _signature(target), "oracle_calls": run_calls,
              "reported_total_oracle_calls": total_calls, "run_oracle_calls": run_calls, "budget": budget, "budget_scope": "PER_RUN",
              "prior_reported_oracle_calls": total_prior,
              "repetitions": repetitions, "trace_entry_cap": MAX_TRACE_ENTRIES,
              "trace": trace}
    result["checkpoint"] = _checkpoint(units, target, current, phase, partitions, chunk_start, index, total_calls)
    return result
