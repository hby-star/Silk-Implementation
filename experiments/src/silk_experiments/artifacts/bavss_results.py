from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from ..registry import ExperimentKind
from .common import sha256_file, write_json_new

EVENT_SCHEMA = "silk-experiment-v2"
IMPLEMENTATIONS = ("silk-bavss-po", "rondo-bavss-po")
PHASES = ("share", "verify", "reconstruct", "reconstruct-core")
TIMING_SEMANTICS = "single-process-aggregate-workload-v1"
SILK_PROFILE = (
    "silk-bavss"
)
SILK_WIRE_PROFILE = "dense-response-digest-compact-item-v2"
RONDO_PROFILE = "breeze-bavss"


class BavssDerivationError(ValueError):
    """Raw bAVSS phase events cannot be deterministically validated."""


@dataclass(frozen=True)
class EventValidation:
    line: int
    event_valid: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class BavssPhaseResult:
    run_id: str
    sample_id: str
    sample_role: str
    sample: int
    seed: int
    implementation: str
    implementation_profile: str
    execution_order_index: int
    phase: str
    opened_index: int | None
    timing_semantics: str
    wall_ns: int
    process_cpu_ns: int
    protocol_wire_bytes_sent: int
    payload_bytes_sent: int
    messages_sent: int
    rss_peak_bytes: int
    protocol_storage_bytes: int
    raw_event_line: int
    raw_events_sha256: str


@dataclass(frozen=True)
class BavssDerivationResult:
    run_valid: bool
    phase_results: tuple[BavssPhaseResult, ...]
    validation: tuple[EventValidation, ...]
    run_reasons: tuple[str, ...]


def derive_bavss_results(raw_run: Path, processed_run: Path) -> BavssDerivationResult:
    raw_run = raw_run.resolve()
    processed_run = processed_run.resolve()
    manifest_path = raw_run / "manifest.toml"
    events_path = raw_run / "events.jsonl"
    manifest = _read_manifest(manifest_path)
    metadata = _validate_manifest(manifest)
    checksum_reasons = _validate_checksums(raw_run)
    events_digest = sha256_file(events_path)
    parsed, validations = _parse_events(events_path, metadata, events_digest)
    run_reasons = [
        *checksum_reasons,
        *_coverage_reasons(parsed, metadata["samples"], metadata["batch_size"]),
    ]
    if any(not validation.event_valid for validation in validations):
        run_reasons.append("one or more raw events are invalid")
    run_valid = not run_reasons

    processed_run.mkdir(parents=True, exist_ok=True)
    _write_phase_results(processed_run / "phase-results.csv", parsed)
    write_json_new(
        processed_run / "event-validation.json",
        {
            "schema_id": "silk-bavss-event-validation/v1",
            "run_id": metadata["run_id"],
            "experiment_id": ExperimentKind.BAVSS_PHASE_COST.value,
            "run_valid": run_valid,
            "run_reasons": run_reasons,
            "events": [asdict(item) for item in validations],
        },
    )
    write_json_new(
        processed_run / "derivation-manifest.json",
        {
            "schema_id": "silk-result-derivation/v1",
            "run_id": metadata["run_id"],
            "algorithm": "bavss-event-log-to-phase-csv/v1",
            "input_sha256": {
                "manifest.toml": sha256_file(manifest_path),
                "events.jsonl": events_digest,
                "checksums.sha256": sha256_file(raw_run / "checksums.sha256"),
            },
            "outputs": ["phase-results.csv", "event-validation.json"],
        },
    )
    return BavssDerivationResult(
        run_valid,
        tuple(parsed),
        tuple(validations),
        tuple(run_reasons),
    )


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise BavssDerivationError(f"cannot read manifest.toml: {error}") from error
    if not isinstance(value, dict):
        raise BavssDerivationError("manifest.toml is not a table")
    return value


def _validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != EVENT_SCHEMA:
        raise BavssDerivationError("unsupported bAVSS manifest schema")
    if manifest.get("experiment_id") != ExperimentKind.BAVSS_PHASE_COST.value:
        raise BavssDerivationError("manifest is not bavss-phase-cost")
    if manifest.get("executor") not in {"docker-aggregate", "aws-aggregate"}:
        raise BavssDerivationError("bavss-phase-cost requires an aggregate executor")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise BavssDerivationError("manifest run_id is missing")
    parameters = manifest.get("resolved_parameters")
    if not isinstance(parameters, dict):
        raise BavssDerivationError("manifest resolved_parameters is missing")
    if manifest.get("executor") == "aws-aggregate" and (
        parameters.get("resource_profile") != "aws-t3a-medium-aggregate-v1"
        or not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("inventory_sha256", "")))
    ):
        raise BavssDerivationError("AWS aggregate manifest lacks bound native environment")
    n = _parameter_int(parameters, "n")
    t = _parameter_int(parameters, "t")
    batch_size = _parameter_int(parameters, "epoch_slots")
    samples = _parameter_int(parameters, "samples")
    sample_role = parameters.get("sample_role")
    if sample_role not in ("smoke", "warmup", "measured"):
        raise BavssDerivationError("bAVSS sample_role must be smoke, warmup, or measured")
    if n <= 0 or t < 0 or n != 3 * t + 1 or batch_size <= 0 or samples <= 0:
        raise BavssDerivationError("bAVSS manifest contains invalid n/t/B/samples")
    for field, expected in (
        ("protocol_revision", "silk"),
        ("silk_profile", SILK_PROFILE),
        ("silk_release_profile", "not-applicable"),
        ("silk_wire_profile", SILK_WIRE_PROFILE),
        ("silk_validation_profile", "per-dealer-validation-statement-v2"),
        ("silk_response_repetitions", "1"),
        (
            "silk_reconstruction_backend",
            "compact-adaptive-multipoint",
        ),
        (
            "silk_certificate_encoding",
            "not-applicable",
        ),
        ("rondo_breeze_profile", RONDO_PROFILE),
        ("rondo_bft_profile", "not-applicable"),
        ("rondo_reconstruction_profile", "compact-single-dealer-set"),
    ):
        if parameters.get(field) != expected:
            raise BavssDerivationError(f"bAVSS manifest {field} is not the current profile")
    if parameters.get("timing_semantics") != TIMING_SEMANTICS:
        raise BavssDerivationError("bAVSS timing semantics is not aggregate workload")
    git_commit = manifest.get("git_commit")
    if not isinstance(git_commit, str) or not git_commit:
        raise BavssDerivationError("bAVSS manifest git_commit is missing")
    source_fingerprint = parameters.get("source_fingerprint")
    if not isinstance(source_fingerprint, str) or not re.fullmatch(
        r"[0-9a-f]{64}", source_fingerprint
    ):
        raise BavssDerivationError("bAVSS manifest source_fingerprint is malformed")
    git_dirty = parameters.get("git_dirty")
    if git_dirty not in {"true", "false"}:
        raise BavssDerivationError("bAVSS manifest git_dirty is invalid")
    if sample_role == "measured" and git_dirty != "false":
        raise BavssDerivationError("measured bAVSS runs require a clean source revision")
    seed = manifest.get("deterministic_seed")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise BavssDerivationError("manifest deterministic_seed is invalid")
    return {
        "run_id": run_id,
        "sample_role": sample_role,
        "n": n,
        "t": t,
        "batch_size": batch_size,
        "samples": samples,
        "seed": seed,
        "git_commit": git_commit,
        "protocol_revision": parameters["protocol_revision"],
        "source_fingerprint": source_fingerprint,
        "build_profile": manifest.get("build_profile"),
    }


def _parameter_int(parameters: dict[str, Any], field: str) -> int:
    value = parameters.get(field)
    if not isinstance(value, str):
        raise BavssDerivationError(f"manifest parameter {field} is missing")
    try:
        parsed = int(value)
    except ValueError as error:
        raise BavssDerivationError(f"manifest parameter {field} is invalid") from error
    if parsed < 0:
        raise BavssDerivationError(f"manifest parameter {field} is negative")
    return parsed


def _validate_checksums(raw_run: Path) -> list[str]:
    checksum_path = raw_run / "checksums.sha256"
    if not checksum_path.is_file():
        return ["checksums.sha256 is missing"]
    reasons: list[str] = []
    declared: dict[str, str] = {}
    for line_number, line in enumerate(
        checksum_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        parts = line.split()
        if len(parts) != 2:
            reasons.append(f"checksums line {line_number} is malformed")
            continue
        digest, relative = parts
        if relative in declared:
            reasons.append(f"checksums contains duplicate path {relative}")
            continue
        declared[relative] = digest
    for relative in ("manifest.toml", "events.jsonl", "samples.csv", "complete"):
        path = raw_run / relative
        if relative not in declared:
            reasons.append(f"checksums does not cover {relative}")
        elif not path.is_file():
            reasons.append(f"checksummed artifact is missing: {relative}")
        elif sha256_file(path) != declared[relative]:
            reasons.append(f"checksum mismatch: {relative}")
    return reasons


def _parse_events(
    path: Path,
    metadata: dict[str, Any],
    events_digest: str,
) -> tuple[list[BavssPhaseResult], list[EventValidation]]:
    results: list[BavssPhaseResult] = []
    validations: list[EventValidation] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        reasons: list[str] = []
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            validations.append(EventValidation(line_number, False, (f"invalid JSON: {error.msg}",)))
            continue
        if not isinstance(event, dict):
            validations.append(EventValidation(line_number, False, ("event is not an object",)))
            continue
        _validate_event(event, metadata, reasons)
        validations.append(EventValidation(line_number, not reasons, tuple(reasons)))
        if not reasons:
            results.append(_phase_result(event, line_number, events_digest))
    if not validations:
        validations.append(EventValidation(0, False, ("events.jsonl is empty",)))
    return results, validations


def _validate_event(
    event: dict[str, Any],
    metadata: dict[str, Any],
    reasons: list[str],
) -> None:
    for field, expected in (
        ("schema_version", EVENT_SCHEMA),
        ("run_id", metadata["run_id"]),
        ("experiment_id", ExperimentKind.BAVSS_PHASE_COST.value),
        ("sample_role", metadata["sample_role"]),
        ("n", metadata["n"]),
        ("t", metadata["t"]),
        ("epoch_slots", metadata["batch_size"]),
        ("git_commit", metadata["git_commit"]),
        ("protocol_revision", metadata["protocol_revision"]),
        ("build_source_fingerprint", metadata["source_fingerprint"]),
        ("build_profile", metadata["build_profile"]),
    ):
        if event.get(field) != expected:
            reasons.append(f"{field} mismatch")
    if event.get("implementation") not in IMPLEMENTATIONS:
        reasons.append("unknown implementation")
    else:
        implementation = str(event["implementation"])
        expected_profile = {
            "silk-bavss-po": SILK_PROFILE,
            "rondo-bavss-po": RONDO_PROFILE,
        }[implementation]
        if event.get("profile") != expected_profile:
            reasons.append("implementation profile mismatch")
        expected_backend = {
            "silk-bavss-po": (
                "compact-adaptive-multipoint"
            ),
            "rondo-bavss-po": "breeze-aggregate-lagrange",
        }[implementation]
        if event.get("actual_reconstruction_backend") != expected_backend:
            reasons.append("reconstruction backend mismatch")
        expected_certificate = {
            "silk-bavss-po": "not-applicable",
            "rondo-bavss-po": "breeze",
        }[implementation]
        if event.get("certificate_encoding") != expected_certificate:
            reasons.append("certificate encoding mismatch")
    if event.get("phase") not in PHASES:
        reasons.append("unknown phase")
    if event.get("measured_or_modelled") != "measured":
        reasons.append("event is not measured")
    if event.get("timing_semantics") != TIMING_SEMANTICS:
        reasons.append("event timing semantics is not aggregate workload")
    if event.get("critical_path") is not False or event.get("success") is not True:
        reasons.append("event is not a successful aggregate-workload observation")
    if event.get("wire_accounting_mode") != "sender-side-framed-node-request/v1":
        reasons.append("unexpected wire accounting mode")
    sample = _event_nonnegative_int(event, "sample", reasons)
    seed = _event_nonnegative_int(event, "seed", reasons)
    order = _event_nonnegative_int(event, "execution_order_index", reasons)
    if sample is not None and sample >= metadata["samples"]:
        reasons.append("sample is outside manifest range")
    if sample is not None and seed is not None and seed != metadata["seed"] + sample:
        reasons.append("sample seed mismatch")
    if order is not None and order not in (0, 1):
        reasons.append("execution order must be 0 or 1")
    slot = event.get("slot")
    if event.get("phase") in {"reconstruct", "reconstruct-core"}:
        if isinstance(slot, bool) or not isinstance(slot, int):
            reasons.append("reconstruct event has no opened index")
        elif not 0 <= slot < metadata["batch_size"]:
            reasons.append("reconstruct opened index is outside the batch")
    elif slot is not None:
        reasons.append("non-reconstruct event declares an opened index")
    numeric_values: dict[str, int | None] = {}
    for field in (
        "wall_ns",
        "cpu_ns",
        "actual_wire_bytes",
        "bytes_sent",
        "message_count",
        "rss_peak_bytes",
        "protocol_storage_bytes",
    ):
        value = _event_nonnegative_int(event, field, reasons)
        numeric_values[field] = value
        if field == "wall_ns" and value == 0:
            reasons.append(f"{field} must be positive")
    if event.get("phase") == "reconstruct-core":
        for field in ("actual_wire_bytes", "bytes_sent", "message_count"):
            if numeric_values[field] not in (None, 0):
                reasons.append(f"reconstruct-core {field} must be zero")
    elif numeric_values["actual_wire_bytes"] == 0:
        reasons.append("actual_wire_bytes must be positive")


def _event_nonnegative_int(
    event: dict[str, Any],
    field: str,
    reasons: list[str],
) -> int | None:
    value = event.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        reasons.append(f"{field} is missing or invalid")
        return None
    if value < 0:
        reasons.append(f"{field} is negative")
        return None
    return value


def _phase_result(
    event: dict[str, Any],
    line_number: int,
    events_digest: str,
) -> BavssPhaseResult:
    sample = int(event["sample"])
    return BavssPhaseResult(
        run_id=str(event["run_id"]),
        sample_id=f"sample-{sample:04}",
        sample_role=str(event["sample_role"]),
        sample=sample,
        seed=int(event["seed"]),
        implementation=str(event["implementation"]),
        implementation_profile=str(event["profile"]),
        execution_order_index=int(event["execution_order_index"]),
        phase=str(event["phase"]),
        opened_index=int(event["slot"]) if event.get("slot") is not None else None,
        timing_semantics=str(event["timing_semantics"]),
        wall_ns=int(event["wall_ns"]),
        process_cpu_ns=int(event["cpu_ns"]),
        protocol_wire_bytes_sent=int(event["actual_wire_bytes"]),
        payload_bytes_sent=int(event["bytes_sent"]),
        messages_sent=int(event["message_count"]),
        rss_peak_bytes=int(event["rss_peak_bytes"]),
        protocol_storage_bytes=int(event["protocol_storage_bytes"]),
        raw_event_line=line_number,
        raw_events_sha256=events_digest,
    )


def _coverage_reasons(
    results: list[BavssPhaseResult],
    samples: int,
    batch_size: int,
) -> list[str]:
    reasons: list[str] = []
    expected: set[tuple[int, str, str, int | None]] = {
        (sample, implementation, phase, None)
        for sample in range(samples)
        for implementation in IMPLEMENTATIONS
        for phase in ("share", "verify")
    }
    expected |= {
        (sample, implementation, phase, index)
        for sample in range(samples)
        for implementation in IMPLEMENTATIONS
        for phase in ("reconstruct", "reconstruct-core")
        for index in range(batch_size)
    }
    observed = [
        (item.sample, item.implementation, item.phase, item.opened_index) for item in results
    ]
    observed_set = set(observed)
    if len(observed) != len(observed_set):
        reasons.append("duplicate implementation/sample/phase events")
    missing = sorted(expected - observed_set)
    unexpected = sorted(observed_set - expected)
    if missing:
        reasons.append(f"missing phase events: {missing}")
    if unexpected:
        reasons.append(f"unexpected phase events: {unexpected}")
    for sample in range(samples):
        sample_rows = [item for item in results if item.sample == sample]
        orders = {
            item.implementation: item.execution_order_index
            for item in sample_rows
            if item.phase == "share"
        }
        if set(orders) == set(IMPLEMENTATIONS) and set(orders.values()) != {0, 1}:
            reasons.append(f"sample {sample}: implementations do not have distinct execution order")
    return reasons


PHASE_FIELDS = tuple(BavssPhaseResult.__dataclass_fields__)


def _write_phase_results(path: Path, results: list[BavssPhaseResult]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PHASE_FIELDS, lineterminator="\n")
        writer.writeheader()
        for result in sorted(
            results,
            key=lambda item: (
                item.sample,
                item.execution_order_index,
                PHASES.index(item.phase),
                item.opened_index if item.opened_index is not None else -1,
            ),
        ):
            writer.writerow(asdict(result))
