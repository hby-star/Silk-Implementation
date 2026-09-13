from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from ..registry import BeaconImplementation, ExperimentKind
from .common import sha256_file, write_json_new

NODE_LOG = re.compile(r"^node-(?P<node>[0-9]+)\.jsonl$")
LOG_SCHEMA = "silk-node-log/v5"
TRANSPORT_PROFILES = frozenset({"persistent-peer-tcp"})
HEADLINE_PHASES = (
    "commitment",
    "agreement",
    "quorum_release",
    "reconstruction",
    "framework_overhead",
)


class ResultDerivationError(ValueError):
    """Node logs do not form a valid run."""


@dataclass(frozen=True)
class NodeValidation:
    node_id: int
    path: str | None
    log_valid: bool
    reasons: tuple[str, ...]
    sha256: str | None


@dataclass(frozen=True)
class NodeResult:
    run_id: str
    sample_id: str
    implementation: str
    node_id: int
    role: str
    protocol_status: str
    node_log_sha256: str
    measurement_wall_ns: int
    output_count: int
    commitment_wall_ns: int
    agreement_wall_ns: int
    quorum_release_wall_ns: int
    reconstruction_wall_ns: int
    framework_overhead_wall_ns: int
    process_cpu_total_ns: int
    rss_peak_bytes: int
    storage_delta_bytes: int
    protocol_wire_bytes_sent: int
    messages_sent: int


@dataclass(frozen=True)
class ParsedNode:
    validation: NodeValidation
    result: NodeResult | None
    events: tuple[dict[str, Any], ...]
    outputs: frozenset[tuple[int, int, int, str]]


@dataclass(frozen=True)
class DerivationResult:
    run_valid: bool
    node_results: tuple[NodeResult, ...]
    validation: tuple[NodeValidation, ...]
    run_results_rows: int


def derive_beacon_results(raw_run: Path, processed_run: Path) -> DerivationResult:
    raw_run = raw_run.resolve()
    processed_run = processed_run.resolve()
    manifest_path = raw_run / "run-manifest.json"
    manifest = _read_json_object(manifest_path)
    _validate_manifest(manifest)
    run_id = str(manifest["run_id"])
    expected_nodes = tuple(int(value) for value in manifest["expected_node_ids"])
    discovered = _discover_node_logs(raw_run)

    parsed: dict[int, ParsedNode] = {}
    for node_id, path in discovered.items():
        parsed[node_id] = _parse_node_log(path, node_id, manifest)

    validations: list[NodeValidation] = []
    node_results: list[NodeResult] = []
    for node_id in expected_nodes:
        node = parsed.get(node_id)
        if node is None:
            validations.append(NodeValidation(node_id, None, False, ("missing node log",), None))
            continue
        validations.append(node.validation)
        if node.result is not None:
            node_results.append(node.result)

    unexpected = sorted(set(discovered) - set(expected_nodes))
    for node_id in unexpected:
        node = parsed[node_id]
        reasons = (*node.validation.reasons, "node is not declared by manifest")
        validations.append(
            NodeValidation(
                node_id,
                node.validation.path,
                False,
                reasons,
                node.validation.sha256,
            )
        )

    run_reasons = _run_validation_reasons(manifest, expected_nodes, parsed)
    run_valid = not run_reasons
    processed_run.mkdir(parents=True, exist_ok=True)
    _write_node_results(processed_run / "node-results.csv", node_results)
    run_rows = _write_run_results(
        processed_run / "run-results.csv",
        manifest,
        tuple(node_results),
        parsed,
        run_valid,
    )
    write_json_new(
        processed_run / "node-validation.json",
        {
            "schema_id": "silk-node-validation/v1",
            "run_id": run_id,
            "experiment_id": ExperimentKind.BEACON_PERFORMANCE.value,
            "implementation": manifest["implementation"],
            "run_valid": run_valid,
            "run_reasons": run_reasons,
            "nodes": [asdict(item) for item in validations],
        },
    )
    input_digests = {
        str(path.relative_to(raw_run)).replace("\\", "/"): sha256_file(path)
        for path in sorted(discovered.values())
    }
    input_digests["run-manifest.json"] = sha256_file(manifest_path)
    for summary in sorted((raw_run / "node-summaries").glob("node-*.json")):
        input_digests[summary.relative_to(raw_run).as_posix()] = sha256_file(summary)
    write_json_new(
        processed_run / "derivation-manifest.json",
        {
            "schema_id": "silk-result-derivation/v1",
            "run_id": run_id,
            "implementation": manifest["implementation"],
            "algorithm": "beacon-node-log-to-csv/v2",
            "input_sha256": input_digests,
            "outputs": ["node-results.csv", "run-results.csv", "node-validation.json"],
        },
    )
    return DerivationResult(run_valid, tuple(node_results), tuple(validations), run_rows)


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_id") != "silk-run-manifest/v1":
        raise ResultDerivationError("unsupported run manifest schema")
    if manifest.get("experiment_id") != ExperimentKind.BEACON_PERFORMANCE.value:
        raise ResultDerivationError("run manifest is not beacon-performance")
    if manifest.get("completion_policy") != "all-participants-durable":
        raise ResultDerivationError("unsupported completion policy")
    try:
        BeaconImplementation.parse(str(manifest.get("implementation", "")))
    except ValueError as error:
        raise ResultDerivationError(str(error)) from error
    for field in (
        "run_id",
        "sample_id",
        "sample_role",
        "executor",
        "network_scenario",
        "resource_profile",
        "protocol_revision",
        "git_commit",
        "source_fingerprint",
        "wire_accounting_mode",
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ResultDerivationError(f"manifest {field} must be a non-empty string")
    if manifest["protocol_revision"] != "silk":
        raise ResultDerivationError("manifest protocol_revision is not current")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest["source_fingerprint"])):
        raise ResultDerivationError("manifest source_fingerprint is malformed")
    git_dirty = manifest.get("git_dirty")
    if not isinstance(git_dirty, bool):
        raise ResultDerivationError("manifest git_dirty must be a boolean")
    if manifest["sample_role"] == "measured" and git_dirty:
        raise ResultDerivationError("measured runs require a clean source revision")
    expected = manifest.get("expected_node_ids")
    if not isinstance(expected, list) or not expected:
        raise ResultDerivationError("manifest must declare expected_node_ids")
    node_ids = [_manifest_int(value, "expected_node_ids") for value in expected]
    if len(node_ids) != len(set(node_ids)) or sorted(node_ids) != list(range(len(node_ids))):
        raise ResultDerivationError("expected_node_ids must be contiguous and unique from zero")
    n = _manifest_int(manifest.get("n"), "n")
    if n != len(node_ids):
        raise ResultDerivationError("manifest n does not match expected_node_ids")
    t = _manifest_int(manifest.get("t"), "t")
    if n <= 0 or t < 0 or 3 * t >= n:
        raise ResultDerivationError("manifest parameters violate n >= 3t+1")
    batch_size = _manifest_int(manifest.get("batch_size"), "batch_size")
    if batch_size <= 0:
        raise ResultDerivationError("manifest batch_size must be positive")
    samples = _manifest_int(manifest.get("samples"), "samples")
    if samples <= 0:
        raise ResultDerivationError("manifest samples must be positive")
    epochs = _manifest_int(manifest.get("epochs"), "epochs")
    if epochs != samples:
        raise ResultDerivationError("manifest epochs must match samples")
    expected_output_count = _manifest_int(
        manifest.get("expected_output_count"), "expected_output_count"
    )
    if expected_output_count <= 0:
        raise ResultDerivationError("manifest expected_output_count must be positive")
    if expected_output_count != batch_size * samples:
        raise ResultDerivationError("manifest expected_output_count must match batch_size*samples")
    if _manifest_int(manifest.get("seed"), "seed") < 0:
        raise ResultDerivationError("manifest seed must be non-negative")
    clock_mode = manifest.get("clock_aggregation_mode", "synchronized-unix")
    if clock_mode not in ("synchronized-unix", "barrier-aligned-monotonic"):
        raise ResultDerivationError("manifest clock_aggregation_mode is unsupported")
    if clock_mode == "synchronized-unix" and not bool(manifest.get("clock_comparable", False)):
        raise ResultDerivationError("synchronized-unix throughput requires comparable clocks")


def _discover_node_logs(raw_run: Path) -> dict[int, Path]:
    discovered: dict[int, Path] = {}
    for path in raw_run.rglob("node-*.jsonl"):
        match = NODE_LOG.fullmatch(path.name)
        if match is None:
            continue
        node_id = int(match.group("node"))
        if node_id in discovered:
            raise ResultDerivationError(f"duplicate node log for node {node_id}")
        discovered[node_id] = path
    return discovered


def _parse_node_log(
    path: Path,
    node_id: int,
    manifest: dict[str, Any],
) -> ParsedNode:
    reasons: list[str] = []
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            reasons.append(f"line {line_number}: invalid JSON: {error.msg}")
            continue
        if not isinstance(value, dict):
            reasons.append(f"line {line_number}: event is not an object")
            continue
        events.append(value)
    if not events:
        reasons.append("node log is empty")

    for sequence, event in enumerate(events):
        prefix = f"event {sequence}"
        if event.get("schema_version") != LOG_SCHEMA:
            reasons.append(f"{prefix}: unsupported schema")
        if event.get("run_id") != manifest["run_id"]:
            reasons.append(f"{prefix}: run_id mismatch")
        if event.get("experiment_id") != ExperimentKind.BEACON_PERFORMANCE.value:
            reasons.append(f"{prefix}: experiment_id mismatch")
        event_node_id = _event_int(prefix, event, "node_id", reasons)
        if event_node_id is not None and event_node_id != node_id:
            reasons.append(f"{prefix}: node_id mismatch")
        event_sequence = _event_int(prefix, event, "node_sequence", reasons)
        if event_sequence is not None and event_sequence != sequence:
            reasons.append(f"{prefix}: node_sequence is not contiguous")
        if event.get("sample_role") != manifest["sample_role"]:
            reasons.append(f"{prefix}: sample_role mismatch")
        for field, manifest_field in (
            ("protocol_revision", "protocol_revision"),
            ("build_git_commit", "git_commit"),
            ("build_source_fingerprint", "source_fingerprint"),
            ("executor", "executor"),
            ("network_scenario", "network_scenario"),
            ("resource_profile", "resource_profile"),
            ("wire_accounting_mode", "wire_accounting_mode"),
        ):
            if event.get(field) != manifest[manifest_field]:
                reasons.append(f"{prefix}: {field} mismatch")
        for field, expected in (
            ("role", "replica"),
            ("clock_source", "process-relative-monotonic-plus-system-time-unix-ns"),
            ("status", "completed"),
        ):
            if event.get(field) != expected:
                reasons.append(f"{prefix}: {field} mismatch")
        if event.get("transport_profile") not in TRANSPORT_PROFILES:
            reasons.append(f"{prefix}: transport_profile mismatch")
        for field in ("implementation", "implementation_profile"):
            value = event.get(field)
            if not isinstance(value, str) or not value:
                reasons.append(f"{prefix}: missing {field}")
        if event.get("implementation") != manifest["implementation"]:
            reasons.append(f"{prefix}: implementation mismatch")
        expected_profile = {
            BeaconImplementation.SILK.value: (
                "silk-beacon"
            ),
            BeaconImplementation.RONDO.value: (
                "rondo-beacon"
            ),
            BeaconImplementation.SPURT.value: (
                "spurt-beacon"
            ),
        }.get(str(event.get("implementation")))
        if expected_profile is None or event.get("implementation_profile") != expected_profile:
            reasons.append(f"{prefix}: implementation_profile mismatch")
        expected_backend = {
            BeaconImplementation.SILK.value: (
                "compact-holder-set-adaptive-multipoint"
            ),
            BeaconImplementation.RONDO.value: (
                "breeze-compact-certified-holder-quorum-verified-dealer-row-fallback-v5"
            ),
            BeaconImplementation.SPURT.value: "dbdh-pairing-lagrange-v1",
        }.get(str(event.get("implementation")))
        if (
            expected_backend is not None
            and event.get("actual_reconstruction_backend") != expected_backend
        ):
            reasons.append(f"{prefix}: reconstruction backend mismatch")
        expected_certificate = {
            BeaconImplementation.SILK.value: ("matching-mldsa65-release-signatures-v3"),
            BeaconImplementation.RONDO.value: ("breeze-qc-plus-four-phase-decision-proof-v1"),
            BeaconImplementation.SPURT.value: "t-plus-one-signed-beacon-messages-v1",
        }.get(str(event.get("implementation")))
        if (
            expected_certificate is not None
            and event.get("certificate_encoding") != expected_certificate
        ):
            reasons.append(f"{prefix}: certificate encoding mismatch")
        if event.get("implementation") == BeaconImplementation.RONDO.value:
            for field, expected in (
                (
                    "rondo_breeze_profile",
                    "breeze-bavss",
                ),
                (
                    "rondo_bft_profile",
                    "rondo-hotstuff-four-phase",
                ),
                (
                    "rondo_bft_signature_profile",
                    "independent-bls-fast-aggregate-signature-with-signer-identities-v1",
                ),
            ):
                if event.get(field) != expected:
                    reasons.append(f"{prefix}: {field} mismatch")
        if event.get("implementation") == BeaconImplementation.SPURT.value:
            if event.get("spurt_fidelity") != "F2":
                reasons.append(f"{prefix}: Spurt events require F2 fidelity")
            if event.get("coverage") != "fixed-committee-honest-leader-normal-path-only":
                reasons.append(f"{prefix}: Spurt coverage mismatch")
            if event.get("claim_scope") != "normal-path-performance":
                reasons.append(f"{prefix}: Spurt claim_scope mismatch")
        if event.get(
            "implementation"
        ) == BeaconImplementation.SILK.value and "standalone-certificate" in str(
            event.get("phase", "")
        ):
            reasons.append(f"{prefix}: standalone certificate work is outside Matrix B")
        if event.get("event_kind") not in ("phase_span", "beacon_output_durable"):
            reasons.append(f"{prefix}: unknown event_kind")
        if event.get("success") is not True:
            reasons.append(f"{prefix}: event is not successful")
        phase = event.get("headline_phase")
        if phase not in HEADLINE_PHASES:
            reasons.append(f"{prefix}: unknown headline_phase")
        for field, manifest_field in (
            ("n", "n"),
            ("t", "t"),
            ("epoch_slots", "batch_size"),
            ("seed", "seed"),
        ):
            parsed = _event_int(prefix, event, field, reasons)
            if parsed is not None and parsed != manifest[manifest_field]:
                reasons.append(f"{prefix}: {field} mismatch")
        event_sample = _event_int(prefix, event, "sample", reasons)
        event_epoch = _event_int(prefix, event, "epoch", reasons)
        if event_sample is not None:
            if event.get("sample_id") != f"sample-{event_sample:04}":
                reasons.append(f"{prefix}: sample_id mismatch")
            if event_sample >= int(manifest["samples"]):
                reasons.append(f"{prefix}: sample is outside manifest range")
            if event_epoch is not None and event_epoch != event_sample + 1:
                reasons.append(f"{prefix}: epoch does not match sample")
        if event.get("slot") is not None:
            event_slot = _event_int(prefix, event, "slot", reasons)
            if event_slot is not None and event_slot >= int(manifest["batch_size"]):
                reasons.append(f"{prefix}: slot is outside manifest range")
        _validate_time(prefix, event, reasons)
        _validate_nonnegative(
            prefix,
            event,
            (
                "process_cpu_ns",
                "rss_peak_bytes",
                "protocol_storage_bytes",
                "protocol_wire_bytes_sent",
                "protocol_wire_bytes_received",
                "messages_sent",
            ),
            reasons,
        )

    outputs_mutable: set[tuple[int, int, int, str]] = set()
    for sequence, event in enumerate(events):
        if event.get("event_kind") != "beacon_output_durable":
            continue
        prefix = f"event {sequence}"
        sample = _event_int(prefix, event, "sample", reasons)
        epoch = _event_int(prefix, event, "epoch", reasons)
        slot = _event_int(prefix, event, "slot", reasons)
        digest_value = event.get("output_digest")
        if digest_value is None:
            reasons.append(f"{prefix}: durable output has no output_digest")
        if event.get("output_kind") != "beacon-output":
            reasons.append(f"{prefix}: durable output has wrong output_kind")
        if event.get("headline_phase") != "reconstruction":
            reasons.append(f"{prefix}: durable output is not reconstruction")
        if (
            sample is not None
            and epoch is not None
            and slot is not None
            and digest_value is not None
        ):
            outputs_mutable.add((sample, epoch, slot, _stable_digest(digest_value)))
    outputs = frozenset(outputs_mutable)
    expected_outputs = int(manifest["expected_output_count"])
    if len(outputs) != expected_outputs:
        reasons.append(f"expected {expected_outputs} durable outputs, found {len(outputs)}")
    output_positions = {(sample, epoch, slot) for sample, epoch, slot, _ in outputs}
    expected_output_positions = {
        (sample, sample + 1, slot)
        for sample in range(int(manifest["samples"]))
        for slot in range(int(manifest["batch_size"]))
    }
    if output_positions != expected_output_positions:
        reasons.append("durable outputs do not cover every configured sample and slot exactly once")

    if manifest["implementation"] == BeaconImplementation.RONDO.value:
        required_bft_phases = (
            "rondo-bft-propose",
            "rondo-bft-prepare-vote",
            "rondo-bft-precommit",
            "rondo-bft-commit",
            "rondo-bft-decide",
        )
        for phase in required_bft_phases:
            phase_events = [event for event in events if event.get("phase") == phase]
            if len(phase_events) != expected_outputs:
                reasons.append(
                    f"Rondo phase {phase} expected {expected_outputs} events, "
                    f"found {len(phase_events)}"
                )
                continue
            positions = [
                (event.get("sample"), event.get("epoch"), event.get("slot"))
                for event in phase_events
            ]
            if len(set(positions)) != len(positions) or set(positions) != output_positions:
                reasons.append(f"Rondo phase {phase} does not cover every output exactly once")
        reconstruction_broadcasts = [
            event for event in events if event.get("phase") == "rondo-aggregate-share-broadcast"
        ]
        if len(reconstruction_broadcasts) != expected_outputs:
            reasons.append(
                "Rondo aggregate-share broadcast expected "
                f"{expected_outputs} events, found {len(reconstruction_broadcasts)}"
            )
        else:
            broadcast_positions = {
                (event.get("sample"), event.get("epoch"), event.get("slot"))
                for event in reconstruction_broadcasts
            }
            if broadcast_positions != output_positions:
                reasons.append(
                    "Rondo aggregate-share broadcast does not cover every output exactly once"
                )
        reconstruction_outputs = [
            event
            for event in events
            if event.get("phase") == "rondo-aggregate-verify-reconstruct-output-durable"
        ]
        if len(reconstruction_outputs) != expected_outputs:
            reasons.append(
                "Rondo durable reconstruction expected "
                f"{expected_outputs} events, found {len(reconstruction_outputs)}"
            )
        batch_size = int(manifest["batch_size"])
        for sample in range(int(manifest["samples"])):
            actual_schedule = [
                (str(event.get("phase")), event.get("slot"))
                for event in sorted(
                    (
                        event
                        for event in events
                        if event.get("sample") == sample
                        and str(event.get("phase", "")).startswith("rondo-bft-")
                        and event.get("phase") != "rondo-bft-retention-gc"
                    ),
                    key=lambda event: int(event["node_sequence"]),
                )
            ]
            expected_schedule: list[tuple[str, int | None]] = []
            for wave in range(batch_size + 3):
                expected_schedule.append(("rondo-bft-pipeline-dispatch", None))
                for phase, offset in (
                    ("rondo-bft-decide", 3),
                    ("rondo-bft-commit", 2),
                    ("rondo-bft-precommit", 1),
                    ("rondo-bft-propose", 0),
                    ("rondo-bft-prepare-vote", 0),
                ):
                    slot = wave - offset
                    if 0 <= slot < batch_size:
                        expected_schedule.append((phase, slot))
            if actual_schedule != expected_schedule:
                reasons.append(
                    f"Rondo sample {sample} does not follow the pipelined four-phase wave schedule"
                )
            sample_events = [event for event in events if event.get("sample") == sample]
            by_phase_slot = {
                (str(event.get("phase")), event.get("slot")): int(event["node_sequence"])
                for event in sample_events
            }
            for slot in range(batch_size):
                decide_sequence = by_phase_slot.get(("rondo-bft-decide", slot))
                broadcast_sequence = by_phase_slot.get(("rondo-aggregate-share-broadcast", slot))
                durable_sequence = by_phase_slot.get(
                    ("rondo-aggregate-verify-reconstruct-output-durable", slot)
                )
                if (
                    decide_sequence is None
                    or broadcast_sequence is None
                    or durable_sequence is None
                ):
                    continue
                if not decide_sequence < broadcast_sequence < durable_sequence:
                    reasons.append(
                        f"Rondo sample {sample} slot {slot} does not follow "
                        "decide -> aggregate broadcast -> durable output order"
                    )
            last_bft_sequence = max(
                (
                    int(event["node_sequence"])
                    for event in sample_events
                    if str(event.get("phase", "")).startswith("rondo-bft-")
                    and event.get("phase") != "rondo-bft-retention-gc"
                ),
                default=-1,
            )
            non_tail_count = max(0, batch_size - 1)
            non_tail_slots = range(non_tail_count)
            pipelined_outputs = sum(
                1
                for slot in non_tail_slots
                if by_phase_slot.get(
                    ("rondo-aggregate-verify-reconstruct-output-durable", slot),
                    last_bft_sequence + 1,
                )
                < last_bft_sequence
            )
            required_pipelined = (non_tail_count + 1) // 2
            # Tiny smoke runs establish the wave schedule and per-slot event
            # order, but their single non-tail output is too scheduler-sensitive
            # to serve as quantitative pipeline-overlap evidence. Formal measured
            # runs retain the overlap gate.
            if manifest["sample_role"] == "measured" and pipelined_outputs < required_pipelined:
                reasons.append(
                    f"Rondo sample {sample} finalized only {pipelined_outputs}/"
                    f"{non_tail_count} non-tail outputs before the BFT drain; "
                    "reconstruction is not observably pipelined"
                )
        if any(str(event.get("phase", "")).startswith("chained-") for event in events):
            reasons.append("unexpected three-chain phase in four-phase Rondo")

    if manifest["implementation"] == BeaconImplementation.SPURT.value:
        required_spurt_phases = (
            "spurt-commitment-pvss-share-to-leader",
            "spurt-aggregation-verify-build-private-proposals",
            "spurt-agreement-propose-verify-private-transcript",
            "spurt-agreement-prepare",
            "spurt-agreement-precommit",
            "spurt-agreement-commit",
            "spurt-agreement-finalize-decide",
            "spurt-reconstruction-share-broadcast",
            "spurt-reconstruction-pairing-output-durable",
            "spurt-beacon-certificate-relay",
        )
        for phase in required_spurt_phases:
            phase_events = [event for event in events if event.get("phase") == phase]
            if len(phase_events) != expected_outputs:
                reasons.append(
                    f"Spurt phase {phase} expected {expected_outputs} events, "
                    f"found {len(phase_events)}"
                )
                continue
            positions = [
                (event.get("sample"), event.get("epoch"), event.get("slot"))
                for event in phase_events
            ]
            if len(set(positions)) != len(positions) or set(positions) != output_positions:
                reasons.append(f"Spurt phase {phase} does not cover every output exactly once")
        batch_size = int(manifest["batch_size"])
        fill_phases = (
            "spurt-commitment-pvss-share-to-leader",
            "spurt-aggregation-verify-build-private-proposals",
        )
        ready_phase = "spurt-agreement-propose-verify-private-transcript"
        output_phases = required_spurt_phases[3:]
        for sample in range(int(manifest["samples"])):
            actual_schedule = [
                (str(event.get("phase")), event.get("slot"))
                for event in sorted(
                    (
                        event
                        for event in events
                        if event.get("sample") == sample
                        and str(event.get("phase", "")).startswith("spurt-")
                    ),
                    key=lambda event: int(event["node_sequence"]),
                )
            ]
            expected_schedule = [
                (phase, slot) for slot in range(batch_size) for phase in fill_phases
            ]
            expected_schedule.extend((ready_phase, slot) for slot in range(batch_size))
            expected_schedule.extend(
                (phase, slot) for slot in range(batch_size) for phase in output_phases
            )
            if actual_schedule != expected_schedule:
                reasons.append(
                    f"Spurt sample {sample} does not follow the future-epoch "
                    "pre-aggregation pipeline schedule"
                )

    if manifest["implementation"] == BeaconImplementation.SILK.value:
        batch_size = int(manifest["batch_size"])
        for sample in range(int(manifest["samples"])):
            sample_events = [e for e in events if e.get("sample") == sample]
            agreement_phases = ("epoch-bft-simple-it", "epoch-bft-certificate-assemble-persist")
            measured_agreement = [
                e.get("phase") for e in sample_events if e.get("headline_phase") == "agreement"
            ]
            if measured_agreement != list(agreement_phases):
                reasons.append(
                    f"Silk sample {sample}: incomplete or reordered Agree instrumentation"
                )
            for phase, slots in (
                ("qr-sign-send", list(range(1, batch_size))),
                ("qr-quorum-wait-qrout-persist", list(range(1, batch_size))),
                ("qr-final-sign-send", [batch_size - 1]),
                ("qr-final-quorum-verify", [batch_size - 1]),
            ):
                if [e.get("slot") for e in sample_events if e.get("phase") == phase] != slots:
                    reasons.append(f"Silk sample {sample}: incomplete signed-release phase {phase}")

    digest = sha256_file(path)
    reasons.extend(_checksum_reasons(path, digest))
    send_totals = None
    try:
        summary = json.loads(
            (path.parent.parent / "node-summaries" / f"node-{node_id:04}.json").read_text(
                encoding="utf-8"
            )
        )
        if summary.get("run_id") != manifest["run_id"] or summary.get("node_id") != node_id:
            raise ValueError("summary identity mismatch")
        send_totals = _completed_send_totals(summary, int(manifest["samples"]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        reasons.append(f"incomplete background send accounting: {error}")
    validation = NodeValidation(
        node_id=node_id,
        path=str(path),
        log_valid=not reasons,
        reasons=tuple(reasons),
        sha256=digest,
    )
    result = None if reasons else _node_result(events, node_id, digest, manifest, outputs)
    if result is not None and send_totals is not None:
        result = replace(
            result, protocol_wire_bytes_sent=send_totals[0], messages_sent=send_totals[1]
        )
    return ParsedNode(validation, result, tuple(events), outputs)


def _completed_send_totals(summary: dict[str, Any], samples: int) -> tuple[int, int]:
    """Count successful frames once, including sends outside foreground phase spans."""
    traces = summary["bft_trace"]
    if sorted(trace["sample"] for trace in traces) != list(range(samples)):
        raise ValueError("send receipts do not cover each sample exactly once")
    wire = messages = 0
    for trace in traces:
        receipts = [
            event
            for key in ("events", "sender_events")
            for event in trace.get(key, [])
            if "socket_write_complete_unix_ns" in event
            and event.get("label") != "experiment-sample-ready-v1"
        ]
        accounting = trace["send_accounting"]
        count = len(receipts)
        size = sum(int(receipt["framed_bytes"]) for receipt in receipts)
        if any(int(receipt["framed_bytes"]) <= 0 for receipt in receipts):
            raise ValueError("nonpositive completed frame size")
        if (
            accounting.get("schema") != "completed-protocol-frames/v1"
            or size != accounting["protocol_framed_bytes"]
            or count != accounting["protocol_messages"]
            or accounting["counter_messages_delta"]
            != count + accounting["excluded_lifecycle_messages"]
            or accounting["counter_framed_bytes_delta"]
            != size + accounting["excluded_lifecycle_framed_bytes"]
        ):
            raise ValueError("completed frame receipts do not reconcile with counters")
        wire += size
        messages += count
    return wire, messages


def _validate_time(prefix: str, event: dict[str, Any], reasons: list[str]) -> None:
    values = {
        field: _event_int(prefix, event, field, reasons)
        for field in (
            "monotonic_start_ns",
            "monotonic_end_ns",
            "unix_start_ns",
            "unix_end_ns",
            "wall_ns",
        )
    }
    if any(value is None for value in values.values()):
        return
    monotonic_start = values["monotonic_start_ns"]
    monotonic_end = values["monotonic_end_ns"]
    unix_start = values["unix_start_ns"]
    unix_end = values["unix_end_ns"]
    wall = values["wall_ns"]
    assert monotonic_start is not None
    assert monotonic_end is not None
    assert unix_start is not None
    assert unix_end is not None
    assert wall is not None
    if min(monotonic_start, monotonic_end, unix_start, unix_end, wall) < 0:
        reasons.append(f"{prefix}: negative time field")
    if monotonic_end < monotonic_start or unix_end < unix_start:
        reasons.append(f"{prefix}: time moves backwards")
    if wall != monotonic_end - monotonic_start:
        reasons.append(f"{prefix}: wall_ns does not match monotonic span")


def _validate_nonnegative(
    prefix: str,
    event: dict[str, Any],
    fields: Iterable[str],
    reasons: list[str],
) -> None:
    for field in fields:
        value = _event_int(prefix, event, field, reasons)
        if value is not None and value < 0:
            reasons.append(f"{prefix}: negative {field}")


def _node_result(
    events: list[dict[str, Any]],
    node_id: int,
    digest: str,
    manifest: dict[str, Any],
    outputs: frozenset[tuple[int, int, int, str]],
) -> NodeResult:
    phase_wall = {
        phase: sum(int(event["wall_ns"]) for event in events if event["headline_phase"] == phase)
        for phase in HEADLINE_PHASES
    }
    storage = [int(event["protocol_storage_bytes"]) for event in events]
    return NodeResult(
        run_id=str(manifest["run_id"]),
        sample_id=str(manifest["sample_id"]),
        implementation=str(manifest["implementation"]),
        node_id=node_id,
        role="replica",
        protocol_status="completed",
        node_log_sha256=digest,
        measurement_wall_ns=_node_measurement_wall(events, manifest),
        output_count=len(outputs),
        commitment_wall_ns=phase_wall["commitment"],
        agreement_wall_ns=phase_wall["agreement"],
        quorum_release_wall_ns=phase_wall["quorum_release"],
        reconstruction_wall_ns=phase_wall["reconstruction"],
        framework_overhead_wall_ns=phase_wall["framework_overhead"],
        process_cpu_total_ns=sum(int(event["process_cpu_ns"]) for event in events),
        rss_peak_bytes=max(int(event["rss_peak_bytes"]) for event in events),
        storage_delta_bytes=max(storage) - min(storage),
        protocol_wire_bytes_sent=sum(int(event["protocol_wire_bytes_sent"]) for event in events),
        messages_sent=sum(int(event["messages_sent"]) for event in events),
    )


def _run_validation_reasons(
    manifest: dict[str, Any],
    expected_nodes: tuple[int, ...],
    parsed: dict[int, ParsedNode],
) -> list[str]:
    reasons: list[str] = []
    for node_id in expected_nodes:
        node = parsed.get(node_id)
        if node is None:
            reasons.append(f"node {node_id}: missing log")
        elif not node.validation.log_valid:
            reasons.append(f"node {node_id}: invalid log")
    valid = [parsed[node_id] for node_id in expected_nodes if node_id in parsed]
    transports = {str(event.get("transport_profile")) for node in valid for event in node.events}
    if len(transports) != 1:
        reasons.append("transport profiles differ within run")
    profiles = {str(event.get("implementation_profile")) for node in valid for event in node.events}
    if len(profiles) != 1:
        reasons.append("implementation profiles differ within run")
    if valid and any(node.outputs != valid[0].outputs for node in valid[1:]):
        reasons.append("durable output sets differ across nodes")
    if len(valid) != int(manifest["n"]):
        reasons.append("failure-free run does not cover all participants")
    unexpected = sorted(set(parsed) - set(expected_nodes))
    if unexpected:
        reasons.append(f"unexpected node logs: {unexpected}")
    return reasons


NODE_FIELDS = tuple(NodeResult.__dataclass_fields__)
RUN_FIELDS = (
    "run_id",
    "sample_id",
    "implementation",
    "expected_node_count",
    "valid_node_count",
    "output_count",
    "measurement_wall_ns",
    "throughput_outputs_per_second",
    "system_process_cpu_ns",
    "system_protocol_wire_bytes_sent",
    "wire_bytes_per_output",
    "wire_kib_per_output",
    "wire_mib_per_output",
    "commitment_wall_ns",
    "agreement_wall_ns",
    "quorum_release_wall_ns",
    "reconstruction_wall_ns",
    "framework_overhead_wall_ns",
)


def _write_node_results(path: Path, results: list[NodeResult]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=NODE_FIELDS, lineterminator="\n")
        writer.writeheader()
        for result in sorted(results, key=lambda item: item.node_id):
            writer.writerow(asdict(result))


def _write_run_results(
    path: Path,
    manifest: dict[str, Any],
    node_results: tuple[NodeResult, ...],
    parsed: dict[int, ParsedNode],
    run_valid: bool,
) -> int:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUN_FIELDS, lineterminator="\n")
        writer.writeheader()
        if not run_valid:
            return 0
        all_events = [event for node in parsed.values() for event in node.events]
        measurement_wall = _measurement_wall(manifest, parsed)
        output_count = node_results[0].output_count
        phase_wall = {
            phase: _critical_path_wall(
                all_events,
                phase,
                str(manifest.get("clock_aggregation_mode", "synchronized-unix")),
            )
            for phase in HEADLINE_PHASES
        }
        system_wire = sum(item.protocol_wire_bytes_sent for item in node_results)
        writer.writerow(
            {
                "run_id": manifest["run_id"],
                "sample_id": manifest["sample_id"],
                "implementation": manifest["implementation"],
                "expected_node_count": manifest["n"],
                "valid_node_count": len(node_results),
                "output_count": output_count,
                "measurement_wall_ns": measurement_wall,
                "throughput_outputs_per_second": (
                    f"{output_count * 1_000_000_000 / measurement_wall:.9f}"
                ),
                "system_process_cpu_ns": sum(item.process_cpu_total_ns for item in node_results),
                "system_protocol_wire_bytes_sent": system_wire,
                "wire_bytes_per_output": f"{system_wire / output_count:.9f}",
                "wire_kib_per_output": f"{system_wire / output_count / 1024:.9f}",
                "wire_mib_per_output": f"{system_wire / output_count / (1024**2):.9f}",
                "commitment_wall_ns": phase_wall["commitment"],
                "agreement_wall_ns": phase_wall["agreement"],
                "quorum_release_wall_ns": phase_wall["quorum_release"],
                "reconstruction_wall_ns": phase_wall["reconstruction"],
                "framework_overhead_wall_ns": phase_wall["framework_overhead"],
            }
        )
    return 1


def _critical_path_wall(
    events: list[dict[str, Any]],
    phase: str,
    clock_aggregation_mode: str = "synchronized-unix",
) -> int:
    selected = [event for event in events if event["headline_phase"] == phase]
    if not selected:
        return 0
    operations: dict[tuple[int, int, int | None, str, int], list[dict[str, Any]]] = {}
    for event in selected:
        key = (
            int(event["sample"]),
            int(event["epoch"]),
            int(event["slot"]) if event.get("slot") is not None else None,
            str(event["phase"]),
            int(event["node_sequence"]),
        )
        operations.setdefault(key, []).append(event)
    if clock_aggregation_mode == "barrier-aligned-monotonic":
        return sum(
            max(int(event["wall_ns"]) for event in operation) for operation in operations.values()
        )
    return sum(
        max(int(event["unix_end_ns"]) for event in operation)
        - min(int(event["unix_start_ns"]) for event in operation)
        for operation in operations.values()
    )


def _measurement_wall(manifest: dict[str, Any], parsed: dict[int, ParsedNode]) -> int:
    mode = manifest.get("clock_aggregation_mode", "synchronized-unix")
    implementation = str(manifest["implementation"])
    samples = range(int(manifest["samples"]))
    if mode == "synchronized-unix":
        all_events = [event for node in parsed.values() for event in node.events]
        return sum(_sample_wall(all_events, sample, implementation, "unix") for sample in samples)
    return sum(
        max(
            _sample_wall(list(node.events), sample, implementation, "monotonic")
            for node in parsed.values()
        )
        for sample in samples
    )


def _node_measurement_wall(events: list[dict[str, Any]], manifest: dict[str, Any]) -> int:
    implementation = str(manifest["implementation"])
    return sum(
        _sample_wall(events, sample, implementation, "monotonic")
        for sample in range(int(manifest["samples"]))
    )


def _sample_wall(
    events: list[dict[str, Any]],
    sample: int,
    implementation: str,
    clock: str,
) -> int:
    sample_events = [event for event in events if int(event["sample"]) == sample]
    terminal_events = _measurement_terminal_events(sample_events, implementation)
    if not sample_events or not terminal_events:
        raise ResultDerivationError(f"sample {sample} has no complete measurement window")
    return max(int(event[f"{clock}_end_ns"]) for event in terminal_events) - min(
        int(event[f"{clock}_start_ns"]) for event in sample_events
    )


def _measurement_terminal_events(
    events: list[dict[str, Any]], implementation: str
) -> list[dict[str, Any]]:
    if implementation == BeaconImplementation.SILK.value:
        return [event for event in events if event.get("phase") == "qr-final-quorum-verify"]
    if implementation == BeaconImplementation.SPURT.value:
        return [event for event in events if event.get("phase") == "spurt-beacon-certificate-relay"]
    return [event for event in events if event.get("event_kind") == "beacon_output_durable"]


def _stable_digest(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _manifest_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResultDerivationError(f"manifest {field} must be an integer")
    return value


def _event_int(
    prefix: str,
    event: dict[str, Any],
    field: str,
    reasons: list[str],
) -> int | None:
    value = event.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        reasons.append(f"{prefix}: missing or invalid {field}")
        return None
    if value < 0:
        reasons.append(f"{prefix}: negative {field}")
        return None
    return value


def _checksum_reasons(path: Path, digest: str) -> list[str]:
    checksum_path = path.with_suffix(".jsonl.sha256")
    if not checksum_path.is_file():
        return ["missing node log checksum"]
    parts = checksum_path.read_text(encoding="utf-8").strip().split()
    if len(parts) != 2:
        return ["malformed node log checksum"]
    declared_digest, declared_name = parts
    reasons: list[str] = []
    if declared_digest != digest:
        reasons.append("node log checksum mismatch")
    if declared_name != path.name:
        reasons.append("node log checksum filename mismatch")
    return reasons


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ResultDerivationError(f"{path.name} is not a JSON object")
    return value
