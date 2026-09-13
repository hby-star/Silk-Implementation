from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from .registry import ExecutionMode, ExperimentKind


class DefinitionError(ValueError):
    """A experiment definition is missing required data."""


@dataclass(frozen=True)
class SmokeDefinition:
    n: int
    t: int
    batch_size: int
    samples: int | None
    epochs: int | None
    sample_role: str


@dataclass(frozen=True)
class MatrixCell:
    n: int
    t: int
    batch_size: int


@dataclass(frozen=True)
class NetworkDefinition:
    profile: str
    bandwidth_mbps: int
    delay_distribution: str
    delay_min_ms: int
    delay_max_ms: int
    loss_percent: float
    reorder_percent: float
    duplicate_percent: float
    seed_policy: str
    region_assignment: str
    regions: tuple[str, ...]
    rtt_matrix_ms: tuple[tuple[float, ...], ...]


@dataclass(frozen=True)
class ResourceDefinition:
    profile: str
    cpu_cores_per_node: float
    memory_mib_per_node: int
    one_container_per_node: bool


@dataclass(frozen=True)
class IsolationDefinition:
    policy: str
    cleanup_before_run: bool
    cleanup_after_run: bool
    verify_terminated: bool
    scope: str


@dataclass(frozen=True)
class MatrixDefinition:
    status: str
    implementations: tuple[str, ...]
    cells: tuple[MatrixCell, ...]
    executors: tuple[str, ...]
    warmup_runs: int
    measured_runs: int
    samples_per_run: int | None
    outputs_per_run: int | None
    network: NetworkDefinition | None
    resources: ResourceDefinition | None
    isolation: IsolationDefinition


@dataclass(frozen=True)
class ExperimentDefinition:
    path: Path
    sha256: str
    kind: ExperimentKind
    execution_mode: ExecutionMode
    executors: tuple[str, ...]
    seed_base: int
    smoke: SmokeDefinition
    matrix: MatrixDefinition
    raw: dict[str, Any]


def load_definition(path: str | Path) -> ExperimentDefinition:
    resolved = Path(path).resolve()
    with resolved.open("rb") as handle:
        raw = tomllib.load(handle)
    if raw.get("schema_version") != 1:
        raise DefinitionError("experiment schema_version must be 1")
    kind = ExperimentKind.parse(str(raw.get("experiment_id", "")))
    execution = _mapping(raw, "execution")
    try:
        mode = ExecutionMode(str(execution["driver"]))
    except (KeyError, ValueError) as error:
        raise DefinitionError("execution.driver must be local-process or distributed") from error
    if mode is not kind.execution_mode:
        raise DefinitionError(f"{kind.value} requires execution.driver={kind.execution_mode.value}")
    executors_raw = execution.get("executors")
    if not isinstance(executors_raw, list) or not executors_raw:
        raise DefinitionError("execution.executors must be a non-empty list")
    executors = tuple(str(value) for value in executors_raw)
    if len(executors) != len(set(executors)):
        raise DefinitionError("execution.executors must not contain duplicates")
    allowed_executors = (
        {"docker-aggregate", "aws-aggregate"}
        if kind is ExperimentKind.BAVSS_PHASE_COST
        else {"docker", "remote-aws"}
    )
    if not set(executors) <= allowed_executors:
        raise DefinitionError(
            f"{kind.value} contains unsupported executors: "
            f"{sorted(set(executors) - allowed_executors)}"
        )
    seed_base = _positive_int(raw.get("seed_base"), "seed_base")
    smoke_raw = _mapping(raw, "smoke")
    if "seeds" in smoke_raw:
        raise DefinitionError("smoke.seeds is obsolete; seed_base defines the smoke seed")
    if kind is ExperimentKind.BAVSS_PHASE_COST:
        if "epochs" in smoke_raw:
            raise DefinitionError("bavss-phase-cost smoke must not declare epochs")
        smoke_samples = _positive_int(smoke_raw.get("samples"), "smoke.samples")
        smoke_epochs = None
    else:
        if "samples" in smoke_raw:
            raise DefinitionError("beacon-performance smoke must use epochs, not samples")
        smoke_samples = None
        smoke_epochs = _positive_int(smoke_raw.get("epochs"), "smoke.epochs")
    smoke = SmokeDefinition(
        n=_positive_int(smoke_raw.get("n"), "smoke.n"),
        t=_nonnegative_int(smoke_raw.get("t"), "smoke.t"),
        batch_size=_positive_int(smoke_raw.get("batch_size"), "smoke.batch_size"),
        samples=smoke_samples,
        epochs=smoke_epochs,
        sample_role=str(smoke_raw.get("sample_role", "")),
    )
    if smoke.sample_role != "smoke":
        raise DefinitionError("smoke.sample_role must be smoke")
    if 3 * smoke.t >= smoke.n:
        raise DefinitionError("smoke parameters violate n >= 3t+1")
    matrix = _mapping(raw, "matrix")
    expected_implementations = (
        ["silk-bavss-po", "rondo-bavss-po"]
        if kind is ExperimentKind.BAVSS_PHASE_COST
        else ["silk-beacon", "rondo-beacon", "spurt-beacon"]
    )
    if matrix.get("implementations") != expected_implementations:
        raise DefinitionError(
            f"{kind.value} matrix implementations must be {expected_implementations}"
        )
    status = str(matrix.get("status", ""))
    if status != "ready":
        raise DefinitionError(f"{kind.value} matrix.status must be ready")
    obsolete_fields = {
        "batch_sizes",
        "committees",
        "epochs_per_run",
        "opened_indices",
    } & matrix.keys()
    if obsolete_fields:
        raise DefinitionError(
            f"matrix uses obsolete Cartesian-product fields: {sorted(obsolete_fields)}"
        )
    if "capacity" in matrix:
        raise DefinitionError("use fixed matrix.outputs_per_run; capacity fallback is unsupported")
    cells_raw = matrix.get("cells")
    if not isinstance(cells_raw, list) or not cells_raw:
        raise DefinitionError("matrix.cells must be a non-empty array")
    cells = tuple(_matrix_cell(value, index) for index, value in enumerate(cells_raw))
    if len(cells) != len(set(cells)):
        raise DefinitionError("matrix.cells must not contain duplicates")
    matrix_executors_raw = matrix.get("executors")
    if not isinstance(matrix_executors_raw, list) or not matrix_executors_raw:
        raise DefinitionError("matrix.executors must be a non-empty array")
    matrix_executors = tuple(str(value) for value in matrix_executors_raw)
    if len(matrix_executors) != len(set(matrix_executors)):
        raise DefinitionError("matrix.executors must not contain duplicates")
    if not set(matrix_executors) <= set(executors):
        raise DefinitionError("matrix.executors must be enabled by execution.executors")
    if kind is ExperimentKind.BAVSS_PHASE_COST and len(matrix_executors) != 1:
        raise DefinitionError("bAVSS matrix requires exactly one aggregate executor")
    samples_per_run = None
    outputs_per_run = None
    network = None
    resources = None
    if kind is ExperimentKind.BAVSS_PHASE_COST:
        if "outputs_per_run" in matrix:
            raise DefinitionError("bAVSS matrix must use samples_per_run, not outputs_per_run")
        samples_per_run = _positive_int(
            matrix.get("samples_per_run"),
            "matrix.samples_per_run",
        )
        if "docker-aggregate" in matrix_executors:
            resources = _resources(_mapping(matrix, "resources"))
            if (
                resources.cpu_cores_per_node != 1
                or resources.memory_mib_per_node != 2_048
                or resources.one_container_per_node
            ):
                raise DefinitionError(
                    "remote aggregate bAVSS requires one 1-vCPU/2048-MiB container per run"
                )
        elif "aws-aggregate" in matrix_executors:
            resources = _resources(_mapping(matrix, "resources"))
            if (
                resources.cpu_cores_per_node != 2
                or resources.memory_mib_per_node != 4096
                or resources.one_container_per_node
                or resources.profile != "aws-t3a-medium-aggregate-v1"
            ):
                raise DefinitionError("AWS aggregate bAVSS requires one 2-vCPU/4096-MiB instance")
        elif "resources" in matrix:
            raise DefinitionError("local bAVSS matrix must not declare Docker resources")
    else:
        if "samples_per_run" in matrix:
            raise DefinitionError("beacon matrix must use outputs_per_run, not samples_per_run")
        outputs_per_run = _positive_int(
            matrix.get("outputs_per_run"),
            "matrix.outputs_per_run",
        )
        for index, cell in enumerate(cells):
            if outputs_per_run % cell.batch_size != 0:
                raise DefinitionError(
                    f"matrix.outputs_per_run must be divisible by matrix.cells[{index}].batch_size"
                )
        network = _network(_mapping(matrix, "network"))
        resources = _resources(_mapping(matrix, "resources"))
    response_repetitions = (
        _positive_int_tuple(
            matrix.get("response_repetitions"),
            "matrix.response_repetitions",
        )
        if kind is ExperimentKind.BAVSS_PHASE_COST
        else ()
    )
    if response_repetitions not in ((), (1,)):
        raise DefinitionError("the current Silk profile supports response_repetitions=[1]")
    parsed_matrix = MatrixDefinition(
        status=status,
        implementations=tuple(expected_implementations),
        cells=cells,
        executors=matrix_executors,
        warmup_runs=_nonnegative_int(matrix.get("warmup_runs"), "matrix.warmup_runs"),
        measured_runs=_positive_int(matrix.get("measured_runs"), "matrix.measured_runs"),
        samples_per_run=samples_per_run,
        outputs_per_run=outputs_per_run,
        network=network,
        resources=resources,
        isolation=_isolation(_mapping(matrix, "isolation")),
    )
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return ExperimentDefinition(
        resolved,
        digest,
        kind,
        mode,
        executors,
        seed_base,
        smoke,
        parsed_matrix,
        raw,
    )


def _mapping(raw: dict[str, Any], field: str) -> dict[str, Any]:
    value = raw.get(field)
    if not isinstance(value, dict):
        raise DefinitionError(f"{field} must be a table")
    return value


def _positive_int(value: object, field: str) -> int:
    parsed = _nonnegative_int(value, field)
    if parsed == 0:
        raise DefinitionError(f"{field} must be positive")
    return parsed


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DefinitionError(f"{field} must be an integer")
    if value < 0:
        raise DefinitionError(f"{field} must be non-negative")
    return value


def _positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DefinitionError(f"{field} must be a number")
    parsed = float(value)
    if parsed <= 0:
        raise DefinitionError(f"{field} must be positive")
    return parsed


def _nonnegative_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DefinitionError(f"{field} must be a number")
    parsed = float(value)
    if parsed < 0:
        raise DefinitionError(f"{field} must be non-negative")
    return parsed


def _rtt_matrix(value: object) -> tuple[tuple[float, ...], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise DefinitionError("matrix.network.rtt_matrix_ms must be an array")
    rows: list[tuple[float, ...]] = []
    for row in value:
        if not isinstance(row, list):
            raise DefinitionError("matrix.network.rtt_matrix_ms rows must be arrays")
        rows.append(
            tuple(_nonnegative_number(item, "matrix.network.rtt_matrix_ms") for item in row)
        )
    return tuple(rows)


def _percentage(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DefinitionError(f"{field} must be a number")
    parsed = float(value)
    if not 0 <= parsed <= 100:
        raise DefinitionError(f"{field} must be between 0 and 100")
    return parsed


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DefinitionError(f"{field} must be a non-empty string")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise DefinitionError(f"{field} must be a boolean")
    return value


def _positive_int_tuple(value: object, field: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise DefinitionError(f"{field} must be a non-empty integer array")
    parsed = tuple(_positive_int(item, field) for item in value)
    if len(parsed) != len(set(parsed)):
        raise DefinitionError(f"{field} must not contain duplicates")
    return parsed


def _matrix_cell(value: object, index: int) -> MatrixCell:
    if not isinstance(value, dict):
        raise DefinitionError(f"matrix.cells[{index}] must be a table")
    cell = MatrixCell(
        n=_positive_int(value.get("n"), f"matrix.cells[{index}].n"),
        t=_nonnegative_int(value.get("t"), f"matrix.cells[{index}].t"),
        batch_size=_positive_int(
            value.get("batch_size"),
            f"matrix.cells[{index}].batch_size",
        ),
    )
    if 3 * cell.t >= cell.n:
        raise DefinitionError("matrix cells must satisfy n >= 3t+1")
    return cell


def _network(value: dict[str, Any]) -> NetworkDefinition:
    network = NetworkDefinition(
        profile=_nonempty_string(value.get("profile"), "matrix.network.profile"),
        bandwidth_mbps=_positive_int(
            value.get("bandwidth_mbps"),
            "matrix.network.bandwidth_mbps",
        ),
        delay_distribution=_nonempty_string(
            value.get("delay_distribution"),
            "matrix.network.delay_distribution",
        ),
        delay_min_ms=_nonnegative_int(
            value.get("delay_min_ms"),
            "matrix.network.delay_min_ms",
        ),
        delay_max_ms=_nonnegative_int(
            value.get("delay_max_ms"),
            "matrix.network.delay_max_ms",
        ),
        loss_percent=_percentage(
            value.get("loss_percent"),
            "matrix.network.loss_percent",
        ),
        reorder_percent=_percentage(
            value.get("reorder_percent"),
            "matrix.network.reorder_percent",
        ),
        duplicate_percent=_percentage(
            value.get("duplicate_percent"),
            "matrix.network.duplicate_percent",
        ),
        seed_policy=_nonempty_string(
            value.get("seed_policy"),
            "matrix.network.seed_policy",
        ),
        region_assignment=str(value.get("region_assignment", "")),
        regions=tuple(str(item) for item in value.get("regions", [])),
        rtt_matrix_ms=_rtt_matrix(value.get("rtt_matrix_ms")),
    )
    if network.delay_distribution not in {"uniform", "fixed-pairwise"}:
        raise DefinitionError("matrix.network.delay_distribution must be uniform or fixed-pairwise")
    if network.delay_min_ms > network.delay_max_ms:
        raise DefinitionError("matrix.network delay_min_ms must not exceed delay_max_ms")
    if network.delay_distribution == "fixed-pairwise":
        if network.region_assignment != "round-robin-v1" or len(network.regions) < 2:
            raise DefinitionError(
                "fixed-pairwise network requires at least two regions and round-robin-v1 assignment"
            )
        if any(not region.strip() for region in network.regions) or len(
            set(network.regions)
        ) != len(network.regions):
            raise DefinitionError("matrix.network regions must be non-empty and distinct")
        if len(network.rtt_matrix_ms) != len(network.regions) or any(
            len(row) != len(network.regions) for row in network.rtt_matrix_ms
        ):
            raise DefinitionError("matrix.network.rtt_matrix_ms must be a square region matrix")
        for source, row in enumerate(network.rtt_matrix_ms):
            if row[source] < 0:
                raise DefinitionError("matrix.network RTT values must be nonnegative")
            for destination, value_ms in enumerate(row):
                if value_ms != network.rtt_matrix_ms[destination][source]:
                    raise DefinitionError("matrix.network RTT matrix must be symmetric")
        observed = [value for row in network.rtt_matrix_ms for value in row]
        if min(observed) != network.delay_min_ms or max(observed) != network.delay_max_ms:
            raise DefinitionError(
                "matrix.network delay_min_ms/delay_max_ms must bound the declared RTT matrix"
            )
    elif network.regions or network.rtt_matrix_ms or network.region_assignment:
        raise DefinitionError("uniform network profile must not declare regional RTT fields")
    return network


def _resources(value: dict[str, Any]) -> ResourceDefinition:
    return ResourceDefinition(
        profile=_nonempty_string(value.get("profile"), "matrix.resources.profile"),
        cpu_cores_per_node=_positive_number(
            value.get("cpu_cores_per_node"),
            "matrix.resources.cpu_cores_per_node",
        ),
        memory_mib_per_node=_positive_int(
            value.get("memory_mib_per_node"),
            "matrix.resources.memory_mib_per_node",
        ),
        one_container_per_node=_boolean(
            value.get("one_container_per_node"),
            "matrix.resources.one_container_per_node",
        ),
    )


def _isolation(value: dict[str, Any]) -> IsolationDefinition:
    return IsolationDefinition(
        policy=_nonempty_string(value.get("policy"), "matrix.isolation.policy"),
        cleanup_before_run=_boolean(
            value.get("cleanup_before_run"),
            "matrix.isolation.cleanup_before_run",
        ),
        cleanup_after_run=_boolean(
            value.get("cleanup_after_run"),
            "matrix.isolation.cleanup_after_run",
        ),
        verify_terminated=_boolean(
            value.get("verify_terminated"),
            "matrix.isolation.verify_terminated",
        ),
        scope=_nonempty_string(value.get("scope"), "matrix.isolation.scope"),
    )
