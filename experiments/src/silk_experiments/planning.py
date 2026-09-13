from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import ExperimentDefinition, load_definition
from .paths import workspace_paths
from .provenance import source_identity
from .registry import BavssExecutor, BeaconExecutor, BeaconImplementation, ExperimentKind

RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PLAN_SCHEMA = "silk-run-plan/v6"
BAVSS_PLAN_SCHEMA = "silk-bavss-run-plan/v5"
SAMPLE_ROLES = ("smoke", "warmup", "measured")


class PlanError(ValueError):
    """A run plan is unsafe or incompatible with the experiment registry."""


@dataclass(frozen=True)
class SmokePlan:
    schema_id: str
    run_id: str
    sample_id: str
    experiment_id: str
    implementation: str
    sample_role: str
    executor: str
    definition_path: str
    definition_sha256: str
    binary_path: str
    binary_sha256: str
    docker_image: str | None
    docker_image_id: str | None
    docker_host: str | None
    inventory_path: str | None
    inventory_sha256: str | None
    placement_aliases: tuple[str, ...]
    placement_regions: tuple[str, ...]
    git_commit: str
    git_dirty: bool
    source_fingerprint: str
    n: int
    t: int
    batch_size: int
    samples: int
    epochs: int
    seed: int
    expected_node_ids: tuple[int, ...]
    expected_output_count: int
    completion_policy: str
    clock_source: str
    clock_sync_profile: str
    clock_comparable: bool
    state_run: str
    raw_run: str
    processed_run: str
    created_at_utc: str


@dataclass(frozen=True)
class BavssSmokePlan:
    schema_id: str
    run_id: str
    experiment_id: str
    sample_role: str
    executor: str
    definition_path: str
    definition_sha256: str
    binary_path: str
    binary_sha256: str
    docker_image: str | None
    docker_image_id: str | None
    docker_host: str | None
    git_commit: str
    git_dirty: bool
    source_fingerprint: str
    n: int
    t: int
    batch_size: int
    samples: int
    seed: int
    state_run: str
    raw_root: str
    raw_run: str
    processed_run: str
    created_at_utc: str
    inventory_path: str | None = None
    inventory_sha256: str | None = None


def build_beacon_smoke_plan(
    definition_path: Path,
    run_id: str,
    implementation: str,
    binary_path: Path | None = None,
    executor: str = "docker",
    docker_image: str | None = None,
    docker_image_id: str | None = None,
    docker_host: str | None = None,
    matrix_n: int | None = None,
    outputs_per_run: int | None = None,
    inventory_path: Path | None = None,
) -> SmokePlan:
    definition = load_definition(definition_path)
    smoke = definition.smoke
    if smoke.epochs is None:
        raise PlanError("beacon smoke definition has no epoch count")
    if matrix_n is None:
        if outputs_per_run is not None:
            raise PlanError("--outputs-per-run requires --matrix-n for beacon qualification")
        n, t, batch_size, epochs = smoke.n, smoke.t, smoke.batch_size, smoke.epochs
    else:
        selected_cells = tuple(cell for cell in definition.matrix.cells if cell.n == matrix_n)
        if len(selected_cells) != 1:
            raise PlanError("--matrix-n must select exactly one declared beacon matrix cell")
        cell = selected_cells[0]
        selected_outputs = (
            definition.matrix.outputs_per_run if outputs_per_run is None else outputs_per_run
        )
        if selected_outputs is None:
            raise PlanError("beacon matrix qualification requires outputs_per_run")
        if selected_outputs != definition.matrix.outputs_per_run:
            raise PlanError("outputs_per_run must match the definition")
        if selected_outputs % cell.batch_size != 0:
            raise PlanError("outputs_per_run must be divisible by the selected batch size")
        n, t, batch_size, epochs = (
            cell.n,
            cell.t,
            cell.batch_size,
            selected_outputs // cell.batch_size,
        )
    return _build_beacon_plan(
        definition,
        run_id,
        implementation,
        smoke.sample_role,
        executor,
        n,
        t,
        batch_size,
        epochs,
        definition.seed_base,
        binary_path,
        docker_image,
        docker_image_id,
        docker_host,
        inventory_path,
    )


def build_bavss_smoke_plan(
    definition_path: Path,
    run_id: str,
    binary_path: Path | None = None,
    executor: str | None = None,
    docker_image: str | None = None,
    docker_image_id: str | None = None,
    docker_host: str | None = None,
    matrix_n: int | None = None,
    inventory_path: Path | None = None,
) -> BavssSmokePlan:
    definition = load_definition(definition_path)
    smoke = definition.smoke
    selected_executor = executor or definition.executors[0]
    if matrix_n is None:
        n, t, batch_size = smoke.n, smoke.t, smoke.batch_size
    else:
        selected_cells = tuple(cell for cell in definition.matrix.cells if cell.n == matrix_n)
        if len(selected_cells) != 1:
            raise PlanError("--matrix-n must select exactly one declared bAVSS matrix cell")
        n, t, batch_size = (
            selected_cells[0].n,
            selected_cells[0].t,
            selected_cells[0].batch_size,
        )
    if smoke.samples is None:
        raise PlanError("bAVSS smoke definition has no sample count")
    return _build_bavss_plan(
        definition,
        run_id,
        smoke.sample_role,
        selected_executor,
        n,
        t,
        batch_size,
        smoke.samples,
        definition.seed_base,
        binary_path,
        docker_image,
        docker_image_id,
        docker_host,
        inventory_path=inventory_path,
    )


def build_beacon_matrix_plans(
    definition_path: Path,
    run_prefix: str,
    binary_path: Path | None = None,
    docker_image: str | None = None,
    docker_image_id: str | None = None,
    docker_host: str | None = None,
    outputs_per_run: int | None = None,
    implementation: str | None = None,
    inventory_path: Path | None = None,
) -> tuple[SmokePlan, ...]:
    definition = load_definition(definition_path)
    if definition.kind is not ExperimentKind.BEACON_PERFORMANCE:
        raise PlanError("beacon matrix requires beacon-performance")
    validate_run_id(run_prefix)
    matrix = definition.matrix
    plans: list[SmokePlan] = []
    identity = _build_identity(binary_path, docker_image, docker_host)
    if matrix.outputs_per_run is None:
        raise PlanError("beacon matrix requires outputs_per_run")
    selected_outputs = matrix.outputs_per_run if outputs_per_run is None else outputs_per_run
    if selected_outputs != matrix.outputs_per_run:
        raise PlanError("outputs_per_run must match the definition")
    implementations = matrix.implementations
    if implementation is not None:
        selected_implementation = BeaconImplementation.parse(implementation).value
        if selected_implementation not in matrix.implementations:
            raise PlanError(f"definition does not enable implementation={selected_implementation}")
        implementations = (selected_implementation,)
    for executor in matrix.executors:
        for cell_index, cell in enumerate(matrix.cells):
            if selected_outputs % cell.batch_size != 0:
                raise PlanError("outputs_per_run must be divisible by every matrix batch size")
            epochs = selected_outputs // cell.batch_size
            for run_index, role in _matrix_runs(matrix.warmup_runs, matrix.measured_runs):
                seed = definition.seed_base + cell_index * 10_000 + run_index * 1_000
                for implementation in implementations:
                    plans.append(
                        _build_beacon_plan(
                            definition,
                            _matrix_run_id(
                                run_prefix,
                                implementation,
                                executor,
                                cell.n,
                                cell.batch_size,
                                role,
                                run_index,
                            ),
                            implementation,
                            role,
                            executor,
                            cell.n,
                            cell.t,
                            cell.batch_size,
                            epochs,
                            seed,
                            binary_path,
                            docker_image,
                            docker_image_id,
                            docker_host,
                            inventory_path,
                            identity=identity,
                        )
                    )
    return tuple(plans)


def build_bavss_matrix_plans(
    definition_path: Path,
    run_prefix: str,
    binary_path: Path | None = None,
    docker_image: str | None = None,
    docker_image_id: str | None = None,
    docker_host: str | None = None,
    inventory_path: Path | None = None,
) -> tuple[BavssSmokePlan, ...]:
    definition = load_definition(definition_path)
    if definition.kind is not ExperimentKind.BAVSS_PHASE_COST:
        raise PlanError("bAVSS matrix requires bavss-phase-cost")
    validate_run_id(run_prefix)
    matrix = definition.matrix
    plans: list[BavssSmokePlan] = []
    identity = _build_identity(binary_path, docker_image, docker_host)
    if matrix.samples_per_run is None:
        raise PlanError("bAVSS matrix requires samples_per_run")
    for executor in matrix.executors:
        for cell_index, cell in enumerate(matrix.cells):
            for run_index, role in _matrix_runs(matrix.warmup_runs, matrix.measured_runs):
                plans.append(
                    _build_bavss_plan(
                        definition,
                        _matrix_run_id(
                            run_prefix,
                            "paired-bavss",
                            executor,
                            cell.n,
                            cell.batch_size,
                            role,
                            run_index,
                        ),
                        role,
                        executor,
                        cell.n,
                        cell.t,
                        cell.batch_size,
                        matrix.samples_per_run,
                        definition.seed_base + cell_index * 10_000 + run_index,
                        binary_path,
                        docker_image,
                        docker_image_id,
                        docker_host,
                        identity=identity,
                        inventory_path=inventory_path,
                    )
                )
    return tuple(plans)


def save_smoke_plan(plan: SmokePlan) -> Path:
    return _save_plan(plan.state_run, plan)


def save_bavss_smoke_plan(plan: BavssSmokePlan) -> Path:
    return _save_plan(plan.state_run, plan)


def save_plan_collection(path: Path, plans: tuple[SmokePlan | BavssSmokePlan, ...]) -> Path:
    resolved = path.resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("x", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_id": "silk-plan-collection/v1",
                "plans": [asdict(plan) for plan in plans],
            },
            handle,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
    return resolved


def load_smoke_plan(path: Path) -> SmokePlan:
    value = json.loads(path.resolve().read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_id") != PLAN_SCHEMA:
        raise PlanError("unsupported beacon run plan schema")
    expected = value.get("expected_node_ids")
    if not isinstance(expected, list):
        raise PlanError("beacon plan expected_node_ids must be a list")
    value["expected_node_ids"] = tuple(expected)
    value["placement_aliases"] = tuple(value.get("placement_aliases", ()))
    value["placement_regions"] = tuple(value.get("placement_regions", ()))
    plan = SmokePlan(**value)
    _validate_beacon_plan(plan)
    return plan


def load_bavss_smoke_plan(path: Path) -> BavssSmokePlan:
    value = json.loads(path.resolve().read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_id") != BAVSS_PLAN_SCHEMA:
        raise PlanError("unsupported bAVSS run plan schema")
    plan = BavssSmokePlan(**value)
    _validate_bavss_plan(plan)
    return plan


def validate_run_id(run_id: str) -> str:
    if not RUN_ID.fullmatch(run_id):
        raise PlanError("run-id contains unsafe characters")
    return run_id


def _build_beacon_plan(
    definition: ExperimentDefinition,
    run_id: str,
    implementation: str,
    sample_role: str,
    executor: str,
    n: int,
    t: int,
    batch_size: int,
    epochs: int,
    seed: int,
    binary_path: Path | None,
    docker_image: str | None,
    docker_image_id: str | None,
    docker_host: str | None,
    inventory_path: Path | None,
    identity: tuple[Path, str, str, bool, str] | None = None,
) -> SmokePlan:
    if definition.kind is not ExperimentKind.BEACON_PERFORMANCE:
        raise PlanError("distributed beacon plan requires beacon-performance")
    implementation = BeaconImplementation.parse(implementation).value
    try:
        selected_executor = BeaconExecutor.parse(executor)
    except ValueError as error:
        raise PlanError(f"unsupported beacon executor: {executor}") from error
    if executor not in definition.executors:
        raise PlanError(f"definition does not enable executor={executor}")
    if selected_executor is BeaconExecutor.AWS_REMOTE:
        network = definition.matrix.network
        resources = definition.matrix.resources
        isolation = definition.matrix.isolation
        if network is None or network.profile != selected_executor.network_scenario:
            raise PlanError("remote-aws requires the aws-native-wan-v1 network profile")
        if network.seed_policy != "aws-native-network-v1":
            raise PlanError("remote-aws must not use a simulated network seed policy")
        if resources is None or resources.profile != selected_executor.resource_profile:
            raise PlanError("remote-aws requires the one-instance-per-node resource profile")
        if resources.one_container_per_node:
            raise PlanError("remote-aws runs native processes, not Docker containers")
        if isolation.scope != "run-scoped-native-processes-and-directories":
            raise PlanError("remote-aws requires native process and run-directory isolation")
    binary, binary_sha256, commit, dirty, fingerprint = identity or _build_identity(binary_path, docker_image, docker_host)
    run_id = validate_run_id(run_id)
    _validate_parameters(sample_role, n, t, batch_size, epochs)
    clock_sync_profile, clock_comparable = selected_executor.clock_profile
    inventory_binding = _inventory_binding(selected_executor, inventory_path, n)
    paths = workspace_paths()
    plan = SmokePlan(
        schema_id=PLAN_SCHEMA,
        run_id=run_id,
        sample_id="sample-0000",
        experiment_id=definition.kind.value,
        implementation=implementation,
        sample_role=sample_role,
        executor=executor,
        definition_path=str(definition.path),
        definition_sha256=definition.sha256,
        binary_path=str(binary),
        binary_sha256=binary_sha256,
        docker_image=docker_image,
        docker_image_id=docker_image_id,
        docker_host=docker_host,
        inventory_path=inventory_binding[0],
        inventory_sha256=inventory_binding[1],
        placement_aliases=inventory_binding[2],
        placement_regions=inventory_binding[3],
        git_commit=commit,
        git_dirty=dirty,
        source_fingerprint=fingerprint,
        n=n,
        t=t,
        batch_size=batch_size,
        samples=epochs,
        epochs=epochs,
        seed=seed,
        expected_node_ids=tuple(range(n)),
        expected_output_count=batch_size * epochs,
        completion_policy=_completion_policy(definition),
        clock_source="system-time-unix-ns-and-process-relative-monotonic",
        clock_sync_profile=clock_sync_profile,
        clock_comparable=clock_comparable,
        state_run=str(paths.state_root / run_id),
        raw_run=str(paths.raw_root / definition.kind.value / implementation / run_id),
        processed_run=str(paths.processed_root / definition.kind.value / implementation / run_id),
        created_at_utc=datetime.now(timezone.utc).isoformat(),
    )
    _validate_beacon_plan(plan, verify_binary=False)
    return plan


def _build_bavss_plan(
    definition: ExperimentDefinition,
    run_id: str,
    sample_role: str,
    executor: str,
    n: int,
    t: int,
    batch_size: int,
    samples: int,
    seed: int,
    binary_path: Path | None,
    docker_image: str | None,
    docker_image_id: str | None,
    docker_host: str | None,
    identity: tuple[Path, str, str, bool, str] | None = None,
    inventory_path: Path | None = None,
) -> BavssSmokePlan:
    if definition.kind is not ExperimentKind.BAVSS_PHASE_COST:
        raise PlanError("aggregate bAVSS plan requires bavss-phase-cost")
    try:
        BavssExecutor.parse(executor)
    except ValueError as error:
        raise PlanError(f"unsupported bAVSS executor: {executor}") from error
    if executor not in definition.executors:
        raise PlanError(f"definition does not enable executor={executor}")
    binary, binary_sha256, commit, dirty, fingerprint = identity or _build_identity(binary_path, docker_image, docker_host)
    run_id = validate_run_id(run_id)
    _validate_parameters(sample_role, n, t, batch_size, samples)
    paths = workspace_paths()
    raw_root = paths.raw_root / definition.kind.value
    inventory_file = inventory_digest = None
    if executor == BavssExecutor.AWS_AGGREGATE.value:
        inventory_file, inventory_digest, _, _ = _inventory_binding(
            BeaconExecutor.AWS_REMOTE, inventory_path, 1
        )
    elif inventory_path is not None:
        raise PlanError("only AWS aggregate plans may bind an inventory")
    plan = BavssSmokePlan(
        schema_id=BAVSS_PLAN_SCHEMA,
        run_id=run_id,
        experiment_id=definition.kind.value,
        sample_role=sample_role,
        executor=executor,
        definition_path=str(definition.path),
        definition_sha256=definition.sha256,
        binary_path=str(binary),
        binary_sha256=binary_sha256,
        docker_image=docker_image,
        docker_image_id=docker_image_id,
        docker_host=docker_host,
        git_commit=commit,
        git_dirty=dirty,
        source_fingerprint=fingerprint,
        n=n,
        t=t,
        batch_size=batch_size,
        samples=samples,
        seed=seed,
        state_run=str(paths.state_root / run_id),
        raw_root=str(raw_root),
        raw_run=str(raw_root / run_id),
        processed_run=str(paths.processed_root / definition.kind.value / run_id),
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        inventory_path=inventory_file,
        inventory_sha256=inventory_digest,
    )
    _validate_bavss_plan(plan, verify_binary=False)
    return plan


def _validate_beacon_plan(plan: SmokePlan, verify_binary: bool = True) -> None:
    validate_run_id(plan.run_id)
    if plan.experiment_id != ExperimentKind.BEACON_PERFORMANCE.value:
        raise PlanError("plan is not beacon-performance")
    BeaconImplementation.parse(plan.implementation)
    if not re.fullmatch(r"[0-9a-f]{64}", plan.source_fingerprint):
        raise PlanError("beacon plan must bind a source fingerprint")
    executor = BeaconExecutor.parse(plan.executor)
    if executor is BeaconExecutor.DOCKER:
        if not plan.docker_image or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", plan.docker_image_id or ""
        ):
            raise PlanError("Docker plans must bind a named image and sha256 image ID")
        if plan.docker_host is not None and not plan.docker_host.startswith("ssh://"):
            raise PlanError("Docker host must use ssh:// when specified")
    elif any(
        value is not None for value in (plan.docker_image, plan.docker_image_id, plan.docker_host)
    ):
        raise PlanError("non-Docker plans must not bind Docker configuration")
    if executor is BeaconExecutor.AWS_REMOTE:
        if not plan.inventory_path or not re.fullmatch(
            r"[0-9a-f]{64}", plan.inventory_sha256 or ""
        ):
            raise PlanError("remote-aws plans must bind an inventory and its SHA-256")
        if len(plan.placement_aliases) != plan.n or len(plan.placement_regions) != plan.n:
            raise PlanError("remote-aws plans require one bound placement per node")
    elif (
        any(value is not None for value in (plan.inventory_path, plan.inventory_sha256))
        or plan.placement_aliases
        or plan.placement_regions
    ):
        raise PlanError("only remote-aws plans may bind an inventory")
    _validate_parameters(plan.sample_role, plan.n, plan.t, plan.batch_size, plan.samples)
    if plan.epochs != plan.samples:
        raise PlanError("beacon epochs and samples must describe the same measured epochs")
    if plan.expected_output_count != plan.batch_size * plan.samples:
        raise PlanError("beacon expected_output_count does not match B*epochs")
    if tuple(range(plan.n)) != plan.expected_node_ids:
        raise PlanError("beacon plan node IDs are not contiguous")
    if verify_binary and plan.sample_role == "measured" and plan.git_dirty:
        raise PlanError("measured beacon runs require a clean planned git revision")
    if verify_binary:
        _verify_binary(plan.binary_path, plan.binary_sha256)


def _validate_bavss_plan(plan: BavssSmokePlan, verify_binary: bool = True) -> None:
    validate_run_id(plan.run_id)
    if plan.experiment_id != ExperimentKind.BAVSS_PHASE_COST.value:
        raise PlanError("plan is not bavss-phase-cost")
    executor = BavssExecutor.parse(plan.executor)
    if not re.fullmatch(r"[0-9a-f]{64}", plan.source_fingerprint):
        raise PlanError("bAVSS plan must bind a source fingerprint")
    if executor is BavssExecutor.DOCKER_AGGREGATE:
        if not plan.docker_image or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", plan.docker_image_id or ""
        ):
            raise PlanError("aggregate bAVSS plans must bind an image and sha256 image ID")
        if plan.docker_host is not None and not plan.docker_host.startswith("ssh://"):
            raise PlanError("aggregate bAVSS Docker host must use ssh:// when specified")
    elif any(
        value is not None for value in (plan.docker_image, plan.docker_image_id, plan.docker_host)
    ):
        raise PlanError("local bAVSS plans must not bind Docker configuration")
    if executor is BavssExecutor.AWS_AGGREGATE:
        if not plan.inventory_path or not re.fullmatch(
            r"[0-9a-f]{64}", plan.inventory_sha256 or ""
        ):
            raise PlanError("AWS aggregate plans must bind an inventory and its SHA-256")
    elif plan.inventory_path is not None or plan.inventory_sha256 is not None:
        raise PlanError("only AWS aggregate plans may bind an inventory")
    _validate_parameters(plan.sample_role, plan.n, plan.t, plan.batch_size, plan.samples)
    if verify_binary and plan.sample_role == "measured" and plan.git_dirty:
        raise PlanError("measured bAVSS runs require a clean planned git revision")
    if verify_binary:
        _verify_binary(plan.binary_path, plan.binary_sha256)


def _validate_parameters(sample_role: str, n: int, t: int, batch_size: int, count: int) -> None:
    if sample_role not in SAMPLE_ROLES:
        raise PlanError("sample_role must be smoke, warmup, or measured")
    if 3 * t >= n or batch_size <= 0 or count <= 0:
        raise PlanError("run parameters must satisfy n >= 3t+1, B>0, and count>0")


def _matrix_runs(warmups: int, measured: int) -> tuple[tuple[int, str], ...]:
    return tuple((index, "warmup") for index in range(warmups)) + tuple(
        (warmups + index, "measured") for index in range(measured)
    )


def _matrix_run_id(
    prefix: str,
    implementation: str,
    executor: str,
    n: int,
    batch_size: int,
    role: str,
    run_index: int,
) -> str:
    short_implementation = implementation.replace("-beacon", "").replace("-bavss-po", "")
    short_executor = {
        "docker": "docker",
    }.get(executor, executor)
    return validate_run_id(
        f"{prefix}-{short_implementation}-{short_executor}-n{n}-b{batch_size}-{role}-{run_index:03}"
    )


def _save_plan(state_run: str, plan: SmokePlan | BavssSmokePlan) -> Path:
    directory = Path(state_run)
    directory.mkdir(parents=True, exist_ok=False)
    path = directory / "plan.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(asdict(plan), handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def _completion_policy(definition: ExperimentDefinition) -> str:
    value = definition.raw.get("smoke", {}).get("completion_policy")
    if value != "all-participants-durable":
        raise PlanError("beacon runs require all-participants-durable completion")
    return str(value)


def _build_identity(
    binary_path: Path | None, docker_image: str | None = None, docker_host: str | None = None
) -> tuple[Path, str, str, bool, str]:
    if binary_path is None and docker_image is not None:
        from .execution.docker_simulation.build import image_runner

        binary_path = image_runner(docker_image, docker_host)
    binary = (binary_path or _default_runner_binary()).resolve()
    if not binary.is_file():
        raise PlanError(f"experiment-runner binary does not exist: {binary}")
    paths = workspace_paths()
    identity = source_identity(paths.code_root)
    return (
        binary,
        _sha256(binary),
        identity.git_commit,
        identity.git_dirty,
        identity.source_fingerprint,
    )


def _inventory_binding(
    executor: BeaconExecutor,
    inventory_path: Path | None,
    node_count: int,
) -> tuple[str | None, str | None, tuple[str, ...], tuple[str, ...]]:
    if executor is not BeaconExecutor.AWS_REMOTE:
        if inventory_path is not None:
            raise PlanError("--inventory is only valid with executor=remote-aws")
        return None, None, (), ()
    if inventory_path is None:
        raise PlanError("remote-aws planning requires --inventory")
    from .execution.inventory import load_inventory

    inventory = load_inventory(inventory_path)
    placement = inventory.replica_placement(node_count)
    return (
        str(inventory.path),
        inventory.sha256,
        tuple(placement[node].alias for node in range(node_count)),
        tuple(placement[node].region for node in range(node_count)),
    )


def _verify_binary(binary_path: str, expected_sha256: str) -> None:
    binary = Path(binary_path)
    if not binary.is_file() or _sha256(binary) != expected_sha256:
        raise PlanError("planned experiment-runner binary is missing or changed")


def _default_runner_binary() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    return workspace_paths().code_root / "target" / "release" / f"experiment-runner{suffix}"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
