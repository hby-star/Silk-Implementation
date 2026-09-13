from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..artifacts import BeaconSmokeResult
from ..config import ExperimentDefinition, load_definition
from ..paths import workspace_paths
from ..planning import SmokePlan, save_plan_collection, save_smoke_plan
from ..registry import BeaconExecutor, ExperimentKind
from ..workflows import run_beacon_smoke
from .model import SuiteResult

MODES = ("smoke", "matrix")


def generated_run_name(environment: str, mode: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{environment}-{mode}-{timestamp}"


def experiments_root() -> Path:
    return workspace_paths().code_root / "experiments"


def default_collection_path(run_prefix: str) -> Path:
    return workspace_paths().state_root.parent / "collections" / f"{run_prefix}.json"


def validate_suite_request(
    *,
    definition_path: Path,
    executor: BeaconExecutor,
    mode: str,
    timeout_seconds: int,
) -> ExperimentDefinition:
    """Validate cheap suite inputs before inspecting or building a runtime artifact."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    definition = load_definition(definition_path)
    if definition.kind is not ExperimentKind.BEACON_PERFORMANCE:
        raise ValueError("suite definition must be beacon-performance")
    if mode == "smoke" and executor.value not in definition.executors:
        raise ValueError(f"definition does not enable executor={executor.value}")
    if mode == "matrix" and definition.matrix.executors != (executor.value,):
        raise ValueError(
            f"{executor.value} matrix requires a definition dedicated to that executor"
        )
    return definition


def materialize_and_run(
    *,
    environment: str,
    mode: str,
    plans: tuple[SmokePlan, ...],
    timeout_seconds: int,
    execute: bool,
    collection_path: Path | None = None,
) -> SuiteResult:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if not plans:
        raise ValueError("suite must contain at least one run plan")
    if mode == "smoke" and len(plans) != 1:
        raise ValueError("smoke suite must contain exactly one plan")
    if mode == "matrix" and collection_path is None:
        raise ValueError("matrix suite requires a collection path")

    plan_paths = tuple(str(save_smoke_plan(plan)) for plan in plans)
    saved_collection = (
        str(save_plan_collection(collection_path, plans)) if collection_path is not None else None
    )
    results: tuple[BeaconSmokeResult, ...] = ()
    if execute:
        results = tuple(run_beacon_smoke(plan, timeout_seconds=timeout_seconds) for plan in plans)
    return SuiteResult(
        environment=environment,
        mode=mode,
        executor=plans[0].executor,
        plan_paths=plan_paths,
        collection_path=saved_collection,
        executed=execute,
        run_results=results,
    )
