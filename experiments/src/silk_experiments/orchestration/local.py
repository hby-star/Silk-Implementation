from __future__ import annotations

from pathlib import Path

from ..execution.docker_simulation import DEFAULT_IMAGE, build_image, image_id
from ..planning import SmokePlan, build_beacon_matrix_plans, build_beacon_smoke_plan
from ..registry import BeaconExecutor
from .common import (
    default_collection_path,
    experiments_root,
    generated_run_name,
    materialize_and_run,
    validate_suite_request,
)
from .model import SuiteResult


def run_local_suite(
    *,
    mode: str = "smoke",
    implementation: str = "silk-beacon",
    definition: Path | None = None,
    run_name: str | None = None,
    collection: Path | None = None,
    image: str = DEFAULT_IMAGE,
    docker_host: str | None = None,
    rebuild: bool = True,
    execute: bool = True,
    timeout_seconds: int = 1_800,
) -> SuiteResult:
    definition_path = (
        definition or experiments_root() / "definitions" / "docker" / "beacon-performance.toml"
    ).resolve()
    validate_suite_request(
        definition_path=definition_path,
        executor=BeaconExecutor.DOCKER,
        mode=mode,
        timeout_seconds=timeout_seconds,
    )
    selected_name = run_name or generated_run_name("local", mode)
    selected_image_id = build_image(image, docker_host) if rebuild else image_id(image, docker_host)
    plans: tuple[SmokePlan, ...]
    if mode == "smoke":
        plan = build_beacon_smoke_plan(
            definition_path,
            selected_name,
            implementation,
            executor=BeaconExecutor.DOCKER.value,
            docker_image=image,
            docker_image_id=selected_image_id,
            docker_host=docker_host,
        )
        plans = (plan,)
        collection_path = None
    elif mode == "matrix":
        plans = build_beacon_matrix_plans(
            definition_path,
            selected_name,
            docker_image=image,
            docker_image_id=selected_image_id,
            docker_host=docker_host,
            implementation=implementation or None,
        )
        collection_path = (collection or default_collection_path(selected_name)).resolve()
    return materialize_and_run(
        environment="local",
        mode=mode,
        plans=plans,
        timeout_seconds=timeout_seconds,
        execute=execute,
        collection_path=collection_path,
    )
