from __future__ import annotations

from dataclasses import dataclass

from ...config import (
    IsolationDefinition,
    NetworkDefinition,
    ResourceDefinition,
    load_definition,
)
from ...planning import SmokePlan
from ...registry import BeaconExecutor, ExperimentKind


@dataclass(frozen=True)
class DockerExecutionProfile:
    network: NetworkDefinition
    resources: ResourceDefinition
    isolation: IsolationDefinition


def docker_execution_profile(plan: SmokePlan) -> DockerExecutionProfile:
    definition = load_definition(plan.definition_path)
    if definition.sha256 != plan.definition_sha256:
        raise RuntimeError("planned experiment definition is missing or changed")
    if definition.kind is not ExperimentKind.BEACON_PERFORMANCE:
        raise RuntimeError("Docker execution requires a beacon-performance definition")
    network = definition.matrix.network
    resources = definition.matrix.resources
    isolation = definition.matrix.isolation
    if network is None or resources is None:
        raise RuntimeError("Docker execution requires network and resource profiles")
    executor = BeaconExecutor.parse(plan.executor)
    if executor is not BeaconExecutor.DOCKER:
        raise RuntimeError("Docker execution profile requires a Docker executor")
    if not resources.one_container_per_node:
        raise RuntimeError("Docker execution requires one container per node")
    if (
        isolation.policy != "strict-between-runs-v1"
        or not isolation.cleanup_before_run
        or not isolation.cleanup_after_run
        or not isolation.verify_terminated
        or isolation.scope != "experiment-labelled-containers-and-networks"
    ):
        raise RuntimeError("Docker execution requires strict labelled-resource cleanup")
    return DockerExecutionProfile(network, resources, isolation)
