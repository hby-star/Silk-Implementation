from __future__ import annotations

from ...planning import SmokePlan
from ...provenance import SourceIdentity
from ...registry import BeaconExecutor
from ..types import BeaconProcessWorkspace, ProcessCapture
from .build import image_id
from .cleanup import cleanup_managed_docker_resources
from .commands import docker_create_command, docker_network_create_command
from .common import docker_command
from .lifecycle import release_container, run_command, wait_container, wait_protocol_complete
from .network import container_name, network_name, network_subnet, node_ip
from .profile import docker_execution_profile
from .staging import DockerStaging


def run_docker_nodes(
    plan: SmokePlan,
    workspace: BeaconProcessWorkspace,
    timeout_seconds: int,
) -> tuple[ProcessCapture, ...]:
    if BeaconExecutor.parse(plan.executor) is not BeaconExecutor.DOCKER:
        raise ValueError("Docker runner requires executor=docker")
    if plan.docker_image is None or plan.docker_image_id is None:
        raise ValueError("Docker plan does not bind an image")
    profile = docker_execution_profile(plan)
    actual_image = image_id(
        plan.docker_image,
        plan.docker_host,
        SourceIdentity(plan.git_commit, plan.git_dirty, plan.source_fingerprint),
    )
    if actual_image != plan.docker_image_id:
        raise RuntimeError(
            f"planned Docker image changed: expected {plan.docker_image_id}, got {actual_image}"
        )
    cleanup_managed_docker_resources(docker_host=plan.docker_host)
    staging = DockerStaging(plan, workspace)
    names = {node: container_name(plan.run_id, node) for node in plan.expected_node_ids}
    collected = False
    try:
        subnet = network_subnet(plan.run_id)
        ips = {node: node_ip(subnet, node) for node in plan.expected_node_ids}
        endpoints = {node: f"{ips[node]}:7000" for node in plan.expected_node_ids}
        network = network_name(plan.run_id)
        run_command(docker_network_create_command(plan, network, plan.docker_host, subnet))
        for node in plan.expected_node_ids:
            run_command(
                docker_create_command(
                    plan,
                    node,
                    names[node],
                    network,
                    endpoints,
                    staging.mounts(node),
                    profile,
                    node_ip_address=ips[node],
                    node_ips=ips,
                    docker_host=plan.docker_host,
                )
            )
        run_command(docker_command(plan.docker_host, "start", *names.values()))

        # Keep all listeners/netem namespaces alive until protocol completion
        # is recorded everywhere. This does not release any protocol barrier.
        for node, name in names.items():
            wait_protocol_complete(
                name,
                node,
                timeout_seconds,
                plan.docker_host,
            )
        for name in names.values():
            release_container(name, plan.docker_host)

        captures = []
        for node in plan.expected_node_ids:
            exit_code = wait_container(
                names[node],
                timeout_seconds,
                plan.docker_host,
            )
            logs = run_command(docker_command(plan.docker_host, "logs", names[node]), check=False)
            captures.append(ProcessCapture(node, exit_code, logs.stdout, logs.stderr))
            staging.collect_node(node)
        collected = True
        return tuple(captures)
    finally:
        try:
            staging.persist_diagnostics(names, plan.docker_host)
        except Exception:
            pass
        try:
            cleanup_managed_docker_resources(plan.run_id, docker_host=plan.docker_host)
            if collected:
                staging.remove_remote_root(plan.docker_image, plan.docker_host)
        finally:
            staging.close()
