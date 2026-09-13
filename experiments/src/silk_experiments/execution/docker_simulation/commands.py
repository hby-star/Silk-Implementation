from __future__ import annotations

import json

from ...planning import SmokePlan
from .common import docker_command, format_number
from .constants import MANAGED_LABEL, NODE_LABEL_KEY, RUN_LABEL_KEY
from .network import (
    netem_seed,
    network_subnet,
    node_mac,
    regional_netem_rules,
    static_neighbor_rules,
)
from .profile import DockerExecutionProfile
from .staging import NodeMounts


def docker_network_create_command(
    plan: SmokePlan,
    network: str,
    docker_host: str | None = None,
    subnet: str | None = None,
) -> list[str]:
    return docker_command(
        docker_host,
        "network",
        "create",
        "--subnet",
        subnet or network_subnet(plan.run_id),
        "--label",
        MANAGED_LABEL,
        "--label",
        f"{RUN_LABEL_KEY}={plan.run_id}",
        network,
    )


def docker_create_command(
    plan: SmokePlan,
    node_id: int,
    name: str,
    network: str,
    endpoints: dict[int, str],
    mounts: NodeMounts,
    profile: DockerExecutionProfile,
    *,
    node_ip_address: str | None = None,
    node_ips: dict[int, str] | None = None,
    docker_host: str | None = None,
) -> list[str]:
    endpoint_json = json.dumps(
        {str(node): endpoint for node, endpoint in endpoints.items()},
        separators=(",", ":"),
        sort_keys=True,
    )
    if plan.docker_image is None:
        raise ValueError("Docker beacon plan does not bind an image")
    command = docker_command(
        docker_host,
        "create",
        "--name",
        name,
        "--hostname",
        name,
        "--network",
        network,
    )
    if node_ip_address is not None:
        command.extend(["--ip", node_ip_address, "--mac-address", node_mac(node_ip_address)])
    command.extend(
        [
            "--label",
            MANAGED_LABEL,
            "--label",
            f"{RUN_LABEL_KEY}={plan.run_id}",
            "--label",
            f"{NODE_LABEL_KEY}={node_id}",
            "--cap-add",
            "NET_ADMIN",
            "--cpus",
            format_number(profile.resources.cpu_cores_per_node),
            "--memory",
            f"{profile.resources.memory_mib_per_node}m",
            "--memory-swap",
            f"{profile.resources.memory_mib_per_node}m",
            "--env",
            f"SILK_NODE_ENDPOINTS_JSON={endpoint_json}",
            "--env",
            f"SILK_SAMPLE_ROLE={plan.sample_role}",
            "--env",
            f"SILK_EXECUTOR={plan.executor}",
            "--env",
            f"SILK_NETWORK_SCENARIO={profile.network.profile}",
            "--env",
            f"SILK_RESOURCE_PROFILE={profile.resources.profile}",
            "--env",
            "SILK_NETEM_ENABLED=1",
            "--env",
            "SILK_EXECUTOR_RETIREMENT=all-complete-v1",
            "--env",
            "SILK_NETEM_INTERFACE=eth0",
            "--env",
            f"SILK_NETEM_BANDWIDTH_MBIT={profile.network.bandwidth_mbps}",
        ]
    )
    if node_ips is not None:
        command.extend(
            [
                "--env",
                f"SILK_NODE_NEIGHBORS={static_neighbor_rules(node_id, node_ips)}",
            ]
        )
    if profile.network.delay_distribution == "uniform":
        delay_mean_ms = (profile.network.delay_min_ms + profile.network.delay_max_ms) / 2
        delay_jitter_ms = (profile.network.delay_max_ms - profile.network.delay_min_ms) / 2
        command.extend(
            [
                "--env",
                "SILK_NETEM_MODE=uniform",
                "--env",
                f"SILK_NETEM_DELAY_MS={format_number(delay_mean_ms)}",
                "--env",
                f"SILK_NETEM_JITTER_MS={format_number(delay_jitter_ms)}",
                "--env",
                f"SILK_NETEM_DISTRIBUTION={profile.network.delay_distribution}",
                "--env",
                f"SILK_NETEM_LOSS_PERCENT={format_number(profile.network.loss_percent)}",
                "--env",
                f"SILK_NETEM_REORDER_PERCENT={format_number(profile.network.reorder_percent)}",
                "--env",
                f"SILK_NETEM_DUPLICATE_PERCENT={format_number(profile.network.duplicate_percent)}",
                "--env",
                f"SILK_NETEM_SEED={netem_seed(plan.seed, node_id)}",
            ]
        )
    else:
        if node_ips is None:
            raise ValueError("regional Docker netem requires fixed node IPs")
        region_index = node_id % len(profile.network.regions)
        command.extend(
            [
                "--env",
                "SILK_NETEM_MODE=region-matrix",
                "--env",
                f"SILK_NODE_REGION={profile.network.regions[region_index]}",
                "--env",
                f"SILK_NETEM_RULES={regional_netem_rules(node_id, node_ips, profile.network)}",
            ]
        )
    command.extend(
        [
            "--mount",
            f"type=bind,source={mounts.definition},target=/run/experiment.toml,readonly",
            "--mount",
            f"type=bind,source={mounts.results},target=/results",
            "--mount",
            f"type=bind,source={mounts.state},target=/state",
        ]
    )
    command.extend(
        [
            plan.docker_image,
            "distributed-run",
            "--config",
            "/run/experiment.toml",
            "--run-id",
            plan.run_id,
            "--implementation",
            plan.implementation,
            "--node-id",
            str(node_id),
            "--n",
            str(plan.n),
            "--t",
            str(plan.t),
            "--slots",
            str(plan.batch_size),
            "--listen",
            "0.0.0.0:7000",
            "--store-root",
            "/state",
            "--output",
            "/results",
            "--samples",
            str(plan.samples),
            "--seed",
            str(plan.seed),
        ]
    )
    return command
