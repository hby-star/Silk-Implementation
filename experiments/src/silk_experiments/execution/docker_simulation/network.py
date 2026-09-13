from __future__ import annotations

import hashlib
import ipaddress

from ...config import NetworkDefinition
from .common import format_number


def netem_seed(run_seed: int, node_id: int) -> int:
    payload = f"run-seed-plus-node-id-v1:{run_seed}:{node_id}".encode()
    value = int.from_bytes(hashlib.sha256(payload).digest()[:4], "big")
    return value or 1


def container_name(run_id: str, node_id: int) -> str:
    return f"silk-{_run_token(run_id)}-node-{node_id:04}"


def network_name(run_id: str) -> str:
    return f"silk-{_run_token(run_id)}"


def network_subnet(run_id: str) -> str:
    third_octet = 16 + hashlib.sha256(run_id.encode("utf-8")).digest()[0] % 224
    return f"172.30.{third_octet}.0/24"


def node_ip(subnet: str, node_id: int) -> str:
    if not 0 <= node_id <= 199:
        raise ValueError("Docker node ID does not fit the experiment subnet")
    prefix = subnet.removesuffix("0/24")
    if prefix == subnet:
        raise ValueError("Docker experiment subnet must be a /24 ending in .0")
    return f"{prefix}{node_id + 10}"


def node_mac(address: str) -> str:
    octets = ipaddress.IPv4Address(address).packed
    return ":".join(("02", "42", *(f"{octet:02x}" for octet in octets)))


def static_neighbor_rules(node_id: int, node_ips: dict[int, str]) -> str:
    if node_id not in node_ips:
        raise ValueError("Docker node ID is missing from the fixed IP assignment")
    return "\n".join(
        f"{address}|{node_mac(address)}"
        for peer, address in sorted(node_ips.items())
        if peer != node_id
    )


def region_assignment(node_ids: tuple[int, ...], network: NetworkDefinition) -> dict[int, str]:
    if network.region_assignment != "round-robin-v1" or not network.regions:
        return {}
    return {node_id: network.regions[node_id % len(network.regions)] for node_id in node_ids}


def regional_netem_rules(
    node_id: int,
    node_ips: dict[int, str],
    network: NetworkDefinition,
) -> str:
    if network.region_assignment != "round-robin-v1" or not network.regions:
        raise ValueError("regional netem requires round-robin-v1 region assignment")
    source_region = node_id % len(network.regions)
    lines: list[str] = []
    for destination_region in range(len(network.regions)):
        destinations = [
            f"{address}/32"
            for destination_node, address in sorted(node_ips.items())
            if destination_node % len(network.regions) == destination_region
        ]
        if not destinations:
            continue
        one_way_delay_ms = network.rtt_matrix_ms[source_region][destination_region] / 2
        lines.append(
            f"{10 + destination_region}|{format_number(one_way_delay_ms)}|{','.join(destinations)}"
        )
    return "\n".join(lines)


def _run_token(run_id: str) -> str:
    prefix = "".join(character.lower() for character in run_id if character.isalnum())[:20]
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:12]
    return f"{prefix or 'run'}-{digest}"
