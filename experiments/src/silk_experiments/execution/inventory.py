from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

HOST_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EC2_INSTANCE_ID = re.compile(r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")


class InventoryError(ValueError):
    """A deployment inventory is incomplete or unsafe."""


@dataclass(frozen=True)
class Host:
    alias: str
    address: str
    user: str
    region: str
    roles: tuple[str, ...]
    data_dir: str
    port: int
    endpoint_address: str
    instance_id: str
    identity_file: str | None
    ssh_gateway: Host | None = None


@dataclass(frozen=True)
class Inventory:
    path: Path
    sha256: str
    hosts: tuple[Host, ...]
    p2p_port: int = 7000

    def replica_placement(self, node_count: int) -> dict[int, Host]:
        """Return the strict one-replica-per-instance AWS placement."""
        if node_count <= 0:
            raise InventoryError("node_count must be positive")
        replicas = tuple(host for host in self.hosts if "replica" in host.roles)
        if len(replicas) < node_count:
            raise InventoryError(
                "remote-aws requires at least one distinct replica host per node: "
                f"nodes={node_count}, replica_hosts={len(replicas)}"
            )
        selected = replicas[:node_count]
        addresses = tuple(host.address for host in selected)
        if len(addresses) != len(set(addresses)):
            raise InventoryError("remote-aws SSH address values must be unique")
        endpoints = tuple(host.endpoint_address for host in selected)
        if len(endpoints) != len(set(endpoints)):
            raise InventoryError("remote-aws endpoint_address values must be unique")
        instance_ids = tuple(host.instance_id for host in selected)
        if len(instance_ids) != len(set(instance_ids)):
            raise InventoryError("remote-aws EC2 instance_id values must be unique")
        return dict(enumerate(selected))


def load_inventory(path: str | Path) -> Inventory:
    resolved = Path(path).resolve()
    raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise InventoryError("inventory schema_version must be 1")
    entries = raw.get("hosts")
    if not isinstance(entries, list) or not entries:
        raise InventoryError("inventory requires a non-empty hosts list")

    hosts = tuple(_parse_host(entry, resolved.parent) for entry in entries)
    aliases = tuple(host.alias for host in hosts)
    if len(aliases) != len(set(aliases)):
        raise InventoryError("inventory aliases must be unique")
    replica_ids = {host.instance_id for host in hosts if "replica" in host.roles}
    if any(host.ssh_gateway and host.ssh_gateway.instance_id in replica_ids for host in hosts):
        raise InventoryError("SSH gateway must be a spare, outside the replica committee")
    p2p_port = raw.get("p2p_port", 7000)
    if isinstance(p2p_port, bool) or not isinstance(p2p_port, int) or not 1 <= p2p_port <= 65535:
        raise InventoryError("inventory p2p_port must be an integer in 1..65535")
    return Inventory(resolved, _sha256(resolved), hosts, p2p_port)


def _parse_host(value: object, inventory_dir: Path) -> Host:
    if not isinstance(value, dict):
        raise InventoryError("inventory host must be a mapping")
    entry: dict[str, Any] = value
    alias = _required_text(entry, "alias")
    if not HOST_ALIAS.fullmatch(alias):
        raise InventoryError(f"invalid inventory host alias: {alias!r}")
    address = _required_text(entry, "address")
    if any(character.isspace() for character in address):
        raise InventoryError(f"host {alias} address must be a host name or IP address")
    user = str(entry.get("user", ""))
    region = _required_text(entry, "region")
    roles_value = entry.get("roles", ["replica"])
    if not isinstance(roles_value, list) or not roles_value:
        raise InventoryError(f"host {alias} roles must be a non-empty list")
    roles = tuple(str(role).strip() for role in roles_value)
    if any(not role for role in roles):
        raise InventoryError(f"host {alias} contains an empty role")

    data_dir = str(entry.get("data_dir", "/srv/silk-experiments"))
    data_path = PurePosixPath(data_dir)
    if not data_path.is_absolute() or ".." in data_path.parts or data_path == PurePosixPath("/"):
        raise InventoryError(f"host {alias} data_dir must be a scoped absolute POSIX path")
    port = entry.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise InventoryError(f"host {alias} port must be in 1..65535")
    endpoint_address = _required_text(entry, "endpoint_address")
    if any(character.isspace() for character in endpoint_address):
        raise InventoryError(f"host {alias} endpoint_address must be a host name or IP address")
    instance_id = _required_text(entry, "instance_id")
    if not EC2_INSTANCE_ID.fullmatch(instance_id):
        raise InventoryError(f"host {alias} has invalid EC2 instance_id {instance_id!r}")
    identity_value = entry.get("identity_file")
    identity_file = None
    if identity_value is not None:
        identity_path = Path(str(identity_value)).expanduser()
        if not identity_path.is_absolute():
            identity_path = (inventory_dir / identity_path).resolve()
        if not identity_path.is_file():
            raise InventoryError(f"host {alias} identity_file does not exist")
        identity_file = str(identity_path)
    gateway = None
    gateway_value = entry.get("ssh_gateway")
    if gateway_value is not None:
        if not isinstance(gateway_value, dict) or gateway_value.get("ssh_gateway") is not None:
            raise InventoryError("SSH gateway must be a single direct host")
        gateway = _parse_host(gateway_value, inventory_dir)
        if (
            gateway.instance_id == instance_id
            or gateway.address == address
            or "replica" in gateway.roles
        ):
            raise InventoryError("SSH gateway must identify a separate spare host")
    return Host(
        alias,
        address,
        user,
        region,
        roles,
        data_dir,
        port,
        endpoint_address,
        instance_id,
        identity_file,
        gateway,
    )


def _required_text(entry: dict[str, Any], field: str) -> str:
    value = str(entry.get(field, "")).strip()
    if not value:
        raise InventoryError(f"inventory host {field} is required")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
